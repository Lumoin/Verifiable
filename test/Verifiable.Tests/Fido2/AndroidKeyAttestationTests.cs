using System.Buffers;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.BouncyCastle;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="AndroidKeyAttestation"/> — the
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation">W3C Web
/// Authentication Level 3, section 8.4: Android Key Attestation Statement Format</see> verification
/// procedure, its section 8.4.1 key description extension checks, and the teeEnforced-only-versus-union
/// RP policy knob.
/// </summary>
/// <remarks>
/// Every fixture mints its certificate chain, key description extension, and attestation signature
/// with an independent oracle — raw <see cref="ECDsa"/>/<see cref="RSA"/>, <see cref="CertificateRequest"/>,
/// and BouncyCastle's ASN.1 writer, never this package's own signing, chain-building, or ASN.1-reading
/// seams — so <see cref="AndroidKeyAttestation"/> is exercised against genuinely external wire material
/// reconstructed solely from the <see cref="AttestationVerificationRequest"/>'s wire-shaped members.
/// </remarks>
[TestClass]
internal sealed class AndroidKeyAttestationTests
{
    /// <summary>The base64url-encoded challenge a valid ceremony embeds and expects.</summary>
    private const string ValidChallenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX";

    /// <summary>The relying party origin a valid ceremony embeds and expects.</summary>
    private const string ValidOrigin = "https://relyingparty.example";

    /// <summary>The correlation identifier the full-ceremony e2e test uses.</summary>
    private const string CorrelationId = "android-key-attestation-test-correlation";


    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>An <see cref="IsCredentialIdUniqueDelegate"/> reporting every credential ID as unique.</summary>
    private static IsCredentialIdUniqueDelegate AlwaysUnique { get; } = static (_, _) => ValueTask.FromResult(true);


    // ---------------------------------------------------------------------------------------
    // Positive
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// An ES256 android-key registration — union-mode knob, conformant <c>teeEnforced</c> — minted
    /// as real wire <c>attestationObject</c> CBOR bytes and verified end to end through
    /// <see cref="Fido2RegistrationVerifier"/> with the shipped
    /// <see cref="AttestationObjectCborReader"/>/<see cref="AndroidKeyAttestationStatementCborReader"/>
    /// defaults — no stub parser anywhere — reports <see cref="CertifiedAttestationResult"/> of type
    /// <see cref="AttestationType.Basic"/>.
    /// </summary>
    [TestMethod]
    public async Task ValidEs256UnionModeRegistrationVerifiesEndToEndThroughShippedCborDefaults()
    {
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();
        byte[] credentialId = [0x01, 0x02, 0x03, 0x04];
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(ValidChallenge, ValidOrigin);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash(clientDataJson, BaseMemoryPool.Shared);
        byte[] challenge = clientDataHash.AsReadOnlySpan().ToArray();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        byte[] keyDescriptionBytes = AndroidKeyAttestationTestVectors.EncodeKeyDescriptionExtensionValue(
            challenge, AndroidKeyAttestationTestVectors.EmptyAuthorizationList, AndroidKeyAttestationTestVectors.ConformantAuthorizationList);
        using X509Certificate2 credCert = AndroidKeyAttestationTestVectors.CreateEcCredCert(rootCert, credentialKey, keyDescriptionBytes);

        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);
        AuthenticatorData authenticatorData = Fido2RegistrationVerifierTests.BuildRegistrationAuthenticatorData(
            Fido2TestVectors.CreateRpIdHash(), aaguid, credentialPublicKey, credentialId, out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(credentialKey, toBeSigned);

        using PkiCertificateMemory credCertPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(credCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        byte[] attStmtCbor = AndroidKeyAttestationStatementCborWriter.Write(WellKnownCoseAlgorithms.Es256, signature, [credCertPki, rootPki]).Memory.ToArray();
        byte[] attestationObjectBytes = Fido2AttestationTestVectors.EncodeAttestationObject(WellKnownWebAuthnAttestationFormats.AndroidKey, attStmtCbor, authDataBytes);

        AttestationObjectParts parts = AttestationObjectCborReader.Parse(attestationObjectBytes);
        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.AndroidKey, parts.Format);

        using RegistrationCeremonyInput ceremonyInput = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataOverride: ClientDataJsonReader.Read(clientDataJson),
            authenticatorDataOverride: authenticatorData,
            expectedRpIdHash: Fido2TestVectors.CreateRpIdHash());
        SelectAttestationVerifierDelegate selectVerifier = Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.AndroidKey, AndroidKeyAttestation.Build(
                AndroidKeyAttestationStatementCborReader.Parse, MicrosoftX509Functions.ValidateChainAsync, MicrosoftX509Functions.ReadCertificateExtensionValue)));

        Fido2RegistrationOutcome outcome = await Fido2RegistrationVerifier.VerifyAsync(
            parts.Format,
            attestationStatement: parts.AttestationStatement,
            authDataBytes,
            clientDataJson,
            ceremonyInput,
            selectVerifier,
            AlwaysUnique,
            trustAnchors: [rootPki],
            validationTime: TestClock.CanonicalEpoch,
            CorrelationId,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.IsInstanceOfType<CertifiedAttestationResult>(outcome.AttestationResult);
        Assert.AreEqual(AttestationType.Basic, ((CertifiedAttestationResult)outcome.AttestationResult).Type);
        Assert.IsTrue(outcome.IsAcceptable);
        using Fido2CredentialRecord? record = outcome.CredentialRecord;
        Assert.IsNotNull(record);
    }


    /// <summary>
    /// An RS256 android-key statement verifies at the direct-verifier level with the Microsoft
    /// backend supplying both chain validation and the key description extension read.
    /// </summary>
    [TestMethod]
    public async Task ValidRs256StatementVerifiesWithMicrosoftBackend()
    {
        AttestationResult result = await VerifyRsaVariantAsync(MicrosoftX509Functions.ReadCertificateExtensionValue);

        Assert.IsInstanceOfType<CertifiedAttestationResult>(result);
    }


    /// <summary>
    /// The SAME RS256 android-key statement verifies end to end through the BouncyCastle backend —
    /// chain validation, credCert public-key extraction, and the key description extension read all
    /// execute via <see cref="BouncyCastleX509Functions"/> — proving RSA leaf-key extraction now
    /// matches <see cref="MicrosoftX509Functions"/>'s output byte-for-byte
    /// (<see cref="BackendLeafKeyParityTests"/>), so the credCert-key-vs-credentialPublicKey comparison
    /// this verifier performs holds on both backends, not the Microsoft backend alone.
    /// </summary>
    [TestMethod]
    public async Task ValidRs256StatementVerifiesWithBouncyCastleBackend()
    {
        AttestationResult result = await VerifyRsaVariantAsync(
            BouncyCastleX509Functions.ReadCertificateExtensionValue, BouncyCastleX509Functions.ValidateChainAsync);

        Assert.IsInstanceOfType<CertifiedAttestationResult>(result);
    }


    /// <summary>
    /// The <c>requireTeeEnforcedAuthorizations</c> knob, when <see langword="true"/>, ignores an
    /// entirely wrong <c>softwareEnforced</c> list and accepts on the conformant <c>teeEnforced</c>
    /// list alone.
    /// </summary>
    [TestMethod]
    public async Task TeeEnforcedOnlyKnobAcceptsWhenTeeEnforcedAloneSatisfiesDespiteWrongSoftwareEnforced()
    {
        var wrongSoftwareEnforced = new AndroidKeyAuthorizationList(new HashSet<int> { 3 }, 1, HasAllApplications: false);
        AttestationResult result = await VerifyEcVariantAsync(
            softwareEnforced: wrongSoftwareEnforced,
            teeEnforced: AndroidKeyAttestationTestVectors.ConformantAuthorizationList,
            requireTeeEnforcedAuthorizations: true);

        Assert.IsInstanceOfType<CertifiedAttestationResult>(result);
    }


    /// <summary>
    /// Union mode accepts when ONLY <c>softwareEnforced</c> satisfies the origin/purpose checks and
    /// <c>teeEnforced</c> carries neither field — the software-only-key shape.
    /// </summary>
    [TestMethod]
    public async Task UnionModeAcceptsWhenOnlySoftwareEnforcedSatisfiesOriginAndPurpose()
    {
        AttestationResult result = await VerifyEcVariantAsync(
            softwareEnforced: AndroidKeyAttestationTestVectors.ConformantAuthorizationList,
            teeEnforced: AndroidKeyAttestationTestVectors.EmptyAuthorizationList,
            requireTeeEnforcedAuthorizations: false);

        Assert.IsInstanceOfType<CertifiedAttestationResult>(result);
    }


    /// <summary>
    /// Union mode checks EACH authorization list independently rather than preferring
    /// <c>teeEnforced</c> and falling back to <c>softwareEnforced</c> only on absence: with
    /// <c>teeEnforced.origin</c> present but WRONG and <c>softwareEnforced.origin</c> present and
    /// correct, union mode still accepts — a "prefer teeEnforced, fall back on null" implementation
    /// would incorrectly reject this case, since it would consult only the (wrong, but non-null)
    /// <c>teeEnforced</c> value.
    /// </summary>
    [TestMethod]
    public async Task UnionModeAcceptsWhenTeeEnforcedOriginIsWrongButSoftwareEnforcedIsCorrect()
    {
        var wrongTeeEnforced = new AndroidKeyAuthorizationList(new HashSet<int> { AndroidKeyAttestationTestVectors.KmPurposeSign }, 1, HasAllApplications: false);
        AttestationResult result = await VerifyEcVariantAsync(
            softwareEnforced: AndroidKeyAttestationTestVectors.ConformantAuthorizationList,
            teeEnforced: wrongTeeEnforced,
            requireTeeEnforcedAuthorizations: false);

        Assert.IsInstanceOfType<CertifiedAttestationResult>(result);
    }


    /// <summary>The mirror of the asymmetry-regression case: <c>softwareEnforced</c> wrong, <c>teeEnforced</c> correct — still accepted under union mode.</summary>
    [TestMethod]
    public async Task UnionModeAcceptsWhenSoftwareEnforcedOriginIsWrongButTeeEnforcedIsCorrect()
    {
        var wrongSoftwareEnforced = new AndroidKeyAuthorizationList(new HashSet<int> { AndroidKeyAttestationTestVectors.KmPurposeSign }, 1, HasAllApplications: false);
        AttestationResult result = await VerifyEcVariantAsync(
            softwareEnforced: wrongSoftwareEnforced,
            teeEnforced: AndroidKeyAttestationTestVectors.ConformantAuthorizationList,
            requireTeeEnforcedAuthorizations: false);

        Assert.IsInstanceOfType<CertifiedAttestationResult>(result);
    }


    /// <summary>A non-zero AAGUID is accepted — section 8.4 carries no zero-AAGUID rule (unlike some other formats).</summary>
    [TestMethod]
    public async Task NonZeroAaguidIsAcceptedAsAPositiveControl()
    {
        AttestationResult result = await VerifyEcVariantAsync(aaguid: Guid.NewGuid());

        Assert.IsInstanceOfType<CertifiedAttestationResult>(result);
    }


    // ---------------------------------------------------------------------------------------
    // Negative
    // ---------------------------------------------------------------------------------------

    /// <summary>An <c>attestationChallenge</c> not matching <c>clientDataHash</c> is rejected.</summary>
    [TestMethod]
    public async Task AttestationChallengeNotMatchingClientDataHashIsRejectedWithAttestationChallengeMismatch()
    {
        Fido2AttestationError? error = await VerifyEcVariantAndGetErrorAsync(challengeOverride: [0xFF, 0xFF, 0xFF, 0xFF]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.AttestationChallengeMismatch.Code, error.Code);
    }


    /// <summary>An <c>allApplications</c> field present on <c>softwareEnforced</c> alone is rejected.</summary>
    [TestMethod]
    public async Task AllApplicationsPresentOnSoftwareEnforcedIsRejectedWithKeyScopedToAllApplications()
    {
        var softwareEnforced = new AndroidKeyAuthorizationList(new HashSet<int>(), null, HasAllApplications: true);
        Fido2AttestationError? error = await VerifyEcVariantAndGetErrorAsync(softwareEnforced: softwareEnforced);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.KeyScopedToAllApplications.Code, error.Code);
    }


    /// <summary>An <c>allApplications</c> field present on <c>teeEnforced</c> alone is rejected.</summary>
    [TestMethod]
    public async Task AllApplicationsPresentOnTeeEnforcedIsRejectedWithKeyScopedToAllApplications()
    {
        var teeEnforced = new AndroidKeyAuthorizationList(new HashSet<int> { AndroidKeyAttestationTestVectors.KmPurposeSign }, AndroidKeyAttestationTestVectors.KmOriginGenerated, HasAllApplications: true);
        Fido2AttestationError? error = await VerifyEcVariantAndGetErrorAsync(teeEnforced: teeEnforced);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.KeyScopedToAllApplications.Code, error.Code);
    }


    /// <summary>An <c>allApplications</c> field present on BOTH lists is rejected.</summary>
    [TestMethod]
    public async Task AllApplicationsPresentOnBothListsIsRejectedWithKeyScopedToAllApplications()
    {
        var softwareEnforced = new AndroidKeyAuthorizationList(new HashSet<int>(), null, HasAllApplications: true);
        var teeEnforced = new AndroidKeyAuthorizationList(new HashSet<int> { AndroidKeyAttestationTestVectors.KmPurposeSign }, AndroidKeyAttestationTestVectors.KmOriginGenerated, HasAllApplications: true);
        Fido2AttestationError? error = await VerifyEcVariantAndGetErrorAsync(softwareEnforced: softwareEnforced, teeEnforced: teeEnforced);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.KeyScopedToAllApplications.Code, error.Code);
    }


    /// <summary>An <c>origin</c> wrong on BOTH lists (union mode) is rejected — neither list satisfies it.</summary>
    [TestMethod]
    public async Task OriginNotGeneratedOnEitherListInUnionModeIsRejectedWithKeyOriginNotGenerated()
    {
        var softwareEnforced = new AndroidKeyAuthorizationList(new HashSet<int> { AndroidKeyAttestationTestVectors.KmPurposeSign }, 1, HasAllApplications: false);
        var teeEnforced = new AndroidKeyAuthorizationList(new HashSet<int> { AndroidKeyAttestationTestVectors.KmPurposeSign }, 2, HasAllApplications: false);
        Fido2AttestationError? error = await VerifyEcVariantAndGetErrorAsync(softwareEnforced: softwareEnforced, teeEnforced: teeEnforced);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.KeyOriginNotGenerated.Code, error.Code);
    }


    /// <summary>A <c>purpose</c> set containing only non-signing purposes on BOTH lists is rejected.</summary>
    [TestMethod]
    public async Task PurposeMissingSignOnBothListsIsRejectedWithKeyPurposeNotSign()
    {
        const int KmPurposeEncrypt = 3;
        var softwareEnforced = new AndroidKeyAuthorizationList(new HashSet<int> { KmPurposeEncrypt }, AndroidKeyAttestationTestVectors.KmOriginGenerated, HasAllApplications: false);
        var teeEnforced = new AndroidKeyAuthorizationList(new HashSet<int> { KmPurposeEncrypt }, AndroidKeyAttestationTestVectors.KmOriginGenerated, HasAllApplications: false);
        Fido2AttestationError? error = await VerifyEcVariantAndGetErrorAsync(softwareEnforced: softwareEnforced, teeEnforced: teeEnforced);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.KeyPurposeNotSign.Code, error.Code);
    }


    /// <summary>
    /// The <c>requireTeeEnforcedAuthorizations</c> knob, when <see langword="true"/>, rejects a
    /// cert whose origin/purpose are satisfied ONLY by <c>softwareEnforced</c> — proving the knob is
    /// load-bearing (this same cert is accepted under union mode, per the paired positive test).
    /// </summary>
    [TestMethod]
    public async Task TeeEnforcedOnlyKnobRejectsWhenOnlySoftwareEnforcedSatisfiesOriginAndPurpose()
    {
        Fido2AttestationError? error = await VerifyEcVariantAndGetErrorAsync(
            softwareEnforced: AndroidKeyAttestationTestVectors.ConformantAuthorizationList,
            teeEnforced: AndroidKeyAttestationTestVectors.EmptyAuthorizationList,
            requireTeeEnforcedAuthorizations: true);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.KeyOriginNotGenerated.Code, error.Code);
    }


    /// <summary>
    /// A credCert public key that does not match <c>credentialPublicKey</c> — an independently
    /// generated EC key, never derived from the real one — is rejected, chain-validated through the
    /// Microsoft backend.
    /// </summary>
    [TestMethod]
    public async Task CredCertKeyNotMatchingCredentialPublicKeyIsRejectedWithCredentialKeyMismatchOnMicrosoftBackend()
    {
        Fido2AttestationError? error = await VerifyEcVariantAndGetErrorAsync(useMismatchedCredentialKey: true, validateChain: MicrosoftX509Functions.ValidateChainAsync);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CredentialKeyMismatch.Code, error.Code);
    }


    /// <summary>The same credCert-key mismatch is rejected chain-validated through the BouncyCastle backend.</summary>
    [TestMethod]
    public async Task CredCertKeyNotMatchingCredentialPublicKeyIsRejectedWithCredentialKeyMismatchOnBouncyCastleBackend()
    {
        Fido2AttestationError? error = await VerifyEcVariantAndGetErrorAsync(
            useMismatchedCredentialKey: true,
            validateChain: BouncyCastleX509Functions.ValidateChainAsync,
            readExtensionValue: BouncyCastleX509Functions.ReadCertificateExtensionValue);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CredentialKeyMismatch.Code, error.Code);
    }


    /// <summary>A tampered signature byte is rejected with <see cref="Fido2AttestationErrors.InvalidSignature"/>.</summary>
    [TestMethod]
    public async Task TamperedSignatureIsRejectedWithInvalidSignature()
    {
        Fido2AttestationError? error = await VerifyEcVariantAndGetErrorAsync(tamperSignature: true);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.InvalidSignature.Code, error.Code);
    }


    /// <summary>A statement claiming RS256 over an EC credCert key is rejected with <see cref="Fido2AttestationErrors.AlgorithmMismatch"/>.</summary>
    [TestMethod]
    public async Task AlgorithmNotMatchingCredCertKeyFamilyIsRejectedWithAlgorithmMismatch()
    {
        Fido2AttestationError? error = await VerifyEcVariantAndGetErrorAsync(algOverride: WellKnownCoseAlgorithms.Rs256);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.AlgorithmMismatch.Code, error.Code);
    }


    /// <summary>An unrecognised COSE algorithm identifier is rejected with <see cref="Fido2AttestationErrors.AlgorithmMismatch"/>.</summary>
    [TestMethod]
    public async Task UnknownCoseAlgorithmIsRejectedWithAlgorithmMismatch()
    {
        Fido2AttestationError? error = await VerifyEcVariantAndGetErrorAsync(algOverride: -99999);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.AlgorithmMismatch.Code, error.Code);
    }


    /// <summary>A credCert carrying no key description extension at all is rejected with <see cref="Fido2AttestationErrors.KeyDescriptionMissing"/>.</summary>
    [TestMethod]
    public async Task MissingKeyDescriptionExtensionIsRejectedWithKeyDescriptionMissing()
    {
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 credCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, credentialKey, isCertificateAuthority: false, organizationalUnit: null, aaguidExtensionValue: null);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(aaguid, credentialPublicKey, out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(credentialKey, toBeSigned);

        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        using PkiCertificateMemory credCertPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(credCert.RawData);
        var statement = new AndroidKeyAttestationStatement(WellKnownCoseAlgorithms.Es256, signature, [credCertPki, rootPki]);

        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: [rootPki]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.KeyDescriptionMissing.Code, error.Code);
    }


    /// <summary>
    /// A key description truncated mid-<c>KeyDescription</c>-SEQUENCE, exercised end to end through
    /// <see cref="AndroidKeyAttestation"/> (not only the unit-level <see cref="AndroidKeyDescriptionReaderTests"/>
    /// battery), is caught and mapped to <see cref="Fido2AttestationErrors.MalformedStatement"/>.
    /// </summary>
    [TestMethod]
    public async Task TruncatedKeyDescriptionIsRejectedWithMalformedStatementThroughTheFullVerifier()
    {
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        byte[] validKeyDescription = AndroidKeyAttestationTestVectors.EncodeKeyDescriptionExtensionValue(
            [1, 2, 3, 4], AndroidKeyAttestationTestVectors.EmptyAuthorizationList, AndroidKeyAttestationTestVectors.ConformantAuthorizationList);
        byte[] truncatedKeyDescription = validKeyDescription[..^4];
        using X509Certificate2 credCert = AndroidKeyAttestationTestVectors.CreateEcCredCert(rootCert, credentialKey, truncatedKeyDescription);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(aaguid, credentialPublicKey, out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(credentialKey, toBeSigned);

        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        using PkiCertificateMemory credCertPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(credCert.RawData);
        var statement = new AndroidKeyAttestationStatement(WellKnownCoseAlgorithms.Es256, signature, [credCertPki, rootPki]);

        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: [rootPki]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.MalformedStatement.Code, error.Code);
    }


    /// <summary>
    /// An <c>attStmt</c> shaped like <c>packed</c>'s self-attestation form (<c>alg</c>/<c>sig</c>,
    /// no <c>x5c</c>) fed to the shipped android-key CBOR default reader is rejected — android-key
    /// has no self-attestation branch, so a missing <c>x5c</c> is a malformed statement.
    /// </summary>
    [TestMethod]
    public async Task PackedShapedStatementWithoutX5cIsRejectedWithMalformedStatementThroughTheShippedReader()
    {
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(aaguid, credentialPublicKey, out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(credentialKey, toBeSigned);

        //Hand-encoded directly: the shipped AndroidKeyAttestationStatementCborWriter always writes x5c
        //(android-key has no self-attestation branch), so this packed-shaped, x5c-omitted map is a shape
        //only a raw, writer-independent encoder can produce.
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(2);
        writer.WriteTextString("alg");
        writer.WriteInt32(WellKnownCoseAlgorithms.Es256);
        writer.WriteTextString("sig");
        writer.WriteByteString(signature);
        writer.WriteEndMap();
        byte[] packedShapedAttStmt = writer.Encode();

        AttestationVerifyDelegate verify = AndroidKeyAttestation.Build(
            AndroidKeyAttestationStatementCborReader.Parse, MicrosoftX509Functions.ValidateChainAsync, MicrosoftX509Functions.ReadCertificateExtensionValue);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: packedShapedAttStmt, trustAnchors: [rootPki], validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        Assert.IsInstanceOfType<RejectedAttestationResult>(result);
        Assert.AreEqual(Fido2AttestationErrors.MalformedStatement.Code, ((RejectedAttestationResult)result).Error.Code);
    }


    /// <summary>A chain that does not build to any supplied trust anchor is rejected with <see cref="Fido2AttestationErrors.ChainValidationFailed"/>.</summary>
    [TestMethod]
    public async Task UntrustedRootIsRejectedWithChainValidationFailed()
    {
        using ECDsa imposterRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 imposterRootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Imposter Root", imposterRootKey);
        using PkiCertificateMemory imposterRootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(imposterRootCert.RawData);

        Fido2AttestationError? error = await VerifyEcVariantAndGetErrorAsync(trustAnchorsOverride: [imposterRootPki]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.ChainValidationFailed.Code, error.Code);
    }


    /// <summary>A credCert revoked by a CRL issued by its root is rejected via the wave-2 revocation seam.</summary>
    [TestMethod]
    public async Task RevokedCredCertIsRejectedWithChainValidationFailed()
    {
        DateTimeOffset validationTime = new(2027, 6, 1, 0, 0, 0, TimeSpan.Zero);

        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        byte[] keyDescriptionBytes = AndroidKeyAttestationTestVectors.EncodeKeyDescriptionExtensionValue(
            [1, 2, 3, 4], AndroidKeyAttestationTestVectors.EmptyAuthorizationList, AndroidKeyAttestationTestVectors.ConformantAuthorizationList);
        using X509Certificate2 credCert = AndroidKeyAttestationTestVectors.CreateEcCredCert(rootCert, credentialKey, keyDescriptionBytes);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(aaguid, credentialPublicKey, out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(credentialKey, toBeSigned);

        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        using PkiCertificateMemory credCertPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(credCert.RawData);
        var statement = new AndroidKeyAttestationStatement(WellKnownCoseAlgorithms.Es256, signature, [credCertPki, rootPki]);

        using PkiCertificateMemory revokingCrl = SyntheticPassportFactory.MintCrl(
            rootCert, credCert, validationTime.AddDays(-1), validationTime.AddDays(30), crlNumber: 1);
        var checker = new CrlRevocationChecker([revokingCrl]);

        AttestationVerifyDelegate verify = AndroidKeyAttestation.Build(
            AndroidKeyAttestationTestVectors.CreateStatementParser(statement),
            MicrosoftX509Functions.ValidateChainAsync,
            MicrosoftX509Functions.ReadCertificateExtensionValue,
            checkRevocation: checker.CheckAsync);
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [rootPki], validationTime: validationTime);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        Assert.IsInstanceOfType<RejectedAttestationResult>(result);
        Assert.AreEqual(Fido2AttestationErrors.ChainValidationFailed.Code, ((RejectedAttestationResult)result).Error.Code);
    }


    // ---------------------------------------------------------------------------------------
    // Shared vector/verify helpers
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Builds and runs a conformant, ES256, EC-keyed android-key statement, applying the given
    /// axis overrides, and returns the raw <see cref="AttestationResult"/>.
    /// </summary>
    private async Task<AttestationResult> VerifyEcVariantAsync(
        AndroidKeyAuthorizationList? softwareEnforced = null,
        AndroidKeyAuthorizationList? teeEnforced = null,
        bool requireTeeEnforcedAuthorizations = false,
        bool useMismatchedCredentialKey = false,
        bool tamperSignature = false,
        int? algOverride = null,
        byte[]? challengeOverride = null,
        Guid? aaguid = null,
        ValidateCertificateChainAsyncDelegate? validateChain = null,
        ReadCertificateExtensionValueDelegate? readExtensionValue = null,
        IReadOnlyList<PkiCertificateMemory>? trustAnchorsOverride = null)
    {
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa mismatchedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        byte[] challenge = challengeOverride ?? clientDataHash.AsReadOnlySpan().ToArray();

        byte[] keyDescriptionBytes = AndroidKeyAttestationTestVectors.EncodeKeyDescriptionExtensionValue(
            challenge,
            softwareEnforced ?? AndroidKeyAttestationTestVectors.EmptyAuthorizationList,
            teeEnforced ?? AndroidKeyAttestationTestVectors.ConformantAuthorizationList);
        using X509Certificate2 credCert = AndroidKeyAttestationTestVectors.CreateEcCredCert(rootCert, credentialKey, keyDescriptionBytes);

        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(
            useMismatchedCredentialKey ? mismatchedKey : credentialKey, WellKnownCoseAlgorithms.Es256);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(aaguid ?? Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(credentialKey, toBeSigned);
        if(tamperSignature)
        {
            signature[0] ^= 0xFF;
        }

        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        using PkiCertificateMemory credCertPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(credCert.RawData);
        var statement = new AndroidKeyAttestationStatement(algOverride ?? WellKnownCoseAlgorithms.Es256, signature, [credCertPki, rootPki]);

        return await VerifyAsync(
            statement, authDataBytes, authenticatorData, clientDataHash,
            trustAnchors: trustAnchorsOverride ?? [rootPki],
            validateChain: validateChain,
            readExtensionValue: readExtensionValue,
            requireTeeEnforcedAuthorizations: requireTeeEnforcedAuthorizations);
    }


    /// <summary>Runs <see cref="VerifyEcVariantAsync"/> and extracts the rejection error, if any.</summary>
    private async Task<Fido2AttestationError?> VerifyEcVariantAndGetErrorAsync(
        AndroidKeyAuthorizationList? softwareEnforced = null,
        AndroidKeyAuthorizationList? teeEnforced = null,
        bool requireTeeEnforcedAuthorizations = false,
        bool useMismatchedCredentialKey = false,
        bool tamperSignature = false,
        int? algOverride = null,
        byte[]? challengeOverride = null,
        ValidateCertificateChainAsyncDelegate? validateChain = null,
        ReadCertificateExtensionValueDelegate? readExtensionValue = null,
        IReadOnlyList<PkiCertificateMemory>? trustAnchorsOverride = null)
    {
        AttestationResult result = await VerifyEcVariantAsync(
            softwareEnforced, teeEnforced, requireTeeEnforcedAuthorizations, useMismatchedCredentialKey,
            tamperSignature, algOverride, challengeOverride, aaguid: null, validateChain, readExtensionValue, trustAnchorsOverride);

        return result is RejectedAttestationResult rejected ? rejected.Error : null;
    }


    /// <summary>
    /// Builds and runs a conformant, RS256, RSA-keyed android-key statement, with
    /// <paramref name="readExtensionValue"/> supplying the key description extension read and
    /// <paramref name="validateChain"/> supplying chain validation, defaulting to the Microsoft backend.
    /// </summary>
    private async Task<AttestationResult> VerifyRsaVariantAsync(
        ReadCertificateExtensionValueDelegate readExtensionValue,
        ValidateCertificateChainAsyncDelegate? validateChain = null)
    {
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using RSA credentialKey = RSA.Create(2048);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        byte[] challenge = clientDataHash.AsReadOnlySpan().ToArray();

        byte[] keyDescriptionBytes = AndroidKeyAttestationTestVectors.EncodeKeyDescriptionExtensionValue(
            challenge, AndroidKeyAttestationTestVectors.EmptyAuthorizationList, AndroidKeyAttestationTestVectors.ConformantAuthorizationList);
        using X509Certificate2 credCert = AndroidKeyAttestationTestVectors.CreateRsaCredCert(rootCert, credentialKey, keyDescriptionBytes);

        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateRsaCoseKey(credentialKey, WellKnownCoseAlgorithms.Rs256);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(aaguid, credentialPublicKey, out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithRsaPkcs1Sha256(credentialKey, toBeSigned);

        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        using PkiCertificateMemory credCertPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(credCert.RawData);
        var statement = new AndroidKeyAttestationStatement(WellKnownCoseAlgorithms.Rs256, signature, [credCertPki, rootPki]);

        return await VerifyAsync(
            statement, authDataBytes, authenticatorData, clientDataHash,
            trustAnchors: [rootPki],
            validateChain: validateChain ?? MicrosoftX509Functions.ValidateChainAsync,
            readExtensionValue: readExtensionValue);
    }


    /// <summary>Builds the <see cref="AndroidKeyAttestation"/> verifier under the given seams, defaulting to the Microsoft backend.</summary>
    private static AttestationVerifyDelegate BuildVerifier(
        ParseAndroidKeyAttestationStatementDelegate parseStatement,
        ValidateCertificateChainAsyncDelegate? validateChain,
        ReadCertificateExtensionValueDelegate? readExtensionValue,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation,
        bool requireTeeEnforcedAuthorizations) =>
        AndroidKeyAttestation.Build(
            parseStatement,
            validateChain ?? MicrosoftX509Functions.ValidateChainAsync,
            readExtensionValue ?? MicrosoftX509Functions.ReadCertificateExtensionValue,
            checkRevocation,
            completeChain: null,
            requireTeeEnforcedAuthorizations);


    /// <summary>Runs the android-key verifier for <paramref name="statement"/> and returns the raw result.</summary>
    private async Task<AttestationResult> VerifyAsync(
        AndroidKeyAttestationStatement statement,
        byte[] authDataBytes,
        AuthenticatorData authenticatorData,
        DigestValue clientDataHash,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        ValidateCertificateChainAsyncDelegate? validateChain = null,
        ReadCertificateExtensionValueDelegate? readExtensionValue = null,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation = null,
        bool requireTeeEnforcedAuthorizations = false)
    {
        AttestationVerifyDelegate verify = BuildVerifier(
            AndroidKeyAttestationTestVectors.CreateStatementParser(statement), validateChain, readExtensionValue, checkRevocation, requireTeeEnforcedAuthorizations);
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: trustAnchors, validationTime: TestClock.CanonicalEpoch);

        return await verify(request, TestContext.CancellationToken);
    }


    /// <summary>Runs <see cref="VerifyAsync(AndroidKeyAttestationStatement,byte[],AuthenticatorData,DigestValue,IReadOnlyList{PkiCertificateMemory},ValidateCertificateChainAsyncDelegate?,ReadCertificateExtensionValueDelegate?,CheckCertificateRevocationStatusAsyncDelegate?,bool)"/> and extracts the rejection error, if any.</summary>
    private async Task<Fido2AttestationError?> VerifyAndGetRejectionErrorAsync(
        AndroidKeyAttestationStatement statement,
        byte[] authDataBytes,
        AuthenticatorData authenticatorData,
        DigestValue clientDataHash,
        IReadOnlyList<PkiCertificateMemory> trustAnchors)
    {
        AttestationResult result = await VerifyAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors);

        return result is RejectedAttestationResult rejected ? rejected.Error : null;
    }
}
