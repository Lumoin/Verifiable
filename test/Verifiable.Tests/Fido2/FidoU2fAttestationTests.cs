using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.BouncyCastle;
using Verifiable.Cbor.Fido2;
using Verifiable.Cbor.Mdoc;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for the <c>fido-u2f</c> attestation statement format verifier (<see cref="FidoU2fAttestation"/>) and its
/// shipped CBOR default statement reader (<see cref="FidoU2fAttestationStatementCborReader"/>) — the
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation">WebAuthn L3 section 8.6</see>
/// verification procedure.
/// </summary>
/// <remarks>
/// Every fixture mints its certificate(s) and signature with an independent oracle — raw
/// <see cref="ECDsa"/>/<see cref="RSA"/> and <see cref="CertificateRequest"/>, never the library's own signing or
/// chain-building seams — so <see cref="FidoU2fAttestation"/> is exercised against genuinely external wire
/// material reconstructed solely from the <see cref="AttestationVerificationRequest"/>'s wire-shaped members, or
/// (for the one full-ceremony test) from raw <c>attestationObject</c>/<c>clientDataJSON</c> wire bytes through the
/// shipped default readers.
/// </remarks>
[TestClass]
internal sealed class FidoU2fAttestationTests
{
    /// <summary>The base64url-encoded challenge the full-ceremony test embeds and expects.</summary>
    private const string ValidChallenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX";

    /// <summary>The relying party origin the full-ceremony test embeds and expects.</summary>
    private const string ValidOrigin = "https://relyingparty.example";

    /// <summary>The correlation identifier the full-ceremony test's verification call uses.</summary>
    private const string CorrelationId = "fido-u2f-attestation-test-correlation";

    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>An <see cref="IsCredentialIdUniqueDelegate"/> reporting every credential ID as unique.</summary>
    private static IsCredentialIdUniqueDelegate AlwaysUnique { get; } = static (_, _) => ValueTask.FromResult(true);


    /// <summary>
    /// A conformant fido-u2f attestation — a single P-256 attestation certificate chaining to a trusted root,
    /// with a valid section 8.6 <c>verificationData</c> signature — verifies to <see cref="CertifiedAttestationResult"/>
    /// of type <see cref="AttestationType.Unknown"/> (owner ruling 6: Basic/AttCA determination is optional and this
    /// layer has no external knowledge to make it), carrying the single-element trust path.
    /// </summary>
    [TestMethod]
    public async Task ConformantAttestationReturnsCertifiedResultWithUnknownType()
    {
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test U2F Attestation Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);

        byte[] rpIdHash = authenticatorData.RpIdHash.AsReadOnlySpan().ToArray();
        byte[] credentialId = authenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
        byte[] verificationData = FidoU2fAttestationTestVectors.BuildVerificationData(
            rpIdHash, clientDataHash, credentialId, credentialPublicKey.X!.Value.Span, credentialPublicKey.Y!.Value.Span);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, verificationData);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new FidoU2fAttestationStatement(signature, [leafPki]);
        AttestationVerifyDelegate verify = BuildVerifier(FidoU2fAttestationTestVectors.CreateStatementParser(statement));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [rootPki], validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        Assert.IsInstanceOfType<CertifiedAttestationResult>(result);
        var certified = (CertifiedAttestationResult)result;
        Assert.AreEqual(AttestationType.Unknown, certified.Type);
        Assert.HasCount(1, certified.TrustPath);
        Assert.AreSame(leafPki, certified.TrustPath[0]);
    }


    /// <summary>
    /// A non-zero AAGUID does not cause a spurious rejection — the mirror image of every other attestation
    /// format's AAGUID handling: section 8.6 imposes no AAGUID check at all (fido-u2f predates AAGUIDs), and the
    /// CR's own section 16.16 test vector embeds a non-zero, HKDF-derived AAGUID. Pins owner ruling that
    /// <see cref="FidoU2fAttestation"/> adds no zero-AAGUID special case.
    /// </summary>
    [TestMethod]
    public async Task NonZeroAaguidDoesNotCauseSpuriousRejection()
    {
        Guid nonZeroAaguid = new("afb3c2ef-c054-df42-5013-d5c88e79c3c1");

        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test U2F Attestation Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(nonZeroAaguid, credentialPublicKey, out byte[] authDataBytes);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);

        Assert.AreNotEqual(Guid.Empty, authenticatorData.AttestedCredentialData!.Aaguid);

        byte[] rpIdHash = authenticatorData.RpIdHash.AsReadOnlySpan().ToArray();
        byte[] credentialId = authenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
        byte[] verificationData = FidoU2fAttestationTestVectors.BuildVerificationData(
            rpIdHash, clientDataHash, credentialId, credentialPublicKey.X!.Value.Span, credentialPublicKey.Y!.Value.Span);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, verificationData);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new FidoU2fAttestationStatement(signature, [leafPki]);
        AttestationVerifyDelegate verify = BuildVerifier(FidoU2fAttestationTestVectors.CreateStatementParser(statement));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [rootPki], validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        Assert.IsInstanceOfType<CertifiedAttestationResult>(result);
    }


    /// <summary>
    /// A wire <c>x5c</c> carrying the attestation certificate alone (no intermediate) still verifies when a
    /// <see cref="CertificateChainCompleter"/> supplies the missing intermediate and a <see cref="CrlRevocationChecker"/>
    /// reports both the leaf and the completed intermediate clean — the wave-2 revocation and chain-completion
    /// seams composing with <see cref="FidoU2fAttestation"/> exactly as they do with <see cref="PackedAttestation"/>.
    /// </summary>
    [TestMethod]
    public async Task LeafOnlyX5cWithChainCompleterAndCleanRevocationReturnsCertifiedResult()
    {
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test U2F Chain Root", rootKey);
        using X509Certificate2 intermediateCert = Fido2AttestationTestVectors.CreateIntermediateCaCertificate(rootCert, intermediateKey);
        X509Extension leafAuthorityKeyIdentifier = Fido2AttestationTestVectors.CreateLeafAuthorityKeyIdentifierExtension(intermediateCert);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            intermediateCert, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit,
            aaguidExtensionValue: null, additionalExtensions: [leafAuthorityKeyIdentifier]);

        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);

        byte[] rpIdHash = authenticatorData.RpIdHash.AsReadOnlySpan().ToArray();
        byte[] credentialId = authenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
        byte[] verificationData = FidoU2fAttestationTestVectors.BuildVerificationData(
            rpIdHash, clientDataHash, credentialId, credentialPublicKey.X!.Value.Span, credentialPublicKey.Y!.Value.Span);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, verificationData);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory intermediatePki = Fido2AttestationTestVectors.ToPkiCertificateMemory(intermediateCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        DateTimeOffset validationTime = new(2027, 6, 1, 0, 0, 0, TimeSpan.Zero);
        using PkiCertificateMemory cleanLeafCrl = SyntheticPassportFactory.MintCrl(
            intermediateCert, revokedCertificate: null, validationTime.AddDays(-1), validationTime.AddDays(30), crlNumber: 1);
        using PkiCertificateMemory cleanIntermediateCrl = SyntheticPassportFactory.MintCrl(
            rootCert, revokedCertificate: null, validationTime.AddDays(-1), validationTime.AddDays(30), crlNumber: 2);
        var checker = new CrlRevocationChecker([cleanLeafCrl, cleanIntermediateCrl]);
        var completer = new CertificateChainCompleter([intermediatePki]);

        var statement = new FidoU2fAttestationStatement(signature, [leafPki]);
        AttestationVerifyDelegate verify = BuildVerifier(FidoU2fAttestationTestVectors.CreateStatementParser(statement), checker.CheckAsync, completer.CompleteAsync);
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [rootPki], validationTime: validationTime);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        Assert.IsInstanceOfType<CertifiedAttestationResult>(result);
    }


    /// <summary>
    /// The capstone proof: a fido-u2f registration minted as real wire <c>attestationObject</c> and
    /// <c>clientDataJSON</c> bytes (no stub parser anywhere) verifies successfully end to end through
    /// <see cref="Fido2RegistrationVerifier.VerifyAsync"/>, composed with the shipped
    /// <see cref="AttestationObjectCborReader"/>, <see cref="FidoU2fAttestationStatementCborReader"/>, and
    /// <see cref="CredentialPublicKeyCborReader"/> defaults.
    /// </summary>
    [TestMethod]
    public async Task ShippedCborDefaultsComposeWithFidoU2fAttestationBuildEndToEndThroughRegistrationVerifier()
    {
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test U2F E2E Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);
        byte[] credentialId = [0x21, 0x22, 0x23, 0x24];
        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();
        byte flags = (byte)(AuthenticatorDataFlags.UserPresentBit | AuthenticatorDataFlags.UserVerifiedBit | AuthenticatorDataFlags.AttestedCredentialDataIncludedBit);
        byte[] credentialPublicKeyCbor = MdocCborCoseKeyWriter.Write(credentialPublicKey).ToArray();
        byte[] attestedCredentialDataBytes = Fido2TestVectors.BuildAttestedCredentialData(aaguid, credentialId, credentialPublicKeyCbor);
        byte[] authDataBytes = Fido2TestVectors.BuildAuthenticatorData(rpIdHash, flags, signCount: 0, attestedCredentialDataBytes);

        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Create, ValidChallenge, ValidOrigin, crossOrigin: null, topOrigin: null);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash(clientDataJson, BaseMemoryPool.Shared);

        byte[] verificationData = FidoU2fAttestationTestVectors.BuildVerificationData(
            rpIdHash, clientDataHash, credentialId, credentialPublicKey.X!.Value.Span, credentialPublicKey.Y!.Value.Span);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, verificationData);

        byte[] attStmtCbor;
        using(PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData))
        {
            attStmtCbor = FidoU2fAttestationStatementCborWriter.Write(signature, [leafPki]).Memory.ToArray();
        }
        byte[] attestationObjectBytes = Fido2AttestationTestVectors.EncodeAttestationObject(WellKnownWebAuthnAttestationFormats.FidoU2f, attStmtCbor, authDataBytes);

        AttestationObjectParts parts = AttestationObjectCborReader.Parse(attestationObjectBytes);
        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.FidoU2f, parts.Format);

        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(parts.AuthenticatorData, CredentialPublicKeyCborReader.Read, BaseMemoryPool.Shared);
        using RegistrationCeremonyInput ceremonyInput = new()
        {
            ClientData = ClientDataJsonReader.Read(clientDataJson),
            AuthenticatorData = authenticatorData,
            ExpectedChallenge = ValidChallenge,
            ExpectedOrigins = new HashSet<string> { ValidOrigin },
            ExpectedRpIdHash = Fido2TestVectors.WrapRpIdHash(rpIdHash, BaseMemoryPool.Shared),
            UserVerification = UserVerificationRequirement.Required,
            AllowedAlgorithms = [WellKnownCoseAlgorithms.Es256]
        };

        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        SelectAttestationVerifierDelegate selectVerifier = Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.FidoU2f, BuildVerifier(FidoU2fAttestationStatementCborReader.Parse)));

        Fido2RegistrationOutcome outcome = await Fido2RegistrationVerifier.VerifyAsync(
            WellKnownWebAuthnAttestationFormats.FidoU2f,
            attestationStatement: parts.AttestationStatement,
            authenticatorDataBytes: parts.AuthenticatorData,
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
        Assert.IsTrue(outcome.IsAcceptable);

        using Fido2CredentialRecord? record = outcome.CredentialRecord;
        Assert.IsNotNull(record);
    }


    /// <summary>A parse delegate that throws is rejected with <see cref="Fido2AttestationErrors.MalformedStatement"/>.</summary>
    [TestMethod]
    public async Task ThrowingParserIsRejectedWithMalformedStatement()
    {
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey: null, out byte[] authDataBytes);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);

        AttestationVerifyDelegate verify = BuildVerifier(FidoU2fAttestationTestVectors.CreateThrowingParser("malformed"));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [], validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        Assert.IsInstanceOfType<RejectedAttestationResult>(result);
        Assert.AreEqual(Fido2AttestationErrors.MalformedStatement.Code, ((RejectedAttestationResult)result).Error.Code);
    }


    /// <summary>Authenticator data with no attested credential data is rejected with <see cref="Fido2AttestationErrors.MissingAttestedCredentialData"/>.</summary>
    [TestMethod]
    public async Task MissingAttestedCredentialDataIsRejectedWithMissingAttestedCredentialData()
    {
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey: null, out byte[] authDataBytes);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);

        using ECDsa dummyKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 dummyCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test U2F Dummy", dummyKey);
        using PkiCertificateMemory dummyPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(dummyCert.RawData);

        var statement = new FidoU2fAttestationStatement(Signature: new byte[] { 1, 2, 3 }, X5c: [dummyPki]);
        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: [dummyPki]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.MissingAttestedCredentialData.Code, error.Code);
    }


    /// <summary>An empty trust anchor list is rejected with <see cref="Fido2AttestationErrors.NoTrustAnchors"/> before any chain building is attempted.</summary>
    [TestMethod]
    public async Task EmptyTrustAnchorsIsRejectedWithNoTrustAnchors()
    {
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 selfSignedLeaf = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test U2F Leaf", leafKey);
        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(selfSignedLeaf.RawData);

        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);

        var statement = new FidoU2fAttestationStatement(Signature: new byte[] { 1, 2, 3 }, X5c: [leafPki]);
        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: []);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.NoTrustAnchors.Code, error.Code);
    }


    /// <summary>A chain that does not build to any supplied trust anchor is rejected with <see cref="Fido2AttestationErrors.ChainValidationFailed"/>.</summary>
    [TestMethod]
    public async Task UntrustedRootIsRejectedWithChainValidationFailed()
    {
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa imposterRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test U2F Root", rootKey);
        using X509Certificate2 imposterRootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test U2F Imposter Root", imposterRootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory imposterRootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(imposterRootCert.RawData);

        var statement = new FidoU2fAttestationStatement(Signature: new byte[] { 1, 2, 3 }, X5c: [leafPki]);
        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: [imposterRootPki]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.ChainValidationFailed.Code, error.Code);
    }


    /// <summary>A P-384 attestation certificate is rejected with <see cref="Fido2AttestationErrors.AttestationCertificateKeyNotP256"/>.</summary>
    [TestMethod]
    public async Task P384AttestationCertificateIsRejectedWithAttestationCertificateKeyNotP256()
    {
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test U2F Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new FidoU2fAttestationStatement(Signature: new byte[] { 1, 2, 3 }, X5c: [leafPki]);
        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: [rootPki]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.AttestationCertificateKeyNotP256.Code, error.Code);
    }


    /// <summary>
    /// An RSA attestation certificate is rejected with <see cref="Fido2AttestationErrors.AttestationCertificateKeyNotP256"/> —
    /// a distinct, distinguishable failure from a generic signature failure, exercising the same check on a
    /// non-EC key family rather than only a wrong EC curve.
    /// </summary>
    [TestMethod]
    public async Task RsaAttestationCertificateIsRejectedWithAttestationCertificateKeyNotP256()
    {
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using RSA leafKey = RSA.Create(2048);
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test U2F Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificateWithRsaKey(
            rootCert, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new FidoU2fAttestationStatement(Signature: new byte[] { 1, 2, 3 }, X5c: [leafPki]);
        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: [rootPki]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.AttestationCertificateKeyNotP256.Code, error.Code);
    }


    /// <summary>A credential public key <c>x</c> coordinate shorter than 32 bytes is rejected with <see cref="Fido2AttestationErrors.CredentialCoordinateLengthInvalid"/>.</summary>
    [TestMethod]
    public async Task CredentialXCoordinateShorterThan32BytesIsRejectedWithCredentialCoordinateLengthInvalid()
    {
        Fido2AttestationError? error = await VerifyCoordinateLengthFixtureAsync(xLength: EllipticCurveConstants.P256.PointArrayLength - 1, yLength: EllipticCurveConstants.P256.PointArrayLength);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CredentialCoordinateLengthInvalid.Code, error.Code);
    }


    /// <summary>A credential public key <c>x</c> coordinate longer than 32 bytes is rejected with <see cref="Fido2AttestationErrors.CredentialCoordinateLengthInvalid"/>.</summary>
    [TestMethod]
    public async Task CredentialXCoordinateLongerThan32BytesIsRejectedWithCredentialCoordinateLengthInvalid()
    {
        Fido2AttestationError? error = await VerifyCoordinateLengthFixtureAsync(xLength: EllipticCurveConstants.P256.PointArrayLength + 1, yLength: EllipticCurveConstants.P256.PointArrayLength);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CredentialCoordinateLengthInvalid.Code, error.Code);
    }


    /// <summary>
    /// A credential public key <c>y</c> coordinate shorter than 32 bytes is rejected with
    /// <see cref="Fido2AttestationErrors.CredentialCoordinateLengthInvalid"/> — the symmetric case to the
    /// <c>x</c>-coordinate fixtures, proving the check applies to both coordinates independently.
    /// </summary>
    [TestMethod]
    public async Task CredentialYCoordinateShorterThan32BytesIsRejectedWithCredentialCoordinateLengthInvalid()
    {
        Fido2AttestationError? error = await VerifyCoordinateLengthFixtureAsync(xLength: EllipticCurveConstants.P256.PointArrayLength, yLength: EllipticCurveConstants.P256.PointArrayLength - 1);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CredentialCoordinateLengthInvalid.Code, error.Code);
    }


    /// <summary>
    /// A signature computed over <c>verificationData</c> built from a different <c>credentialId</c> than the one
    /// authenticator data actually reports is rejected with <see cref="Fido2AttestationErrors.InvalidSignature"/> —
    /// proving the verifier reconstructs <c>verificationData</c> from the wire <c>authData</c>, not from a cached
    /// or re-derived value.
    /// </summary>
    [TestMethod]
    public async Task TamperedCredentialIdInSignedTranscriptIsRejectedWithInvalidSignature()
    {
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test U2F Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);

        byte[] rpIdHash = authenticatorData.RpIdHash.AsReadOnlySpan().ToArray();
        byte[] tamperedCredentialId = [0xFF, 0xFE, 0xFD, 0xFC];
        byte[] tamperedVerificationData = FidoU2fAttestationTestVectors.BuildVerificationData(
            rpIdHash, clientDataHash, tamperedCredentialId, credentialPublicKey.X!.Value.Span, credentialPublicKey.Y!.Value.Span);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, tamperedVerificationData);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new FidoU2fAttestationStatement(signature, [leafPki]);
        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: [rootPki]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.InvalidSignature.Code, error.Code);
    }


    /// <summary>
    /// A signature computed over <c>verificationData</c> built from a different <c>rpIdHash</c> than the one
    /// authenticator data actually reports is rejected with <see cref="Fido2AttestationErrors.InvalidSignature"/>.
    /// </summary>
    [TestMethod]
    public async Task TamperedRpIdHashInSignedTranscriptIsRejectedWithInvalidSignature()
    {
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test U2F Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);

        byte[] tamperedRpIdHash = authenticatorData.RpIdHash.AsReadOnlySpan().ToArray();
        tamperedRpIdHash[0] ^= 0xFF;
        byte[] credentialId = authenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
        byte[] tamperedVerificationData = FidoU2fAttestationTestVectors.BuildVerificationData(
            tamperedRpIdHash, clientDataHash, credentialId, credentialPublicKey.X!.Value.Span, credentialPublicKey.Y!.Value.Span);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, tamperedVerificationData);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new FidoU2fAttestationStatement(signature, [leafPki]);
        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: [rootPki]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.InvalidSignature.Code, error.Code);
    }


    /// <summary>
    /// A signature computed over <c>verificationData</c> built from a different <c>clientDataHash</c> than the
    /// one the request actually carries is rejected with <see cref="Fido2AttestationErrors.InvalidSignature"/>.
    /// </summary>
    [TestMethod]
    public async Task TamperedClientDataHashInSignedTranscriptIsRejectedWithInvalidSignature()
    {
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test U2F Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using DigestValue tamperedClientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([9, 9, 9], BaseMemoryPool.Shared);

        byte[] rpIdHash = authenticatorData.RpIdHash.AsReadOnlySpan().ToArray();
        byte[] credentialId = authenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
        byte[] tamperedVerificationData = FidoU2fAttestationTestVectors.BuildVerificationData(
            rpIdHash, tamperedClientDataHash, credentialId, credentialPublicKey.X!.Value.Span, credentialPublicKey.Y!.Value.Span);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, tamperedVerificationData);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new FidoU2fAttestationStatement(signature, [leafPki]);
        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: [rootPki]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.InvalidSignature.Code, error.Code);
    }


    /// <summary>
    /// A fixed-width IEEE P1363-encoded signature (never DER, as section 6.5.5 requires) is rejected with
    /// <see cref="Fido2AttestationErrors.InvalidSignature"/> rather than throwing — the wire-encoding-confusion
    /// fixture, proving <see cref="Fido2EcdsaWireSignature.WrapWireSignatureForVerification"/>'s DER-to-P1363
    /// conversion fails closed on an already-P1363 value instead of crashing.
    /// </summary>
    [TestMethod]
    public async Task P1363EncodedSignatureIsRejectedWithInvalidSignature()
    {
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test U2F Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);

        byte[] rpIdHash = authenticatorData.RpIdHash.AsReadOnlySpan().ToArray();
        byte[] credentialId = authenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
        byte[] verificationData = FidoU2fAttestationTestVectors.BuildVerificationData(
            rpIdHash, clientDataHash, credentialId, credentialPublicKey.X!.Value.Span, credentialPublicKey.Y!.Value.Span);
        byte[] p1363Signature = leafKey.SignData(verificationData, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new FidoU2fAttestationStatement(p1363Signature, [leafPki]);
        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: [rootPki]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.InvalidSignature.Code, error.Code);
    }


    /// <summary>An <c>x5c</c> array with zero elements is rejected by the shipped default reader.</summary>
    [TestMethod]
    public void StatementDefaultRejectsAnEmptyX5cArray()
    {
        //Hand-encoded directly: the shipped writer enforces exactly one x5c element by construction and
        //could never produce this shape, so the fixture is an oracle independent of it.
        byte[] cbor = FidoU2fAttestationTestVectors.EncodeFidoU2fAttStmtRaw(sig: [1, 2, 3]);

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => FidoU2fAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared));

        Assert.Contains("exactly one element", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>An <c>x5c</c> array with two elements is rejected by the shipped default reader.</summary>
    [TestMethod]
    public void StatementDefaultRejectsAnX5cArrayWithTwoElements()
    {
        //Hand-encoded directly: the shipped writer enforces exactly one x5c element by construction and
        //could never produce this shape, so the fixture is an oracle independent of it.
        byte[] cbor = FidoU2fAttestationTestVectors.EncodeFidoU2fAttStmtRaw(sig: [1, 2, 3], x5cEntries: [[9, 9, 9], [8, 8, 8]]);

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => FidoU2fAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared));

        Assert.Contains("exactly one element", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A statement missing the required <c>sig</c> member is rejected by the shipped default reader.</summary>
    [TestMethod]
    public void StatementDefaultRejectsAMissingSigMember()
    {
        //Hand-encoded directly: the shipped writer always writes both required members, so a map missing
        //sig is a shape only a raw, writer-independent encoder can produce.
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(1);
        writer.WriteTextString("x5c");
        writer.WriteStartArray(1);
        writer.WriteByteString([1, 2, 3]);
        writer.WriteEndArray();
        writer.WriteEndMap();
        byte[] cbor = writer.Encode();

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => FidoU2fAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared));

        Assert.Contains("x5c", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A statement missing the required <c>x5c</c> member is rejected by the shipped default reader.</summary>
    [TestMethod]
    public void StatementDefaultRejectsAMissingX5cMember()
    {
        //Hand-encoded directly: the shipped writer always writes both required members, so a map missing
        //x5c is a shape only a raw, writer-independent encoder can produce.
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(1);
        writer.WriteTextString("sig");
        writer.WriteByteString([1, 2, 3]);
        writer.WriteEndMap();
        byte[] cbor = writer.Encode();

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => FidoU2fAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared));

        Assert.Contains("x5c", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A statement carrying an unrecognised member is rejected by the shipped default reader.</summary>
    [TestMethod]
    public void StatementDefaultRejectsAnUnrecognisedMember()
    {
        //Hand-encoded directly: the shipped writer only ever emits sig/x5c, so a map carrying an
        //unrecognised member is a shape only a raw, writer-independent encoder can produce.
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(3);
        writer.WriteTextString("foo");
        writer.WriteBoolean(true);
        writer.WriteTextString("sig");
        writer.WriteByteString([1, 2, 3]);
        writer.WriteTextString("x5c");
        writer.WriteStartArray(1);
        writer.WriteByteString([9, 9, 9]);
        writer.WriteEndArray();
        writer.WriteEndMap();
        byte[] cbor = writer.Encode();

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => FidoU2fAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared));

        Assert.Contains("foo", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A byte trailing an otherwise-valid statement map is rejected by the shipped default reader.</summary>
    [TestMethod]
    public void StatementDefaultRejectsTrailingBytes()
    {
        //Hand-encoded directly rather than through the shipped writer: the corruption below (an appended
        //trailing byte) is the fixture under test, independent of whichever encoder built the valid prefix.
        byte[] valid = FidoU2fAttestationTestVectors.EncodeFidoU2fAttStmtRaw(sig: [1, 2, 3], x5cEntries: [[9, 9, 9]]);
        byte[] withTrailingByte = [.. valid, 0xFF];

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => FidoU2fAttestationStatementCborReader.Parse(withTrailingByte, BaseMemoryPool.Shared));

        Assert.Contains("trailing", exception.Message, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>The shipped default reader parses a minted, conformant statement — the positive control for the reader alone.</summary>
    [TestMethod]
    public void StatementDefaultParsesAMintedStatement()
    {
        byte[] signature = [1, 2, 3, 4, 5, 6, 7, 8];
        byte[] certificateBytes = [9, 8, 7, 6, 5];
        using PkiCertificateMemory certificate = Fido2AttestationTestVectors.ToPkiCertificateMemory(certificateBytes);
        TaggedMemory<byte> cbor = FidoU2fAttestationStatementCborWriter.Write(signature, [certificate]);

        FidoU2fAttestationStatement statement = FidoU2fAttestationStatementCborReader.Parse(cbor.Memory, BaseMemoryPool.Shared);
        try
        {
            Assert.IsTrue(statement.Signature.Span.SequenceEqual(signature));
            Assert.HasCount(1, statement.X5c);
            Assert.IsTrue(statement.X5c[0].IsX509Certificate);
            Assert.IsTrue(statement.X5c[0].AsReadOnlySpan().SequenceEqual(certificateBytes));
        }
        finally
        {
            foreach(PkiCertificateMemory decodedCertificate in statement.X5c)
            {
                decodedCertificate.Dispose();
            }
        }
    }


    /// <summary>Builds the <see cref="FidoU2fAttestation"/> verifier under given seams.</summary>
    /// <param name="parseStatement">The statement parser to wire in.</param>
    /// <param name="checkRevocation">The revocation seam to wire, or <see langword="null"/> for none.</param>
    /// <param name="completeChain">The chain-completion seam to wire, or <see langword="null"/> for none.</param>
    /// <returns>The assembled <see cref="AttestationVerifyDelegate"/>.</returns>
    private static AttestationVerifyDelegate BuildVerifier(
        ParseFidoU2fAttestationStatementDelegate parseStatement,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation = null,
        CompleteCertificateChainAsyncDelegate? completeChain = null) =>
        FidoU2fAttestation.Build(parseStatement, MicrosoftX509Functions.ValidateChainAsync, checkRevocation, completeChain);


    /// <summary>Runs the verifier for <paramref name="statement"/> and returns the rejection error, if any.</summary>
    /// <param name="statement">The pre-built statement the stub parser returns.</param>
    /// <param name="authDataBytes">The raw <c>authData</c> bytes.</param>
    /// <param name="authenticatorData">The parsed <c>authData</c> view.</param>
    /// <param name="clientDataHash">The <c>clientDataHash</c> digest.</param>
    /// <param name="trustAnchors">The trust anchors to verify chain building against.</param>
    /// <returns>The <see cref="Fido2AttestationError"/> of a <see cref="RejectedAttestationResult"/>, or <see langword="null"/>.</returns>
    private async Task<Fido2AttestationError?> VerifyAndGetRejectionErrorAsync(
        FidoU2fAttestationStatement statement,
        byte[] authDataBytes,
        AuthenticatorData authenticatorData,
        DigestValue clientDataHash,
        IReadOnlyList<PkiCertificateMemory> trustAnchors)
    {
        AttestationVerifyDelegate verify = BuildVerifier(FidoU2fAttestationTestVectors.CreateStatementParser(statement));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: trustAnchors, validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        return result is RejectedAttestationResult rejected ? rejected.Error : null;
    }


    /// <summary>
    /// Mints a conformant P-256 root/leaf chain and a hand-built credential public key whose <c>x</c>/<c>y</c>
    /// coordinates are <paramref name="xLength"/>/<paramref name="yLength"/> bytes, then runs the verifier and
    /// returns the rejection error, if any — the shared body for the coordinate-length negative fixtures.
    /// </summary>
    /// <param name="xLength">The byte length to give the credential public key's <c>x</c> coordinate.</param>
    /// <param name="yLength">The byte length to give the credential public key's <c>y</c> coordinate.</param>
    /// <returns>The <see cref="Fido2AttestationError"/> of a <see cref="RejectedAttestationResult"/>, or <see langword="null"/>.</returns>
    private async Task<Fido2AttestationError?> VerifyCoordinateLengthFixtureAsync(int xLength, int yLength)
    {
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test U2F Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        CoseKey credentialPublicKey = FidoU2fAttestationTestVectors.CreateP256CoseKeyWithCoordinateLengths(xLength, yLength);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new FidoU2fAttestationStatement(Signature: new byte[] { 1, 2, 3 }, X5c: [leafPki]);

        return await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: [rootPki]);
    }
}
