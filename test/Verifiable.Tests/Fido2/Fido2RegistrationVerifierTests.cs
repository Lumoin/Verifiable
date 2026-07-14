using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cbor.Mdoc;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Firewalled end-to-end tests for <see cref="Fido2RegistrationVerifier"/>: the WebAuthn L3
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">section 7.1</see>
/// registration ceremony orchestrator, composed of the attestation statement verification in
/// <see cref="PackedAttestation"/>/<see cref="NoneAttestation"/>, the surface-field rules in
/// <see cref="Fido2ValidationProfiles.RegistrationRules"/>, and the RP-supplied
/// <see cref="IsCredentialIdUniqueDelegate"/>.
/// </summary>
/// <remarks>
/// Every test reconstructs the ceremony input from wire bytes only — a real <c>clientDataJSON</c>
/// parsed via <see cref="ClientDataJsonReader"/> and a real <c>authData</c> binary layout built via
/// <see cref="Fido2TestVectors"/> — and mints attestation statements with an independent oracle
/// (raw <see cref="ECDsa"/>/<see cref="CertificateRequest"/>, never the library's own signing or
/// chain-building seams), reusing the WAVE 3 <see cref="Fido2AttestationTestVectors"/> and
/// <see cref="Fido2TestVectors"/> infrastructure. The outer <c>attestationObject</c> CBOR
/// (<c>fmt</c>/<c>attStmt</c>/<c>authData</c>) decode is out of scope — this library's CBOR codec
/// is deferred — so, mirroring <c>PackedSelfAttestationTests</c>/<c>PackedCertifiedAttestationTests</c>,
/// the raw <c>attStmt</c> bytes handed to <see cref="Fido2RegistrationVerifier.VerifyAsync"/> are a
/// placeholder and the real <see cref="PackedAttestationStatement"/> is threaded through a stub
/// <see cref="ParsePackedAttestationStatementDelegate"/>.
/// </remarks>
[TestClass]
internal sealed class Fido2RegistrationVerifierTests
{
    /// <summary>The canonical CTAP2 CBOR encoding of the empty map, the only <c>attStmt</c> the <c>none</c> format accepts.</summary>
    internal const byte CanonicalEmptyMap = 0xA0;

    /// <summary>The base64url-encoded challenge a valid ceremony embeds and expects.</summary>
    private const string ValidChallenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX";

    /// <summary>The relying party origin a valid ceremony embeds and expects.</summary>
    internal const string ValidOrigin = "https://relyingparty.example";

    /// <summary>The correlation identifier every verification call in this fixture uses.</summary>
    internal const string CorrelationId = "fido2-registration-verifier-test-correlation";

    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>An <see cref="IsCredentialIdUniqueDelegate"/> reporting every credential ID as unique.</summary>
    internal static IsCredentialIdUniqueDelegate AlwaysUnique { get; } = static (_, _) => ValueTask.FromResult(true);

    /// <summary>An <see cref="IsCredentialIdUniqueDelegate"/> reporting every credential ID as already registered.</summary>
    private static IsCredentialIdUniqueDelegate AlwaysDuplicate { get; } = static (_, _) => ValueTask.FromResult(false);


    /// <summary>
    /// A <c>none</c>-attestation registration with valid surface fields is acceptable: the
    /// attestation result is <see cref="NoneAttestationResult"/>, no claim fails, and the built
    /// credential record's fields match the minted <c>authData</c> exactly.
    /// </summary>
    [TestMethod]
    public async Task ValidNoneAttestationRegistrationIsAcceptableWithPopulatedCredentialRecord()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(credentialKeys.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);
        MdocTestFixtures.DisposeKeyMaterial(credentialKeys);
        Guid aaguid = Guid.NewGuid();
        byte[] credentialId = [0x0A, 0x0B, 0x0C, 0x0D];
        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();

        using AuthenticatorData authenticatorData = BuildRegistrationAuthenticatorData(
            rpIdHash, aaguid, credentialPublicKey, credentialId, out byte[] authDataBytes, signCount: 3, backupEligible: true, backupState: true);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Create, ValidChallenge, ValidOrigin);
        using RegistrationCeremonyInput ceremonyInput = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataOverride: ClientDataJsonReader.Read(clientDataJson),
            authenticatorDataOverride: authenticatorData,
            expectedRpIdHash: rpIdHash);

        SelectAttestationVerifierDelegate selectVerifier = Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.None, NoneAttestation.Build()));

        Fido2RegistrationOutcome outcome = await Fido2RegistrationVerifier.VerifyAsync(
            WellKnownWebAuthnAttestationFormats.None,
            attestationStatement: new byte[] { CanonicalEmptyMap },
            authDataBytes,
            clientDataJson,
            ceremonyInput,
            selectVerifier,
            AlwaysUnique,
            trustAnchors: [],
            validationTime: TestClock.CanonicalEpoch,
            CorrelationId,
            BaseMemoryPool.Shared,
            transports: ["internal", "hybrid"],
            cancellationToken: TestContext.CancellationToken);

        Assert.IsInstanceOfType<NoneAttestationResult>(outcome.AttestationResult);
        Assert.IsTrue(outcome.IsAcceptable);
        Assert.IsFalse(HasFailureClaim(outcome.Claims));

        using Fido2CredentialRecord? record = outcome.CredentialRecord;
        Assert.IsNotNull(record);
        Assert.AreEqual(WellKnownPublicKeyCredentialTypes.PublicKey, record.Type);
        Assert.IsTrue(credentialId.AsSpan().SequenceEqual(record.Id.AsReadOnlySpan()));
        Assert.AreSame(credentialPublicKey, record.PublicKey);
        Assert.AreEqual(3u, record.SignCount);
        Assert.IsTrue(record.UvInitialized);
        Assert.HasCount(2, record.Transports);
        Assert.IsTrue(record.BackupEligible);
        Assert.IsTrue(record.BackupState);
    }


    /// <summary>
    /// A registration whose reported transports include a string outside the
    /// <see href="https://www.w3.org/TR/webauthn-3/#enum-transport">section 5.8.4</see>
    /// <c>AuthenticatorTransport</c> enumeration is still acceptable, and the credential record
    /// carries that unknown string verbatim: transports come from the client response, not
    /// <c>authData</c>, so this layer has no registry to validate them against and stores whatever
    /// the caller supplies (tally clause 3353).
    /// </summary>
    [TestMethod]
    public async Task UnknownTransportStringIsAcceptedAndPersistedVerbatimInCredentialRecord()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(credentialKeys.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);
        MdocTestFixtures.DisposeKeyMaterial(credentialKeys);
        Guid aaguid = Guid.NewGuid();
        byte[] credentialId = [0x0B, 0x0C, 0x0D, 0x0E];
        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();

        using AuthenticatorData authenticatorData = BuildRegistrationAuthenticatorData(rpIdHash, aaguid, credentialPublicKey, credentialId, out byte[] authDataBytes);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Create, ValidChallenge, ValidOrigin);
        using RegistrationCeremonyInput ceremonyInput = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataOverride: ClientDataJsonReader.Read(clientDataJson),
            authenticatorDataOverride: authenticatorData,
            expectedRpIdHash: rpIdHash);

        SelectAttestationVerifierDelegate selectVerifier = Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.None, NoneAttestation.Build()));

        string[] reportedTransports = ["usb", "vendor-proprietary-transport"];
        Fido2RegistrationOutcome outcome = await Fido2RegistrationVerifier.VerifyAsync(
            WellKnownWebAuthnAttestationFormats.None,
            attestationStatement: new byte[] { CanonicalEmptyMap },
            authDataBytes,
            clientDataJson,
            ceremonyInput,
            selectVerifier,
            AlwaysUnique,
            trustAnchors: [],
            validationTime: TestClock.CanonicalEpoch,
            CorrelationId,
            BaseMemoryPool.Shared,
            transports: reportedTransports,
            cancellationToken: TestContext.CancellationToken);

        Assert.IsInstanceOfType<NoneAttestationResult>(outcome.AttestationResult);
        Assert.IsTrue(outcome.IsAcceptable);

        using Fido2CredentialRecord? record = outcome.CredentialRecord;
        Assert.IsNotNull(record);
        Assert.HasCount(2, record.Transports);
        Assert.AreEqual("usb", record.Transports[0]);
        Assert.AreEqual("vendor-proprietary-transport", record.Transports[1]);
    }


    /// <summary>
    /// A <c>packed</c> self-attestation (no <c>x5c</c>) registration with a valid signature and
    /// matching <c>alg</c> is acceptable and reports <see cref="SelfAttestationResult"/>.
    /// </summary>
    [TestMethod]
    public async Task ValidPackedSelfAttestationRegistrationIsAcceptable()
    {
        //Independent oracle: signs the self-attestation statement below (SignWithEcdsaP256), never the library's own signing seam.
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);
        Guid aaguid = Guid.NewGuid();
        byte[] credentialId = [0x01, 0x02, 0x03, 0x04];
        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();

        using AuthenticatorData authenticatorData = BuildRegistrationAuthenticatorData(rpIdHash, aaguid, credentialPublicKey, credentialId, out byte[] authDataBytes);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Create, ValidChallenge, ValidOrigin);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash(clientDataJson, BaseMemoryPool.Shared);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(credentialKey, toBeSigned);
        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signature, X5c: null);

        using RegistrationCeremonyInput ceremonyInput = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataOverride: ClientDataJsonReader.Read(clientDataJson),
            authenticatorDataOverride: authenticatorData,
            expectedRpIdHash: rpIdHash);
        SelectAttestationVerifierDelegate selectVerifier = Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.Packed, BuildPackedVerifier(statement)));

        Fido2RegistrationOutcome outcome = await Fido2RegistrationVerifier.VerifyAsync(
            WellKnownWebAuthnAttestationFormats.Packed,
            attestationStatement: ReadOnlyMemory<byte>.Empty,
            authDataBytes,
            clientDataJson,
            ceremonyInput,
            selectVerifier,
            AlwaysUnique,
            trustAnchors: [],
            validationTime: TestClock.CanonicalEpoch,
            CorrelationId,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.IsInstanceOfType<SelfAttestationResult>(outcome.AttestationResult);
        Assert.IsTrue(outcome.IsAcceptable);
        using Fido2CredentialRecord? record = outcome.CredentialRecord;
        Assert.IsNotNull(record);
        Assert.AreSame(credentialPublicKey, record.PublicKey);
    }


    /// <summary>
    /// A <c>packed</c> certified (<c>x5c</c>-present) registration whose chain validates against
    /// the supplied trust anchors is acceptable and reports <see cref="CertifiedAttestationResult"/>,
    /// with the credential record carrying the credential's own public key — distinct from the
    /// attestation certificate's key that signed the statement.
    /// </summary>
    [TestMethod]
    public async Task ValidPackedCertifiedAttestationRegistrationIsAcceptable()
    {
        //Cert-factory carve-out: feeds CreateSelfSignedCa (CertificateRequest) to mint the trust-anchor root.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        //Cert-factory + independent-oracle carve-out: feeds CreateLeafAttestationCertificate and signs the attestation statement below.
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        Guid aaguid = Guid.NewGuid();
        byte[] credentialId = [0x05, 0x06, 0x07, 0x08];
        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguid);

        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(credentialKeys.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);
        MdocTestFixtures.DisposeKeyMaterial(credentialKeys);
        using AuthenticatorData authenticatorData = BuildRegistrationAuthenticatorData(rpIdHash, aaguid, credentialPublicKey, credentialId, out byte[] authDataBytes);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Create, ValidChallenge, ValidOrigin);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash(clientDataJson, BaseMemoryPool.Shared);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, toBeSigned);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signature, X5c: [leafPki, rootPki]);

        using RegistrationCeremonyInput ceremonyInput = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataOverride: ClientDataJsonReader.Read(clientDataJson),
            authenticatorDataOverride: authenticatorData,
            expectedRpIdHash: rpIdHash);
        SelectAttestationVerifierDelegate selectVerifier = Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.Packed, BuildPackedVerifier(statement)));

        Fido2RegistrationOutcome outcome = await Fido2RegistrationVerifier.VerifyAsync(
            WellKnownWebAuthnAttestationFormats.Packed,
            attestationStatement: ReadOnlyMemory<byte>.Empty,
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
        Assert.IsTrue(outcome.IsAcceptable);
        using Fido2CredentialRecord? record = outcome.CredentialRecord;
        Assert.IsNotNull(record);
        Assert.AreSame(credentialPublicKey, record.PublicKey);
    }


    /// <summary>
    /// A packed-certified registration whose trust path has no configured anchors is rejected with
    /// <see cref="Fido2AttestationErrors.NoTrustAnchors"/> when the relying party's downgrade knob is
    /// off (the default) — today's fail-closed rejection, unchanged.
    /// </summary>
    [TestMethod]
    public async Task UntrustedPackedCertifiedAttestationWithDowngradeKnobOffIsRejected()
    {
        Fido2RegistrationOutcome outcome = await VerifyPackedCertifiedForDowngradeAsync(
            acceptsUntrustedAttestationAsNone: false, tamperSignature: false, suppliesValidTrustAnchor: false);

        Assert.IsInstanceOfType<RejectedAttestationResult>(outcome.AttestationResult);
        Assert.AreEqual(Fido2AttestationErrors.NoTrustAnchors.Code, ((RejectedAttestationResult)outcome.AttestationResult).Error.Code);
        Assert.IsFalse(outcome.IsAcceptable);
        Assert.IsNull(outcome.CredentialRecord);
        Assert.AreEqual(ClaimOutcome.Failure, GetClaimOutcome(outcome.Claims, Fido2ClaimIds.Fido2RegistrationAttestationTrustworthy));
        Assert.IsFalse(HasClaim(outcome.Claims, Fido2ClaimIds.Fido2RegistrationAttestationDowngraded));
    }


    /// <summary>
    /// A packed-certified registration whose trust path has no configured anchors is ACCEPTABLE, with
    /// the attestation downgraded to a <see cref="NoneAttestationResult"/> carrying a
    /// <see cref="Fido2AttestationDowngrade"/> marker, when the relying party opts into the downgrade
    /// knob: the §7.1 trust-gate rule sees the none-equivalent verdict (fixing the line-124-shaped
    /// second gate in the same motion — a credential record IS built), and
    /// <see cref="Fido2ClaimIds.Fido2RegistrationAttestationDowngraded"/> records the original format
    /// and trust-path error for relying-party audit.
    /// </summary>
    [TestMethod]
    public async Task UntrustedPackedCertifiedAttestationWithDowngradeKnobOnIsAcceptableAndEmitsDowngradedClaim()
    {
        Fido2RegistrationOutcome outcome = await VerifyPackedCertifiedForDowngradeAsync(
            acceptsUntrustedAttestationAsNone: true, tamperSignature: false, suppliesValidTrustAnchor: false);

        NoneAttestationResult noneResult = Assert.IsInstanceOfType<NoneAttestationResult>(outcome.AttestationResult);
        Assert.IsNotNull(noneResult.Downgrade);
        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.Packed, noneResult.Downgrade.Format);
        Assert.AreEqual(Fido2AttestationErrors.NoTrustAnchors.Code, noneResult.Downgrade.OriginalError.Code);

        Assert.IsTrue(outcome.IsAcceptable);
        using Fido2CredentialRecord? record = outcome.CredentialRecord;
        Assert.IsNotNull(record);

        Assert.AreEqual(ClaimOutcome.Success, GetClaimOutcome(outcome.Claims, Fido2ClaimIds.Fido2RegistrationAttestationTrustworthy));
        Claim downgradedClaim = GetClaim(outcome.Claims, Fido2ClaimIds.Fido2RegistrationAttestationDowngraded);
        Assert.AreEqual(ClaimOutcome.Success, downgradedClaim.Outcome);
        Fido2AttestationDowngradeClaimContext context = Assert.IsInstanceOfType<Fido2AttestationDowngradeClaimContext>(downgradedClaim.Context);
        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.Packed, context.Downgrade.Format);
        Assert.AreEqual(Fido2AttestationErrors.NoTrustAnchors.Code, context.Downgrade.OriginalError.Code);
    }


    /// <summary>
    /// A packed-certified registration whose trust path fails to build to the ONE supplied anchor —
    /// an unrelated, independently self-signed root, never an issuer of the minted leaf — is ACCEPTABLE
    /// with the same downgrade shape as <see cref="UntrustedPackedCertifiedAttestationWithDowngradeKnobOnIsAcceptableAndEmitsDowngradedClaim"/>,
    /// confirming the row-6107 downgrade knob treats <see cref="Fido2AttestationErrors.ChainValidationFailed"/>
    /// identically to <see cref="Fido2AttestationErrors.NoTrustAnchors"/> — both are the two eligible
    /// trust-path-shortfall reasons, not just the one already covered above.
    /// </summary>
    [TestMethod]
    public async Task UntrustedPackedCertifiedAttestationWithChainValidationFailedAndDowngradeKnobOnIsAcceptableAndEmitsDowngradedClaim()
    {
        Fido2RegistrationOutcome outcome = await VerifyPackedCertifiedForDowngradeAsync(
            acceptsUntrustedAttestationAsNone: true, tamperSignature: false, suppliesValidTrustAnchor: false, suppliesImposterTrustAnchor: true);

        NoneAttestationResult noneResult = Assert.IsInstanceOfType<NoneAttestationResult>(outcome.AttestationResult);
        Assert.IsNotNull(noneResult.Downgrade);
        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.Packed, noneResult.Downgrade.Format);
        Assert.AreEqual(Fido2AttestationErrors.ChainValidationFailed.Code, noneResult.Downgrade.OriginalError.Code);

        Assert.IsTrue(outcome.IsAcceptable);
        using Fido2CredentialRecord? record = outcome.CredentialRecord;
        Assert.IsNotNull(record);

        Assert.AreEqual(ClaimOutcome.Success, GetClaimOutcome(outcome.Claims, Fido2ClaimIds.Fido2RegistrationAttestationTrustworthy));
        Claim downgradedClaim = GetClaim(outcome.Claims, Fido2ClaimIds.Fido2RegistrationAttestationDowngraded);
        Assert.AreEqual(ClaimOutcome.Success, downgradedClaim.Outcome);
        Fido2AttestationDowngradeClaimContext context = Assert.IsInstanceOfType<Fido2AttestationDowngradeClaimContext>(downgradedClaim.Context);
        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.Packed, context.Downgrade.Format);
        Assert.AreEqual(Fido2AttestationErrors.ChainValidationFailed.Code, context.Downgrade.OriginalError.Code);
    }


    /// <summary>
    /// A packed-certified registration with a VALID trust path but a tampered attestation signature is
    /// still rejected with <see cref="Fido2AttestationErrors.InvalidSignature"/> even with the
    /// downgrade knob on: only the two trust-path-shortfall reasons are eligible for downgrade — an
    /// invalid signature never is, regardless of the knob.
    /// </summary>
    [TestMethod]
    public async Task InvalidSignaturePackedCertifiedAttestationWithDowngradeKnobOnIsStillRejected()
    {
        Fido2RegistrationOutcome outcome = await VerifyPackedCertifiedForDowngradeAsync(
            acceptsUntrustedAttestationAsNone: true, tamperSignature: true, suppliesValidTrustAnchor: true);

        Assert.IsInstanceOfType<RejectedAttestationResult>(outcome.AttestationResult);
        Assert.AreEqual(Fido2AttestationErrors.InvalidSignature.Code, ((RejectedAttestationResult)outcome.AttestationResult).Error.Code);
        Assert.IsFalse(outcome.IsAcceptable);
        Assert.IsNull(outcome.CredentialRecord);
        Assert.IsFalse(HasClaim(outcome.Claims, Fido2ClaimIds.Fido2RegistrationAttestationDowngraded));
    }


    /// <summary>
    /// A credential ID the relying party's storage already knows about (<see cref="AlwaysDuplicate"/>)
    /// fails <see cref="Fido2ClaimIds.Fido2RegistrationCredentialIdUnique"/> specifically, even
    /// though the attestation and every other surface-field claim succeed, and no credential
    /// record is built.
    /// </summary>
    [TestMethod]
    public async Task DuplicateCredentialIdFailsCredentialIdUniqueClaimAndYieldsNoCredentialRecord()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(credentialKeys.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);
        MdocTestFixtures.DisposeKeyMaterial(credentialKeys);
        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();

        using AuthenticatorData authenticatorData = BuildRegistrationAuthenticatorData(rpIdHash, Guid.NewGuid(), credentialPublicKey, [0x01], out byte[] authDataBytes);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Create, ValidChallenge, ValidOrigin);
        using RegistrationCeremonyInput ceremonyInput = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataOverride: ClientDataJsonReader.Read(clientDataJson),
            authenticatorDataOverride: authenticatorData,
            expectedRpIdHash: rpIdHash);

        SelectAttestationVerifierDelegate selectVerifier = Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.None, NoneAttestation.Build()));

        Fido2RegistrationOutcome outcome = await Fido2RegistrationVerifier.VerifyAsync(
            WellKnownWebAuthnAttestationFormats.None,
            attestationStatement: new byte[] { CanonicalEmptyMap },
            authDataBytes,
            clientDataJson,
            ceremonyInput,
            selectVerifier,
            AlwaysDuplicate,
            trustAnchors: [],
            validationTime: TestClock.CanonicalEpoch,
            CorrelationId,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.IsInstanceOfType<NoneAttestationResult>(outcome.AttestationResult);
        Assert.IsFalse(outcome.IsAcceptable);
        Assert.IsNull(outcome.CredentialRecord);
        Assert.AreEqual(ClaimOutcome.Failure, GetClaimOutcome(outcome.Claims, Fido2ClaimIds.Fido2RegistrationCredentialIdUnique));
        AssertOnlyClaimFails(outcome.Claims, Fido2ClaimIds.Fido2RegistrationCredentialIdUnique);
    }


    /// <summary>
    /// A tampered self-attestation signature is rejected with
    /// <see cref="Fido2AttestationErrors.InvalidSignature"/>: the outcome carries the specific
    /// <see cref="RejectedAttestationResult"/>, the attestation-trustworthy claim fails, and the
    /// outcome is unacceptable with no credential record.
    /// </summary>
    [TestMethod]
    public async Task TamperedSelfAttestationSignatureIsRejectedWithInvalidSignature()
    {
        //Independent oracle: signs the self-attestation statement below (SignWithEcdsaP256) before the signature is tampered.
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);
        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();

        using AuthenticatorData authenticatorData = BuildRegistrationAuthenticatorData(rpIdHash, Guid.NewGuid(), credentialPublicKey, [0x01, 0x02], out byte[] authDataBytes);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Create, ValidChallenge, ValidOrigin);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash(clientDataJson, BaseMemoryPool.Shared);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(credentialKey, toBeSigned);
        signature[0] ^= 0xFF;
        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signature, X5c: null);

        using RegistrationCeremonyInput ceremonyInput = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataOverride: ClientDataJsonReader.Read(clientDataJson),
            authenticatorDataOverride: authenticatorData,
            expectedRpIdHash: rpIdHash);
        SelectAttestationVerifierDelegate selectVerifier = Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.Packed, BuildPackedVerifier(statement)));

        Fido2RegistrationOutcome outcome = await Fido2RegistrationVerifier.VerifyAsync(
            WellKnownWebAuthnAttestationFormats.Packed,
            attestationStatement: ReadOnlyMemory<byte>.Empty,
            authDataBytes,
            clientDataJson,
            ceremonyInput,
            selectVerifier,
            AlwaysUnique,
            trustAnchors: [],
            validationTime: TestClock.CanonicalEpoch,
            CorrelationId,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.IsInstanceOfType<RejectedAttestationResult>(outcome.AttestationResult);
        Assert.AreEqual(Fido2AttestationErrors.InvalidSignature.Code, ((RejectedAttestationResult)outcome.AttestationResult).Error.Code);
        Assert.IsFalse(outcome.IsAcceptable);
        Assert.IsNull(outcome.CredentialRecord);
        Assert.AreEqual(ClaimOutcome.Failure, GetClaimOutcome(outcome.Claims, Fido2ClaimIds.Fido2RegistrationAttestationTrustworthy));
    }


    /// <summary>
    /// A relying party ID hash that does not match <c>authData.rpIdHash</c> fails
    /// <see cref="Fido2ClaimIds.Fido2RegistrationRpIdHash"/> specifically, while the attestation
    /// itself (which does not cover <c>rpIdHash</c> independently of the signed transcript) still
    /// verifies as <see cref="NoneAttestationResult"/>.
    /// </summary>
    [TestMethod]
    public async Task WrongExpectedRpIdHashFailsRpIdHashClaimOnly()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(credentialKeys.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);
        MdocTestFixtures.DisposeKeyMaterial(credentialKeys);
        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();

        using AuthenticatorData authenticatorData = BuildRegistrationAuthenticatorData(rpIdHash, Guid.NewGuid(), credentialPublicKey, [0x09], out byte[] authDataBytes);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Create, ValidChallenge, ValidOrigin);

        byte[] wrongRpIdHash = Fido2TestVectors.CreateRpIdHash();
        wrongRpIdHash[0] ^= 0x01;
        using RegistrationCeremonyInput ceremonyInput = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataOverride: ClientDataJsonReader.Read(clientDataJson),
            authenticatorDataOverride: authenticatorData,
            expectedRpIdHash: wrongRpIdHash);

        SelectAttestationVerifierDelegate selectVerifier = Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.None, NoneAttestation.Build()));

        Fido2RegistrationOutcome outcome = await Fido2RegistrationVerifier.VerifyAsync(
            WellKnownWebAuthnAttestationFormats.None,
            attestationStatement: new byte[] { CanonicalEmptyMap },
            authDataBytes,
            clientDataJson,
            ceremonyInput,
            selectVerifier,
            AlwaysUnique,
            trustAnchors: [],
            validationTime: TestClock.CanonicalEpoch,
            CorrelationId,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.IsInstanceOfType<NoneAttestationResult>(outcome.AttestationResult);
        Assert.IsFalse(outcome.IsAcceptable);
        Assert.IsNull(outcome.CredentialRecord);
        AssertOnlyClaimFails(outcome.Claims, Fido2ClaimIds.Fido2RegistrationRpIdHash);
    }


    /// <summary>
    /// A challenge the client reports that does not match the relying party's expected challenge
    /// fails <see cref="Fido2ClaimIds.Fido2RegistrationChallenge"/> specifically.
    /// </summary>
    [TestMethod]
    public async Task WrongChallengeFailsChallengeClaimOnly()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(credentialKeys.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);
        MdocTestFixtures.DisposeKeyMaterial(credentialKeys);
        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();

        using AuthenticatorData authenticatorData = BuildRegistrationAuthenticatorData(rpIdHash, Guid.NewGuid(), credentialPublicKey, [0x0E], out byte[] authDataBytes);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Create, "a-completely-different-challenge", ValidOrigin);
        using RegistrationCeremonyInput ceremonyInput = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataOverride: ClientDataJsonReader.Read(clientDataJson),
            authenticatorDataOverride: authenticatorData,
            expectedRpIdHash: rpIdHash);

        SelectAttestationVerifierDelegate selectVerifier = Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.None, NoneAttestation.Build()));

        Fido2RegistrationOutcome outcome = await Fido2RegistrationVerifier.VerifyAsync(
            WellKnownWebAuthnAttestationFormats.None,
            attestationStatement: new byte[] { CanonicalEmptyMap },
            authDataBytes,
            clientDataJson,
            ceremonyInput,
            selectVerifier,
            AlwaysUnique,
            trustAnchors: [],
            validationTime: TestClock.CanonicalEpoch,
            CorrelationId,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.IsFalse(outcome.IsAcceptable);
        AssertOnlyClaimFails(outcome.Claims, Fido2ClaimIds.Fido2RegistrationChallenge);
    }


    /// <summary>
    /// An origin the relying party does not expect fails
    /// <see cref="Fido2ClaimIds.Fido2RegistrationOrigin"/> specifically.
    /// </summary>
    [TestMethod]
    public async Task WrongOriginFailsOriginClaimOnly()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(credentialKeys.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);
        MdocTestFixtures.DisposeKeyMaterial(credentialKeys);
        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();

        using AuthenticatorData authenticatorData = BuildRegistrationAuthenticatorData(rpIdHash, Guid.NewGuid(), credentialPublicKey, [0x0F], out byte[] authDataBytes);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Create, ValidChallenge, "https://attacker.example");
        using RegistrationCeremonyInput ceremonyInput = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataOverride: ClientDataJsonReader.Read(clientDataJson),
            authenticatorDataOverride: authenticatorData,
            expectedRpIdHash: rpIdHash);

        SelectAttestationVerifierDelegate selectVerifier = Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.None, NoneAttestation.Build()));

        Fido2RegistrationOutcome outcome = await Fido2RegistrationVerifier.VerifyAsync(
            WellKnownWebAuthnAttestationFormats.None,
            attestationStatement: new byte[] { CanonicalEmptyMap },
            authDataBytes,
            clientDataJson,
            ceremonyInput,
            selectVerifier,
            AlwaysUnique,
            trustAnchors: [],
            validationTime: TestClock.CanonicalEpoch,
            CorrelationId,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.IsFalse(outcome.IsAcceptable);
        AssertOnlyClaimFails(outcome.Claims, Fido2ClaimIds.Fido2RegistrationOrigin);
    }


    /// <summary>
    /// An attested credential algorithm the relying party did not solicit fails
    /// <see cref="Fido2ClaimIds.Fido2RegistrationCredentialAlgorithm"/> specifically, even though
    /// the attestation signature — which does not depend on the RP's <c>pubKeyCredParams</c> —
    /// still verifies.
    /// </summary>
    [TestMethod]
    public async Task UnsolicitedCredentialAlgorithmFailsCredentialAlgorithmClaimOnly()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(credentialKeys.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);
        MdocTestFixtures.DisposeKeyMaterial(credentialKeys);
        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();

        AuthenticatorData authenticatorData = BuildRegistrationAuthenticatorData(rpIdHash, Guid.NewGuid(), credentialPublicKey, [0x10], out byte[] authDataBytes);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Create, ValidChallenge, ValidOrigin);

        //The relying party only solicited RS256 (-257); the credential's ES256 (-7) key is unsolicited.
        using RegistrationCeremonyInput ceremonyInput = new()
        {
            ClientData = ClientDataJsonReader.Read(clientDataJson),
            AuthenticatorData = authenticatorData,
            ExpectedChallenge = ValidChallenge,
            ExpectedOrigins = new HashSet<string> { ValidOrigin },
            ExpectedRpIdHash = Fido2TestVectors.WrapRpIdHash(rpIdHash, BaseMemoryPool.Shared),
            UserVerification = UserVerificationRequirement.Required,
            AllowedAlgorithms = [WellKnownCoseAlgorithms.Rs256]
        };

        SelectAttestationVerifierDelegate selectVerifier = Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.None, NoneAttestation.Build()));

        Fido2RegistrationOutcome outcome = await Fido2RegistrationVerifier.VerifyAsync(
            WellKnownWebAuthnAttestationFormats.None,
            attestationStatement: new byte[] { CanonicalEmptyMap },
            authDataBytes,
            clientDataJson,
            ceremonyInput,
            selectVerifier,
            AlwaysUnique,
            trustAnchors: [],
            validationTime: TestClock.CanonicalEpoch,
            CorrelationId,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.IsInstanceOfType<NoneAttestationResult>(outcome.AttestationResult);
        Assert.IsFalse(outcome.IsAcceptable);
        AssertOnlyClaimFails(outcome.Claims, Fido2ClaimIds.Fido2RegistrationCredentialAlgorithm);
    }


    /// <summary>
    /// An unregistered attestation statement format (no verifier selected for <c>fmt</c>) fails
    /// closed with <see cref="Fido2AttestationErrors.UnregisteredFormat"/> rather than throwing.
    /// </summary>
    [TestMethod]
    public async Task UnregisteredAttestationFormatIsRejectedWithUnregisteredFormat()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(credentialKeys.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);
        MdocTestFixtures.DisposeKeyMaterial(credentialKeys);
        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();

        using AuthenticatorData authenticatorData = BuildRegistrationAuthenticatorData(rpIdHash, Guid.NewGuid(), credentialPublicKey, [0x11], out byte[] authDataBytes);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Create, ValidChallenge, ValidOrigin);
        using RegistrationCeremonyInput ceremonyInput = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataOverride: ClientDataJsonReader.Read(clientDataJson),
            authenticatorDataOverride: authenticatorData,
            expectedRpIdHash: rpIdHash);

        //No format registered at all: the selector always returns null.
        SelectAttestationVerifierDelegate selectVerifier = Fido2AttestationSelectors.FromFormats();

        Fido2RegistrationOutcome outcome = await Fido2RegistrationVerifier.VerifyAsync(
            WellKnownWebAuthnAttestationFormats.AndroidKey,
            attestationStatement: ReadOnlyMemory<byte>.Empty,
            authDataBytes,
            clientDataJson,
            ceremonyInput,
            selectVerifier,
            AlwaysUnique,
            trustAnchors: [],
            validationTime: TestClock.CanonicalEpoch,
            CorrelationId,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.IsInstanceOfType<RejectedAttestationResult>(outcome.AttestationResult);
        Assert.AreEqual(Fido2AttestationErrors.UnregisteredFormat.Code, ((RejectedAttestationResult)outcome.AttestationResult).Error.Code);
        Assert.IsFalse(outcome.IsAcceptable);
        Assert.IsNull(outcome.CredentialRecord);
    }


    /// <summary>
    /// Mints a section 8.2.1-conformant packed-certified registration (real independent
    /// <see cref="ECDsa"/>-signed leaf/root chain, real wire <c>authData</c>/<c>clientDataJSON</c>)
    /// and runs it through <see cref="Fido2RegistrationVerifier.VerifyAsync"/> with the row-6107
    /// downgrade knob set to <paramref name="acceptsUntrustedAttestationAsNone"/>, for the downgrade
    /// matrix tests.
    /// </summary>
    /// <param name="acceptsUntrustedAttestationAsNone">The downgrade knob value.</param>
    /// <param name="tamperSignature">Whether to flip a byte of the attestation signature before verifying.</param>
    /// <param name="suppliesValidTrustAnchor">
    /// When <see langword="true"/>, the minted root is supplied as the sole trust anchor (a valid
    /// trust path); when <see langword="false"/>, no trust anchors are supplied at all
    /// (<see cref="Fido2AttestationErrors.NoTrustAnchors"/>) — unless
    /// <paramref name="suppliesImposterTrustAnchor"/> overrides this to supply an unrelated anchor
    /// instead.
    /// </param>
    /// <param name="suppliesImposterTrustAnchor">
    /// When <see langword="true"/>, an unrelated, independently self-signed root — never an issuer of
    /// the minted leaf — is supplied as the sole trust anchor, so the chain fails to build to it
    /// (<see cref="Fido2AttestationErrors.ChainValidationFailed"/>), the second of the two downgrade-eligible
    /// trust-path-shortfall reasons alongside <see cref="Fido2AttestationErrors.NoTrustAnchors"/>. Takes
    /// precedence over <paramref name="suppliesValidTrustAnchor"/> when <see langword="true"/>.
    /// </param>
    /// <returns>The registration outcome.</returns>
    private async Task<Fido2RegistrationOutcome> VerifyPackedCertifiedForDowngradeAsync(
        bool acceptsUntrustedAttestationAsNone, bool tamperSignature, bool suppliesValidTrustAnchor, bool suppliesImposterTrustAnchor = false)
    {
        //Cert-factory carve-out: feeds CreateSelfSignedCa (CertificateRequest) to mint the trust-anchor root.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        //Cert-factory + independent-oracle carve-out: feeds CreateLeafAttestationCertificate and signs the attestation statement below.
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        //Cert-factory carve-out: feeds CreateSelfSignedCa to mint an unrelated root, never an issuer of the leaf.
        using ECDsa imposterRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();
        byte[] credentialId = [0x20, 0x21, 0x22, 0x23];
        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Downgrade Attestation Root", rootKey);
        using X509Certificate2 imposterRootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Downgrade Imposter Root", imposterRootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguid);

        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(credentialKeys.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);
        MdocTestFixtures.DisposeKeyMaterial(credentialKeys);
        using AuthenticatorData authenticatorData = BuildRegistrationAuthenticatorData(rpIdHash, aaguid, credentialPublicKey, credentialId, out byte[] authDataBytes);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Create, ValidChallenge, ValidOrigin);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash(clientDataJson, BaseMemoryPool.Shared);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, toBeSigned);
        if(tamperSignature)
        {
            signature[0] ^= 0xFF;
        }

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        using PkiCertificateMemory imposterRootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(imposterRootCert.RawData);
        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signature, X5c: [leafPki, rootPki]);

        using RegistrationCeremonyInput ceremonyInput = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataOverride: ClientDataJsonReader.Read(clientDataJson),
            authenticatorDataOverride: authenticatorData,
            expectedRpIdHash: rpIdHash);
        SelectAttestationVerifierDelegate selectVerifier = Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.Packed, BuildPackedVerifier(statement)));

        IReadOnlyList<PkiCertificateMemory> trustAnchors = suppliesImposterTrustAnchor
            ? [imposterRootPki]
            : suppliesValidTrustAnchor ? [rootPki] : [];

        return await Fido2RegistrationVerifier.VerifyAsync(
            WellKnownWebAuthnAttestationFormats.Packed,
            attestationStatement: ReadOnlyMemory<byte>.Empty,
            authDataBytes,
            clientDataJson,
            ceremonyInput,
            selectVerifier,
            AlwaysUnique,
            trustAnchors,
            validationTime: TestClock.CanonicalEpoch,
            CorrelationId,
            BaseMemoryPool.Shared,
            acceptsUntrustedAttestationAsNone: acceptsUntrustedAttestationAsNone,
            cancellationToken: TestContext.CancellationToken);
    }


    /// <summary>Builds the <see cref="PackedAttestation"/> verifier under a stub parser returning <paramref name="statement"/>.</summary>
    private static AttestationVerifyDelegate BuildPackedVerifier(PackedAttestationStatement statement) =>
        PackedAttestation.Build(
            Fido2AttestationTestVectors.CreateStatementParser(statement),
            MicrosoftX509Functions.ValidateChainAsync,
            MicrosoftX509Functions.ReadCertificateProfile,
            MicrosoftX509Functions.ReadCertificateExtensionValue);


    /// <summary>
    /// Assembles a registration <c>authData</c> binary layout (per WebAuthn L3 section 6.1) with
    /// the <c>UP</c>/<c>UV</c> bits set and attested credential data present — the shape a
    /// successful registration ceremony produces — and the parsed view aliasing an independent
    /// buffer with the same content, mirroring <see cref="Fido2AttestationTestVectors.BuildAuthenticatorData"/>
    /// but with configurable flags and signature counter for the ceremony-rules axes this fixture
    /// exercises.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the DigestValue/CredentialId carriers transfers to the returned AuthenticatorData, which the caller embeds into a RegistrationCeremonyInput it disposes via a using declaration.")]
    internal static AuthenticatorData BuildRegistrationAuthenticatorData(
        byte[] rpIdHash,
        Guid aaguid,
        CoseKey credentialPublicKey,
        byte[] credentialId,
        out byte[] rawBytes,
        uint signCount = 0,
        bool backupEligible = false,
        bool backupState = false)
    {
        byte flags = (byte)(AuthenticatorDataFlags.UserPresentBit | AuthenticatorDataFlags.UserVerifiedBit | AuthenticatorDataFlags.AttestedCredentialDataIncludedBit
            | (backupEligible ? AuthenticatorDataFlags.BackupEligibleBit : 0)
            | (backupState ? AuthenticatorDataFlags.BackupStateBit : 0));

        byte[] credentialPublicKeyCbor = MdocCborCoseKeyWriter.Write(credentialPublicKey).ToArray();
        byte[] attestedCredentialDataBytes = Fido2TestVectors.BuildAttestedCredentialData(aaguid, credentialId, credentialPublicKeyCbor);
        rawBytes = Fido2TestVectors.BuildAuthenticatorData(rpIdHash, flags, signCount, attestedCredentialDataBytes);

        var attestedCredentialData = new AttestedCredentialData(aaguid, CredentialId.Create(credentialId, BaseMemoryPool.Shared), credentialPublicKey);

        return new AuthenticatorData(Fido2TestVectors.WrapRpIdHash(rpIdHash, BaseMemoryPool.Shared), new AuthenticatorDataFlags(flags), signCount, attestedCredentialData, ReadOnlyMemory<byte>.Empty);
    }


    /// <summary>Finds the outcome of the claim carrying <paramref name="claimId"/> in <paramref name="claims"/>.</summary>
    private static ClaimOutcome GetClaimOutcome(ClaimIssueResult claims, ClaimId claimId)
    {
        foreach(Claim claim in claims.Claims)
        {
            if(claim.Id.Code == claimId.Code)
            {
                return claim.Outcome;
            }
        }

        throw new InvalidOperationException($"Claim '{claimId}' was not present in the result.");
    }


    /// <summary>Finds the claim carrying <paramref name="claimId"/> in <paramref name="claims"/>.</summary>
    private static Claim GetClaim(ClaimIssueResult claims, ClaimId claimId)
    {
        foreach(Claim claim in claims.Claims)
        {
            if(claim.Id.Code == claimId.Code)
            {
                return claim;
            }
        }

        throw new InvalidOperationException($"Claim '{claimId}' was not present in the result.");
    }


    /// <summary>Determines whether <paramref name="claims"/> carries a claim with <paramref name="claimId"/> at all.</summary>
    private static bool HasClaim(ClaimIssueResult claims, ClaimId claimId)
    {
        foreach(Claim claim in claims.Claims)
        {
            if(claim.Id.Code == claimId.Code)
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>Determines whether any claim in <paramref name="claims"/> carries <see cref="ClaimOutcome.Failure"/>.</summary>
    private static bool HasFailureClaim(ClaimIssueResult claims)
    {
        foreach(Claim claim in claims.Claims)
        {
            if(claim.Outcome == ClaimOutcome.Failure)
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Asserts that exactly the claim carrying <paramref name="expectedFailingClaimId"/> is
    /// <see cref="ClaimOutcome.Failure"/> and every other claim in <paramref name="claims"/>
    /// succeeds — the fail-closed idiom: flipping one axis must not silently let an unrelated
    /// claim also fail, or mask the failure entirely.
    /// </summary>
    private static void AssertOnlyClaimFails(ClaimIssueResult claims, ClaimId expectedFailingClaimId)
    {
        foreach(Claim claim in claims.Claims)
        {
            //Fido2RegistrationExtensionOutputs is always NotApplicable for this file's inputs: none
            //of them populate ClientExtensionOutputs/AuthenticatorExtensionOutputs, so this claim
            //would otherwise mismatch the Success default at every call site.
            ClaimOutcome expected = claim.Id.Code == expectedFailingClaimId.Code
                ? ClaimOutcome.Failure
                : claim.Id.Code == Fido2ClaimIds.Fido2RegistrationExtensionOutputs.Code
                    ? ClaimOutcome.NotApplicable
                    : ClaimOutcome.Success;
            Assert.AreEqual(expected, claim.Outcome, $"Claim '{claim.Id}' outcome mismatch.");
        }
    }
}
