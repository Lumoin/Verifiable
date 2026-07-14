using System.Buffers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="TpmAttestation"/> — the
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">WebAuthn L3 section 8.3</see>
/// <c>tpm</c> attestation statement format verification procedure, including the
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-cert-requirements">section 8.3.1</see>
/// AIK certificate profile checks: one conformant positive fixture, then one adversarial negative
/// per named verification step.
/// </summary>
/// <remarks>
/// Every fixture mints its AIK certificate and TPM wire structures (TPMT_PUBLIC/TPMS_ATTEST) with
/// an independent oracle — raw <see cref="ECDsa"/>/<see cref="CertificateRequest"/> for the
/// certificate, and <c>Verifiable.Tpm</c>'s own spec-exact wire types
/// (<see cref="TpmAttestationTestVectors.BuildEccPubAreaBytes"/>,
/// <see cref="TpmAttestationTestVectors.BuildCertifyCertInfoBytes"/>) for the TPM structures — never
/// the library's own signing or chain-building seams, so <see cref="TpmAttestation"/> is exercised
/// against genuinely external wire material reconstructed solely from the
/// <see cref="AttestationVerificationRequest"/>'s wire-shaped members.
/// </remarks>
[TestClass]
internal sealed class TpmAttestationTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A fully section 8.3/8.3.1-conformant statement verifies as
    /// <see cref="CertifiedAttestationResult"/> with attestation type
    /// <see cref="AttestationType.AttestationCa"/> — the positive control for the whole procedure.
    /// </summary>
    [TestMethod]
    public async Task ConformantStatementVerifiesAsAttestationCa()
    {
        using Scenario scenario = BuildConformantScenario();

        AttestationResult result = await RunAsync(scenario).ConfigureAwait(false);

        Assert.IsInstanceOfType<CertifiedAttestationResult>(result);
        Assert.AreEqual(AttestationType.AttestationCa, ((CertifiedAttestationResult)result).Type);
    }


    /// <summary>Authenticator data carrying no attested credential data is rejected — <see cref="Fido2AttestationErrors.MissingAttestedCredentialData"/>.</summary>
    [TestMethod]
    public async Task MissingAttestedCredentialDataIsRejected()
    {
        using Scenario scenario = BuildConformantScenario();
        using AuthenticatorData noAttestedCredentialData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), null, out byte[] authDataBytes);

        Fido2AttestationError? error = await RunAndGetErrorAsync(scenario, authenticatorDataOverride: noAttestedCredentialData, authDataBytesOverride: authDataBytes).ConfigureAwait(false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.MissingAttestedCredentialData.Code, error.Code);
    }


    /// <summary>
    /// A <c>pubArea</c> built over a different key than <c>credentialPublicKey</c> is rejected —
    /// <see cref="Fido2AttestationErrors.PublicAreaKeyMismatch"/>, the section 8.3 step 2 check.
    /// </summary>
    [TestMethod]
    public async Task PubAreaKeyMismatchIsRejected()
    {
        using Scenario scenario = BuildConformantScenario();

        //A P-256 key distinct from scenario.CredentialKey, minted on the spot so its public point
        //produces a pubArea that mismatches the credential key — the PublicAreaKeyMismatch fixture.
        //Raw ECDsa because BuildEccPubAreaBytes calls ExportParameters directly; no project surface
        //hands back a raw ECDsa from TestKeyMaterialProvider's wrapped key-memory types.
        using ECDsa otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] mismatchedPubArea = TpmAttestationTestVectors.BuildEccPubAreaBytes(otherKey);

        Fido2AttestationError? error = await RunAndGetErrorAsync(scenario, pubAreaOverride: mismatchedPubArea).ConfigureAwait(false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.PublicAreaKeyMismatch.Code, error.Code);
    }


    /// <summary>An empty <c>x5c</c> array is rejected — <see cref="Fido2AttestationErrors.MalformedStatement"/> (the tpm format has no self-attestation branch).</summary>
    [TestMethod]
    public async Task EmptyX5cIsRejectedWithMalformedStatement()
    {
        using Scenario scenario = BuildConformantScenario();

        Fido2AttestationError? error = await RunAndGetErrorAsync(scenario, x5cOverride: []).ConfigureAwait(false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.MalformedStatement.Code, error.Code);
    }


    /// <summary>No trust anchors supplied is rejected — <see cref="Fido2AttestationErrors.NoTrustAnchors"/>.</summary>
    [TestMethod]
    public async Task NoTrustAnchorsIsRejected()
    {
        using Scenario scenario = BuildConformantScenario();

        Fido2AttestationError? error = await RunAndGetErrorAsync(scenario, trustAnchorsOverride: []).ConfigureAwait(false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.NoTrustAnchors.Code, error.Code);
    }


    /// <summary>An AIK certificate chaining to an unrelated root is rejected — <see cref="Fido2AttestationErrors.ChainValidationFailed"/>.</summary>
    [TestMethod]
    public async Task ChainValidationFailedForUnrelatedTrustAnchorIsRejected()
    {
        using Scenario scenario = BuildConformantScenario();

        //Cert-factory carve-out: mints a self-signed root via CertificateRequest that the trust anchor
        //list never carries, so the AIK chain has nothing to validate against.
        using ECDsa unrelatedRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 unrelatedRoot = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Unrelated Root", unrelatedRootKey);
        using PkiCertificateMemory unrelatedRootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(unrelatedRoot.RawData);

        Fido2AttestationError? error = await RunAndGetErrorAsync(scenario, trustAnchorsOverride: [unrelatedRootPki]).ConfigureAwait(false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.ChainValidationFailed.Code, error.Code);
    }


    /// <summary>An AIK certificate encoded as X.509 version 1 is rejected — <see cref="Fido2AttestationErrors.CertificateProfileViolation"/>.</summary>
    [TestMethod]
    public async Task NonVersion3CertificateIsRejectedWithCertificateProfileViolation()
    {
        using Scenario scenario = BuildConformantScenario();
        using X509Certificate2 version1AikCertificate = Fido2AttestationTestVectors.CreateVersion1LeafAttestationCertificate(scenario.RootCertificate, scenario.AikKey);
        Assert.AreEqual(1, version1AikCertificate.Version);

        Fido2AttestationError? error = await RunAndGetErrorAsync(scenario, aikCertificateOverride: version1AikCertificate).ConfigureAwait(false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CertificateProfileViolation.Code, error.Code);
    }


    /// <summary>A non-empty AIK certificate Subject is rejected — <see cref="Fido2AttestationErrors.CertificateProfileViolation"/>.</summary>
    [TestMethod]
    public async Task NonEmptySubjectIsRejectedWithCertificateProfileViolation()
    {
        using Scenario scenario = BuildConformantScenario();
        using X509Certificate2 nonEmptySubjectCertificate = TpmAttestationTestVectors.CreateAikCertificate(scenario.RootCertificate, scenario.AikKey, emptySubject: false);

        Fido2AttestationError? error = await RunAndGetErrorAsync(scenario, aikCertificateOverride: nonEmptySubjectCertificate).ConfigureAwait(false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CertificateProfileViolation.Code, error.Code);
    }


    /// <summary>An AIK certificate with Basic Constraints CA=true is rejected — <see cref="Fido2AttestationErrors.CertificateProfileViolation"/>.</summary>
    [TestMethod]
    public async Task CertificateAuthorityLeafIsRejectedWithCertificateProfileViolation()
    {
        using Scenario scenario = BuildConformantScenario();
        using X509Certificate2 caFlaggedCertificate = TpmAttestationTestVectors.CreateAikCertificate(scenario.RootCertificate, scenario.AikKey, isCertificateAuthority: true);

        Fido2AttestationError? error = await RunAndGetErrorAsync(scenario, aikCertificateOverride: caFlaggedCertificate).ConfigureAwait(false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CertificateProfileViolation.Code, error.Code);
    }


    /// <summary>An AIK certificate carrying no Subject Alternative Name extension is rejected — <see cref="Fido2AttestationErrors.CertificateProfileViolation"/>.</summary>
    [TestMethod]
    public async Task MissingSubjectAlternativeNameIsRejectedWithCertificateProfileViolation()
    {
        using Scenario scenario = BuildConformantScenario();
        using X509Certificate2 noSanCertificate = TpmAttestationTestVectors.CreateAikCertificate(scenario.RootCertificate, scenario.AikKey, includeSubjectAlternativeName: false);

        Fido2AttestationError? error = await RunAndGetErrorAsync(scenario, aikCertificateOverride: noSanCertificate).ConfigureAwait(false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CertificateProfileViolation.Code, error.Code);
    }


    /// <summary>A Subject Alternative Name missing the <c>tcg-at-tpmModel</c> device attribute is rejected — <see cref="Fido2AttestationErrors.CertificateProfileViolation"/>.</summary>
    [TestMethod]
    public async Task SubjectAlternativeNameMissingModelAttributeIsRejectedWithCertificateProfileViolation()
    {
        using Scenario scenario = BuildConformantScenario();
        using X509Certificate2 incompleteSanCertificate = TpmAttestationTestVectors.CreateAikCertificate(scenario.RootCertificate, scenario.AikKey, tpmModel: null);

        Fido2AttestationError? error = await RunAndGetErrorAsync(scenario, aikCertificateOverride: incompleteSanCertificate).ConfigureAwait(false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CertificateProfileViolation.Code, error.Code);
    }


    /// <summary>An AIK certificate whose Extended Key Usage omits <c>tcg-kp-AIKCertificate</c> is rejected — <see cref="Fido2AttestationErrors.CertificateProfileViolation"/>.</summary>
    [TestMethod]
    public async Task MissingAikExtendedKeyUsageIsRejectedWithCertificateProfileViolation()
    {
        using Scenario scenario = BuildConformantScenario();
        using X509Certificate2 noEkuCertificate = TpmAttestationTestVectors.CreateAikCertificate(scenario.RootCertificate, scenario.AikKey, includeAikExtendedKeyUsage: false);

        Fido2AttestationError? error = await RunAndGetErrorAsync(scenario, aikCertificateOverride: noEkuCertificate).ConfigureAwait(false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CertificateProfileViolation.Code, error.Code);
    }


    /// <summary>
    /// An AIK certificate carrying an <c>id-fido-gen-ce-aaguid</c> extension that mismatches the
    /// authenticator data's AAGUID is rejected — <see cref="Fido2AttestationErrors.AaguidMismatch"/>.
    /// </summary>
    [TestMethod]
    public async Task AaguidExtensionMismatchIsRejectedWithAaguidMismatch()
    {
        using Scenario scenario = BuildConformantScenario();

        //Cert-factory carve-out: builds the AIK certificate by hand (rather than through
        //TpmAttestationTestVectors.CreateAikCertificate) so the id-fido-gen-ce-aaguid extension can be
        //embedded alongside the ordinary AIK profile extensions.
        var certificateRequest = new CertificateRequest(string.Empty, scenario.AikKey, HashAlgorithmName.SHA256);
        certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        certificateRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid(TpmAttestationTestVectors.AikCertificateKeyPurposeOid, "tcg-kp-AIKCertificate")], critical: false));
        certificateRequest.CertificateExtensions.Add(new X509Extension(
            "2.5.29.17", TpmAttestationTestVectors.EncodeTcgSubjectAlternativeName(
                TpmAttestationTestVectors.DefaultTpmManufacturer, TpmAttestationTestVectors.DefaultTpmModel, TpmAttestationTestVectors.DefaultTpmVersion),
            critical: true));
        certificateRequest.CertificateExtensions.Add(new X509Extension(
            Fido2AttestationTestVectors.AaguidExtensionOid, Fido2AttestationTestVectors.EncodeAaguidExtensionValue(Guid.NewGuid()), critical: false));

        DateTimeOffset now = TestClock.CanonicalEpoch;
        using X509Certificate2 mismatchedAaguidCertificate = certificateRequest.Create(
            scenario.RootCertificate, now.AddDays(-1), now.AddYears(1), [1, 2, 3, 4]).CopyWithPrivateKey(scenario.AikKey);

        Fido2AttestationError? error = await RunAndGetErrorAsync(scenario, aikCertificateOverride: mismatchedAaguidCertificate).ConfigureAwait(false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.AaguidMismatch.Code, error.Code);
    }


    /// <summary>
    /// An attestation statement whose <c>alg</c> maps to an algorithm family inconsistent with the
    /// AIK's own P-256 key is rejected — <see cref="Fido2AttestationErrors.AlgorithmMismatch"/>.
    /// </summary>
    [TestMethod]
    public async Task AlgorithmInconsistentWithAikKeyIsRejectedWithAlgorithmMismatch()
    {
        using Scenario scenario = BuildConformantScenario();

        Fido2AttestationError? error = await RunAndGetErrorAsync(scenario, algOverride: WellKnownCoseAlgorithms.Rs256).ConfigureAwait(false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.AlgorithmMismatch.Code, error.Code);
    }


    /// <summary>
    /// A <c>pubArea</c> whose <c>nameAlg</c> is an algorithm this verification procedure has no
    /// registered digest for is rejected — <see cref="Fido2AttestationErrors.UnsupportedAlgorithm"/>
    /// — the Name-computation half of section 8.3's final validation step.
    /// </summary>
    [TestMethod]
    public async Task UnsupportedNameAlgorithmIsRejected()
    {
        using Scenario scenario = BuildConformantScenario();
        byte[] sha1PubArea = TpmAttestationTestVectors.BuildEccPubAreaBytes(scenario.CredentialKey, TpmAlgIdConstants.TPM_ALG_SHA1);
        byte[] certifiedName = TpmAttestationTestVectors.ComputeTpmName(scenario.PubAreaBytes);
        byte[] certInfoBytes = TpmAttestationTestVectors.BuildCertifyCertInfoBytes(certifiedName, SignerName, scenario.ExtraData);
        (byte[] r, byte[] s) = TpmAttestationTestVectors.SignWithEcdsaP256Components(scenario.AikKey, certInfoBytes);
        byte[] sigBytes = TpmAttestationTestVectors.BuildEcdsaSignatureBytes(TpmAlgIdConstants.TPM_ALG_SHA256, r, s);

        //The pubArea's nameAlg is SHA-1 (unsupported), but its unique/parameters still match the
        //credential key, and certifiedName (over the real SHA-256 pubArea) plus the sig are held
        //otherwise conformant, isolating the nameAlg check.
        Fido2AttestationError? error = await RunAndGetErrorAsync(
            scenario, pubAreaOverride: sha1PubArea, certInfoOverride: certInfoBytes, sigOverride: sigBytes).ConfigureAwait(false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.UnsupportedAlgorithm.Code, error.Code);
    }


    /// <summary>A tampered <c>certInfo</c> whose signature no longer verifies is rejected — <see cref="Fido2AttestationErrors.InvalidSignature"/>.</summary>
    [TestMethod]
    public async Task TamperedCertInfoIsRejectedWithInvalidSignature()
    {
        using Scenario scenario = BuildConformantScenario();
        byte[] tamperedCertInfo = [.. scenario.CertInfoBytes];
        tamperedCertInfo[^1] ^= 0xFF;

        Fido2AttestationError? error = await RunAndGetErrorAsync(scenario, certInfoOverride: tamperedCertInfo).ConfigureAwait(false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.InvalidSignature.Code, error.Code);
    }


    /// <summary>
    /// A <c>certInfo.extraData</c> that does not equal the hash of <c>attToBeSigned</c> is
    /// rejected — <see cref="Fido2AttestationErrors.AttestationDigestMismatch"/>.
    /// </summary>
    [TestMethod]
    public async Task ExtraDataMismatchIsRejectedWithAttestationDigestMismatch()
    {
        using Scenario scenario = BuildConformantScenario();
        byte[] wrongExtraData = new byte[32];

        //Junk payload: any 32 bytes that differ from the correct extraData digest suffice.
        RandomNumberGenerator.Fill(wrongExtraData);
        byte[] certifiedName = TpmAttestationTestVectors.ComputeTpmName(scenario.PubAreaBytes);
        byte[] certInfoBytes = TpmAttestationTestVectors.BuildCertifyCertInfoBytes(certifiedName, SignerName, wrongExtraData);
        (byte[] r, byte[] s) = TpmAttestationTestVectors.SignWithEcdsaP256Components(scenario.AikKey, certInfoBytes);
        byte[] sigBytes = TpmAttestationTestVectors.BuildEcdsaSignatureBytes(TpmAlgIdConstants.TPM_ALG_SHA256, r, s);

        Fido2AttestationError? error = await RunAndGetErrorAsync(scenario, certInfoOverride: certInfoBytes, sigOverride: sigBytes).ConfigureAwait(false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.AttestationDigestMismatch.Code, error.Code);
    }


    /// <summary><c>certInfo.magic</c> not set to <c>TPM_GENERATED_VALUE</c> is rejected — <see cref="Fido2AttestationErrors.CertInfoNotTpmGenerated"/>.</summary>
    [TestMethod]
    public async Task NonTpmGeneratedMagicIsRejected()
    {
        using Scenario scenario = BuildConformantScenario();
        byte[] certifiedName = TpmAttestationTestVectors.ComputeTpmName(scenario.PubAreaBytes);
        byte[] certInfoBytes = TpmAttestationTestVectors.BuildCertifyCertInfoBytes(certifiedName, SignerName, scenario.ExtraData, magic: 0xDEADBEEF);
        (byte[] r, byte[] s) = TpmAttestationTestVectors.SignWithEcdsaP256Components(scenario.AikKey, certInfoBytes);
        byte[] sigBytes = TpmAttestationTestVectors.BuildEcdsaSignatureBytes(TpmAlgIdConstants.TPM_ALG_SHA256, r, s);

        Fido2AttestationError? error = await RunAndGetErrorAsync(scenario, certInfoOverride: certInfoBytes, sigOverride: sigBytes).ConfigureAwait(false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CertInfoNotTpmGenerated.Code, error.Code);
    }


    /// <summary><c>certInfo.type</c> not set to <c>TPM_ST_ATTEST_CERTIFY</c> is rejected — <see cref="Fido2AttestationErrors.CertInfoNotCertifyType"/>.</summary>
    [TestMethod]
    public async Task NonCertifyTypeIsRejected()
    {
        using Scenario scenario = BuildConformantScenario();
        byte[] certInfoBytes = TpmAttestationTestVectors.BuildQuoteCertInfoBytes(SignerName, scenario.ExtraData);
        (byte[] r, byte[] s) = TpmAttestationTestVectors.SignWithEcdsaP256Components(scenario.AikKey, certInfoBytes);
        byte[] sigBytes = TpmAttestationTestVectors.BuildEcdsaSignatureBytes(TpmAlgIdConstants.TPM_ALG_SHA256, r, s);

        Fido2AttestationError? error = await RunAndGetErrorAsync(scenario, certInfoOverride: certInfoBytes, sigOverride: sigBytes).ConfigureAwait(false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CertInfoNotCertifyType.Code, error.Code);
    }


    /// <summary>
    /// A <c>certInfo.attested.name</c> that does not match <c>pubArea</c>'s own computed Name is
    /// rejected — <see cref="Fido2AttestationErrors.CertifiedNameMismatch"/>.
    /// </summary>
    [TestMethod]
    public async Task CertifiedNameMismatchIsRejected()
    {
        using Scenario scenario = BuildConformantScenario();

        //A P-256 key distinct from scenario.CredentialKey, minted on the spot so its Name mismatches the
        //Name pubArea itself computes — the CertifiedNameMismatch fixture. Raw ECDsa because
        //BuildEccPubAreaBytes calls ExportParameters directly; no project surface hands back a raw
        //ECDsa from TestKeyMaterialProvider's wrapped key-memory types.
        using ECDsa otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] wrongName = TpmAttestationTestVectors.ComputeTpmName(TpmAttestationTestVectors.BuildEccPubAreaBytes(otherKey));
        byte[] certInfoBytes = TpmAttestationTestVectors.BuildCertifyCertInfoBytes(wrongName, SignerName, scenario.ExtraData);
        (byte[] r, byte[] s) = TpmAttestationTestVectors.SignWithEcdsaP256Components(scenario.AikKey, certInfoBytes);
        byte[] sigBytes = TpmAttestationTestVectors.BuildEcdsaSignatureBytes(TpmAlgIdConstants.TPM_ALG_SHA256, r, s);

        Fido2AttestationError? error = await RunAndGetErrorAsync(scenario, certInfoOverride: certInfoBytes, sigOverride: sigBytes).ConfigureAwait(false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CertifiedNameMismatch.Code, error.Code);
    }


    /// <summary>
    /// A parse delegate simulating a real CBOR codec that rejects a malformed <c>attStmt</c> throws
    /// <see cref="Fido2FormatException"/>, mapped to <see cref="Fido2AttestationErrors.MalformedStatement"/>.
    /// </summary>
    [TestMethod]
    public async Task CborParseFailureIsRejectedWithMalformedStatement()
    {
        using Scenario scenario = BuildConformantScenario();
        AttestationVerifyDelegate verify = BuildVerifier(TpmAttestationTestVectors.CreateThrowingParser("attStmt is not a CTAP2 canonical CBOR map."));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            scenario.AuthDataBytes, scenario.AuthenticatorData, scenario.ClientDataHash, ReadOnlyMemory<byte>.Empty, [scenario.RootPki], TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<RejectedAttestationResult>(result);
        Assert.AreEqual(Fido2AttestationErrors.MalformedStatement.Code, ((RejectedAttestationResult)result).Error.Code);
    }


    /// <summary>A structurally invalid (too-short) <c>pubArea</c> is rejected — <see cref="Fido2AttestationErrors.MalformedStatement"/>.</summary>
    [TestMethod]
    public async Task TruncatedPubAreaIsRejectedWithMalformedStatement()
    {
        using Scenario scenario = BuildConformantScenario();

        Fido2AttestationError? error = await RunAndGetErrorAsync(scenario, pubAreaOverride: new byte[] { 0x00, 0x17 }).ConfigureAwait(false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.MalformedStatement.Code, error.Code);
    }


    /// <summary>A structurally invalid (too-short) <c>certInfo</c> is rejected — <see cref="Fido2AttestationErrors.MalformedStatement"/>.</summary>
    [TestMethod]
    public async Task TruncatedCertInfoIsRejectedWithMalformedStatement()
    {
        using Scenario scenario = BuildConformantScenario();

        Fido2AttestationError? error = await RunAndGetErrorAsync(scenario, certInfoOverride: [0xFF, 0x54, 0x43, 0x47]).ConfigureAwait(false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.MalformedStatement.Code, error.Code);
    }


    /// <summary>
    /// A <c>certInfo</c> truncated to exactly the TPMS_CLOCK_INFO.<c>safe</c> single-byte boundary — the
    /// wire position where the fixed pooled <c>qualifiedSigner</c>/<c>extraData</c> fields have already
    /// been rented and the very next read is the one-byte TPMI_YES_NO — is rejected with
    /// <see cref="Fido2AttestationErrors.MalformedStatement"/>, the same classification every other
    /// short-buffer <c>certInfo</c> gets.
    /// </summary>
    [TestMethod]
    public async Task TruncatedCertInfoAtClockInfoSafeByteBoundaryIsRejectedWithMalformedStatement()
    {
        using Scenario scenario = BuildConformantScenario();

        int offsetBeforeSafeByte = sizeof(uint) + sizeof(ushort)
            + (sizeof(ushort) + SignerName.Length)
            + (sizeof(ushort) + scenario.ExtraData.Length)
            + sizeof(ulong) + sizeof(uint) + sizeof(uint);
        byte[] truncatedCertInfo = scenario.CertInfoBytes[..offsetBeforeSafeByte];

        Fido2AttestationError? error = await RunAndGetErrorAsync(scenario, certInfoOverride: truncatedCertInfo).ConfigureAwait(false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.MalformedStatement.Code, error.Code);
    }


    /// <summary>
    /// A <c>pubArea</c> declaring an MLDSA key, truncated to exactly the TPMS_MLDSA_PARMS.<c>allowExternalMu</c>
    /// single-byte boundary, is rejected with <see cref="Fido2AttestationErrors.MalformedStatement"/> — the
    /// pubArea-side analogue of <see cref="TruncatedCertInfoAtClockInfoSafeByteBoundaryIsRejectedWithMalformedStatement"/>,
    /// hitting the same single-byte TpmReader.ReadByte read from the parameters side of TPMT_PUBLIC rather
    /// than certInfo's clockInfo.
    /// </summary>
    [TestMethod]
    public async Task TruncatedMlDsaPubAreaAtAllowExternalMuByteBoundaryIsRejectedWithMalformedStatement()
    {
        using Scenario scenario = BuildConformantScenario();

        //TPMT_PUBLIC prefix (type, nameAlg, objectAttributes, an empty TPM2B_DIGEST authPolicy) followed by
        //TPMS_MLDSA_PARMS.parameterSet, deliberately stopping one byte short of allowExternalMu (TPMI_YES_NO)
        //so TpmsMlDsaParms.Parse's TpmiYesNo.Parse -> TpmReader.ReadByte exhausts the buffer.
        const int TruncatedPubAreaLength = sizeof(ushort) + sizeof(ushort) + sizeof(uint) + sizeof(ushort) + sizeof(ushort);
        using IMemoryOwner<byte> truncatedPubAreaOwner = BaseMemoryPool.Shared.Rent(TruncatedPubAreaLength);
        Span<byte> truncatedPubAreaSpan = truncatedPubAreaOwner.Memory.Span[..TruncatedPubAreaLength];
        var writer = new TpmWriter(truncatedPubAreaSpan);
        writer.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_MLDSA);
        writer.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_SHA256);
        writer.WriteUInt32(0);
        writer.WriteUInt16(0);
        writer.WriteUInt16((ushort)TpmMlDsaParameterSet.TPM_MLDSA_44);

        Fido2AttestationError? error = await RunAndGetErrorAsync(scenario, pubAreaOverride: truncatedPubAreaOwner.Memory[..TruncatedPubAreaLength]).ConfigureAwait(false);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.MalformedStatement.Code, error.Code);
    }


    /// <summary>The fixed dummy Name used for the AIK's own <c>qualifiedSigner</c> — ignored by section 8.3's verification procedure.</summary>
    private static byte[] SignerName { get; } = [0x00, 0x0B, .. new byte[32]];


    /// <summary>
    /// The full set of pieces a conformant <c>tpm</c> attestation statement is built from, so a test
    /// can override exactly one piece downstream while holding the rest conformant. Owns every
    /// disposable piece it carries; a test disposes it via a <see langword="using"/> declaration.
    /// </summary>
    private sealed class Scenario: IDisposable
    {
        public required ECDsa RootKey { get; init; }
        public required ECDsa CredentialKey { get; init; }
        public required ECDsa AikKey { get; init; }
        public required X509Certificate2 RootCertificate { get; init; }
        public required X509Certificate2 AikCertificate { get; init; }
        public required PkiCertificateMemory RootPki { get; init; }
        public required PkiCertificateMemory AikPki { get; init; }
        public required byte[] PubAreaBytes { get; init; }
        public required byte[] ExtraData { get; init; }
        public required byte[] CertInfoBytes { get; init; }
        public required byte[] SignatureBytes { get; init; }
        public required AuthenticatorData AuthenticatorData { get; init; }
        public required byte[] AuthDataBytes { get; init; }
        public required DigestValue ClientDataHash { get; init; }

        public void Dispose()
        {
            RootKey.Dispose();
            CredentialKey.Dispose();
            AikKey.Dispose();
            RootCertificate.Dispose();
            AikCertificate.Dispose();
            RootPki.Dispose();
            AikPki.Dispose();
            AuthenticatorData.Dispose();
            ClientDataHash.Dispose();
        }
    }


    /// <summary>Builds a fully section 8.3/8.3.1-conformant scenario.</summary>
    private static Scenario BuildConformantScenario()
    {
        //rootKey/aikKey feed the section 8.3.1 AIK certificate chain via CertificateRequest (cert-factory
        //carve-out); aikKey separately signs certInfo directly below as the independent oracle the
        //verifier validates against (oracle carve-out). credentialKey has no library-crypto role of its
        //own — the same ECDsa instance is shared, unmodified, between CreateP256CoseKey and
        //BuildEccPubAreaBytes so both wire views encode the identical public point, and both callees are
        //typed to ECDsa.
        ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECDsa aikKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();

        X509Certificate2 rootCertificate = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test TPM Vendor Root", rootKey);
        X509Certificate2 aikCertificate = TpmAttestationTestVectors.CreateAikCertificate(rootCertificate, aikKey);

        DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(
            aaguid, Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256), out byte[] authDataBytes);
        byte[] attToBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);

        //Independent-oracle carve-out: SHA-256 over attToBeSigned recomputes the exact digest certInfo's
        //extraData must carry for TpmAttestation's own digest check to pass.
        byte[] extraData = SHA256.HashData(attToBeSigned);

        byte[] pubAreaBytes = TpmAttestationTestVectors.BuildEccPubAreaBytes(credentialKey);
        byte[] certifiedName = TpmAttestationTestVectors.ComputeTpmName(pubAreaBytes);
        byte[] certInfoBytes = TpmAttestationTestVectors.BuildCertifyCertInfoBytes(certifiedName, SignerName, extraData);
        (byte[] r, byte[] s) = TpmAttestationTestVectors.SignWithEcdsaP256Components(aikKey, certInfoBytes);
        byte[] signatureBytes = TpmAttestationTestVectors.BuildEcdsaSignatureBytes(TpmAlgIdConstants.TPM_ALG_SHA256, r, s);

        return new Scenario
        {
            RootKey = rootKey,
            CredentialKey = credentialKey,
            AikKey = aikKey,
            RootCertificate = rootCertificate,
            AikCertificate = aikCertificate,
            RootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCertificate.RawData),
            AikPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(aikCertificate.RawData),
            PubAreaBytes = pubAreaBytes,
            ExtraData = extraData,
            CertInfoBytes = certInfoBytes,
            SignatureBytes = signatureBytes,
            AuthenticatorData = authenticatorData,
            AuthDataBytes = authDataBytes,
            ClientDataHash = clientDataHash
        };
    }


    /// <summary>Runs the verifier for the conformant scenario, applying no overrides.</summary>
    private async Task<AttestationResult> RunAsync(Scenario scenario) =>
        await RunAsync(
            scenario, scenario.PubAreaBytes, scenario.CertInfoBytes, scenario.SignatureBytes,
            [scenario.AikPki, scenario.RootPki], [scenario.RootPki], scenario.AuthenticatorData, scenario.AuthDataBytes, WellKnownCoseAlgorithms.Es256).ConfigureAwait(false);


    /// <summary>Runs the verifier with exactly one piece of the scenario overridden, and returns the resulting rejection error, if any.</summary>
    private async Task<Fido2AttestationError?> RunAndGetErrorAsync(
        Scenario scenario,
        ReadOnlyMemory<byte>? pubAreaOverride = null,
        byte[]? certInfoOverride = null,
        byte[]? sigOverride = null,
        IReadOnlyList<PkiCertificateMemory>? x5cOverride = null,
        IReadOnlyList<PkiCertificateMemory>? trustAnchorsOverride = null,
        X509Certificate2? aikCertificateOverride = null,
        AuthenticatorData? authenticatorDataOverride = null,
        byte[]? authDataBytesOverride = null,
        int? algOverride = null)
    {
        PkiCertificateMemory? overrideAikPki = aikCertificateOverride is not null
            ? Fido2AttestationTestVectors.ToPkiCertificateMemory(aikCertificateOverride.RawData)
            : null;
        try
        {
            IReadOnlyList<PkiCertificateMemory> x5c = x5cOverride
                ?? (overrideAikPki is not null ? [overrideAikPki, scenario.RootPki] : [scenario.AikPki, scenario.RootPki]);

            AttestationResult result = await RunAsync(
                scenario,
                pubAreaOverride ?? scenario.PubAreaBytes,
                certInfoOverride ?? scenario.CertInfoBytes,
                sigOverride ?? scenario.SignatureBytes,
                x5c,
                trustAnchorsOverride ?? [scenario.RootPki],
                authenticatorDataOverride ?? scenario.AuthenticatorData,
                authDataBytesOverride ?? scenario.AuthDataBytes,
                algOverride ?? WellKnownCoseAlgorithms.Es256).ConfigureAwait(false);

            return result is RejectedAttestationResult rejected ? rejected.Error : null;
        }
        finally
        {
            overrideAikPki?.Dispose();
        }
    }


    /// <summary>Assembles a statement/request from the given pieces and runs the verifier.</summary>
    private async Task<AttestationResult> RunAsync(
        Scenario scenario,
        ReadOnlyMemory<byte> pubArea,
        byte[] certInfo,
        byte[] sig,
        IReadOnlyList<PkiCertificateMemory> x5c,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        AuthenticatorData authenticatorData,
        byte[] authDataBytes,
        int alg)
    {
        var statement = new TpmAttestationStatement(alg, sig, certInfo, pubArea, x5c);
        AttestationVerifyDelegate verify = BuildVerifier(TpmAttestationTestVectors.CreateStatementParser(statement));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, scenario.ClientDataHash, ReadOnlyMemory<byte>.Empty, trustAnchors, TestClock.CanonicalEpoch);

        return await verify(request, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Builds the <see cref="TpmAttestation"/> verifier under a given statement parser.</summary>
    private static AttestationVerifyDelegate BuildVerifier(ParseTpmAttestationStatementDelegate parseStatement) =>
        TpmAttestation.Build(
            parseStatement,
            MicrosoftX509Functions.ValidateChainAsync,
            MicrosoftX509Functions.ReadCertificateProfile,
            MicrosoftX509Functions.ReadCertificateExtensionValue);
}
