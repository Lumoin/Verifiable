using System.Buffers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for the <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements">WebAuthn
/// L3 section 8.2.1</see> certificate-profile completeness of <see cref="PackedAttestation"/>'s certified branch:
/// the Subject-C/O/CN requirements, the AAGUID extension criticality rejection, certificate validity-window
/// enforcement, and the algorithm-mismatch/legacy-field fail-closed contracts.
/// </summary>
/// <remarks>
/// Every fixture mints its certificate chain and attestation signature with an independent oracle — raw
/// <see cref="ECDsa"/> and <see cref="CertificateRequest"/>, never the library's own signing or chain-building
/// seams — so <see cref="PackedAttestation"/> is exercised against genuinely external wire material
/// reconstructed solely from the <see cref="AttestationVerificationRequest"/>'s wire-shaped members.
/// </remarks>
[TestClass]
internal sealed class PackedCertificateProfileTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>The fixed instant the validity-window boundary tests evaluate chain validation at.</summary>
    private static DateTimeOffset ValidationTime { get; } = new(2026, 7, 4, 0, 0, 0, TimeSpan.Zero);


    /// <summary>A leaf omitting the required Subject-C is rejected with <see cref="Fido2AttestationErrors.CertificateProfileViolation"/>.</summary>
    [TestMethod]
    public async Task MissingSubjectCountryIsRejectedWithCertificateProfileViolation()
    {
        Fido2AttestationError? error = await VerifyConformantChainWithLeafOverrideAsync(country: null);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CertificateProfileViolation.Code, error.Code);
    }


    /// <summary>A leaf omitting the required Subject-O is rejected with <see cref="Fido2AttestationErrors.CertificateProfileViolation"/>.</summary>
    [TestMethod]
    public async Task MissingSubjectOrganizationIsRejectedWithCertificateProfileViolation()
    {
        Fido2AttestationError? error = await VerifyConformantChainWithLeafOverrideAsync(organization: null);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CertificateProfileViolation.Code, error.Code);
    }


    /// <summary>A leaf omitting the required Subject-CN is rejected with <see cref="Fido2AttestationErrors.CertificateProfileViolation"/>.</summary>
    [TestMethod]
    public async Task MissingSubjectCommonNameIsRejectedWithCertificateProfileViolation()
    {
        Fido2AttestationError? error = await VerifyConformantChainWithLeafOverrideAsync(commonName: null);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CertificateProfileViolation.Code, error.Code);
    }


    /// <summary>
    /// A leaf whose Subject-C is the ISO 3166-1 user-assigned code <c>AA</c> is rejected with
    /// <see cref="Fido2AttestationErrors.CertificateProfileViolation"/>.
    /// </summary>
    [TestMethod]
    public async Task SubjectCountryUserAssignedAaIsRejectedWithCertificateProfileViolation()
    {
        Fido2AttestationError? error = await VerifyConformantChainWithLeafOverrideAsync(country: "AA");

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CertificateProfileViolation.Code, error.Code);
    }


    /// <summary>
    /// A leaf whose Subject-C is <c>XZ</c> — within the ISO 3166-1 user-assigned <c>X*</c> range — is
    /// rejected with <see cref="Fido2AttestationErrors.CertificateProfileViolation"/>.
    /// </summary>
    [TestMethod]
    public async Task SubjectCountryUserAssignedXzIsRejectedWithCertificateProfileViolation()
    {
        Fido2AttestationError? error = await VerifyConformantChainWithLeafOverrideAsync(country: "XZ");

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CertificateProfileViolation.Code, error.Code);
    }


    /// <summary>A lowercase Subject-C fails the structural "two ASCII uppercase letters" check.</summary>
    [TestMethod]
    public async Task SubjectCountryLowercaseIsRejectedWithCertificateProfileViolation()
    {
        Fido2AttestationError? error = await VerifyConformantChainWithLeafOverrideAsync(country: "us");

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CertificateProfileViolation.Code, error.Code);
    }


    /// <summary>A three-letter Subject-C fails the structural "exactly two letters" check.</summary>
    [TestMethod]
    public async Task SubjectCountryThreeLettersIsRejectedWithCertificateProfileViolation()
    {
        Fido2AttestationError? error = await VerifyConformantChainWithLeafOverrideAsync(country: "USA");

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CertificateProfileViolation.Code, error.Code);
    }


    /// <summary>A conformant Subject-C of <c>FI</c> — not user-assigned — passes the profile check.</summary>
    [TestMethod]
    public async Task ConformantCountryFiPassesAsCertifiedResult()
    {
        AttestationResult result = await VerifyConformantChainWithLeafOverrideRawAsync(country: "FI");

        Assert.IsInstanceOfType<CertifiedAttestationResult>(result);
    }


    /// <summary>
    /// A leaf whose <c>id-fido-gen-ce-aaguid</c> extension is marked critical is rejected with
    /// <see cref="Fido2AttestationErrors.ChainValidationFailed"/>: per RFC 5280 section 4.2, any
    /// certificate-using system MUST reject a certificate carrying an unrecognised critical
    /// extension, and BOTH chain validators this codebase registers (Microsoft's
    /// <see cref="X509Chain"/> and BouncyCastle's <c>PkixCertPathBuilder</c>) enforce exactly that
    /// during chain building — before <see cref="PackedAttestation"/>'s own section 8.2.1 "the
    /// extension MUST NOT be marked as critical" check ever runs. The two requirements police the
    /// same fact from two layers; whichever validates the certificate chain rejects it first.
    /// </summary>
    [TestMethod]
    public async Task AaguidExtensionMarkedCriticalIsRejectedWithChainValidationFailed()
    {
        //X.509 certificate factory carve-out: CertificateRequest signs the self-signed root CA with this key.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        //X.509 certificate factory carve-out: CertificateRequest signs the leaf certificate with this key, which
        //also signs the attestation transcript below as the independent oracle.
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit,
            aaguidExtensionValue: aaguid, aaguidExtensionIsCritical: true);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(
            aaguid, Fido2AttestationTestVectors.CreateP256CoseKey(leafKey, WellKnownCoseAlgorithms.Es256), out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, toBeSigned);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signature, X5c: [leafPki, rootPki]);
        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: [rootPki], validationTime: TestClock.CanonicalEpoch);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.ChainValidationFailed.Code, error.Code);
    }


    /// <summary>
    /// A leaf certificate encoded as X.509 version 1 is rejected with
    /// <see cref="Fido2AttestationErrors.CertificateProfileViolation"/>: section 8.2.1 requires
    /// version 3, which is the only version an X.509 certificate extension (Basic Constraints,
    /// Key Usage, the AAGUID extension, etc.) can be carried in, so a version-1 leaf is both a
    /// direct version violation and structurally unable to carry those required extensions.
    /// </summary>
    [TestMethod]
    public async Task LeafCertificateVersion1IsRejectedWithCertificateProfileViolation()
    {
        //X.509 certificate factory carve-out: CertificateRequest signs the self-signed root CA with this key.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        //X.509 certificate factory carve-out: CertificateRequest signs the leaf certificate with this key, which
        //also signs the attestation transcript below as the independent oracle.
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateVersion1LeafAttestationCertificate(rootCert, leafKey);
        Assert.AreEqual(1, leafCert.Version);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(
            Guid.NewGuid(), Fido2AttestationTestVectors.CreateP256CoseKey(leafKey, WellKnownCoseAlgorithms.Es256), out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, toBeSigned);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signature, X5c: [leafPki, rootPki]);
        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: [rootPki], validationTime: TestClock.CanonicalEpoch);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CertificateProfileViolation.Code, error.Code);
    }


    /// <summary>
    /// A leaf carrying the <c>id-fido-gen-ce-fw-version</c> extension marked critical is rejected
    /// with <see cref="Fido2AttestationErrors.ChainValidationFailed"/>, for the same RFC 5280
    /// section 4.2 reason documented on
    /// <see cref="AaguidExtensionMarkedCriticalIsRejectedWithChainValidationFailed"/>: both
    /// registered chain validators reject an unrecognised critical extension during chain
    /// building, before any of this layer's own extension-specific checks run. Section 8.2.1 only
    /// says the firmware-version extension "MUST NOT be marked as critical" — it is not modelled by
    /// this layer at all — so the rejection is enforced purely by that lower layer.
    /// </summary>
    [TestMethod]
    public async Task LeafWithCriticalFirmwareVersionExtensionIsRejectedWithChainValidationFailed()
    {
        //X.509 certificate factory carve-out: CertificateRequest signs the self-signed root CA with this key.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        //X.509 certificate factory carve-out: CertificateRequest signs the leaf certificate with this key, which
        //also signs the attestation transcript below as the independent oracle.
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var firmwareVersionExtension = new X509Extension(
            Fido2AttestationTestVectors.FirmwareVersionExtensionOid,
            Fido2AttestationTestVectors.EncodeFirmwareVersionExtensionValue(42),
            critical: true);

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit,
            aaguidExtensionValue: null, additionalExtensions: [firmwareVersionExtension]);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(
            Guid.NewGuid(), Fido2AttestationTestVectors.CreateP256CoseKey(leafKey, WellKnownCoseAlgorithms.Es256), out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, toBeSigned);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signature, X5c: [leafPki, rootPki]);
        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: [rootPki], validationTime: TestClock.CanonicalEpoch);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.ChainValidationFailed.Code, error.Code);
    }


    /// <summary>
    /// A leaf whose validity window ended before <c>validationTime</c> is rejected with
    /// <see cref="Fido2AttestationErrors.ChainValidationFailed"/>.
    /// </summary>
    [TestMethod]
    public async Task LeafExpiredAtValidationTimeIsRejectedWithChainValidationFailed()
    {
        DateTimeOffset notBefore = ValidationTime.AddDays(-184);
        DateTimeOffset notAfter = ValidationTime.AddDays(-33);

        Fido2AttestationError? error = await VerifyConformantChainWithValidityWindowAsync(notBefore, notAfter, ValidationTime);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.ChainValidationFailed.Code, error.Code);
    }


    /// <summary>
    /// A leaf whose validity window starts after <c>validationTime</c> is rejected with
    /// <see cref="Fido2AttestationErrors.ChainValidationFailed"/>.
    /// </summary>
    [TestMethod]
    public async Task LeafNotYetValidAtValidationTimeIsRejectedWithChainValidationFailed()
    {
        DateTimeOffset notBefore = ValidationTime.AddDays(28);
        DateTimeOffset notAfter = ValidationTime.AddDays(912);

        Fido2AttestationError? error = await VerifyConformantChainWithValidityWindowAsync(notBefore, notAfter, ValidationTime);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.ChainValidationFailed.Code, error.Code);
    }


    /// <summary>
    /// An unknown COSE <c>alg</c> (e.g. <c>-12345</c>) claimed on the certified branch is rejected with
    /// <see cref="Fido2AttestationErrors.AlgorithmMismatch"/>: an unmapped algorithm identifier cannot be
    /// consistent with any leaf key family.
    /// </summary>
    [TestMethod]
    public async Task UnknownStatementAlgOnCertifiedBranchIsRejectedWithAlgorithmMismatch()
    {
        const int unknownCoseAlgorithm = -12345;

        //X.509 certificate factory carve-out: CertificateRequest signs the self-signed root CA with this key.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        //X.509 certificate factory carve-out: CertificateRequest signs the leaf certificate with this key, which
        //also signs the attestation transcript below as the independent oracle.
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(
            aaguid, Fido2AttestationTestVectors.CreateP256CoseKey(leafKey, WellKnownCoseAlgorithms.Es256), out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, toBeSigned);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new PackedAttestationStatement(Alg: unknownCoseAlgorithm, Signature: signature, X5c: [leafPki, rootPki]);
        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: [rootPki], validationTime: TestClock.CanonicalEpoch);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.AlgorithmMismatch.Code, error.Code);
    }


    /// <summary>
    /// On the self-attestation branch, an unknown COSE <c>alg</c> that equals the credential public key's
    /// own (also unknown) <c>alg</c> still verifies to <see cref="SelfAttestationResult"/>: section 8.2's
    /// self-attestation step only checks that <c>alg</c> matches the credential public key's <c>alg</c> — it
    /// does not require the value to be a recognised algorithm identifier. For an EC2 credential the
    /// verification algorithm is resolved from <c>kty</c>/<c>crv</c> alone (unlike the RSA family, which
    /// needs <c>alg</c> to disambiguate PKCS#1 from PSS), so an unmapped <c>alg</c> does not change how the
    /// signature is checked, and a genuinely valid EC signature verifies regardless.
    /// </summary>
    [TestMethod]
    public async Task UnknownAlgOnSelfBranchWithMatchingCredentialAlgVerifiesAsSelfAttestation()
    {
        const int unknownCoseAlgorithm = -12345;

        //Independent oracle: this ECDsa both derives the credentialPublicKey below and signs the transcript
        //further down, so PackedAttestation's own COSE verify is exercised against externally produced wire material.
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, unknownCoseAlgorithm);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(credentialKey, toBeSigned);

        var statement = new PackedAttestationStatement(Alg: unknownCoseAlgorithm, Signature: signature, X5c: null);
        AttestationVerifyDelegate verify = BuildVerifier(Fido2AttestationTestVectors.CreateStatementParser(statement));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [], validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        Assert.IsInstanceOfType<SelfAttestationResult>(result);
    }


    /// <summary>
    /// A parse delegate simulating a real CBOR codec that encounters the legacy <c>ecdaaKeyId</c> member —
    /// removed from <c>attStmt</c> by WebAuthn L3 section 8.2 — throws <see cref="Fido2FormatException"/>,
    /// which is caught and mapped to <see cref="Fido2AttestationErrors.MalformedStatement"/>, exactly as any
    /// other malformed <c>attStmt</c> is.
    /// </summary>
    [TestMethod]
    public async Task LegacyEcdaaKeyIdParseFailureIsRejectedWithMalformedStatement()
    {
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), null, out byte[] authDataBytes);

        AttestationVerifyDelegate verify = BuildVerifier(Fido2AttestationTestVectors.CreateThrowingParser(
            "attStmt carries the legacy ecdaaKeyId member, removed from packed attStmt by WebAuthn L3 section 8.2."));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [], validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        Assert.IsInstanceOfType<RejectedAttestationResult>(result);
        Assert.AreEqual(Fido2AttestationErrors.MalformedStatement.Code, ((RejectedAttestationResult)result).Error.Code);
    }


    /// <summary>
    /// Mints a section 8.2.1-conformant chain overriding one Subject attribute, verifies it, and returns the
    /// rejection error, if any.
    /// </summary>
    /// <param name="country">The Subject-C override. Defaults to the conformant <c>US</c>.</param>
    /// <param name="organization">The Subject-O override. Defaults to a conformant vendor name.</param>
    /// <param name="commonName">The Subject-CN override. Defaults to a conformant vendor-chosen name.</param>
    /// <returns>The <see cref="Fido2AttestationError"/> of a <see cref="RejectedAttestationResult"/>, or <see langword="null"/>.</returns>
    private async Task<Fido2AttestationError?> VerifyConformantChainWithLeafOverrideAsync(
        string? country = "US", string? organization = "Test Authenticator Vendor", string? commonName = "Test Authenticator")
    {
        AttestationResult result = await VerifyConformantChainWithLeafOverrideRawAsync(country, organization, commonName);

        return result is RejectedAttestationResult rejected ? rejected.Error : null;
    }


    /// <summary>
    /// Mints a section 8.2.1-conformant chain overriding one Subject attribute and returns the raw
    /// <see cref="AttestationResult"/>.
    /// </summary>
    /// <param name="country">The Subject-C override. Defaults to the conformant <c>US</c>.</param>
    /// <param name="organization">The Subject-O override. Defaults to a conformant vendor name.</param>
    /// <param name="commonName">The Subject-CN override. Defaults to a conformant vendor-chosen name.</param>
    /// <returns>The raw verification result.</returns>
    private async Task<AttestationResult> VerifyConformantChainWithLeafOverrideRawAsync(
        string? country = "US", string? organization = "Test Authenticator Vendor", string? commonName = "Test Authenticator")
    {
        //X.509 certificate factory carve-out: CertificateRequest signs the self-signed root CA with this key.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        //X.509 certificate factory carve-out: CertificateRequest signs the leaf certificate with this key, which
        //also signs the attestation transcript below as the independent oracle.
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null,
            country: country, organization: organization, commonName: commonName);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(
            aaguid, Fido2AttestationTestVectors.CreateP256CoseKey(leafKey, WellKnownCoseAlgorithms.Es256), out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, toBeSigned);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signature, X5c: [leafPki, rootPki]);
        AttestationVerifyDelegate verify = BuildVerifier(Fido2AttestationTestVectors.CreateStatementParser(statement));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [rootPki], validationTime: TestClock.CanonicalEpoch);

        return await verify(request, TestContext.CancellationToken);
    }


    /// <summary>
    /// Mints a section 8.2.1-conformant chain with an explicit leaf validity window, verifies it at
    /// <paramref name="validationTime"/>, and returns the rejection error, if any.
    /// </summary>
    /// <param name="notBefore">The leaf certificate's <c>notBefore</c> instant.</param>
    /// <param name="notAfter">The leaf certificate's <c>notAfter</c> instant.</param>
    /// <param name="validationTime">The instant chain validation is evaluated at.</param>
    /// <returns>The <see cref="Fido2AttestationError"/> of a <see cref="RejectedAttestationResult"/>, or <see langword="null"/>.</returns>
    private async Task<Fido2AttestationError?> VerifyConformantChainWithValidityWindowAsync(
        DateTimeOffset notBefore, DateTimeOffset notAfter, DateTimeOffset validationTime)
    {
        //X.509 certificate factory carve-out: CertificateRequest signs the self-signed root CA with this key.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        //X.509 certificate factory carve-out: CertificateRequest signs the leaf certificate with this key, which
        //also signs the attestation transcript below as the independent oracle.
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null,
            notBefore: notBefore, notAfter: notAfter);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(
            aaguid, Fido2AttestationTestVectors.CreateP256CoseKey(leafKey, WellKnownCoseAlgorithms.Es256), out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, toBeSigned);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signature, X5c: [leafPki, rootPki]);

        return await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: [rootPki], validationTime: validationTime);
    }


    /// <summary>Builds the <see cref="PackedAttestation"/> verifier under a given statement parser.</summary>
    /// <param name="parseStatement">The stub statement parser to wire in.</param>
    /// <returns>The assembled <see cref="AttestationVerifyDelegate"/>.</returns>
    private static AttestationVerifyDelegate BuildVerifier(ParsePackedAttestationStatementDelegate parseStatement) =>
        PackedAttestation.Build(
            parseStatement,
            MicrosoftX509Functions.ValidateChainAsync,
            MicrosoftX509Functions.ReadCertificateProfile,
            MicrosoftX509Functions.ReadCertificateExtensionValue);


    /// <summary>Runs the verifier for <paramref name="statement"/> and returns the rejection error, if any.</summary>
    /// <param name="statement">The pre-built statement the stub parser returns.</param>
    /// <param name="authDataBytes">The raw <c>authData</c> bytes.</param>
    /// <param name="authenticatorData">The parsed <c>authData</c> view.</param>
    /// <param name="clientDataHash">The <c>clientDataHash</c> digest.</param>
    /// <param name="trustAnchors">The trust anchors to verify chain building against.</param>
    /// <param name="validationTime">The instant chain validation is evaluated at.</param>
    /// <returns>The <see cref="Fido2AttestationError"/> of a <see cref="RejectedAttestationResult"/>, or <see langword="null"/>.</returns>
    private async Task<Fido2AttestationError?> VerifyAndGetRejectionErrorAsync(
        PackedAttestationStatement statement,
        byte[] authDataBytes,
        AuthenticatorData authenticatorData,
        DigestValue clientDataHash,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        DateTimeOffset validationTime)
    {
        AttestationVerifyDelegate verify = BuildVerifier(Fido2AttestationTestVectors.CreateStatementParser(statement));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: trustAnchors, validationTime: validationTime);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        return result is RejectedAttestationResult rejected ? rejected.Error : null;
    }
}
