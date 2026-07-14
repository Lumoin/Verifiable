using System.Buffers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for the certified (Basic/AttCA, <c>x5c</c>-present) branch of <see cref="PackedAttestation"/> — the
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">WebAuthn L3 section 8.2</see>
/// verification procedure that validates the attestation certificate chain against supplied trust anchors,
/// enforces the <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements">section
/// 8.2.1</see> leaf certificate profile, and checks the <c>id-fido-gen-ce-aaguid</c> extension when present.
/// </summary>
/// <remarks>
/// Every fixture mints its certificate chain and attestation signature with an independent oracle — raw
/// <see cref="ECDsa"/> and <see cref="CertificateRequest"/>, never the library's own signing or chain-building
/// seams — so <see cref="PackedAttestation"/> is exercised against genuinely external wire material
/// reconstructed solely from the <see cref="AttestationVerificationRequest"/>'s wire-shaped members.
/// </remarks>
[TestClass]
internal sealed class PackedCertifiedAttestationTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A section 8.2.1-conformant leaf (OU "Authenticator Attestation", not a CA, matching AAGUID extension)
    /// chaining to a trusted root, with a valid signature and consistent <c>alg</c>, verifies to
    /// <see cref="CertifiedAttestationResult"/> of type <see cref="AttestationType.Unknown"/> — Basic and AttCA
    /// are indistinguishable without externally provided authenticator metadata — carrying the same
    /// <c>x5c</c> instances as the trust path.
    /// </summary>
    [TestMethod]
    public async Task ConformantChainWithMatchingAaguidReturnsCertifiedResultWithSameTrustPathInstances()
    {
        //Cert-factory carve-out (rootKey mints the CA only) and independent-oracle carve-out (leafKey is
        //embedded in the leaf certificate below and signs the transcript further down, so PackedAttestation
        //is exercised against genuinely external wire material).
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguid);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);

        //The registered credential key is fixture material — a role distinct from leafKey (the
        //attestation-signing key above) — never signed with or independently re-verified here, so any
        //ready-made P-256 key serves.
        var credentialKeyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(credentialKeyMaterial.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);
        credentialKeyMaterial.PublicKey.Dispose();
        credentialKeyMaterial.PrivateKey.Dispose();

        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(aaguid, credentialPublicKey, out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, toBeSigned);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        PkiCertificateMemory[] x5c = [leafPki, rootPki];

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signature, X5c: x5c);
        AttestationVerifyDelegate verify = BuildVerifier(Fido2AttestationTestVectors.CreateStatementParser(statement));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [rootPki], validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        Assert.IsInstanceOfType<CertifiedAttestationResult>(result);
        var certified = (CertifiedAttestationResult)result;
        Assert.AreEqual(AttestationType.Unknown, certified.Type);
        Assert.HasCount(2, certified.TrustPath);
        Assert.AreSame(leafPki, certified.TrustPath[0]);
        Assert.AreSame(rootPki, certified.TrustPath[1]);
    }


    /// <summary>An empty trust anchor list is rejected with <see cref="Fido2AttestationErrors.NoTrustAnchors"/> before any chain building is attempted.</summary>
    [TestMethod]
    public async Task EmptyTrustAnchorsIsRejectedWithNoTrustAnchors()
    {
        //Cert-factory carve-out (rootKey mints the CA only) and independent-oracle carve-out (leafKey also
        //derives the credentialPublicKey below and signs the transcript further down, so PackedAttestation
        //is exercised against genuinely external wire material).
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(aaguid, Fido2AttestationTestVectors.CreateP256CoseKey(leafKey, WellKnownCoseAlgorithms.Es256), out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, toBeSigned);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signature, X5c: [leafPki, rootPki]);

        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: []);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.NoTrustAnchors.Code, error.Code);
    }


    /// <summary>A chain that does not build to any supplied trust anchor is rejected with <see cref="Fido2AttestationErrors.ChainValidationFailed"/>.</summary>
    [TestMethod]
    public async Task AnchorsNotContainingTheRootIsRejectedWithChainValidationFailed()
    {
        //Cert-factory carve-out (rootKey and imposterRootKey each mint an unrelated CA certificate) and
        //independent-oracle carve-out (leafKey also derives the credentialPublicKey below and signs the
        //transcript further down, so PackedAttestation is exercised against genuinely external wire material).
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa imposterRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 imposterRootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Imposter Root", imposterRootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(aaguid, Fido2AttestationTestVectors.CreateP256CoseKey(leafKey, WellKnownCoseAlgorithms.Es256), out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, toBeSigned);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        using PkiCertificateMemory imposterRootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(imposterRootCert.RawData);

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signature, X5c: [leafPki, rootPki]);

        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: [imposterRootPki]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.ChainValidationFailed.Code, error.Code);
    }


    /// <summary>
    /// An <c>x5c</c> chain whose certificates are out of order (the root first, the attestation
    /// leaf last) is rejected: <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">
    /// section 8.2</see>'s CDDL and verification procedure both assume the attestation certificate
    /// is <c>x5c</c>'s first element, and this codebase's chain-validation delegate loads that first
    /// element as the certificate to build a path for. With the root in that position, chain
    /// building itself succeeds trivially (the root is directly present in the supplied trust
    /// anchors), so the actually-observed rejection is the section 8.2.1 certificate-profile check
    /// running against the root certificate in the leaf position — the root is a certificate
    /// authority and carries none of the required leaf Subject attributes — rather than a dedicated
    /// ordering error or the chain-building failure a leaf-first assumption might otherwise suggest.
    /// </summary>
    [TestMethod]
    public async Task MisorderedX5cChainWithLeafNotFirstIsRejectedWithCertificateProfileViolation()
    {
        //Cert-factory carve-out (rootKey mints the CA only) and independent-oracle carve-out (leafKey also
        //derives the credentialPublicKey below and signs the transcript further down, so PackedAttestation
        //is exercised against genuinely external wire material).
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(aaguid, Fido2AttestationTestVectors.CreateP256CoseKey(leafKey, WellKnownCoseAlgorithms.Es256), out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, toBeSigned);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        PkiCertificateMemory[] misorderedX5c = Fido2AttestationTestVectors.ReverseChainOrder([leafPki, rootPki]);

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signature, X5c: misorderedX5c);

        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: [rootPki]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CertificateProfileViolation.Code, error.Code);
    }


    /// <summary>A leaf missing the required Subject-OU "Authenticator Attestation" is rejected with <see cref="Fido2AttestationErrors.CertificateProfileViolation"/>.</summary>
    [TestMethod]
    public async Task LeafWithoutRequiredOrganizationalUnitIsRejectedWithCertificateProfileViolation()
    {
        //Cert-factory carve-out (rootKey mints the CA only) and independent-oracle carve-out (leafKey also
        //derives the credentialPublicKey below and signs the transcript further down, so PackedAttestation
        //is exercised against genuinely external wire material).
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, isCertificateAuthority: false, organizationalUnit: null, aaguidExtensionValue: null);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(aaguid, Fido2AttestationTestVectors.CreateP256CoseKey(leafKey, WellKnownCoseAlgorithms.Es256), out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, toBeSigned);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signature, X5c: [leafPki, rootPki]);

        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: [rootPki]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CertificateProfileViolation.Code, error.Code);
    }


    /// <summary>A leaf marked as a certificate authority is rejected with <see cref="Fido2AttestationErrors.CertificateProfileViolation"/>.</summary>
    [TestMethod]
    public async Task LeafMarkedAsCertificateAuthorityIsRejectedWithCertificateProfileViolation()
    {
        //Cert-factory carve-out (rootKey mints the CA only) and independent-oracle carve-out (leafKey also
        //derives the credentialPublicKey below and signs the transcript further down, so PackedAttestation
        //is exercised against genuinely external wire material).
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, true, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(aaguid, Fido2AttestationTestVectors.CreateP256CoseKey(leafKey, WellKnownCoseAlgorithms.Es256), out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, toBeSigned);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signature, X5c: [leafPki, rootPki]);

        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: [rootPki]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.CertificateProfileViolation.Code, error.Code);
    }


    /// <summary>
    /// A leaf whose <c>id-fido-gen-ce-aaguid</c> extension carries an AAGUID different from
    /// <c>authData</c>'s attested credential data is rejected with <see cref="Fido2AttestationErrors.AaguidMismatch"/>.
    /// </summary>
    [TestMethod]
    public async Task AaguidExtensionMismatchingAuthenticatorDataAaguidIsRejectedWithAaguidMismatch()
    {
        //Cert-factory carve-out (rootKey mints the CA only) and independent-oracle carve-out (leafKey also
        //derives the credentialPublicKey below and signs the transcript further down, so PackedAttestation
        //is exercised against genuinely external wire material).
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid certificateAaguid = Guid.NewGuid();
        Guid authDataAaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, certificateAaguid);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(authDataAaguid, Fido2AttestationTestVectors.CreateP256CoseKey(leafKey, WellKnownCoseAlgorithms.Es256), out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, toBeSigned);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signature, X5c: [leafPki, rootPki]);

        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: [rootPki]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.AaguidMismatch.Code, error.Code);
    }


    /// <summary>A tampered attestation signature is rejected with <see cref="Fido2AttestationErrors.InvalidSignature"/>.</summary>
    [TestMethod]
    public async Task TamperedSignatureIsRejectedWithInvalidSignature()
    {
        //Cert-factory carve-out (rootKey mints the CA only) and independent-oracle carve-out (leafKey also
        //derives the credentialPublicKey below and signs the transcript further down, before the resulting
        //signature is deliberately corrupted).
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(aaguid, Fido2AttestationTestVectors.CreateP256CoseKey(leafKey, WellKnownCoseAlgorithms.Es256), out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, toBeSigned);
        signature[0] ^= 0xFF;

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signature, X5c: [leafPki, rootPki]);

        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: [rootPki]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.InvalidSignature.Code, error.Code);
    }


    /// <summary>
    /// A section 8.2.1-conformant ES384 leaf, with a valid signature and consistent <c>alg</c>, verifies to
    /// <see cref="CertifiedAttestationResult"/> — the ES384 packed certified-attestation algorithm-matrix row.
    /// </summary>
    [TestMethod]
    public async Task Es384ConformantChainReturnsCertifiedResult()
    {
        //Cert-factory carve-out (rootKey mints the CA only) and independent-oracle carve-out (leafKey, P-384,
        //also derives the credentialPublicKey below and signs the transcript further down, so
        //PackedAttestation is exercised against genuinely external wire material).
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(aaguid, Fido2AttestationTestVectors.CreateP384CoseKey(leafKey, WellKnownCoseAlgorithms.Es384), out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP384(leafKey, toBeSigned);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es384, Signature: signature, X5c: [leafPki, rootPki]);
        AttestationVerifyDelegate verify = BuildVerifier(Fido2AttestationTestVectors.CreateStatementParser(statement));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [rootPki], validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        Assert.IsInstanceOfType<CertifiedAttestationResult>(result);
    }


    /// <summary>
    /// A section 8.2.1-conformant ES512 leaf, with a valid signature and consistent <c>alg</c>, verifies to
    /// <see cref="CertifiedAttestationResult"/> — the ES512 packed certified-attestation algorithm-matrix row.
    /// </summary>
    [TestMethod]
    public async Task Es512ConformantChainReturnsCertifiedResult()
    {
        //Cert-factory carve-out (rootKey mints the CA only) and independent-oracle carve-out (leafKey, P-521,
        //also derives the credentialPublicKey below and signs the transcript further down, so
        //PackedAttestation is exercised against genuinely external wire material).
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(aaguid, Fido2AttestationTestVectors.CreateP521CoseKey(leafKey, WellKnownCoseAlgorithms.Es512), out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP521(leafKey, toBeSigned);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es512, Signature: signature, X5c: [leafPki, rootPki]);
        AttestationVerifyDelegate verify = BuildVerifier(Fido2AttestationTestVectors.CreateStatementParser(statement));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [rootPki], validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        Assert.IsInstanceOfType<CertifiedAttestationResult>(result);
    }


    /// <summary>
    /// A section 8.2.1-conformant RS256 leaf — an RSA-2048 leaf key, the family the statement's <c>alg</c>
    /// must match — with a valid signature and consistent <c>alg</c>, verifies to
    /// <see cref="CertifiedAttestationResult"/> — the RS256 packed certified-attestation algorithm-matrix row.
    /// </summary>
    [TestMethod]
    public async Task Rs256ConformantChainWithRsaLeafReturnsCertifiedResult()
    {
        //Cert-factory carve-out (rootKey mints the CA only) and independent-oracle carve-out (leafKey,
        //RSA-2048, also derives the credentialPublicKey below and signs the transcript further down, so
        //PackedAttestation is exercised against genuinely external wire material).
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using RSA leafKey = RSA.Create(2048);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificateWithRsaKey(
            rootCert, leafKey, false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(aaguid, Fido2AttestationTestVectors.CreateRsaCoseKey(leafKey, WellKnownCoseAlgorithms.Rs256), out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithRsaPkcs1Sha256(leafKey, toBeSigned);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Rs256, Signature: signature, X5c: [leafPki, rootPki]);
        AttestationVerifyDelegate verify = BuildVerifier(Fido2AttestationTestVectors.CreateStatementParser(statement));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [rootPki], validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        Assert.IsInstanceOfType<CertifiedAttestationResult>(result);
    }


    /// <summary>
    /// A statement <c>alg</c> (RS256) inconsistent with the leaf certificate's actual key family (P-256 EC) is
    /// rejected with <see cref="Fido2AttestationErrors.AlgorithmMismatch"/>, even though the signature itself —
    /// resolved from the leaf key's own algorithm, not from the claimed <c>alg</c> — verifies correctly.
    /// </summary>
    [TestMethod]
    public async Task AlgInconsistentWithLeafKeyFamilyIsRejectedWithAlgorithmMismatch()
    {
        //Cert-factory carve-out (rootKey mints the CA only) and independent-oracle carve-out (leafKey also
        //derives the credentialPublicKey below and signs the transcript further down; the mismatch under
        //test is the statement's declared alg, not the signing key itself).
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(aaguid, Fido2AttestationTestVectors.CreateP256CoseKey(leafKey, WellKnownCoseAlgorithms.Es256), out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, toBeSigned);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        //RS256 (-257): a valid signature under the leaf's actual P-256 key, but an alg claim from a different key family.
        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Rs256, Signature: signature, X5c: [leafPki, rootPki]);

        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash, trustAnchors: [rootPki]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.AlgorithmMismatch.Code, error.Code);
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


    /// <summary>Runs the certified-path verifier for <paramref name="statement"/> and returns the rejection error, if any.</summary>
    /// <param name="statement">The pre-built statement the stub parser returns.</param>
    /// <param name="authDataBytes">The raw <c>authData</c> bytes.</param>
    /// <param name="authenticatorData">The parsed <c>authData</c> view.</param>
    /// <param name="clientDataHash">The <c>clientDataHash</c> digest.</param>
    /// <param name="trustAnchors">The trust anchors to verify chain building against.</param>
    /// <returns>The <see cref="Fido2AttestationError"/> of a <see cref="RejectedAttestationResult"/>, or <see langword="null"/>.</returns>
    private async Task<Fido2AttestationError?> VerifyAndGetRejectionErrorAsync(
        PackedAttestationStatement statement,
        byte[] authDataBytes,
        AuthenticatorData authenticatorData,
        DigestValue clientDataHash,
        IReadOnlyList<PkiCertificateMemory> trustAnchors)
    {
        AttestationVerifyDelegate verify = BuildVerifier(Fido2AttestationTestVectors.CreateStatementParser(statement));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: trustAnchors, validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        return result is RejectedAttestationResult rejected ? rejected.Error : null;
    }
}
