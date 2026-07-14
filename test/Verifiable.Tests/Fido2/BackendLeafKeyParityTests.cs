using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Backend leaf-key-extraction parity tests: for every X.509 leaf public-key algorithm the two
/// chain-validation backends support (EC P-256/P-384/P-521, RSA-2048/4096), mints one root-to-leaf
/// chain, validates it through BOTH <see cref="MicrosoftX509Functions.ValidateChainAsync"/> and
/// <see cref="BouncyCastleX509Functions.ValidateChainAsync"/>, and asserts the two returned leaf
/// <see cref="PublicKeyMemory"/> values agree on <see cref="Tag"/> and on their byte content — the
/// regression net that catches any future backend key-extraction format drift, such as the RSA PKCS#1
/// encoding gap the two backends' leaf-key extraction once had between them.
/// </summary>
[TestClass]
internal sealed class BackendLeafKeyParityTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>A P-256 leaf key extracts to the same tag and bytes on both backends.</summary>
    [TestMethod]
    public async Task P256LeafKeyMatchesAcrossBackends()
    {
        //Cert-factory carve-out: this key is signing input to CreateLeafAttestationCertificate's CertificateRequest, which requires a framework ECDsa instance.
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await AssertLeafKeyParityAsync(leafKey);
    }


    /// <summary>A P-384 leaf key extracts to the same tag and bytes on both backends.</summary>
    [TestMethod]
    public async Task P384LeafKeyMatchesAcrossBackends()
    {
        //Cert-factory carve-out: this key is signing input to CreateLeafAttestationCertificate's CertificateRequest, which requires a framework ECDsa instance.
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        await AssertLeafKeyParityAsync(leafKey);
    }


    /// <summary>A P-521 leaf key extracts to the same tag and bytes on both backends.</summary>
    [TestMethod]
    public async Task P521LeafKeyMatchesAcrossBackends()
    {
        //Cert-factory carve-out: this key is signing input to CreateLeafAttestationCertificate's CertificateRequest, which requires a framework ECDsa instance.
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        await AssertLeafKeyParityAsync(leafKey);
    }


    /// <summary>
    /// An RSA-2048 leaf key extracts to the same tag and bytes on both backends — the regression test
    /// for the RSA PKCS#1 encoding gap <see cref="BouncyCastleX509Functions"/> once had relative to
    /// <see cref="MicrosoftX509Functions"/>.
    /// </summary>
    [TestMethod]
    public async Task Rsa2048LeafKeyMatchesAcrossBackends()
    {
        //Cert-factory carve-out: this key is signing input to CreateRsaLeafCertificateWithAuthorityKeyIdentifier's CertificateRequest, which requires a framework RSA instance.
        using RSA leafKey = RSA.Create(2048);
        await AssertLeafKeyParityAsync(leafKey);
    }


    /// <summary>An RSA-4096 leaf key extracts to the same tag and bytes on both backends.</summary>
    [TestMethod]
    public async Task Rsa4096LeafKeyMatchesAcrossBackends()
    {
        //Cert-factory carve-out: this key is signing input to CreateRsaLeafCertificateWithAuthorityKeyIdentifier's CertificateRequest, which requires a framework RSA instance.
        using RSA leafKey = RSA.Create(4096);
        await AssertLeafKeyParityAsync(leafKey);
    }


    /// <summary>
    /// Both backends' <see cref="ExtractAuthorityKeyIdentifierDelegate"/> implementations
    /// (<see cref="MicrosoftX509Functions.GetAuthorityKeyIdentifier"/> and
    /// <see cref="BouncyCastleX509Functions.GetAuthorityKeyIdentifier"/>) read the identical
    /// base64url-encoded AuthorityKeyIdentifier <c>KeyIdentifier</c> bytes from the same minted
    /// certificate.
    /// </summary>
    [TestMethod]
    public void AuthorityKeyIdentifierMatchesAcrossBackends()
    {
        //Cert-factory carve-out: both keys are signing input to CreateSelfSignedCa/CreateLeafAttestationCertificate's CertificateRequest calls, which require framework ECDsa instances.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Parity Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert,
            leafKey,
            isCertificateAuthority: false,
            Fido2AttestationTestVectors.RequiredOrganizationalUnit,
            aaguidExtensionValue: null,
            additionalExtensions: [Fido2AttestationTestVectors.CreateLeafAuthorityKeyIdentifierExtension(rootCert)]);
        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);

        string? microsoftKeyIdentifier = MicrosoftX509Functions.GetAuthorityKeyIdentifier(leafPki, TestSetup.Base64UrlEncoder);
        string? bouncyCastleKeyIdentifier = BouncyCastleX509Functions.GetAuthorityKeyIdentifier(leafPki, TestSetup.Base64UrlEncoder);

        Assert.IsNotNull(microsoftKeyIdentifier);
        Assert.IsNotNull(bouncyCastleKeyIdentifier);
        Assert.AreEqual(microsoftKeyIdentifier, bouncyCastleKeyIdentifier);
    }


    /// <summary>Both backends report <see langword="null"/> for a certificate carrying no AuthorityKeyIdentifier extension.</summary>
    [TestMethod]
    public void AuthorityKeyIdentifierIsNullOnBothBackendsWhenExtensionAbsent()
    {
        //Cert-factory carve-out: this key is signing input to CreateSelfSignedCa's CertificateRequest, which requires a framework ECDsa instance.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Parity Root", rootKey);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        //CreateSelfSignedCa adds no AuthorityKeyIdentifier extension to the self-signed root.
        Assert.IsNull(MicrosoftX509Functions.GetAuthorityKeyIdentifier(rootPki, TestSetup.Base64UrlEncoder));
        Assert.IsNull(BouncyCastleX509Functions.GetAuthorityKeyIdentifier(rootPki, TestSetup.Base64UrlEncoder));
    }


    /// <summary>
    /// Mints a root CA and an EC leaf certificate signed by it, then asserts the two backends' extracted
    /// leaf keys agree.
    /// </summary>
    /// <param name="leafKey">The leaf's own EC key pair.</param>
    private async Task AssertLeafKeyParityAsync(ECDsa leafKey)
    {
        //Cert-factory carve-out: this key is signing input to CreateSelfSignedCa's CertificateRequest, which requires a framework ECDsa instance.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Parity Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert,
            leafKey,
            isCertificateAuthority: false,
            Fido2AttestationTestVectors.RequiredOrganizationalUnit,
            aaguidExtensionValue: null,
            additionalExtensions: [Fido2AttestationTestVectors.CreateLeafAuthorityKeyIdentifierExtension(rootCert)]);

        await AssertLeafKeyParityAsync(rootCert.RawData, leafCert.RawData);
    }


    /// <summary>
    /// Mints a root CA and an RSA leaf certificate signed by it, then asserts the two backends'
    /// extracted leaf keys agree.
    /// </summary>
    /// <param name="leafKey">The leaf's own RSA key pair.</param>
    private async Task AssertLeafKeyParityAsync(RSA leafKey)
    {
        //Cert-factory carve-out: this key is signing input to CreateSelfSignedCa's CertificateRequest, which requires a framework ECDsa instance.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Parity Root", rootKey);
        using X509Certificate2 leafCert = CreateRsaLeafCertificateWithAuthorityKeyIdentifier(rootCert, leafKey);

        await AssertLeafKeyParityAsync(rootCert.RawData, leafCert.RawData);
    }


    /// <summary>
    /// Validates the leaf-first, two-certificate chain through both X.509 backends and asserts the two
    /// returned leaf public keys are <see cref="Tag"/>-equal and byte-equal.
    /// </summary>
    /// <param name="rootDer">The root CA certificate's DER bytes.</param>
    /// <param name="leafDer">The leaf certificate's DER bytes.</param>
    private async Task AssertLeafKeyParityAsync(byte[] rootDer, byte[] leafDer)
    {
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootDer);
        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafDer);
        IReadOnlyList<PkiCertificateMemory> chain = [leafPki, rootPki];
        IReadOnlyList<PkiCertificateMemory> trustAnchors = [rootPki];
        DateTimeOffset validationTime = TestClock.CanonicalEpoch;

        using PublicKeyMemory microsoftKey = await MicrosoftX509Functions.ValidateChainAsync(
            chain, trustAnchors, validationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);
        using PublicKeyMemory bouncyCastleKey = await BouncyCastleX509Functions.ValidateChainAsync(
            chain, trustAnchors, validationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(microsoftKey.Tag, bouncyCastleKey.Tag);
        Assert.IsTrue(microsoftKey.AsReadOnlySpan().SequenceEqual(bouncyCastleKey.AsReadOnlySpan()));
    }


    /// <summary>
    /// Mints an RSA leaf certificate issued by <paramref name="issuerCertificate"/>, carrying a Subject
    /// Key Identifier and an Authority Key Identifier referencing the issuer — the ambiguous-issuer-safe
    /// minting convention this suite's certificates follow — since
    /// <see cref="Fido2AttestationTestVectors.CreateLeafAttestationCertificateWithRsaKey"/> exposes no
    /// <c>additionalExtensions</c> parameter to add one.
    /// </summary>
    /// <param name="issuerCertificate">The issuing CA certificate (private key attached).</param>
    /// <param name="leafKey">The leaf's own RSA key pair; the private half is attached to the result.</param>
    /// <returns>The leaf certificate, private key attached.</returns>
    private static X509Certificate2 CreateRsaLeafCertificateWithAuthorityKeyIdentifier(X509Certificate2 issuerCertificate, RSA leafKey)
    {
        //Cert-factory carve-out: mints an X.509 leaf certificate via CertificateRequest, the framework's own chain-minting primitive.
        var request = new CertificateRequest(
            $"C=US, O=Test Authenticator Vendor, OU={Fido2AttestationTestVectors.RequiredOrganizationalUnit}, CN=Test Authenticator",
            leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
        request.CertificateExtensions.Add(Fido2AttestationTestVectors.CreateLeafAuthorityKeyIdentifierExtension(issuerCertificate));

        //Cert-factory carve-out: GetECDsaPrivateKey and X509SignatureGenerator are the framework's own
        //chain-signing primitives, the same category as CertificateRequest itself.
        //CertificateRequest.Create(X509Certificate2, ...) requires the issuer's key algorithm to match
        //the request's own; an RSA leaf signed by the EC test root needs the explicit
        //X509SignatureGenerator overload instead, mirroring Fido2AttestationTestVectors's own RSA
        //leaf-minting helper.
        using ECDsa issuerKey = issuerCertificate.GetECDsaPrivateKey()
            ?? throw new ArgumentException("Issuer certificate must carry an ECDsa private key.", nameof(issuerCertificate));
        X509SignatureGenerator issuerSignatureGenerator = X509SignatureGenerator.CreateForECDsa(issuerKey);

        byte[] serialNumber = RandomNumberGenerator.GetBytes(16);
        return request.Create(
            issuerCertificate.SubjectName,
            issuerSignatureGenerator,
            notBefore: new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
            notAfter: new DateTimeOffset(2029, 1, 1, 0, 0, 0, TimeSpan.Zero),
            serialNumber).CopyWithPrivateKey(leafKey);
    }
}
