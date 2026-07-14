using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="MetadataBlobVerification"/>: signature, chain, serial-number, staleness, and
/// status-gating enforcement, all through the SHIPPED <see cref="MetadataBlobReader"/> default —
/// every BLOB minted fresh under an independent, self-contained MDS root/signer PKI.
/// </summary>
[TestClass]
internal sealed class MetadataBlobVerificationTests
{
    /// <summary>The fixed instant every test in this file validates against.</summary>
    private static DateTimeOffset ValidationTime { get; } = new(2027, 6, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The tenant every test in this file uses unless it is itself testing tenant threading.</summary>
    private static TenantId DefaultTenantId { get; } = new("mds-verification-tests");

    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>A well-formed ES256 BLOB, chained to its configured trust anchor, verifies successfully.</summary>
    [TestMethod]
    public async Task VerifiedHappyPathEs256()
    {
        using MdsPkiFixture fixture = MetadataBlobTestVectors.CreateMdsPkiFixture();
        byte[] blobBytes = BuildSignedBlob(fixture, WellKnownJwaValues.Es256, out _);

        using PkiCertificateMemory rootPki = MetadataBlobTestVectors.ToPkiCertificateMemory(fixture.RootCertificate.RawData);
        MetadataBlobResult result = await VerifyAsync(blobBytes, [rootPki]);

        Assert.IsInstanceOfType<VerifiedMetadataBlobResult>(result);
        ((VerifiedMetadataBlobResult)result).Blob.Dispose();
    }


    /// <summary>A well-formed RS256 BLOB, signed by an RSA leaf issued from the EC root, verifies successfully.</summary>
    [TestMethod]
    public async Task VerifiedHappyPathRs256()
    {
        //Cert-factory carve-out: this key is signing input to CreateMdsRootCa's CertificateRequest.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Root Rsa", rootKey);
        //Cert-factory carve-out (signing input to CreateMdsSigningCertificateRsa's CertificateRequest) and independent
        //oracle: SignRs256 below signs the BLOB with this raw RSA key, and the library's own RS256 verifier is proven
        //against that independent signature.
        using RSA signingKey = RSA.Create(2048);
        using X509Certificate2 signingCertificate = MetadataBlobTestVectors.CreateMdsSigningCertificateRsa(rootCertificate, signingKey);

        string entryJson = MetadataBlobTestVectors.BuildEntryJson(aaguid: Guid.NewGuid());
        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Rs256, [signingCertificate.RawData]);
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [entryJson]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignRs256(signingKey, data));

        using PkiCertificateMemory rootPki = MetadataBlobTestVectors.ToPkiCertificateMemory(rootCertificate.RawData);
        MetadataBlobResult result = await VerifyAsync(blobBytes, [rootPki]);

        Assert.IsInstanceOfType<VerifiedMetadataBlobResult>(result);
        ((VerifiedMetadataBlobResult)result).Blob.Dispose();
    }


    /// <summary>A BLOB whose signature segment is tampered after signing fails signature verification.</summary>
    [TestMethod]
    public async Task SignatureTamperIsRejected()
    {
        using MdsPkiFixture fixture = MetadataBlobTestVectors.CreateMdsPkiFixture();
        byte[] blobBytes = MetadataBlobTestVectors.TamperSignatureSegment(BuildSignedBlob(fixture, WellKnownJwaValues.Es256, out _));

        using PkiCertificateMemory rootPki = MetadataBlobTestVectors.ToPkiCertificateMemory(fixture.RootCertificate.RawData);
        Fido2MetadataError? error = await VerifyAndGetRejectionErrorAsync(blobBytes, [rootPki]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2MetadataErrors.InvalidBlobSignature.Code, error.Code);
    }


    /// <summary>A BLOB whose <c>x5c</c> chains to a root that is not the configured trust anchor is rejected.</summary>
    [TestMethod]
    public async Task WrongRootIsRejected()
    {
        using MdsPkiFixture fixture = MetadataBlobTestVectors.CreateMdsPkiFixture();
        byte[] blobBytes = BuildSignedBlob(fixture, WellKnownJwaValues.Es256, out _);

        //Cert-factory carve-out: this key is signing input to CreateMdsRootCa's CertificateRequest.
        using ECDsa untrustedRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 untrustedRoot = MetadataBlobTestVectors.CreateMdsRootCa("CN=Untrusted MDS Root", untrustedRootKey);
        using PkiCertificateMemory untrustedRootPki = MetadataBlobTestVectors.ToPkiCertificateMemory(untrustedRoot.RawData);

        Fido2MetadataError? error = await VerifyAndGetRejectionErrorAsync(blobBytes, [untrustedRootPki]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2MetadataErrors.BlobChainValidationFailed.Code, error.Code);
    }


    /// <summary>A BLOB verified with no supplied trust anchors is rejected.</summary>
    [TestMethod]
    public async Task NoTrustAnchorsIsRejected()
    {
        using MdsPkiFixture fixture = MetadataBlobTestVectors.CreateMdsPkiFixture();
        byte[] blobBytes = BuildSignedBlob(fixture, WellKnownJwaValues.Es256, out _);

        Fido2MetadataError? error = await VerifyAndGetRejectionErrorAsync(blobBytes, []);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2MetadataErrors.NoBlobTrustAnchors.Code, error.Code);
    }


    /// <summary>A BLOB whose JWT Header declares <c>alg:"none"</c> is rejected by the algorithm allowlist.</summary>
    [TestMethod]
    public async Task UnsupportedAlgorithmNoneIsRejected()
    {
        using MdsPkiFixture fixture = MetadataBlobTestVectors.CreateMdsPkiFixture();
        byte[] blobBytes = BuildSignedBlob(fixture, WellKnownJwaValues.None, out _);

        using PkiCertificateMemory rootPki = MetadataBlobTestVectors.ToPkiCertificateMemory(fixture.RootCertificate.RawData);
        Fido2MetadataError? error = await VerifyAndGetRejectionErrorAsync(blobBytes, [rootPki]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2MetadataErrors.UnsupportedBlobAlgorithm.Code, error.Code);
    }


    /// <summary>A BLOB whose JWT Header declares <c>alg:"HS256"</c> is rejected by the algorithm allowlist.</summary>
    [TestMethod]
    public async Task UnsupportedAlgorithmHs256IsRejected()
    {
        using MdsPkiFixture fixture = MetadataBlobTestVectors.CreateMdsPkiFixture();
        byte[] blobBytes = BuildSignedBlob(fixture, WellKnownJwaValues.Hs256, out _);

        using PkiCertificateMemory rootPki = MetadataBlobTestVectors.ToPkiCertificateMemory(fixture.RootCertificate.RawData);
        Fido2MetadataError? error = await VerifyAndGetRejectionErrorAsync(blobBytes, [rootPki]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2MetadataErrors.UnsupportedBlobAlgorithm.Code, error.Code);
    }


    /// <summary>A BLOB whose <c>no</c> does not exceed the caller's previously-cached serial number is rejected.</summary>
    [TestMethod]
    public async Task SerialNumberRegressionIsRejected()
    {
        using MdsPkiFixture fixture = MetadataBlobTestVectors.CreateMdsPkiFixture();
        byte[] blobBytes = BuildSignedBlob(fixture, WellKnownJwaValues.Es256, out _, no: 5);
        var store = new FakeMetadataBlobSerialNumberStore();
        store.Seed(DefaultTenantId, 5);

        using PkiCertificateMemory rootPki = MetadataBlobTestVectors.ToPkiCertificateMemory(fixture.RootCertificate.RawData);
        Fido2MetadataError? error = await VerifyAndGetRejectionErrorAsync(
            blobBytes, [rootPki],
            serialNumberPolicy: MetadataBlobSerialNumberPolicy.Required,
            resolvePreviousSerialNumber: store.ResolveAsync,
            persistVerifiedBlob: store.PersistAsync);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2MetadataErrors.SerialNumberNotIncreasing.Code, error.Code);
        Assert.IsEmpty(store.Persisted);
    }


    /// <summary>
    /// A BLOB whose <c>no</c> is exactly one greater than the caller's previously-cached serial
    /// number is accepted, and the accepted serial number is persisted through the write half of
    /// the resolve/persist pair — the strictly-greater boundary MDS-2954/MDS-2955 describe.
    /// </summary>
    [TestMethod]
    public async Task SerialNumberOneGreaterThanPreviousIsAcceptedAndPersisted()
    {
        using MdsPkiFixture fixture = MetadataBlobTestVectors.CreateMdsPkiFixture();
        byte[] blobBytes = BuildSignedBlob(fixture, WellKnownJwaValues.Es256, out _, no: 6);
        var store = new FakeMetadataBlobSerialNumberStore();
        store.Seed(DefaultTenantId, 5);

        using PkiCertificateMemory rootPki = MetadataBlobTestVectors.ToPkiCertificateMemory(fixture.RootCertificate.RawData);
        MetadataBlobResult result = await VerifyAsync(
            blobBytes, [rootPki],
            serialNumberPolicy: MetadataBlobSerialNumberPolicy.Required,
            resolvePreviousSerialNumber: store.ResolveAsync,
            persistVerifiedBlob: store.PersistAsync);

        Assert.IsInstanceOfType<VerifiedMetadataBlobResult>(result);
        ((VerifiedMetadataBlobResult)result).Blob.Dispose();
        Assert.HasCount(1, store.Persisted);
        Assert.AreEqual(DefaultTenantId, store.Persisted[0].TenantId);
        Assert.AreEqual(6L, store.Persisted[0].SerialNumber);
    }


    /// <summary>
    /// A verification request declaring <see cref="MetadataBlobSerialNumberPolicy.Required"/> with
    /// neither the resolve nor the persist delegate wired yields the distinguishable
    /// <see cref="MetadataBlobStoreUnavailableResult"/> — never a silent skip of the monotonicity
    /// defense.
    /// </summary>
    [TestMethod]
    public async Task RequiredSerialNumberPolicyWithUnwiredDelegatesYieldsStoreUnavailable()
    {
        using MdsPkiFixture fixture = MetadataBlobTestVectors.CreateMdsPkiFixture();
        byte[] blobBytes = BuildSignedBlob(fixture, WellKnownJwaValues.Es256, out _);

        using PkiCertificateMemory rootPki = MetadataBlobTestVectors.ToPkiCertificateMemory(fixture.RootCertificate.RawData);
        MetadataBlobResult result = await VerifyAsync(
            blobBytes, [rootPki], serialNumberPolicy: MetadataBlobSerialNumberPolicy.Required);

        Assert.IsInstanceOfType<MetadataBlobStoreUnavailableResult>(result);
        Assert.AreEqual(Fido2MetadataErrors.SerialNumberStoreUnavailable.Code, ((MetadataBlobStoreUnavailableResult)result).Error.Code);
    }


    /// <summary>
    /// A resolve delegate that throws is treated identically to an unwired one — the exception never
    /// escapes <see cref="MetadataBlobVerification.VerifyAsync"/>; verification fails closed to
    /// <see cref="MetadataBlobStoreUnavailableResult"/>.
    /// </summary>
    [TestMethod]
    public async Task ThrowingResolveDelegateYieldsStoreUnavailable()
    {
        using MdsPkiFixture fixture = MetadataBlobTestVectors.CreateMdsPkiFixture();
        byte[] blobBytes = BuildSignedBlob(fixture, WellKnownJwaValues.Es256, out _);
        var store = new FakeMetadataBlobSerialNumberStore();

        using PkiCertificateMemory rootPki = MetadataBlobTestVectors.ToPkiCertificateMemory(fixture.RootCertificate.RawData);
        MetadataBlobResult result = await VerifyAsync(
            blobBytes, [rootPki],
            serialNumberPolicy: MetadataBlobSerialNumberPolicy.Required,
            resolvePreviousSerialNumber: ThrowingMetadataBlobSerialNumberResolver.ResolveAsync,
            persistVerifiedBlob: store.PersistAsync);

        Assert.IsInstanceOfType<MetadataBlobStoreUnavailableResult>(result);
        Assert.AreEqual(Fido2MetadataErrors.SerialNumberStoreUnavailable.Code, ((MetadataBlobStoreUnavailableResult)result).Error.Code);
        Assert.IsEmpty(store.Persisted);
    }


    /// <summary>
    /// A request declaring <see cref="MetadataBlobSerialNumberPolicy.NotTracked"/> verifies
    /// successfully with a regressing serial number, and never consults or records into a store —
    /// proving the opt-out is a real skip, not merely an unreachable code path.
    /// </summary>
    [TestMethod]
    public async Task NotTrackedSerialNumberPolicyAcceptsARegressingSerialNumber()
    {
        using MdsPkiFixture fixture = MetadataBlobTestVectors.CreateMdsPkiFixture();
        byte[] blobBytes = BuildSignedBlob(fixture, WellKnownJwaValues.Es256, out _, no: 1);
        var store = new FakeMetadataBlobSerialNumberStore();
        store.Seed(DefaultTenantId, 999);

        using PkiCertificateMemory rootPki = MetadataBlobTestVectors.ToPkiCertificateMemory(fixture.RootCertificate.RawData);
        MetadataBlobResult result = await VerifyAsync(
            blobBytes, [rootPki],
            serialNumberPolicy: MetadataBlobSerialNumberPolicy.NotTracked,
            resolvePreviousSerialNumber: store.ResolveAsync,
            persistVerifiedBlob: store.PersistAsync);

        Assert.IsInstanceOfType<VerifiedMetadataBlobResult>(result);
        ((VerifiedMetadataBlobResult)result).Blob.Dispose();
        Assert.IsEmpty(store.Persisted);
    }


    /// <summary>
    /// A tampered signature is rejected before the serial-number seam is ever reached, so the persist
    /// delegate never fires — persist runs only on the accepted path, never on any rejection.
    /// </summary>
    [TestMethod]
    public async Task PersistIsNotInvokedWhenSignatureTamperRejects()
    {
        using MdsPkiFixture fixture = MetadataBlobTestVectors.CreateMdsPkiFixture();
        byte[] blobBytes = MetadataBlobTestVectors.TamperSignatureSegment(BuildSignedBlob(fixture, WellKnownJwaValues.Es256, out _));
        var store = new FakeMetadataBlobSerialNumberStore();

        using PkiCertificateMemory rootPki = MetadataBlobTestVectors.ToPkiCertificateMemory(fixture.RootCertificate.RawData);
        Fido2MetadataError? error = await VerifyAndGetRejectionErrorAsync(
            blobBytes, [rootPki],
            serialNumberPolicy: MetadataBlobSerialNumberPolicy.Required,
            resolvePreviousSerialNumber: store.ResolveAsync,
            persistVerifiedBlob: store.PersistAsync);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2MetadataErrors.InvalidBlobSignature.Code, error.Code);
        Assert.IsEmpty(store.Persisted);
    }


    /// <summary>
    /// Two tenants resolving different previously-cached serial numbers from the SAME store get
    /// per-tenant outcomes for the SAME BLOB serial number — proving <see cref="TenantId"/> is
    /// genuinely threaded into the resolve delegate rather than a single shared baseline.
    /// </summary>
    [TestMethod]
    public async Task TenantScopedResolveProducesPerTenantOutcomes()
    {
        using MdsPkiFixture fixture = MetadataBlobTestVectors.CreateMdsPkiFixture();
        byte[] blobBytes = BuildSignedBlob(fixture, WellKnownJwaValues.Es256, out _, no: 10);
        var store = new FakeMetadataBlobSerialNumberStore();
        TenantId tenantAllowing = new("tenant-behind-the-new-serial");
        TenantId tenantRejecting = new("tenant-ahead-of-the-new-serial");
        store.Seed(tenantAllowing, 9);
        store.Seed(tenantRejecting, 10);

        using PkiCertificateMemory rootPki = MetadataBlobTestVectors.ToPkiCertificateMemory(fixture.RootCertificate.RawData);

        MetadataBlobResult allowedResult = await VerifyAsync(
            blobBytes, [rootPki], tenantId: tenantAllowing,
            serialNumberPolicy: MetadataBlobSerialNumberPolicy.Required,
            resolvePreviousSerialNumber: store.ResolveAsync,
            persistVerifiedBlob: store.PersistAsync);
        Assert.IsInstanceOfType<VerifiedMetadataBlobResult>(allowedResult);
        ((VerifiedMetadataBlobResult)allowedResult).Blob.Dispose();

        MetadataBlobResult rejectedResult = await VerifyAsync(
            blobBytes, [rootPki], tenantId: tenantRejecting,
            serialNumberPolicy: MetadataBlobSerialNumberPolicy.Required,
            resolvePreviousSerialNumber: store.ResolveAsync,
            persistVerifiedBlob: store.PersistAsync);
        Assert.IsInstanceOfType<RejectedMetadataBlobResult>(rejectedResult);
        Assert.AreEqual(Fido2MetadataErrors.SerialNumberNotIncreasing.Code, ((RejectedMetadataBlobResult)rejectedResult).Error.Code);

        Assert.HasCount(1, store.Persisted);
        Assert.AreEqual(tenantAllowing, store.Persisted[0].TenantId);
    }


    /// <summary>
    /// A request declaring <see cref="MetadataBlobRevocationPolicy.Required"/> with no revocation
    /// delegate wired to <see cref="MetadataBlobVerification.Build"/> yields the distinguishable
    /// <see cref="MetadataBlobStoreUnavailableResult"/> — never a silent chain validation without
    /// revocation checking.
    /// </summary>
    [TestMethod]
    public async Task RequiredRevocationPolicyWithUnwiredDelegateYieldsStoreUnavailable()
    {
        using MdsPkiFixture fixture = MetadataBlobTestVectors.CreateMdsPkiFixture();
        byte[] blobBytes = BuildSignedBlob(fixture, WellKnownJwaValues.Es256, out _);

        using PkiCertificateMemory rootPki = MetadataBlobTestVectors.ToPkiCertificateMemory(fixture.RootCertificate.RawData);
        MetadataBlobResult result = await VerifyAsync(
            blobBytes, [rootPki], revocationPolicy: MetadataBlobRevocationPolicy.Required);

        Assert.IsInstanceOfType<MetadataBlobStoreUnavailableResult>(result);
        Assert.AreEqual(Fido2MetadataErrors.RevocationCheckUnavailable.Code, ((MetadataBlobStoreUnavailableResult)result).Error.Code);
    }


    /// <summary>
    /// A request declaring <see cref="MetadataBlobRevocationPolicy.NotChecked"/> verifies
    /// successfully — and the result observably carries the <c>NotChecked</c> posture — even when a
    /// revocation delegate that would otherwise reject the chain is wired to
    /// <see cref="MetadataBlobVerification.Build"/>, proving the opt-out genuinely overrides rather
    /// than merely going unused.
    /// </summary>
    [TestMethod]
    public async Task NotCheckedRevocationPolicyBypassesAWiredRevocationDelegate()
    {
        using MdsPkiFixture fixture = MetadataBlobTestVectors.CreateMdsPkiFixture();
        byte[] blobBytes = BuildSignedBlob(fixture, WellKnownJwaValues.Es256, out _);

        using PkiCertificateMemory rootPki = MetadataBlobTestVectors.ToPkiCertificateMemory(fixture.RootCertificate.RawData);
        MetadataBlobResult result = await VerifyAsync(
            blobBytes, [rootPki],
            revocationPolicy: MetadataBlobRevocationPolicy.NotChecked,
            checkRevocation: AlwaysRevokedCertificateChecker.CheckAsync);

        Assert.IsInstanceOfType<VerifiedMetadataBlobResult>(result);
        var verified = (VerifiedMetadataBlobResult)result;
        Assert.AreEqual(MetadataBlobRevocationPolicy.NotChecked, verified.RevocationPolicy);
        verified.Blob.Dispose();
    }


    /// <summary>
    /// An accepted verification under <see cref="MetadataBlobRevocationPolicy.Required"/> — with a
    /// wired delegate that reports every certificate as not revoked — carries the <c>Required</c>
    /// posture on its result, so a caller can tell the two accepted-but-differently-checked shapes
    /// apart without re-deriving the request it came from.
    /// </summary>
    [TestMethod]
    public async Task VerifiedResultCarriesTheRequiredRevocationPosture()
    {
        using MdsPkiFixture fixture = MetadataBlobTestVectors.CreateMdsPkiFixture();
        byte[] blobBytes = BuildSignedBlob(fixture, WellKnownJwaValues.Es256, out _);

        DateTimeOffset crlThisUpdate = ValidationTime.AddDays(-1);
        DateTimeOffset crlNextUpdate = ValidationTime.AddDays(30);
        using PkiCertificateMemory cleanCrl = SyntheticPassportFactory.MintCrl(fixture.RootCertificate, revokedCertificate: null, crlThisUpdate, crlNextUpdate, crlNumber: 1);
        var checker = new CrlRevocationChecker([cleanCrl]);

        using PkiCertificateMemory rootPki = MetadataBlobTestVectors.ToPkiCertificateMemory(fixture.RootCertificate.RawData);
        MetadataBlobResult result = await VerifyAsync(
            blobBytes, [rootPki],
            revocationPolicy: MetadataBlobRevocationPolicy.Required,
            checkRevocation: checker.CheckAsync);

        Assert.IsInstanceOfType<VerifiedMetadataBlobResult>(result);
        var verified = (VerifiedMetadataBlobResult)result;
        Assert.AreEqual(MetadataBlobRevocationPolicy.Required, verified.RevocationPolicy);
        verified.Blob.Dispose();
    }


    /// <summary>A BLOB whose <c>nextUpdate</c> date has already passed as of the validation time is rejected.</summary>
    [TestMethod]
    public async Task StaleNextUpdateIsRejected()
    {
        using MdsPkiFixture fixture = MetadataBlobTestVectors.CreateMdsPkiFixture();
        string entryJson = MetadataBlobTestVectors.BuildEntryJson(aaguid: Guid.NewGuid());
        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [fixture.SigningCertificate.RawData]);
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2020-01-01", [entryJson]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(fixture.SigningKey, data));

        using PkiCertificateMemory rootPki = MetadataBlobTestVectors.ToPkiCertificateMemory(fixture.RootCertificate.RawData);
        Fido2MetadataError? error = await VerifyAndGetRejectionErrorAsync(blobBytes, [rootPki]);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2MetadataErrors.BlobStale.Code, error.Code);
    }


    /// <summary>A BLOB whose signing certificate has been revoked by a CRL issued from the trust anchor is rejected.</summary>
    [TestMethod]
    public async Task RevokedSignerCertificateIsRejected()
    {
        using MdsPkiFixture fixture = MetadataBlobTestVectors.CreateMdsPkiFixture();
        byte[] blobBytes = BuildSignedBlob(fixture, WellKnownJwaValues.Es256, out _);

        DateTimeOffset crlThisUpdate = ValidationTime.AddDays(-1);
        DateTimeOffset crlNextUpdate = ValidationTime.AddDays(30);
        using PkiCertificateMemory revokingCrl = SyntheticPassportFactory.MintCrl(fixture.RootCertificate, fixture.SigningCertificate, crlThisUpdate, crlNextUpdate, crlNumber: 1);
        var checker = new CrlRevocationChecker([revokingCrl]);

        using PkiCertificateMemory rootPki = MetadataBlobTestVectors.ToPkiCertificateMemory(fixture.RootCertificate.RawData);
        Fido2MetadataError? error = await VerifyAndGetRejectionErrorAsync(blobBytes, [rootPki], checkRevocation: checker.CheckAsync);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2MetadataErrors.BlobChainValidationFailed.Code, error.Code);
    }


    /// <summary>
    /// An INTERMEDIATE CA certificate in the BLOB's <c>x5c</c> — distinct from the leaf signing
    /// certificate — revoked by a CRL issued from the root trust anchor is rejected, even though the
    /// leaf signer itself carries no revocation status of its own. Chain-of-trust granularity: this
    /// is PKI-level revocation of the signer CHAIN, not FIDO-status-level gating of an authenticator
    /// entry (the separate axis <see cref="RevokedStatusRejectsTrustUnderDefaultPolicy"/> covers).
    /// </summary>
    [TestMethod]
    public async Task RevokedIntermediateCertificateInX5cIsRejected()
    {
        //Cert-factory carve-out: this key is signing input to CreateMdsRootCa's CertificateRequest.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Root Intermediate", rootKey);
        //Cert-factory carve-out: this key is signing input to CreateIntermediateCaCertificate's CertificateRequest.
        using ECDsa intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 intermediateCertificate = Fido2AttestationTestVectors.CreateIntermediateCaCertificate(rootCertificate, intermediateKey, "CN=Test MDS Intermediate");
        //Cert-factory carve-out (signing input to CreateMdsSigningCertificate's CertificateRequest) and independent
        //oracle: SignEs256 below signs the BLOB with this raw ECDsa key, and the library's own ES256 verifier is
        //proven against that independent signature.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        //Fido2AttestationTestVectors.CreateIntermediateCaCertificate's own validity window (2026-01-01
        //to 2029-01-01) is narrower than CreateMdsSigningCertificate's default (…-2030-01-01); the
        //signer's window must fit within its issuer's, so it is supplied explicitly here.
        using X509Certificate2 signingCertificate = MetadataBlobTestVectors.CreateMdsSigningCertificate(
            intermediateCertificate, signingKey, notAfter: new DateTimeOffset(2028, 6, 1, 0, 0, 0, TimeSpan.Zero));

        string entryJson = MetadataBlobTestVectors.BuildEntryJson(aaguid: Guid.NewGuid());
        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signingCertificate.RawData, intermediateCertificate.RawData]);
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [entryJson]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        DateTimeOffset crlThisUpdate = ValidationTime.AddDays(-1);
        DateTimeOffset crlNextUpdate = ValidationTime.AddDays(30);
        using PkiCertificateMemory revokingIntermediateCrl = SyntheticPassportFactory.MintCrl(rootCertificate, intermediateCertificate, crlThisUpdate, crlNextUpdate, crlNumber: 1);
        var checker = new CrlRevocationChecker([revokingIntermediateCrl]);

        using PkiCertificateMemory rootPki = MetadataBlobTestVectors.ToPkiCertificateMemory(rootCertificate.RawData);
        Fido2MetadataError? error = await VerifyAndGetRejectionErrorAsync(blobBytes, [rootPki], checkRevocation: checker.CheckAsync);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2MetadataErrors.BlobChainValidationFailed.Code, error.Code);
    }


    /// <summary>
    /// A registration's AAGUID has no corresponding entry in the parsed BLOB at all: the lookup
    /// reports a miss (fail-open at the lookup layer — "MDS has no opinion" — never itself a BLOB
    /// rejection), which the caller's own policy then decides how to act on.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TryFindEntryByAaguid reports a miss here, so the out entry is null — there is nothing to dispose; the analyzer cannot see that from the call site alone.")]
    public async Task AaguidLookupMissReportsNoMatchWithoutRejectingTheBlob()
    {
        using MdsPkiFixture fixture = MetadataBlobTestVectors.CreateMdsPkiFixture();
        byte[] blobBytes = BuildSignedBlob(fixture, WellKnownJwaValues.Es256, out Guid listedAaguid);
        Guid unlistedAaguid = Guid.NewGuid();
        Assert.AreNotEqual(listedAaguid, unlistedAaguid);

        using PkiCertificateMemory rootPki = MetadataBlobTestVectors.ToPkiCertificateMemory(fixture.RootCertificate.RawData);
        MetadataBlobResult result = await VerifyAsync(blobBytes, [rootPki]);

        Assert.IsInstanceOfType<VerifiedMetadataBlobResult>(result);
        MetadataBlob blob = ((VerifiedMetadataBlobResult)result).Blob;
        try
        {
            Assert.IsFalse(MetadataBlobPayloadQueries.TryFindEntryByAaguid(blob.Payload, unlistedAaguid, out MetadataBlobPayloadEntry? entry));
            Assert.IsNull(entry);
        }
        finally
        {
            blob.Dispose();
        }
    }


    /// <summary>A matched entry whose deciding status is <see cref="WellKnownAuthenticatorStatuses.Revoked"/> is not trusted, under the default policy.</summary>
    [TestMethod]
    public async Task RevokedStatusRejectsTrustUnderDefaultPolicy()
    {
        (MetadataBlob blob, MetadataBlobPayloadEntry entry) = await VerifyAndGetSingleEntryAsync(WellKnownAuthenticatorStatuses.Revoked);
        using(blob)
        {
            Assert.IsFalse(MetadataBlobPayloadQueries.EvaluateStatus(entry).Accepted);
        }
    }


    /// <summary>A matched entry whose deciding status is <see cref="WellKnownAuthenticatorStatuses.UserVerificationBypass"/> is not trusted, under the default policy.</summary>
    [TestMethod]
    public async Task UserVerificationBypassRejectsTrustUnderDefaultPolicy()
    {
        (MetadataBlob blob, MetadataBlobPayloadEntry entry) = await VerifyAndGetSingleEntryAsync(WellKnownAuthenticatorStatuses.UserVerificationBypass);
        using(blob)
        {
            Assert.IsFalse(MetadataBlobPayloadQueries.EvaluateStatus(entry).Accepted);
        }
    }


    /// <summary>A matched entry whose deciding status is <see cref="WellKnownAuthenticatorStatuses.AttestationKeyCompromise"/> is not trusted, under the default policy.</summary>
    [TestMethod]
    public async Task AttestationKeyCompromiseRejectsTrustUnderDefaultPolicy()
    {
        (MetadataBlob blob, MetadataBlobPayloadEntry entry) = await VerifyAndGetSingleEntryAsync(WellKnownAuthenticatorStatuses.AttestationKeyCompromise);
        using(blob)
        {
            Assert.IsFalse(MetadataBlobPayloadQueries.EvaluateStatus(entry).Accepted);
        }
    }


    /// <summary>A matched entry whose deciding status is <see cref="WellKnownAuthenticatorStatuses.UserKeyRemoteCompromise"/> is not trusted, under the default policy.</summary>
    [TestMethod]
    public async Task UserKeyRemoteCompromiseRejectsTrustUnderDefaultPolicy()
    {
        (MetadataBlob blob, MetadataBlobPayloadEntry entry) = await VerifyAndGetSingleEntryAsync(WellKnownAuthenticatorStatuses.UserKeyRemoteCompromise);
        using(blob)
        {
            Assert.IsFalse(MetadataBlobPayloadQueries.EvaluateStatus(entry).Accepted);
        }
    }


    /// <summary>A matched entry whose deciding status is <see cref="WellKnownAuthenticatorStatuses.UserKeyPhysicalCompromise"/> is not trusted, under the default policy.</summary>
    [TestMethod]
    public async Task UserKeyPhysicalCompromiseRejectsTrustUnderDefaultPolicy()
    {
        (MetadataBlob blob, MetadataBlobPayloadEntry entry) = await VerifyAndGetSingleEntryAsync(WellKnownAuthenticatorStatuses.UserKeyPhysicalCompromise);
        using(blob)
        {
            Assert.IsFalse(MetadataBlobPayloadQueries.EvaluateStatus(entry).Accepted);
        }
    }


    /// <summary>A matched entry whose deciding status is <see cref="WellKnownAuthenticatorStatuses.FidoCertified"/> is trusted.</summary>
    [TestMethod]
    public async Task FidoCertifiedStatusAcceptsTrust()
    {
        (MetadataBlob blob, MetadataBlobPayloadEntry entry) = await VerifyAndGetSingleEntryAsync(WellKnownAuthenticatorStatuses.FidoCertified);
        using(blob)
        {
            Assert.IsTrue(MetadataBlobPayloadQueries.EvaluateStatus(entry).Accepted);
        }
    }


    /// <summary>
    /// With two dated status reports, the one with the greater <c>effectiveDate</c> decides — not
    /// merely the last one in wire order — proving the evaluation is genuinely date-driven.
    /// </summary>
    [TestMethod]
    public async Task LatestReportByEffectiveDateWinsWithTwoDatedReports()
    {
        //The REVOKED report is listed FIRST but dated LATER; the FIDO_CERTIFIED report is listed
        //second but dated earlier. A naive "last in the array wins" evaluation would pick
        //FIDO_CERTIFIED; the correct, date-driven evaluation picks REVOKED.
        string[] statusReports =
        [
            MetadataBlobTestVectors.BuildStatusReportJson(WellKnownAuthenticatorStatuses.Revoked, "2025-06-01"),
            MetadataBlobTestVectors.BuildStatusReportJson(WellKnownAuthenticatorStatuses.FidoCertified, "2020-01-01")
        ];

        (MetadataBlob blob, MetadataBlobPayloadEntry entry) = await VerifyAndGetSingleEntryAsync(statusReportJsons: statusReports);
        using(blob)
        {
            MetadataStatusEvaluation evaluation = MetadataBlobPayloadQueries.EvaluateStatus(entry);
            Assert.IsFalse(evaluation.Accepted);
            Assert.AreEqual(WellKnownAuthenticatorStatuses.Revoked, evaluation.DecidingStatusReport!.Status);
        }
    }


    /// <summary>A caller-supplied trust-terminating policy can accept an entry the default policy would reject.</summary>
    [TestMethod]
    public async Task CallerPolicyOverrideAcceptsARevokedEntry()
    {
        (MetadataBlob blob, MetadataBlobPayloadEntry entry) = await VerifyAndGetSingleEntryAsync(WellKnownAuthenticatorStatuses.Revoked);
        using(blob)
        {
            MetadataStatusEvaluation evaluation = MetadataBlobPayloadQueries.EvaluateStatus(entry, trustTerminating: new HashSet<string>(StringComparer.Ordinal));
            Assert.IsTrue(evaluation.Accepted);
        }
    }


    /// <summary>Builds and signs a Metadata BLOB with a single AAGUID'd entry, under <paramref name="fixture"/>'s PKI.</summary>
    private static byte[] BuildSignedBlob(MdsPkiFixture fixture, string algorithm, out Guid aaguid, long no = 1, string nextUpdate = "2030-01-01")
    {
        aaguid = Guid.NewGuid();
        string entryJson = MetadataBlobTestVectors.BuildEntryJson(aaguid: aaguid);
        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(algorithm, [fixture.SigningCertificate.RawData]);
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(no, nextUpdate, [entryJson]);

        return MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(fixture.SigningKey, data));
    }


    /// <summary>
    /// Builds, signs, and verifies a BLOB with a single entry carrying <paramref name="statusReportJsons"/>
    /// (or, when <see langword="null"/>, a single report of <paramref name="status"/>), returning
    /// the verified BLOB alongside the matched entry for a status-evaluation assertion. Asserts the
    /// BLOB itself verifies successfully — status gating is a separate, subsequent policy decision
    /// from BLOB signature/chain validity. The caller owns and disposes the returned BLOB, which in
    /// turn owns the returned entry — the entry is never disposed separately.
    /// </summary>
    private async Task<(MetadataBlob Blob, MetadataBlobPayloadEntry Entry)> VerifyAndGetSingleEntryAsync(string? status = null, IReadOnlyList<string>? statusReportJsons = null)
    {
        using MdsPkiFixture fixture = MetadataBlobTestVectors.CreateMdsPkiFixture();
        Guid aaguid = Guid.NewGuid();
        IReadOnlyList<string> reports = statusReportJsons ?? [MetadataBlobTestVectors.BuildStatusReportJson(status!, "2020-01-01")];
        string entryJson = MetadataBlobTestVectors.BuildEntryJson(aaguid: aaguid, statusReportJsons: reports);
        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [fixture.SigningCertificate.RawData]);
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [entryJson]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(fixture.SigningKey, data));

        using PkiCertificateMemory rootPki = MetadataBlobTestVectors.ToPkiCertificateMemory(fixture.RootCertificate.RawData);
        MetadataBlobResult result = await VerifyAsync(blobBytes, [rootPki]);

        Assert.IsInstanceOfType<VerifiedMetadataBlobResult>(result);
        MetadataBlob blob = ((VerifiedMetadataBlobResult)result).Blob;
        Assert.IsTrue(MetadataBlobPayloadQueries.TryFindEntryByAaguid(blob.Payload, aaguid, out MetadataBlobPayloadEntry? entry));

        return (blob, entry!);
    }


    /// <summary>
    /// Builds and runs the <see cref="MetadataBlobVerification"/> verifier over
    /// <paramref name="blobBytes"/>. <paramref name="serialNumberPolicy"/>/<paramref name="revocationPolicy"/>,
    /// when left <see langword="null"/>, are derived from whether the corresponding delegate was
    /// supplied — <see cref="MetadataBlobSerialNumberPolicy.Required"/>/<see cref="MetadataBlobRevocationPolicy.Required"/>
    /// when it was, <c>NotTracked</c>/<c>NotChecked</c> otherwise — so the majority of tests that care
    /// about neither seam stay unchanged while a test exercising the seam states its policy explicitly.
    /// </summary>
    private async Task<MetadataBlobResult> VerifyAsync(
        byte[] blobBytes,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        TenantId? tenantId = null,
        MetadataBlobSerialNumberPolicy? serialNumberPolicy = null,
        MetadataBlobRevocationPolicy? revocationPolicy = null,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation = null,
        ResolvePreviousMetadataBlobSerialNumberAsyncDelegate? resolvePreviousSerialNumber = null,
        PersistVerifiedMetadataBlobAsyncDelegate? persistVerifiedBlob = null)
    {
        VerifyMetadataBlobAsyncDelegate verify = MetadataBlobVerification.Build(
            MetadataBlobReader.Read,
            MicrosoftX509Functions.ValidateChainAsync,
            checkRevocation,
            resolvePreviousSerialNumber: resolvePreviousSerialNumber,
            persistVerifiedBlob: persistVerifiedBlob);

        var request = new MetadataBlobVerificationRequest(
            blobBytes,
            trustAnchors,
            ValidationTime,
            tenantId ?? DefaultTenantId,
            serialNumberPolicy ?? (resolvePreviousSerialNumber is not null ? MetadataBlobSerialNumberPolicy.Required : MetadataBlobSerialNumberPolicy.NotTracked),
            revocationPolicy ?? (checkRevocation is not null ? MetadataBlobRevocationPolicy.Required : MetadataBlobRevocationPolicy.NotChecked),
            BaseMemoryPool.Shared);

        return await verify(request, TestContext.CancellationToken);
    }


    /// <summary>Runs <see cref="VerifyAsync"/> and returns the rejection error, if any.</summary>
    private async Task<Fido2MetadataError?> VerifyAndGetRejectionErrorAsync(
        byte[] blobBytes,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        TenantId? tenantId = null,
        MetadataBlobSerialNumberPolicy? serialNumberPolicy = null,
        MetadataBlobRevocationPolicy? revocationPolicy = null,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation = null,
        ResolvePreviousMetadataBlobSerialNumberAsyncDelegate? resolvePreviousSerialNumber = null,
        PersistVerifiedMetadataBlobAsyncDelegate? persistVerifiedBlob = null)
    {
        MetadataBlobResult result = await VerifyAsync(
            blobBytes, trustAnchors, tenantId, serialNumberPolicy, revocationPolicy, checkRevocation, resolvePreviousSerialNumber, persistVerifiedBlob);

        return result is RejectedMetadataBlobResult rejected ? rejected.Error : null;
    }
}
