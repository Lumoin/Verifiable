using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Validates CAdES verification (ETSI EN 319 122-1): a CMS SignedData whose signature covers the mandatory
/// signed attributes binding the signer and content (level B), optionally raised by a signature timestamp
/// (level T). The signed data is minted with the framework's own CMS signer and an independently computed
/// signing-certificate-v2 hash (SHA-256, the BCL oracle), and verified through the library, so the library's
/// registered CMS verifier and digest must agree with the independent signer for the signature to be accepted.
/// </summary>
[TestClass]
internal sealed class CAdESVerificationTests
{
    private static readonly DateTimeOffset NotBefore = new(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset NotAfter = new(2034, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset SigningTime = new(2025, 3, 14, 0, 0, 0, TimeSpan.Zero);


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task VerifiesACAdESBaselineSignature()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the cades content"u8, signerCertificate, SigningTime);

        using CAdESVerificationResult result = await CAdESVerification.VerifyAsync(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CAdESVerificationStatus.Valid, result.Status, "A CAdES-B-B signature whose signing-certificate-v2 binds the signer verifies.");
        Assert.AreEqual(Convert.ToHexString("the cades content"u8), Convert.ToHexString(result.Content.Span), "The verified content must be the signed payload.");
        Assert.IsNotNull(result.SignerCertificate, "The signer certificate must surface on success.");
        Assert.IsTrue(result.SignerCertificate!.AsReadOnlyMemory().Span.SequenceEqual(signerCertificate.RawData), "The surfaced signer certificate must equal the one that signed.");
        Assert.AreEqual(SigningTime, result.SigningTime, "The signing-time attribute must surface.");
    }


    [TestMethod]
    public async Task VerifiesACAdESBaselineSignatureWithAnExplicitHashAlgorithm()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        //The ESSCertIDv2 names its SHA-256 hash algorithm explicitly rather than relying on the default.
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the cades content"u8, signerCertificate, SigningTime, explicitHashAlgorithm: true);

        using CAdESVerificationResult result = await CAdESVerification.VerifyAsync(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CAdESVerificationStatus.Valid, result.Status, "An ESSCertIDv2 that names its SHA-256 hash algorithm explicitly verifies.");
    }


    [TestMethod]
    public async Task VerifiesACAdESTimestampSignatureAndReportsTheLevelAndTime()
    {
        DateTimeOffset timestampTime = new(2025, 6, 1, 12, 0, 0, TimeSpan.Zero);

        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using ECDsa tsaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var tsaCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(tsaKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdEST("the cades content"u8, signerCertificate, SigningTime, tsaCertificate, timestampTime);

        using CAdESVerificationResult result = await CAdESVerification.VerifyAsync(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CAdESVerificationStatus.Valid, result.Status, "A CAdES-T signature with a timestamp binding the signature verifies.");
        Assert.AreEqual(CAdESLevel.Timestamp, result.Level, "A verified signature timestamp raises the level to T.");
        Assert.AreEqual(timestampTime, result.TimestampTime, "The trusted time from the timestamp token must surface.");
    }


    [TestMethod]
    public async Task ABaselineSignatureReportsTheBaselineLevelAndNoTimestamp()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the cades content"u8, signerCertificate, SigningTime);

        using CAdESVerificationResult result = await CAdESVerification.VerifyAsync(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CAdESLevel.Baseline, result.Level, "A signature without a timestamp is a baseline (B) signature.");
        Assert.IsNull(result.TimestampTime, "A baseline signature carries no timestamp time.");
    }


    [TestMethod]
    public async Task RejectsACAdESTimestampOverTamperedContent()
    {
        DateTimeOffset timestampTime = new(2025, 6, 1, 12, 0, 0, TimeSpan.Zero);

        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using ECDsa tsaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var tsaCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(tsaKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdEST("the cades content"u8, signerCertificate, SigningTime, tsaCertificate, timestampTime);
        using CmsSignedData tampered = CmsSignedDataTestFactory.TamperContent(carrier, "the cades content"u8);

        using CAdESVerificationResult result = await CAdESVerification.VerifyAsync(tampered, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A tampered CAdES-T signature must not verify.");
    }


    [TestMethod]
    public async Task RejectsWhenTheSigningCertificateAttributeIsMissing()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        //A plain CMS signature with no signing-certificate-v2 attribute is not a CAdES-B signature.
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the cades content"u8, signerCertificate, SigningTime, includeSigningCertificate: false);

        using CAdESVerificationResult result = await CAdESVerification.VerifyAsync(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CAdESVerificationStatus.MissingSigningCertificate, result.Status, "A CMS signature without signing-certificate-v2 is rejected as not CAdES-B.");
        Assert.IsFalse(result.IsValid, "A missing signing-certificate attribute is not a valid CAdES signature.");
    }


    [TestMethod]
    public async Task RejectsWhenTheSigningCertificateHashDoesNotMatch()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        //The signing-certificate-v2 hash binds a different certificate than the one that signed.
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the cades content"u8, signerCertificate, SigningTime, bindWrongCertificate: true);

        using CAdESVerificationResult result = await CAdESVerification.VerifyAsync(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CAdESVerificationStatus.SigningCertificateMismatch, result.Status, "A signing-certificate-v2 hash that does not match the signer certificate is rejected.");
    }


    [TestMethod]
    public async Task RejectsTamperedContent()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the cades content"u8, signerCertificate, SigningTime);
        using CmsSignedData tampered = CmsSignedDataTestFactory.TamperContent(carrier, "the cades content"u8);

        using CAdESVerificationResult result = await CAdESVerification.VerifyAsync(tampered, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CAdESVerificationStatus.InvalidSignature, result.Status, "A tampered content fails the CMS signature, so the CAdES verification is invalid.");
    }
}
