using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Validates the neutral CMS SignedData verification seam — the shared core of eMRTD Passive
/// Authentication and the CAdES family of EU advanced signatures — by signing content as CMS with a
/// minted certificate and verifying it through the registered delegate.
/// </summary>
[TestClass]
internal sealed class CmsSignedDataVerificationTests
{
    private static readonly DateTimeOffset NotBefore = SyntheticPassportFactory.NotBefore;
    private static readonly DateTimeOffset NotAfter = SyntheticPassportFactory.NotAfter;
    private static readonly DateTimeOffset SigningTime = new(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task VerifiesCmsSignedDataAndSurfacesContentAndSigner()
    {
        //Cert-factory carve-out: CertificateRequest requires a framework AsymmetricAlgorithm to sign the
        //self-signed certificate; this key is never converted to library PrivateKeyMemory, so it stays
        //framework-native for its whole lifetime.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCms("the signed content"u8, signerCertificate);

        VerifyCmsSignedDataDelegate verify = ResolveVerify();
        using CmsVerifiedContent verified = await verify(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(Convert.ToHexString("the signed content"u8), Convert.ToHexString(verified.Content.Span),
            "The verified content must be the signed payload.");
        Assert.AreEqual("1.2.840.113549.1.7.1", verified.ContentType, "The content type must be id-data.");
        Assert.HasCount(1, verified.Certificates, "The signer certificate must be surfaced.");
        Assert.IsTrue(
            verified.SignerCertificate.AsReadOnlyMemory().Span.SequenceEqual(signerCertificate.RawData),
            "The surfaced signer certificate must equal the one that signed.");
    }


    [TestMethod]
    public async Task RejectsCmsSignedDataWithTamperedContent()
    {
        //Cert-factory carve-out: CertificateRequest requires a framework AsymmetricAlgorithm to sign the
        //self-signed certificate; this key is never converted to library PrivateKeyMemory, so it stays
        //framework-native for its whole lifetime.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCms("the signed content"u8, signerCertificate);
        using CmsSignedData tampered = CmsSignedDataTestFactory.TamperContent(carrier, "the signed content"u8);

        VerifyCmsSignedDataDelegate verify = ResolveVerify();

        bool threw = false;
        try
        {
            using CmsVerifiedContent _ = await verify(tampered, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(CryptographicException)
        {
            threw = true;
        }

        Assert.IsTrue(threw, "Verification must reject CMS SignedData whose content was tampered with.");
    }


    [TestMethod]
    public async Task SurfacesTheSignersSignedAttributes()
    {
        //Cert-factory carve-out: CertificateRequest requires a framework AsymmetricAlgorithm to sign the
        //self-signed certificate; this key is never converted to library PrivateKeyMemory, so it stays
        //framework-native for its whole lifetime.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCms("the signed content"u8, signerCertificate, withSigningTime: true, SigningTime);

        VerifyCmsSignedDataDelegate verify = ResolveVerify();
        using CmsVerifiedContent verified = await verify(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //Adding any signed attribute makes the signature cover the authenticated set, so content-type,
        //message-digest, and the signing-time are all present and surfaced through the seam.
        Assert.IsTrue(verified.TryGetSignedAttribute("1.2.840.113549.1.9.5", out CmsSignedAttribute? signingTime), "The signing-time signed attribute must surface.");
        Assert.IsGreaterThan(0, signingTime!.Length, "The surfaced signing-time value must carry its DER bytes.");
        Assert.IsTrue(verified.TryGetSignedAttribute("1.2.840.113549.1.9.4", out _), "The message-digest signed attribute must surface.");
        Assert.IsFalse(verified.TryGetSignedAttribute("1.2.840.113549.1.9.16.2.47", out _), "An attribute the signer did not add is absent.");
    }


    private static VerifyCmsSignedDataDelegate ResolveVerify() =>
        CryptographicKeyFactory.GetFunction<VerifyCmsSignedDataDelegate>(typeof(VerifyCmsSignedDataDelegate))
            ?? throw new InvalidOperationException("No VerifyCmsSignedDataDelegate has been registered.");
}
