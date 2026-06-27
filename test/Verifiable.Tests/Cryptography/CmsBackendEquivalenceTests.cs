using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Proves the CMS SignedData verification seam is provider-neutral across three independent backends: the
/// Microsoft backend (the default, over <c>SignedCms</c>), the BouncyCastle backend, and the fully managed
/// backend (own ASN.1 parse, delegating only the elliptic-curve primitive to the registered seam). All three
/// verify the same signed data and produce equivalent <see cref="CmsVerifiedContent"/> — the same content,
/// signer certificate, and signed attributes — so CAdES and eMRTD Passive Authentication, which depend only
/// on the verified-content shape, work over any backend unchanged.
/// </summary>
[TestClass]
internal sealed class CmsBackendEquivalenceTests
{
    private const string BouncyCastleQualifier = "BouncyCastle";
    private const string ManagedQualifier = "Managed";

    private static readonly DateTimeOffset NotBefore = new(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset NotAfter = new(2034, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset SigningTime = new(2025, 3, 14, 0, 0, 0, TimeSpan.Zero);


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task AllThreeBackendsVerifyTheSameSignedDataEquivalently()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the cross-backend content"u8, signerCertificate, SigningTime);

        using CmsVerifiedContent fromMicrosoft = await Resolve(qualifier: null)(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using CmsVerifiedContent fromBouncyCastle = await Resolve(BouncyCastleQualifier)(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using CmsVerifiedContent fromManaged = await Resolve(ManagedQualifier)(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //Cross-check both the BouncyCastle and the managed backends against the Microsoft reference.
        AssertEquivalent(fromMicrosoft, fromBouncyCastle, "BouncyCastle");
        AssertEquivalent(fromMicrosoft, fromManaged, "managed");
    }


    [TestMethod]
    public async Task AllThreeBackendsVerifyAnRsaSignedDataEquivalently()
    {
        using RSA signingKey = RSA.Create(2048);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the cross-backend content"u8, signerCertificate, SigningTime);

        using CmsVerifiedContent fromMicrosoft = await Resolve(qualifier: null)(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using CmsVerifiedContent fromBouncyCastle = await Resolve(BouncyCastleQualifier)(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using CmsVerifiedContent fromManaged = await Resolve(ManagedQualifier)(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //The managed backend routes RSA to the registered RSA seam (PKCS#1 v1.5, SHA-256, exponent 65537) and
        //must agree byte-for-byte with the two reference backends on a 2048-bit RSA signer.
        AssertEquivalent(fromMicrosoft, fromBouncyCastle, "BouncyCastle");
        AssertEquivalent(fromMicrosoft, fromManaged, "managed");
    }


    [TestMethod]
    public async Task TheManagedBackendVerifiesACAdESBaselineSignature()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the cross-backend content"u8, signerCertificate, SigningTime);

        //The managed backend surfaces the signing-certificate-v2 attribute CAdES checks, so the CAdES rules
        //hold over its verified content exactly as over the default backend.
        using CmsVerifiedContent verified = await Resolve(ManagedQualifier)(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verified.TryGetSignedAttribute(CmsSignedDataTestFactory.SigningCertificateV2Oid, out _), "The managed backend must surface the signing-certificate-v2 attribute CAdES depends on.");
    }


    [TestMethod]
    public async Task TheManagedBackendRejectsTamperedContent()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the cross-backend content"u8, signerCertificate, SigningTime);
        using CmsSignedData tampered = CmsSignedDataTestFactory.TamperContent(carrier, "the cross-backend content"u8);

        await Assert.ThrowsExactlyAsync<CryptographicException>(
            async () =>
            {
                using CmsVerifiedContent _ = await Resolve(ManagedQualifier)(tampered, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);
    }


    /// <summary>
    /// Asserts two verified-content results are equivalent: the same content type, content, signer
    /// certificate, and signed attributes (by object identifier and value).
    /// </summary>
    private static void AssertEquivalent(CmsVerifiedContent reference, CmsVerifiedContent other, string backendName)
    {
        Assert.AreEqual(reference.ContentType, other.ContentType, $"The {backendName} backend must report the same encapsulated content type.");
        Assert.AreEqual(Convert.ToHexString(reference.Content.Span), Convert.ToHexString(other.Content.Span), $"The {backendName} backend must surface the same encapsulated content.");
        Assert.IsTrue(
            reference.SignerCertificate.AsReadOnlyMemory().Span.SequenceEqual(other.SignerCertificate.AsReadOnlyMemory().Span),
            $"The {backendName} backend must surface the same signer certificate.");

        Assert.HasCount(reference.SignedAttributes.Count, other.SignedAttributes, $"The {backendName} backend must surface the same number of signed attributes.");
        foreach(CmsSignedAttribute attribute in reference.SignedAttributes)
        {
            Assert.IsTrue(other.TryGetSignedAttribute(attribute.AttributeType, out CmsSignedAttribute? match), $"The {backendName} backend must surface the signed attribute {attribute.AttributeType}.");
            Assert.IsTrue(attribute.AsReadOnlySpan().SequenceEqual(match!.AsReadOnlySpan()), $"The signed attribute {attribute.AttributeType} must have the same value under the {backendName} backend.");
        }
    }


    private static VerifyCmsSignedDataDelegate Resolve(string? qualifier) =>
        CryptographicKeyFactory.GetFunction<VerifyCmsSignedDataDelegate>(typeof(VerifyCmsSignedDataDelegate), qualifier)
            ?? throw new InvalidOperationException($"No VerifyCmsSignedDataDelegate has been registered for qualifier '{qualifier ?? "(default)"}'.");
}
