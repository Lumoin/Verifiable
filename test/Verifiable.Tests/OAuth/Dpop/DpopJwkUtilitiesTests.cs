using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Dpop;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth.Dpop;

[TestClass]
internal sealed class DpopJwkUtilitiesTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void ToJwkProducesKtyCrvXY()
    {
        var keys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keys.PublicKey;

        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
            publicKey, WellKnownJwaValues.Es256, TestSetup.Base64UrlEncoder);

        Assert.AreEqual(WellKnownKeyTypeValues.Ec, jwk[WellKnownJwkMemberNames.Kty]);
        Assert.AreEqual(WellKnownCurveValues.P256, jwk[WellKnownJwkMemberNames.Crv]);
        Assert.IsTrue(jwk.ContainsKey(WellKnownJwkMemberNames.X));
        Assert.IsTrue(jwk.ContainsKey(WellKnownJwkMemberNames.Y));
        Assert.IsFalse(jwk.ContainsKey(WellKnownJwkMemberNames.Alg),
            "DPoP JWK header must not include 'alg' — alg lives separately on the JWS protected header.");
    }


    [TestMethod]
    public void ComputeThumbprintMatchesJwkThumbprintUtilities()
    {
        var keys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keys.PublicKey;

        string viaDpop = DpopJwkUtilities.ComputeThumbprint(
            publicKey, WellKnownJwaValues.Es256, TestSetup.Base64UrlEncoder, SensitiveMemoryPool<byte>.Shared);

        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
            publicKey, WellKnownJwaValues.Es256, TestSetup.Base64UrlEncoder);
        using IMemoryOwner<byte> directHash = JwkThumbprintUtilities.ComputeECThumbprint(
            SensitiveMemoryPool<byte>.Shared,
            jwk[WellKnownJwkMemberNames.Crv],
            jwk[WellKnownJwkMemberNames.Kty],
            jwk[WellKnownJwkMemberNames.X],
            jwk[WellKnownJwkMemberNames.Y]);
        string direct = TestSetup.Base64UrlEncoder(directHash.Memory.Span);

        Assert.AreEqual(direct, viaDpop);
    }


    [TestMethod]
    public void PublicKeyFromJwkRoundTripsThumbprint()
    {
        var keys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var originalPublicKey = keys.PublicKey;

        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
            originalPublicKey, WellKnownJwaValues.Es256, TestSetup.Base64UrlEncoder);

        using PublicKeyMemory reconstructed = DpopJwkUtilities.PublicKeyFromJwk(
            jwk, WellKnownJwaValues.Es256, TestSetup.Base64UrlDecoder, SensitiveMemoryPool<byte>.Shared);

        string originalThumbprint = DpopJwkUtilities.ComputeThumbprint(
            originalPublicKey, WellKnownJwaValues.Es256, TestSetup.Base64UrlEncoder, SensitiveMemoryPool<byte>.Shared);
        string reconstructedThumbprint = DpopJwkUtilities.ComputeThumbprint(
            reconstructed, WellKnownJwaValues.Es256, TestSetup.Base64UrlEncoder, SensitiveMemoryPool<byte>.Shared);

        Assert.AreEqual(originalThumbprint, reconstructedThumbprint,
            "JWK round-trip must preserve the thumbprint identity.");
    }


    [TestMethod]
    public void ToJwkRejectsNonEcdsaAlg()
    {
        var keys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keys.PublicKey;

        Assert.ThrowsExactly<NotSupportedException>(() => _ = DpopJwkUtilities.ToJwk(
            publicKey, WellKnownJwaValues.Hs256, TestSetup.Base64UrlEncoder));
    }
}
