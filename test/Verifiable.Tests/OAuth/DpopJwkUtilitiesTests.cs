using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Dpop;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

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
            publicKey, WellKnownJwaValues.Es256, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
            publicKey, WellKnownJwaValues.Es256, TestSetup.Base64UrlEncoder);
        using IMemoryOwner<byte> directHash = JwkThumbprintUtilities.ComputeECThumbprint(
            BaseMemoryPool.Shared,
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
            jwk, WellKnownJwaValues.Es256, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

        string originalThumbprint = DpopJwkUtilities.ComputeThumbprint(
            originalPublicKey, WellKnownJwaValues.Es256, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string reconstructedThumbprint = DpopJwkUtilities.ComputeThumbprint(
            reconstructed, WellKnownJwaValues.Es256, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        Assert.AreEqual(originalThumbprint, reconstructedThumbprint,
            "JWK round-trip must preserve the thumbprint identity.");
    }


    //RFC 9449 §4.2 RSA path — DpopJwkUtilities must produce kty=RSA / n / e
    //for an RSA-2048 key, the thumbprint must match the kty-appropriate
    //utility, and PublicKeyFromJwk must round-trip the material.

    [TestMethod]
    public void ToJwkProducesKtyNeForRsa2048()
    {
        var keys = TestKeyMaterialProvider.CreateRsa2048KeyMaterial();
        using var publicKey = keys.PublicKey;

        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
            publicKey, WellKnownJwaValues.Rs256, TestSetup.Base64UrlEncoder);

        Assert.AreEqual(WellKnownKeyTypeValues.Rsa, jwk[WellKnownJwkMemberNames.Kty]);
        Assert.IsTrue(jwk.ContainsKey(WellKnownJwkMemberNames.N));
        Assert.IsTrue(jwk.ContainsKey(WellKnownJwkMemberNames.E));
        Assert.IsFalse(jwk.ContainsKey(WellKnownJwkMemberNames.Crv),
            "RSA JWKs must not carry 'crv'.");
        Assert.IsFalse(jwk.ContainsKey(WellKnownJwkMemberNames.Alg),
            "DPoP JWK header must not include 'alg' — alg lives separately on the JWS protected header.");
    }


    [TestMethod]
    public void ComputeThumbprintForRsa2048MatchesJwkThumbprintUtilities()
    {
        var keys = TestKeyMaterialProvider.CreateRsa2048KeyMaterial();
        using var publicKey = keys.PublicKey;

        string viaDpop = DpopJwkUtilities.ComputeThumbprint(
            publicKey, WellKnownJwaValues.Rs256, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
            publicKey, WellKnownJwaValues.Rs256, TestSetup.Base64UrlEncoder);
        using IMemoryOwner<byte> directHash = JwkThumbprintUtilities.ComputeRsaThumbprint(
            BaseMemoryPool.Shared,
            jwk[WellKnownJwkMemberNames.E],
            jwk[WellKnownJwkMemberNames.Kty],
            jwk[WellKnownJwkMemberNames.N]);
        string direct = TestSetup.Base64UrlEncoder(directHash.Memory.Span);

        Assert.AreEqual(direct, viaDpop);
    }


    [TestMethod]
    public void PublicKeyFromJwkRoundTripsThumbprintForRsa2048()
    {
        var keys = TestKeyMaterialProvider.CreateRsa2048KeyMaterial();
        using var originalPublicKey = keys.PublicKey;

        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
            originalPublicKey, WellKnownJwaValues.Rs256, TestSetup.Base64UrlEncoder);

        using PublicKeyMemory reconstructed = DpopJwkUtilities.PublicKeyFromJwk(
            jwk, WellKnownJwaValues.Rs256, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

        string originalThumbprint = DpopJwkUtilities.ComputeThumbprint(
            originalPublicKey, WellKnownJwaValues.Rs256, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string reconstructedThumbprint = DpopJwkUtilities.ComputeThumbprint(
            reconstructed, WellKnownJwaValues.Rs256, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        Assert.AreEqual(originalThumbprint, reconstructedThumbprint,
            "JWK round-trip must preserve the thumbprint identity for RSA keys.");
    }


    //RFC 9449 §4.2 EdDSA path — DpopJwkUtilities must produce kty=OKP /
    //crv=Ed25519 / x for an Ed25519 key.

    [TestMethod]
    public void ToJwkProducesKtyCrvXForEd25519()
    {
        var keys = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using var publicKey = keys.PublicKey;

        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
            publicKey, WellKnownJwaValues.EdDsa, TestSetup.Base64UrlEncoder);

        Assert.AreEqual(WellKnownKeyTypeValues.Okp, jwk[WellKnownJwkMemberNames.Kty]);
        Assert.AreEqual(WellKnownCurveValues.Ed25519, jwk[WellKnownJwkMemberNames.Crv]);
        Assert.IsTrue(jwk.ContainsKey(WellKnownJwkMemberNames.X));
        Assert.IsFalse(jwk.ContainsKey(WellKnownJwkMemberNames.Y),
            "OKP JWKs must not carry 'y'.");
        Assert.IsFalse(jwk.ContainsKey(WellKnownJwkMemberNames.Alg),
            "DPoP JWK header must not include 'alg' — alg lives separately on the JWS protected header.");
    }


    [TestMethod]
    public void ComputeThumbprintForEd25519MatchesJwkThumbprintUtilities()
    {
        var keys = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using var publicKey = keys.PublicKey;

        string viaDpop = DpopJwkUtilities.ComputeThumbprint(
            publicKey, WellKnownJwaValues.EdDsa, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
            publicKey, WellKnownJwaValues.EdDsa, TestSetup.Base64UrlEncoder);
        using IMemoryOwner<byte> directHash = JwkThumbprintUtilities.ComputeEdDsaThumbprint(
            BaseMemoryPool.Shared,
            jwk[WellKnownJwkMemberNames.Crv],
            jwk[WellKnownJwkMemberNames.Kty],
            jwk[WellKnownJwkMemberNames.X]);
        string direct = TestSetup.Base64UrlEncoder(directHash.Memory.Span);

        Assert.AreEqual(direct, viaDpop);
    }


    [TestMethod]
    public void PublicKeyFromJwkRoundTripsThumbprintForEd25519()
    {
        var keys = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using var originalPublicKey = keys.PublicKey;

        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
            originalPublicKey, WellKnownJwaValues.EdDsa, TestSetup.Base64UrlEncoder);

        using PublicKeyMemory reconstructed = DpopJwkUtilities.PublicKeyFromJwk(
            jwk, WellKnownJwaValues.EdDsa, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

        string originalThumbprint = DpopJwkUtilities.ComputeThumbprint(
            originalPublicKey, WellKnownJwaValues.EdDsa, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string reconstructedThumbprint = DpopJwkUtilities.ComputeThumbprint(
            reconstructed, WellKnownJwaValues.EdDsa, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        Assert.AreEqual(originalThumbprint, reconstructedThumbprint,
            "JWK round-trip must preserve the thumbprint identity for Ed25519 keys.");
    }
}
