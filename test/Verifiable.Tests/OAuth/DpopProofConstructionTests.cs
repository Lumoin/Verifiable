using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Dpop;
using Verifiable.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

[TestClass]
internal sealed class DpopProofConstructionTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(
        new DateTimeOffset(2026, 5, 13, 12, 0, 0, TimeSpan.Zero));


    [TestMethod]
    public async Task BuildAsyncProducesThreeSegmentJws()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        DpopProofClaims claims = BuildClaims();

        string proof = await DpopProofConstruction.BuildAsync(
            claims,
            key,
            TestSetup.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        string[] parts = proof.Split('.');
        Assert.HasCount(3, parts);
        Assert.IsFalse(string.IsNullOrEmpty(parts[0]));
        Assert.IsFalse(string.IsNullOrEmpty(parts[1]));
        Assert.IsFalse(string.IsNullOrEmpty(parts[2]));
    }


    [TestMethod]
    public async Task BuildAsyncEmitsTypDpopJwtInHeader()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await DpopProofConstruction.BuildAsync(
            BuildClaims(),
            key,
            TestSetup.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        DpopProofHeader header = DecodeHeader(proof);
        Assert.AreEqual(WellKnownDpopValues.ProofTypeHeader, header.Typ);
        Assert.AreEqual(WellKnownJwaValues.Es256, header.Alg);
    }


    [TestMethod]
    public async Task BuildAsyncEmbedsCorrectJwkForP256Key()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var publicKey = keys.PublicKey;
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await DpopProofConstruction.BuildAsync(
            BuildClaims(),
            key,
            TestSetup.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        IReadOnlyDictionary<string, string> expectedJwk = DpopJwkUtilities.ToJwk(
            publicKey, WellKnownJwaValues.Es256, TestSetup.Base64UrlEncoder);

        DpopProofHeader header = DecodeHeader(proof);
        Assert.AreEqual(expectedJwk[WellKnownJwkMemberNames.Kty], header.Jwk[WellKnownJwkMemberNames.Kty]);
        Assert.AreEqual(expectedJwk[WellKnownJwkMemberNames.Crv], header.Jwk[WellKnownJwkMemberNames.Crv]);
        Assert.AreEqual(expectedJwk[WellKnownJwkMemberNames.X], header.Jwk[WellKnownJwkMemberNames.X]);
        Assert.AreEqual(expectedJwk[WellKnownJwkMemberNames.Y], header.Jwk[WellKnownJwkMemberNames.Y]);
    }


    [TestMethod]
    public async Task BuildAsyncOmitsNonceClaimWhenNotProvided()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        string proof = await DpopProofConstruction.BuildAsync(
            BuildClaims(),
            key,
            TestSetup.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        DpopProofClaims parsed = DecodeClaims(proof);
        Assert.IsNull(parsed.Nonce);
        Assert.IsNull(parsed.Ath);
    }


    [TestMethod]
    public async Task BuildAsyncIncludesNonceAndAthWhenProvided()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey key = new(keys, WellKnownJwaValues.Es256);

        DpopProofClaims claims = BuildClaims() with
        {
            Nonce = "fresh-nonce",
            Ath = "fake-ath-hash"
        };

        string proof = await DpopProofConstruction.BuildAsync(
            claims,
            key,
            TestSetup.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        DpopProofClaims parsed = DecodeClaims(proof);
        Assert.AreEqual("fresh-nonce", parsed.Nonce);
        Assert.AreEqual("fake-ath-hash", parsed.Ath);
    }


    private DpopProofClaims BuildClaims() => new()
    {
        Htm = WellKnownHttpMethods.Post,
        Htu = "https://as.example.com/token",
        Iat = TimeProvider.GetUtcNow(),
        Jti = Guid.NewGuid().ToString("N")
    };


    private static DpopProofHeader DecodeHeader(string proof)
    {
        string[] parts = proof.Split('.');
        using System.Buffers.IMemoryOwner<byte> bytes = TestSetup.Base64UrlDecoder(parts[0], BaseMemoryPool.Shared);
        return DpopTestSupport.ParseHeaderJson(bytes.Memory);
    }


    private static DpopProofClaims DecodeClaims(string proof)
    {
        string[] parts = proof.Split('.');
        using System.Buffers.IMemoryOwner<byte> bytes = TestSetup.Base64UrlDecoder(parts[1], BaseMemoryPool.Shared);
        return DpopTestSupport.ParseClaimsJson(bytes.Memory);
    }
}
