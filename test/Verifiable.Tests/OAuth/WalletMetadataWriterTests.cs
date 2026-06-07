using System.Buffers;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Characterization + override tests for <see cref="WalletMetadataWriter"/> — the
/// §5.10 <c>wallet_metadata</c> document. The first test pins exactly what
/// <see cref="Oid4VpWalletCapabilities.HaipDefault"/> emits, so an accidental change
/// to a default value or to the writer breaks a test rather than silently shipping
/// (and only surfacing against an external verifier). The second exercises and
/// documents the <c>with</c>-expression override path.
/// </summary>
[TestClass]
internal sealed class WalletMetadataWriterTests
{
    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;


    [TestMethod]
    public void HaipDefaultEmitsEveryRequiredMemberWithItsBaselineValue()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> exchangeKeys =
            BouncyCastleKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory exchangePublic = exchangeKeys.PublicKey;
        using PrivateKeyMemory exchangePrivate = exchangeKeys.PrivateKey;

        string json = WalletMetadataWriter.BuildForWalletPost(
            Oid4VpWalletCapabilities.HaipDefault,
            exchangePublic,
            "A256GCM",
            TestSetup.Base64UrlEncoder,
            Pool);

        //Pin the baseline document. If a default or the writer changes, these break.
        Assert.Contains("\"issuer\":\"https://wallet.example.com\"", json, StringComparison.Ordinal);
        Assert.Contains("\"authorization_endpoint\":\"openid4vp://\"", json, StringComparison.Ordinal);
        Assert.Contains("\"response_types_supported\":[\"vp_token\"]", json, StringComparison.Ordinal);
        Assert.Contains("\"response_modes_supported\":[\"direct_post.jwt\",\"direct_post\"]", json, StringComparison.Ordinal);
        Assert.Contains(
            "\"client_id_prefixes_supported\":[\"redirect_uri\",\"x509_san_dns\",\"verifier_attestation\"," +
            "\"openid_federation\",\"decentralized_identifier\"]",
            json, StringComparison.Ordinal);
        Assert.Contains("\"request_object_signing_alg_values_supported\":[\"ES256\"]", json, StringComparison.Ordinal);
        Assert.Contains("\"authorization_encryption_alg_values_supported\":[\"ECDH-ES\"]", json, StringComparison.Ordinal);
        Assert.Contains("\"authorization_encryption_enc_values_supported\":[\"A128GCM\",\"A256GCM\"]", json, StringComparison.Ordinal);
        Assert.Contains("\"vp_formats_supported\":{\"dc+sd-jwt\":", json, StringComparison.Ordinal);
        Assert.Contains("\"jwks\":{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"use\":\"enc\",", json, StringComparison.Ordinal);
        Assert.Contains("\"authorization_encrypted_response_enc\":\"A256GCM\"", json, StringComparison.Ordinal);

        //The baseline must satisfy our own strict verifier — the producer and the
        //oracle agree.
        Assert.IsNull(WalletMetadataReader.DescribeWalletPostDefect(json),
            "HaipDefault wallet_metadata must pass the strict verifier with no defect.");
    }


    [TestMethod]
    public void CapabilityOverridesAreReflectedInTheEmittedMetadata()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> exchangeKeys =
            BouncyCastleKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory exchangePublic = exchangeKeys.PublicKey;
        using PrivateKeyMemory exchangePrivate = exchangeKeys.PrivateKey;

        //The documented override path: start from the baseline, change only what the
        //deployment needs (real https issuer, the scanned custom scheme, the verifier's
        //single prefix).
        Oid4VpWalletCapabilities capabilities = Oid4VpWalletCapabilities.HaipDefault with
        {
            Issuer = "https://wallet.lumoin.com",
            AuthorizationEndpoint = "mdoc-openid4vp://",
            ClientIdPrefixesSupported = ["x509_san_dns"]
        };

        string json = WalletMetadataWriter.BuildForWalletPost(
            capabilities,
            exchangePublic,
            "A256GCM",
            TestSetup.Base64UrlEncoder,
            Pool);

        Assert.Contains("\"issuer\":\"https://wallet.lumoin.com\"", json, StringComparison.Ordinal);
        Assert.Contains("\"authorization_endpoint\":\"mdoc-openid4vp://\"", json, StringComparison.Ordinal);
        Assert.Contains("\"client_id_prefixes_supported\":[\"x509_san_dns\"]", json, StringComparison.Ordinal);

        //Members not overridden still carry the baseline.
        Assert.Contains("\"response_types_supported\":[\"vp_token\"]", json, StringComparison.Ordinal);

        Assert.IsNull(WalletMetadataReader.DescribeWalletPostDefect(json),
            "The overridden wallet_metadata must still pass the strict verifier.");
    }


    [TestMethod]
    public void P384ExchangeKeyEmitsP384JwkAndRecoversIt()
    {
        AssertExchangeKeyRoundTrips(
            BouncyCastleKeyMaterialCreator.CreateP384ExchangeKeys,
            WellKnownCurveValues.P384,
            CryptoAlgorithm.P384);
    }


    [TestMethod]
    public void P521ExchangeKeyEmitsP521JwkAndRecoversIt()
    {
        AssertExchangeKeyRoundTrips(
            BouncyCastleKeyMaterialCreator.CreateP521ExchangeKeys,
            WellKnownCurveValues.P521,
            CryptoAlgorithm.P521);
    }


    [TestMethod]
    public void X25519ExchangeKeyEmitsOkpJwkAndRecoversIt()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> exchangeKeys =
            BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory exchangePublic = exchangeKeys.PublicKey;
        using PrivateKeyMemory exchangePrivate = exchangeKeys.PrivateKey;

        string json = WalletMetadataWriter.BuildForWalletPost(
            Oid4VpWalletCapabilities.HaipDefault,
            exchangePublic,
            "A256GCM",
            TestSetup.Base64UrlEncoder,
            Pool);

        //X25519 is an OKP key: kty=OKP, crv=X25519, a single x coordinate and no y.
        Assert.Contains(
            $"\"jwks\":{{\"keys\":[{{\"kty\":\"{WellKnownKeyTypeValues.Okp}\",\"crv\":\"{WellKnownCurveValues.X25519}\",\"use\":\"enc\",\"x\":",
            json, StringComparison.Ordinal,
            "jwks must carry the X25519 OKP exchange key.");
        Assert.DoesNotContain("\"y\":", json, StringComparison.Ordinal,
            "An OKP exchange key must not emit a y coordinate.");

        (string? jwksJson, _) = WalletMetadataReader.ParseForJarEncryption(json);
        Assert.IsNotNull(jwksJson, "wallet_metadata must expose a jwks object.");

        using PublicKeyMemory recovered = JwksEpkExtractor.ExtractEcdhEncryptionKey(
            jwksJson, TestSetup.Base64UrlDecoder, Pool);

        Assert.IsTrue(
            recovered.AsReadOnlySpan().SequenceEqual(exchangePublic.AsReadOnlySpan()),
            "Recovered raw key must match the wallet's X25519 exchange public key.");
        Assert.AreEqual(CryptoAlgorithm.X25519, recovered.Tag.Get<CryptoAlgorithm>(),
            "Recovered key must be tagged X25519.");
        Assert.AreEqual(Purpose.Exchange, recovered.Tag.Get<Purpose>(),
            "Recovered key must carry Purpose.Exchange.");
    }


    [TestMethod]
    public void BrainpoolP256r1ExchangeKeyEmitsBrainpoolJwkAndRecoversIt()
    {
        AssertExchangeKeyRoundTrips(
            BouncyCastleKeyMaterialCreator.CreateBrainpoolP256r1ExchangeKeys,
            WellKnownCurveValues.BrainpoolP256r1,
            CryptoAlgorithm.BrainpoolP256r1);
    }


    [TestMethod]
    public void BrainpoolP320r1ExchangeKeyEmitsBrainpoolJwkAndRecoversIt()
    {
        AssertExchangeKeyRoundTrips(
            BouncyCastleKeyMaterialCreator.CreateBrainpoolP320r1ExchangeKeys,
            WellKnownCurveValues.BrainpoolP320r1,
            CryptoAlgorithm.BrainpoolP320r1);
    }


    [TestMethod]
    public void BrainpoolP384r1ExchangeKeyEmitsBrainpoolJwkAndRecoversIt()
    {
        AssertExchangeKeyRoundTrips(
            BouncyCastleKeyMaterialCreator.CreateBrainpoolP384r1ExchangeKeys,
            WellKnownCurveValues.BrainpoolP384r1,
            CryptoAlgorithm.BrainpoolP384r1);
    }


    [TestMethod]
    public void BrainpoolP512r1ExchangeKeyEmitsBrainpoolJwkAndRecoversIt()
    {
        AssertExchangeKeyRoundTrips(
            BouncyCastleKeyMaterialCreator.CreateBrainpoolP512r1ExchangeKeys,
            WellKnownCurveValues.BrainpoolP512r1,
            CryptoAlgorithm.BrainpoolP512r1);
    }


    /// <summary>
    /// Asserts that an EC exchange key emits the correct EC JWK (<c>kty=EC</c>,
    /// the right <c>crv</c>, field-sized <c>x</c>/<c>y</c>) and that a verifier can
    /// recover that exact key, tagged with the matching exchange algorithm, from the
    /// posted <c>jwks</c>, so the producer and the consumer agree on the wire shape.
    /// </summary>
    private static void AssertExchangeKeyRoundTrips(
        Func<MemoryPool<byte>, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> createKeys,
        string expectedCrv,
        CryptoAlgorithm expectedAlgorithm)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> exchangeKeys = createKeys(Pool);
        using PublicKeyMemory exchangePublic = exchangeKeys.PublicKey;
        using PrivateKeyMemory exchangePrivate = exchangeKeys.PrivateKey;

        string json = WalletMetadataWriter.BuildForWalletPost(
            Oid4VpWalletCapabilities.HaipDefault,
            exchangePublic,
            "A256GCM",
            TestSetup.Base64UrlEncoder,
            Pool);

        Assert.Contains(
            $"\"jwks\":{{\"keys\":[{{\"kty\":\"EC\",\"crv\":\"{expectedCrv}\",\"use\":\"enc\",",
            json, StringComparison.Ordinal,
            $"jwks must carry the {expectedCrv} EC exchange key.");

        //A verifier reads jwks and recovers the wallet's exchange key for JAR encryption.
        (string? jwksJson, _) = WalletMetadataReader.ParseForJarEncryption(json);
        Assert.IsNotNull(jwksJson, "wallet_metadata must expose a jwks object.");

        using PublicKeyMemory recovered = JwksEpkExtractor.ExtractEcdhEncryptionKey(
            jwksJson, TestSetup.Base64UrlDecoder, Pool);

        Assert.IsTrue(
            recovered.AsReadOnlySpan().SequenceEqual(exchangePublic.AsReadOnlySpan()),
            "Recovered uncompressed point must match the wallet's exchange public key.");
        Assert.AreEqual(expectedAlgorithm, recovered.Tag.Get<CryptoAlgorithm>(),
            "Recovered key must be tagged with the matching exchange algorithm.");
        Assert.AreEqual(Purpose.Exchange, recovered.Tag.Get<Purpose>(),
            "Recovered key must carry Purpose.Exchange.");
    }
}
