using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Tests for ECDH-ES key agreement with P-256 and AES-GCM content encryption using
/// the split delegate design. Covers encrypt (<see cref="JweExtensions.EncryptAsync"/>)
/// and decrypt (<see cref="JweExtensions.DecryptAsync"/>) for both backends
/// and their cross-backend combinations.
/// </summary>
[TestClass]
internal sealed class EcdhEsTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    private static readonly JwtHeaderSerializer JwtHeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);


    [TestMethod]
    public async Task EncryptProducesValidCompactJweStructure()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            BouncyCastleKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        UnencryptedJwe unencrypted = UnencryptedJwe.ForEcdhEs(
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            Encoding.UTF8.GetBytes(/*lang=json,strict*/ "{\"vp_token\":\"test\"}").AsMemory());

        using JweMessage message = await unencrypted.EncryptAsync(
            publicKey,
            JwtHeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJwe = message.ToCompactJwe(TestSetup.Base64UrlEncoder);

        string[] parts = compactJwe.Split('.');
        Assert.HasCount(5, parts, "Compact JWE must have exactly five dot-separated parts.");
        Assert.IsFalse(string.IsNullOrEmpty(parts[0]), "Protected header must not be empty.");
        Assert.IsTrue(string.IsNullOrEmpty(parts[1]), "Encrypted key slot must be empty for ECDH-ES.");
        Assert.IsFalse(string.IsNullOrEmpty(parts[2]), "IV must not be empty.");
        Assert.IsFalse(string.IsNullOrEmpty(parts[3]), "Ciphertext must not be empty.");
        Assert.IsFalse(string.IsNullOrEmpty(parts[4]), "Authentication tag must not be empty.");
    }


    [TestMethod]
    public async Task EncryptedHeaderContainsRequiredParameters()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            BouncyCastleKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        UnencryptedJwe unencrypted = UnencryptedJwe.ForEcdhEs(
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            Encoding.UTF8.GetBytes(/*lang=json,strict*/ "{\"iss\":\"test\"}").AsMemory());

        using JweMessage message = await unencrypted.EncryptAsync(
            publicKey,
            JwtHeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        string headerEncoded = message.ToCompactJwe(TestSetup.Base64UrlEncoder).Split('.')[0];
        using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(headerEncoded, Pool);
        string headerJson = Encoding.UTF8.GetString(headerBytes.Memory.Span);

        Assert.IsTrue(headerJson.Contains($"\"alg\":\"{WellKnownJweAlgorithms.EcdhEs}\"",
            StringComparison.Ordinal), "Header must contain alg=ECDH-ES.");
        Assert.IsTrue(headerJson.Contains($"\"enc\":\"{WellKnownJweEncryptionAlgorithms.A128Gcm}\"",
            StringComparison.Ordinal), "Header must contain enc=A128GCM.");
        Assert.IsTrue(headerJson.Contains($"\"{WellKnownJwkValues.Epk}\"",
            StringComparison.Ordinal), "Header must contain the epk.");
        Assert.IsTrue(headerJson.Contains($"\"{WellKnownJwkValues.Kty}\":\"{WellKnownKeyTypeValues.Ec}\"",
            StringComparison.Ordinal), "EPK must have kty=EC.");
        Assert.IsTrue(headerJson.Contains($"\"{WellKnownJwkValues.Crv}\":\"{WellKnownCurveValues.P256}\"",
            StringComparison.Ordinal), "EPK must have crv=P-256.");
    }


    [TestMethod]
    public async Task BouncyCastleRoundTripProducesOriginalPlaintext()
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(
            /*lang=json,strict*/ "{\"vp_token\":\"eyJhbGciOiJFUzI1NiJ9.test.sig\"}");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            BouncyCastleKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using JweMessage encrypted = await UnencryptedJwe.ForEcdhEs(
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            plaintext.AsMemory()).EncryptAsync(
                publicKey,
                JwtHeaderSerializer,
                TestSetup.Base64UrlEncoder,
                CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
                ConcatKdf.DefaultKeyDerivationDelegate,
                BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

        using AeadMessage parsed = JweParsing.ParseCompact(
            encrypted.ToCompactJwe(TestSetup.Base64UrlEncoder),
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            TestSetup.Base64UrlDecoder,
            Pool);

        using DecryptedContent decrypted = await parsed.DecryptAsync(
            privateKey,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(
            decrypted.AsReadOnlySpan().SequenceEqual(plaintext),
            "Decrypted plaintext must match the original.");
    }


    [TestMethod]
    public async Task MicrosoftRoundTripProducesOriginalPlaintext()
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(
            /*lang=json,strict*/ "{\"iss\":\"https://wallet.example.com\"}");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using JweMessage encrypted = await UnencryptedJwe.ForEcdhEs(
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            plaintext.AsMemory()).EncryptAsync(
                publicKey,
                JwtHeaderSerializer,
                TestSetup.Base64UrlEncoder,
                CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                MicrosoftKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
                ConcatKdf.DefaultKeyDerivationDelegate,
                MicrosoftKeyAgreementFunctions.AesGcmEncryptAsync,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

        using AeadMessage parsed = JweParsing.ParseCompact(
            encrypted.ToCompactJwe(TestSetup.Base64UrlEncoder),
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            TestSetup.Base64UrlDecoder,
            Pool);

        using DecryptedContent decrypted = await parsed.DecryptAsync(
            privateKey,
            MicrosoftKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesGcmDecryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(
            decrypted.AsReadOnlySpan().SequenceEqual(plaintext),
            "Microsoft round-trip must produce the original plaintext.");
    }


    [TestMethod]
    public async Task BouncyCastleEncryptMicrosoftDecryptProducesOriginalPlaintext()
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(
            /*lang=json,strict*/ "{\"sub\":\"cross-backend\"}");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using JweMessage encrypted = await UnencryptedJwe.ForEcdhEs(
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            plaintext.AsMemory()).EncryptAsync(
                publicKey,
                JwtHeaderSerializer,
                TestSetup.Base64UrlEncoder,
                CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
                ConcatKdf.DefaultKeyDerivationDelegate,
                BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

        using AeadMessage parsed = JweParsing.ParseCompact(
            encrypted.ToCompactJwe(TestSetup.Base64UrlEncoder),
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            TestSetup.Base64UrlDecoder,
            Pool);

        using DecryptedContent decrypted = await parsed.DecryptAsync(
            privateKey,
            MicrosoftKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesGcmDecryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(
            decrypted.AsReadOnlySpan().SequenceEqual(plaintext),
            "BouncyCastle encrypt and Microsoft decrypt must interoperate.");
    }


    [TestMethod]
    public async Task MicrosoftEncryptBouncyCastleDecryptProducesOriginalPlaintext()
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(
            /*lang=json,strict*/ "{\"sub\":\"cross-backend-reverse\"}");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            BouncyCastleKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using JweMessage encrypted = await UnencryptedJwe.ForEcdhEs(
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            plaintext.AsMemory()).EncryptAsync(
                publicKey,
                JwtHeaderSerializer,
                TestSetup.Base64UrlEncoder,
                CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                MicrosoftKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
                ConcatKdf.DefaultKeyDerivationDelegate,
                MicrosoftKeyAgreementFunctions.AesGcmEncryptAsync,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

        using AeadMessage parsed = JweParsing.ParseCompact(
            encrypted.ToCompactJwe(TestSetup.Base64UrlEncoder),
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            TestSetup.Base64UrlDecoder,
            Pool);

        using DecryptedContent decrypted = await parsed.DecryptAsync(
            privateKey,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(
            decrypted.AsReadOnlySpan().SequenceEqual(plaintext),
            "Microsoft encrypt and BouncyCastle decrypt must interoperate.");
    }


    [TestMethod]
    public async Task RegistryDispatchRoundTripProducesOriginalPlaintext()
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(
            /*lang=json,strict*/ "{\"nonce\":\"abc123\"}");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            BouncyCastleKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using JweMessage encrypted = await UnencryptedJwe.ForEcdhEs(
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            plaintext.AsMemory()).EncryptAsync(
                publicKey,
                JwtHeaderSerializer,
                TestSetup.Base64UrlEncoder,
                CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
                ConcatKdf.DefaultKeyDerivationDelegate,
                BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

        using AeadMessage parsed = JweParsing.ParseCompact(
            encrypted.ToCompactJwe(TestSetup.Base64UrlEncoder),
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            TestSetup.Base64UrlDecoder,
            Pool);

        using DecryptedContent decrypted = await parsed.DecryptAsync(
            privateKey,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(
            decrypted.AsReadOnlySpan().SequenceEqual(plaintext),
            "Registry-dispatched decrypt must produce the original plaintext.");
    }


    [TestMethod]
    public async Task TamperedCiphertextThrowsCryptographicException()
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(
            /*lang=json,strict*/ "{\"sub\":\"user-42\"}");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            BouncyCastleKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using JweMessage encrypted = await UnencryptedJwe.ForEcdhEs(
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            plaintext.AsMemory()).EncryptAsync(
                publicKey,
                JwtHeaderSerializer,
                TestSetup.Base64UrlEncoder,
                CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
                ConcatKdf.DefaultKeyDerivationDelegate,
                BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

        string tampered = TamperSegment(encrypted.ToCompactJwe(TestSetup.Base64UrlEncoder), segmentIndex: 3);

        using AeadMessage parsed = JweParsing.ParseCompact(
            tampered,
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            TestSetup.Base64UrlDecoder,
            Pool);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await parsed.DecryptAsync(
                privateKey,
                BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
                ConcatKdf.DefaultKeyDerivationDelegate,
                BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);
    }


    [TestMethod]
    public async Task TamperedAuthTagThrowsCryptographicException()
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(
            /*lang=json,strict*/ "{\"sub\":\"user-99\"}");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            BouncyCastleKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using JweMessage encrypted = await UnencryptedJwe.ForEcdhEs(
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            plaintext.AsMemory()).EncryptAsync(
                publicKey,
                JwtHeaderSerializer,
                TestSetup.Base64UrlEncoder,
                CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
                ConcatKdf.DefaultKeyDerivationDelegate,
                BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

        string tampered = TamperSegment(encrypted.ToCompactJwe(TestSetup.Base64UrlEncoder), segmentIndex: 4);

        using AeadMessage parsed = JweParsing.ParseCompact(
            tampered,
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            TestSetup.Base64UrlDecoder,
            Pool);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await parsed.DecryptAsync(
                privateKey,
                BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
                ConcatKdf.DefaultKeyDerivationDelegate,
                BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);
    }


    [TestMethod]
    public async Task WrongAlgorithmInHeaderThrowsFormatException()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            BouncyCastleKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory publicKey = keyPair.PublicKey;

        using JweMessage encrypted = await UnencryptedJwe.ForEcdhEs(
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            Encoding.UTF8.GetBytes(/*lang=json,strict*/ "{\"test\":true}").AsMemory()).EncryptAsync(
                publicKey,
                JwtHeaderSerializer,
                TestSetup.Base64UrlEncoder,
                CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
                ConcatKdf.DefaultKeyDerivationDelegate,
                BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

        Assert.ThrowsExactly<FormatException>(() =>
            JweParsing.ParseCompact(
                encrypted.ToCompactJwe(TestSetup.Base64UrlEncoder),
                WellKnownJweAlgorithms.EcdhEsA128Kw,
                WellKnownJweEncryptionAlgorithms.A128Gcm,
                TestSetup.Base64UrlDecoder,
                Pool));
    }


    [TestMethod]
    public void OversizedTokenThrowsArgumentException()
    {
        string oversized = new('A', JweParsing.MaxCompactJweByteCount + 1);

        Assert.ThrowsExactly<ArgumentException>(() =>
            JweParsing.ParseCompact(
                oversized,
                WellKnownJweAlgorithms.EcdhEs,
                WellKnownJweEncryptionAlgorithms.A128Gcm,
                TestSetup.Base64UrlDecoder,
                Pool));
    }


    [TestMethod]
    public async Task WrongExpectedEncryptionThrowsFormatException()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            BouncyCastleKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory publicKey = keyPair.PublicKey;

        using JweMessage encrypted = await UnencryptedJwe.ForEcdhEs(
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            Encoding.UTF8.GetBytes(/*lang=json,strict*/ "{\"test\":true}").AsMemory()).EncryptAsync(
                publicKey,
                JwtHeaderSerializer,
                TestSetup.Base64UrlEncoder,
                CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
                ConcatKdf.DefaultKeyDerivationDelegate,
                BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

        Assert.ThrowsExactly<FormatException>(() =>
            JweParsing.ParseCompact(
                encrypted.ToCompactJwe(TestSetup.Base64UrlEncoder),
                WellKnownJweAlgorithms.EcdhEs,
                WellKnownJweEncryptionAlgorithms.A256Gcm,
                TestSetup.Base64UrlDecoder,
                Pool));
    }


    private static string TamperSegment(string compactJwe, int segmentIndex)
    {
        string[] parts = compactJwe.Split('.');
        using IMemoryOwner<byte> decoded = TestSetup.Base64UrlDecoder(parts[segmentIndex], Pool);
        decoded.Memory.Span[0] ^= 0xFF;
        parts[segmentIndex] = TestSetup.Base64UrlEncoder(decoded.Memory.Span);
        return string.Join('.', parts);
    }
}
