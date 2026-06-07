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

        Assert.Contains($"\"alg\":\"{WellKnownJweAlgorithms.EcdhEs}\"",
            headerJson, StringComparison.Ordinal, "Header must contain alg=ECDH-ES.");
        Assert.Contains($"\"enc\":\"{WellKnownJweEncryptionAlgorithms.A128Gcm}\"",
            headerJson, StringComparison.Ordinal, "Header must contain enc=A128GCM.");
        Assert.Contains($"\"{WellKnownJoseHeaderNames.Epk}\"",
            headerJson, StringComparison.Ordinal, "Header must contain the epk.");
        Assert.Contains($"\"{WellKnownJwkMemberNames.Kty}\":\"{WellKnownKeyTypeValues.Ec}\"",
            headerJson, StringComparison.Ordinal, "EPK must have kty=EC.");
        Assert.Contains($"\"{WellKnownJwkMemberNames.Crv}\":\"{WellKnownCurveValues.P256}\"",
            headerJson, StringComparison.Ordinal, "EPK must have crv=P-256.");
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


    [TestMethod]
    public async Task BrainpoolP256r1RoundTripProducesOriginalPlaintext()
    {
        await BrainpoolRoundTripAsync(
            BouncyCastleKeyMaterialCreator.CreateBrainpoolP256r1ExchangeKeys,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptBrainpoolP256r1Async,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptBrainpoolP256r1Async,
            WellKnownCurveValues.BrainpoolP256r1).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task BrainpoolP320r1RoundTripProducesOriginalPlaintext()
    {
        await BrainpoolRoundTripAsync(
            BouncyCastleKeyMaterialCreator.CreateBrainpoolP320r1ExchangeKeys,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptBrainpoolP320r1Async,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptBrainpoolP320r1Async,
            WellKnownCurveValues.BrainpoolP320r1).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task BrainpoolP384r1RoundTripProducesOriginalPlaintext()
    {
        await BrainpoolRoundTripAsync(
            BouncyCastleKeyMaterialCreator.CreateBrainpoolP384r1ExchangeKeys,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptBrainpoolP384r1Async,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptBrainpoolP384r1Async,
            WellKnownCurveValues.BrainpoolP384r1).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task BrainpoolP512r1RoundTripProducesOriginalPlaintext()
    {
        await BrainpoolRoundTripAsync(
            BouncyCastleKeyMaterialCreator.CreateBrainpoolP512r1ExchangeKeys,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptBrainpoolP512r1Async,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptBrainpoolP512r1Async,
            WellKnownCurveValues.BrainpoolP512r1).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task P384BouncyCastleRoundTripProducesOriginalPlaintext()
    {
        await NistRoundTripAsync(
            BouncyCastleKeyMaterialCreator.CreateP384ExchangeKeys,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP384Async,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptP384Async,
            BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
            WellKnownCurveValues.P384).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task P384MicrosoftRoundTripProducesOriginalPlaintext()
    {
        await NistRoundTripAsync(
            MicrosoftKeyMaterialCreator.CreateP384ExchangeKeys,
            MicrosoftKeyAgreementFunctions.EcdhKeyAgreementEncryptP384Async,
            MicrosoftKeyAgreementFunctions.AesGcmEncryptAsync,
            MicrosoftKeyAgreementFunctions.EcdhKeyAgreementDecryptP384Async,
            MicrosoftKeyAgreementFunctions.AesGcmDecryptAsync,
            WellKnownCurveValues.P384).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task P384BouncyCastleEncryptMicrosoftDecryptProducesOriginalPlaintext()
    {
        await NistRoundTripAsync(
            MicrosoftKeyMaterialCreator.CreateP384ExchangeKeys,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP384Async,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            MicrosoftKeyAgreementFunctions.EcdhKeyAgreementDecryptP384Async,
            MicrosoftKeyAgreementFunctions.AesGcmDecryptAsync,
            WellKnownCurveValues.P384).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task P521BouncyCastleRoundTripProducesOriginalPlaintext()
    {
        await NistRoundTripAsync(
            BouncyCastleKeyMaterialCreator.CreateP521ExchangeKeys,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP521Async,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptP521Async,
            BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
            WellKnownCurveValues.P521).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task P521MicrosoftRoundTripProducesOriginalPlaintext()
    {
        await NistRoundTripAsync(
            MicrosoftKeyMaterialCreator.CreateP521ExchangeKeys,
            MicrosoftKeyAgreementFunctions.EcdhKeyAgreementEncryptP521Async,
            MicrosoftKeyAgreementFunctions.AesGcmEncryptAsync,
            MicrosoftKeyAgreementFunctions.EcdhKeyAgreementDecryptP521Async,
            MicrosoftKeyAgreementFunctions.AesGcmDecryptAsync,
            WellKnownCurveValues.P521).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task P521BouncyCastleEncryptMicrosoftDecryptProducesOriginalPlaintext()
    {
        await NistRoundTripAsync(
            MicrosoftKeyMaterialCreator.CreateP521ExchangeKeys,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP521Async,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            MicrosoftKeyAgreementFunctions.EcdhKeyAgreementDecryptP521Async,
            MicrosoftKeyAgreementFunctions.AesGcmDecryptAsync,
            WellKnownCurveValues.P521).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task X25519RoundTripProducesOriginalPlaintextAndOkpEpk()
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(
            /*lang=json,strict*/ "{\"vp_token\":\"eyJhbGciOiJFUzI1NiJ9.test.sig\"}");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
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
                BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptX25519Async,
                ConcatKdf.DefaultKeyDerivationDelegate,
                BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

        string compactJwe = encrypted.ToCompactJwe(TestSetup.Base64UrlEncoder);

        string headerEncoded = compactJwe.Split('.')[0];
        using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(headerEncoded, Pool);
        string headerJson = Encoding.UTF8.GetString(headerBytes.Memory.Span);

        //X25519 is an OKP key (RFC 8037): kty=OKP, crv=X25519, a single x and no y —
        //proving the epk shape is driven by the key's tag, not hardcoded to EC.
        Assert.Contains($"\"{WellKnownJwkMemberNames.Kty}\":\"{WellKnownKeyTypeValues.Okp}\"",
            headerJson, StringComparison.Ordinal, "EPK must have kty=OKP.");
        Assert.Contains($"\"{WellKnownJwkMemberNames.Crv}\":\"{WellKnownCurveValues.X25519}\"",
            headerJson, StringComparison.Ordinal, "EPK must have crv=X25519.");
        Assert.DoesNotContain($"\"{WellKnownJwkMemberNames.Y}\":",
            headerJson, StringComparison.Ordinal, "An OKP epk must not carry a y coordinate.");

        using AeadMessage parsed = JweParsing.ParseCompact(
            compactJwe,
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            TestSetup.Base64UrlDecoder,
            Pool);

        using DecryptedContent decrypted = await parsed.DecryptAsync(
            privateKey,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptX25519Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(
            decrypted.AsReadOnlySpan().SequenceEqual(plaintext),
            "X25519 round-trip must produce the original plaintext.");
    }


    //Drives a full ECDH-ES JWE round-trip over one NIST curve (P-384/P-521, RFC 7518
    //§6.2.1): one backend's exchange key encrypts, the wire form is reparsed (running the
    //epk point-on-curve validation through DefaultEpkCrvToTagConverter), and the chosen
    //backend decrypts. Asserts the recovered plaintext and that the emitted epk carried
    //the expected NIST crv name — proving DefaultTagToEpkCrvConverter wired the curve, and
    //(for the cross-backend cases) that the P-521 66-byte shared secret padding agrees.
    private async Task NistRoundTripAsync(
        Func<MemoryPool<byte>, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> createKeys,
        KeyAgreementEncryptDelegate encrypt,
        AeadEncryptDelegate aeadEncrypt,
        KeyAgreementDecryptDelegate decrypt,
        AeadDecryptDelegate aeadDecrypt,
        string expectedCrv)
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(
            /*lang=json,strict*/ "{\"vp_token\":\"eyJhbGciOiJFUzI1NiJ9.test.sig\"}");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair = createKeys(Pool);
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
                encrypt,
                ConcatKdf.DefaultKeyDerivationDelegate,
                aeadEncrypt,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

        string compactJwe = encrypted.ToCompactJwe(TestSetup.Base64UrlEncoder);

        string headerEncoded = compactJwe.Split('.')[0];
        using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(headerEncoded, Pool);
        string headerJson = Encoding.UTF8.GetString(headerBytes.Memory.Span);
        Assert.Contains($"\"{WellKnownJwkMemberNames.Crv}\":\"{expectedCrv}\"",
            headerJson, StringComparison.Ordinal,
            $"EPK must carry crv={expectedCrv}.");

        using AeadMessage parsed = JweParsing.ParseCompact(
            compactJwe,
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            TestSetup.Base64UrlDecoder,
            Pool);

        using DecryptedContent decrypted = await parsed.DecryptAsync(
            privateKey,
            decrypt,
            ConcatKdf.DefaultKeyDerivationDelegate,
            aeadDecrypt,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(
            decrypted.AsReadOnlySpan().SequenceEqual(plaintext),
            $"NIST {expectedCrv} round-trip must produce the original plaintext.");
    }


    //Drives a full ECDH-ES JWE round-trip over one Brainpool curve (RFC 5639): the
    //wallet's exchange key encrypts, the wire form is reparsed (which runs the epk
    //point-on-curve validation through DefaultEpkCrvToTagConverter), and the recipient
    //decrypts. Asserts the recovered plaintext and that the emitted epk carried the
    //expected Brainpool crv name — proving DefaultTagToEpkCrvConverter wired the curve.
    private async Task BrainpoolRoundTripAsync(
        Func<MemoryPool<byte>, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> createKeys,
        KeyAgreementEncryptDelegate encrypt,
        KeyAgreementDecryptDelegate decrypt,
        string expectedCrv)
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(
            /*lang=json,strict*/ "{\"vp_token\":\"eyJhbGciOiJFUzI1NiJ9.test.sig\"}");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair = createKeys(Pool);
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
                encrypt,
                ConcatKdf.DefaultKeyDerivationDelegate,
                BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

        string compactJwe = encrypted.ToCompactJwe(TestSetup.Base64UrlEncoder);

        string headerEncoded = compactJwe.Split('.')[0];
        using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(headerEncoded, Pool);
        string headerJson = Encoding.UTF8.GetString(headerBytes.Memory.Span);
        Assert.Contains($"\"{WellKnownJwkMemberNames.Crv}\":\"{expectedCrv}\"",
            headerJson, StringComparison.Ordinal,
            $"EPK must carry crv={expectedCrv}.");

        using AeadMessage parsed = JweParsing.ParseCompact(
            compactJwe,
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            TestSetup.Base64UrlDecoder,
            Pool);

        using DecryptedContent decrypted = await parsed.DecryptAsync(
            privateKey,
            decrypt,
            ConcatKdf.DefaultKeyDerivationDelegate,
            BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(
            decrypted.AsReadOnlySpan().SequenceEqual(plaintext),
            $"Brainpool {expectedCrv} round-trip must produce the original plaintext.");
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
