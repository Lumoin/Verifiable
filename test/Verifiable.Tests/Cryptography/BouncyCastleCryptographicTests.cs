using System.Buffers;
using System.Text;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests BouncyCastle as the cryptographic provider across all supported algorithms,
    /// including classical (Ed25519, ECDSA, X25519, RSA) and post-quantum (ML-DSA, ML-KEM).
    /// </summary>
    [TestClass]
    internal sealed class BouncyCastleCryptographicTests
    {
        public TestContext TestContext { get; set; } = null!;

        private static byte[] TestData { get; } = Encoding.UTF8.GetBytes("BouncyCastle cryptographic test payload.");


        [TestMethod]
        public void Ed25519KeyPairHasNonEmptyMaterial()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateEd25519Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.IsGreaterThan(0, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public async Task Ed25519SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateEd25519Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctions.SignEd25519Async, BouncyCastleCryptographicFunctions.VerifyEd25519Async).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task P256SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateP256Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctions.SignP256Async, BouncyCastleCryptographicFunctions.VerifyP256Async).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task P384SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateP384Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctions.SignP384Async, BouncyCastleCryptographicFunctions.VerifyP384Async).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task P521SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateP521Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctions.SignP521Async, BouncyCastleCryptographicFunctions.VerifyP521Async).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task Secp256k1SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateSecp256k1Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctions.SignSecp256k1Async, BouncyCastleCryptographicFunctions.VerifySecp256k1Async).ConfigureAwait(false);
        }


        [TestMethod]
        public void X25519KeyPairHasNonEmptyMaterial()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateX25519Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.IsGreaterThan(0, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public async Task X25519SharedSecretDerivationIsSymmetric()
        {
            var aliceKeys = BouncyCastleKeyMaterialCreator.CreateX25519Keys(SensitiveMemoryPool<byte>.Shared);
            using var alicePub = aliceKeys.PublicKey;
            using var alicePriv = aliceKeys.PrivateKey;

            var bobKeys = BouncyCastleKeyMaterialCreator.CreateX25519Keys(SensitiveMemoryPool<byte>.Shared);
            using var bobPub = bobKeys.PublicKey;
            using var bobPriv = bobKeys.PrivateKey;

            using var aliceSecret = await BouncyCastleCryptographicFunctions.DeriveX25519SharedSecretAsync(
                alicePriv.AsReadOnlyMemory(), bobPub.AsReadOnlyMemory(), SensitiveMemoryPool<byte>.Shared).ConfigureAwait(false);
            using var bobSecret = await BouncyCastleCryptographicFunctions.DeriveX25519SharedSecretAsync(
                bobPriv.AsReadOnlyMemory(), alicePub.AsReadOnlyMemory(), SensitiveMemoryPool<byte>.Shared).ConfigureAwait(false);

            Assert.IsTrue(aliceSecret.Memory.Span.SequenceEqual(bobSecret.Memory.Span));
        }


        [TestMethod]
        public async Task Rsa2048SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateRsa2048Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctions.SignRsa2048Async, BouncyCastleCryptographicFunctions.VerifyRsa2048Async).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task Rsa4096SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateRsa4096Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctions.SignRsa4096Async, BouncyCastleCryptographicFunctions.VerifyRsa4096Async).ConfigureAwait(false);
        }


        [TestMethod]
        public void MlDsa44KeyPairHasCorrectPublicKeySize()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateMlDsa44Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.AreEqual(1312, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public async Task MlDsa44SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateMlDsa44Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctions.SignMlDsa44Async, BouncyCastleCryptographicFunctions.VerifyMlDsa44Async).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task MlDsa44TamperedSignatureFailsVerification()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateMlDsa44Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertTamperedSignatureFailsAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctions.SignMlDsa44Async, BouncyCastleCryptographicFunctions.VerifyMlDsa44Async).ConfigureAwait(false);
        }


        [TestMethod]
        public void MlDsa65KeyPairHasCorrectPublicKeySize()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateMlDsa65Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.AreEqual(1952, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public async Task MlDsa65SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateMlDsa65Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctions.SignMlDsa65Async, BouncyCastleCryptographicFunctions.VerifyMlDsa65Async).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task MlDsa65WrongKeyDoesNotVerify()
        {
            var aliceKeys = BouncyCastleKeyMaterialCreator.CreateMlDsa65Keys(SensitiveMemoryPool<byte>.Shared);
            using var alicePublicKey = aliceKeys.PublicKey;
            using var alicePrivateKey = aliceKeys.PrivateKey;

            var bobKeys = BouncyCastleKeyMaterialCreator.CreateMlDsa65Keys(SensitiveMemoryPool<byte>.Shared);
            using var bobPublicKey = bobKeys.PublicKey;
            using var bobPrivateKey = bobKeys.PrivateKey;

            ReadOnlyMemory<byte> data = TestData;
            using var signature = await BouncyCastleCryptographicFunctions.SignMlDsa65Async(
                alicePrivateKey.AsReadOnlyMemory(), data, SensitiveMemoryPool<byte>.Shared,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            bool isValid = await BouncyCastleCryptographicFunctions.VerifyMlDsa65Async(
                data, signature.AsReadOnlyMemory(), bobPublicKey.AsReadOnlyMemory(),
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(isValid);
        }


        [TestMethod]
        public void MlDsa87KeyPairHasCorrectPublicKeySize()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateMlDsa87Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.AreEqual(2592, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public async Task MlDsa87SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateMlDsa87Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctions.SignMlDsa87Async, BouncyCastleCryptographicFunctions.VerifyMlDsa87Async).ConfigureAwait(false);
        }


        [TestMethod]
        public void MlKem512KeyPairHasCorrectPublicKeySize()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateMlKem512Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.AreEqual(800, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public void MlKem512EncapsulateDecapsulateProducesSameSecret()
        {
            AssertMlKemRoundTrip(
                BouncyCastleKeyMaterialCreator.CreateMlKem512Keys,
                BouncyCastleCryptographicFunctions.EncapsulateMlKem512,
                BouncyCastleCryptographicFunctions.DecapsulateMlKem512);
        }


        [TestMethod]
        public void MlKem768KeyPairHasCorrectPublicKeySize()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateMlKem768Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.AreEqual(1184, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public void MlKem768EncapsulateDecapsulateProducesSameSecret()
        {
            AssertMlKemRoundTrip(
                BouncyCastleKeyMaterialCreator.CreateMlKem768Keys,
                BouncyCastleCryptographicFunctions.EncapsulateMlKem768,
                BouncyCastleCryptographicFunctions.DecapsulateMlKem768);
        }


        [TestMethod]
        public void MlKem768DifferentKeysProduceDifferentSecrets()
        {
            var aliceKeys = BouncyCastleKeyMaterialCreator.CreateMlKem768Keys(SensitiveMemoryPool<byte>.Shared);
            using var alicePublicKey = aliceKeys.PublicKey;
            using var alicePrivateKey = aliceKeys.PrivateKey;

            var bobKeys = BouncyCastleKeyMaterialCreator.CreateMlKem768Keys(SensitiveMemoryPool<byte>.Shared);
            using var bobPublicKey = bobKeys.PublicKey;
            using var bobPrivateKey = bobKeys.PrivateKey;

            var (ciphertext, senderSecret) = BouncyCastleCryptographicFunctions.EncapsulateMlKem768(
                alicePublicKey.AsReadOnlyMemory(), SensitiveMemoryPool<byte>.Shared);
            using var ct = ciphertext;
            using var ss = senderSecret;

            using var wrongSecret = BouncyCastleCryptographicFunctions.DecapsulateMlKem768(
                bobPrivateKey.AsReadOnlyMemory(), ct.Memory, SensitiveMemoryPool<byte>.Shared);

            Assert.IsFalse(ss.Memory.Span.SequenceEqual(wrongSecret.Memory.Span));
        }


        [TestMethod]
        public void MlKem1024KeyPairHasCorrectPublicKeySize()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateMlKem1024Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.AreEqual(1568, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public void MlKem1024EncapsulateDecapsulateProducesSameSecret()
        {
            AssertMlKemRoundTrip(
                BouncyCastleKeyMaterialCreator.CreateMlKem1024Keys,
                BouncyCastleCryptographicFunctions.EncapsulateMlKem1024,
                BouncyCastleCryptographicFunctions.DecapsulateMlKem1024);
        }


        private async Task AssertSignAndVerifyAsync(
            PrivateKeyMemory privateKey,
            PublicKeyMemory publicKey,
            SigningDelegate sign,
            VerificationDelegate verify)
        {
            ReadOnlyMemory<byte> data = TestData;
            using var signature = await sign(privateKey.AsReadOnlyMemory(), data, SensitiveMemoryPool<byte>.Shared,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsGreaterThan(0, signature.AsReadOnlyMemory().Length);

            bool isValid = await verify(data, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory(),
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(isValid);
        }


        private async Task AssertTamperedSignatureFailsAsync(
            PrivateKeyMemory privateKey,
            PublicKeyMemory publicKey,
            SigningDelegate sign,
            VerificationDelegate verify)
        {
            ReadOnlyMemory<byte> data = TestData;
            using var signature = await sign(privateKey.AsReadOnlyMemory(), data, SensitiveMemoryPool<byte>.Shared,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            byte[] tamperedBytes = signature.AsReadOnlyMemory().ToArray();
            tamperedBytes[0] ^= 0xFF;
            tamperedBytes[tamperedBytes.Length - 1] ^= 0xFF;

            bool isValid = await verify(data, tamperedBytes, publicKey.AsReadOnlyMemory(),
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(isValid);
        }


        private static void AssertMlKemRoundTrip(
            Func<MemoryPool<byte>, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> createKeys,
            Func<ReadOnlyMemory<byte>, MemoryPool<byte>, (IMemoryOwner<byte> Ciphertext, IMemoryOwner<byte> SharedSecret)> encapsulate,
            Func<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>, MemoryPool<byte>, IMemoryOwner<byte>> decapsulate)
        {
            var keys = createKeys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            var (ciphertext, senderSecret) = encapsulate(publicKey.AsReadOnlyMemory(), SensitiveMemoryPool<byte>.Shared);
            using var ct = ciphertext;
            using var ss = senderSecret;

            using var receiverSecret = decapsulate(privateKey.AsReadOnlyMemory(), ct.Memory, SensitiveMemoryPool<byte>.Shared);

            Assert.AreEqual(32, ss.Memory.Length);
            Assert.AreEqual(32, receiverSecret.Memory.Length);
            Assert.IsTrue(ss.Memory.Span.SequenceEqual(receiverSecret.Memory.Span));
        }
    }
}