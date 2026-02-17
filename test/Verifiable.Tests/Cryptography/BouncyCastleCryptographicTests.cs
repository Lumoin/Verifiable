using System.Text;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests BouncyCastle as the cryptographic provider across all supported algorithms.
    /// </summary>
    [TestClass]
    internal sealed class BouncyCastleCryptographicTests
    {
        public TestContext TestContext { get; set; } = null!;

        /// <summary>
        /// Shared test payload used for all sign-and-verify tests.
        /// </summary>
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

            ReadOnlyMemory<byte> data = TestData;
            using var signature = await BouncyCastleCryptographicFunctions
                .SignEd25519Async(privateKey.AsReadOnlyMemory(), data, SensitiveMemoryPool<byte>.Shared)
                .ConfigureAwait(false);

            bool isVerified = await BouncyCastleCryptographicFunctions
                .VerifyEd25519Async(data, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory())
                .ConfigureAwait(false);

            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async Task Ed25519IdentifiedKeySignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateEd25519Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = new PublicKey(keys.PublicKey, "ed25519-test", BouncyCastleCryptographicFunctions.VerifyEd25519Async);
            using var privateKey = new PrivateKey(keys.PrivateKey, "ed25519-test", BouncyCastleCryptographicFunctions.SignEd25519Async);

            ReadOnlyMemory<byte> data = TestData;
            using var signature = await privateKey.SignAsync(data, SensitiveMemoryPool<byte>.Shared).ConfigureAwait(false);

            Assert.IsTrue(await publicKey.VerifyAsync(data, signature).ConfigureAwait(false));
        }


        [TestMethod]
        public async Task P256SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateP256Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            ReadOnlyMemory<byte> data = TestData;
            using var signature = await BouncyCastleCryptographicFunctions
                .SignP256Async(privateKey.AsReadOnlyMemory(), data, SensitiveMemoryPool<byte>.Shared)
                .ConfigureAwait(false);

            bool isVerified = await BouncyCastleCryptographicFunctions
                .VerifyP256Async(data, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory())
                .ConfigureAwait(false);

            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async Task P384SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateP384Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            ReadOnlyMemory<byte> data = TestData;
            using var signature = await BouncyCastleCryptographicFunctions
                .SignP384Async(privateKey.AsReadOnlyMemory(), data, SensitiveMemoryPool<byte>.Shared)
                .ConfigureAwait(false);

            bool isVerified = await BouncyCastleCryptographicFunctions
                .VerifyP384Async(data, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory())
                .ConfigureAwait(false);

            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async Task P521SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateP521Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            ReadOnlyMemory<byte> data = TestData;
            using var signature = await BouncyCastleCryptographicFunctions
                .SignP521Async(privateKey.AsReadOnlyMemory(), data, SensitiveMemoryPool<byte>.Shared)
                .ConfigureAwait(false);

            bool isVerified = await BouncyCastleCryptographicFunctions
                .VerifyP521Async(data, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory())
                .ConfigureAwait(false);

            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async Task Secp256k1SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateSecp256k1Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            ReadOnlyMemory<byte> data = TestData;
            using var signature = await BouncyCastleCryptographicFunctions
                .SignSecp256k1Async(privateKey.AsReadOnlyMemory(), data, SensitiveMemoryPool<byte>.Shared)
                .ConfigureAwait(false);

            bool isVerified = await BouncyCastleCryptographicFunctions
                .VerifySecp256k1Async(data, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory())
                .ConfigureAwait(false);

            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async Task Rsa2048SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateRsa2048Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            ReadOnlyMemory<byte> data = TestData;
            using var signature = await BouncyCastleCryptographicFunctions
                .SignRsa2048Async(privateKey.AsReadOnlyMemory(), data, SensitiveMemoryPool<byte>.Shared)
                .ConfigureAwait(false);

            bool isVerified = await BouncyCastleCryptographicFunctions
                .VerifyRsa2048Async(data, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory())
                .ConfigureAwait(false);

            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async Task Rsa4096SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateRsa4096Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            ReadOnlyMemory<byte> data = TestData;
            using var signature = await BouncyCastleCryptographicFunctions
                .SignRsa4096Async(privateKey.AsReadOnlyMemory(), data, SensitiveMemoryPool<byte>.Shared)
                .ConfigureAwait(false);

            bool isVerified = await BouncyCastleCryptographicFunctions
                .VerifyRsa4096Async(data, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory())
                .ConfigureAwait(false);

            Assert.IsTrue(isVerified);
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
        public async Task X25519SharedSecretDerivationProducesSameResultForBothParties()
        {
            var aliceKeys = BouncyCastleKeyMaterialCreator.CreateX25519Keys(SensitiveMemoryPool<byte>.Shared);
            using var alicePublicKey = aliceKeys.PublicKey;
            using var alicePrivateKey = aliceKeys.PrivateKey;

            var bobKeys = BouncyCastleKeyMaterialCreator.CreateX25519Keys(SensitiveMemoryPool<byte>.Shared);
            using var bobPublicKey = bobKeys.PublicKey;
            using var bobPrivateKey = bobKeys.PrivateKey;

            using var aliceSecret = await BouncyCastleCryptographicFunctions
                .DeriveX25519SharedSecretAsync(alicePrivateKey.AsReadOnlyMemory(), bobPublicKey.AsReadOnlyMemory(), SensitiveMemoryPool<byte>.Shared)
                .ConfigureAwait(false);

            using var bobSecret = await BouncyCastleCryptographicFunctions
                .DeriveX25519SharedSecretAsync(bobPrivateKey.AsReadOnlyMemory(), alicePublicKey.AsReadOnlyMemory(), SensitiveMemoryPool<byte>.Shared)
                .ConfigureAwait(false);

            Assert.IsTrue(aliceSecret.Memory.Span.SequenceEqual(bobSecret.Memory.Span));
        }
    }
}