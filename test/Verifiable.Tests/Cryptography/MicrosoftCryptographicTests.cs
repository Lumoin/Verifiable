using System.Text;
using Verifiable.Cryptography;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests Microsoft as the cryptographic provider across all supported algorithms.
    /// </summary>
    [TestClass]
    internal sealed class MicrosoftCryptographicTests
    {
        public TestContext TestContext { get; set; } = null!;

        /// <summary>
        /// Shared test payload used for all sign-and-verify tests.
        /// </summary>
        private static byte[] TestData { get; } = Encoding.UTF8.GetBytes("Hello, did:key signature!");


        [TestMethod]
        public void P256KeyPairHasNonEmptyMaterial()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateP256Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.IsGreaterThan(0, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public async Task P256SignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateP256Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            using var signature = await MicrosoftCryptographicFunctions
                .SignP256Async(privateKey.AsReadOnlyMemory(), TestData, SensitiveMemoryPool<byte>.Shared)
                .ConfigureAwait(false);

            bool isVerified = await MicrosoftCryptographicFunctions
                .VerifyP256Async(TestData, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory())
                .ConfigureAwait(false);

            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async Task P256IdentifiedKeySignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateP256Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = new PublicKey(keys.PublicKey, "p256-test", MicrosoftCryptographicFunctions.VerifyP256Async);
            using var privateKey = new PrivateKey(keys.PrivateKey, "p256-test", MicrosoftCryptographicFunctions.SignP256Async);

            ReadOnlyMemory<byte> data = TestData;
            using var signature = await privateKey.SignAsync(data, SensitiveMemoryPool<byte>.Shared).ConfigureAwait(false);

            Assert.IsTrue(await publicKey.VerifyAsync(data, signature).ConfigureAwait(false));
        }


        [TestMethod]
        public void P384KeyPairHasNonEmptyMaterial()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateP384Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.IsGreaterThan(0, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public async Task P384SignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateP384Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            using var signature = await MicrosoftCryptographicFunctions
                .SignP384Async(privateKey.AsReadOnlyMemory(), TestData, SensitiveMemoryPool<byte>.Shared)
                .ConfigureAwait(false);

            bool isVerified = await MicrosoftCryptographicFunctions
                .VerifyP384Async(TestData, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory())
                .ConfigureAwait(false);

            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public void P521KeyPairHasNonEmptyMaterial()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateP521Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.IsGreaterThan(0, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public async Task P521SignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateP521Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            using var signature = await MicrosoftCryptographicFunctions
                .SignP521Async(privateKey.AsReadOnlyMemory(), TestData, SensitiveMemoryPool<byte>.Shared)
                .ConfigureAwait(false);

            bool isVerified = await MicrosoftCryptographicFunctions
                .VerifyP521Async(TestData, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory())
                .ConfigureAwait(false);

            Assert.IsTrue(isVerified);
        }


        [SkipOnMacOSTestMethod]
        public void Secp256k1KeyPairHasNonEmptyMaterial()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateSecp256k1Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.IsGreaterThan(0, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [SkipOnMacOSTestMethod]
        public async Task Secp256k1SignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateSecp256k1Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            using var signature = await MicrosoftCryptographicFunctions
                .SignSecp256k1Async(privateKey.AsReadOnlyMemory(), TestData, SensitiveMemoryPool<byte>.Shared)
                .ConfigureAwait(false);

            bool isVerified = await MicrosoftCryptographicFunctions
                .VerifySecp256k1Async(TestData, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory())
                .ConfigureAwait(false);

            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public void Rsa2048KeyPairHasNonEmptyMaterial()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.IsGreaterThan(0, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public async Task Rsa2048SignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            using var signature = await MicrosoftCryptographicFunctions
                .SignRsa2048Async(privateKey.AsReadOnlyMemory(), TestData, SensitiveMemoryPool<byte>.Shared)
                .ConfigureAwait(false);

            bool isVerified = await MicrosoftCryptographicFunctions
                .VerifyRsa2048Async(TestData, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory())
                .ConfigureAwait(false);

            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public void Rsa4096KeyPairHasNonEmptyMaterial()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa4096Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.IsGreaterThan(0, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public async Task Rsa4096SignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa4096Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            using var signature = await MicrosoftCryptographicFunctions
                .SignRsa4096Async(privateKey.AsReadOnlyMemory(), TestData, SensitiveMemoryPool<byte>.Shared)
                .ConfigureAwait(false);

            bool isVerified = await MicrosoftCryptographicFunctions
                .VerifyRsa4096Async(TestData, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory())
                .ConfigureAwait(false);

            Assert.IsTrue(isVerified);
        }
    }
}