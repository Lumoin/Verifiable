using System.Text;
using Verifiable.Cryptography;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests Microsoft CNG as the cryptographic provider across all supported algorithms,
    /// including ECDSA (P-256, P-384, P-521, secp256k1) and RSA with multiple hash/padding combinations.
    /// </summary>
    [TestClass]
    internal sealed class MicrosoftCryptographicTests
    {
        public TestContext TestContext { get; set; } = null!;

        private static byte[] TestData { get; } = Encoding.UTF8.GetBytes("Microsoft cryptographic test payload.");


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

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctions.SignP256Async, MicrosoftCryptographicFunctions.VerifyP256Async).ConfigureAwait(false);
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

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctions.SignP384Async, MicrosoftCryptographicFunctions.VerifyP384Async).ConfigureAwait(false);
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

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctions.SignP521Async, MicrosoftCryptographicFunctions.VerifyP521Async).ConfigureAwait(false);
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

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctions.SignSecp256k1Async, MicrosoftCryptographicFunctions.VerifySecp256k1Async).ConfigureAwait(false);
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

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctions.SignRsa2048Async, MicrosoftCryptographicFunctions.VerifyRsa2048Async).ConfigureAwait(false);
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

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctions.SignRsa4096Async, MicrosoftCryptographicFunctions.VerifyRsa4096Async).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task RsaSha256Pkcs1SignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctions.SignRsaSha256Pkcs1Async, MicrosoftCryptographicFunctions.VerifyRsaSha256Pkcs1Async).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task RsaSha256PssSignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctions.SignRsaSha256PssAsync, MicrosoftCryptographicFunctions.VerifyRsaSha256PssAsync).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task RsaSha384Pkcs1SignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctions.SignRsaSha384Pkcs1Async, MicrosoftCryptographicFunctions.VerifyRsaSha384Pkcs1Async).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task RsaSha384PssSignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctions.SignRsaSha384PssAsync, MicrosoftCryptographicFunctions.VerifyRsaSha384PssAsync).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task RsaSha512Pkcs1SignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa4096Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctions.SignRsaSha512Pkcs1Async, MicrosoftCryptographicFunctions.VerifyRsaSha512Pkcs1Async).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task RsaSha512PssSignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa4096Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctions.SignRsaSha512PssAsync, MicrosoftCryptographicFunctions.VerifyRsaSha512PssAsync).ConfigureAwait(false);
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
    }
}