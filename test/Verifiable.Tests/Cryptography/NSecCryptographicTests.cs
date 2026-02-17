using System.Text;
using Verifiable.Cryptography;
using Verifiable.NSec;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests NSec as the cryptographic provider across all supported algorithms.
    /// </summary>
    [TestClass]
    internal sealed class NSecCryptographicTests
    {
        public TestContext TestContext { get; set; } = null!;

        /// <summary>
        /// Shared test payload used for all sign-and-verify tests.
        /// </summary>
        private static byte[] TestData { get; } = Encoding.UTF8.GetBytes("NSec cryptographic test payload.");


        [TestMethod]
        public void Ed25519KeyPairHasNonEmptyMaterial()
        {
            var keys = NSecKeyMaterialCreator.CreateEd25519Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.IsGreaterThan(0, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public async Task Ed25519SignatureVerifies()
        {
            var keys = NSecKeyMaterialCreator.CreateEd25519Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            ReadOnlyMemory<byte> data = TestData;
            using var signature = await privateKey.SignAsync(data, NSecCryptographicFunctions.SignEd25519Async, SensitiveMemoryPool<byte>.Shared)
                .ConfigureAwait(false);

            Assert.IsTrue(await publicKey.VerifyAsync(data, signature, NSecCryptographicFunctions.VerifyEd25519Async)
                .ConfigureAwait(false));
        }


        [TestMethod]
        public async Task Ed25519IdentifiedKeySignatureVerifies()
        {
            var keys = NSecKeyMaterialCreator.CreateEd25519Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = new PublicKey(keys.PublicKey, "ed25519-test", NSecCryptographicFunctions.VerifyEd25519Async);
            using var privateKey = new PrivateKey(keys.PrivateKey, "ed25519-test", NSecCryptographicFunctions.SignEd25519Async);

            ReadOnlyMemory<byte> data = TestData;
            using var signature = await privateKey.SignAsync(data, SensitiveMemoryPool<byte>.Shared).ConfigureAwait(false);

            Assert.IsTrue(await publicKey.VerifyAsync(data, signature).ConfigureAwait(false));
        }


        [TestMethod]
        public void X25519KeyPairHasNonEmptyMaterial()
        {
            var keys = NSecKeyMaterialCreator.CreateX25519Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.IsGreaterThan(0, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }
    }
}