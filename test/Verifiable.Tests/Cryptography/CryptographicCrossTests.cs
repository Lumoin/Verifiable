using System.Text;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.NSec;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Cross-library verification tests ensuring keys and signatures are interoperable
    /// between BouncyCastle and NSec backends.
    /// </summary>
    [TestClass]
    internal sealed class CryptographicCrossTests
    {
        public TestContext TestContext { get; set; } = null!;

        private static byte[] TestData { get; } = Encoding.UTF8.GetBytes("Cross-library interoperability test payload.");


        [TestMethod]
        public async Task BouncyCastleKeysVerifiedByNSecOnEd25519()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateEd25519Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            ReadOnlyMemory<byte> data = TestData;
            using var signature = await NSecCryptographicFunctions.SignEd25519Async(
                privateKey.AsReadOnlyMemory(), data, SensitiveMemoryPool<byte>.Shared,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(await NSecCryptographicFunctions.VerifyEd25519Async(
                data, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory(),
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false));
        }


        [TestMethod]
        public async Task NSecKeysVerifiedByBouncyCastleOnEd25519()
        {
            var keys = NSecKeyMaterialCreator.CreateEd25519Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            ReadOnlyMemory<byte> data = TestData;
            using var signature = await BouncyCastleCryptographicFunctions.SignEd25519Async(
                privateKey.AsReadOnlyMemory(), data, SensitiveMemoryPool<byte>.Shared,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(await BouncyCastleCryptographicFunctions.VerifyEd25519Async(
                data, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory(),
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false));
        }


        [TestMethod]
        public async Task NSecSignedVerifiedByBouncyCastleOnEd25519()
        {
            var keys = NSecKeyMaterialCreator.CreateEd25519Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            ReadOnlyMemory<byte> data = TestData;
            using var signature = await NSecCryptographicFunctions.SignEd25519Async(
                privateKey.AsReadOnlyMemory(), data, SensitiveMemoryPool<byte>.Shared,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(await BouncyCastleCryptographicFunctions.VerifyEd25519Async(
                data, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory(),
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false));
        }


        [TestMethod]
        public async Task BouncyCastleSignedVerifiedByNSecOnEd25519()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateEd25519Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            ReadOnlyMemory<byte> data = TestData;
            using var signature = await BouncyCastleCryptographicFunctions.SignEd25519Async(
                privateKey.AsReadOnlyMemory(), data, SensitiveMemoryPool<byte>.Shared,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(await NSecCryptographicFunctions.VerifyEd25519Async(
                data, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory(),
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false));
        }
    }
}