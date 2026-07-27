using System.Text;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Libsodium;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Cross-library verification tests ensuring keys and signatures are interoperable
    /// between BouncyCastle and libsodium backends.
    /// </summary>
    [TestClass]
    internal sealed class CryptographicCrossTests
    {
        public TestContext TestContext { get; set; } = null!;

        private static byte[] TestData { get; } = Encoding.UTF8.GetBytes("Cross-library interoperability test payload.");


        [TestMethod]
        public async Task BouncyCastleKeysVerifiedByLibsodiumOnEd25519()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            ReadOnlyMemory<byte> data = TestData;
            (Signature signature, CryptoEvent? _) = await LibsodiumCryptographicFunctions.SignEd25519Async(
                privateKey.AsReadOnlyMemory(), data, BaseMemoryPool.Shared,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            using var disposableSignature = signature;

            (bool isVerified, CryptoEvent? _) = await LibsodiumCryptographicFunctions.VerifyEd25519Async(
                data, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory(),
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async Task LibsodiumKeysVerifiedByBouncyCastleOnEd25519()
        {
            var keys = LibsodiumKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            ReadOnlyMemory<byte> data = TestData;
            (Signature signature, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.SignEd25519Async(
                privateKey.AsReadOnlyMemory(), data, BaseMemoryPool.Shared,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            using var disposableSignature = signature;

            (bool isVerified, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.VerifyEd25519Async(
                data, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory(),
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async Task LibsodiumSignedVerifiedByBouncyCastleOnEd25519()
        {
            var keys = LibsodiumKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            ReadOnlyMemory<byte> data = TestData;
            (Signature signature, CryptoEvent? _) = await LibsodiumCryptographicFunctions.SignEd25519Async(
                privateKey.AsReadOnlyMemory(), data, BaseMemoryPool.Shared,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            using var disposableSignature = signature;

            (bool isVerified, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.VerifyEd25519Async(
                data, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory(),
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async Task BouncyCastleSignedVerifiedByLibsodiumOnEd25519()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            ReadOnlyMemory<byte> data = TestData;
            (Signature signature, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.SignEd25519Async(
                privateKey.AsReadOnlyMemory(), data, BaseMemoryPool.Shared,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            using var disposableSignature = signature;

            (bool isVerified, CryptoEvent? _) = await LibsodiumCryptographicFunctions.VerifyEd25519Async(
                data, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory(),
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(isVerified);
        }
    }
}
