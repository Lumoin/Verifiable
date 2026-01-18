using System.Buffers;
using System.Text;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// These test specifically BouncyCastle as the cryptographic provider.
    /// </summary>
    [TestClass]
    public sealed class BouncyCastleCryptographicTests
    {
        /// <summary>
        /// Used in tests as test data.
        /// </summary>
        private byte[] TestData { get; } = Encoding.UTF8.GetBytes("This is a test string.");


        [TestMethod]
        public void CanGenerateKeyPairEd255019()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateEd25519Keys(MemoryPool<byte>.Shared);
            Assert.IsGreaterThan(0, keys.PublicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, keys.PrivateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public async ValueTask CanSignAndVerifyEd255019()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateEd25519Keys(MemoryPool<byte>.Shared);
            var publicKey = keys.PublicKey;
            var privateKey = keys.PrivateKey;

            var data = (ReadOnlyMemory<byte>)TestData;
            using var signature = await privateKey.SignAsync(data, BouncyCastleCryptographicFunctions.SignEd25519Async, MemoryPool<byte>.Shared);
            Assert.IsTrue(await publicKey.VerifyAsync(data, signature, BouncyCastleCryptographicFunctions.VerifyEd25519Async));
        }


        [TestMethod]
        public async ValueTask CanCreateIdentifiedKeyAndVerify()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateEd25519Keys(MemoryPool<byte>.Shared);

            var publicKey = new PublicKey(keys.PublicKey, "Test-1", BouncyCastleCryptographicFunctions.VerifyEd25519Async);
            var privateKey = new PrivateKey(keys.PrivateKey, "Test-1", BouncyCastleCryptographicFunctions.SignEd25519Async);

            var data = (ReadOnlyMemory<byte>)TestData;
            using var signature = await privateKey.SignAsync(data, MemoryPool<byte>.Shared);
            Assert.IsTrue(await publicKey.VerifyAsync(data, signature));
        }
    }
}
