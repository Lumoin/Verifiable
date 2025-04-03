using System.Buffers;
using System.Text;
using Verifiable.BouncyCastle;
using Verifiable.Core.Cryptography;

namespace Verifiable.Tests
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
            var keys = BouncyCastleKeyCreator.CreateEd25519Keys(MemoryPool<byte>.Shared);
            Assert.IsTrue(keys.PublicKey.AsReadOnlySpan().Length > 0);
            Assert.IsTrue(keys.PrivateKey.AsReadOnlySpan().Length > 0);
        }


        [TestMethod]
        public void CanSignAndVerifyEd255019()
        {
            var keys = BouncyCastleKeyCreator.CreateEd25519Keys(MemoryPool<byte>.Shared);
            var publicKey = keys.PublicKey;
            var privateKey = keys.PrivateKey;
            
            var data = (ReadOnlySpan<byte>)TestData;
            using var signature = privateKey.Sign(data, BouncyCastleAlgorithms.SignEd25519, MemoryPool<byte>.Shared);
            Assert.IsTrue(publicKey.Verify(data, signature, BouncyCastleAlgorithms.VerifyEd25519));
        }


        [TestMethod]
        public void CanCreateIdentifiedKeyAndVerify()
        {
            var keys = BouncyCastleKeyCreator.CreateEd25519Keys(MemoryPool<byte>.Shared);

            var publicKey = new PublicKey(keys.PublicKey, "Test-1", BouncyCastleAlgorithms.VerifyEd25519);
            var privateKey = new PrivateKey(keys.PrivateKey, "Test-1", BouncyCastleAlgorithms.SignEd25519);

            var data = (ReadOnlySpan<byte>)TestData;
            using var signature = privateKey.Sign(data, MemoryPool<byte>.Shared);
            Assert.IsTrue(publicKey.Verify(data, signature));
        }
    }
}
