using System.Buffers;
using System.Text;
using Verifiable.BouncyCastle;
using Verifiable.Core.Cryptography;
using Verifiable.NSec;

namespace Verifiable.Tests.Core
{
    //TODO: Automate the combinations in testing.

    /// <summary>
    /// Test cases for cross-checking library implementations.
    /// </summary>
    [TestClass]
    public sealed class CryptographicCrossTests
    {
        /// <summary>
        /// Used in tests.
        /// </summary>
        public byte[] TestData = Encoding.UTF8.GetBytes("This is a test string.");


        [TestMethod]
        public void BouncyGeneratedKeysUsedByNSecOnEd25519()
        {            
            var keys = BouncyCastleKeyCreator.CreateEd25519Keys(ExactSizeMemoryPool<byte>.Shared);
            var publicKey = keys.PublicKey;
            var privateKey = keys.PrivateKey;

            var data = (ReadOnlySpan<byte>)TestData;
            using var signature = privateKey.Sign(data, NSecAlgorithms.SignEd25519, ExactSizeMemoryPool<byte>.Shared);
            Assert.IsTrue(publicKey.Verify(data, signature, NSecAlgorithms.VerifyEd25519));
        }


        [TestMethod]
        public void NSecGeneratedKeysUsedByBouncyOnEd25519()
        {            
            var keys = NSecKeyCreator.CreateEd25519Keys(ExactSizeMemoryPool<byte>.Shared);
            var publicKey = keys.PublicKey;
            var privateKey = keys.PrivateKey;

            var data = (ReadOnlySpan<byte>)TestData;
            using var signature = privateKey.Sign(data, BouncyCastleAlgorithms.SignEd25519, ExactSizeMemoryPool<byte>.Shared);
            Assert.IsTrue(publicKey.Verify(data, signature, BouncyCastleAlgorithms.VerifyEd25519));
        }


        [TestMethod]
        public void NSecGeneratedSignatureVerifiedByBouncyOnEd25519()
        {
            var keys = NSecKeyCreator.CreateEd25519Keys(ExactSizeMemoryPool<byte>.Shared);
            var publicKey = keys.PublicKey;
            var privateKey = keys.PrivateKey;

            var data = (ReadOnlySpan<byte>)TestData;
            using var signature = privateKey.Sign(data, NSecAlgorithms.SignEd25519, MemoryPool<byte>.Shared);
            Assert.IsTrue(publicKey.Verify(data, signature, BouncyCastleAlgorithms.VerifyEd25519));
        }


        [TestMethod]
        public void BouncyGeneratedSignatureVerifiedByBouncyOnEd25519()
        {
            var keys = BouncyCastleKeyCreator.CreateEd25519Keys(ExactSizeMemoryPool<byte>.Shared);            
            var publicKey = keys.PublicKey;
            var privateKey = keys.PrivateKey;

            var data = (ReadOnlySpan<byte>)TestData;
            using var signature = privateKey.Sign(data, BouncyCastleAlgorithms.SignEd25519, ExactSizeMemoryPool<byte>.Shared);
            Assert.IsTrue(publicKey.Verify(data, signature, NSecAlgorithms.VerifyEd25519));
        }
    }
}
