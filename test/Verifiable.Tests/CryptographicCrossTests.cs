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
        public async ValueTask BouncyGeneratedKeysUsedByNSecOnEd25519()
        {            
            var keys = BouncyCastleKeyCreator.CreateEd25519Keys(SensitiveMemoryPool<byte>.Shared);
            var publicKey = keys.PublicKey;
            var privateKey = keys.PrivateKey;

            var data = new ReadOnlyMemory<byte>(TestData);
            using var signature = await privateKey.SignAsync(data, NSecAlgorithms.SignEd25519Async, SensitiveMemoryPool<byte>.Shared);
            Assert.IsTrue(await publicKey.VerifyAsync(data, signature, NSecAlgorithms.VerifyEd25519));
        }


        [TestMethod]
        public async ValueTask NSecGeneratedKeysUsedByBouncyOnEd25519()
        {            
            var keys = NSecKeyCreator.CreateEd25519Keys(SensitiveMemoryPool<byte>.Shared);
            var publicKey = keys.PublicKey;
            var privateKey = keys.PrivateKey;

            var data = (ReadOnlyMemory<byte>)TestData;
            using var signature = await privateKey.SignAsync(data, BouncyCastleAlgorithms.SignEd25519Async, SensitiveMemoryPool<byte>.Shared);
            Assert.IsTrue(await publicKey.VerifyAsync(data, signature, BouncyCastleAlgorithms.VerifyEd25519Async));
        }


        [TestMethod]
        public async ValueTask NSecGeneratedSignatureVerifiedByBouncyOnEd25519()
        {
            var keys = NSecKeyCreator.CreateEd25519Keys(SensitiveMemoryPool<byte>.Shared);
            var publicKey = keys.PublicKey;
            var privateKey = keys.PrivateKey;

            var data = new ReadOnlyMemory<byte>(TestData);
            using var signature = await privateKey.SignAsync(data, NSecAlgorithms.SignEd25519Async, MemoryPool<byte>.Shared);
            Assert.IsTrue(await publicKey.VerifyAsync(data, signature, BouncyCastleAlgorithms.VerifyEd25519Async));
        }


        [TestMethod]
        public async ValueTask BouncyGeneratedSignatureVerifiedByBouncyOnEd25519()
        {
            var keys = BouncyCastleKeyCreator.CreateEd25519Keys(SensitiveMemoryPool<byte>.Shared);            
            var publicKey = keys.PublicKey;
            var privateKey = keys.PrivateKey;

            var data = (ReadOnlyMemory<byte>)TestData;
            using var signature = await privateKey.SignAsync(data, BouncyCastleAlgorithms.SignEd25519Async, SensitiveMemoryPool<byte>.Shared);
            Assert.IsTrue(await publicKey.VerifyAsync(data, signature, NSecAlgorithms.VerifyEd25519));
        }
    }
}
