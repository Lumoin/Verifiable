using Verifiable.BouncyCastle;
using Verifiable.Core.Cryptography;
using System;
using System.Buffers;
using System.Text;
using Xunit;

namespace Verifiable.Tests
{
    /// <summary>
    /// These test specifically BouncyCastle as the cryptographic provider.
    /// </summary>
    public class BouncyCastleCryptographicTests
    {
        /// <summary>
        /// Used in tests as test data.
        /// </summary>
        private byte[] TestData { get; } = Encoding.UTF8.GetBytes("This is a test string.");


        [Fact]
        public void CanGenerateKeyPairEd255019()
        {
            var keys = BouncyCastleKeyCreator.CreateEd25519Keys(MemoryPool<byte>.Shared);
            Assert.NotNull(keys.PublicKey);
            Assert.NotNull(keys.PrivateKey);
        }


        [Fact]
        public void CanSignAndVerifyEd255019()
        {
            var keys = BouncyCastleKeyCreator.CreateEd25519Keys(MemoryPool<byte>.Shared);
            var publicKey = keys.PublicKey;
            var privateKey = keys.PrivateKey;
            
            var data = (ReadOnlySpan<byte>)TestData;
            using var signature = privateKey.Sign(data, BouncyCastleAlgorithms.SignEd25519, MemoryPool<byte>.Shared);
            Assert.True(publicKey.Verify(data, signature, BouncyCastleAlgorithms.VerifyEd25519));
        }


        [Fact]
        public void CanCreateIdentifiedKeyAndVerify()
        {
            var keys = BouncyCastleKeyCreator.CreateEd25519Keys(MemoryPool<byte>.Shared);

            var publicKey = new PublicKey(keys.PublicKey, "Test-1", BouncyCastleAlgorithms.VerifyEd25519);
            var privateKey = new PrivateKey(keys.PrivateKey, "Test-1", BouncyCastleAlgorithms.SignEd25519);

            var data = (ReadOnlySpan<byte>)TestData;
            using var signature = privateKey.Sign(data, MemoryPool<byte>.Shared);
            Assert.True(publicKey.Verify(data, signature));
        }
    }
}
