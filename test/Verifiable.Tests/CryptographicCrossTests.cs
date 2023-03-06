using Verifiable.BouncyCastle;
using Verifiable.Core.Cryptography;
using Verifiable.NSec;
using System;
using System.Buffers;
using System.Text;
using Xunit;

namespace Verifiable.Core
{
    //TODO: Automate the combinations in testing.

    /// <summary>
    /// Test cases for cross-checking library implementations.
    /// </summary>
    public class CryptographicCrossTests
    {
        /// <summary>
        /// Used in tests.
        /// </summary>
        public byte[] TestData = Encoding.UTF8.GetBytes("This is a test string.");


        [Fact]
        public void BouncyGeneratedKeysUsedByNSecOnEd25519()
        {            
            var keys = BouncyCastleKeyCreator.CreateEd25519Keys(ExactSizeMemoryPool<byte>.Shared);
            var publicKey = keys.PublicKey;
            var privateKey = keys.PrivateKey;

            var data = (ReadOnlySpan<byte>)TestData;
            using var signature = privateKey.Sign(data, NSecAlgorithms.SignEd25519, ExactSizeMemoryPool<byte>.Shared);
            Assert.True(publicKey.Verify(data, signature, NSecAlgorithms.VerifyEd25519));
        }


        [Fact]
        public void NSecGeneratedKeysUsedByBouncyOnEd25519()
        {            
            var keys = NSecKeyCreator.CreateEd25519Keys(ExactSizeMemoryPool<byte>.Shared);
            var publicKey = keys.PublicKey;
            var privateKey = keys.PrivateKey;

            var data = (ReadOnlySpan<byte>)TestData;
            using var signature = privateKey.Sign(data, BouncyCastleAlgorithms.SignEd25519, ExactSizeMemoryPool<byte>.Shared);
            Assert.True(publicKey.Verify(data, signature, BouncyCastleAlgorithms.VerifyEd25519));
        }


        [Fact]
        public void NSecGeneratedSignatureVerifiedByBouncyOnEd25519()
        {
            var keys = NSecKeyCreator.CreateEd25519Keys(ExactSizeMemoryPool<byte>.Shared);
            var publicKey = keys.PublicKey;
            var privateKey = keys.PrivateKey;

            var data = (ReadOnlySpan<byte>)TestData;
            using var signature = privateKey.Sign(data, NSecAlgorithms.SignEd25519, MemoryPool<byte>.Shared);
            Assert.True(publicKey.Verify(data, signature, BouncyCastleAlgorithms.VerifyEd25519));
        }


        [Fact]
        public void BouncyGeneratedSignatureVerifiedByBouncyOnEd25519()
        {
            var keys = BouncyCastleKeyCreator.CreateEd25519Keys(ExactSizeMemoryPool<byte>.Shared);            
            var publicKey = keys.PublicKey;
            var privateKey = keys.PrivateKey;

            var data = (ReadOnlySpan<byte>)TestData;
            using var signature = privateKey.Sign(data, BouncyCastleAlgorithms.SignEd25519, ExactSizeMemoryPool<byte>.Shared);
            Assert.True(publicKey.Verify(data, signature, NSecAlgorithms.VerifyEd25519));
        }
    }
}
