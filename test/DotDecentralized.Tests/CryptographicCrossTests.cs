using DotDecentralized.BouncyCastle;
using DotDecentralized.Core.Cryptography;
using DotDecentralized.NSec;
using System;
using System.Buffers;
using System.Text;
using Xunit;

namespace DotDecentralized.Tests
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
            var bouncyGenerator = new BouncyCastleKeyGenerator();
            var keys = bouncyGenerator.GenerateEd25519PublicPrivateKeyPair(MemoryPool<byte>.Shared);
            var publicKey = keys.Item1;
            var privateKey = keys.Item2;

            var data = (ReadOnlySpan<byte>)TestData;
            using var signature = privateKey.Sign(data, NSecAlgorithms.SignEd25519, MemoryPool<byte>.Shared);
            Assert.True(publicKey.Verify(data, signature, NSecAlgorithms.VerifyEd25519));
        }


        [Fact]
        public void NSecGeneratedKeysUsedByBouncyOnEd25519()
        {
            var nsecKeyGenerator = new NSecKeyGenerator();
            var keys = nsecKeyGenerator.GenerateEd25519PublicPrivateKeyPair(MemoryPool<byte>.Shared);
            var publicKey = keys.Item1;
            var privateKey = keys.Item2;

            var data = (ReadOnlySpan<byte>)TestData;
            using var signature = privateKey.Sign(data, BouncyCastleAlgorithms.SignEd25519, MemoryPool<byte>.Shared);
            Assert.True(publicKey.Verify(data, signature, BouncyCastleAlgorithms.VerifyEd25519));
        }


        [Fact]
        public void NSecGeneratedSignatureVerifiedByBouncyOnEd25519()
        {
            var nsecKeyGenerator = new NSecKeyGenerator();
            var keys = nsecKeyGenerator.GenerateEd25519PublicPrivateKeyPair(MemoryPool<byte>.Shared);
            var publicKey = keys.Item1;
            var privateKey = keys.Item2;

            var data = (ReadOnlySpan<byte>)TestData;
            using var signature = privateKey.Sign(data, NSecAlgorithms.SignEd25519, MemoryPool<byte>.Shared);
            Assert.True(publicKey.Verify(data, signature, BouncyCastleAlgorithms.VerifyEd25519));
        }


        [Fact]
        public void BouncyGeneratedSignatureVerifiedByBouncyOnEd25519()
        {
            var bouncyGenerator = new BouncyCastleKeyGenerator();
            var keys = bouncyGenerator.GenerateEd25519PublicPrivateKeyPair(MemoryPool<byte>.Shared);
            var publicKey = keys.Item1;
            var privateKey = keys.Item2;

            var data = (ReadOnlySpan<byte>)TestData;
            using var signature = privateKey.Sign(data, BouncyCastleAlgorithms.SignEd25519, MemoryPool<byte>.Shared);
            Assert.True(publicKey.Verify(data, signature, NSecAlgorithms.VerifyEd25519));
        }
    }
}
