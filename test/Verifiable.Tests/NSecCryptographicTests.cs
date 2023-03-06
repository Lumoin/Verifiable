using Verifiable.Core.Cryptography;
using Verifiable.NSec;
using System;
using System.Buffers;
using System.Text;
using Xunit;


namespace Verifiable.Core
{
    /// <summary>
    /// These test specifically NSec as the cryptographic provider.
    /// </summary>
    public class NSecCryptographicTests
    {
        /// <summary>
        /// Used in tests as test data.
        /// </summary>
        private byte[] TestData { get; } = Encoding.UTF8.GetBytes("This is a test string.");

        
        [Fact]
        public void CanGenerateKeyPairEd255019()
        {
            var keys = NSecKeyCreator.CreateEd25519Keys(ExactSizeMemoryPool<byte>.Shared);
            
            Assert.NotNull(keys.PublicKey);
            Assert.NotNull(keys.PrivateKey);
        }


        [Fact]
        public void CanSignAndVerifyEd255019()
        {
            var keys = NSecKeyCreator.CreateEd25519Keys(ExactSizeMemoryPool<byte>.Shared);
            var publicKey = keys.PublicKey;
            var privateKey = keys.PrivateKey;

            var data = (ReadOnlySpan<byte>)TestData;
            using Signature signature = privateKey.Sign(data, NSecAlgorithms.SignEd25519, MemoryPool<byte>.Shared);
            Assert.True(publicKey.Verify(data, signature, NSecAlgorithms.VerifyEd25519));
        }


        [Fact]
        public void CanCreateIdentifiedKeyAndVerify()
        {
            var keys = NSecKeyCreator.CreateEd25519Keys(ExactSizeMemoryPool<byte>.Shared);

            var publicKey = new PublicKey(keys.PublicKey, "Test-1", NSecAlgorithms.VerifyEd25519);
            var privateKey = new PrivateKey(keys.PrivateKey, "Test-1", NSecAlgorithms.SignEd25519);

            var data = (ReadOnlySpan<byte>)TestData;
            using Signature signature = privateKey.Sign(data, MemoryPool<byte>.Shared);
            Assert.True(publicKey.Verify(data, signature));
        }
    }
}