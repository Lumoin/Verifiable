using System.Buffers;
using System.Text;
using Verifiable.Core.Cryptography;
using Verifiable.NSec;


namespace Verifiable.Tests.Core
{
    /// <summary>
    /// These test specifically NSec as the cryptographic provider.
    /// </summary>
    [TestClass]
    public sealed class NSecCryptographicTests
    {
        /// <summary>
        /// Used in tests as test data.
        /// </summary>
        private byte[] TestData { get; } = Encoding.UTF8.GetBytes("This is a test string.");


        [TestMethod]
        public void CanGenerateKeyPairEd255019()
        {
            var keys = NSecKeyCreator.CreateEd25519Keys(ExactSizeMemoryPool<byte>.Shared);

            Assert.IsGreaterThan(0, keys.PublicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, keys.PrivateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public void CanSignAndVerifyEd255019()
        {
            var keys = NSecKeyCreator.CreateEd25519Keys(ExactSizeMemoryPool<byte>.Shared);
            var publicKey = keys.PublicKey;
            var privateKey = keys.PrivateKey;

            var data = (ReadOnlySpan<byte>)TestData;
            using Signature signature = privateKey.Sign(data, NSecAlgorithms.SignEd25519, MemoryPool<byte>.Shared);
            Assert.IsTrue(publicKey.Verify(data, signature, NSecAlgorithms.VerifyEd25519));
        }


        [TestMethod]
        public void CanCreateIdentifiedKeyAndVerify()
        {
            var keys = NSecKeyCreator.CreateEd25519Keys(ExactSizeMemoryPool<byte>.Shared);

            var publicKey = new PublicKey(keys.PublicKey, "Test-1", NSecAlgorithms.VerifyEd25519);
            var privateKey = new PrivateKey(keys.PrivateKey, "Test-1", NSecAlgorithms.SignEd25519);

            var data = (ReadOnlySpan<byte>)TestData;
            using Signature signature = privateKey.Sign(data, MemoryPool<byte>.Shared);
            Assert.IsTrue(publicKey.Verify(data, signature));
        }
    }
}