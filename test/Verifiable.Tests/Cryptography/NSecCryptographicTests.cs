using System.Buffers;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.NSec;


namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// These test specifically NSec as the cryptographic provider.
    /// </summary>
    [TestClass]
    internal sealed class NSecCryptographicTests
    {
        /// <summary>
        /// Used in tests as test data.
        /// </summary>
        private byte[] TestData { get; } = Encoding.UTF8.GetBytes("This is a test string.");


        [TestMethod]
        public void CanGenerateKeyPairEd255019()
        {
            var keys = NSecKeyCreator.CreateEd25519Keys(SensitiveMemoryPool<byte>.Shared);

            Assert.IsGreaterThan(0, keys.PublicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, keys.PrivateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public async ValueTask CanSignAndVerifyEd255019()
        {
            var keys = NSecKeyCreator.CreateEd25519Keys(SensitiveMemoryPool<byte>.Shared);
            var publicKey = keys.PublicKey;
            var privateKey = keys.PrivateKey;

            var data = (ReadOnlyMemory<byte>)TestData;
            using Signature signature = await privateKey.SignAsync(data, NSecAlgorithms.SignEd25519Async, MemoryPool<byte>.Shared)
                .ConfigureAwait(false);
            Assert.IsTrue(await publicKey.VerifyAsync(data, signature, NSecAlgorithms.VerifyEd25519Async)
                .ConfigureAwait(false));
        }


        [TestMethod]
        public async ValueTask CanCreateIdentifiedKeyAndVerify()
        {
            var keys = NSecKeyCreator.CreateEd25519Keys(SensitiveMemoryPool<byte>.Shared);

            using var publicKey = new PublicKey(keys.PublicKey, "Test-1", NSecAlgorithms.VerifyEd25519Async);
            using var privateKey = new PrivateKey(keys.PrivateKey, "Test-1", NSecAlgorithms.SignEd25519Async);

            var data = (ReadOnlyMemory<byte>)TestData;
            using Signature signature = await privateKey.SignAsync(data, MemoryPool<byte>.Shared).ConfigureAwait(false);
            Assert.IsTrue(await publicKey.VerifyAsync(data, signature).ConfigureAwait(false));
        }
    }
}