using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Microsoft;

namespace Verifiable.Tests.Cryptography
{
[TestClass]
internal class CryptoFunctionRegistryTests
    {
        private static byte[] TestData { get; } = Encoding.UTF8.GetBytes("Hello, CryptoFunctionRegistryTests!");


        [TestMethod]
        public async ValueTask P256SignatureVerifies()
        {
            var compressedKeys = MicrosoftKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);

            var privateKey = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(CryptoAlgorithm.P256, Purpose.Signing);
            var publicKey = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(CryptoAlgorithm.P256, Purpose.Verification);

            var signature = await privateKey(compressedKeys.PrivateKey.AsReadOnlyMemory(), TestData, BaseMemoryPool.Shared, context: null, cancellationToken: default)
                .ConfigureAwait(false);
            bool isVerified = await publicKey(TestData, signature.AsReadOnlyMemory(), compressedKeys.PublicKey.AsReadOnlyMemory(), context: null, cancellationToken: default)
                .ConfigureAwait(false);
            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async ValueTask P256SignatureVerifiesHighestLevel()
        {
            var compressedKeys = MicrosoftKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);

            using var publicKey = CryptographicKeyFactory.CreatePublicKey(compressedKeys.PublicKey, "key-identifier", compressedKeys.PublicKey.Tag);
            using var privateKey = CryptographicKeyFactory.CreatePrivateKey(compressedKeys.PrivateKey, "key-identifier", compressedKeys.PrivateKey.Tag);
            var signature = await privateKey.SignAsync(TestData.AsMemory(), BaseMemoryPool.Shared)
                .ConfigureAwait(false);
            bool isVerified = await publicKey.VerifyAsync(TestData.AsMemory(), signature)
                .ConfigureAwait(false);

            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async ValueTask Rsa2048SignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);

            var privateKey = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(CryptoAlgorithm.Rsa2048, Purpose.Signing);
            var publicKey = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(CryptoAlgorithm.Rsa2048, Purpose.Verification);

            var signature = await privateKey(keys.PrivateKey.AsReadOnlyMemory(), TestData, BaseMemoryPool.Shared, context: null, cancellationToken: default).ConfigureAwait(false);
            bool isVerified = await publicKey(TestData, signature.AsReadOnlyMemory(), keys.PublicKey.AsReadOnlyMemory(), context: null, cancellationToken: default).ConfigureAwait(false);
            Assert.IsTrue(isVerified);
        }
    }
}
