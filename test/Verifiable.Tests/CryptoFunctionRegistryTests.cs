using System.Text;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;
using Verifiable.Microsoft;

namespace Verifiable.Tests
{
    [TestClass]
    public class CryptoFunctionRegistryTests
    {
        private static byte[] TestData { get; } = Encoding.UTF8.GetBytes("Hello, CryptoFunctionRegistryTests!");


        [TestMethod]
        public async ValueTask P256SignatureVerifies()
        {
            var compressedKeys = MicrosoftKeyMaterialCreator.CreateP256Keys(SensitiveMemoryPool<byte>.Shared);

            var privateKey = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(CryptoAlgorithm.P256, Purpose.Signing);
            var publicKey = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(CryptoAlgorithm.P256, Purpose.Verification);

            var signature = await privateKey(compressedKeys.PrivateKey.AsReadOnlySpan(), TestData, SensitiveMemoryPool<byte>.Shared);
            bool isVerified = await publicKey(TestData, signature.Memory.Span, compressedKeys.PublicKey.AsReadOnlySpan());
            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async ValueTask P256SignatureVerifiesHighestLevel()
        {
            var compressedKeys = MicrosoftKeyMaterialCreator.CreateP256Keys(SensitiveMemoryPool<byte>.Shared);

            var publicKey = CryptographicKeyFactory.CreatePublicKey(compressedKeys.PublicKey, "key-identifier", compressedKeys.PublicKey.Tag);
            var privateKey = CryptographicKeyFactory.CreatePrivateKey(compressedKeys.PrivateKey, "key-identifier", compressedKeys.PrivateKey.Tag);
            var signature = await privateKey.SignAsync(TestData.AsMemory(), SensitiveMemoryPool<byte>.Shared);
            bool isVerified = await publicKey.VerifyAsync(TestData.AsMemory(), signature);

            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async ValueTask Rsa2048SignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(SensitiveMemoryPool<byte>.Shared);

            var privateKey = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(CryptoAlgorithm.Rsa2048, Purpose.Signing);
            var publicKey = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(CryptoAlgorithm.Rsa2048, Purpose.Verification);

            var signature = await privateKey(keys.PrivateKey.AsReadOnlySpan(), TestData, SensitiveMemoryPool<byte>.Shared);
            bool isVerified = await publicKey(TestData, signature.Memory.Span, keys.PublicKey.AsReadOnlySpan());
            Assert.IsTrue(isVerified);
        }
    }
}
