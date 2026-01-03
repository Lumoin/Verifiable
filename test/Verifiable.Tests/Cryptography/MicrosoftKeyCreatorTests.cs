using System.Text;
using Verifiable.Cryptography;
using Verifiable.Microsoft;

namespace Verifiable.Tests.Cryptography
{
    [TestClass]
    public class MicrosoftKeyCreatorTests
    {
        private static byte[] TestData { get; } = Encoding.UTF8.GetBytes("Hello, did:key signature!");


        [TestMethod]
        public async ValueTask P256SignatureVerifies()
        {
            var compressedKeys = MicrosoftKeyMaterialCreator.CreateP256Keys(SensitiveMemoryPool<byte>.Shared);
            var signature = await MicrosoftCryptographicFunctions.SignP256Async(compressedKeys.PrivateKey.AsReadOnlySpan(), TestData, SensitiveMemoryPool<byte>.Shared);
            bool isVerified = await MicrosoftCryptographicFunctions.VerifyP256Async(TestData, signature.Memory.Span, compressedKeys.PublicKey.AsReadOnlySpan());
            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async ValueTask P384SignatureVerifies()
        {
            var compressedKeys = MicrosoftKeyMaterialCreator.CreateP384Keys(SensitiveMemoryPool<byte>.Shared);
            var signature = await MicrosoftCryptographicFunctions.SignP384Async(compressedKeys.PrivateKey.AsReadOnlySpan(), TestData, SensitiveMemoryPool<byte>.Shared);
            bool isVerified = await MicrosoftCryptographicFunctions.VerifyP384Async(TestData, signature.Memory.Span, compressedKeys.PublicKey.AsReadOnlySpan());

            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async ValueTask P521SignatureVerifies()
        {
            var compressedKeys = MicrosoftKeyMaterialCreator.CreateP521Keys(SensitiveMemoryPool<byte>.Shared);
            var signature = await MicrosoftCryptographicFunctions.SignP521Async(compressedKeys.PrivateKey.AsReadOnlySpan(), TestData, SensitiveMemoryPool<byte>.Shared);
            bool isVerified = await MicrosoftCryptographicFunctions.VerifyP521Async(TestData, signature.Memory.Span, compressedKeys.PublicKey.AsReadOnlySpan());
            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async ValueTask Secp256k1SignatureVerifies()
        {
            var compressedKeys = MicrosoftKeyMaterialCreator.CreateSecp256k1Keys(SensitiveMemoryPool<byte>.Shared);
            var signature = await MicrosoftCryptographicFunctions.SignSecp256k1Async(compressedKeys.PrivateKey.AsReadOnlySpan(), TestData, SensitiveMemoryPool<byte>.Shared);
            bool isVerified = await MicrosoftCryptographicFunctions.VerifySecp256k1Async(TestData, signature.Memory.Span, compressedKeys.PublicKey.AsReadOnlySpan());
            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async ValueTask Rsa2048SignatureVerifies()
        {
            var rsaKeys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(SensitiveMemoryPool<byte>.Shared);
            var signature = await MicrosoftCryptographicFunctions.SignRsa2048Async(rsaKeys.PrivateKey.AsReadOnlySpan(), TestData, SensitiveMemoryPool<byte>.Shared);
            bool isVerified = await MicrosoftCryptographicFunctions.VerifyRsa2048Async(TestData, signature.Memory.Span, rsaKeys.PublicKey.AsReadOnlySpan());
            Assert.IsTrue(isVerified);
        }
    }
}

