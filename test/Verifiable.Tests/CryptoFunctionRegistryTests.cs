using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;
using Verifiable.Microsoft;

namespace Verifiable.Tests
{
    [TestClass]
    public class CryptoFunctionRegistryTests
    {
        private static byte[] TestData { get; } = Encoding.UTF8.GetBytes("Hello, did:key signature!");
        
        public CryptoFunctionRegistryTests()
        {
            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.Initialize((CryptoAlgorithm algorithm, Purpose purpose, string? qualifier = null) =>
            {
                return (algorithm, purpose, qualifier) switch
                {
                    var (alg, purp, q) when alg.Equals(CryptoAlgorithm.P256) && purp.Equals(Purpose.Signing) && q == $"{nameof(CryptoFunctionRegistryTests)}" => MicrosoftCryptographicFunctions.SignP256Async,
                    var (alg, purp, q) when alg.Equals(CryptoAlgorithm.P384) && purp.Equals(Purpose.Signing) && q == $"{nameof(CryptoFunctionRegistryTests)}" => MicrosoftCryptographicFunctions.SignP384Async,
                    _ => throw new ArgumentException($"No signing function registered for {algorithm}, {purpose} with qualifier {qualifier}.")
                };
            },
            (CryptoAlgorithm algorithm, Purpose purpose, string? qualifier = null) =>
            {
                return (algorithm, purpose, qualifier) switch
                {
                    var (alg, purp, q) when alg.Equals(CryptoAlgorithm.P256) && purp.Equals(Purpose.Verification) && q == $"{nameof(CryptoFunctionRegistryTests)}" => MicrosoftCryptographicFunctions.VerifyP256Async,
                    var (alg, purp, q) when alg.Equals(CryptoAlgorithm.P384) && purp.Equals(Purpose.Verification) && q == $"{nameof(CryptoFunctionRegistryTests)}" => MicrosoftCryptographicFunctions.VerifyP384Async,                    
                    var (alg, purp, q) when alg.Equals(CryptoAlgorithm.P256) && purp.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyP256Async, //This is a default implementation...
                    _ => throw new ArgumentException($"No verification function registered for {algorithm}, {purpose} with qualifier {qualifier}.")
                };
            });

            CryptographicKeyFactory2.Initialize((Tag tag, string? qualifier) =>
            {
                CryptoAlgorithm algorithm = tag.Get<CryptoAlgorithm>();
                Purpose purpose = (Purpose)tag[typeof(Purpose)];
                return (publicKeyBytes, dataToVerify, signature) =>
                {                    
                    var verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose, qualifier);
                    return verificationDelegate(dataToVerify.Span, signature.AsReadOnlySpan(), publicKeyBytes.Span);
                };
            },
            (Tag tag, string? qualifier) =>
            {
                CryptoAlgorithm algorithm = tag.Get<CryptoAlgorithm>();
                Purpose purpose = (Purpose)tag[typeof(Purpose)];
                return async (privateKeyBytes, dataToVerify, signature) =>
                {
                    var signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose, qualifier);
                    var ret = await signingDelegate(privateKeyBytes.Span, dataToVerify.Span, signature);

                    return new Signature(ret, tag);
                };
            });           
        }


        [TestMethod]
        public async ValueTask P256SignatureVerifies()
        {            
            var compressedKeys = MicrosoftKeyCreator.CreateP256Keys(ExactSizeMemoryPool<byte>.Shared);

            var privateKey = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(CryptoAlgorithm.P256, Purpose.Signing, nameof(CryptoFunctionRegistryTests));
            var publicKey = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(CryptoAlgorithm.P256, Purpose.Verification, nameof(CryptoFunctionRegistryTests));

            var signature = await privateKey(compressedKeys.PrivateKey.AsReadOnlySpan(), TestData, ExactSizeMemoryPool<byte>.Shared);            
            bool isVerified = await publicKey(TestData, signature.Memory.Span, compressedKeys.PublicKey.AsReadOnlySpan());
            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async ValueTask P256SignatureVerifiesHigherLevel()
        {
            static (ReadOnlyMemory<byte> TransformedKeyMaterial, string OutputFormat) keyMaterialTransformer(ReadOnlyMemory<byte> keyMaterial, string inputFormat, (string Format, string KeyType)[] preferredFormats)
            {
                if(inputFormat == "raw")
                {
                    return (keyMaterial, "Raw");
                }
                if(inputFormat == "compressed")
                {
                    if(EllipticCurveUtilities.IsCompressed(keyMaterial.Span))
                    {
                        var curveType = inputFormat.Equals("secP256k1", StringComparison.Ordinal) ? EllipticCurveTypes.Secp256k1 : EllipticCurveTypes.NistCurves;
                        byte[] uncompressedY = EllipticCurveUtilities.Decompress(keyMaterial.Span, curveType);
                        byte[] uncompressedX = keyMaterial.Slice(1).ToArray();

                        return (new ReadOnlyMemory<byte>([EllipticCurveUtilities.UncompressedCoordinateFormat, .. uncompressedX, .. uncompressedY]), "Raw");
                    }
                }

                throw new NotImplementedException("temp");
            }

            var compressedKeys = MicrosoftKeyCreator.CreateP256Keys(ExactSizeMemoryPool<byte>.Shared);
            
            var signature = await CryptographicFunctions.SignP256Async(
                new ReadOnlyMemory<byte>(TestData),
                compressedKeys.PrivateKey.AsReadOnlyMemory(),
                "raw",
                keyMaterialTransformer,
                null);

            
            bool isVerified = await CryptographicFunctions.VerifyP256Async(
                TestData,
                signature,
                compressedKeys.PublicKey.AsReadOnlyMemory(),
                "compressed",
                keyMaterialTransformer,
                null);

            //var signature = await CryptographicFunctions.SignP256Async(new ReadOnlyMemory<byte>(TestData), compressedKeys.PrivateKey.AsReadOnlyMemory(), "compressed");
            //bool isVerified = await CryptographicFunctions.VerifyP256Async(TestData, signature, compressedKeys.PublicKey.AsReadOnlyMemory(), "compressed", () => { });
            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async ValueTask P256SignatureVerifiesHighestLevel()
        {
            var compressedKeys = MicrosoftKeyCreator.CreateP256Keys(ExactSizeMemoryPool<byte>.Shared);

            var publicKey = CryptographicKeyFactory2.CreatePublicKey(compressedKeys.PublicKey, "key-identifier", compressedKeys.PublicKey.Tag, nameof(CryptoFunctionRegistryTests));
            var privateKey = CryptographicKeyFactory2.CreatePrivateKey(compressedKeys.PrivateKey, "key-identifier", compressedKeys.PrivateKey.Tag, nameof(CryptoFunctionRegistryTests));
            var signature = await privateKey.SignAsync(TestData.AsMemory(), ExactSizeMemoryPool<byte>.Shared);
            bool isVerified = await publicKey.VerifyAsync(TestData.AsMemory(), signature);

            Assert.IsTrue(isVerified);
        }
    }
}
