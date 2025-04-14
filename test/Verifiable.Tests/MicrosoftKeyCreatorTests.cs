using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Core.Cryptography;
using Verifiable.Microsoft;

namespace Verifiable.Tests
{
    [TestClass]
    public class MicrosoftKeyCreatorTests
    {
        private static byte[] TestData { get; } = Encoding.UTF8.GetBytes("Hello, did:key signature!");


        [TestMethod]
        public async ValueTask P256SignatureVerifies()
        {
            var compressedKeys = MicrosoftKeyCreator.CreateP256Keys(ExactSizeMemoryPool<byte>.Shared);
            var signature = await MicrosoftCryptographicFunctions3.SignP256Async(compressedKeys.PrivateKey.AsReadOnlyMemory(), TestData, ExactSizeMemoryPool<byte>.Shared);
            bool isVerified = await MicrosoftCryptographicFunctions3.VerifyP256Async(TestData, signature.AsReadOnlyMemory(), compressedKeys.PublicKey.AsReadOnlyMemory());
            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async ValueTask P384SignatureVerifies()
        {
            var compressedKeys = MicrosoftKeyCreator.CreateP384Keys(ExactSizeMemoryPool<byte>.Shared);
            var signature = await MicrosoftCryptographicFunctions3.SignP384Async(compressedKeys.PrivateKey.AsReadOnlyMemory(), TestData, ExactSizeMemoryPool<byte>.Shared);
            bool isVerified = await MicrosoftCryptographicFunctions3.VerifyP384Async(TestData, signature.AsReadOnlyMemory(), compressedKeys.PublicKey.AsReadOnlyMemory());
            bool isVerified2 = await MicrosoftCryptographicFunctions3.VerifyP384Async_2(compressedKeys.PublicKey.AsReadOnlyMemory(), TestData, signature);

            Assert.IsTrue(isVerified);
            Assert.IsTrue(isVerified2);
        }


        [TestMethod]
        public async ValueTask P521SignatureVerifies()
        {
            var compressedKeys = MicrosoftKeyCreator.CreateP521Keys(ExactSizeMemoryPool<byte>.Shared);
            var signature = await MicrosoftCryptographicFunctions3.SignP521Async(compressedKeys.PrivateKey.AsReadOnlyMemory(), TestData, ExactSizeMemoryPool<byte>.Shared);
            bool isVerified = await MicrosoftCryptographicFunctions3.VerifyP521Async(TestData, signature.AsReadOnlyMemory(), compressedKeys.PublicKey.AsReadOnlyMemory());
            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async ValueTask Secp256k1SignatureVerifies()
        {
            var compressedKeys = MicrosoftKeyCreator.CreateSecp256k1Keys(ExactSizeMemoryPool<byte>.Shared);
            var signature = MicrosoftCryptographicFunctions3.SignSecp256k1(compressedKeys.PrivateKey.AsReadOnlyMemory(), TestData);
            bool isVerified = await MicrosoftCryptographicFunctions3.VerifySecp256k1Async(TestData, new ReadOnlyMemory<byte>(signature.ToArray()), compressedKeys.PublicKey.AsReadOnlyMemory());
            Assert.IsTrue(isVerified);
        }
    }


    public static class MicrosoftCryptographicFunctions3
    {
        public static ValueTask<bool> VerifyP256Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial)
        {
            HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA256;
            ECCurve curve = ECCurve.NamedCurves.nistP256;

            return ValueTask.FromResult(VerifyEcdsa(dataToVerify, signature, publicKeyMaterial, hashAlgorithm, curve));
        }


        public static ValueTask<bool> VerifyP384Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial)
        {
            HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA384;
            ECCurve curve = ECCurve.NamedCurves.nistP384;

            return ValueTask.FromResult(VerifyEcdsa(dataToVerify, signature, publicKeyMaterial, hashAlgorithm, curve));
        }


        public static ValueTask<bool> VerifyP384Async_2(ReadOnlyMemory<byte> publicKeyMaterial, ReadOnlyMemory<byte> dataToVerify, Signature signature)
        {
            return ValueTask.FromResult(VerifyEcdsa(dataToVerify, signature.AsReadOnlyMemory(), publicKeyMaterial, HashAlgorithmName.SHA384, ECCurve.NamedCurves.nistP384));
        }


        public static ValueTask<bool> VerifyP521Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial)
        {
            HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA512;
            ECCurve curve = ECCurve.NamedCurves.nistP521;

            return ValueTask.FromResult(VerifyEcdsa(dataToVerify, signature, publicKeyMaterial, hashAlgorithm, curve));
        }

        public static ValueTask<bool> VerifySecp256k1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial)
        {
            HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA256;
            ECCurve curve = ECCurve.CreateFromFriendlyName("secP256k1");

            return ValueTask.FromResult(VerifyEcdsa(dataToVerify, signature, publicKeyMaterial, hashAlgorithm, curve));
        }


        public static ValueTask<Signature> SignP256Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool)
        {
            var key = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = privateKeyBytes.ToArray()
            });

            var signature = key.SignData(dataToSign.Span, HashAlgorithmName.SHA256);
            var memoryPooledSignature = signaturePool.Rent(signature.Length);
            signature.CopyTo(memoryPooledSignature.Memory.Span);

            return ValueTask.FromResult(new Signature(memoryPooledSignature, Tag.P256Signature));
        }


        public static ValueTask<Signature> SignP384Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool)
        {
            var key = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP384,
                D = privateKeyBytes.ToArray()
            });

            var signature = key.SignData(dataToSign.Span, HashAlgorithmName.SHA384);
            var memoryPooledSignature = signaturePool.Rent(signature.Length);
            signature.CopyTo(memoryPooledSignature.Memory.Span);

            return ValueTask.FromResult(new Signature(memoryPooledSignature, Tag.P384Signature));
        }


        public static ValueTask<Signature> SignP521Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool)
        {
            var key = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP521,
                D = privateKeyBytes.ToArray()
            });

            var signature = key.SignData(dataToSign.Span, HashAlgorithmName.SHA512);
            var memoryPooledSignature = signaturePool.Rent(signature.Length);
            signature.CopyTo(memoryPooledSignature.Memory.Span);

            return ValueTask.FromResult(new Signature(memoryPooledSignature, Tag.P384Signature));
        }


        public static ReadOnlySpan<byte> SignSecp256k1(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign)
        {
            var key = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.CreateFromFriendlyName("secP256k1"),
                D = privateKeyBytes.ToArray()
            });
            
            return key.SignData(dataToSign, HashAlgorithmName.SHA256);
        }


        public static ReadOnlySpan<byte> SignHs256(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign)
        {
            return HMACSHA256.HashData(privateKeyBytes, dataToSign);
        }


        public static ReadOnlySpan<byte> SignHs384(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign)
        {
            return HMACSHA384.HashData(privateKeyBytes, dataToSign);
        }


        public static ReadOnlySpan<byte> SignHs512(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign)
        {
            return HMACSHA512.HashData(privateKeyBytes, dataToSign);
        }


        public static ReadOnlySpan<byte> SignRs256(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign)
        {
            return SignRsa(privateKeyBytes, dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }


        public static ReadOnlySpan<byte> SignRs384(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign)
        {
            return SignRsa(privateKeyBytes, dataToSign, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
        }


        public static ReadOnlySpan<byte> SignRs512(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign)
        {
            return SignRsa(privateKeyBytes, dataToSign, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        }


        public static ReadOnlySpan<byte> SignPs256(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign)
        {
            return SignRsa(privateKeyBytes, dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }


        public static ReadOnlySpan<byte> SignPs384(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign)
        {
            return SignRsa(privateKeyBytes, dataToSign, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
        }


        public static ReadOnlySpan<byte> SignPs512(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign)
        {
            return SignRsa(privateKeyBytes, dataToSign, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
        }


        public static bool VerifyHs256(ReadOnlySpan<byte> publicKeyBytes, ReadOnlySpan<byte> dataToSign, ReadOnlySpan<byte> signatureBytesToVerify)
        {
            return signatureBytesToVerify.SequenceEqual(SignHs256(publicKeyBytes, dataToSign));
        }


        public static bool VerifyHs384(ReadOnlySpan<byte> publicKeyBytes, ReadOnlySpan<byte> dataToSign, ReadOnlySpan<byte> signatureBytesToVerify)
        {
            return signatureBytesToVerify.SequenceEqual(SignHs384(publicKeyBytes, dataToSign));
        }


        public static bool VerifyHs512(ReadOnlySpan<byte> publicKeyBytes, ReadOnlySpan<byte> dataToSign, ReadOnlySpan<byte> signatureBytesToVerify)
        {
            return signatureBytesToVerify.SequenceEqual(SignHs512(publicKeyBytes, dataToSign));
        }


        private static ReadOnlySpan<byte> SignRsa(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, HashAlgorithmName hashAlgorithmName, RSASignaturePadding rsaSignaturePadding)
        {
            using(var key = RSA.Create())
            {
                key.ImportPkcs8PrivateKey(privateKeyBytes, out _);
                return key.SignData(dataToSign, hashAlgorithmName, rsaSignaturePadding);
            }
        }


        private static bool VerifyEcdsa(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, HashAlgorithmName hashAlgorithm, ECCurve curve)
        {
            if(EllipticCurveUtilities.IsCompressed(publicKeyMaterial.Span))
            {
                var curveType = curve.Oid.FriendlyName!.Equals("secP256k1", StringComparison.Ordinal) ? EllipticCurveTypes.Secp256k1 : EllipticCurveTypes.NistCurves;
                byte[] uncompressedY = EllipticCurveUtilities.Decompress(publicKeyMaterial.Span, curveType);
                byte[] uncompressedX = publicKeyMaterial.Slice(1).ToArray();
                ECParameters parameters = new()
                {
                    Curve = curve,
                    Q = new ECPoint
                    {
                        X = uncompressedX,
                        Y = uncompressedY
                    }
                };

                var key = ECDsa.Create(parameters);
                return key.VerifyData(dataToVerify.Span, signature.Span, hashAlgorithm);
            }

            return false;
        }
    }
}
