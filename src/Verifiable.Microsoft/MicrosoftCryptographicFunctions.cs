using System;
using System.Buffers;
using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable.Microsoft
{
    /// <summary>
    /// Provides cryptographic functions for digital signatures using Microsoft cryptographic libraries.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The caller is responsible for disposing the returned objects.")]
    public static class MicrosoftCryptographicFunctions
    {
        public static ValueTask<bool> VerifyP256Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyECDsa(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256);
        }

        public static ValueTask<Signature> SignP256Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignECDsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256, CryptoTags.P256Signature);
        }

        public static ValueTask<bool> VerifyP384Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyECDsa(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384);
        }

        public static ValueTask<Signature> SignP384Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignECDsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384, CryptoTags.P384Signature);
        }

        public static ValueTask<bool> VerifyP521Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyECDsa(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512);
        }

        public static ValueTask<Signature> SignP521Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignECDsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512, CryptoTags.P521Signature);
        }

        public static ValueTask<bool> VerifySecp256k1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyECDsa(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, ECCurve.CreateFromFriendlyName("secP256k1"), HashAlgorithmName.SHA256);
        }

        public static ValueTask<Signature> SignSecp256k1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignECDsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, ECCurve.CreateFromFriendlyName("secP256k1"), HashAlgorithmName.SHA256, CryptoTags.Secp256k1Signature);
        }

        public static ValueTask<Signature> SignRsa2048Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, CryptoTags.Rsa2048Signature);
        }

        public static ValueTask<bool> VerifyRsa2048Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        public static ValueTask<Signature> SignRsa4096Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, CryptoTags.Rsa4096Signature);
        }

        public static ValueTask<bool> VerifyRsa4096Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        public static ValueTask<bool> VerifyRsaSha256Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        public static ValueTask<Signature> SignRsaSha256Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, CryptoTags.RsaSha256Pkcs1Signature);
        }

        public static ValueTask<bool> VerifyRsaSha256PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }

        public static ValueTask<Signature> SignRsaSha256PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA256, RSASignaturePadding.Pss, CryptoTags.RsaSha256PssSignature);
        }

        public static ValueTask<bool> VerifyRsaSha384Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
        }

        public static ValueTask<Signature> SignRsaSha384Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1, CryptoTags.RsaSha384Pkcs1Signature);
        }

        public static ValueTask<bool> VerifyRsaSha384PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
        }

        public static ValueTask<Signature> SignRsaSha384PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA384, RSASignaturePadding.Pss, CryptoTags.RsaSha384PssSignature);
        }

        public static ValueTask<bool> VerifyRsaSha512Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        }

        public static ValueTask<Signature> SignRsaSha512Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1, CryptoTags.RsaSha512Pkcs1Signature);
        }

        public static ValueTask<bool> VerifyRsaSha512PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
        }

        public static ValueTask<Signature> SignRsaSha512PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA512, RSASignaturePadding.Pss, CryptoTags.RsaSha512PssSignature);
        }

        private static ValueTask<bool> VerifyECDsa(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, ECCurve curve, HashAlgorithmName hashAlgorithmName)
        {
            if(EllipticCurveUtilities.IsCompressed(publicKeyMaterial))
            {
                var curveType = curve.Oid.FriendlyName!.Equals("secP256k1", StringComparison.Ordinal) ? EllipticCurveTypes.Secp256k1 : EllipticCurveTypes.NistCurves;
                byte[] uncompressedY = EllipticCurveUtilities.Decompress(publicKeyMaterial, curveType);
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
                return ValueTask.FromResult(key.VerifyData(dataToVerify, signature, hashAlgorithmName));
            }

            return ValueTask.FromResult(false);
        }

        
        private static ValueTask<Signature> SignECDsa(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, ECCurve curve, HashAlgorithmName hashAlgorithmName, Tag signatureTag)
        {
            var key = ECDsa.Create(new ECParameters
            {
                Curve = curve,
                D = privateKeyBytes.ToArray()
            });

            var signatureBytes = key.SignData(dataToSign, hashAlgorithmName);
            var memoryPooledSignature = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryPooledSignature.Memory.Span);

            return ValueTask.FromResult(new Signature(memoryPooledSignature, signatureTag));
        }

        private static ValueTask<bool> VerifyRsaAsync(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            using(RSA rsa = RSA.Create())
            {
                try
                {
                    rsa.ImportRSAPublicKey(publicKeyMaterial, out _);
                }
                catch
                {
                    var parameters = new RSAParameters
                    {
                        Modulus = publicKeyMaterial.ToArray(),
                        Exponent = [0x01, 0x00, 0x01]
                    };
                    rsa.ImportParameters(parameters);
                }

                return ValueTask.FromResult(rsa.VerifyData(dataToVerify, signature, hashAlgorithmName, padding));
            }
        }

        private static ValueTask<Signature> SignRsa(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Tag signatureTag)
        {
            using(RSA rsa = RSA.Create())
            {
                rsa.ImportRSAPrivateKey(privateKeyBytes, out _);
                byte[] signatureBytes = rsa.SignData(dataToSign, hashAlgorithmName, padding);
                IMemoryOwner<byte> memoryPooledSignature = signaturePool.Rent(signatureBytes.Length);
                signatureBytes.CopyTo(memoryPooledSignature.Memory.Span);

                return ValueTask.FromResult(new Signature(memoryPooledSignature, signatureTag));
            }
        }
    }
}