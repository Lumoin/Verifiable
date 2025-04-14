using System;
using System.Buffers;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Verifiable.Microsoft
{
    public static class MicrosoftCryptographicFunctions
    {
        public static ValueTask<bool> VerifyP256Async(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, FrozenDictionary<string, object>? context)
        {
            return VerifyECDsa(dataToVerify, signature, publicKeyMaterial, ECCurve.NamedCurves.nistP256);
        }


        public static ValueTask<IMemoryOwner<byte>> SignP256Async(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context)
        {
            var key = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = privateKeyBytes.ToArray()
            });

            var signature = key.SignData(dataToSign, HashAlgorithmName.SHA256);
            var memoryPooledSignature = signaturePool.Rent(signature.Length);
            signature.CopyTo(memoryPooledSignature.Memory.Span);

            return ValueTask.FromResult(memoryPooledSignature);
        }


        public static ValueTask<bool> VerifyP384Async(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, FrozenDictionary<string, object>? context)
        {
            return VerifyECDsa(dataToVerify, signature, publicKeyMaterial, ECCurve.NamedCurves.nistP384);
        }


        public static ValueTask<IMemoryOwner<byte>> SignP384Async(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context)
        {
            var key = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP384,
                D = privateKeyBytes.ToArray()
            });

            var signature = key.SignData(dataToSign, HashAlgorithmName.SHA384);
            var memoryPooledSignature = signaturePool.Rent(signature.Length);
            signature.CopyTo(memoryPooledSignature.Memory.Span);

            return ValueTask.FromResult(memoryPooledSignature);
        }


        public static ValueTask<bool> VerifyP521Async(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            return VerifyECDsa(dataToVerify, signature, publicKeyMaterial, ECCurve.NamedCurves.nistP521);
        }


        public static ValueTask<bool> VerifySecp256k1Async(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            return VerifyECDsa(dataToVerify, signature, publicKeyMaterial, ECCurve.CreateFromFriendlyName("secP256k1"));
        }


        public static ValueTask<bool> VerifyRsaSha256Pkcs1Async(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            return VerifyRsa(dataToVerify, signature, publicKeyMaterial, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }


        public static ValueTask<bool> VerifyRsaSha256PssAsync(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            return VerifyRsa(dataToVerify, signature, publicKeyMaterial, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }


        public static ValueTask<bool> VerifyRsaSha384Pkcs1Async(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            return VerifyRsa(dataToVerify, signature, publicKeyMaterial, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
        }


        public static ValueTask<bool> VerifyRsaSha384PssAsync(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            return VerifyRsa(dataToVerify, signature, publicKeyMaterial, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
        }


        public static ValueTask<bool> VerifyRsaSha512Pkcs1Async(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            return VerifyRsa(dataToVerify, signature, publicKeyMaterial, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        }


        public static ValueTask<bool> VerifyRsaSha512PssAsync(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            return VerifyRsa(dataToVerify, signature, publicKeyMaterial, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
        }



        private static ValueTask<bool> VerifyECDsa(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, ECCurve curve)
        {
            using(ECDsa ecdsa = ECDsa.Create(curve))
            {                
                ecdsa.ImportSubjectPublicKeyInfo(publicKeyMaterial, out _);
                return ValueTask.FromResult(ecdsa.VerifyData(dataToVerify, signature, HashAlgorithmName.SHA256));
            }
        }


        private static ValueTask<bool> VerifyRsa(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            using(RSA rsa = RSA.Create())
            {
                rsa.ImportSubjectPublicKeyInfo(publicKeyMaterial, out _);

                return ValueTask.FromResult(rsa.VerifyData(dataToVerify, signature, hashAlgorithmName, padding));
            }
        }
    }
}
