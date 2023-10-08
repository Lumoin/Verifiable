using System;
using System.Security.Cryptography;

namespace Verifiable.Microsoft
{
    public static class MicrosoftCryptographicFunctions
    {
        public static bool VerifyP256(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            return VerifyECDsa(dataToVerify, signature, publicKeyMaterial, ECCurve.NamedCurves.nistP256);
        }


        public static bool VerifyP384(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            return VerifyECDsa(dataToVerify, signature, publicKeyMaterial, ECCurve.NamedCurves.nistP384);
        }


        public static bool VerifyP521(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            return VerifyECDsa(dataToVerify, signature, publicKeyMaterial, ECCurve.NamedCurves.nistP521);
        }


        public static bool VerifySecp256k1(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            return VerifyECDsa(dataToVerify, signature, publicKeyMaterial, ECCurve.CreateFromFriendlyName("secP256k1"));
        }


        public static bool VerifyRsaSha256Pkcs1(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            return VerifyRsa(dataToVerify, signature, publicKeyMaterial, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }


        public static bool VerifyRsaSha256Pss(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            return VerifyRsa(dataToVerify, signature, publicKeyMaterial, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }


        public static bool VerifyRsaSha384Pkcs1(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            return VerifyRsa(dataToVerify, signature, publicKeyMaterial, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
        }


        public static bool VerifyRsaSha384Pss(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            return VerifyRsa(dataToVerify, signature, publicKeyMaterial, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
        }


        public static bool VerifyRsaSha512Pkcs1(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            return VerifyRsa(dataToVerify, signature, publicKeyMaterial, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        }


        public static bool VerifyRsaSha512Pss(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            return VerifyRsa(dataToVerify, signature, publicKeyMaterial, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
        }



        private static bool VerifyECDsa(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, ECCurve curve)
        {
            using(ECDsa ecdsa = ECDsa.Create(curve))
            {                
                ecdsa.ImportSubjectPublicKeyInfo(publicKeyMaterial, out _);
                return ecdsa.VerifyData(dataToVerify, signature, HashAlgorithmName.SHA256);
            }
        }


        private static bool VerifyRsa(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            using(RSA rsa = RSA.Create())
            {
                rsa.ImportSubjectPublicKeyInfo(publicKeyMaterial, out _);

                return rsa.VerifyData(dataToVerify, signature, hashAlgorithmName, padding);
            }
        }

    }
}
