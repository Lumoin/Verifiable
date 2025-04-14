using System.Collections.Frozen;
using System.Security.Cryptography;

namespace Verifiable.Tests
{   
    public static class CryptographicFunctions
    {
        public static ValueTask<bool> VerifyP256Async(
            ReadOnlyMemory<byte> dataToVerify,
            ReadOnlyMemory<byte> signature,
            ReadOnlyMemory<byte> keyMaterial,
            string inputFormat,
            Func<ReadOnlyMemory<byte>, string, (string Format, string KeyType)[], (ReadOnlyMemory<byte> TransformedKeyMaterial, string OutputFormat)> keyMaterialTransformer,
            FrozenDictionary<string, object>? context)
        {
            return VerifyECDsaAsync(dataToVerify, signature, keyMaterial, inputFormat, keyMaterialTransformer, ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256, "NISTP256");
        }

        public static ValueTask<bool> VerifySecp256k1Async(
            ReadOnlyMemory<byte> dataToVerify,
            ReadOnlyMemory<byte> signature,
            ReadOnlyMemory<byte> keyMaterial,
            string inputFormat,
            Func<ReadOnlyMemory<byte>, string, (string Format, string KeyType)[], (ReadOnlyMemory<byte> TransformedKeyMaterial, string OutputFormat)> keyMaterialTransformer,
            FrozenDictionary<string, object>? context)
        {
            return VerifyECDsaAsync(dataToVerify, signature, keyMaterial, inputFormat, keyMaterialTransformer, ECCurve.CreateFromFriendlyName("secP256k1"), HashAlgorithmName.SHA256, "SECP256k1");
        }

        public static ValueTask<bool> VerifyP384sync(
            ReadOnlyMemory<byte> dataToVerify,
            ReadOnlyMemory<byte> signature,
            ReadOnlyMemory<byte> keyMaterial,
            string inputFormat,
            Func<ReadOnlyMemory<byte>, string, (string Format, string KeyType)[], (ReadOnlyMemory<byte> TransformedKeyMaterial, string OutputFormat)> keyMaterialTransformer,
            FrozenDictionary<string, object>? context)
        {
            return VerifyECDsaAsync(dataToVerify, signature, keyMaterial, inputFormat, keyMaterialTransformer, ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384, "NISTP384");
        }


        public static ValueTask<bool> VerifyP521sync(
            ReadOnlyMemory<byte> dataToVerify,
            ReadOnlyMemory<byte> signature,
            ReadOnlyMemory<byte> keyMaterial,
            string inputFormat,
            Func<ReadOnlyMemory<byte>, string, (string Format, string KeyType)[], (ReadOnlyMemory<byte> TransformedKeyMaterial, string OutputFormat)> keyMaterialTransformer,
            FrozenDictionary<string, object>? context)
        {
            return VerifyECDsaAsync(dataToVerify, signature, keyMaterial, inputFormat, keyMaterialTransformer, ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512, "NISTP521");
        }


        public static ValueTask<ReadOnlyMemory<byte>> SignP256Async(
            ReadOnlyMemory<byte> dataToSign,
            ReadOnlyMemory<byte> privateKey,
            string inputFormat,
            Func<ReadOnlyMemory<byte>, string, (string Format, string KeyType)[], (ReadOnlyMemory<byte> TransformedKeyMaterial, string OutputFormat)> keyMaterialTransformer,
            FrozenDictionary<string, object>? context)
        {
            return SignECDsaAsync(dataToSign, privateKey, inputFormat, keyMaterialTransformer, ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256, "NISTP256");
        }


        public static ValueTask<ReadOnlyMemory<byte>> SignSecp256k1Async(
            ReadOnlyMemory<byte> dataToSign,
            ReadOnlyMemory<byte> privateKey,
            string inputFormat,
            Func<ReadOnlyMemory<byte>, string, (string Format, string KeyType)[], (ReadOnlyMemory<byte> TransformedKeyMaterial, string OutputFormat)> keyMaterialTransformer,
            FrozenDictionary<string, object>? context)
        {
            return SignECDsaAsync(dataToSign, privateKey, inputFormat, keyMaterialTransformer, ECCurve.CreateFromFriendlyName("secP256k1"), HashAlgorithmName.SHA256, "SECP256k1");
        }

        public static ValueTask<ReadOnlyMemory<byte>> SignP384sync(
            ReadOnlyMemory<byte> dataToSign,
            ReadOnlyMemory<byte> privateKey,
            string inputFormat,
            Func<ReadOnlyMemory<byte>, string, (string Format, string KeyType)[], (ReadOnlyMemory<byte> TransformedKeyMaterial, string OutputFormat)> keyMaterialTransformer,
            FrozenDictionary<string, object>? context)
        {
            return SignECDsaAsync(dataToSign, privateKey, inputFormat, keyMaterialTransformer, ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384, "NISTP384");
        }

        public static ValueTask<ReadOnlyMemory<byte>> SignP521sync(
            ReadOnlyMemory<byte> dataToSign,
            ReadOnlyMemory<byte> privateKey,
            string inputFormat,
            Func<ReadOnlyMemory<byte>, string, (string Format, string KeyType)[], (ReadOnlyMemory<byte> TransformedKeyMaterial, string OutputFormat)> keyMaterialTransformer,
            FrozenDictionary<string, object>? context)
        {
            return SignECDsaAsync(dataToSign, privateKey, inputFormat, keyMaterialTransformer, ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA512, "NISTP512");
        }


        public static ValueTask<bool> VerifyRsaSha256Pkcs1Async(
           ReadOnlyMemory<byte> dataToVerify,
           ReadOnlyMemory<byte> signature,
           ReadOnlyMemory<byte> keyMaterial,
           FrozenDictionary<string, object>? context)
        {
            return VerifyRsaAsync(dataToVerify, signature, keyMaterial, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }


        public static ValueTask<bool> VerifyRsaSha256PssAsync(
            ReadOnlyMemory<byte> dataToVerify,
            ReadOnlyMemory<byte> signature,
            ReadOnlyMemory<byte> keyMaterial,
            FrozenDictionary<string, object>? context)
        {
            return VerifyRsaAsync(dataToVerify, signature, keyMaterial, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }

        public static ValueTask<bool> VerifyHmacSha256Async(
            ReadOnlyMemory<byte> dataToVerify,
            ReadOnlyMemory<byte> signature,
            ReadOnlyMemory<byte> keyMaterial,
            FrozenDictionary<string, object>? context)
        {
            return VerifyHmacAsync(dataToVerify, signature, keyMaterial, HashAlgorithmName.SHA256);
        }

        public static ValueTask<ReadOnlyMemory<byte>> SignRsaSha256Pkcs1Async(
            ReadOnlyMemory<byte> dataToSign,
            ReadOnlyMemory<byte> privateKey,
            FrozenDictionary<string, object>? context)
        {
            return SignRsaAsync(dataToSign, privateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        public static ValueTask<ReadOnlyMemory<byte>> SignHmacSha256Async(
            ReadOnlyMemory<byte> dataToSign,
            ReadOnlyMemory<byte> keyMaterial,
            FrozenDictionary<string, object>? context)
        {
            return SignHmacAsync(dataToSign, keyMaterial, HashAlgorithmName.SHA256);
        }

        private static ValueTask<bool> VerifyECDsaAsync(
            ReadOnlyMemory<byte> dataToVerify,
            ReadOnlyMemory<byte> signature,
            ReadOnlyMemory<byte> keyMaterial,
            string inputFormat,
            Func<ReadOnlyMemory<byte>, string, (string Format, string KeyType)[], (ReadOnlyMemory<byte> TransformedKeyMaterial, string OutputFormat)> keyMaterialTransformer,
            ECCurve curve,
            HashAlgorithmName hashAlgorithmName,
            string keyType)
        {
            var facilityPreferredFormats = new[]
            {
                ("SubjectPublicKeyInfo", keyType),
                ("Raw", keyType)
            };

            var (transformedKeyMaterial, outputFormat) = keyMaterialTransformer(keyMaterial, inputFormat, facilityPreferredFormats);

            if(!facilityPreferredFormats.Any(pref => pref.Item1 == outputFormat && pref.Item2 == keyType))
                throw new InvalidOperationException($"Key material format '{outputFormat}' or type '{keyType}' is not supported.");

            using var ecdsa = ECDsa.Create(curve);

            if(outputFormat == "SubjectPublicKeyInfo")
            {
                ecdsa.ImportSubjectPublicKeyInfo(transformedKeyMaterial.Span, out _);
            }
            else if(outputFormat == "Raw")
            {
                byte[] uncompressedX = transformedKeyMaterial.Span.Slice(1, (transformedKeyMaterial.Length - 1) / 2).ToArray();
                byte[] uncompressedY = transformedKeyMaterial.Span.Slice(1 + uncompressedX.Length).ToArray();

                ECParameters parameters = new()
                {
                    Curve = curve,
                    Q = new ECPoint { X = uncompressedX, Y = uncompressedY }
                };
                ecdsa.ImportParameters(parameters);
            }
            else
            {
                throw new NotSupportedException($"Key material format '{outputFormat}' is not recognized.");
            }

            return ValueTask.FromResult(ecdsa.VerifyData(dataToVerify.Span, signature.Span, hashAlgorithmName));
        }

        private static ValueTask<ReadOnlyMemory<byte>> SignECDsaAsync(
            ReadOnlyMemory<byte> dataToSign,
            ReadOnlyMemory<byte> privateKey,
            string inputFormat,
            Func<ReadOnlyMemory<byte>, string, (string Format, string KeyType)[], (ReadOnlyMemory<byte> TransformedKeyMaterial, string OutputFormat)> keyMaterialTransformer,
            ECCurve curve,
            HashAlgorithmName hashAlgorithmName,
            string keyType)
        {
            var facilityPreferredFormats = new[] { ("Raw", keyType) };

            var (transformedKeyMaterial, outputFormat) = keyMaterialTransformer(privateKey, inputFormat, facilityPreferredFormats);

            if(!facilityPreferredFormats.Any(pref => pref.Item1 == outputFormat && pref.Item2 == keyType))
                throw new InvalidOperationException($"Key material format '{outputFormat}' or type '{keyType}' is not supported.");

            using var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = curve,
                D = transformedKeyMaterial.ToArray()
            });

            var signature = ecdsa.SignData(dataToSign.Span, hashAlgorithmName);
            return ValueTask.FromResult(new ReadOnlyMemory<byte>(signature));
        }

        private static ValueTask<bool> VerifyRsaAsync(
            ReadOnlyMemory<byte> dataToVerify,
            ReadOnlyMemory<byte> signature,
            ReadOnlyMemory<byte> keyMaterial,
            HashAlgorithmName hashAlgorithmName,
            RSASignaturePadding padding)
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(keyMaterial.Span, out _);
            return ValueTask.FromResult(rsa.VerifyData(dataToVerify.Span, signature.Span, hashAlgorithmName, padding));
        }

        private static ValueTask<ReadOnlyMemory<byte>> SignRsaAsync(
            ReadOnlyMemory<byte> dataToSign,
            ReadOnlyMemory<byte> privateKey,
            HashAlgorithmName hashAlgorithmName,
            RSASignaturePadding padding)
        {
            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(privateKey.Span, out _);
            var signature = rsa.SignData(dataToSign.Span, hashAlgorithmName, padding);
            return ValueTask.FromResult(new ReadOnlyMemory<byte>(signature));
        }

        private static ValueTask<bool> VerifyHmacAsync(
            ReadOnlyMemory<byte> dataToVerify,
            ReadOnlyMemory<byte> signature,
            ReadOnlyMemory<byte> keyMaterial,
            HashAlgorithmName hashAlgorithmName)
        {
            using var hmac = CreateHmac(hashAlgorithmName, keyMaterial.Span);
            var computedSignature = hmac.ComputeHash(dataToVerify.Span.ToArray());
            return ValueTask.FromResult(signature.Span.SequenceEqual(computedSignature));
        }

        private static ValueTask<ReadOnlyMemory<byte>> SignHmacAsync(
            ReadOnlyMemory<byte> dataToSign,
            ReadOnlyMemory<byte> keyMaterial,
            HashAlgorithmName hashAlgorithmName)
        {
            using var hmac = CreateHmac(hashAlgorithmName, keyMaterial.Span);
            var signature = hmac.ComputeHash(dataToSign.Span.ToArray());
            return ValueTask.FromResult(new ReadOnlyMemory<byte>(signature));
        }

        private static HMAC CreateHmac(HashAlgorithmName hashAlgorithmName, ReadOnlySpan<byte> key)
        {
            return hashAlgorithmName.Name switch
            {
                "SHA256" => new HMACSHA256(key.ToArray()),
                "SHA384" => new HMACSHA384(key.ToArray()),
                "SHA512" => new HMACSHA512(key.ToArray()),
                _ => throw new NotSupportedException($"Hash algorithm {hashAlgorithmName.Name} is not supported for HMAC.")
            };
        }
    }
}
