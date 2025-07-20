using System;
using System.Collections.Frozen;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Verifiable.Microsoft
{
    /// <summary>
    /// Provides cryptographic functions for signing and verifying data using ECDSA algorithms.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This class is designed to handle cryptographic operations while maintaining flexibility and extensibility
    /// through a "capability by convention" approach. It uses a plain <see cref="Func{T1, T2, T3, TResult}"/>
    /// delegate for dynamically transforming key materials to formats suitable for the required cryptographic operations.
    /// </para>
    /// <para>
    /// The cryptographic operations in this class support the following conventions for <see cref="CryptoAlgorithm"/>
    /// and <see cref="EncodingScheme"/> values, which are internally used to process key material transformations.
    /// The preferred encoding scheme for each algorithm is also specified.
    /// </para>
    /// <para><strong>Supported CryptoAlgorithm and EncodingScheme Pairings:</strong></para>
    /// <list type="table">
    /// <listheader>
    /// <term>CryptoAlgorithm</term>
    /// <term>Supported EncodingSchemes</term>
    /// <term>Preferred EncodingScheme</term>
    /// </listheader>
    /// <item>
    /// <term><c>P256</c></term>
    /// <description><c>Raw</c>, <c>SubjectPublicKeyInfo</c></description>
    /// <description><c>Raw</c></description>
    /// </item>
    /// <item>
    /// <term><c>P384</c></term>
    /// <description><c>Raw</c>, <c>SubjectPublicKeyInfo</c></description>
    /// <description><c>Raw</c></description>
    /// </item>
    /// <item>
    /// <term><c>P521</c></term>
    /// <description><c>Raw</c>, <c>SubjectPublicKeyInfo</c></description>
    /// <description><c>Raw</c></description>
    /// </item>
    /// <item>
    /// <term><c>Secp256k1</c></term>
    /// <description><c>Raw</c>, <c>SubjectPublicKeyInfo</c></description>
    /// <description><c>Raw</c></description>
    /// </item>
    /// <item>
    /// <term><c>Rsa2048</c></term>
    /// <description><c>Der</c>, <c>SubjectPublicKeyInfo</c></description>
    /// <description><c>Der</c></description>
    /// </item>
    /// <item>
    /// <term><c>Rsa4096</c></term>
    /// <description><c>Der</c>, <c>SubjectPublicKeyInfo</c></description>
    /// <description><c>Der</c></description>
    /// </item>
    /// </list>
    /// <para>
    /// These conventions enable the class to operate flexibly while ensuring that inputs and outputs adhere to
    /// well-defined standards. Consumers of this class should ensure their key material is prepared or transformed
    /// according to these conventions.
    /// </para>
    /// </remarks>
    /// <summary>
    /// Provides cryptographic functions for signing and verifying data using ECDSA, RSA, and HMAC algorithms.
    /// </summary>
    public static class CryptographicFunctions
    {
        /// <summary>
        /// Verifies a digital signature using the P-256 curve.
        /// </summary>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="keyMaterial">The public key material used for verification.</param>
        /// <param name="inputFormat">The format of the provided key material.</param>
        /// <param name="keyMaterialTransformer">A delegate for transforming the key material to a suitable format.</param>
        /// <param name="context">Optional context information for cryptographic operations.</param>
        /// <returns>A task that resolves to <c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
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

        /// <summary>
        /// Verifies a digital signature using the P-384 curve.
        /// </summary>
        public static ValueTask<bool> VerifyP384Async(
            ReadOnlyMemory<byte> dataToVerify,
            ReadOnlyMemory<byte> signature,
            ReadOnlyMemory<byte> keyMaterial,
            string inputFormat,
            Func<ReadOnlyMemory<byte>, string, (string Format, string KeyType)[], (ReadOnlyMemory<byte> TransformedKeyMaterial, string OutputFormat)> keyMaterialTransformer,
            FrozenDictionary<string, object>? context)
        {
            return VerifyECDsaAsync(dataToVerify, signature, keyMaterial, inputFormat, keyMaterialTransformer, ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384, "NISTP384");
        }

        /// <summary>
        /// Verifies a digital signature using the P-521 curve.
        /// </summary>
        public static ValueTask<bool> VerifyP521Async(
            ReadOnlyMemory<byte> dataToVerify,
            ReadOnlyMemory<byte> signature,
            ReadOnlyMemory<byte> keyMaterial,
            string inputFormat,
            Func<ReadOnlyMemory<byte>, string, (string Format, string KeyType)[], (ReadOnlyMemory<byte> TransformedKeyMaterial, string OutputFormat)> keyMaterialTransformer,
            FrozenDictionary<string, object>? context)
        {
            return VerifyECDsaAsync(dataToVerify, signature, keyMaterial, inputFormat, keyMaterialTransformer, ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512, "NISTP521");
        }

        /// <summary>
        /// Signs data using the P-256 curve.
        /// </summary>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="privateKey">The private key material for signing.</param>
        /// <param name="inputFormat">The format of the provided key material.</param>
        /// <param name="keyMaterialTransformer">A delegate for transforming the key material to a suitable format.</param>
        /// <param name="context">Optional context information for cryptographic operations.</param>
        /// <returns>A task that resolves to the generated signature.</returns>
        public static ValueTask<ReadOnlyMemory<byte>> SignP256Async(
            ReadOnlyMemory<byte> dataToSign,
            ReadOnlyMemory<byte> privateKey,
            string inputFormat,
            Func<ReadOnlyMemory<byte>, string, (string Format, string KeyType)[], (ReadOnlyMemory<byte> TransformedKeyMaterial, string OutputFormat)> keyMaterialTransformer,
            FrozenDictionary<string, object>? context)
        {
            return SignECDsaAsync(dataToSign, privateKey, inputFormat, keyMaterialTransformer, ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256, "NISTP256");
        }

        /// <summary>
        /// Signs data using the P-384 curve.
        /// </summary>
        public static ValueTask<ReadOnlyMemory<byte>> SignP384Async(
            ReadOnlyMemory<byte> dataToSign,
            ReadOnlyMemory<byte> privateKey,
            string inputFormat,
            Func<ReadOnlyMemory<byte>, string, (string Format, string KeyType)[], (ReadOnlyMemory<byte> TransformedKeyMaterial, string OutputFormat)> keyMaterialTransformer,
            FrozenDictionary<string, object>? context)
        {
            return SignECDsaAsync(dataToSign, privateKey, inputFormat, keyMaterialTransformer, ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384, "NISTP384");
        }

        /// <summary>
        /// Signs data using the P-521 curve.
        /// </summary>
        public static ValueTask<ReadOnlyMemory<byte>> SignP521Async(
            ReadOnlyMemory<byte> dataToSign,
            ReadOnlyMemory<byte> privateKey,
            string inputFormat,
            Func<ReadOnlyMemory<byte>, string, (string Format, string KeyType)[], (ReadOnlyMemory<byte> TransformedKeyMaterial, string OutputFormat)> keyMaterialTransformer,
            FrozenDictionary<string, object>? context)
        {
            return SignECDsaAsync(dataToSign, privateKey, inputFormat, keyMaterialTransformer, ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512, "NISTP521");
        }

        // Placeholder for other functions for RSA and HMAC
        // They will follow the same signature and callback pattern.
        // Examples include:
        // - Sign/VerifyRsaSha256Pkcs1Async
        // - Sign/VerifyHs256Async

        // Shared ECDSA Sign and Verify Logic
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
            var driverSupportedFormats = new[]
            {
                ("SubjectPublicKeyInfo", keyType),
                ("Raw", keyType)
            };

            var (transformedKeyMaterial, outputFormat) = keyMaterialTransformer(keyMaterial, inputFormat, driverSupportedFormats);

            if(!driverSupportedFormats.Any(pref => pref.Item1 == outputFormat && pref.Item2 == keyType))
            {
                throw new InvalidOperationException($"Key material format '{outputFormat}' or type '{keyType}' is not supported.");
            }

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
            var facilityPreferredFormats = new[]
            {
                ("Raw", keyType)
            };

            var (transformedKeyMaterial, outputFormat) = keyMaterialTransformer(privateKey, inputFormat, facilityPreferredFormats);

            if(!facilityPreferredFormats.Any(pref => pref.Item1 == outputFormat && pref.Item2 == keyType))
            {
                throw new InvalidOperationException($"Key material format '{outputFormat}' or type '{keyType}' is not supported.");
            }

            using var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = curve,
                D = transformedKeyMaterial.ToArray()
            });

            var signature = ecdsa.SignData(dataToSign.Span, hashAlgorithmName);
            return ValueTask.FromResult(new ReadOnlyMemory<byte>(signature));
        }
    }
}
