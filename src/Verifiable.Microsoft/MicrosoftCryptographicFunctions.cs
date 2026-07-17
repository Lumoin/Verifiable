using System;
using System.Buffers;
using System.Collections.Frozen;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Provider;
using CryptoLibraryInfo = Verifiable.Cryptography.Provider.CryptoLibrary;

namespace Verifiable.Microsoft
{
    /// <summary>
    /// Provides cryptographic functions for digital signatures using Microsoft cryptographic libraries.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The caller is responsible for disposing the returned objects.")]
    public static class MicrosoftCryptographicFunctions
    {
        private static ProviderLibrary ProviderLib { get; } = new(
            typeof(MicrosoftCryptographicFunctions).Assembly.GetName().Name
                ?? "Verifiable.Microsoft",
            typeof(MicrosoftCryptographicFunctions).Assembly.GetName().Version?.ToString()
                ?? "Unknown");

        private static CryptoLibraryInfo CryptoLib { get; } = new(
            "System.Security.Cryptography",
            typeof(RandomNumberGenerator).Assembly.GetName().Version?.ToString()
                ?? System.Environment.Version.ToString());

        private static ProviderClass ProviderCls { get; } =
            new(nameof(MicrosoftCryptographicFunctions));


        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyP256Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyECDsa(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.P256, ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256);
        }

        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignP256Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignECDsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256, CryptoTags.P256Signature);
        }

        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyP384Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyECDsa(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.P384, ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384);
        }

        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignP384Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignECDsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384, CryptoTags.P384Signature);
        }

        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyP521Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyECDsa(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.P521, ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512);
        }

        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignP521Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignECDsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512, CryptoTags.P521Signature);
        }

        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifySecp256k1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyECDsa(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.Secp256k1, ECCurve.CreateFromFriendlyName("secP256k1"), HashAlgorithmName.SHA256);
        }

        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignSecp256k1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignECDsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, ECCurve.CreateFromFriendlyName("secP256k1"), HashAlgorithmName.SHA256, CryptoTags.Secp256k1Signature);
        }

        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsa2048Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, CryptoTags.Rsa2048Signature);
        }

        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsa2048Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.Rsa2048, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsa4096Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, CryptoTags.Rsa4096Signature);
        }

        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsa4096Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.Rsa4096, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha256Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.RsaSha256, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha256Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, CryptoTags.RsaSha256Pkcs1Signature);
        }

        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha256PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.RsaSha256Pss, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }

        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha256PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA256, RSASignaturePadding.Pss, CryptoTags.RsaSha256PssSignature);
        }

        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha384Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.RsaSha384, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
        }

        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha384Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1, CryptoTags.RsaSha384Pkcs1Signature);
        }

        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha384PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.RsaSha384Pss, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
        }

        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha384PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA384, RSASignaturePadding.Pss, CryptoTags.RsaSha384PssSignature);
        }

        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha512Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.RsaSha512, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        }

        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha512Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1, CryptoTags.RsaSha512Pkcs1Signature);
        }

        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha512PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.RsaSha512Pss, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
        }

        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha512PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA512, RSASignaturePadding.Pss, CryptoTags.RsaSha512PssSignature);
        }

        private static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyECDsa(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, CryptoAlgorithm algorithm, ECCurve curve, HashAlgorithmName hashAlgorithmName)
        {
            ProviderOperation operation = new(nameof(VerifyECDsa));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Verify);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                activity.SetTag(CryptoTelemetry.Signature.Algorithm, "ECDSA");
                activity.SetTag(CryptoTelemetry.Signature.Curve, MapCurveDisplay(curve));
            }

            EllipticCurveTypes curveType = curve.Oid.FriendlyName!.Equals("secP256k1", StringComparison.Ordinal)
                ? EllipticCurveTypes.Secp256k1
                : EllipticCurveTypes.NistCurves;

            //Accept either SEC1 public-key encoding: the compressed form the library uses for verification keys,
            //or the uncompressed point an eMRTD SubjectPublicKeyInfo (EF.DG14 / EF.DG15) carries.
            //NormalizeToUncompressed decompresses a compressed point and copies an uncompressed one through, so
            //both encodings verify — mirroring the BouncyCastle verifier, which already accepts both via
            //DecodePoint. Malformed key material or an off-curve point verifies as false rather than throwing,
            //keeping verification fail-closed.
            byte[] uncompressedPoint;
            try
            {
                uncompressedPoint = EllipticCurveUtilities.NormalizeToUncompressed(publicKeyMaterial, curveType);
            }
            catch(ArgumentException)
            {
                return CompletedVerification(false, algorithm, dataToVerify.Length, VerificationOutcome.Error);
            }

            ECParameters parameters = new()
            {
                Curve = curve,
                Q = new ECPoint
                {
                    X = EllipticCurveUtilities.SliceXCoordinate(uncompressedPoint).ToArray(),
                    Y = EllipticCurveUtilities.SliceYCoordinate(uncompressedPoint).ToArray()
                }
            };

            try
            {
                using ECDsa key = ECDsa.Create(parameters);
                bool isVerified = key.VerifyData(dataToVerify, signature, hashAlgorithmName);

                return CompletedVerification(isVerified, algorithm, dataToVerify.Length, isVerified ? VerificationOutcome.Valid : VerificationOutcome.Invalid);
            }
            catch(CryptographicException)
            {
                return CompletedVerification(false, algorithm, dataToVerify.Length, VerificationOutcome.Error);
            }
        }


        private static ValueTask<(Signature Signature, CryptoEvent? Event)> SignECDsa(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, ECCurve curve, HashAlgorithmName hashAlgorithmName, Tag signatureTag)
        {
            ProviderOperation operation = new(nameof(SignECDsa));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Sign);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                activity.SetTag(CryptoTelemetry.Signature.Algorithm, "ECDSA");
                activity.SetTag(CryptoTelemetry.Signature.Curve, MapCurveDisplay(curve));
            }

            //ECParameters.D is a byte[]-typed BCL struct field, so importing the raw scalar always
            //needs a byte[] copy; it is zeroed in finally once ECDsa.Create has imported it, and the
            //ECDsa handle is disposed deterministically rather than left for the GC.
            byte[] privateKeyArray = privateKeyBytes.ToArray();
            byte[] signatureBytes;
            try
            {
                using ECDsa key = ECDsa.Create(new ECParameters
                {
                    Curve = curve,
                    D = privateKeyArray
                });

                signatureBytes = key.SignData(dataToSign, hashAlgorithmName);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(privateKeyArray);
            }

            var memoryPooledSignature = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryPooledSignature.Memory.Span);

            var signatureResult = new Signature(memoryPooledSignature, signatureTag);
            CryptoEvent evt = SignatureProducedEvent.Create(
                signatureTag.Get<CryptoAlgorithm>(), dataToSign.Length, signatureBytes.Length, CryptoLib.Name);

            return ValueTask.FromResult<(Signature, CryptoEvent?)>((signatureResult, evt));
        }

        private static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaAsync(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, CryptoAlgorithm algorithm, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            ProviderOperation operation = new(nameof(VerifyRsaAsync));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Verify);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                activity.SetTag(CryptoTelemetry.Signature.Algorithm, "RSA");
            }

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

                bool isVerified = rsa.VerifyData(dataToVerify, signature, hashAlgorithmName, padding);

                return CompletedVerification(isVerified, algorithm, dataToVerify.Length, isVerified ? VerificationOutcome.Valid : VerificationOutcome.Invalid);
            }
        }

        private static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsa(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Tag signatureTag)
        {
            ProviderOperation operation = new(nameof(SignRsa));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Sign);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                activity.SetTag(CryptoTelemetry.Signature.Algorithm, "RSA");
            }

            using(RSA rsa = RSA.Create())
            {
                rsa.ImportRSAPrivateKey(privateKeyBytes, out _);
                byte[] signatureBytes = rsa.SignData(dataToSign, hashAlgorithmName, padding);
                IMemoryOwner<byte> memoryPooledSignature = signaturePool.Rent(signatureBytes.Length);
                signatureBytes.CopyTo(memoryPooledSignature.Memory.Span);

                var signatureResult = new Signature(memoryPooledSignature, signatureTag);
                CryptoEvent evt = SignatureProducedEvent.Create(
                    signatureTag.Get<CryptoAlgorithm>(), dataToSign.Length, signatureBytes.Length, CryptoLib.Name);

                return ValueTask.FromResult<(Signature, CryptoEvent?)>((signatureResult, evt));
            }
        }


        /// <summary>
        /// Builds the completed <see cref="ValueTask{TResult}"/> tuple a <see cref="VerificationDelegate"/>
        /// returns: the verification result paired with the <see cref="VerificationCompletedEvent"/> describing it.
        /// </summary>
        private static ValueTask<(bool IsVerified, CryptoEvent? Event)> CompletedVerification(bool isVerified, CryptoAlgorithm algorithm, int dataLength, VerificationOutcome outcome)
        {
            CryptoEvent evt = VerificationCompletedEvent.Create(algorithm, outcome, dataLength, CryptoLib.Name);

            return ValueTask.FromResult<(bool, CryptoEvent?)>((isVerified, evt));
        }


        private static string MapCurveDisplay(ECCurve curve) =>
            curve.Oid.FriendlyName switch
            {
                "nistP256" => "P-256",
                "nistP384" => "P-384",
                "nistP521" => "P-521",
                "secP256k1" => "secp256k1",
                _ => curve.Oid.FriendlyName ?? "Unknown"
            };
    }
}