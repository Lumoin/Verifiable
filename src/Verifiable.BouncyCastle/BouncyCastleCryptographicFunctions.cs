using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using System;
using System.Buffers;
using System.Collections.Frozen;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Provider;
using CryptoLibraryInfo = Verifiable.Cryptography.Provider.CryptoLibrary;

namespace Verifiable.BouncyCastle
{
    /// <summary>
    /// Provides cryptographic signing and verification functions using the BouncyCastle library.
    /// This includes Ed25519, ECDSA (P-256, P-384, P-521, secp256k1), RSA PKCS#1 v1.5, RSA-PSS,
    /// and X25519 key agreement. All signing operations produce pool-allocated signatures tagged
    /// with their algorithm. All ECDSA signatures use the fixed-size IEEE P1363 (r || s) encoding.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The caller is responsible for disposing the returned objects.")]
    public static class BouncyCastleCryptographicFunctions
    {
        private static ProviderLibrary ProviderLib { get; } = new(
            typeof(BouncyCastleCryptographicFunctions).Assembly.GetName().Name ?? "Verifiable.BouncyCastle",
            typeof(BouncyCastleCryptographicFunctions).Assembly.GetName().Version?.ToString() ?? "Unknown");

        //BouncyCastle is an independently versioned NuGet package — its assembly
        //version is the most meaningful CBOM identifier.
        private static CryptoLibraryInfo CryptoLib { get; } = new(
            "Org.BouncyCastle.Cryptography",
            typeof(Org.BouncyCastle.Security.SecureRandom).Assembly.GetName().Version?.ToString() ?? "Unknown");

        private static ProviderClass ProviderCls { get; } = new(nameof(BouncyCastleCryptographicFunctions));


        /// <summary>
        /// Signs data using Ed25519 (EdDSA over Curve25519).
        /// </summary>
        /// <param name="privateKeyBytes">The 32-byte Ed25519 private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the 64-byte signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.Ed25519Signature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignEd25519Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);

            ProviderOperation operation = new(nameof(SignEd25519Async));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Sign);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                activity.SetTag(CryptoTelemetry.Signature.Algorithm, "Ed25519");
            }

            //The span ctor copies the scalar into BouncyCastle's own buffer — no naked byte[]
            //of private-key material for us to track and zero.
            AsymmetricKeyParameter keyParameter = new Ed25519PrivateKeyParameters(privateKeyBytes.Span);
            var privateKey = (Ed25519PrivateKeyParameters)keyParameter;

            var signer = new Ed25519Signer();
            signer.Init(forSigning: true, privateKey);
            signer.BlockUpdate(dataToSign.ToArray(), off: 0, len: dataToSign.Length);

            var signature = (ReadOnlySpan<byte>)signer.GenerateSignature();
            var memoryPooledSignature = signaturePool.Rent(signature.Length);
            signature.CopyTo(memoryPooledSignature.Memory.Span);

            var signatureResult = new Signature(memoryPooledSignature, CryptoTags.Ed25519Signature);
            CryptoEvent evt = SignatureProducedEvent.Create(
                CryptoAlgorithm.Ed25519, dataToSign.Length, signature.Length, CryptoLib.Name);

            return ValueTask.FromResult<(Signature, CryptoEvent?)>((signatureResult, evt));
        }


        /// <summary>
        /// Verifies an Ed25519 signature.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The 64-byte Ed25519 signature to verify.</param>
        /// <param name="publicKeyMaterial">The 32-byte Ed25519 public key.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyEd25519Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ProviderOperation operation = new(nameof(VerifyEd25519Async));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Verify);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                activity.SetTag(CryptoTelemetry.Signature.Algorithm, "Ed25519");
            }

            var publicKey = new Ed25519PublicKeyParameters(publicKeyMaterial.ToArray(), 0);
            var validator = new Ed25519Signer();
            validator.Init(forSigning: false, publicKey);
            validator.BlockUpdate(dataToVerify.ToArray(), off: 0, len: dataToVerify.Length);

            bool isVerified = validator.VerifySignature(signature.ToArray());
            CryptoEvent evt = VerificationCompletedEvent.Create(
                CryptoAlgorithm.Ed25519, isVerified ? VerificationOutcome.Valid : VerificationOutcome.Invalid, dataToVerify.Length, CryptoLib.Name);

            return ValueTask.FromResult<(bool, CryptoEvent?)>((isVerified, evt));
        }


        /// <summary>
        /// Signs data using ECDSA with the P-256 (secp256r1) curve and SHA-256.
        /// </summary>
        /// <param name="privateKeyBytes">The 32-byte P-256 private key scalar.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the 64-byte signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.P256Signature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignP256Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "secp256r1", CryptoTags.P256Signature, 32);
        }


        /// <summary>
        /// Verifies an ECDSA signature produced with the P-256 (secp256r1) curve and SHA-256.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The 64-byte IEEE P1363 signature to verify.</param>
        /// <param name="publicKeyMaterial">The compressed or uncompressed P-256 public key.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyP256Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.P256, "secp256r1", 32);
        }


        /// <summary>
        /// Signs data using ECDSA with the P-384 (secp384r1) curve and SHA-384.
        /// </summary>
        /// <param name="privateKeyBytes">The 48-byte P-384 private key scalar.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the 96-byte signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.P384Signature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignP384Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "secp384r1", CryptoTags.P384Signature, 48);
        }


        /// <summary>
        /// Verifies an ECDSA signature produced with the P-384 (secp384r1) curve and SHA-384.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The 96-byte IEEE P1363 signature to verify.</param>
        /// <param name="publicKeyMaterial">The compressed or uncompressed P-384 public key.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyP384Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.P384, "secp384r1", 48);
        }


        /// <summary>
        /// Signs data using ECDSA with the P-521 (secp521r1) curve and SHA-512.
        /// </summary>
        /// <param name="privateKeyBytes">The 66-byte P-521 private key scalar.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the 132-byte signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.P521Signature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignP521Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "secp521r1", CryptoTags.P521Signature, 66);
        }


        /// <summary>
        /// Verifies an ECDSA signature produced with the P-521 (secp521r1) curve and SHA-512.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The 132-byte IEEE P1363 signature to verify.</param>
        /// <param name="publicKeyMaterial">The compressed or uncompressed P-521 public key.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyP521Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.P521, "secp521r1", 66);
        }


        /// <summary>
        /// Signs data using ECDSA with the Brainpool P-224r1 curve and SHA-224.
        /// </summary>
        /// <remarks>
        /// brainpoolP224r1 has no fully-specified ECDSA registration in RFC 9864 / IANA COSE (it is added
        /// here as an ECDH/key-agreement curve, notably for eMRTD Chip Authentication), so there is no COSE
        /// algorithm identifier for this signature; SHA-224 is the field-matched hash.
        /// </remarks>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignBrainpoolP224r1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "brainpoolP224r1", CryptoTags.BrainpoolP224r1Signature, 28);
        }


        /// <summary>
        /// Verifies an ECDSA signature produced with the Brainpool P-224r1 curve and SHA-224.
        /// </summary>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyBrainpoolP224r1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.BrainpoolP224r1, "brainpoolP224r1", 28);
        }


        /// <summary>
        /// Signs data using ECDSA with the Brainpool P-256r1 curve and SHA-256
        /// (RFC 9864 fully-specified ECDSA <c>ESB256</c>, COSE alg <c>-265</c>).
        /// </summary>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignBrainpoolP256r1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "brainpoolP256r1", CryptoTags.BrainpoolP256r1Signature, 32);
        }


        /// <summary>
        /// Verifies an ECDSA signature produced with the Brainpool P-256r1 curve and SHA-256.
        /// </summary>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyBrainpoolP256r1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.BrainpoolP256r1, "brainpoolP256r1", 32);
        }


        /// <summary>
        /// Signs data using ECDSA with the Brainpool P-320r1 curve and SHA-384
        /// (RFC 9864 fully-specified ECDSA <c>ESB320</c>, COSE alg <c>-266</c>).
        /// </summary>
        /// <remarks>
        /// The hash size (SHA-384, 48 bytes) deliberately exceeds the field size
        /// (320 bits, 40 bytes) per RFC 9864 §5; ECDSA truncates the hash to the
        /// field bit length internally during signing.
        /// </remarks>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignBrainpoolP320r1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "brainpoolP320r1", CryptoTags.BrainpoolP320r1Signature, 40);
        }


        /// <summary>
        /// Verifies an ECDSA signature produced with the Brainpool P-320r1 curve and SHA-384.
        /// </summary>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyBrainpoolP320r1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.BrainpoolP320r1, "brainpoolP320r1", 40);
        }


        /// <summary>
        /// Signs data using ECDSA with the Brainpool P-384r1 curve and SHA-384
        /// (RFC 9864 fully-specified ECDSA <c>ESB384</c>, COSE alg <c>-267</c>).
        /// </summary>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignBrainpoolP384r1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "brainpoolP384r1", CryptoTags.BrainpoolP384r1Signature, 48);
        }


        /// <summary>
        /// Verifies an ECDSA signature produced with the Brainpool P-384r1 curve and SHA-384.
        /// </summary>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyBrainpoolP384r1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.BrainpoolP384r1, "brainpoolP384r1", 48);
        }


        /// <summary>
        /// Signs data using ECDSA with the Brainpool P-512r1 curve and SHA-512
        /// (RFC 9864 fully-specified ECDSA <c>ESB512</c>, COSE alg <c>-268</c>).
        /// </summary>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignBrainpoolP512r1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "brainpoolP512r1", CryptoTags.BrainpoolP512r1Signature, 64);
        }


        /// <summary>
        /// Verifies an ECDSA signature produced with the Brainpool P-512r1 curve and SHA-512.
        /// </summary>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyBrainpoolP512r1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.BrainpoolP512r1, "brainpoolP512r1", 64);
        }


        /// <summary>
        /// Signs data using ECDSA with the secp256k1 curve and SHA-256.
        /// </summary>
        /// <param name="privateKeyBytes">The 32-byte secp256k1 private key scalar.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the 64-byte signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.Secp256k1Signature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignSecp256k1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "secp256k1", CryptoTags.Secp256k1Signature, 32);
        }


        /// <summary>
        /// Verifies an ECDSA signature produced with the secp256k1 curve and SHA-256.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The 64-byte IEEE P1363 signature to verify.</param>
        /// <param name="publicKeyMaterial">The compressed or uncompressed secp256k1 public key.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifySecp256k1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.Secp256k1, "secp256k1", 32);
        }


        /// <summary>
        /// Derives a shared secret using X25519 (Curve25519 Diffie-Hellman key agreement).
        /// The resulting 32-byte shared secret is allocated from the provided memory pool
        /// and the intermediate secret is cleared from memory immediately after copying.
        /// </summary>
        /// <param name="privateKeyBytes">The 32-byte X25519 private key.</param>
        /// <param name="publicKeyBytes">The 32-byte X25519 public key of the other party.</param>
        /// <param name="memoryPool">The memory pool used to allocate the shared secret buffer.</param>
        /// <returns>A pool-allocated buffer containing the 32-byte shared secret.</returns>
        /// <exception cref="InvalidOperationException">Thrown if the rented buffer is too small.</exception>
        public static ValueTask<IMemoryOwner<byte>> DeriveX25519SharedSecretAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> publicKeyBytes, MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            //The span ctors copy the scalar and the peer's point into BouncyCastle's own buffers —
            //no naked byte[] of private-key material for us to track and zero.
            var privateKeyParams = new X25519PrivateKeyParameters(privateKeyBytes.Span);
            var publicKeyParams = new X25519PublicKeyParameters(publicKeyBytes.Span);

            var agreement = new X25519Agreement();
            agreement.Init(privateKeyParams);

            var sharedSecret = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(publicKeyParams, sharedSecret, 0);

            var memoryOwner = memoryPool.Rent(sharedSecret.Length);
            if(memoryOwner.Memory.Length < sharedSecret.Length)
            {
                memoryOwner.Dispose();
                throw new InvalidOperationException("The rented buffer size is smaller than the requested size.");
            }

            sharedSecret.CopyTo(memoryOwner.Memory.Span);
            Array.Clear(sharedSecret, 0, sharedSecret.Length);

            return ValueTask.FromResult(memoryOwner);
        }


        /// <summary>
        /// Signs data using RSA 2048 with PKCS#1 v1.5 padding and SHA-256.
        /// </summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA 2048 private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.Rsa2048Signature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsa2048Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsaPkcs1Async(privateKeyBytes, dataToSign, signaturePool, new Sha256Digest(), CryptoTags.Rsa2048Signature);
        }


        /// <summary>
        /// Verifies an RSA 2048 PKCS#1 v1.5 signature using SHA-256.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The RSA signature to verify.</param>
        /// <param name="publicKeyMaterial">The DER-encoded RSA 2048 public key.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsa2048Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaPkcs1Async(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.Rsa2048, new Sha256Digest());
        }


        /// <summary>
        /// Signs data using RSA 4096 with PKCS#1 v1.5 padding and SHA-256.
        /// </summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA 4096 private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.Rsa4096Signature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsa4096Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsaPkcs1Async(privateKeyBytes, dataToSign, signaturePool, new Sha256Digest(), CryptoTags.Rsa4096Signature);
        }


        /// <summary>
        /// Verifies an RSA 4096 PKCS#1 v1.5 signature using SHA-256.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The RSA signature to verify.</param>
        /// <param name="publicKeyMaterial">The DER-encoded RSA 4096 public key.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsa4096Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaPkcs1Async(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.Rsa4096, new Sha256Digest());
        }


        /// <summary>
        /// Signs data using RSA with PKCS#1 v1.5 padding and SHA-256.
        /// </summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.RsaSha256Pkcs1Signature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha256Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsaPkcs1Async(privateKeyBytes, dataToSign, signaturePool, new Sha256Digest(), CryptoTags.RsaSha256Pkcs1Signature);
        }


        /// <summary>
        /// Verifies an RSA PKCS#1 v1.5 signature using SHA-256.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The RSA signature to verify.</param>
        /// <param name="publicKeyMaterial">The DER-encoded RSA public key.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha256Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaPkcs1Async(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.RsaSha256, new Sha256Digest());
        }


        /// <summary>
        /// Signs data using RSA with PSS padding and SHA-256.
        /// </summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.RsaSha256PssSignature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha256PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsaPssAsync(privateKeyBytes, dataToSign, signaturePool, new Sha256Digest(), CryptoTags.RsaSha256PssSignature);
        }


        /// <summary>
        /// Verifies an RSA PSS signature using SHA-256.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The RSA signature to verify.</param>
        /// <param name="publicKeyMaterial">The DER-encoded RSA public key.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha256PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaPssAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.RsaSha256Pss, new Sha256Digest());
        }


        /// <summary>
        /// Signs data using RSA with PKCS#1 v1.5 padding and SHA-384.
        /// </summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.RsaSha384Pkcs1Signature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha384Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsaPkcs1Async(privateKeyBytes, dataToSign, signaturePool, new Sha384Digest(), CryptoTags.RsaSha384Pkcs1Signature);
        }


        /// <summary>
        /// Verifies an RSA PKCS#1 v1.5 signature using SHA-384.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The RSA signature to verify.</param>
        /// <param name="publicKeyMaterial">The DER-encoded RSA public key.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha384Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaPkcs1Async(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.RsaSha384, new Sha384Digest());
        }


        /// <summary>
        /// Signs data using RSA with PSS padding and SHA-384.
        /// </summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.RsaSha384PssSignature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha384PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsaPssAsync(privateKeyBytes, dataToSign, signaturePool, new Sha384Digest(), CryptoTags.RsaSha384PssSignature);
        }


        /// <summary>
        /// Verifies an RSA PSS signature using SHA-384.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The RSA signature to verify.</param>
        /// <param name="publicKeyMaterial">The DER-encoded RSA public key.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha384PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaPssAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.RsaSha384Pss, new Sha384Digest());
        }


        /// <summary>
        /// Signs data using RSA with PKCS#1 v1.5 padding and SHA-512.
        /// </summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.RsaSha512Pkcs1Signature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha512Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsaPkcs1Async(privateKeyBytes, dataToSign, signaturePool, new Sha512Digest(), CryptoTags.RsaSha512Pkcs1Signature);
        }


        /// <summary>
        /// Verifies an RSA PKCS#1 v1.5 signature using SHA-512.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The RSA signature to verify.</param>
        /// <param name="publicKeyMaterial">The DER-encoded RSA public key.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha512Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaPkcs1Async(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.RsaSha512, new Sha512Digest());
        }


        /// <summary>
        /// Signs data using RSA with PSS padding and SHA-512.
        /// </summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.RsaSha512PssSignature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha512PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsaPssAsync(privateKeyBytes, dataToSign, signaturePool, new Sha512Digest(), CryptoTags.RsaSha512PssSignature);
        }


        /// <summary>
        /// Verifies an RSA PSS signature using SHA-512.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The RSA signature to verify.</param>
        /// <param name="publicKeyMaterial">The DER-encoded RSA public key.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha512PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaPssAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.RsaSha512Pss, new Sha512Digest());
        }


        /// <summary>
        /// Signs data using ML-DSA-44 in deterministic mode (security level 2).
        /// </summary>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of Signature is transferred to the caller.")]
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignMlDsa44Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignMlDsaAsync(MLDsaParameters.ml_dsa_44, privateKeyBytes, dataToSign, signaturePool, CryptoTags.MlDsa44Signature);
        }


        /// <summary>
        /// Verifies an ML-DSA-44 signature (security level 2).
        /// </summary>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyMlDsa44Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyMlDsaAsync(MLDsaParameters.ml_dsa_44, dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.MlDsa44);
        }


        /// <summary>
        /// Signs data using ML-DSA-65 in deterministic mode (security level 3).
        /// </summary>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of Signature is transferred to the caller.")]
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignMlDsa65Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignMlDsaAsync(MLDsaParameters.ml_dsa_65, privateKeyBytes, dataToSign, signaturePool, CryptoTags.MlDsa65Signature);
        }


        /// <summary>
        /// Verifies an ML-DSA-65 signature (security level 3).
        /// </summary>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyMlDsa65Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyMlDsaAsync(MLDsaParameters.ml_dsa_65, dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.MlDsa65);
        }


        /// <summary>
        /// Signs data using ML-DSA-87 in deterministic mode (security level 5).
        /// </summary>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of Signature is transferred to the caller.")]
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignMlDsa87Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignMlDsaAsync(MLDsaParameters.ml_dsa_87, privateKeyBytes, dataToSign, signaturePool, CryptoTags.MlDsa87Signature);
        }


        /// <summary>
        /// Verifies an ML-DSA-87 signature (security level 5).
        /// </summary>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyMlDsa87Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyMlDsaAsync(MLDsaParameters.ml_dsa_87, dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.MlDsa87);
        }


        /// <summary>
        /// Encapsulates a shared secret using ML-KEM-512 (security level 1).
        /// Produces a ciphertext (768 bytes) and a shared secret (32 bytes).
        /// </summary>
        public static (IMemoryOwner<byte> Ciphertext, IMemoryOwner<byte> SharedSecret) EncapsulateMlKem512(ReadOnlyMemory<byte> publicKeyBytes, MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return EncapsulateMlKem(MLKemParameters.ml_kem_512, publicKeyBytes, memoryPool);
        }


        /// <summary>
        /// Decapsulates a shared secret from ML-KEM-512 ciphertext (security level 1).
        /// </summary>
        public static IMemoryOwner<byte> DecapsulateMlKem512(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> ciphertext, MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return DecapsulateMlKem(MLKemParameters.ml_kem_512, privateKeyBytes, ciphertext, memoryPool);
        }


        /// <summary>
        /// Encapsulates a shared secret using ML-KEM-768 (security level 3).
        /// Produces a ciphertext (1088 bytes) and a shared secret (32 bytes).
        /// </summary>
        public static (IMemoryOwner<byte> Ciphertext, IMemoryOwner<byte> SharedSecret) EncapsulateMlKem768(ReadOnlyMemory<byte> publicKeyBytes, MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return EncapsulateMlKem(MLKemParameters.ml_kem_768, publicKeyBytes, memoryPool);
        }


        /// <summary>
        /// Decapsulates a shared secret from ML-KEM-768 ciphertext (security level 3).
        /// </summary>
        public static IMemoryOwner<byte> DecapsulateMlKem768(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> ciphertext, MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return DecapsulateMlKem(MLKemParameters.ml_kem_768, privateKeyBytes, ciphertext, memoryPool);
        }


        /// <summary>
        /// Encapsulates a shared secret using ML-KEM-1024 (security level 5).
        /// Produces a ciphertext (1568 bytes) and a shared secret (32 bytes).
        /// </summary>
        public static (IMemoryOwner<byte> Ciphertext, IMemoryOwner<byte> SharedSecret) EncapsulateMlKem1024(ReadOnlyMemory<byte> publicKeyBytes, MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return EncapsulateMlKem(MLKemParameters.ml_kem_1024, publicKeyBytes, memoryPool);
        }


        /// <summary>
        /// Decapsulates a shared secret from ML-KEM-1024 ciphertext (security level 5).
        /// </summary>
        public static IMemoryOwner<byte> DecapsulateMlKem1024(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> ciphertext, MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return DecapsulateMlKem(MLKemParameters.ml_kem_1024, privateKeyBytes, ciphertext, memoryPool);
        }


        /// <summary>
        /// Signs data using ECDSA with deterministic k generation (RFC 6979) for the specified curve.
        /// The data is hashed with the curve-appropriate hash algorithm before signing. The resulting
        /// signature is encoded in fixed-size IEEE P1363 format (r || s) where each component is
        /// zero-padded to <paramref name="componentSize"/> bytes.
        /// </summary>
        /// <param name="privateKeyBytes">The raw private key scalar bytes.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="curveName">The SEC curve name (e.g., "secp256r1", "secp256k1").</param>
        /// <param name="signatureTag">The tag identifying the signature algorithm.</param>
        /// <param name="componentSize">The byte length of each signature component (r and s).</param>
        /// <returns>A pool-allocated signature in IEEE P1363 encoding.</returns>
        private static ValueTask<(Signature Signature, CryptoEvent? Event)> SignEcdsaAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, string curveName, Tag signatureTag, int componentSize)
        {
            ProviderOperation operation = new(nameof(SignEcdsaAsync));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Sign);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                activity.SetTag(CryptoTelemetry.Signature.Algorithm, "ECDSA");
                activity.SetTag(CryptoTelemetry.Signature.Curve, MapEcdsaCurve(curveName));
            }

            X9ECParameters curveParams = ECNamedCurveTable.GetByName(curveName);
            ECDomainParameters domainParams = new(curveParams.Curve, curveParams.G, curveParams.N, curveParams.H);

            //The span ctor copies the scalar into BouncyCastle's own immutable magnitude — no naked
            //byte[] of private-key material for us to track and zero.
            BigInteger d = new(1, privateKeyBytes.Span);
            ECPrivateKeyParameters privateKey = new(d, domainParams);

            byte[] hash = ComputeHash(dataToSign.Span, curveName);

            ECDsaSigner signer = new(new HMacDsaKCalculator(GetDigest(curveName)));
            signer.Init(forSigning: true, privateKey);

            BigInteger[] signatureComponents = signer.GenerateSignature(hash);
            BigInteger r = signatureComponents[0];
            BigInteger s = signatureComponents[1];

            //Encode r and s into fixed-size IEEE P1363 format, left-padded with zeros.
            byte[] signatureBytes = new byte[componentSize * 2];
            byte[] rBytes = r.ToByteArrayUnsigned();
            byte[] sBytes = s.ToByteArrayUnsigned();

            Array.Copy(rBytes, 0, signatureBytes, componentSize - rBytes.Length, rBytes.Length);
            Array.Copy(sBytes, 0, signatureBytes, componentSize * 2 - sBytes.Length, sBytes.Length);

            IMemoryOwner<byte> memoryPooledSignature = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryPooledSignature.Memory.Span);

            var signatureResult = new Signature(memoryPooledSignature, signatureTag);
            CryptoEvent evt = SignatureProducedEvent.Create(
                signatureTag.Get<CryptoAlgorithm>(), dataToSign.Length, signatureBytes.Length, CryptoLib.Name);

            return ValueTask.FromResult<(Signature, CryptoEvent?)>((signatureResult, evt));
        }


        /// <summary>
        /// Verifies an ECDSA signature in IEEE P1363 encoding against the specified curve.
        /// The public key may be in compressed or uncompressed SEC1 encoding; BouncyCastle
        /// handles both transparently via <c>DecodePoint</c>.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The IEEE P1363-encoded signature (r || s).</param>
        /// <param name="publicKeyMaterial">The SEC1-encoded public key (compressed or uncompressed).</param>
        /// <param name="curveName">The SEC curve name (e.g., "secp256r1", "secp256k1").</param>
        /// <param name="componentSize">The byte length of each signature component (r and s).</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        private static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyEcdsaAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, CryptoAlgorithm algorithm, string curveName, int componentSize)
        {
            ProviderOperation operation = new(nameof(VerifyEcdsaAsync));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Verify);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                activity.SetTag(CryptoTelemetry.Signature.Algorithm, "ECDSA");
                activity.SetTag(CryptoTelemetry.Signature.Curve, MapEcdsaCurve(curveName));
            }

            X9ECParameters curveParams = ECNamedCurveTable.GetByName(curveName);
            ECDomainParameters domainParams = new(curveParams.Curve, curveParams.G, curveParams.N, curveParams.H);

            Org.BouncyCastle.Math.EC.ECPoint point = curveParams.Curve.DecodePoint(publicKeyMaterial.ToArray());
            ECPublicKeyParameters publicKey = new(point, domainParams);

            byte[] hash = ComputeHash(dataToVerify.Span, curveName);

            //Split the fixed-size IEEE P1363 signature back into r and s components.
            ReadOnlySpan<byte> signatureSpan = signature.Span;
            byte[] rBytes = signatureSpan.Slice(0, componentSize).ToArray();
            byte[] sBytes = signatureSpan.Slice(componentSize, componentSize).ToArray();

            BigInteger r = new(1, rBytes);
            BigInteger s = new(1, sBytes);

            ECDsaSigner verifier = new();
            verifier.Init(forSigning: false, publicKey);

            bool isVerified = verifier.VerifySignature(hash, r, s);
            CryptoEvent evt = VerificationCompletedEvent.Create(
                algorithm, isVerified ? VerificationOutcome.Valid : VerificationOutcome.Invalid, dataToVerify.Length, CryptoLib.Name);

            return ValueTask.FromResult<(bool, CryptoEvent?)>((isVerified, evt));
        }


        /// <summary>
        /// Signs data using RSA with PKCS#1 v1.5 signature padding.
        /// The private key is expected in PKCS#1 DER format (<c>RSAPrivateKey</c>),
        /// matching the output of <c>RSA.ExportRSAPrivateKey()</c> and the
        /// BouncyCastle key material creator.
        /// </summary>
        /// <param name="privateKeyBytes">The PKCS#1 DER-encoded RSA private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="digest">The hash digest to use (e.g., SHA-256, SHA-384, SHA-512).</param>
        /// <param name="signatureTag">The tag identifying the signature algorithm.</param>
        /// <returns>A pool-allocated RSA PKCS#1 v1.5 signature.</returns>
        private static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaPkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, IDigest digest, Tag signatureTag)
        {
            ProviderOperation operation = new(nameof(SignRsaPkcs1Async));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Sign);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                activity.SetTag(CryptoTelemetry.Signature.Algorithm, "RSA");
            }

            RsaPrivateCrtKeyParameters privateKey = ParseRsaPrivateKey(privateKeyBytes.Span);
            RsaDigestSigner signer = new(digest);
            signer.Init(forSigning: true, privateKey);
            signer.BlockUpdate(dataToSign.ToArray(), 0, dataToSign.Length);

            byte[] signatureBytes = signer.GenerateSignature();
            IMemoryOwner<byte> memoryPooledSignature = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryPooledSignature.Memory.Span);

            var signatureResult = new Signature(memoryPooledSignature, signatureTag);
            CryptoEvent evt = SignatureProducedEvent.Create(
                signatureTag.Get<CryptoAlgorithm>(), dataToSign.Length, signatureBytes.Length, CryptoLib.Name);

            return ValueTask.FromResult<(Signature, CryptoEvent?)>((signatureResult, evt));
        }


        /// <summary>
        /// Verifies an RSA PKCS#1 v1.5 signature. The public key is expected in the
        /// DID-compatible format produced by <see cref="RsaUtilities.Encode"/>.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The RSA PKCS#1 v1.5 signature to verify.</param>
        /// <param name="publicKeyMaterial">The encoded RSA public key.</param>
        /// <param name="digest">The hash digest to use (e.g., SHA-256, SHA-384, SHA-512).</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        private static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaPkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, CryptoAlgorithm algorithm, IDigest digest)
        {
            ProviderOperation operation = new(nameof(VerifyRsaPkcs1Async));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Verify);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                activity.SetTag(CryptoTelemetry.Signature.Algorithm, "RSA");
            }

            RsaKeyParameters publicKey = ParseRsaPublicKey(publicKeyMaterial.Span);
            RsaDigestSigner verifier = new(digest);
            verifier.Init(forSigning: false, publicKey);
            verifier.BlockUpdate(dataToVerify.ToArray(), 0, dataToVerify.Length);

            bool isVerified = verifier.VerifySignature(signature.ToArray());
            CryptoEvent evt = VerificationCompletedEvent.Create(
                algorithm, isVerified ? VerificationOutcome.Valid : VerificationOutcome.Invalid, dataToVerify.Length, CryptoLib.Name);

            return ValueTask.FromResult<(bool, CryptoEvent?)>((isVerified, evt));
        }


        /// <summary>
        /// Signs data using RSA with PSS (Probabilistic Signature Scheme) padding.
        /// The salt length is set to the digest size. The private key is expected in
        /// PKCS#1 DER format (<c>RSAPrivateKey</c>).
        /// </summary>
        /// <param name="privateKeyBytes">The PKCS#1 DER-encoded RSA private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="digest">The hash digest to use (e.g., SHA-256, SHA-384, SHA-512).</param>
        /// <param name="signatureTag">The tag identifying the signature algorithm.</param>
        /// <returns>A pool-allocated RSA-PSS signature.</returns>
        private static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaPssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, IDigest digest, Tag signatureTag)
        {
            ProviderOperation operation = new(nameof(SignRsaPssAsync));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Sign);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                activity.SetTag(CryptoTelemetry.Signature.Algorithm, "RSA");
            }

            RsaPrivateCrtKeyParameters privateKey = ParseRsaPrivateKey(privateKeyBytes.Span);
            PssSigner signer = new(new RsaEngine(), digest, digest.GetDigestSize());
            signer.Init(forSigning: true, privateKey);
            signer.BlockUpdate(dataToSign.ToArray(), 0, dataToSign.Length);

            byte[] signatureBytes = signer.GenerateSignature();
            IMemoryOwner<byte> memoryPooledSignature = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryPooledSignature.Memory.Span);

            var signatureResult = new Signature(memoryPooledSignature, signatureTag);
            CryptoEvent evt = SignatureProducedEvent.Create(
                signatureTag.Get<CryptoAlgorithm>(), dataToSign.Length, signatureBytes.Length, CryptoLib.Name);

            return ValueTask.FromResult<(Signature, CryptoEvent?)>((signatureResult, evt));
        }


        /// <summary>
        /// Verifies an RSA PSS signature. The public key is expected in the
        /// DID-compatible format produced by <see cref="RsaUtilities.Encode"/>.
        /// The salt length is set to the digest size.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The RSA-PSS signature to verify.</param>
        /// <param name="publicKeyMaterial">The encoded RSA public key.</param>
        /// <param name="digest">The hash digest to use (e.g., SHA-256, SHA-384, SHA-512).</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        private static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaPssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, CryptoAlgorithm algorithm, IDigest digest)
        {
            ProviderOperation operation = new(nameof(VerifyRsaPssAsync));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Verify);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                activity.SetTag(CryptoTelemetry.Signature.Algorithm, "RSA");
            }

            RsaKeyParameters publicKey = ParseRsaPublicKey(publicKeyMaterial.Span);
            PssSigner verifier = new(new RsaEngine(), digest, digest.GetDigestSize());
            verifier.Init(forSigning: false, publicKey);
            verifier.BlockUpdate(dataToVerify.ToArray(), 0, dataToVerify.Length);

            bool isVerified = verifier.VerifySignature(signature.ToArray());
            CryptoEvent evt = VerificationCompletedEvent.Create(
                algorithm, isVerified ? VerificationOutcome.Valid : VerificationOutcome.Invalid, dataToVerify.Length, CryptoLib.Name);

            return ValueTask.FromResult<(bool, CryptoEvent?)>((isVerified, evt));
        }


        /// <summary>
        /// Signs data using the specified ML-DSA parameter set in deterministic mode.
        /// Reconstructs key parameters from raw encoded bytes.
        /// </summary>
        private static ValueTask<(Signature Signature, CryptoEvent? Event)> SignMlDsaAsync(
            MLDsaParameters parameters,
            ReadOnlyMemory<byte> privateKeyBytes,
            ReadOnlyMemory<byte> dataToSign,
            MemoryPool<byte> signaturePool,
            Tag signatureTag)
        {
            ProviderOperation operation = new(nameof(SignMlDsaAsync));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Sign);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                activity.SetTag(CryptoTelemetry.Signature.Algorithm, "ML-DSA");
            }

            //MLDsaPrivateKeyParameters exposes no public constructor or span-accepting static factory,
            //only this byte[]-only FromEncoding, so the private key is copied once here and zeroed
            //immediately after decoding. The decoded MLDsaPrivateKeyParameters retains its own internal
            //copy of the key material, which cannot be zeroed from outside BouncyCastle.
            byte[] privateKeyArray = privateKeyBytes.ToArray();
            MLDsaPrivateKeyParameters privateKey;
            try
            {
                privateKey = MLDsaPrivateKeyParameters.FromEncoding(parameters, privateKeyArray);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(privateKeyArray);
            }

            var signer = new MLDsaSigner(parameters, deterministic: true);
            signer.Init(forSigning: true, privateKey);
            signer.BlockUpdate(dataToSign.ToArray(), 0, dataToSign.Length);

            byte[] signatureBytes = signer.GenerateSignature();
            IMemoryOwner<byte> memoryPooledSignature = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryPooledSignature.Memory.Span);

            var signatureResult = new Signature(memoryPooledSignature, signatureTag);
            CryptoEvent evt = SignatureProducedEvent.Create(
                signatureTag.Get<CryptoAlgorithm>(), dataToSign.Length, signatureBytes.Length, CryptoLib.Name);

            return ValueTask.FromResult<(Signature, CryptoEvent?)>((signatureResult, evt));
        }


        /// <summary>
        /// Verifies a signature using the specified ML-DSA parameter set.
        /// Reconstructs key parameters from raw encoded bytes.
        /// </summary>
        private static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyMlDsaAsync(
            MLDsaParameters parameters,
            ReadOnlyMemory<byte> dataToVerify,
            ReadOnlyMemory<byte> signature,
            ReadOnlyMemory<byte> publicKeyMaterial,
            CryptoAlgorithm algorithm)
        {
            ProviderOperation operation = new(nameof(VerifyMlDsaAsync));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Verify);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                activity.SetTag(CryptoTelemetry.Signature.Algorithm, "ML-DSA");
            }

            var publicKey = MLDsaPublicKeyParameters.FromEncoding(parameters, publicKeyMaterial.ToArray());
            var verifier = new MLDsaSigner(parameters, deterministic: true);
            verifier.Init(forSigning: false, publicKey);
            verifier.BlockUpdate(dataToVerify.ToArray(), 0, dataToVerify.Length);

            bool isVerified = verifier.VerifySignature(signature.ToArray());
            CryptoEvent evt = VerificationCompletedEvent.Create(
                algorithm, isVerified ? VerificationOutcome.Valid : VerificationOutcome.Invalid, dataToVerify.Length, CryptoLib.Name);

            return ValueTask.FromResult<(bool, CryptoEvent?)>((isVerified, evt));
        }


        /// <summary>
        /// Encapsulates a shared secret using the specified ML-KEM parameter set.
        /// Produces a ciphertext and a shared secret from the recipient's public key.
        /// </summary>
        private static (IMemoryOwner<byte> Ciphertext, IMemoryOwner<byte> SharedSecret) EncapsulateMlKem(
            MLKemParameters parameters,
            ReadOnlyMemory<byte> publicKeyBytes,
            MemoryPool<byte> memoryPool)
        {
            var publicKey = MLKemPublicKeyParameters.FromEncoding(parameters, publicKeyBytes.ToArray());
            var encapsulator = new MLKemEncapsulator(parameters);
            encapsulator.Init(publicKey);

            byte[] ciphertext = new byte[encapsulator.EncapsulationLength];
            byte[] sharedSecret = new byte[encapsulator.SecretLength];
            encapsulator.Encapsulate(ciphertext, 0, ciphertext.Length, sharedSecret, 0, sharedSecret.Length);

            IMemoryOwner<byte> ciphertextMemory = memoryPool.Rent(ciphertext.Length);
            ciphertext.CopyTo(ciphertextMemory.Memory.Span);

            IMemoryOwner<byte> secretMemory = memoryPool.Rent(sharedSecret.Length);
            sharedSecret.CopyTo(secretMemory.Memory.Span);

            Array.Clear(sharedSecret, 0, sharedSecret.Length);

            return (ciphertextMemory, secretMemory);
        }


        /// <summary>
        /// Decapsulates a shared secret from ciphertext using the specified ML-KEM parameter set
        /// and the recipient's private key.
        /// </summary>
        private static IMemoryOwner<byte> DecapsulateMlKem(
            MLKemParameters parameters,
            ReadOnlyMemory<byte> privateKeyBytes,
            ReadOnlyMemory<byte> ciphertext,
            MemoryPool<byte> memoryPool)
        {
            //MLKemPrivateKeyParameters exposes no public constructor or span-accepting static factory,
            //only this byte[]-only FromEncoding, so the private key is copied once here and zeroed
            //immediately after decoding. The decoded MLKemPrivateKeyParameters retains its own internal
            //copy of the key material, which cannot be zeroed from outside BouncyCastle.
            byte[] privateKeyArray = privateKeyBytes.ToArray();
            MLKemPrivateKeyParameters privateKey;
            try
            {
                privateKey = MLKemPrivateKeyParameters.FromEncoding(parameters, privateKeyArray);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(privateKeyArray);
            }

            var decapsulator = new MLKemDecapsulator(parameters);
            decapsulator.Init(privateKey);

            byte[] sharedSecret = new byte[decapsulator.SecretLength];
            decapsulator.Decapsulate(ciphertext.ToArray(), 0, ciphertext.Length, sharedSecret, 0, sharedSecret.Length);

            IMemoryOwner<byte> secretMemory = memoryPool.Rent(sharedSecret.Length);
            sharedSecret.CopyTo(secretMemory.Memory.Span);
            Array.Clear(sharedSecret, 0, sharedSecret.Length);

            return secretMemory;
        }


        /// <summary>
        /// Parses a PKCS#1 DER-encoded RSA private key (<c>RSAPrivateKey</c>) into BouncyCastle
        /// key parameters. This format is produced by both <c>RSA.ExportRSAPrivateKey()</c>
        /// and <see cref="BouncyCastleKeyMaterialCreator"/>.
        /// </summary>
        /// <param name="privateKeyBytes">The PKCS#1 DER-encoded private key.</param>
        /// <returns>The parsed private key parameters with CRT components.</returns>
        private static RsaPrivateCrtKeyParameters ParseRsaPrivateKey(ReadOnlySpan<byte> privateKeyBytes)
        {
            //BouncyCastle's classic ASN.1 object model (Asn1Sequence, RsaPrivateKeyStructure) accepts
            //only byte[], so the DER-encoded private key is copied once here and zeroed immediately
            //after the ASN.1 structure is parsed. The resulting RsaPrivateCrtKeyParameters holds the
            //modulus, exponents, and CRT factors as BigInteger magnitudes — BigInteger's internal int[]
            //magnitude is immutable and cannot be zeroed from outside BouncyCastle, so those copies
            //remain for the key's lifetime.
            byte[] derBytes = privateKeyBytes.ToArray();
            try
            {
                RsaPrivateKeyStructure rsa = RsaPrivateKeyStructure.GetInstance(Asn1Sequence.GetInstance(derBytes));
                return new RsaPrivateCrtKeyParameters(
                    rsa.Modulus,
                    rsa.PublicExponent,
                    rsa.PrivateExponent,
                    rsa.Prime1,
                    rsa.Prime2,
                    rsa.Exponent1,
                    rsa.Exponent2,
                    rsa.Coefficient);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(derBytes);
            }
        }


        /// <summary>
        /// Parses an RSA public key either from a raw big-endian modulus (the did:key convention
        /// produced by <see cref="RsaUtilities.Encode"/>, which always assumes the standard 65537
        /// public exponent) or from a DER PKCS#1 <c>RSAPublicKey ::= SEQUENCE { modulus INTEGER,
        /// publicExponent INTEGER }</c> (RFC 8017 Appendix A.1.1, the same shape RFC 8230 §4's
        /// COSE RSA <c>n</c>/<c>e</c> labels round-trip through). The DER form carries whatever
        /// public exponent the key actually uses, so it is parsed rather than assumed.
        /// </summary>
        /// <param name="publicKeyMaterial">The raw modulus or DER-encoded RSA public key.</param>
        /// <returns>The parsed public key parameters.</returns>
        private static RsaKeyParameters ParseRsaPublicKey(ReadOnlySpan<byte> publicKeyMaterial)
        {
            if(publicKeyMaterial.Length == RsaUtilities.Rsa2048ModulusLength || publicKeyMaterial.Length == RsaUtilities.Rsa4096ModulusLength)
            {
                return new RsaKeyParameters(isPrivate: false, new BigInteger(1, publicKeyMaterial.ToArray()), BigInteger.ValueOf(65537));
            }

            AsnReader sequenceReader = new AsnReader(publicKeyMaterial.ToArray(), AsnEncodingRules.DER).ReadSequence();
            System.Numerics.BigInteger modulus = sequenceReader.ReadInteger();
            System.Numerics.BigInteger exponent = sequenceReader.ReadInteger();

            //The sign-magnitude constructor (sign = 1) is used rather than the two's-complement one,
            //since System.Numerics.BigInteger's unsigned big-endian byte form always encodes a
            //positive RSA modulus/exponent, and a two's-complement read would misinterpret an
            //MSB-set modulus as negative.
            return new RsaKeyParameters(
                isPrivate: false,
                new BigInteger(1, modulus.ToByteArray(isUnsigned: true, isBigEndian: true)),
                new BigInteger(1, exponent.ToByteArray(isUnsigned: true, isBigEndian: true)));
        }


        /// <summary>
        /// Maps a SEC/Brainpool curve name to the JOSE display form used in telemetry.
        /// NIST <c>secpNNNr1</c> names map to the <c>P-NNN</c> display form; secp256k1 and
        /// the Brainpool curves pass through unchanged.
        /// </summary>
        /// <param name="curveName">The SEC or Brainpool curve name.</param>
        /// <returns>The telemetry display name for the curve.</returns>
        private static string MapEcdsaCurve(string curveName) => curveName switch
        {
            "secp256r1" => "P-256",
            "secp384r1" => "P-384",
            "secp521r1" => "P-521",
            _ => curveName
        };


        /// <summary>
        /// Computes the appropriate hash for the given ECDSA curve. Both secp256r1 and secp256k1
        /// use SHA-256, secp384r1 uses SHA-384, and secp521r1 uses SHA-512.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <param name="curveName">The SEC curve name.</param>
        /// <returns>The hash digest of the data.</returns>
        /// <exception cref="NotSupportedException">Thrown if the curve is not recognized.</exception>
        private static byte[] ComputeHash(ReadOnlySpan<byte> data, string curveName)
        {
            //Brainpool hash bindings per RFC 9864 §5: BP-256 → SHA-256,
            //BP-320 → SHA-384, BP-384 → SHA-384, BP-512 → SHA-512. Note that
            //BP-320 uses SHA-384 even though SHA-384 output exceeds the field
            //size — ECDSA truncates internally. brainpoolP224r1 (not an RFC 9864
            //fully-specified algorithm) uses the field-matched SHA-224, computed
            //through BouncyCastle because the framework has no managed SHA-224.
            return curveName switch
            {
                "brainpoolP224r1" => ComputeSha224(data),
                "secp256r1" or "secp256k1" or "brainpoolP256r1" => SHA256.HashData(data),
                "secp384r1" or "brainpoolP320r1" or "brainpoolP384r1" => SHA384.HashData(data),
                "secp521r1" or "brainpoolP512r1" => SHA512.HashData(data),
                _ => throw new NotSupportedException($"Curve '{curveName}' is not supported.")
            };
        }


        /// <summary>
        /// Computes a SHA-224 digest through BouncyCastle — the framework provides no managed SHA-224 class,
        /// and brainpoolP224r1 ECDSA pairs with the field-matched SHA-224.
        /// </summary>
        private static byte[] ComputeSha224(ReadOnlySpan<byte> data)
        {
            var digest = new Sha224Digest();
            digest.BlockUpdate(data);
            byte[] result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result);

            return result;
        }


        /// <summary>
        /// Returns the BouncyCastle digest instance appropriate for deterministic ECDSA k generation
        /// (RFC 6979 via <see cref="HMacDsaKCalculator"/>) on the specified curve.
        /// </summary>
        /// <param name="curveName">The SEC curve name.</param>
        /// <returns>A new <see cref="IDigest"/> instance for the curve.</returns>
        /// <exception cref="NotSupportedException">Thrown if the curve is not recognized.</exception>
        private static IDigest GetDigest(string curveName)
        {
            //Mirrors ComputeHash's RFC 9864 §5 mapping so that the RFC 6979
            //k-derivation uses the same hash family as the message digest.
            return curveName switch
            {
                "brainpoolP224r1" => new Sha224Digest(),
                "secp256r1" or "secp256k1" or "brainpoolP256r1" => new Sha256Digest(),
                "secp384r1" or "brainpoolP320r1" or "brainpoolP384r1" => new Sha384Digest(),
                "secp521r1" or "brainpoolP512r1" => new Sha512Digest(),
                _ => throw new NotSupportedException($"Curve '{curveName}' is not supported.")
            };
        }
    }
}