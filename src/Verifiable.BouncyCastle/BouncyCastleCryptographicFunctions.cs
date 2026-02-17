using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using System;
using System.Buffers;
using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;

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
        /// <summary>
        /// Signs data using Ed25519 (EdDSA over Curve25519).
        /// </summary>
        /// <param name="privateKeyBytes">The 32-byte Ed25519 private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the 64-byte signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.Ed25519Signature"/>.</returns>
        public static ValueTask<Signature> SignEd25519Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            AsymmetricKeyParameter keyParameter = new Ed25519PrivateKeyParameters(privateKeyBytes.ToArray(), 0);
            var privateKey = (Ed25519PrivateKeyParameters)keyParameter;

            var signer = new Ed25519Signer();
            signer.Init(forSigning: true, privateKey);
            signer.BlockUpdate(dataToSign.ToArray(), off: 0, len: dataToSign.Length);

            var signature = (ReadOnlySpan<byte>)signer.GenerateSignature();
            var memoryPooledSignature = signaturePool.Rent(signature.Length);
            signature.CopyTo(memoryPooledSignature.Memory.Span);

            return ValueTask.FromResult(new Signature(memoryPooledSignature, CryptoTags.Ed25519Signature));
        }


        /// <summary>
        /// Verifies an Ed25519 signature.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The 64-byte Ed25519 signature to verify.</param>
        /// <param name="publicKeyMaterial">The 32-byte Ed25519 public key.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<bool> VerifyEd25519Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            var publicKey = new Ed25519PublicKeyParameters(publicKeyMaterial.ToArray(), 0);
            var validator = new Ed25519Signer();
            validator.Init(forSigning: false, publicKey);
            validator.BlockUpdate(dataToVerify.ToArray(), off: 0, len: dataToVerify.Length);

            return ValueTask.FromResult(validator.VerifySignature(signature.ToArray()));
        }


        /// <summary>
        /// Signs data using ECDSA with the P-256 (secp256r1) curve and SHA-256.
        /// </summary>
        /// <param name="privateKeyBytes">The 32-byte P-256 private key scalar.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the 64-byte signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.P256Signature"/>.</returns>
        public static ValueTask<Signature> SignP256Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
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
        public static ValueTask<bool> VerifyP256Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, "secp256r1", 32);
        }


        /// <summary>
        /// Signs data using ECDSA with the P-384 (secp384r1) curve and SHA-384.
        /// </summary>
        /// <param name="privateKeyBytes">The 48-byte P-384 private key scalar.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the 96-byte signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.P384Signature"/>.</returns>
        public static ValueTask<Signature> SignP384Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
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
        public static ValueTask<bool> VerifyP384Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, "secp384r1", 48);
        }


        /// <summary>
        /// Signs data using ECDSA with the P-521 (secp521r1) curve and SHA-512.
        /// </summary>
        /// <param name="privateKeyBytes">The 66-byte P-521 private key scalar.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the 132-byte signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.P521Signature"/>.</returns>
        public static ValueTask<Signature> SignP521Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
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
        public static ValueTask<bool> VerifyP521Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, "secp521r1", 66);
        }


        /// <summary>
        /// Signs data using ECDSA with the secp256k1 curve and SHA-256.
        /// </summary>
        /// <param name="privateKeyBytes">The 32-byte secp256k1 private key scalar.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the 64-byte signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.Secp256k1Signature"/>.</returns>
        public static ValueTask<Signature> SignSecp256k1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
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
        public static ValueTask<bool> VerifySecp256k1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, "secp256k1", 32);
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
            var privateKeyParams = new X25519PrivateKeyParameters(privateKeyBytes.Span.ToArray());
            var publicKeyParams = new X25519PublicKeyParameters(publicKeyBytes.Span.ToArray());

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
        public static ValueTask<Signature> SignRsa2048Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
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
        public static ValueTask<bool> VerifyRsa2048Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaPkcs1Async(dataToVerify, signature, publicKeyMaterial, new Sha256Digest());
        }


        /// <summary>
        /// Signs data using RSA 4096 with PKCS#1 v1.5 padding and SHA-256.
        /// </summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA 4096 private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.Rsa4096Signature"/>.</returns>
        public static ValueTask<Signature> SignRsa4096Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
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
        public static ValueTask<bool> VerifyRsa4096Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaPkcs1Async(dataToVerify, signature, publicKeyMaterial, new Sha256Digest());
        }


        /// <summary>
        /// Signs data using RSA with PKCS#1 v1.5 padding and SHA-256.
        /// </summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.RsaSha256Pkcs1Signature"/>.</returns>
        public static ValueTask<Signature> SignRsaSha256Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
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
        public static ValueTask<bool> VerifyRsaSha256Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaPkcs1Async(dataToVerify, signature, publicKeyMaterial, new Sha256Digest());
        }


        /// <summary>
        /// Signs data using RSA with PSS padding and SHA-256.
        /// </summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.RsaSha256PssSignature"/>.</returns>
        public static ValueTask<Signature> SignRsaSha256PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
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
        public static ValueTask<bool> VerifyRsaSha256PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaPssAsync(dataToVerify, signature, publicKeyMaterial, new Sha256Digest());
        }


        /// <summary>
        /// Signs data using RSA with PKCS#1 v1.5 padding and SHA-384.
        /// </summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.RsaSha384Pkcs1Signature"/>.</returns>
        public static ValueTask<Signature> SignRsaSha384Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
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
        public static ValueTask<bool> VerifyRsaSha384Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaPkcs1Async(dataToVerify, signature, publicKeyMaterial, new Sha384Digest());
        }


        /// <summary>
        /// Signs data using RSA with PSS padding and SHA-384.
        /// </summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.RsaSha384PssSignature"/>.</returns>
        public static ValueTask<Signature> SignRsaSha384PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
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
        public static ValueTask<bool> VerifyRsaSha384PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaPssAsync(dataToVerify, signature, publicKeyMaterial, new Sha384Digest());
        }


        /// <summary>
        /// Signs data using RSA with PKCS#1 v1.5 padding and SHA-512.
        /// </summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.RsaSha512Pkcs1Signature"/>.</returns>
        public static ValueTask<Signature> SignRsaSha512Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
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
        public static ValueTask<bool> VerifyRsaSha512Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaPkcs1Async(dataToVerify, signature, publicKeyMaterial, new Sha512Digest());
        }


        /// <summary>
        /// Signs data using RSA with PSS padding and SHA-512.
        /// </summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.RsaSha512PssSignature"/>.</returns>
        public static ValueTask<Signature> SignRsaSha512PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
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
        public static ValueTask<bool> VerifyRsaSha512PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaPssAsync(dataToVerify, signature, publicKeyMaterial, new Sha512Digest());
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
        private static ValueTask<Signature> SignEcdsaAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, string curveName, Tag signatureTag, int componentSize)
        {
            X9ECParameters curveParams = ECNamedCurveTable.GetByName(curveName);
            ECDomainParameters domainParams = new(curveParams.Curve, curveParams.G, curveParams.N, curveParams.H);

            BigInteger d = new(1, privateKeyBytes.ToArray());
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

            return ValueTask.FromResult(new Signature(memoryPooledSignature, signatureTag));
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
        private static ValueTask<bool> VerifyEcdsaAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, string curveName, int componentSize)
        {
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

            return ValueTask.FromResult(verifier.VerifySignature(hash, r, s));
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
        private static ValueTask<Signature> SignRsaPkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, IDigest digest, Tag signatureTag)
        {
            RsaPrivateCrtKeyParameters privateKey = ParseRsaPrivateKey(privateKeyBytes.Span);
            RsaDigestSigner signer = new(digest);
            signer.Init(forSigning: true, privateKey);
            signer.BlockUpdate(dataToSign.ToArray(), 0, dataToSign.Length);

            byte[] signatureBytes = signer.GenerateSignature();
            IMemoryOwner<byte> memoryPooledSignature = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryPooledSignature.Memory.Span);

            return ValueTask.FromResult(new Signature(memoryPooledSignature, signatureTag));
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
        private static ValueTask<bool> VerifyRsaPkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, IDigest digest)
        {
            RsaKeyParameters publicKey = ParseRsaPublicKey(publicKeyMaterial.Span);
            RsaDigestSigner verifier = new(digest);
            verifier.Init(forSigning: false, publicKey);
            verifier.BlockUpdate(dataToVerify.ToArray(), 0, dataToVerify.Length);

            return ValueTask.FromResult(verifier.VerifySignature(signature.ToArray()));
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
        private static ValueTask<Signature> SignRsaPssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, IDigest digest, Tag signatureTag)
        {
            RsaPrivateCrtKeyParameters privateKey = ParseRsaPrivateKey(privateKeyBytes.Span);
            PssSigner signer = new(new RsaEngine(), digest, digest.GetDigestSize());
            signer.Init(forSigning: true, privateKey);
            signer.BlockUpdate(dataToSign.ToArray(), 0, dataToSign.Length);

            byte[] signatureBytes = signer.GenerateSignature();
            IMemoryOwner<byte> memoryPooledSignature = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryPooledSignature.Memory.Span);

            return ValueTask.FromResult(new Signature(memoryPooledSignature, signatureTag));
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
        private static ValueTask<bool> VerifyRsaPssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, IDigest digest)
        {
            RsaKeyParameters publicKey = ParseRsaPublicKey(publicKeyMaterial.Span);
            PssSigner verifier = new(new RsaEngine(), digest, digest.GetDigestSize());
            verifier.Init(forSigning: false, publicKey);
            verifier.BlockUpdate(dataToVerify.ToArray(), 0, dataToVerify.Length);

            return ValueTask.FromResult(verifier.VerifySignature(signature.ToArray()));
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
            RsaPrivateKeyStructure rsa = RsaPrivateKeyStructure.GetInstance(Asn1Sequence.GetInstance(privateKeyBytes.ToArray()));
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


        /// <summary>
        /// Parses an RSA public key from the DID-compatible format produced by
        /// <see cref="RsaUtilities.Encode"/>. This decodes the modulus and uses
        /// the standard RSA public exponent (65537).
        /// </summary>
        /// <param name="publicKeyMaterial">The encoded RSA public key.</param>
        /// <returns>The parsed public key parameters.</returns>
        private static RsaKeyParameters ParseRsaPublicKey(ReadOnlySpan<byte> publicKeyMaterial)
        {
            byte[] modulusBytes = RsaUtilities.Decode(publicKeyMaterial);
            return new RsaKeyParameters(isPrivate: false, new BigInteger(1, modulusBytes), BigInteger.ValueOf(65537));
        }


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
            return curveName switch
            {
                "secp256r1" or "secp256k1" => SHA256.HashData(data),
                "secp384r1" => SHA384.HashData(data),
                "secp521r1" => SHA512.HashData(data),
                _ => throw new NotSupportedException($"Curve '{curveName}' is not supported.")
            };
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
            return curveName switch
            {
                "secp256r1" or "secp256k1" => new Sha256Digest(),
                "secp384r1" => new Sha384Digest(),
                "secp521r1" => new Sha512Digest(),
                _ => throw new NotSupportedException($"Curve '{curveName}' is not supported.")
            };
        }
    }
}