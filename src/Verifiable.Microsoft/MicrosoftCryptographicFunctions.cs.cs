using System;
using System.Buffers;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable.Microsoft
{
    /// <summary>
    /// Provides cryptographic functions for digital signatures using Microsoft cryptographic libraries.
    /// </summary>
    public static class MicrosoftCryptographicFunctions
    {
        /// <summary>
        /// Verifies a signature using the NIST P-256 elliptic curve.
        /// </summary>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKeyMaterial">The public key material used for verification.</param>
        /// <param name="context">Optional context information for the verification process.</param>
        /// <returns>A task that represents the asynchronous operation, containing a boolean indicating whether the signature is valid.</returns>
        public static ValueTask<bool> VerifyP256Async(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyECDsa(dataToVerify, signature, publicKeyMaterial, ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256);
        }


        /// <summary>
        /// Signs data using the NIST P-256 elliptic curve.
        /// </summary>
        /// <param name="privateKeyBytes">The private key used for signing.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool to allocate signature buffer from.</param>
        /// <param name="context">Optional context information for the signing process.</param>
        /// <returns>A task that represents the asynchronous operation, containing the signature.</returns>
        public static ValueTask<IMemoryOwner<byte>> SignP256Async(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return SignECDsa(privateKeyBytes, dataToSign, signaturePool, ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256);
        }


        /// <summary>
        /// Verifies a signature using the NIST P-384 elliptic curve.
        /// </summary>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKeyMaterial">The public key material used for verification.</param>
        /// <param name="context">Optional context information for the verification process.</param>
        /// <returns>A task that represents the asynchronous operation, containing a boolean indicating whether the signature is valid.</returns>
        public static ValueTask<bool> VerifyP384Async(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyECDsa(dataToVerify, signature, publicKeyMaterial, ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384);
        }


        /// <summary>
        /// Signs data using the NIST P-384 elliptic curve.
        /// </summary>
        /// <param name="privateKeyBytes">The private key used for signing.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool to allocate signature buffer from.</param>
        /// <param name="context">Optional context information for the signing process.</param>
        /// <returns>A task that represents the asynchronous operation, containing the signature.</returns>
        public static ValueTask<IMemoryOwner<byte>> SignP384Async(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return SignECDsa(privateKeyBytes, dataToSign, signaturePool, ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384);
        }


        /// <summary>
        /// Verifies a signature using the NIST P-521 elliptic curve.
        /// </summary>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKeyMaterial">The public key material used for verification.</param>
        /// <param name="context">Optional context information for the verification process.</param>
        /// <returns>A task that represents the asynchronous operation, containing a boolean indicating whether the signature is valid.</returns>
        public static ValueTask<bool> VerifyP521Async(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyECDsa(dataToVerify, signature, publicKeyMaterial, ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512);
        }


        /// <summary>
        /// Signs data using the NIST P-521 elliptic curve.
        /// </summary>
        /// <param name="privateKeyBytes">The private key used for signing.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool to allocate signature buffer from.</param>
        /// <param name="context">Optional context information for the signing process.</param>
        /// <returns>A task that represents the asynchronous operation, containing the signature.</returns>
        public static ValueTask<IMemoryOwner<byte>> SignP521Async(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return SignECDsa(privateKeyBytes, dataToSign, signaturePool, ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512);
        }


        /// <summary>
        /// Verifies a signature using the secp256k1 elliptic curve.
        /// </summary>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKeyMaterial">The public key material used for verification.</param>
        /// <param name="context">Optional context information for the verification process.</param>
        /// <returns>A task that represents the asynchronous operation, containing a boolean indicating whether the signature is valid.</returns>
        public static ValueTask<bool> VerifySecp256k1Async(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyECDsa(dataToVerify, signature, publicKeyMaterial, ECCurve.CreateFromFriendlyName("secP256k1"), HashAlgorithmName.SHA256);
        }


        /// <summary>
        /// Signs data using the secp256k1 elliptic curve.
        /// </summary>
        /// <param name="privateKeyBytes">The private key used for signing.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool to allocate signature buffer from.</param>
        /// <param name="context">Optional context information for the signing process.</param>
        /// <returns>A task that represents the asynchronous operation, containing the signature.</returns>
        public static ValueTask<IMemoryOwner<byte>> SignSecp256k1Async(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return SignECDsa(privateKeyBytes, dataToSign, signaturePool, ECCurve.CreateFromFriendlyName("secP256k1"), HashAlgorithmName.SHA256);
        }


        /// <summary>
        /// Signs data using RSA with a 2048-bit key, SHA-256 hash, and PKCS#1 v1.5 padding.
        /// This method is compatible with DID and VC profiles that require RSA 2048 with PKCS#1 padding,
        /// such as the older <c>did:key</c> profiles.
        /// </summary>
        /// <param name="privateKeyBytes">
        /// The DER-encoded PKCS#1 RSA private key bytes. This should contain the full key structure including modulus, exponent, and private components.
        /// </param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="context">Optional context information for the signing process.</param>
        /// <returns>
        /// A task that represents the asynchronous operation, containing the signature
        /// as a pooled memory buffer.
        /// </returns>
        public static ValueTask<IMemoryOwner<byte>> SignRsa2048Async(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return SignRsa(privateKeyBytes, dataToSign, signaturePool, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }


        /// <summary>
        /// Verifies an RSA signature using SHA-256 hash and PKCS#1 padding for 2048-bit keys.
        /// This method is compatible with DID and VC profiles that require RSA 2048 with PKCS#1 v1.5 padding,
        /// such as the older <c>did:key</c> profiles.
        /// </summary>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKeyMaterial">The public key material used for verification. This should be DER-encoded SubjectPublicKeyInfo.</param>
        /// <param name="context">Optional context information for the verification process.</param>
        /// <returns>A task that represents the asynchronous operation, containing a boolean indicating whether the signature is valid.</returns>
        public static ValueTask<bool> VerifyRsa2048Async(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaAsync(dataToVerify, signature, publicKeyMaterial, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }


        /// <summary>
        /// Signs data using RSA with a 4096-bit key, SHA-256 hash, and PKCS#1 v1.5 padding.
        /// This method is compatible with DID and VC profiles that require RSA 4096 with PKCS#1 padding,
        /// such as the older <c>did:key</c> profiles.
        /// </summary>
        /// <param name="privateKeyBytes">
        /// The DER-encoded PKCS#1 RSA private key bytes. This should contain the full key structure including modulus, exponent, and private components.
        /// </param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="context">Optional context information for the signing process.</param>
        /// <returns>
        /// A task that represents the asynchronous operation, containing the signature
        /// as a pooled memory buffer.
        /// </returns>
        public static ValueTask<IMemoryOwner<byte>> SignRsa4096Async(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return SignRsa(privateKeyBytes, dataToSign, signaturePool, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }


        /// <summary>
        /// Verifies an RSA signature using SHA-256 hash and PKCS#1 padding for 4096-bit keys.
        /// This method is compatible with DID and VC profiles that require RSA 4096 with PKCS#1 v1.5 padding,
        /// such as the older <c>did:key</c> profiles.
        /// </summary>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKeyMaterial">The public key material used for verification. This should be DER-encoded SubjectPublicKeyInfo.</param>
        /// <param name="context">Optional context information for the verification process.</param>
        /// <returns>A task that represents the asynchronous operation, containing a boolean indicating whether the signature is valid.</returns>
        public static ValueTask<bool> VerifyRsa4096Async(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaAsync(dataToVerify, signature, publicKeyMaterial, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }


        /// <summary>
        /// Verifies an RSA signature using SHA-256 hash and PKCS#1 padding.
        /// </summary>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKeyMaterial">The public key material used for verification.</param>
        /// <param name="context">Optional context information for the verification process.</param>
        /// <returns>A task that represents the asynchronous operation, containing a boolean indicating whether the signature is valid.</returns>
        public static ValueTask<bool> VerifyRsaSha256Pkcs1Async(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaAsync(dataToVerify, signature, publicKeyMaterial, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }


        /// <summary>
        /// Signs data using RSA with SHA-256 hash and PKCS#1 padding.
        /// </summary>
        /// <param name="privateKeyBytes">The private key used for signing.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool to allocate signature buffer from.</param>
        /// <param name="context">Optional context information for the signing process.</param>
        /// <returns>A task that represents the asynchronous operation, containing the signature.</returns>
        public static ValueTask<IMemoryOwner<byte>> SignRsaSha256Pkcs1Async(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return SignRsa(privateKeyBytes, dataToSign, signaturePool, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }


        /// <summary>
        /// Verifies an RSA signature using SHA-256 hash and PSS padding.
        /// </summary>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKeyMaterial">The public key material used for verification.</param>
        /// <param name="context">Optional context information for the verification process.</param>
        /// <returns>A task that represents the asynchronous operation, containing a boolean indicating whether the signature is valid.</returns>
        public static ValueTask<bool> VerifyRsaSha256PssAsync(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaAsync(dataToVerify, signature, publicKeyMaterial, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }


        /// <summary>
        /// Signs data using RSA with SHA-256 hash and PSS padding.
        /// </summary>
        /// <param name="privateKeyBytes">The private key used for signing.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool to allocate signature buffer from.</param>
        /// <param name="context">Optional context information for the signing process.</param>
        /// <returns>A task that represents the asynchronous operation, containing the signature.</returns>
        public static ValueTask<IMemoryOwner<byte>> SignRsaSha256PssAsync(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return SignRsa(privateKeyBytes, dataToSign, signaturePool, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }


        /// <summary>
        /// Verifies an RSA signature using SHA-384 hash and PKCS#1 padding.
        /// </summary>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKeyMaterial">The public key material used for verification.</param>
        /// <param name="context">Optional context information for the verification process.</param>
        /// <returns>A task that represents the asynchronous operation, containing a boolean indicating whether the signature is valid.</returns>
        public static ValueTask<bool> VerifyRsaSha384Pkcs1Async(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaAsync(dataToVerify, signature, publicKeyMaterial, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
        }


        /// <summary>
        /// Signs data using RSA with SHA-384 hash and PKCS#1 padding.
        /// </summary>
        /// <param name="privateKeyBytes">The private key used for signing.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool to allocate signature buffer from.</param>
        /// <param name="context">Optional context information for the signing process.</param>
        /// <returns>A task that represents the asynchronous operation, containing the signature.</returns>
        public static ValueTask<IMemoryOwner<byte>> SignRsaSha384Pkcs1Async(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return SignRsa(privateKeyBytes, dataToSign, signaturePool, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
        }


        /// <summary>
        /// Verifies an RSA signature using SHA-384 hash and PSS padding.
        /// </summary>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKeyMaterial">The public key material used for verification.</param>
        /// <param name="context">Optional context information for the verification process.</param>
        /// <returns>A task that represents the asynchronous operation, containing a boolean indicating whether the signature is valid.</returns>
        public static ValueTask<bool> VerifyRsaSha384PssAsync(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaAsync(dataToVerify, signature, publicKeyMaterial, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
        }


        /// <summary>
        /// Signs data using RSA with SHA-384 hash and PSS padding.
        /// </summary>
        /// <param name="privateKeyBytes">The private key used for signing.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool to allocate signature buffer from.</param>
        /// <param name="context">Optional context information for the signing process.</param>
        /// <returns>A task that represents the asynchronous operation, containing the signature.</returns>
        public static ValueTask<IMemoryOwner<byte>> SignRsaSha384PssAsync(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return SignRsa(privateKeyBytes, dataToSign, signaturePool, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
        }


        /// <summary>
        /// Verifies an RSA signature using SHA-512 hash and PKCS#1 padding.
        /// </summary>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKeyMaterial">The public key material used for verification.</param>
        /// <param name="context">Optional context information for the verification process.</param>
        /// <returns>A task that represents the asynchronous operation, containing a boolean indicating whether the signature is valid.</returns>
        public static ValueTask<bool> VerifyRsaSha512Pkcs1Async(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaAsync(dataToVerify, signature, publicKeyMaterial, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        }


        /// <summary>
        /// Signs data using RSA with SHA-512 hash and PKCS#1 padding.
        /// </summary>
        /// <param name="privateKeyBytes">The private key used for signing.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool to allocate signature buffer from.</param>
        /// <param name="context">Optional context information for the signing process.</param>
        /// <returns>A task that represents the asynchronous operation, containing the signature.</returns>
        public static ValueTask<IMemoryOwner<byte>> SignRsaSha512Pkcs1Async(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return SignRsa(privateKeyBytes, dataToSign, signaturePool, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        }


        /// <summary>
        /// Verifies an RSA signature using SHA-512 hash and PSS padding.
        /// </summary>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKeyMaterial">The public key material used for verification.</param>
        /// <param name="context">Optional context information for the verification process.</param>
        /// <returns>A task that represents the asynchronous operation, containing a boolean indicating whether the signature is valid.</returns>
        public static ValueTask<bool> VerifyRsaSha512PssAsync(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaAsync(dataToVerify, signature, publicKeyMaterial, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
        }


        /// <summary>
        /// Signs data using RSA with SHA-512 hash and PSS padding.
        /// </summary>
        /// <param name="privateKeyBytes">The private key used for signing.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool to allocate signature buffer from.</param>
        /// <param name="context">Optional context information for the signing process.</param>
        /// <returns>A task that represents the asynchronous operation, containing the signature.</returns>
        public static ValueTask<IMemoryOwner<byte>> SignRsaSha512PssAsync(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return SignRsa(privateKeyBytes, dataToSign, signaturePool, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
        }


        /// <summary>
        /// Helper method to verify a signature using ECDSA.
        /// </summary>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKeyMaterial">The public key material used for verification.</param>
        /// <param name="curve">The elliptic curve to use.</param>
        /// <param name="hashAlgorithmName">The hash algorithm to use.</param>
        /// <returns>A task that represents the asynchronous operation, containing a boolean indicating whether the signature is valid.</returns>
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


        /// <summary>
        /// Helper method to sign data using ECDSA.
        /// </summary>
        /// <param name="privateKeyBytes">The private key used for signing.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool to allocate signature buffer from.</param>
        /// <param name="curve">The elliptic curve to use.</param>
        /// <param name="hashAlgorithmName">The hash algorithm to use.</param>
        /// <returns>A task that represents the asynchronous operation, containing the signature.</returns>
        private static ValueTask<IMemoryOwner<byte>> SignECDsa(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, ECCurve curve, HashAlgorithmName hashAlgorithmName)
        {
            //Create a new ECDSA instance with the specified curve and private key.
            var key = ECDsa.Create(new ECParameters
            {
                Curve = curve,
                D = privateKeyBytes.ToArray()
            });

            //Sign the data using the specified hash algorithm.
            var signature = key.SignData(dataToSign, hashAlgorithmName);

            //Allocate memory for the signature from the provided pool.
            var memoryPooledSignature = signaturePool.Rent(signature.Length);

            //Copy the signature to the allocated memory.
            signature.CopyTo(memoryPooledSignature.Memory.Span);

            //Return the signature.
            return ValueTask.FromResult(memoryPooledSignature);
        }


        /// <summary>
        /// Helper method to verify a signature using RSA.
        /// </summary>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKeyMaterial">The public key material used for verification.</param>
        /// <param name="hashAlgorithmName">The hash algorithm to use.</param>
        /// <param name="padding">The padding mode to use.</param>
        /// <returns>A task that represents the asynchronous operation, containing a boolean indicating whether the signature is valid.</returns>
        private static ValueTask<bool> VerifyRsaAsync(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            using(RSA rsa = RSA.Create())
            {
                //Try to import the key directly as SubjectPublicKeyInfo format.
                try
                {
                    rsa.ImportRSAPublicKey(publicKeyMaterial, out _);
                }
                catch
                {
                    //If that fails, try as a raw modulus (custom encoding).
                    //Note: This depends on what RsaUtilities.Encode does in your actual code.
                    //The actual implementation might need to match your RsaUtilities.Encode/Decode logic.
                    var parameters = new RSAParameters
                    {
                        Modulus = publicKeyMaterial.ToArray(),
                        Exponent = [0x01, 0x00, 0x01] //Default exponent 65537.
                    };
                    rsa.ImportParameters(parameters);
                }

                //Verify the signature and return the result.
                return ValueTask.FromResult(rsa.VerifyData(dataToVerify, signature, hashAlgorithmName, padding));
            }
        }

        /// <summary>
        /// Helper method to sign data using RSA.
        /// </summary>
        /// <param name="privateKeyBytes">The private key used for signing.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool to allocate signature buffer from.</param>
        /// <param name="hashAlgorithmName">The hash algorithm to use.</param>
        /// <param name="padding">The padding mode to use.</param>
        /// <returns>A task that represents the asynchronous operation, containing the signature.</returns>
        private static ValueTask<IMemoryOwner<byte>> SignRsa(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            //Create a new RSA instance.
            using(RSA rsa = RSA.Create())
            {
                //Import the private key material.
                rsa.ImportRSAPrivateKey(privateKeyBytes, out _);

                //Sign the data using the specified hash algorithm and padding.
                byte[] signature = rsa.SignData(dataToSign, hashAlgorithmName, padding);

                //Allocate memory for the signature from the provided pool.
                IMemoryOwner<byte> memoryPooledSignature = signaturePool.Rent(signature.Length);

                //Copy the signature to the allocated memory.
                signature.CopyTo(memoryPooledSignature.Memory.Span);

                //Return the signature.
                return ValueTask.FromResult(memoryPooledSignature);
            }
        }
    }
}