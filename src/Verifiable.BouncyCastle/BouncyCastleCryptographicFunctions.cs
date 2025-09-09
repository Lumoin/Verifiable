using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using System;
using System.Buffers;
using System.Collections.Frozen;
using System.IO;
using System.Threading.Tasks;

namespace Verifiable.BouncyCastle
{
    /// <summary>
    /// Provides cryptographic functions for digital signatures using BouncyCastle cryptographic libraries.
    /// This class handles verification and signing operations for various elliptic curve algorithms
    /// that are not natively supported by Microsoft's cryptographic libraries.
    /// </summary>
    public static class BouncyCastleCryptographicFunctions
    {
        public static ValueTask<IMemoryOwner<byte>> DeriveX25519SharedSecretAsync(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> publicKeyBytes, MemoryPool<byte> memoryPool)
        {
            var privateKeyParams = new X25519PrivateKeyParameters(privateKeyBytes.ToArray());
            var publicKeyParams = new X25519PublicKeyParameters(publicKeyBytes.ToArray());

            var agreement = new X25519Agreement();
            agreement.Init(privateKeyParams);

            var sharedSecret = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(publicKeyParams, sharedSecret, 0);

            var memoryOwner = memoryPool.Rent(sharedSecret.Length);
            if(memoryOwner.Memory.Length != sharedSecret.Length)
            {
                throw new InvalidOperationException("The rented buffer size does not match the requested size.");
            }

            sharedSecret.CopyTo(memoryOwner.Memory.Span);
            Array.Clear(sharedSecret, 0, sharedSecret.Length); // Clear sensitive data

            return ValueTask.FromResult(memoryOwner);
        }

        /// <summary>
        /// Verifies a signature using the NIST P-256 elliptic curve with SHA-256 hash algorithm.
        /// </summary>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKeyMaterial">The public key material used for verification.</param>
        /// <param name="context">Optional context information for the verification process.</param>
        /// <returns>A task that represents the asynchronous operation, containing a boolean indicating whether the signature is valid.</returns>
        public static ValueTask<bool> VerifyP256Async(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            const string SignatureAlgorithm = "SHA256withECDSA";
            const string CurveName = "P-256";

            return ValueTask.FromResult(Verify(dataToVerify, signature, publicKeyMaterial, SignatureAlgorithm, CurveName));
        }

        /// <summary>
        /// Verifies a signature using the NIST P-384 elliptic curve with SHA-384 hash algorithm.
        /// </summary>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKeyMaterial">The public key material used for verification.</param>
        /// <param name="context">Optional context information for the verification process.</param>
        /// <returns>A task that represents the asynchronous operation, containing a boolean indicating whether the signature is valid.</returns>
        public static ValueTask<bool> VerifyP384Async(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            const string SignatureAlgorithm = "SHA384withECDSA";
            const string CurveName = "P-384";

            return ValueTask.FromResult(Verify(dataToVerify, signature, publicKeyMaterial, SignatureAlgorithm, CurveName));
        }

        /// <summary>
        /// Verifies a signature using the NIST P-521 elliptic curve with SHA-512 hash algorithm.
        /// </summary>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKeyMaterial">The public key material used for verification.</param>
        /// <param name="context">Optional context information for the verification process.</param>
        /// <returns>A task that represents the asynchronous operation, containing a boolean indicating whether the signature is valid.</returns>
        public static ValueTask<bool> VerifyP521Async(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            const string SignatureAlgorithm = "SHA512withECDSA";
            const string CurveName = "P-521";

            return ValueTask.FromResult(Verify(dataToVerify, signature, publicKeyMaterial, SignatureAlgorithm, CurveName));
        }

        /// <summary>
        /// Verifies a signature using the secp256k1 elliptic curve with SHA-256 hash algorithm.
        /// This curve is commonly used in Bitcoin and other cryptocurrency applications.
        /// </summary>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKeyMaterial">The public key material used for verification.</param>
        /// <param name="context">Optional context information for the verification process.</param>
        /// <returns>A task that represents the asynchronous operation, containing a boolean indicating whether the signature is valid.</returns>
        public static ValueTask<bool> VerifySecp256k1Async(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            const string SignatureAlgorithm = "SHA256withECDSA";
            const string CurveName = "secp256k1";

            return ValueTask.FromResult(Verify(dataToVerify, signature, publicKeyMaterial, SignatureAlgorithm, CurveName));
        }

        /// <summary>
        /// Verifies a signature using the Ed25519 elliptic curve digital signature algorithm.
        /// Ed25519 is a high-performance elliptic curve signature scheme that provides excellent security.
        /// </summary>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKeyMaterial">The public key material used for verification.</param>
        /// <param name="context">Optional context information for the verification process.</param>
        /// <returns>A task that represents the asynchronous operation, containing a boolean indicating whether the signature is valid.</returns>
        public static ValueTask<bool> VerifyEd25519Async(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            const string SignatureAlgorithm = "Ed25519";
            return ValueTask.FromResult(Verify(dataToVerify, signature, publicKeyMaterial, SignatureAlgorithm, string.Empty));
        }

        /// <summary>
        /// Signs data using the NIST P-256 elliptic curve with SHA-256 hash algorithm.
        /// </summary>
        /// <param name="privateKeyBytes">The private key used for signing.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool to allocate signature buffer from.</param>
        /// <param name="context">Optional context information for the signing process.</param>
        /// <returns>A task that represents the asynchronous operation, containing the signature.</returns>
        public static ValueTask<IMemoryOwner<byte>> SignP256Async(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            const string SignatureAlgorithm = "SHA256withECDSA";
            const string CurveName = "P-256";

            //TODO: Implement ECDSA signing for P-256.
            throw new NotImplementedException($"ECDSA signing for {CurveName} with {SignatureAlgorithm} is not yet implemented.");
        }

        /// <summary>
        /// Signs data using the NIST P-384 elliptic curve with SHA-384 hash algorithm.
        /// </summary>
        /// <param name="privateKeyBytes">The private key used for signing.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool to allocate signature buffer from.</param>
        /// <param name="context">Optional context information for the signing process.</param>
        /// <returns>A task that represents the asynchronous operation, containing the signature.</returns>
        public static ValueTask<IMemoryOwner<byte>> SignP384Async(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            const string SignatureAlgorithm = "SHA384withECDSA";
            const string CurveName = "P-384";

            //TODO: Implement ECDSA signing for P-384.
            throw new NotImplementedException($"ECDSA signing for {CurveName} with {SignatureAlgorithm} is not yet implemented.");
        }

        /// <summary>
        /// Signs data using the NIST P-521 elliptic curve with SHA-512 hash algorithm.
        /// </summary>
        /// <param name="privateKeyBytes">The private key used for signing.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool to allocate signature buffer from.</param>
        /// <param name="context">Optional context information for the signing process.</param>
        /// <returns>A task that represents the asynchronous operation, containing the signature.</returns>
        public static ValueTask<IMemoryOwner<byte>> SignP521Async(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            const string SignatureAlgorithm = "SHA512withECDSA";
            const string CurveName = "P-521";

            //TODO: Implement ECDSA signing for P-521.
            throw new NotImplementedException($"ECDSA signing for {CurveName} with {SignatureAlgorithm} is not yet implemented.");
        }

        /// <summary>
        /// Signs data using the secp256k1 elliptic curve with SHA-256 hash algorithm.
        /// This curve is commonly used in Bitcoin and other cryptocurrency applications.
        /// </summary>
        /// <param name="privateKeyBytes">The private key used for signing.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool to allocate signature buffer from.</param>
        /// <param name="context">Optional context information for the signing process.</param>
        /// <returns>A task that represents the asynchronous operation, containing the signature.</returns>
        public static ValueTask<IMemoryOwner<byte>> SignSecp256k1Async(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            const string SignatureAlgorithm = "SHA256withECDSA";
            const string CurveName = "secp256k1";

            //TODO: Implement ECDSA signing for secp256k1.
            throw new NotImplementedException($"ECDSA signing for {CurveName} with {SignatureAlgorithm} is not yet implemented.");
        }

        /// <summary>
        /// Signs data using the Ed25519 elliptic curve digital signature algorithm.
        /// Ed25519 is a high-performance elliptic curve signature scheme that provides excellent security.
        /// </summary>
        /// <param name="privateKeyBytes">The private key used for signing.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool to allocate signature buffer from.</param>
        /// <param name="context">Optional context information for the signing process.</param>
        /// <returns>A task that represents the asynchronous operation, containing the signature.</returns>
        public static ValueTask<IMemoryOwner<byte>> SignEd25519Async(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            //TODO: Check if BouncyCastle Ed25519Signer can write directly to a pre-allocated span.
            //TODO: Consider using unsafe code or pinning to avoid the ToArray() calls.
            var privateKeyParams = new Ed25519PrivateKeyParameters(privateKeyBytes.ToArray(), 0);
            var signer = new Ed25519Signer();
            signer.Init(forSigning: true, privateKeyParams);
            signer.BlockUpdate(dataToSign.ToArray(), 0, dataToSign.Length);

            var signature = (ReadOnlySpan<byte>)signer.GenerateSignature();
            var memoryPooledSignature = signaturePool.Rent(signature.Length);
            signature.CopyTo(memoryPooledSignature.Memory.Span);

            return ValueTask.FromResult(memoryPooledSignature);
        }

        /// <summary>
        /// Core verification method that handles signature verification for various algorithms using BouncyCastle.
        /// This method implements the security-conscious approach of explicitly validating key formats
        /// and algorithm parameters to prevent downgrade attacks.
        /// </summary>
        /// <param name="dataToVerify">The data that was originally signed.</param>
        /// <param name="signature">The signature bytes to verify.</param>
        /// <param name="publicKeyMaterial">The public key material in SubjectPublicKeyInfo format or raw bytes for Ed25519.</param>
        /// <param name="signatureAlgorithm">The signature algorithm to use (e.g., "SHA256withECDSA", "Ed25519").</param>
        /// <param name="curveName">The curve name for ECDSA algorithms, or empty string for Ed25519.</param>
        /// <returns>True if the signature is valid; otherwise, false.</returns>
        private static bool Verify(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, string signatureAlgorithm, string curveName)
        {
            ICipherParameters publicKeyParams;

            if(signatureAlgorithm == "Ed25519")
            {
                //For Ed25519, the public key material is expected to be the raw 32-byte public key.
                publicKeyParams = new Ed25519PublicKeyParameters(publicKeyMaterial.ToArray(), 0);
            }
            else
            {
                //For ECDSA algorithms, we expect SubjectPublicKeyInfo format and explicitly validate the curve.
                //PublicKeyFactory.CreateKey is not used here because it automatically detects
                //the key type from the key material.
                //The automatic key type detection could lead to potential security issues if an attacker
                //is able to manipulate the key format to use a weaker algorithm or curve.

                SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.GetInstance(publicKeyMaterial.ToArray());
                Asn1Object asn1Params = subjectPublicKeyInfo.AlgorithmID.Parameters.ToAsn1Object();
                DerObjectIdentifier oid = (DerObjectIdentifier)asn1Params;

                X9ECParameters x9EC = ECNamedCurveTable.GetByOid(oid);
                ECDomainParameters ecDomain = new(x9EC.Curve, x9EC.G, x9EC.N, x9EC.H, x9EC.GetSeed());

                Org.BouncyCastle.Math.EC.ECPoint publicKeyPoint = x9EC.Curve.DecodePoint(subjectPublicKeyInfo.PublicKeyData.GetBytes());
                publicKeyParams = new ECPublicKeyParameters(publicKeyPoint, ecDomain);

                //Helper function to calculate the expected signature length based on the field size.
                static int GetSignatureLength(int fieldSizeInBits)
                {
                    //Round up to the nearest byte, and then multiply by 2 for R and S values.
                    //This is done instead of just dividing by four since P-521 length
                    //is not divisible by four.
                    return (fieldSizeInBits + 7) / 8 * 2;
                }

                //BouncyCastle expects the signature to be in ASN.1 DER format for SHA algorithms.
                //TODO: Be explicit regarding the signature format instead of "knowing" it's in raw format.
                //If the signature is in raw format (concatenated R and S values), convert it to DER format.
                if(signatureAlgorithm.StartsWith("SHA") && signature.Length == GetSignatureLength(publicKeyPoint.Curve.FieldSize))
                {
                    int halfLength = signature.Length / 2;
                    Org.BouncyCastle.Math.BigInteger r = new Org.BouncyCastle.Math.BigInteger(1, signature.ToArray(), 0, halfLength);
                    Org.BouncyCastle.Math.BigInteger s = new Org.BouncyCastle.Math.BigInteger(1, signature.ToArray(), halfLength, halfLength);

                    using(MemoryStream derSignatureStream = new())
                    {
                        DerSequenceGenerator seqGen = new(derSignatureStream);
                        seqGen.AddObject(new DerInteger(r));
                        seqGen.AddObject(new DerInteger(s));
                        seqGen.Close();

                        signature = derSignatureStream.ToArray();
                    }
                }
            }

            //Create the signer instance and initialize it for verification.
            ISigner signer = SignerUtilities.GetSigner(signatureAlgorithm);
            signer.Init(forSigning: false, publicKeyParams);

            //Update the signer with the data that was originally signed.
            signer.BlockUpdate(dataToVerify.ToArray(), 0, dataToVerify.Length);

            //Perform the signature verification and return the result.
            bool ret = signer.VerifySignature(signature.ToArray());
            return ret;
        }
    }
}