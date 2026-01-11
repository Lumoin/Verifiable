using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable.BouncyCastle
{
    /// <summary>
    /// This class has a collection of adapter functions used in <see cref="SensitiveMemoryKey"/> operations matching delegates in <see cref="SensitiveMemory"/>.
    /// </summary>
    public static class BouncyCastleAlgorithms
    {
        /// <summary>
        /// A function that adapts <see cref="PrivateKey.SignAsync(ReadOnlyMemory{byte}, MemoryPool{byte})"/> with delegate <see cref="SigningFunction{TPrivateKeyBytes, TDataToSign, TResult}"/>.
        /// </summary>
        /// <param name="privateKeyBytes">The private key bytes.</param>
        /// <param name="dataToSign">The data to be signed.</param>
        /// <param name="signaturePool">The pool from where to reserve the memory for <see cref="Signature"/>.</param>
        /// <returns>The signature created from <paramref name="dataToSign"/> using <paramref name="privateKeyBytes"/>.</returns>
        public static ValueTask<Signature> SignEd25519Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool)
        {
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
        /// <param name="publicKeyBytes">The public key bytes.</param>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        public static ValueTask<bool> VerifyEd25519Async(ReadOnlyMemory<byte> publicKeyBytes, ReadOnlyMemory<byte> dataToVerify, Signature signature)
        {
            var publicKey = new Ed25519PublicKeyParameters(publicKeyBytes.ToArray(), 0);
            var validator = new Ed25519Signer();
            validator.Init(forSigning: false, publicKey);
            validator.BlockUpdate(dataToVerify.ToArray(), off: 0, len: dataToVerify.Length);

            return ValueTask.FromResult(validator.VerifySignature(((ReadOnlySpan<byte>)signature).ToArray()));
        }


        /// <summary>
        /// Signs data using ECDSA P-256 (secp256r1) with SHA-256.
        /// </summary>
        /// <param name="privateKeyBytes">The private key D value (32 bytes).</param>
        /// <param name="dataToSign">The data to be signed.</param>
        /// <param name="signaturePool">The pool from where to reserve the memory for <see cref="Signature"/>.</param>
        /// <returns>The signature in IEEE P1363 fixed-length format (64 bytes: r || s).</returns>
        public static ValueTask<Signature> SignP256Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool)
        {
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "secp256r1", CryptoTags.P256Signature, 32);
        }


        /// <summary>
        /// Verifies an ECDSA P-256 (secp256r1) signature.
        /// </summary>
        /// <param name="publicKeyBytes">The compressed public key bytes (33 bytes).</param>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify in IEEE P1363 format (64 bytes).</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        public static ValueTask<bool> VerifyP256Async(ReadOnlyMemory<byte> publicKeyBytes, ReadOnlyMemory<byte> dataToVerify, Signature signature)
        {
            return VerifyEcdsaAsync(publicKeyBytes, dataToVerify, signature, "secp256r1", 32);
        }


        /// <summary>
        /// Signs data using ECDSA P-384 (secp384r1) with SHA-384.
        /// </summary>
        /// <param name="privateKeyBytes">The private key D value (48 bytes).</param>
        /// <param name="dataToSign">The data to be signed.</param>
        /// <param name="signaturePool">The pool from where to reserve the memory for <see cref="Signature"/>.</param>
        /// <returns>The signature in IEEE P1363 fixed-length format (96 bytes: r || s).</returns>
        public static ValueTask<Signature> SignP384Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool)
        {
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "secp384r1", CryptoTags.P384Signature, 48);
        }


        /// <summary>
        /// Verifies an ECDSA P-384 (secp384r1) signature.
        /// </summary>
        /// <param name="publicKeyBytes">The compressed public key bytes (49 bytes).</param>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify in IEEE P1363 format (96 bytes).</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        public static ValueTask<bool> VerifyP384Async(ReadOnlyMemory<byte> publicKeyBytes, ReadOnlyMemory<byte> dataToVerify, Signature signature)
        {
            return VerifyEcdsaAsync(publicKeyBytes, dataToVerify, signature, "secp384r1", 48);
        }


        /// <summary>
        /// Signs data using ECDSA P-521 (secp521r1) with SHA-512.
        /// </summary>
        /// <param name="privateKeyBytes">The private key D value (66 bytes).</param>
        /// <param name="dataToSign">The data to be signed.</param>
        /// <param name="signaturePool">The pool from where to reserve the memory for <see cref="Signature"/>.</param>
        /// <returns>The signature in IEEE P1363 fixed-length format (132 bytes: r || s).</returns>
        public static ValueTask<Signature> SignP521Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool)
        {
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "secp521r1", CryptoTags.P521Signature, 66);
        }


        /// <summary>
        /// Verifies an ECDSA P-521 (secp521r1) signature.
        /// </summary>
        /// <param name="publicKeyBytes">The compressed public key bytes (67 bytes).</param>
        /// <param name="dataToVerify">The data that was signed.</param>
        /// <param name="signature">The signature to verify in IEEE P1363 format (132 bytes).</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        public static ValueTask<bool> VerifyP521Async(ReadOnlyMemory<byte> publicKeyBytes, ReadOnlyMemory<byte> dataToVerify, Signature signature)
        {
            return VerifyEcdsaAsync(publicKeyBytes, dataToVerify, signature, "secp521r1", 66);
        }


        /// <summary>
        /// Generic ECDSA signing implementation using BouncyCastle.
        /// </summary>
        private static ValueTask<Signature> SignEcdsaAsync(
            ReadOnlyMemory<byte> privateKeyBytes,
            ReadOnlyMemory<byte> dataToSign,
            MemoryPool<byte> signaturePool,
            string curveName,
            Tag signatureTag,
            int componentSize)
        {
            //Get the curve parameters.
            X9ECParameters curveParams = ECNamedCurveTable.GetByName(curveName);
            ECDomainParameters domainParams = new(curveParams.Curve, curveParams.G, curveParams.N, curveParams.H);

            //Create private key from D value.
            BigInteger d = new(1, privateKeyBytes.ToArray());
            ECPrivateKeyParameters privateKey = new(d, domainParams);

            //Hash the data first (ECDSA signs the hash, not raw data).
            byte[] hash = ComputeHash(dataToSign.Span, curveName);

            //Sign using deterministic ECDSA (RFC 6979).
            ECDsaSigner signer = new(new HMacDsaKCalculator(GetDigest(curveName)));
            signer.Init(forSigning: true, privateKey);

            BigInteger[] signatureComponents = signer.GenerateSignature(hash);
            BigInteger r = signatureComponents[0];
            BigInteger s = signatureComponents[1];

            //Convert to IEEE P1363 fixed-length format (r || s).
            byte[] signatureBytes = new byte[componentSize * 2];
            byte[] rBytes = r.ToByteArrayUnsigned();
            byte[] sBytes = s.ToByteArrayUnsigned();

            //Pad r and s to fixed length.
            Array.Copy(rBytes, 0, signatureBytes, componentSize - rBytes.Length, rBytes.Length);
            Array.Copy(sBytes, 0, signatureBytes, componentSize * 2 - sBytes.Length, sBytes.Length);

            IMemoryOwner<byte> memoryPooledSignature = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryPooledSignature.Memory.Span);

            return ValueTask.FromResult(new Signature(memoryPooledSignature, signatureTag));
        }


        /// <summary>
        /// Generic ECDSA verification implementation using BouncyCastle.
        /// </summary>
        private static ValueTask<bool> VerifyEcdsaAsync(
            ReadOnlyMemory<byte> publicKeyBytes,
            ReadOnlyMemory<byte> dataToVerify,
            Signature signature,
            string curveName,
            int componentSize)
        {
            //Get the curve parameters.
            X9ECParameters curveParams = ECNamedCurveTable.GetByName(curveName);
            ECDomainParameters domainParams = new(curveParams.Curve, curveParams.G, curveParams.N, curveParams.H);

            //Decode the compressed public key point.
            Org.BouncyCastle.Math.EC.ECPoint point = curveParams.Curve.DecodePoint(publicKeyBytes.ToArray());
            ECPublicKeyParameters publicKey = new(point, domainParams);

            //Hash the data.
            byte[] hash = ComputeHash(dataToVerify.Span, curveName);

            //Extract r and s from IEEE P1363 format.
            ReadOnlySpan<byte> signatureSpan = signature;
            byte[] rBytes = signatureSpan.Slice(0, componentSize).ToArray();
            byte[] sBytes = signatureSpan.Slice(componentSize, componentSize).ToArray();

            BigInteger r = new(1, rBytes);
            BigInteger s = new(1, sBytes);

            //Verify.
            ECDsaSigner verifier = new();
            verifier.Init(forSigning: false, publicKey);

            bool isValid = verifier.VerifySignature(hash, r, s);
            return ValueTask.FromResult(isValid);
        }


        /// <summary>
        /// Computes the appropriate hash for the curve.
        /// </summary>
        private static byte[] ComputeHash(ReadOnlySpan<byte> data, string curveName)
        {
            return curveName switch
            {
                "secp256r1" => SHA256.HashData(data),
                "secp384r1" => SHA384.HashData(data),
                "secp521r1" => SHA512.HashData(data),
                _ => throw new NotSupportedException($"Curve '{curveName}' is not supported.")
            };
        }


        /// <summary>
        /// Gets the appropriate digest for the curve (used in deterministic k calculation).
        /// </summary>
        private static Org.BouncyCastle.Crypto.IDigest GetDigest(string curveName)
        {
            return curveName switch
            {
                "secp256r1" => new Org.BouncyCastle.Crypto.Digests.Sha256Digest(),
                "secp384r1" => new Org.BouncyCastle.Crypto.Digests.Sha384Digest(),
                "secp521r1" => new Org.BouncyCastle.Crypto.Digests.Sha512Digest(),
                _ => throw new NotSupportedException($"Curve '{curveName}' is not supported.")
            };
        }
    }
}