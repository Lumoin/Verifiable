using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Buffers;
using System.Collections.Frozen;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable.BouncyCastle
{
    public static class BouncyCastleCryptographicFunctions
    {
        public static ValueTask<Signature> SignEd25519Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
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


        public static ValueTask<bool> VerifyEd25519Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            var publicKey = new Ed25519PublicKeyParameters(publicKeyMaterial.ToArray(), 0);
            var validator = new Ed25519Signer();
            validator.Init(forSigning: false, publicKey);
            validator.BlockUpdate(dataToVerify.ToArray(), off: 0, len: dataToVerify.Length);

            return ValueTask.FromResult(validator.VerifySignature(signature.ToArray()));
        }


        public static ValueTask<Signature> SignP256Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "secp256r1", CryptoTags.P256Signature, 32);
        }


        public static ValueTask<bool> VerifyP256Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, "secp256r1", 32);
        }


        public static ValueTask<Signature> SignP384Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "secp384r1", CryptoTags.P384Signature, 48);
        }


        public static ValueTask<bool> VerifyP384Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, "secp384r1", 48);
        }


        public static ValueTask<Signature> SignP521Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "secp521r1", CryptoTags.P521Signature, 66);
        }


        public static ValueTask<bool> VerifyP521Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, "secp521r1", 66);
        }


        public static ValueTask<IMemoryOwner<byte>> DeriveX25519SharedSecretAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> publicKeyBytes, MemoryPool<byte> memoryPool)
        {   
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


        public static ValueTask<Signature> SignRsa2048Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return SignRsaPkcs1Async(privateKeyBytes, dataToSign, signaturePool, new Sha256Digest(), CryptoTags.Rsa2048Signature);
        }


        public static ValueTask<bool> VerifyRsa2048Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaPkcs1Async(dataToVerify, signature, publicKeyMaterial, new Sha256Digest());
        }


        public static ValueTask<Signature> SignRsa4096Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return SignRsaPkcs1Async(privateKeyBytes, dataToSign, signaturePool, new Sha256Digest(), CryptoTags.Rsa4096Signature);
        }


        public static ValueTask<bool> VerifyRsa4096Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaPkcs1Async(dataToVerify, signature, publicKeyMaterial, new Sha256Digest());
        }


        public static ValueTask<Signature> SignRsaSha256Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return SignRsaPkcs1Async(privateKeyBytes, dataToSign, signaturePool, new Sha256Digest(), CryptoTags.RsaSha256Pkcs1Signature);
        }


        public static ValueTask<bool> VerifyRsaSha256Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaPkcs1Async(dataToVerify, signature, publicKeyMaterial, new Sha256Digest());
        }


        public static ValueTask<Signature> SignRsaSha256PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return SignRsaPssAsync(privateKeyBytes, dataToSign, signaturePool, new Sha256Digest(), CryptoTags.RsaSha256PssSignature);
        }


        public static ValueTask<bool> VerifyRsaSha256PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaPssAsync(dataToVerify, signature, publicKeyMaterial, new Sha256Digest());
        }


        public static ValueTask<Signature> SignRsaSha384Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return SignRsaPkcs1Async(privateKeyBytes, dataToSign, signaturePool, new Sha384Digest(), CryptoTags.RsaSha384Pkcs1Signature);
        }


        public static ValueTask<bool> VerifyRsaSha384Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaPkcs1Async(dataToVerify, signature, publicKeyMaterial, new Sha384Digest());
        }


        public static ValueTask<Signature> SignRsaSha384PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return SignRsaPssAsync(privateKeyBytes, dataToSign, signaturePool, new Sha384Digest(), CryptoTags.RsaSha384PssSignature);
        }


        public static ValueTask<bool> VerifyRsaSha384PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaPssAsync(dataToVerify, signature, publicKeyMaterial, new Sha384Digest());
        }


        public static ValueTask<Signature> SignRsaSha512Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return SignRsaPkcs1Async(privateKeyBytes, dataToSign, signaturePool, new Sha512Digest(), CryptoTags.RsaSha512Pkcs1Signature);
        }


        public static ValueTask<bool> VerifyRsaSha512Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaPkcs1Async(dataToVerify, signature, publicKeyMaterial, new Sha512Digest());
        }


        public static ValueTask<Signature> SignRsaSha512PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return SignRsaPssAsync(privateKeyBytes, dataToSign, signaturePool, new Sha512Digest(), CryptoTags.RsaSha512PssSignature);
        }


        public static ValueTask<bool> VerifyRsaSha512PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null)
        {
            return VerifyRsaPssAsync(dataToVerify, signature, publicKeyMaterial, new Sha512Digest());
        }


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

            byte[] signatureBytes = new byte[componentSize * 2];
            byte[] rBytes = r.ToByteArrayUnsigned();
            byte[] sBytes = s.ToByteArrayUnsigned();

            Array.Copy(rBytes, 0, signatureBytes, componentSize - rBytes.Length, rBytes.Length);
            Array.Copy(sBytes, 0, signatureBytes, componentSize * 2 - sBytes.Length, sBytes.Length);

            IMemoryOwner<byte> memoryPooledSignature = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryPooledSignature.Memory.Span);

            return ValueTask.FromResult(new Signature(memoryPooledSignature, signatureTag));
        }


        private static ValueTask<bool> VerifyEcdsaAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, string curveName, int componentSize)
        {
            X9ECParameters curveParams = ECNamedCurveTable.GetByName(curveName);
            ECDomainParameters domainParams = new(curveParams.Curve, curveParams.G, curveParams.N, curveParams.H);

            Org.BouncyCastle.Math.EC.ECPoint point = curveParams.Curve.DecodePoint(publicKeyMaterial.ToArray());
            ECPublicKeyParameters publicKey = new(point, domainParams);

            byte[] hash = ComputeHash(dataToVerify.Span, curveName);

            ReadOnlySpan<byte> signatureSpan = signature.Span;
            byte[] rBytes = signatureSpan.Slice(0, componentSize).ToArray();
            byte[] sBytes = signatureSpan.Slice(componentSize, componentSize).ToArray();

            BigInteger r = new(1, rBytes);
            BigInteger s = new(1, sBytes);

            ECDsaSigner verifier = new();
            verifier.Init(forSigning: false, publicKey);

            return ValueTask.FromResult(verifier.VerifySignature(hash, r, s));
        }


        private static ValueTask<Signature> SignRsaPkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, IDigest digest, Tag signatureTag)
        {
            RsaPrivateCrtKeyParameters privateKey = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(privateKeyBytes.ToArray());
            RsaDigestSigner signer = new(digest);
            signer.Init(forSigning: true, privateKey);
            signer.BlockUpdate(dataToSign.ToArray(), 0, dataToSign.Length);

            byte[] signatureBytes = signer.GenerateSignature();
            IMemoryOwner<byte> memoryPooledSignature = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryPooledSignature.Memory.Span);

            return ValueTask.FromResult(new Signature(memoryPooledSignature, signatureTag));
        }


        private static ValueTask<bool> VerifyRsaPkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, IDigest digest)
        {
            RsaKeyParameters publicKey = (RsaKeyParameters)PublicKeyFactory.CreateKey(publicKeyMaterial.ToArray());
            RsaDigestSigner verifier = new(digest);
            verifier.Init(forSigning: false, publicKey);
            verifier.BlockUpdate(dataToVerify.ToArray(), 0, dataToVerify.Length);

            return ValueTask.FromResult(verifier.VerifySignature(signature.ToArray()));
        }


        private static ValueTask<Signature> SignRsaPssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, IDigest digest, Tag signatureTag)
        {
            RsaPrivateCrtKeyParameters privateKey = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(privateKeyBytes.ToArray());
            PssSigner signer = new(new RsaEngine(), digest, digest.GetDigestSize());
            signer.Init(forSigning: true, privateKey);
            signer.BlockUpdate(dataToSign.ToArray(), 0, dataToSign.Length);

            byte[] signatureBytes = signer.GenerateSignature();
            IMemoryOwner<byte> memoryPooledSignature = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryPooledSignature.Memory.Span);

            return ValueTask.FromResult(new Signature(memoryPooledSignature, signatureTag));
        }


        private static ValueTask<bool> VerifyRsaPssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, IDigest digest)
        {
            RsaKeyParameters publicKey = (RsaKeyParameters)PublicKeyFactory.CreateKey(publicKeyMaterial.ToArray());
            PssSigner verifier = new(new RsaEngine(), digest, digest.GetDigestSize());
            verifier.Init(forSigning: false, publicKey);
            verifier.BlockUpdate(dataToVerify.ToArray(), 0, dataToVerify.Length);

            return ValueTask.FromResult(verifier.VerifySignature(signature.ToArray()));
        }


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


        private static IDigest GetDigest(string curveName)
        {
            return curveName switch
            {
                "secp256r1" => new Sha256Digest(),
                "secp384r1" => new Sha384Digest(),
                "secp521r1" => new Sha512Digest(),
                _ => throw new NotSupportedException($"Curve '{curveName}' is not supported.")
            };
        }
    }
}