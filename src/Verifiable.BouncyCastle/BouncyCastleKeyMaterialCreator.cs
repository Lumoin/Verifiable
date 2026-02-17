using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;

namespace Verifiable.BouncyCastle
{
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The caller is responsible for disposing the returned key material instances.")]
    public static class BouncyCastleKeyMaterialCreator
    {
        private static readonly SecureRandom random = new();

        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP256Keys(MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return CreateEcKeys("secp256r1", CryptoTags.P256PublicKey, CryptoTags.P256PrivateKey, memoryPool);
        }

        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP384Keys(MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return CreateEcKeys("secp384r1", CryptoTags.P384PublicKey, CryptoTags.P384PrivateKey, memoryPool);
        }

        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP521Keys(MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return CreateEcKeys("secp521r1", CryptoTags.P521PublicKey, CryptoTags.P521PrivateKey, memoryPool);
        }

        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateSecp256k1Keys(MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return CreateEcKeys("secp256k1", CryptoTags.Secp256k1PublicKey, CryptoTags.Secp256k1PrivateKey, memoryPool);
        }

        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsa2048Keys(MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return CreateRsaKeys(2048, memoryPool);
        }

        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsa4096Keys(MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return CreateRsaKeys(4096, memoryPool);
        }


        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateEd25519Keys(MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            var generator = new Ed25519KeyPairGenerator();
            generator.Init(new Ed25519KeyGenerationParameters(random));
            var keyPair = generator.GenerateKeyPair();

            var publicKey = ((Ed25519PublicKeyParameters)keyPair.Public).GetEncoded();
            var privateKey = ((Ed25519PrivateKeyParameters)keyPair.Private).GetEncoded();

            // Clear the sensitive data from memory as soon as possible
            var publicKeyMemory = new PublicKeyMemory(AsPooledMemory(publicKey, memoryPool), CryptoTags.Ed25519PublicKey);
            var privateKeyMemory = new PrivateKeyMemory(AsPooledMemory(privateKey, memoryPool), CryptoTags.Ed25519PrivateKey);
            Array.Clear(publicKey, 0, publicKey.Length);
            Array.Clear(privateKey, 0, privateKey.Length);

            return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
        }


        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateX25519Keys(MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            var generator = new X25519KeyPairGenerator();
            generator.Init(new X25519KeyGenerationParameters(random));
            var keyPair = generator.GenerateKeyPair();

            var publicKey = ((X25519PublicKeyParameters)keyPair.Public).GetEncoded();
            var privateKey = ((X25519PrivateKeyParameters)keyPair.Private).GetEncoded();

            //Clear the sensitive data from memory as soon as possible.
            var publicKeyMemory = new PublicKeyMemory(AsPooledMemory(publicKey, memoryPool), CryptoTags.X25519PublicKey);
            var privateKeyMemory = new PrivateKeyMemory(AsPooledMemory(privateKey, memoryPool), CryptoTags.X25519PrivateKey);
            Array.Clear(publicKey, 0, publicKey.Length);
            Array.Clear(privateKey, 0, privateKey.Length);

            return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
        }


        /// <summary>
        /// Creates ML-DSA-44 key material (NIST FIPS 204, security level 2).
        /// Public key: 1312 bytes. Private key: 2560 bytes (seed-expanded).
        /// </summary>
        /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
        /// <returns>A new key pair. The caller must dispose each key individually.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlDsa44Keys(MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return CreateMlDsaKeys(MLDsaParameters.ml_dsa_44, memoryPool, CryptoTags.MlDsa44PublicKey, CryptoTags.MlDsa44PrivateKey);
        }


        /// <summary>
        /// Creates ML-DSA-65 key material (NIST FIPS 204, security level 3).
        /// Public key: 1952 bytes. Private key: 4032 bytes (seed-expanded).
        /// </summary>
        /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
        /// <returns>A new key pair. The caller must dispose each key individually.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlDsa65Keys(MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return CreateMlDsaKeys(MLDsaParameters.ml_dsa_65, memoryPool, CryptoTags.MlDsa65PublicKey, CryptoTags.MlDsa65PrivateKey);
        }


        /// <summary>
        /// Creates ML-DSA-87 key material (NIST FIPS 204, security level 5).
        /// Public key: 2592 bytes. Private key: 4896 bytes (seed-expanded).
        /// </summary>
        /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
        /// <returns>A new key pair. The caller must dispose each key individually.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlDsa87Keys(MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return CreateMlDsaKeys(MLDsaParameters.ml_dsa_87, memoryPool, CryptoTags.MlDsa87PublicKey, CryptoTags.MlDsa87PrivateKey);
        }


        /// <summary>
        /// Creates ML-KEM-512 key material (NIST FIPS 203, security level 1).
        /// Public key: 800 bytes. Ciphertext: 768 bytes. Shared secret: 32 bytes.
        /// </summary>
        /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
        /// <returns>A new key pair. The caller must dispose each key individually.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlKem512Keys(MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return CreateMlKemKeys(MLKemParameters.ml_kem_512, memoryPool, CryptoTags.MlKem512PublicKey, CryptoTags.MlKem512PrivateKey);
        }


        /// <summary>
        /// Creates ML-KEM-768 key material (NIST FIPS 203, security level 3).
        /// Public key: 1184 bytes. Ciphertext: 1088 bytes. Shared secret: 32 bytes.
        /// </summary>
        /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
        /// <returns>A new key pair. The caller must dispose each key individually.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlKem768Keys(MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return CreateMlKemKeys(MLKemParameters.ml_kem_768, memoryPool, CryptoTags.MlKem768PublicKey, CryptoTags.MlKem768PrivateKey);
        }


        /// <summary>
        /// Creates ML-KEM-1024 key material (NIST FIPS 203, security level 5).
        /// Public key: 1568 bytes. Ciphertext: 1568 bytes. Shared secret: 32 bytes.
        /// </summary>
        /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
        /// <returns>A new key pair. The caller must dispose each key individually.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlKem1024Keys(MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return CreateMlKemKeys(MLKemParameters.ml_kem_1024, memoryPool, CryptoTags.MlKem1024PublicKey, CryptoTags.MlKem1024PrivateKey);
        }


        private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateEcKeys(
            string secCurveName,
            Tag publicKeyTag,
            Tag privateKeyTag,
            MemoryPool<byte> memoryPool)
        {
            var curve = SecNamedCurves.GetByName(secCurveName);
            var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
            var generator = new ECKeyPairGenerator();
            var random = new SecureRandom();
            var keyGenParam = new ECKeyGenerationParameters(domainParams, random);

            generator.Init(keyGenParam);
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
            var publicKeyParam = (ECPublicKeyParameters)keyPair.Public;
            var privateKeyParam = (ECPrivateKeyParameters)keyPair.Private;

            byte[] compressedPublicKey = publicKeyParam.Q.GetEncoded(compressed: true);
            byte[] privateKeyBytes = privateKeyParam.D.ToByteArrayUnsigned();

            //Normalize private key to fixed curve size.
            int expectedKeySize = (curve.Curve.FieldSize + 7) / 8;
            IMemoryOwner<byte> privateKeyBuffer;

            if(privateKeyBytes.Length < expectedKeySize)
            {
                //Pad with leading zeros using pool.
                privateKeyBuffer = memoryPool.Rent(expectedKeySize);
                privateKeyBuffer.Memory.Span.Clear();
                privateKeyBytes.CopyTo(privateKeyBuffer.Memory.Span[(expectedKeySize - privateKeyBytes.Length)..]);
            }
            else
            {
                privateKeyBuffer = AsPooledMemory(privateKeyBytes, memoryPool);
            }

            var publicKeyMemory = new PublicKeyMemory(AsPooledMemory(compressedPublicKey, memoryPool), publicKeyTag);
            var privateKeyMemory = new PrivateKeyMemory(privateKeyBuffer, privateKeyTag);

            Array.Clear(compressedPublicKey, 0, compressedPublicKey.Length);
            Array.Clear(privateKeyBytes, 0, privateKeyBytes.Length);

            return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
        }


        private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsaKeys(int keySizeInBits, MemoryPool<byte> memoryPool)
        {
            static (Tag PublicKeyTag, Tag PrivateKeyTag) GetTags(int keySizeInBits)
            {
                return keySizeInBits switch
                {
                    2048 => (CryptoTags.Rsa2048PublicKey, CryptoTags.Rsa2048PrivateKey),
                    4096 => (CryptoTags.Rsa4096PublicKey, CryptoTags.Rsa4096PrivateKey),
                    _ => throw new NotSupportedException($"The RSA key size {keySizeInBits} bits is not supported.")
                };
            }

            var generator = new RsaKeyPairGenerator();
            var random = new SecureRandom();
            var keyGenParam = new KeyGenerationParameters(random, keySizeInBits);

            generator.Init(keyGenParam);
            var keyPair = generator.GenerateKeyPair();

            var publicKeyParam = (RsaKeyParameters)keyPair.Public;
            var privateKeyParam = (RsaPrivateCrtKeyParameters)keyPair.Private;

            //Encode the public key modulus in the DID-compatible format.
            byte[] modulusBytes = publicKeyParam.Modulus.ToByteArrayUnsigned();
            byte[] derEncodedPublicKey = RsaUtilities.Encode(modulusBytes);

            //Serialize the private key as PKCS#1 DER, compatible with both backends.
            byte[] privateKeyBytes = RsaPrivateKeyStructure.GetInstance(new RsaPrivateKeyStructure(
                privateKeyParam.Modulus,
                privateKeyParam.PublicExponent,
                privateKeyParam.Exponent,
                privateKeyParam.P,
                privateKeyParam.Q,
                privateKeyParam.DP,
                privateKeyParam.DQ,
                privateKeyParam.QInv)).GetDerEncoded();

            var (publicKeyTag, privateKeyTag) = GetTags(keySizeInBits);
            var publicKeyMemory = new PublicKeyMemory(AsPooledMemory(derEncodedPublicKey, memoryPool), publicKeyTag);
            var privateKeyMemory = new PrivateKeyMemory(AsPooledMemory(privateKeyBytes, memoryPool), privateKeyTag);

            Array.Clear(modulusBytes, 0, modulusBytes.Length);
            Array.Clear(derEncodedPublicKey, 0, derEncodedPublicKey.Length);
            Array.Clear(privateKeyBytes, 0, privateKeyBytes.Length);

            return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
        }


        /// <summary>
        /// Creates ML-DSA key material for the given parameter set. The keys are serialized
        /// as raw encoded bytes via <c>GetEncoded()</c>.
        /// </summary>
        private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlDsaKeys(
            MLDsaParameters parameters,
            MemoryPool<byte> memoryPool,
            Tag publicKeyTag,
            Tag privateKeyTag)
        {
            var keyGenParameters = new MLDsaKeyGenerationParameters(random, parameters);
            var keyPairGen = new MLDsaKeyPairGenerator();
            keyPairGen.Init(keyGenParameters);

            AsymmetricCipherKeyPair keyPair = keyPairGen.GenerateKeyPair();
            byte[] publicKeyBytes = ((MLDsaPublicKeyParameters)keyPair.Public).GetEncoded();
            byte[] privateKeyBytes = ((MLDsaPrivateKeyParameters)keyPair.Private).GetEncoded();

            var publicKeyMemory = new PublicKeyMemory(AsPooledMemory(publicKeyBytes, memoryPool), publicKeyTag);
            var privateKeyMemory = new PrivateKeyMemory(AsPooledMemory(privateKeyBytes, memoryPool), privateKeyTag);

            Array.Clear(publicKeyBytes, 0, publicKeyBytes.Length);
            Array.Clear(privateKeyBytes, 0, privateKeyBytes.Length);

            return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
        }


        /// <summary>
        /// Creates ML-KEM key material for the given parameter set. The keys are serialized
        /// as raw encoded bytes via <c>GetEncoded()</c>.
        /// </summary>
        private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlKemKeys(
            MLKemParameters parameters,
            MemoryPool<byte> memoryPool,
            Tag publicKeyTag,
            Tag privateKeyTag)
        {
            var keyGenParameters = new MLKemKeyGenerationParameters(random, parameters);
            var keyPairGen = new MLKemKeyPairGenerator();
            keyPairGen.Init(keyGenParameters);

            AsymmetricCipherKeyPair keyPair = keyPairGen.GenerateKeyPair();
            byte[] publicKeyBytes = ((MLKemPublicKeyParameters)keyPair.Public).GetEncoded();
            byte[] privateKeyBytes = ((MLKemPrivateKeyParameters)keyPair.Private).GetEncoded();

            var publicKeyMemory = new PublicKeyMemory(AsPooledMemory(publicKeyBytes, memoryPool), publicKeyTag);
            var privateKeyMemory = new PrivateKeyMemory(AsPooledMemory(privateKeyBytes, memoryPool), privateKeyTag);

            Array.Clear(publicKeyBytes, 0, publicKeyBytes.Length);
            Array.Clear(privateKeyBytes, 0, privateKeyBytes.Length);

            return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
        }


        private static IMemoryOwner<byte> AsPooledMemory(byte[] keyBytes, MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(keyBytes);
            ArgumentNullException.ThrowIfNull(memoryPool);
            //It may be that the provided MemoryPool allocates more bytes than asked for.
            //Like the default .NET MemoryPool. But for many of the DID key operations
            //that create string representations of the key material, such as Base58 encoding,
            //it is important that the key material is not padded with zeroes.
            IMemoryOwner<byte> keyBuffer = memoryPool.Rent(keyBytes.Length);
            if(keyBuffer.Memory.Length != keyBytes.Length)
            {
                throw new InvalidOperationException("The rented buffer size does not match the requested size.");
            }

            keyBytes.AsSpan().CopyTo(keyBuffer.Memory.Span.Slice(0, keyBytes.Length));

            return keyBuffer;
        }
    }
}