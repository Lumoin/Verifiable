using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Buffers;
using Verifiable.Cryptography;

namespace Verifiable.BouncyCastle
{
    public static class BouncyCastleKeyMaterialCreator
    {
        private static readonly SecureRandom random = new();

        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP256Keys(MemoryPool<byte> memoryPool)
        {
            return CreateEcKeys("secp256r1", CryptoTags.P256PublicKey, CryptoTags.P256PrivateKey, memoryPool);
        }

        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP384Keys(MemoryPool<byte> memoryPool)
        {
            return CreateEcKeys("secp384r1", CryptoTags.P384PublicKey, CryptoTags.P384PrivateKey, memoryPool);
        }

        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP521Keys(MemoryPool<byte> memoryPool)
        {
            return CreateEcKeys("secp521r1", CryptoTags.P521PublicKey, CryptoTags.P521PrivateKey, memoryPool);
        }

        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateSecp256k1Keys(MemoryPool<byte> memoryPool)
        {
            return CreateEcKeys("secp256k1", CryptoTags.Secp256k1PublicKey, CryptoTags.Secp256k1PrivateKey, memoryPool);
        }

        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsa2048Keys(MemoryPool<byte> memoryPool)
        {
            return CreateRsaKeys(2048, memoryPool);
        }

        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsa4096Keys(MemoryPool<byte> memoryPool)
        {
            return CreateRsaKeys(4096, memoryPool);
        }


        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateEd25519Keys(MemoryPool<byte> memoryPool)
        {
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
            var generator = new X25519KeyPairGenerator();
            generator.Init(new X25519KeyGenerationParameters(random));
            var keyPair = generator.GenerateKeyPair();

            var publicKey = ((X25519PublicKeyParameters)keyPair.Public).GetEncoded();
            var privateKey = ((X25519PrivateKeyParameters)keyPair.Private).GetEncoded();

            // Clear the sensitive data from memory as soon as possible
            var publicKeyMemory = new PublicKeyMemory(AsPooledMemory(publicKey, memoryPool), CryptoTags.X25519PublicKey);
            var privateKeyMemory = new PrivateKeyMemory(AsPooledMemory(privateKey, memoryPool), CryptoTags.X25519PrivateKey);
            Array.Clear(publicKey, 0, publicKey.Length);
            Array.Clear(privateKey, 0, privateKey.Length);

            return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
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

            // Cast to RsaPublic/PrivateKeyParameters
            var publicKeyParam = (RsaKeyParameters)keyPair.Public;
            var privateKeyParam = (RsaPrivateCrtKeyParameters)keyPair.Private;

            // Get public key modulus and private key 'D' bytes
            byte[] modulusBytes = publicKeyParam.Modulus.ToByteArray();
            byte[] privateKeyBytes = privateKeyParam.Exponent.ToByteArray();

            // Encode public key modulus
            byte[] derEncodedPublicKey = RsaUtilities.Encode(modulusBytes);

            var (publicKeyTag, privateKeyTag) = GetTags(keySizeInBits);
            var publicKeyMemory = new PublicKeyMemory(AsPooledMemory(derEncodedPublicKey, memoryPool), publicKeyTag);
            var privateKeyMemory = new PrivateKeyMemory(AsPooledMemory(privateKeyBytes, memoryPool), privateKeyTag);

            // Clear sensitive data from memory
            Array.Clear(modulusBytes, 0, modulusBytes.Length);
            Array.Clear(privateKeyBytes, 0, privateKeyBytes.Length);
            Array.Clear(derEncodedPublicKey, 0, derEncodedPublicKey.Length);

            return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
        }


        private static IMemoryOwner<byte> AsPooledMemory(byte[] keyBytes, MemoryPool<byte> memoryPool)
        {
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