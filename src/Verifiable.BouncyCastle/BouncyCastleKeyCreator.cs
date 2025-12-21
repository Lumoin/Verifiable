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
    public static class BouncyCastleKeyCreator
    {
        private static readonly SecureRandom random = new();

        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP256Keys(MemoryPool<byte> memoryPool)
        {
            return CreateEcKeys("P-256", memoryPool);
        }

        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP384Keys(MemoryPool<byte> memoryPool)
        {
            return CreateEcKeys("P-384", memoryPool);
        }

        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP521Keys(MemoryPool<byte> memoryPool)
        {
            return CreateEcKeys("P-521", memoryPool);
        }

        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateSecp256k1Keys(MemoryPool<byte> memoryPool)
        {
            return CreateEcKeys("secp256k1", memoryPool);
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
            var publicKeyMemory = new PublicKeyMemory(AsPooledMemory(publicKey, memoryPool), Tag.Ed25519PublicKey);
            var privateKeyMemory = new PrivateKeyMemory(AsPooledMemory(privateKey, memoryPool), Tag.Ed25519PrivateKey);
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
            var publicKeyMemory = new PublicKeyMemory(AsPooledMemory(publicKey, memoryPool), Tag.X25519PublicKey);
            var privateKeyMemory = new PrivateKeyMemory(AsPooledMemory(privateKey, memoryPool), Tag.X25519PrivateKey);
            Array.Clear(publicKey, 0, publicKey.Length);
            Array.Clear(privateKey, 0, privateKey.Length);

            return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
        }


        private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateEcKeys(string namedCurve, MemoryPool<byte> memoryPool)
        {
            static (Tag PublicKeyTag, Tag PrivateKeyTag) GetTags(string namedCurve)
            {
                return namedCurve switch
                {
                    "P-256" => (Tag.P256PublicKey, Tag.P256PrivateKey),
                    "P-384" => (Tag.P384PublicKey, Tag.P384PrivateKey),
                    "P-521" => (Tag.P521PublicKey, Tag.P521PrivateKey),
                    "secp256k1" => (Tag.Secp256k1PublicKey, Tag.Secp256k1PrivateKey),
                    _ => throw new NotSupportedException($"The curve {namedCurve} is not supported.")
                };
            }

            var curve = SecNamedCurves.GetByName(namedCurve);
            var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
            var generator = new ECKeyPairGenerator();
            var random = new SecureRandom();
            var keyGenParam = new ECKeyGenerationParameters(domainParams, random);

            generator.Init(keyGenParam);
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
            var publicKeyParam = (ECPublicKeyParameters)keyPair.Public;
            var privateKeyParam = (ECPrivateKeyParameters)keyPair.Private;

            byte[] compressedPublicKey = publicKeyParam.Q.GetEncoded(compressed: true);
            byte[] privateKeyBytes = privateKeyParam.D.ToByteArray();
            var (publicKeyTag, privateKeyTag) = GetTags(namedCurve);
            var publicKeyMemory = new PublicKeyMemory(AsPooledMemory(compressedPublicKey, memoryPool), publicKeyTag);
            var privateKeyMemory = new PrivateKeyMemory(AsPooledMemory(privateKeyBytes, memoryPool), privateKeyTag);
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
                    2048 => (Tag.Rsa2048PublicKey, Tag.Rsa2048PrivateKey),
                    4096 => (Tag.Rsa4096PublicKey, Tag.Rsa4096PrivateKey),
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
