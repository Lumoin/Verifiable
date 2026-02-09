using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Verifiable.Cryptography;


namespace Verifiable.Microsoft
{
    /// <summary>
    /// Creates cryptographic key material using .NET's built-in cryptographic providers.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The caller is responsible for disposing the returned key material instances.")]
    public static class MicrosoftKeyMaterialCreator
    {
        /// <summary>
        /// Creates a P-256 (secp256r1/prime256v1) key pair.
        /// </summary>
        /// <param name="memoryPool">The memory pool for key data allocation.</param>
        /// <returns>The public and private key material.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP256Keys(MemoryPool<byte> memoryPool)
        {
            return CreateEcKeys(ECCurve.NamedCurves.nistP256, memoryPool);
        }


        /// <summary>
        /// Creates a P-384 (secp384r1) key pair.
        /// </summary>
        /// <param name="memoryPool">The memory pool for key data allocation.</param>
        /// <returns>The public and private key material.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP384Keys(MemoryPool<byte> memoryPool)
        {
            return CreateEcKeys(ECCurve.NamedCurves.nistP384, memoryPool);
        }


        /// <summary>
        /// Creates a P-521 (secp521r1) key pair.
        /// </summary>
        /// <param name="memoryPool">The memory pool for key data allocation.</param>
        /// <returns>The public and private key material.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP521Keys(MemoryPool<byte> memoryPool)
        {
            return CreateEcKeys(ECCurve.NamedCurves.nistP521, memoryPool);
        }


        /// <summary>
        /// Creates a secp256k1 key pair.
        /// </summary>
        /// <param name="memoryPool">The memory pool for key data allocation.</param>
        /// <returns>The public and private key material.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateSecp256k1Keys(MemoryPool<byte> memoryPool)
        {
            return CreateEcKeys(ECCurve.CreateFromFriendlyName("secP256k1"), memoryPool);
        }


        /// <summary>
        /// Creates an RSA 2048-bit key pair.
        /// </summary>
        /// <param name="memoryPool">The memory pool for key data allocation.</param>
        /// <returns>The public and private key material.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsa2048Keys(MemoryPool<byte> memoryPool)
        {
            return CreateRsaKeys(2048, memoryPool);
        }


        /// <summary>
        /// Creates an RSA 4096-bit key pair.
        /// </summary>
        /// <param name="memoryPool">The memory pool for key data allocation.</param>
        /// <returns>The public and private key material.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsa4096Keys(MemoryPool<byte> memoryPool)
        {
            return CreateRsaKeys(4096, memoryPool);
        }


        private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateEcKeys(ECCurve namedCurve, MemoryPool<byte> memoryPool)
        {
            static (Tag PublicKeyTag, Tag PrivateKeyTag) GetTags(ECCurve namedCurve)
            {
                return namedCurve.Oid.FriendlyName switch
                {
                    "nistP256" => (CryptoTags.P256PublicKey, CryptoTags.P256PrivateKey),
                    "nistP384" => (CryptoTags.P384PublicKey, CryptoTags.P384PrivateKey),
                    "nistP521" => (CryptoTags.P521PublicKey, CryptoTags.P521PrivateKey),
                    "secP256k1" => (CryptoTags.Secp256k1PublicKey, CryptoTags.Secp256k1PrivateKey),
                    _ => throw new NotSupportedException($"The curve {namedCurve.Oid.FriendlyName} is not supported.")
                };
            }

            using(var key = ECDsa.Create(namedCurve))
            {
                ECParameters parameters = key.ExportParameters(includePrivateParameters: true);
                byte[] compressedKeyMaterial = EllipticCurveUtilities.Compress(parameters.Q.X, parameters.Q.Y);

                var (publicKeyTag, privateKeyTag) = GetTags(namedCurve);
                var publicKeyMemory = new PublicKeyMemory(AsPooledMemory(compressedKeyMaterial, memoryPool), publicKeyTag);
                var privateKeyMemory = new PrivateKeyMemory(AsPooledMemory(parameters.D!, memoryPool), privateKeyTag);

                CryptographicOperations.ZeroMemory(compressedKeyMaterial);
                CryptographicOperations.ZeroMemory(parameters.Q.X);
                CryptographicOperations.ZeroMemory(parameters.Q.Y);
                CryptographicOperations.ZeroMemory(parameters.D);

                return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
            }
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

            using(var key = RSA.Create(keySizeInBits))
            {
                RSAParameters parameters = key.ExportParameters(includePrivateParameters: true);
                byte[] derEncodedPublicKey = RsaUtilities.Encode(parameters.Modulus!);

                var (publicKeyTag, privateKeyTag) = GetTags(keySizeInBits);
                var publicKeyMemory = new PublicKeyMemory(AsPooledMemory(derEncodedPublicKey, memoryPool), publicKeyTag);
                var privateKeyMemory = new PrivateKeyMemory(AsPooledMemory(key.ExportRSAPrivateKey(), memoryPool), privateKeyTag);

                CryptographicOperations.ZeroMemory(derEncodedPublicKey);
                CryptographicOperations.ZeroMemory(parameters.Modulus);
                CryptographicOperations.ZeroMemory(parameters.D);

                return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
            }
        }


        private static IMemoryOwner<byte> AsPooledMemory(byte[] keyBytes, MemoryPool<byte> memoryPool)
        {
            //The default .NET MemoryPool may allocate more bytes than requested.
            //For DID key operations that create string representations (e.g., Base58),
            //the key material must not be padded with zeroes.
            IMemoryOwner<byte> keyBuffer = memoryPool.Rent(keyBytes.Length);
            keyBytes.AsSpan().CopyTo(keyBuffer.Memory.Span.Slice(0, keyBytes.Length));

            return keyBuffer;
        }
    }
}