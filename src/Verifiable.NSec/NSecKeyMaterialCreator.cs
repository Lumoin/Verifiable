using NSec.Cryptography;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Key = NSec.Cryptography.Key;

namespace Verifiable.NSec
{
    /// <summary>
    /// Creates key material for NSec-supported algorithms. The caller is responsible
    /// for disposing the individual <see cref="PublicKeyMemory"/> and <see cref="PrivateKeyMemory"/>
    /// instances returned within the key material.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The caller is responsible for disposing the returned key material instances.")]
    public static class NSecKeyMaterialCreator
    {
        /// <summary>
        /// Creates fresh Ed25519 key material using the NSec cryptographic backend.
        /// </summary>
        /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
        /// <returns>A new key pair. The caller is responsible for disposing each key individually.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateEd25519Keys(MemoryPool<byte> memoryPool)
        {
            return CreateKeys(SignatureAlgorithm.Ed25519, memoryPool, CryptoTags.Ed25519PublicKey, CryptoTags.Ed25519PrivateKey);
        }


        /// <summary>
        /// Creates fresh X25519 key material using the NSec cryptographic backend.
        /// </summary>
        /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
        /// <returns>A new key pair. The caller is responsible for disposing each key individually.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateX25519Keys(MemoryPool<byte> memoryPool)
        {
            return CreateKeys(KeyAgreementAlgorithm.X25519, memoryPool, CryptoTags.X25519PublicKey, CryptoTags.X25519PrivateKey);
        }


        /// <summary>
        /// Creates key material for the given NSec algorithm by generating a key pair,
        /// exporting the raw bytes, and wrapping them in pooled memory.
        /// </summary>
        private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateKeys(
            Algorithm algorithm,
            MemoryPool<byte> memoryPool,
            Tag publicKeyTag,
            Tag privateKeyTag)
        {
            using(var key = Key.Create(algorithm, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport }))
            {
                var publicKeyBytes = key.Export(KeyBlobFormat.RawPublicKey);
                var privateKeyBytes = key.Export(KeyBlobFormat.RawPrivateKey);

                var publicKeyMemory = new PublicKeyMemory(AsPooledMemory(publicKeyBytes, memoryPool), publicKeyTag);
                var privateKeyMemory = new PrivateKeyMemory(AsPooledMemory(privateKeyBytes, memoryPool), privateKeyTag);
                Array.Clear(publicKeyBytes, 0, publicKeyBytes.Length);
                Array.Clear(privateKeyBytes, 0, privateKeyBytes.Length);

                return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
            }
        }


        private static IMemoryOwner<byte> AsPooledMemory(byte[] keyBytes, MemoryPool<byte> memoryPool)
        {
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