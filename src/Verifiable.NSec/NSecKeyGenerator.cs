using NSec.Cryptography;
using System;
using System.Buffers;
using Verifiable.Cryptography;
using Key = NSec.Cryptography.Key;

namespace Verifiable.NSec
{
    public static class NSecKeyCreator
    {
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateEd25519Keys(MemoryPool<byte> memoryPool)
        {
            return CreateKeys(SignatureAlgorithm.Ed25519, memoryPool, Tag.Ed25519PublicKey, Tag.Ed25519PrivateKey);
        }

        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateX25519Keys(MemoryPool<byte> memoryPool)
        {
            return CreateKeys(KeyAgreementAlgorithm.X25519, memoryPool, Tag.X25519PublicKey, Tag.X25519PrivateKey);
        }

        

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
