using DotDecentralized.Core.Cryptography;
using NSec.Cryptography;
using System;
using System.Buffers;

namespace DotDecentralized.NSec
{
    /// <inheritdoc />
    public class NSecKeyGenerator: IKeyGenerator
    {
        /// <inheritdoc />
        public Tuple<PublicKeyMemory, PrivateKeyMemory> GenerateEd25519PublicPrivateKeyPair(MemoryPool<byte> keyMemoryPool)
        {
            var algorithm = SignatureAlgorithm.Ed25519;
            var creationParameters = new KeyCreationParameters
            {
                ExportPolicy = KeyExportPolicies.AllowPlaintextExport
            };

            using(var publicPrivateKey = global::NSec.Cryptography.Key.Create(algorithm, creationParameters))
            {
                ReadOnlySpan<byte> publicKeyBytes = publicPrivateKey.Export(KeyBlobFormat.RawPublicKey);
                ReadOnlySpan<byte> privateKeyBytes = publicPrivateKey.Export(KeyBlobFormat.RawPrivateKey);

                var publicKeyBuffer = keyMemoryPool.Rent(publicKeyBytes.Length);
                var privateKeyBuffer = keyMemoryPool.Rent(privateKeyBytes.Length);

                privateKeyBytes.CopyTo(privateKeyBuffer.Memory.Span);
                publicKeyBytes.CopyTo(publicKeyBuffer.Memory.Span);

                var publicKey = new PublicKeyMemory(publicKeyBuffer);
                var privateKey = new PrivateKeyMemory(privateKeyBuffer);

                return Tuple.Create(publicKey, privateKey);
            }
        }
    }
}
