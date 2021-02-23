using DotDecentralized.Core.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Buffers;

namespace DotDecentralized.BouncyCastle
{
    /// <inheritdoc />
    public class BouncyCastleKeyGenerator: IKeyGenerator
    {
        public Tuple<PublicKeyMemory, PrivateKeyMemory> GenerateEd25519PublicPrivateKeyPair(MemoryPool<byte> keyMemoryPool)
        {
            /*var seed = new byte[] { 0x1 };
            var randomnessGenerator = SecureRandom.GetInstance("SHA256PRNG", autoSeed: false);
            randomnessGenerator.SetSeed(seed);*/
            var randomnessGenerator = SecureRandom.GetInstance("SHA256PRNG", autoSeed: true);

            var keyPairGenerator = new Ed25519KeyPairGenerator();
            keyPairGenerator.Init(new Ed25519KeyGenerationParameters(randomnessGenerator));
            var keyPair = keyPairGenerator.GenerateKeyPair();

            ReadOnlySpan<byte> publicKeyBytes = ((Ed25519PublicKeyParameters)keyPair.Public).GetEncoded();
            ReadOnlySpan<byte> privateKeyBytes = ((Ed25519PrivateKeyParameters)keyPair.Private).GetEncoded();

            var publicKeyBuffer = keyMemoryPool.Rent(publicKeyBytes.Length);
            var privateKeyBuffer = keyMemoryPool.Rent(privateKeyBytes.Length);

            publicKeyBytes.CopyTo(publicKeyBuffer.Memory.Span);
            privateKeyBytes.CopyTo(privateKeyBuffer.Memory.Span);

            var publicKey = new PublicKeyMemory(publicKeyBuffer);
            var privateKey = new PrivateKeyMemory(privateKeyBuffer);

            return Tuple.Create(publicKey, privateKey);
        }
    }
}
