using System;
using System.Buffers;

namespace DotDecentralized.Core.Cryptography
{
    /// <summary>
    /// An interface for key generator.
    /// </summary>
    public interface IKeyGenerator
    {
        /// <summary>
        /// Generates a public private key pair.
        /// </summary>
        /// <param name="keyMemoryPool">The memory pool from which to allocate the public and private key bytes.</param>
        /// <returns>Public and private key memory.</returns>
        Tuple<PublicKeyMemory, PrivateKeyMemory> GenerateEd25519PublicPrivateKeyPair(MemoryPool<byte> keyMemoryPool);
    }
}
