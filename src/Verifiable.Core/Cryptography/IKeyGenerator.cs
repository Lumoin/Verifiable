using System.Buffers;

namespace Verifiable.Core.Cryptography
{
    /// <summary>
    /// An interface for key generator.
    /// </summary>
    public interface IKeyGenerator
    {
        /// <summary>
        /// Generates a public private key pair of type Ed25519 --> Should <see cref="CryptographyAlgorithmConstants.Ecdh.XYZ split to separate constants and namespace? Maybe!.
        /// </summary>
        /// <param name="keyMemoryPool">The memory pool from which to allocate the public and private key bytes.</param>
        /// <returns>Public and private key memory.</returns>
        (PublicKeyMemory PublicKeyMemory, PrivateKeyMemory PrivateKeyMemory) GenerateEd25519PublicPrivateKeyPair(MemoryPool<byte> keyMemoryPool);

        /// <summary>
        /// Generates a public private key pair.
        /// </summary>
        /// <param name="keyMemoryPool">The memory pool from which to allocate the public and private key bytes.</param>
        /// <returns>Public and private key memory.</returns>
        (PublicKeyMemory PublicKeyMemory, PrivateKeyMemory PrivateKeyMemory) GenerateX25519PublicPrivateKeyPair(MemoryPool<byte> keyMemoryPool);
    }
}
