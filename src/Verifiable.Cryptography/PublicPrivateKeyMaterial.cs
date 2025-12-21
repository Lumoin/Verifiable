using System.Buffers;

namespace Verifiable.Cryptography
{
    /// <summary>
    /// Delegate for creating public/private key material using a memory pool.
    /// </summary>
    /// <typeparam name="TPublicKeyMemory">The public key memory type.</typeparam>
    /// <typeparam name="TPrivateKeyMemory">The private key memory type.</typeparam>
    /// <param name="keyDataPool">The memory pool for key data allocation.</param>
    /// <returns>The created key material.</returns>
    public delegate PublicPrivateKeyMaterial<TPublicKeyMemory, TPrivateKeyMemory> PublicPrivateKeyCreationDelegate<TPublicKeyMemory, TPrivateKeyMemory>(MemoryPool<byte> keyDataPool)
        where TPublicKeyMemory : PublicKeyMemory
        where TPrivateKeyMemory : PrivateKeyMemory;


    /// <summary>
    /// Delegate for creating typed public/private key material using a memory pool.
    /// </summary>
    /// <typeparam name="TPublicPrivateKeyMaterial">The key material type.</typeparam>
    /// <typeparam name="TPublicKeyMemory">The public key memory type.</typeparam>
    /// <typeparam name="TPrivateKeyMemory">The private key memory type.</typeparam>
    /// <param name="keyDataPool">The memory pool for key data allocation.</param>
    /// <returns>The created key material.</returns>
    public delegate TPublicPrivateKeyMaterial PublicPrivateKeyCreationDelegateWithPool<TPublicPrivateKeyMaterial, TPublicKeyMemory, TPrivateKeyMemory>(MemoryPool<byte> keyDataPool)
        where TPublicPrivateKeyMaterial : PublicPrivateKeyMaterial<TPublicKeyMemory, TPrivateKeyMemory>
        where TPublicKeyMemory : PublicKeyMemory
        where TPrivateKeyMemory : PrivateKeyMemory;


    /// <summary>
    /// Holds a public/private key pair with type-safe memory management.
    /// </summary>
    /// <typeparam name="TPublicKeyMemory">The public key memory type.</typeparam>
    /// <typeparam name="TPrivateKeyMemory">The private key memory type.</typeparam>
    /// <param name="PublicKey">The public key.</param>
    /// <param name="PrivateKey">The private key.</param>
    public record class PublicPrivateKeyMaterial<TPublicKeyMemory, TPrivateKeyMemory>(TPublicKeyMemory PublicKey, TPrivateKeyMemory PrivateKey)
        where TPublicKeyMemory : PublicKeyMemory
        where TPrivateKeyMemory : PrivateKeyMemory;


    /// <summary>
    /// Extension methods for creating key material.
    /// </summary>
    public static class PublicPrivateKeyMaterialExtensions
    {
        /// <summary>
        /// Creates key material using the specified delegate and memory pool.
        /// </summary>
        public static PublicPrivateKeyMaterial<TPublicKeyMemory, TPrivateKeyMemory> Create<TPublicKeyMemory, TPrivateKeyMemory>(
            MemoryPool<byte> keyDataPool,
            PublicPrivateKeyCreationDelegate<TPublicKeyMemory, TPrivateKeyMemory> keyLoader)
            where TPublicKeyMemory : PublicKeyMemory
            where TPrivateKeyMemory : PrivateKeyMemory
        {
            return keyLoader(keyDataPool);
        }


        /// <summary>
        /// Creates typed key material using the specified delegate and memory pool.
        /// </summary>
        public static TPublicPrivateKeyMaterial Create<TPublicPrivateKeyMaterial, TPublicKeyMemory, TPrivateKeyMemory>(
            MemoryPool<byte> keyDataPool,
            PublicPrivateKeyCreationDelegateWithPool<TPublicPrivateKeyMaterial, TPublicKeyMemory, TPrivateKeyMemory> keyLoader)
            where TPublicPrivateKeyMaterial : PublicPrivateKeyMaterial<TPublicKeyMemory, TPrivateKeyMemory>
            where TPublicKeyMemory : PublicKeyMemory
            where TPrivateKeyMemory : PrivateKeyMemory
        {
            return keyLoader(keyDataPool);
        }
    }
}