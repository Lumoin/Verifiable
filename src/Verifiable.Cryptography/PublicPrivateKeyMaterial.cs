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
        where TPublicKeyMemory: PublicKeyMemory
        where TPrivateKeyMemory: PrivateKeyMemory;


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
        where TPublicKeyMemory: PublicKeyMemory
        where TPrivateKeyMemory: PrivateKeyMemory;


    /// <summary>
    /// A transport tuple that briefly holds a public/private key pair together after creation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This type is a non-owning container. It does not implement <see cref="IDisposable"/>
    /// because it does not own the lifetime of the keys it holds. The typical usage pattern is:
    /// </para>
    /// <list type="number">
    /// <item><description>
    /// A factory method (e.g. <see cref="PublicPrivateKeyMaterialExtensions.Create{TPublicKeyMemory, TPrivateKeyMemory}"/>)
    /// creates the pair and returns it in this container.
    /// </description></item>
    /// <item><description>
    /// The caller immediately unpacks the keys. The public key typically goes into a DID document,
    /// credential, or other public structure. The private key goes to secure storage, a signing
    /// operation, or a hardware security module.
    /// </description></item>
    /// <item><description>
    /// Each key's new owner is responsible for its disposal. The container is discarded.
    /// </description></item>
    /// </list>
    /// <para>
    /// Making this type disposable would imply ownership semantics it does not have. Since the
    /// two keys typically transfer to different owners with different lifetimes, a container-level
    /// <c>Dispose</c> would risk double-disposal when the actual owners also dispose the keys.
    /// </para>
    /// <para>
    /// In test scenarios where both keys are used locally, dispose them individually:
    /// </para>
    /// <code>
    /// var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
    /// try
    /// {
    ///     //Use keyPair.PublicKey and keyPair.PrivateKey.
    /// }
    /// finally
    /// {
    ///     keyPair.PublicKey.Dispose();
    ///     keyPair.PrivateKey.Dispose();
    /// }
    /// </code>
    /// </remarks>
    /// <typeparam name="TPublicKeyMemory">The public key memory type.</typeparam>
    /// <typeparam name="TPrivateKeyMemory">The private key memory type.</typeparam>
    /// <param name="PublicKey">The public key.</param>
    /// <param name="PrivateKey">The private key.</param>
    public record class PublicPrivateKeyMaterial<TPublicKeyMemory, TPrivateKeyMemory>(TPublicKeyMemory PublicKey, TPrivateKeyMemory PrivateKey)
        where TPublicKeyMemory: PublicKeyMemory
        where TPrivateKeyMemory: PrivateKeyMemory;


    /// <summary>
    /// Factory methods for creating <see cref="PublicPrivateKeyMaterial{TPublicKeyMemory, TPrivateKeyMemory}"/>
    /// instances through creation delegates.
    /// </summary>
    public static class PublicPrivateKeyMaterialExtensions
    {
        /// <summary>
        /// Creates key material using the specified delegate and memory pool.
        /// </summary>
        /// <typeparam name="TPublicKeyMemory">The public key memory type.</typeparam>
        /// <typeparam name="TPrivateKeyMemory">The private key memory type.</typeparam>
        /// <param name="keyDataPool">The memory pool for key data allocation.</param>
        /// <param name="keyCreator">The delegate that performs the actual key generation.</param>
        /// <returns>A transport tuple containing the generated key pair. The caller assumes
        /// ownership of both keys and is responsible for their disposal.</returns>
        public static PublicPrivateKeyMaterial<TPublicKeyMemory, TPrivateKeyMemory> Create<TPublicKeyMemory, TPrivateKeyMemory>(
            MemoryPool<byte> keyDataPool,
            PublicPrivateKeyCreationDelegate<TPublicKeyMemory, TPrivateKeyMemory> keyCreator)
            where TPublicKeyMemory: PublicKeyMemory
            where TPrivateKeyMemory: PrivateKeyMemory
        {
            ArgumentNullException.ThrowIfNull(keyDataPool);
            ArgumentNullException.ThrowIfNull(keyCreator);

            return keyCreator(keyDataPool);
        }


        /// <summary>
        /// Creates typed key material using the specified delegate and memory pool.
        /// </summary>
        /// <typeparam name="TPublicPrivateKeyMaterial">The key material type.</typeparam>
        /// <typeparam name="TPublicKeyMemory">The public key memory type.</typeparam>
        /// <typeparam name="TPrivateKeyMemory">The private key memory type.</typeparam>
        /// <param name="keyDataPool">The memory pool for key data allocation.</param>
        /// <param name="keyCreator">The delegate that performs the actual key generation.</param>
        /// <returns>A transport tuple containing the generated key pair. The caller assumes
        /// ownership of both keys and is responsible for their disposal.</returns>
        public static TPublicPrivateKeyMaterial Create<TPublicPrivateKeyMaterial, TPublicKeyMemory, TPrivateKeyMemory>(
            MemoryPool<byte> keyDataPool,
            PublicPrivateKeyCreationDelegateWithPool<TPublicPrivateKeyMaterial, TPublicKeyMemory, TPrivateKeyMemory> keyCreator)
            where TPublicPrivateKeyMaterial : PublicPrivateKeyMaterial<TPublicKeyMemory, TPrivateKeyMemory>
            where TPublicKeyMemory: PublicKeyMemory
            where TPrivateKeyMemory: PrivateKeyMemory
        {
            ArgumentNullException.ThrowIfNull(keyDataPool);
            ArgumentNullException.ThrowIfNull(keyCreator);

            return keyCreator(keyDataPool);
        }
    }
}