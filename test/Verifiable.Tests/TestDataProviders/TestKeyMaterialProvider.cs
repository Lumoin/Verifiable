using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Microsoft;

namespace Verifiable.Tests.TestDataProviders
{
    /// <summary>
    /// Provides factory methods for key material creation. Each call returns a fresh,
    /// independently disposable instance so that tests do not share mutable state.
    /// </summary>
    internal static class TestKeyMaterialProvider
    {
        /// <summary>
        /// Creates fresh P-256 key material using the Microsoft cryptographic backend.
        /// </summary>
        /// <returns>A new disposable key pair. The caller is responsible for disposal.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP256KeyMaterial()
            => PublicPrivateKeyMaterialExtensions.Create(SensitiveMemoryPool<byte>.Shared, MicrosoftKeyMaterialCreator.CreateP256Keys);

        /// <summary>
        /// Creates fresh P-384 key material using the Microsoft cryptographic backend.
        /// </summary>
        /// <returns>A new disposable key pair. The caller is responsible for disposal.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP384KeyMaterial()
            => PublicPrivateKeyMaterialExtensions.Create(SensitiveMemoryPool<byte>.Shared, MicrosoftKeyMaterialCreator.CreateP384Keys);

        /// <summary>
        /// Creates fresh P-521 key material using the Microsoft cryptographic backend.
        /// </summary>
        /// <returns>A new disposable key pair. The caller is responsible for disposal.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP521KeyMaterial()
            => PublicPrivateKeyMaterialExtensions.Create(SensitiveMemoryPool<byte>.Shared, MicrosoftKeyMaterialCreator.CreateP521Keys);

        /// <summary>
        /// Creates fresh secp256k1 key material using the BouncyCastle cryptographic backend.
        /// </summary>
        /// <returns>A new disposable key pair. The caller is responsible for disposal.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateSecp256k1KeyMaterial()
            => PublicPrivateKeyMaterialExtensions.Create(SensitiveMemoryPool<byte>.Shared, BouncyCastleKeyMaterialCreator.CreateSecp256k1Keys);

        /// <summary>
        /// Creates fresh RSA 2048 key material using the Microsoft cryptographic backend.
        /// </summary>
        /// <returns>A new disposable key pair. The caller is responsible for disposal.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsa2048KeyMaterial()
            => PublicPrivateKeyMaterialExtensions.Create(SensitiveMemoryPool<byte>.Shared, MicrosoftKeyMaterialCreator.CreateRsa2048Keys);

        /// <summary>
        /// Creates fresh RSA 4096 key material using the Microsoft cryptographic backend.
        /// </summary>
        /// <returns>A new disposable key pair. The caller is responsible for disposal.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsa4096KeyMaterial()
            => PublicPrivateKeyMaterialExtensions.Create(SensitiveMemoryPool<byte>.Shared, MicrosoftKeyMaterialCreator.CreateRsa4096Keys);

        /// <summary>
        /// Creates fresh Ed25519 key material using the BouncyCastle cryptographic backend.
        /// </summary>
        /// <returns>A new disposable key pair. The caller is responsible for disposal.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateEd25519KeyMaterial()
            => PublicPrivateKeyMaterialExtensions.Create(SensitiveMemoryPool<byte>.Shared, BouncyCastleKeyMaterialCreator.CreateEd25519Keys);

        /// <summary>
        /// Creates fresh X25519 key material using the BouncyCastle cryptographic backend.
        /// </summary>
        /// <returns>A new disposable key pair. The caller is responsible for disposal.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateX25519KeyMaterial()
            => PublicPrivateKeyMaterialExtensions.Create(SensitiveMemoryPool<byte>.Shared, BouncyCastleKeyMaterialCreator.CreateX25519Keys);
    }
}