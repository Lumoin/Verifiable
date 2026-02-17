using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Microsoft;

namespace Verifiable.Tests.TestDataProviders
{
    /// <summary>
    /// Provides key material for tests. The default <c>Create*KeyMaterial()</c> methods generate
    /// keys once per algorithm and return independently disposable copies on each call, avoiding
    /// expensive repeated generation while preventing shared mutable state between tests.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Because the cached methods always return copies of the same underlying key pair,
    /// tests that require two <em>distinct</em> key pairs (e.g., wrong-key verification tests)
    /// must call <c>CreateFresh*KeyMaterial()</c> instead, which generates a brand-new key pair
    /// on every invocation.
    /// </para>
    /// </remarks>
    internal static class TestKeyMaterialProvider
    {
        private static readonly Lazy<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> P256Source = new(() =>
            MicrosoftKeyMaterialCreator.CreateP256Keys(SensitiveMemoryPool<byte>.Shared));

        private static readonly Lazy<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> P384Source = new(() =>
            MicrosoftKeyMaterialCreator.CreateP384Keys(SensitiveMemoryPool<byte>.Shared));

        private static readonly Lazy<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> P521Source = new(() =>
            MicrosoftKeyMaterialCreator.CreateP521Keys(SensitiveMemoryPool<byte>.Shared));

        private static readonly Lazy<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> Secp256k1Source = new(() =>
            BouncyCastleKeyMaterialCreator.CreateSecp256k1Keys(SensitiveMemoryPool<byte>.Shared));

        private static readonly Lazy<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> Rsa2048Source = new(() =>
            MicrosoftKeyMaterialCreator.CreateRsa2048Keys(SensitiveMemoryPool<byte>.Shared));

        private static readonly Lazy<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> Rsa4096Source = new(() =>
            MicrosoftKeyMaterialCreator.CreateRsa4096Keys(SensitiveMemoryPool<byte>.Shared));

        private static readonly Lazy<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> Ed25519Source = new(() =>
            BouncyCastleKeyMaterialCreator.CreateEd25519Keys(SensitiveMemoryPool<byte>.Shared));

        private static readonly Lazy<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> X25519Source = new(() =>
            BouncyCastleKeyMaterialCreator.CreateX25519Keys(SensitiveMemoryPool<byte>.Shared));

        private static readonly Lazy<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> MlDsa44Source = new(() =>
            BouncyCastleKeyMaterialCreator.CreateMlDsa44Keys(SensitiveMemoryPool<byte>.Shared));

        private static readonly Lazy<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> MlDsa65Source = new(() =>
            BouncyCastleKeyMaterialCreator.CreateMlDsa65Keys(SensitiveMemoryPool<byte>.Shared));

        private static readonly Lazy<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> MlDsa87Source = new(() =>
            BouncyCastleKeyMaterialCreator.CreateMlDsa87Keys(SensitiveMemoryPool<byte>.Shared));

        private static readonly Lazy<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> MlKem512Source = new(() =>
            BouncyCastleKeyMaterialCreator.CreateMlKem512Keys(SensitiveMemoryPool<byte>.Shared));

        private static readonly Lazy<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> MlKem768Source = new(() =>
            BouncyCastleKeyMaterialCreator.CreateMlKem768Keys(SensitiveMemoryPool<byte>.Shared));

        private static readonly Lazy<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> MlKem1024Source = new(() =>
            BouncyCastleKeyMaterialCreator.CreateMlKem1024Keys(SensitiveMemoryPool<byte>.Shared));


        /// <summary>
        /// Returns a disposable copy of P-256 key material (Microsoft backend).
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP256KeyMaterial()
            => CopyKeyMaterial(P256Source.Value);

        /// <summary>
        /// Returns a disposable copy of P-384 key material (Microsoft backend).
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP384KeyMaterial()
            => CopyKeyMaterial(P384Source.Value);

        /// <summary>
        /// Returns a disposable copy of P-521 key material (Microsoft backend).
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP521KeyMaterial()
            => CopyKeyMaterial(P521Source.Value);

        /// <summary>
        /// Returns a disposable copy of secp256k1 key material (BouncyCastle backend).
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateSecp256k1KeyMaterial()
            => CopyKeyMaterial(Secp256k1Source.Value);

        /// <summary>
        /// Returns a disposable copy of RSA-2048 key material (Microsoft backend).
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsa2048KeyMaterial()
            => CopyKeyMaterial(Rsa2048Source.Value);

        /// <summary>
        /// Returns a disposable copy of RSA-4096 key material (Microsoft backend).
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsa4096KeyMaterial()
            => CopyKeyMaterial(Rsa4096Source.Value);

        /// <summary>
        /// Returns a disposable copy of Ed25519 key material (BouncyCastle backend).
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateEd25519KeyMaterial()
            => CopyKeyMaterial(Ed25519Source.Value);

        /// <summary>
        /// Returns a disposable copy of X25519 key material (BouncyCastle backend).
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateX25519KeyMaterial()
            => CopyKeyMaterial(X25519Source.Value);

        /// <summary>
        /// Returns a disposable copy of ML-DSA-44 key material (BouncyCastle backend, NIST security level 2).
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlDsa44KeyMaterial()
            => CopyKeyMaterial(MlDsa44Source.Value);

        /// <summary>
        /// Returns a disposable copy of ML-DSA-65 key material (BouncyCastle backend, NIST security level 3).
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlDsa65KeyMaterial()
            => CopyKeyMaterial(MlDsa65Source.Value);

        /// <summary>
        /// Returns a disposable copy of ML-DSA-87 key material (BouncyCastle backend, NIST security level 5).
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlDsa87KeyMaterial()
            => CopyKeyMaterial(MlDsa87Source.Value);

        /// <summary>
        /// Returns a disposable copy of ML-KEM-512 key material (BouncyCastle backend, NIST security level 1).
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlKem512KeyMaterial()
            => CopyKeyMaterial(MlKem512Source.Value);

        /// <summary>
        /// Returns a disposable copy of ML-KEM-768 key material (BouncyCastle backend, NIST security level 3).
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlKem768KeyMaterial()
            => CopyKeyMaterial(MlKem768Source.Value);

        /// <summary>
        /// Returns a disposable copy of ML-KEM-1024 key material (BouncyCastle backend, NIST security level 5).
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlKem1024KeyMaterial()
            => CopyKeyMaterial(MlKem1024Source.Value);


        /// <summary>
        /// Generates a brand-new P-256 key pair. Use when tests require distinct keys
        /// (e.g., wrong-key verification scenarios).
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateFreshP256KeyMaterial()
            => MicrosoftKeyMaterialCreator.CreateP256Keys(SensitiveMemoryPool<byte>.Shared);

        /// <summary>
        /// Generates a brand-new P-384 key pair. Use when tests require distinct keys.
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateFreshP384KeyMaterial()
            => MicrosoftKeyMaterialCreator.CreateP384Keys(SensitiveMemoryPool<byte>.Shared);

        /// <summary>
        /// Generates a brand-new P-521 key pair. Use when tests require distinct keys.
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateFreshP521KeyMaterial()
            => MicrosoftKeyMaterialCreator.CreateP521Keys(SensitiveMemoryPool<byte>.Shared);

        /// <summary>
        /// Generates a brand-new secp256k1 key pair. Use when tests require distinct keys.
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateFreshSecp256k1KeyMaterial()
            => BouncyCastleKeyMaterialCreator.CreateSecp256k1Keys(SensitiveMemoryPool<byte>.Shared);

        /// <summary>
        /// Generates a brand-new RSA-2048 key pair. Use when tests require distinct keys.
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateFreshRsa2048KeyMaterial()
            => MicrosoftKeyMaterialCreator.CreateRsa2048Keys(SensitiveMemoryPool<byte>.Shared);

        /// <summary>
        /// Generates a brand-new RSA-4096 key pair. Use when tests require distinct keys.
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateFreshRsa4096KeyMaterial()
            => MicrosoftKeyMaterialCreator.CreateRsa4096Keys(SensitiveMemoryPool<byte>.Shared);

        /// <summary>
        /// Generates a brand-new Ed25519 key pair. Use when tests require distinct keys.
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateFreshEd25519KeyMaterial()
            => BouncyCastleKeyMaterialCreator.CreateEd25519Keys(SensitiveMemoryPool<byte>.Shared);

        /// <summary>
        /// Generates a brand-new ML-DSA-44 key pair. Use when tests require distinct keys.
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateFreshMlDsa44KeyMaterial()
            => BouncyCastleKeyMaterialCreator.CreateMlDsa44Keys(SensitiveMemoryPool<byte>.Shared);

        /// <summary>
        /// Generates a brand-new ML-DSA-65 key pair. Use when tests require distinct keys.
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateFreshMlDsa65KeyMaterial()
            => BouncyCastleKeyMaterialCreator.CreateMlDsa65Keys(SensitiveMemoryPool<byte>.Shared);

        /// <summary>
        /// Generates a brand-new ML-DSA-87 key pair. Use when tests require distinct keys.
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateFreshMlDsa87KeyMaterial()
            => BouncyCastleKeyMaterialCreator.CreateMlDsa87Keys(SensitiveMemoryPool<byte>.Shared);

        /// <summary>
        /// Generates a brand-new ML-KEM-512 key pair. Use when tests require distinct keys.
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateFreshMlKem512KeyMaterial()
            => BouncyCastleKeyMaterialCreator.CreateMlKem512Keys(SensitiveMemoryPool<byte>.Shared);

        /// <summary>
        /// Generates a brand-new ML-KEM-768 key pair. Use when tests require distinct keys.
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateFreshMlKem768KeyMaterial()
            => BouncyCastleKeyMaterialCreator.CreateMlKem768Keys(SensitiveMemoryPool<byte>.Shared);

        /// <summary>
        /// Generates a brand-new ML-KEM-1024 key pair. Use when tests require distinct keys.
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateFreshMlKem1024KeyMaterial()
            => BouncyCastleKeyMaterialCreator.CreateMlKem1024Keys(SensitiveMemoryPool<byte>.Shared);


        /// <summary>
        /// Creates an independently disposable deep copy of the source key material.
        /// The copy allocates from <see cref="SensitiveMemoryPool{T}"/> and preserves the
        /// original <see cref="Tag"/> metadata on each key.
        /// </summary>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The caller is responsible for disposing the returned key material instances.")]
        private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CopyKeyMaterial(
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> source)
        {
            var publicKeyCopy = CopyPublicKey(source.PublicKey);
            var privateKeyCopy = CopyPrivateKey(source.PrivateKey);

            return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyCopy, privateKeyCopy);
        }


        private static PublicKeyMemory CopyPublicKey(PublicKeyMemory source)
        {
            ReadOnlySpan<byte> bytes = source.AsReadOnlySpan();
            IMemoryOwner<byte> buffer = SensitiveMemoryPool<byte>.Shared.Rent(bytes.Length);
            bytes.CopyTo(buffer.Memory.Span);

            return new PublicKeyMemory(buffer, source.Tag);
        }


        private static PrivateKeyMemory CopyPrivateKey(PrivateKeyMemory source)
        {
            ReadOnlySpan<byte> bytes = source.AsReadOnlySpan();
            IMemoryOwner<byte> buffer = SensitiveMemoryPool<byte>.Shared.Rent(bytes.Length);
            bytes.CopyTo(buffer.Memory.Span);

            return new PrivateKeyMemory(buffer, source.Tag);
        }
    }
}