using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Provider;
using CryptoLibraryInfo = Verifiable.Cryptography.Provider.CryptoLibrary;

namespace Verifiable.Libsodium
{
    /// <summary>
    /// Creates key material for libsodium-supported algorithms (Ed25519, X25519). The caller is
    /// responsible for disposing the individual <see cref="PublicKeyMemory"/> and
    /// <see cref="PrivateKeyMemory"/> instances returned within the key material.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The caller is responsible for disposing the returned key material instances.")]
    public static class LibsodiumKeyMaterialCreator
    {
        /// <summary>
        /// Identifies this assembly (name and version) as the provider library for CBOM/telemetry attribution.
        /// </summary>
        private static ProviderLibrary ProviderLib { get; } = new(
            typeof(LibsodiumKeyMaterialCreator).Assembly.GetName().Name ?? "Verifiable.Libsodium",
            typeof(LibsodiumKeyMaterialCreator).Assembly.GetName().Version?.ToString() ?? "Unknown");

        /// <summary>
        /// Identifies the native libsodium library for CBOM/telemetry attribution. The native libsodium binary
        /// is wrapped directly by this project's own binding rather than by an intermediate managed wrapper,
        /// so the native library's own version string is the meaningful CBOM identifier.
        /// </summary>
        private static CryptoLibraryInfo CryptoLib { get; } = new("libsodium", LibsodiumNativeMethods.GetVersionString());

        /// <summary>
        /// Identifies this class as the provider class for CBOM/telemetry attribution.
        /// </summary>
        private static ProviderClass ProviderCls { get; } = new(nameof(LibsodiumKeyMaterialCreator));


        /// <summary>
        /// Creates fresh Ed25519 key material using the libsodium cryptographic backend.
        /// </summary>
        /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
        /// <returns>A new key pair. The caller is responsible for disposing each key individually.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateEd25519Keys(BaseMemoryPool memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            LibsodiumNativeMethods.EnsureInitialized();

            ProviderOperation operation = new(nameof(CreateEd25519Keys));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.KeyGen);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                CryptoAlgorithm keyAlgorithm = CryptoTags.Ed25519PrivateKey.Get<CryptoAlgorithm>();
                activity.SetTag(CryptoTelemetry.Key.AlgorithmCode, keyAlgorithm.Algorithm.ToString(CultureInfo.InvariantCulture));
                activity.SetTag(CryptoTelemetry.Key.Algorithm, keyAlgorithm.ToString());
                activity.SetTag(CryptoTelemetry.Key.Type, "private-key");
            }

            IMemoryOwner<byte> publicKeyOwner = memoryPool.Rent(LibsodiumNativeMethods.Ed25519PublicKeyLength);
            IMemoryOwner<byte> privateKeyOwner = memoryPool.Rent(LibsodiumNativeMethods.Ed25519SeedLength);

            Span<byte> seed = stackalloc byte[LibsodiumNativeMethods.Ed25519SeedLength];
            LibsodiumNativeMethods.randombytes_buf(seed, (nuint)seed.Length);

            try
            {
                using IMemoryOwner<byte> secretKeyScratchOwner = LibsodiumNativeMethods.AllocateSecretKeyScratch(
                    "libsodium failed to allocate secure scratch memory for Ed25519 key generation.");
                using MemoryHandle secretKeyScratchHandle = secretKeyScratchOwner.Memory.Pin();

                nint secretKeyScratch;
                unsafe
                {
                    secretKeyScratch = (nint)secretKeyScratchHandle.Pointer;
                }

                int keypairResult = LibsodiumNativeMethods.crypto_sign_seed_keypair(
                    publicKeyOwner.Memory.Span[..LibsodiumNativeMethods.Ed25519PublicKeyLength], secretKeyScratch, seed);
                if(keypairResult != 0)
                {
                    throw new CryptographicException("libsodium failed to generate an Ed25519 keypair.");
                }

                seed.CopyTo(privateKeyOwner.Memory.Span[..LibsodiumNativeMethods.Ed25519SeedLength]);
            }
            catch
            {
                publicKeyOwner.Dispose();
                privateKeyOwner.Dispose();
                throw;
            }
            finally
            {
                seed.Clear();
            }

            var publicKeyMemory = new PublicKeyMemory(publicKeyOwner, CryptoTags.Ed25519PublicKey);
            var privateKeyMemory = new PrivateKeyMemory(privateKeyOwner, CryptoTags.Ed25519PrivateKey);

            return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
        }


        /// <summary>
        /// Creates fresh X25519 key material using the libsodium cryptographic backend.
        /// </summary>
        /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
        /// <returns>A new key pair. The caller is responsible for disposing each key individually.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateX25519Keys(BaseMemoryPool memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            LibsodiumNativeMethods.EnsureInitialized();

            ProviderOperation operation = new(nameof(CreateX25519Keys));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.KeyGen);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                CryptoAlgorithm keyAlgorithm = CryptoTags.X25519PrivateKey.Get<CryptoAlgorithm>();
                activity.SetTag(CryptoTelemetry.Key.AlgorithmCode, keyAlgorithm.Algorithm.ToString(CultureInfo.InvariantCulture));
                activity.SetTag(CryptoTelemetry.Key.Algorithm, keyAlgorithm.ToString());
                activity.SetTag(CryptoTelemetry.Key.Type, "private-key");
            }

            IMemoryOwner<byte> privateKeyOwner = memoryPool.Rent(LibsodiumNativeMethods.X25519ScalarLength);
            LibsodiumNativeMethods.randombytes_buf(
                privateKeyOwner.Memory.Span[..LibsodiumNativeMethods.X25519ScalarLength], (nuint)LibsodiumNativeMethods.X25519ScalarLength);

            IMemoryOwner<byte> publicKeyOwner = memoryPool.Rent(LibsodiumNativeMethods.X25519PointLength);
            int scalarMultResult = LibsodiumNativeMethods.crypto_scalarmult_base(
                publicKeyOwner.Memory.Span[..LibsodiumNativeMethods.X25519PointLength],
                privateKeyOwner.Memory.Span[..LibsodiumNativeMethods.X25519ScalarLength]);
            if(scalarMultResult != 0)
            {
                publicKeyOwner.Dispose();
                privateKeyOwner.Dispose();
                throw new CryptographicException("libsodium failed to derive an X25519 public key.");
            }

            var publicKeyMemory = new PublicKeyMemory(publicKeyOwner, CryptoTags.X25519PublicKey);
            var privateKeyMemory = new PrivateKeyMemory(privateKeyOwner, CryptoTags.X25519PrivateKey);

            return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
        }
    }
}
