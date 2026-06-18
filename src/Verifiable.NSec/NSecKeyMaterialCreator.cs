using NSec.Cryptography;
using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Provider;
using CryptoLibraryInfo = Verifiable.Cryptography.Provider.CryptoLibrary;
using Key = NSec.Cryptography.Key;

namespace Verifiable.NSec
{
    /// <summary>
    /// Creates key material for NSec-supported algorithms. The caller is responsible
    /// for disposing the individual <see cref="PublicKeyMemory"/> and <see cref="PrivateKeyMemory"/>
    /// instances returned within the key material.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The caller is responsible for disposing the returned key material instances.")]
    public static class NSecKeyMaterialCreator
    {
        private static readonly ProviderLibrary ProviderLib = new(
            typeof(NSecKeyMaterialCreator).Assembly.GetName().Name ?? "Verifiable.NSec",
            typeof(NSecKeyMaterialCreator).Assembly.GetName().Version?.ToString() ?? "Unknown");

        //NSec wraps the native libsodium binary; its assembly version is the meaningful CBOM identifier.
        private static readonly CryptoLibraryInfo CryptoLib = new(
            "NSec.Cryptography",
            typeof(global::NSec.Cryptography.SignatureAlgorithm).Assembly.GetName().Version?.ToString() ?? "Unknown");

        private static readonly ProviderClass ProviderCls = new(nameof(NSecKeyMaterialCreator));


        /// <summary>
        /// Creates fresh Ed25519 key material using the NSec cryptographic backend.
        /// </summary>
        /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
        /// <returns>A new key pair. The caller is responsible for disposing each key individually.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateEd25519Keys(MemoryPool<byte> memoryPool)
        {
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

            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> material = CreateKeys(SignatureAlgorithm.Ed25519, memoryPool, CryptoTags.Ed25519PublicKey, CryptoTags.Ed25519PrivateKey);

            return material;
        }


        /// <summary>
        /// Creates fresh X25519 key material using the NSec cryptographic backend.
        /// </summary>
        /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
        /// <returns>A new key pair. The caller is responsible for disposing each key individually.</returns>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateX25519Keys(MemoryPool<byte> memoryPool)
        {
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

            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> material = CreateKeys(KeyAgreementAlgorithm.X25519, memoryPool, CryptoTags.X25519PublicKey, CryptoTags.X25519PrivateKey);

            return material;
        }


        /// <summary>
        /// Creates key material for the given NSec algorithm by generating a key pair,
        /// exporting the raw bytes, and wrapping them in pooled memory.
        /// </summary>
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
