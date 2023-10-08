﻿using Verifiable.BouncyCastle;
using Verifiable.Core.Cryptography;
using Verifiable.Microsoft;

namespace Verifiable.Tests.TestDataProviders
{
    /// <summary>
    /// Provides key material that is generated once per test run and reused across all test cases.
    /// </summary>
    public static class TestKeyMaterialProvider
    {
        /// <summary>
        /// P-256 key material by Microsoft.
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> P256KeyMaterial { get; } = PublicPrivateKeyMaterialExtensions.Create(ExactSizeMemoryPool<byte>.Shared, MicrosoftKeyCreator.CreateP256Keys);

        /// <summary>
        /// P-384 key material by Microsoft.
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> P384KeyMaterial { get; } = PublicPrivateKeyMaterialExtensions.Create(ExactSizeMemoryPool<byte>.Shared, MicrosoftKeyCreator.CreateP384Keys);

        /// <summary>
        /// P-521 key material by Microsoft.
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> P521KeyMaterial { get; } = PublicPrivateKeyMaterialExtensions.Create(ExactSizeMemoryPool<byte>.Shared, MicrosoftKeyCreator.CreateP521Keys);

        /// <summary>
        /// Secp256k1 key material by Microsoft.
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> Secp256k1KeyMaterial { get; } = PublicPrivateKeyMaterialExtensions.Create(ExactSizeMemoryPool<byte>.Shared, MicrosoftKeyCreator.CreateSecp256k1Keys);

        /// <summary>
        /// RSA 2048 key material by Microsoft.
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> Rsa2048KeyMaterial { get; } = PublicPrivateKeyMaterialExtensions.Create(ExactSizeMemoryPool<byte>.Shared, MicrosoftKeyCreator.CreateRsa2048Keys);

        /// <summary>
        /// RSA 4096 key material by Microsoft.
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> Rsa4096KeyMaterial { get; } = PublicPrivateKeyMaterialExtensions.Create(ExactSizeMemoryPool<byte>.Shared, MicrosoftKeyCreator.CreateRsa4096Keys);

        /// <summary>
        /// Ed25519 key material by BouncyCastle.
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> Ed25519KeyMaterial { get; } = PublicPrivateKeyMaterialExtensions.Create(ExactSizeMemoryPool<byte>.Shared, BouncyCastleKeyCreator.CreateEd25519Keys);

        /// <summary>
        /// X25519 key material by BouncyCastle.
        /// </summary>
        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> X25519KeyMaterial { get; } = PublicPrivateKeyMaterialExtensions.Create(ExactSizeMemoryPool<byte>.Shared, BouncyCastleKeyCreator.CreateX25519Keys);
    }
}
