using System.Buffers;
using System.Collections.Frozen;
using System.Text;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Cross-library verification tests between BouncyCastle and Microsoft cryptographic backends.
    /// For each supported algorithm, every combination of signing and verification backend is
    /// exercised to ensure interoperability. Key material is created once per test and shared
    /// across backend combinations since the raw byte format is backend-agnostic.
    /// </summary>
    [TestClass]
    internal sealed class CryptographicCrossTests
    {
        public TestContext TestContext { get; set; } = null!;

        /// <summary>
        /// Shared test payload used for all cross-library tests.
        /// </summary>
        private static byte[] TestData { get; } = Encoding.UTF8.GetBytes("Cross-library verification payload.");

        /// <summary>
        /// Delegate matching the shape of all signing functions.
        /// </summary>
        internal delegate ValueTask<Signature> SignDelegate(
            ReadOnlyMemory<byte> privateKey,
            ReadOnlyMemory<byte> data,
            MemoryPool<byte> pool,
            FrozenDictionary<string, object>? context);

        /// <summary>
        /// Delegate matching the shape of all verification functions.
        /// </summary>
        internal delegate ValueTask<bool> VerifyDelegate(
            ReadOnlyMemory<byte> data,
            ReadOnlyMemory<byte> signature,
            ReadOnlyMemory<byte> publicKey,
            FrozenDictionary<string, object>? context);

        /// <summary>
        /// Delegate matching the shape of all key creation factory methods.
        /// </summary>
        internal delegate PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> KeyCreator(MemoryPool<byte> pool);


        public static IEnumerable<object[]> P256Combinations => BuildCombinations(
            (MicrosoftCryptographicFunctions.SignP256Async, "Microsoft"),
            (BouncyCastleCryptographicFunctions.SignP256Async, "BouncyCastle"),
            (MicrosoftCryptographicFunctions.VerifyP256Async, "Microsoft"),
            (BouncyCastleCryptographicFunctions.VerifyP256Async, "BouncyCastle"));


        [TestMethod]
        [DynamicData(nameof(P256Combinations))]
        public async Task P256CrossLibrarySignatureVerifies(SignDelegate sign, VerifyDelegate verify, string scenario)
        {
            var keys = MicrosoftKeyMaterialCreator.CreateP256Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(publicKey, privateKey, sign, verify).ConfigureAwait(false);
        }


        public static IEnumerable<object[]> P384Combinations => BuildCombinations(
            (MicrosoftCryptographicFunctions.SignP384Async, "Microsoft"),
            (BouncyCastleCryptographicFunctions.SignP384Async, "BouncyCastle"),
            (MicrosoftCryptographicFunctions.VerifyP384Async, "Microsoft"),
            (BouncyCastleCryptographicFunctions.VerifyP384Async, "BouncyCastle"));


        [TestMethod]
        [DynamicData(nameof(P384Combinations))]
        public async Task P384CrossLibrarySignatureVerifies(SignDelegate sign, VerifyDelegate verify, string scenario)
        {
            var keys = MicrosoftKeyMaterialCreator.CreateP384Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(publicKey, privateKey, sign, verify).ConfigureAwait(false);
        }


        public static IEnumerable<object[]> P521Combinations => BuildCombinations(
            (MicrosoftCryptographicFunctions.SignP521Async, "Microsoft"),
            (BouncyCastleCryptographicFunctions.SignP521Async, "BouncyCastle"),
            (MicrosoftCryptographicFunctions.VerifyP521Async, "Microsoft"),
            (BouncyCastleCryptographicFunctions.VerifyP521Async, "BouncyCastle"));


        [TestMethod]
        [DynamicData(nameof(P521Combinations))]
        public async Task P521CrossLibrarySignatureVerifies(SignDelegate sign, VerifyDelegate verify, string scenario)
        {
            var keys = MicrosoftKeyMaterialCreator.CreateP521Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(publicKey, privateKey, sign, verify).ConfigureAwait(false);
        }


        public static IEnumerable<object[]> Secp256k1Combinations => BuildCombinations(
            (MicrosoftCryptographicFunctions.SignSecp256k1Async, "Microsoft"),
            (BouncyCastleCryptographicFunctions.SignSecp256k1Async, "BouncyCastle"),
            (MicrosoftCryptographicFunctions.VerifySecp256k1Async, "Microsoft"),
            (BouncyCastleCryptographicFunctions.VerifySecp256k1Async, "BouncyCastle"));


        [SkipOnMacOSTestMethod]
        [DynamicData(nameof(Secp256k1Combinations))]
        public async Task Secp256k1CrossLibrarySignatureVerifies(SignDelegate sign, VerifyDelegate verify, string scenario)
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateSecp256k1Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(publicKey, privateKey, sign, verify).ConfigureAwait(false);
        }


        public static IEnumerable<object[]> Rsa2048Combinations => BuildCombinations(
            (MicrosoftCryptographicFunctions.SignRsa2048Async, "Microsoft"),
            (BouncyCastleCryptographicFunctions.SignRsa2048Async, "BouncyCastle"),
            (MicrosoftCryptographicFunctions.VerifyRsa2048Async, "Microsoft"),
            (BouncyCastleCryptographicFunctions.VerifyRsa2048Async, "BouncyCastle"));


        [TestMethod]
        [DynamicData(nameof(Rsa2048Combinations))]
        public async Task Rsa2048CrossLibrarySignatureVerifies(SignDelegate sign, VerifyDelegate verify, string scenario)
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(publicKey, privateKey, sign, verify).ConfigureAwait(false);
        }


        public static IEnumerable<object[]> Rsa4096Combinations => BuildCombinations(
            (MicrosoftCryptographicFunctions.SignRsa4096Async, "Microsoft"),
            (BouncyCastleCryptographicFunctions.SignRsa4096Async, "BouncyCastle"),
            (MicrosoftCryptographicFunctions.VerifyRsa4096Async, "Microsoft"),
            (BouncyCastleCryptographicFunctions.VerifyRsa4096Async, "BouncyCastle"));


        [TestMethod]
        [DynamicData(nameof(Rsa4096Combinations))]
        public async Task Rsa4096CrossLibrarySignatureVerifies(SignDelegate sign, VerifyDelegate verify, string scenario)
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa4096Keys(SensitiveMemoryPool<byte>.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(publicKey, privateKey, sign, verify).ConfigureAwait(false);
        }


        /// <summary>
        /// Performs a round-trip sign-and-verify using the given delegates against the provided key material.
        /// </summary>
        private static async Task AssertSignAndVerifyAsync(
            PublicKeyMemory publicKey,
            PrivateKeyMemory privateKey,
            SignDelegate sign,
            VerifyDelegate verify)
        {
            ReadOnlyMemory<byte> data = TestData;

            using var signature = await sign(privateKey.AsReadOnlyMemory(), data, SensitiveMemoryPool<byte>.Shared, null)
                .ConfigureAwait(false);

            bool isVerified = await verify(data, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory(), null)
                .ConfigureAwait(false);

            Assert.IsTrue(isVerified);
        }


        /// <summary>
        /// Generates all sign × verify combinations from two signers and two verifiers,
        /// yielding four test cases with descriptive scenario labels.
        /// </summary>
        private static IEnumerable<object[]> BuildCombinations(
            (SignDelegate Signer, string Name) signer1,
            (SignDelegate Signer, string Name) signer2,
            (VerifyDelegate Verifier, string Name) verifier1,
            (VerifyDelegate Verifier, string Name) verifier2)
        {
            (SignDelegate Signer, string Name)[] signers = [signer1, signer2];
            (VerifyDelegate Verifier, string Name)[] verifiers = [verifier1, verifier2];

            foreach(var (signer, signerName) in signers)
            {
                foreach(var (verifier, verifierName) in verifiers)
                {
                    yield return [signer, verifier, $"Sign:{signerName} Verify:{verifierName}"];
                }
            }
        }
    }
}