using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests the platform ML-DSA/ML-KEM key creators in <see cref="MicrosoftKeyMaterialCreator"/>
    /// against the independent BouncyCastle implementation: keys the platform creates must sign,
    /// verify, encapsulate and decapsulate through <see cref="BouncyCastleCryptographicFunctions"/>,
    /// proving the exported private-key byte format is the FIPS 203/204 encoding both backends
    /// agree on — the primitive-level cross-check available in-tree. Where the platform ships no
    /// implementation the tests are inconclusive rather than silently green.
    /// </summary>
    [TestClass]
    internal sealed class MicrosoftPostQuantumKeyMaterialTests
    {
        /// <summary>The MSTest context carrying the run's cancellation token.</summary>
        public TestContext TestContext { get; set; } = null!;

        /// <summary>The payload signed and verified across the backends.</summary>
        private static byte[] TestData { get; } = Encoding.UTF8.GetBytes("Platform post-quantum key material test payload.");


        /// <summary>
        /// Marks the test inconclusive where the platform ships no ML-DSA implementation
        /// (<see cref="MLDsa.IsSupported"/>), matching the platform cross-check convention.
        /// </summary>
        private static void RequirePlatformMlDsa()
        {
#pragma warning disable SYSLIB5006 //The platform's ML-DSA surface is experimental; probing its availability is the point of this gate.
            if(!MLDsa.IsSupported)
            {
                Assert.Inconclusive("The platform ships no ML-DSA implementation; the platform key creator needs one.");
            }
#pragma warning restore SYSLIB5006
        }


        /// <summary>
        /// Marks the test inconclusive where the platform ships no ML-KEM implementation
        /// (<see cref="MLKem.IsSupported"/>), matching the platform cross-check convention.
        /// </summary>
        private static void RequirePlatformMlKem()
        {
#pragma warning disable SYSLIB5006 //The platform's ML-KEM surface is experimental; probing its availability is the point of this gate.
            if(!MLKem.IsSupported)
            {
                Assert.Inconclusive("The platform ships no ML-KEM implementation; the platform key creator needs one.");
            }
#pragma warning restore SYSLIB5006
        }


        /// <summary>
        /// The platform-created ML-DSA-44 keys carry the exact FIPS 204 Table 2 encodings:
        /// a 1312-octet public key and a 2560-octet expanded private key.
        /// </summary>
        [TestMethod]
        public void MlDsa44PlatformKeysCarryTheFips204Encodings()
        {
            RequirePlatformMlDsa();

            var keys = MicrosoftKeyMaterialCreator.CreateMlDsa44Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.HasCount(1312, publicKey.AsReadOnlySpan());
            Assert.HasCount(2560, privateKey.AsReadOnlySpan());
        }


        /// <summary>
        /// ML-DSA-44 keys the platform creates sign and verify through the independent
        /// BouncyCastle implementation — the cross-backend byte-format proof.
        /// </summary>
        [TestMethod]
        public async Task MlDsa44PlatformKeysSignAndVerifyThroughTheIndependentImplementation()
        {
            RequirePlatformMlDsa();

            var keys = MicrosoftKeyMaterialCreator.CreateMlDsa44Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctions.SignMlDsa44Async, BouncyCastleCryptographicFunctions.VerifyMlDsa44Async).ConfigureAwait(false);
        }


        /// <summary>
        /// The platform-created ML-DSA-65 keys carry the exact FIPS 204 Table 2 encodings:
        /// a 1952-octet public key and a 4032-octet expanded private key.
        /// </summary>
        [TestMethod]
        public void MlDsa65PlatformKeysCarryTheFips204Encodings()
        {
            RequirePlatformMlDsa();

            var keys = MicrosoftKeyMaterialCreator.CreateMlDsa65Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.HasCount(1952, publicKey.AsReadOnlySpan());
            Assert.HasCount(4032, privateKey.AsReadOnlySpan());
        }


        /// <summary>
        /// ML-DSA-65 keys the platform creates sign and verify through the independent
        /// BouncyCastle implementation.
        /// </summary>
        [TestMethod]
        public async Task MlDsa65PlatformKeysSignAndVerifyThroughTheIndependentImplementation()
        {
            RequirePlatformMlDsa();

            var keys = MicrosoftKeyMaterialCreator.CreateMlDsa65Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctions.SignMlDsa65Async, BouncyCastleCryptographicFunctions.VerifyMlDsa65Async).ConfigureAwait(false);
        }


        /// <summary>
        /// A signature minted with a platform-created ML-DSA-65 private key and tampered afterwards
        /// fails BouncyCastle verification — the cross-backend pairing rejects, not only accepts.
        /// </summary>
        [TestMethod]
        public async Task MlDsa65PlatformKeyTamperedSignatureFailsIndependentVerification()
        {
            RequirePlatformMlDsa();

            var keys = MicrosoftKeyMaterialCreator.CreateMlDsa65Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            ReadOnlyMemory<byte> data = TestData;
            (Signature signature, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.SignMlDsa65Async(
                privateKey.AsReadOnlyMemory(), data, BaseMemoryPool.Shared,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            using var disposableSignature = signature;

            byte[] tamperedBytes = signature.AsReadOnlyMemory().ToArray();
            tamperedBytes[0] ^= 0xFF;
            tamperedBytes[^1] ^= 0xFF;

            (bool isValid, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.VerifyMlDsa65Async(
                data, tamperedBytes, publicKey.AsReadOnlyMemory(),
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(isValid);
        }


        /// <summary>
        /// The platform-created ML-DSA-87 keys carry the exact FIPS 204 Table 2 encodings:
        /// a 2592-octet public key and a 4896-octet expanded private key.
        /// </summary>
        [TestMethod]
        public void MlDsa87PlatformKeysCarryTheFips204Encodings()
        {
            RequirePlatformMlDsa();

            var keys = MicrosoftKeyMaterialCreator.CreateMlDsa87Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.HasCount(2592, publicKey.AsReadOnlySpan());
            Assert.HasCount(4896, privateKey.AsReadOnlySpan());
        }


        /// <summary>
        /// ML-DSA-87 keys the platform creates sign and verify through the independent
        /// BouncyCastle implementation.
        /// </summary>
        [TestMethod]
        public async Task MlDsa87PlatformKeysSignAndVerifyThroughTheIndependentImplementation()
        {
            RequirePlatformMlDsa();

            var keys = MicrosoftKeyMaterialCreator.CreateMlDsa87Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctions.SignMlDsa87Async, BouncyCastleCryptographicFunctions.VerifyMlDsa87Async).ConfigureAwait(false);
        }


        /// <summary>
        /// The platform-created ML-KEM-512 keys carry the exact FIPS 203 Table 3 encodings:
        /// an 800-octet encapsulation key and a 1632-octet decapsulation key.
        /// </summary>
        [TestMethod]
        public void MlKem512PlatformKeysCarryTheFips203Encodings()
        {
            RequirePlatformMlKem();

            var keys = MicrosoftKeyMaterialCreator.CreateMlKem512Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.HasCount(800, publicKey.AsReadOnlySpan());
            Assert.HasCount(1632, privateKey.AsReadOnlySpan());
        }


        /// <summary>
        /// ML-KEM-512 keys the platform creates round-trip a shared secret through the independent
        /// BouncyCastle encapsulation and decapsulation.
        /// </summary>
        [TestMethod]
        public void MlKem512PlatformKeysRoundTripThroughTheIndependentImplementation()
        {
            RequirePlatformMlKem();

            AssertMlKemRoundTrip(
                MicrosoftKeyMaterialCreator.CreateMlKem512Keys,
                BouncyCastleCryptographicFunctions.EncapsulateMlKem512,
                BouncyCastleCryptographicFunctions.DecapsulateMlKem512);
        }


        /// <summary>
        /// The platform-created ML-KEM-768 keys carry the exact FIPS 203 Table 3 encodings:
        /// an 1184-octet encapsulation key and a 2400-octet decapsulation key.
        /// </summary>
        [TestMethod]
        public void MlKem768PlatformKeysCarryTheFips203Encodings()
        {
            RequirePlatformMlKem();

            var keys = MicrosoftKeyMaterialCreator.CreateMlKem768Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.HasCount(1184, publicKey.AsReadOnlySpan());
            Assert.HasCount(2400, privateKey.AsReadOnlySpan());
        }


        /// <summary>
        /// ML-KEM-768 keys the platform creates round-trip a shared secret through the independent
        /// BouncyCastle encapsulation and decapsulation.
        /// </summary>
        [TestMethod]
        public void MlKem768PlatformKeysRoundTripThroughTheIndependentImplementation()
        {
            RequirePlatformMlKem();

            AssertMlKemRoundTrip(
                MicrosoftKeyMaterialCreator.CreateMlKem768Keys,
                BouncyCastleCryptographicFunctions.EncapsulateMlKem768,
                BouncyCastleCryptographicFunctions.DecapsulateMlKem768);
        }


        /// <summary>
        /// The platform-created ML-KEM-1024 keys carry the exact FIPS 203 Table 3 encodings:
        /// a 1568-octet encapsulation key and a 3168-octet decapsulation key.
        /// </summary>
        [TestMethod]
        public void MlKem1024PlatformKeysCarryTheFips203Encodings()
        {
            RequirePlatformMlKem();

            var keys = MicrosoftKeyMaterialCreator.CreateMlKem1024Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.HasCount(1568, publicKey.AsReadOnlySpan());
            Assert.HasCount(3168, privateKey.AsReadOnlySpan());
        }


        /// <summary>
        /// ML-KEM-1024 keys the platform creates round-trip a shared secret through the independent
        /// BouncyCastle encapsulation and decapsulation.
        /// </summary>
        [TestMethod]
        public void MlKem1024PlatformKeysRoundTripThroughTheIndependentImplementation()
        {
            RequirePlatformMlKem();

            AssertMlKemRoundTrip(
                MicrosoftKeyMaterialCreator.CreateMlKem1024Keys,
                BouncyCastleCryptographicFunctions.EncapsulateMlKem1024,
                BouncyCastleCryptographicFunctions.DecapsulateMlKem1024);
        }


        /// <summary>
        /// An ML-DSA creation whose pinned private-key rental is refused must release the
        /// already-populated public-key rental: the injected-refusal accounting expects
        /// <c>ReturnedCount == RentedCount - 1</c>, the refused rent itself being the only
        /// unreturned ordinal.
        /// </summary>
        [TestMethod]
        public void MlDsaCreationRefusedAtThePrivateKeyRentalReleasesThePublicKeyRental()
        {
            RequirePlatformMlDsa();

            using var metered = new MeteredHousePool();
            metered.OnRent = total =>
            {
                if(total == 2)
                {
                    throw new InvalidOperationException("Injected refusal of the pinned private-key rental.");
                }
            };

            _ = Assert.ThrowsExactly<InvalidOperationException>(
                () => MicrosoftKeyMaterialCreator.CreateMlDsa87Keys(metered.Pool));

            Assert.AreEqual(metered.RentedCount - 1, metered.ReturnedCount);
        }


        /// <summary>
        /// An ML-KEM creation whose pinned decapsulation-key rental is refused must release the
        /// already-populated encapsulation-key rental: the injected-refusal accounting expects
        /// <c>ReturnedCount == RentedCount - 1</c>, the refused rent itself being the only
        /// unreturned ordinal.
        /// </summary>
        [TestMethod]
        public void MlKemCreationRefusedAtTheDecapsulationKeyRentalReleasesTheEncapsulationKeyRental()
        {
            RequirePlatformMlKem();

            using var metered = new MeteredHousePool();
            metered.OnRent = total =>
            {
                if(total == 2)
                {
                    throw new InvalidOperationException("Injected refusal of the pinned decapsulation-key rental.");
                }
            };

            _ = Assert.ThrowsExactly<InvalidOperationException>(
                () => MicrosoftKeyMaterialCreator.CreateMlKem1024Keys(metered.Pool));

            Assert.AreEqual(metered.RentedCount - 1, metered.ReturnedCount);
        }


        /// <summary>
        /// Signs the test payload with <paramref name="privateKey"/> and verifies with
        /// <paramref name="publicKey"/> through the given independent-implementation delegates.
        /// </summary>
        /// <param name="privateKey">The platform-created private key.</param>
        /// <param name="publicKey">The platform-created public key.</param>
        /// <param name="sign">The independent implementation's signing function.</param>
        /// <param name="verify">The independent implementation's verification function.</param>
        private async Task AssertSignAndVerifyAsync(
            PrivateKeyMemory privateKey,
            PublicKeyMemory publicKey,
            SigningDelegate sign,
            VerificationDelegate verify)
        {
            ReadOnlyMemory<byte> data = TestData;
            (Signature signature, CryptoEvent? _) = await sign(privateKey.AsReadOnlyMemory(), data, BaseMemoryPool.Shared,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            using var disposableSignature = signature;

            Assert.IsGreaterThan(0, signature.AsReadOnlyMemory().Length);

            (bool isValid, CryptoEvent? _) = await verify(data, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory(),
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(isValid);
        }


        /// <summary>
        /// Creates a key pair with <paramref name="createKeys"/>, encapsulates against its public
        /// key and decapsulates with its private key through the given independent-implementation
        /// functions, asserting both sides derive the same 32-octet shared secret.
        /// </summary>
        /// <param name="createKeys">The platform key creator under test.</param>
        /// <param name="encapsulate">The independent implementation's encapsulation function.</param>
        /// <param name="decapsulate">The independent implementation's decapsulation function.</param>
        private static void AssertMlKemRoundTrip(
            Func<BaseMemoryPool, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> createKeys,
            Func<ReadOnlyMemory<byte>, BaseMemoryPool, (IMemoryOwner<byte> Ciphertext, IMemoryOwner<byte> SharedSecret)> encapsulate,
            Func<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>, BaseMemoryPool, IMemoryOwner<byte>> decapsulate)
        {
            var keys = createKeys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            var (ciphertext, senderSecret) = encapsulate(publicKey.AsReadOnlyMemory(), BaseMemoryPool.Shared);
            using var ct = ciphertext;
            using var ss = senderSecret;

            using var receiverSecret = decapsulate(privateKey.AsReadOnlyMemory(), ct.Memory, BaseMemoryPool.Shared);

            Assert.HasCount(32, ss.Memory);
            Assert.HasCount(32, receiverSecret.Memory);
            Assert.IsTrue(ss.Memory.Span.SequenceEqual(receiverSecret.Memory.Span));
        }
    }
}
