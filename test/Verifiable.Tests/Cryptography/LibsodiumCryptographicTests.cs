using System;
using System.Buffers;
using System.Text;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Libsodium;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests libsodium as the cryptographic provider across its supported algorithms (Ed25519,
    /// X25519), porting the intent of the retired managed-wrapper Ed25519/X25519 provider tests onto
    /// the new binding, plus the IETF known-answer vectors (R-6) that pin the native binding against
    /// <see href="https://www.rfc-editor.org/rfc/rfc8032">RFC 8032</see> (Ed25519) and
    /// <see href="https://www.rfc-editor.org/rfc/rfc7748">RFC 7748</see> (X25519).
    /// </summary>
    [TestClass]
    internal sealed class LibsodiumCryptographicTests
    {
        /// <summary>The MSTest context for the running test, used for cancellation.</summary>
        public TestContext TestContext { get; set; } = null!;

        /// <summary>
        /// Shared test payload used for the non-vector sign-and-verify tests.
        /// </summary>
        private static byte[] TestData { get; } = Encoding.UTF8.GetBytes("Libsodium cryptographic test payload.");


        /// <summary>
        /// A fresh libsodium Ed25519 keypair has non-empty public and private key material.
        /// </summary>
        [TestMethod]
        public void Ed25519KeyPairHasNonEmptyMaterial()
        {
            var keys = LibsodiumKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.IsGreaterThan(0, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        /// <summary>
        /// A signature produced by <see cref="LibsodiumCryptographicFunctions.SignEd25519Async"/> over
        /// a fresh keypair verifies with <see cref="LibsodiumCryptographicFunctions.VerifyEd25519Async"/>.
        /// </summary>
        [TestMethod]
        public async Task Ed25519SignatureVerifies()
        {
            var keys = LibsodiumKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            ReadOnlyMemory<byte> data = TestData;
            using var signature = await privateKey.SignAsync(data, LibsodiumCryptographicFunctions.SignEd25519Async, BaseMemoryPool.Shared)
                .ConfigureAwait(false);

            Assert.IsTrue(await publicKey.VerifyAsync(data, signature, LibsodiumCryptographicFunctions.VerifyEd25519Async)
                .ConfigureAwait(false));
        }


        /// <summary>
        /// The same round trip succeeds when the keys are wrapped in the delegate-identified
        /// <see cref="PublicKey"/>/<see cref="PrivateKey"/> carriers instead of calling the backend
        /// functions directly.
        /// </summary>
        [TestMethod]
        public async Task Ed25519IdentifiedKeySignatureVerifies()
        {
            var keys = LibsodiumKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
            using var publicKey = new PublicKey(keys.PublicKey, "ed25519-test", LibsodiumCryptographicFunctions.VerifyEd25519Async);
            using var privateKey = new PrivateKey(keys.PrivateKey, "ed25519-test", LibsodiumCryptographicFunctions.SignEd25519Async);

            ReadOnlyMemory<byte> data = TestData;
            using var signature = await privateKey.SignAsync(data, BaseMemoryPool.Shared).ConfigureAwait(false);

            Assert.IsTrue(await publicKey.VerifyAsync(data, signature).ConfigureAwait(false));
        }


        /// <summary>
        /// A fresh libsodium X25519 keypair has non-empty public and private key material.
        /// </summary>
        [TestMethod]
        public void X25519KeyPairHasNonEmptyMaterial()
        {
            var keys = LibsodiumKeyMaterialCreator.CreateX25519Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.IsGreaterThan(0, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        /// <summary>
        /// RFC 8032 §7.1 TEST 1 (the empty message): the seed must derive the known-answer public
        /// key and produce the known-answer signature bytes exactly.
        /// </summary>
        [TestMethod]
        public async Task Rfc8032Test1VectorMatchesKnownAnswer() =>
            await AssertRfc8032VectorAsync(
                seedHex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                publicKeyHex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                messageHex: "",
                signatureHex: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
                .ConfigureAwait(false);


        /// <summary>
        /// RFC 8032 §7.1 TEST 2 (a 1-byte message): the seed must derive the known-answer public key
        /// and produce the known-answer signature bytes exactly.
        /// </summary>
        [TestMethod]
        public async Task Rfc8032Test2VectorMatchesKnownAnswer() =>
            await AssertRfc8032VectorAsync(
                seedHex: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                publicKeyHex: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                messageHex: "72",
                signatureHex: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
                .ConfigureAwait(false);


        /// <summary>
        /// RFC 8032 §7.1 TEST 3 (a 2-byte message): the seed must derive the known-answer public key
        /// and produce the known-answer signature bytes exactly.
        /// </summary>
        [TestMethod]
        public async Task Rfc8032Test3VectorMatchesKnownAnswer() =>
            await AssertRfc8032VectorAsync(
                seedHex: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                publicKeyHex: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                messageHex: "af82",
                signatureHex: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")
                .ConfigureAwait(false);


        /// <summary>
        /// RFC 8032 §7.1 TEST SHA(abc) (a 64-byte message): the seed must derive the known-answer
        /// public key and produce the known-answer signature bytes exactly.
        /// </summary>
        [TestMethod]
        public async Task Rfc8032ShaAbcVectorMatchesKnownAnswer() =>
            await AssertRfc8032VectorAsync(
                seedHex: "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
                publicKeyHex: "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
                messageHex: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                signatureHex: "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704")
                .ConfigureAwait(false);


        /// <summary>
        /// RFC 7748 §5.2 X25519 test vector: <c>crypto_scalarmult</c> over a fixed scalar and
        /// u-coordinate must match the known-answer output u-coordinate exactly.
        /// </summary>
        [TestMethod]
        public void Rfc7748Section5Point2ScalarMultVectorMatchesKnownAnswer()
        {
            byte[] scalar = Convert.FromHexString("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
            byte[] uCoordinate = Convert.FromHexString("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
            byte[] expectedOutput = Convert.FromHexString("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

            Span<byte> output = stackalloc byte[LibsodiumNativeMethods.X25519PointLength];
            int result = LibsodiumNativeMethods.crypto_scalarmult(output, scalar, uCoordinate);

            Assert.AreEqual(0, result);
            Assert.IsTrue(output.SequenceEqual(expectedOutput), "crypto_scalarmult must match the RFC 7748 section 5.2 known-answer output.");
        }


        /// <summary>
        /// RFC 7748 §6.1 Diffie-Hellman example: Alice's and Bob's key pairs must derive from their
        /// private scalars via <c>crypto_scalarmult_base</c>, and both directions of
        /// <c>crypto_scalarmult</c> must agree on the known-answer shared secret K.
        /// </summary>
        [TestMethod]
        public void Rfc7748Section6Point1DiffieHellmanVectorMatchesKnownAnswer()
        {
            byte[] alicePrivate = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
            byte[] alicePublic = Convert.FromHexString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
            byte[] bobPrivate = Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
            byte[] bobPublic = Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
            byte[] expectedShared = Convert.FromHexString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

            Span<byte> derivedAlicePublic = stackalloc byte[LibsodiumNativeMethods.X25519PointLength];
            Assert.AreEqual(0, LibsodiumNativeMethods.crypto_scalarmult_base(derivedAlicePublic, alicePrivate));
            Assert.IsTrue(derivedAlicePublic.SequenceEqual(alicePublic), "Alice's public key must match the RFC 7748 section 6.1 known answer.");

            Span<byte> derivedBobPublic = stackalloc byte[LibsodiumNativeMethods.X25519PointLength];
            Assert.AreEqual(0, LibsodiumNativeMethods.crypto_scalarmult_base(derivedBobPublic, bobPrivate));
            Assert.IsTrue(derivedBobPublic.SequenceEqual(bobPublic), "Bob's public key must match the RFC 7748 section 6.1 known answer.");

            Span<byte> sharedFromAlice = stackalloc byte[LibsodiumNativeMethods.X25519PointLength];
            Assert.AreEqual(0, LibsodiumNativeMethods.crypto_scalarmult(sharedFromAlice, alicePrivate, bobPublic));

            Span<byte> sharedFromBob = stackalloc byte[LibsodiumNativeMethods.X25519PointLength];
            Assert.AreEqual(0, LibsodiumNativeMethods.crypto_scalarmult(sharedFromBob, bobPrivate, alicePublic));

            Assert.IsTrue(sharedFromAlice.SequenceEqual(expectedShared), "Alice's computed shared secret must match the RFC 7748 section 6.1 known answer.");
            Assert.IsTrue(sharedFromBob.SequenceEqual(expectedShared), "Bob's computed shared secret must match the RFC 7748 section 6.1 known answer.");
        }


        /// <summary>
        /// Self-consistency KAT for the ed25519-to-curve25519 conversion: two independently generated
        /// Ed25519 keypairs, each converted to its birationally equivalent X25519 form, must agree on
        /// the X25519 Diffie-Hellman shared secret regardless of which side's converted private scalar
        /// or public point is used to compute it.
        /// </summary>
        [TestMethod]
        public void Ed25519ToCurve25519ConversionAgreesOnDiffieHellman()
        {
            Span<byte> seedA = stackalloc byte[LibsodiumNativeMethods.Ed25519SeedLength];
            Span<byte> seedB = stackalloc byte[LibsodiumNativeMethods.Ed25519SeedLength];
            LibsodiumNativeMethods.randombytes_buf(seedA, (nuint)seedA.Length);
            LibsodiumNativeMethods.randombytes_buf(seedB, (nuint)seedB.Length);

            Span<byte> pkA = stackalloc byte[LibsodiumNativeMethods.Ed25519PublicKeyLength];
            Span<byte> pkB = stackalloc byte[LibsodiumNativeMethods.Ed25519PublicKeyLength];

            using IMemoryOwner<byte> secretKeyScratchOwnerA = LibsodiumNativeMethods.AllocateSecretKeyScratch(
                "libsodium must allocate the first Ed25519 secret-key scratch.");
            using IMemoryOwner<byte> secretKeyScratchOwnerB = LibsodiumNativeMethods.AllocateSecretKeyScratch(
                "libsodium must allocate the second Ed25519 secret-key scratch.");
            using MemoryHandle secretKeyScratchHandleA = secretKeyScratchOwnerA.Memory.Pin();
            using MemoryHandle secretKeyScratchHandleB = secretKeyScratchOwnerB.Memory.Pin();

            nint secretKeyScratchA;
            nint secretKeyScratchB;
            unsafe
            {
                secretKeyScratchA = (nint)secretKeyScratchHandleA.Pointer;
                secretKeyScratchB = (nint)secretKeyScratchHandleB.Pointer;
            }

            Assert.AreEqual(0, LibsodiumNativeMethods.crypto_sign_seed_keypair(pkA, secretKeyScratchA, seedA));
            Assert.AreEqual(0, LibsodiumNativeMethods.crypto_sign_seed_keypair(pkB, secretKeyScratchB, seedB));

            Span<byte> x25519PkA = stackalloc byte[LibsodiumNativeMethods.X25519PointLength];
            Span<byte> x25519PkB = stackalloc byte[LibsodiumNativeMethods.X25519PointLength];
            Assert.AreEqual(0, LibsodiumNativeMethods.crypto_sign_ed25519_pk_to_curve25519(x25519PkA, pkA));
            Assert.AreEqual(0, LibsodiumNativeMethods.crypto_sign_ed25519_pk_to_curve25519(x25519PkB, pkB));

            Span<byte> x25519SkA = stackalloc byte[LibsodiumNativeMethods.X25519ScalarLength];
            Span<byte> x25519SkB = stackalloc byte[LibsodiumNativeMethods.X25519ScalarLength];
            Assert.AreEqual(0, LibsodiumNativeMethods.crypto_sign_ed25519_sk_to_curve25519(x25519SkA, secretKeyScratchA));
            Assert.AreEqual(0, LibsodiumNativeMethods.crypto_sign_ed25519_sk_to_curve25519(x25519SkB, secretKeyScratchB));

            Span<byte> sharedFromA = stackalloc byte[LibsodiumNativeMethods.X25519PointLength];
            Span<byte> sharedFromB = stackalloc byte[LibsodiumNativeMethods.X25519PointLength];
            Assert.AreEqual(0, LibsodiumNativeMethods.crypto_scalarmult(sharedFromA, x25519SkA, x25519PkB));
            Assert.AreEqual(0, LibsodiumNativeMethods.crypto_scalarmult(sharedFromB, x25519SkB, x25519PkA));

            Assert.IsTrue(sharedFromA.SequenceEqual(sharedFromB),
                "Independently converted Ed25519 keypairs must agree on the X25519 Diffie-Hellman shared secret.");
        }


        /// <summary>
        /// The PRODUCTION <see cref="LibsodiumKeyConversion.ConvertEd25519PublicKeyToCurve25519PublicKey"/>
        /// must be byte-identical to an independently derived native-direct conversion
        /// (<c>crypto_sign_ed25519_pk_to_curve25519</c> called directly, bypassing the production method)
        /// for the same minted Ed25519 public key. This is the oracle-equality half of the correctness
        /// pinning the adversarial review found missing: the existing self-consistency KAT calls the
        /// native methods directly and never exercises the production conversion method at all.
        /// </summary>
        [TestMethod]
        public void ConvertEd25519PublicKeyToCurve25519PublicKeyMatchesNativeDirectConversion()
        {
            var keys = LibsodiumKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            using IMemoryOwner<byte> productionConverted = LibsodiumKeyConversion.ConvertEd25519PublicKeyToCurve25519PublicKey(
                publicKey.AsReadOnlySpan(), BaseMemoryPool.Shared);

            Span<byte> nativeDirectConverted = stackalloc byte[LibsodiumNativeMethods.X25519PointLength];
            int conversionResult = LibsodiumNativeMethods.crypto_sign_ed25519_pk_to_curve25519(nativeDirectConverted, publicKey.AsReadOnlySpan());
            Assert.AreEqual(0, conversionResult, "The independent native-direct conversion must succeed for a validly minted Ed25519 public key.");

            Assert.IsTrue(
                productionConverted.Memory.Span[..LibsodiumNativeMethods.X25519PointLength].SequenceEqual(nativeDirectConverted),
                "The production ConvertEd25519PublicKeyToCurve25519PublicKey output must be byte-identical to the independent native-direct conversion.");
        }


        /// <summary>
        /// The PRODUCTION <see cref="LibsodiumKeyConversion.ConvertEd25519PrivateKeyToCurve25519PrivateKey"/>
        /// must be byte-identical to an independently derived native-direct conversion
        /// (<c>crypto_sign_seed_keypair</c> into sodium scratch, then <c>crypto_sign_ed25519_sk_to_curve25519</c>
        /// called directly, bypassing the production method) for the same minted Ed25519 seed. Composes the
        /// same oracle path as <see cref="Ed25519ToCurve25519ConversionAgreesOnDiffieHellman"/> without
        /// duplicating its DH-agreement assertion.
        /// </summary>
        [TestMethod]
        public void ConvertEd25519PrivateKeyToCurve25519PrivateKeyMatchesNativeDirectConversion()
        {
            var keys = LibsodiumKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            using IMemoryOwner<byte> productionConverted = LibsodiumKeyConversion.ConvertEd25519PrivateKeyToCurve25519PrivateKey(
                privateKey.AsReadOnlySpan(), BaseMemoryPool.Shared);

            Span<byte> nativeDirectConverted = stackalloc byte[LibsodiumNativeMethods.X25519ScalarLength];
            Span<byte> publicKeyScratch = stackalloc byte[LibsodiumNativeMethods.Ed25519PublicKeyLength];
            using(IMemoryOwner<byte> secretKeyScratchOwner = LibsodiumNativeMethods.AllocateSecretKeyScratch(
                "libsodium must allocate the Ed25519 secret-key scratch for the independent oracle path."))
            using(MemoryHandle secretKeyScratchHandle = secretKeyScratchOwner.Memory.Pin())
            {
                nint secretKeyScratch;
                unsafe
                {
                    secretKeyScratch = (nint)secretKeyScratchHandle.Pointer;
                }

                Assert.AreEqual(0, LibsodiumNativeMethods.crypto_sign_seed_keypair(publicKeyScratch, secretKeyScratch, privateKey.AsReadOnlySpan()),
                    "The independent oracle path's keypair expansion must succeed for the minted seed.");
                Assert.AreEqual(0, LibsodiumNativeMethods.crypto_sign_ed25519_sk_to_curve25519(nativeDirectConverted, secretKeyScratch),
                    "The independent native-direct sk-to-curve25519 conversion must succeed.");
            }

            Assert.IsTrue(
                productionConverted.Memory.Span[..LibsodiumNativeMethods.X25519ScalarLength].SequenceEqual(nativeDirectConverted),
                "The production ConvertEd25519PrivateKeyToCurve25519PrivateKey output must be byte-identical to the independent native-direct conversion.");
        }


        /// <summary>
        /// <c>crypto_scalarmult_base</c> over the PRODUCTION-converted X25519 private scalar must equal the
        /// PRODUCTION-converted X25519 public point for the same source Ed25519 keypair. This catches both
        /// conversion methods being consistently wrong in a way that oracle equality alone (pinning each
        /// method in isolation against its own native-direct counterpart) would not: a shared bug that
        /// shifted both production methods' outputs the same wrong way could still agree with a native-direct
        /// oracle that shared the same flaw, but could not still satisfy the scalarmult_base correspondence.
        /// </summary>
        [TestMethod]
        public void ConvertedX25519PrivateScalarCorrespondsToConvertedX25519PublicKeyViaScalarmultBase()
        {
            var keys = LibsodiumKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            using IMemoryOwner<byte> convertedPublicKey = LibsodiumKeyConversion.ConvertEd25519PublicKeyToCurve25519PublicKey(
                publicKey.AsReadOnlySpan(), BaseMemoryPool.Shared);
            using IMemoryOwner<byte> convertedPrivateScalar = LibsodiumKeyConversion.ConvertEd25519PrivateKeyToCurve25519PrivateKey(
                privateKey.AsReadOnlySpan(), BaseMemoryPool.Shared);

            Span<byte> derivedPublicKey = stackalloc byte[LibsodiumNativeMethods.X25519PointLength];
            int scalarMultResult = LibsodiumNativeMethods.crypto_scalarmult_base(
                derivedPublicKey, convertedPrivateScalar.Memory.Span[..LibsodiumNativeMethods.X25519ScalarLength]);
            Assert.AreEqual(0, scalarMultResult, "crypto_scalarmult_base must succeed over the production-converted private scalar.");

            Assert.IsTrue(
                derivedPublicKey.SequenceEqual(convertedPublicKey.Memory.Span[..LibsodiumNativeMethods.X25519PointLength]),
                "crypto_scalarmult_base over the production-converted private scalar must equal the production-converted public point.");
        }


        /// <summary>
        /// <see cref="LibsodiumCryptographicFunctions.SignEd25519Async"/> fails closed with
        /// <see cref="ArgumentException"/> when the private key is not the 32-byte RFC 8032 seed length
        /// (R-3 malformed-length guard).
        /// </summary>
        [TestMethod]
        public async Task SignEd25519AsyncWithWrongLengthPrivateKeyThrowsArgumentException()
        {
            byte[] wrongLengthPrivateKey = new byte[LibsodiumNativeMethods.Ed25519SeedLength - 1];
            ReadOnlyMemory<byte> data = TestData;

            await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
                await LibsodiumCryptographicFunctions.SignEd25519Async(
                    wrongLengthPrivateKey, data, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken)
                .ConfigureAwait(false)).ConfigureAwait(false);
        }


        /// <summary>
        /// <see cref="LibsodiumCryptographicFunctions.VerifyEd25519Async"/> fails closed with
        /// <see cref="ArgumentException"/> when the public key is not exactly 32 bytes (R-3 malformed-length
        /// guard).
        /// </summary>
        [TestMethod]
        public async Task VerifyEd25519AsyncWithWrongLengthPublicKeyThrowsArgumentException()
        {
            byte[] wrongLengthPublicKey = new byte[LibsodiumNativeMethods.Ed25519PublicKeyLength - 1];
            byte[] arbitrarySignature = new byte[LibsodiumNativeMethods.Ed25519SignatureLength];
            ReadOnlyMemory<byte> data = TestData;

            await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
                await LibsodiumCryptographicFunctions.VerifyEd25519Async(
                    data, arbitrarySignature, wrongLengthPublicKey, cancellationToken: TestContext.CancellationToken)
                .ConfigureAwait(false)).ConfigureAwait(false);
        }


        /// <summary>
        /// <see cref="LibsodiumCryptographicFunctions.VerifyEd25519Async"/> fails closed with
        /// <see cref="ArgumentException"/> when the signature is not exactly 64 bytes (R-3 malformed-length
        /// guard).
        /// </summary>
        [TestMethod]
        public async Task VerifyEd25519AsyncWithWrongLengthSignatureThrowsArgumentException()
        {
            byte[] arbitraryPublicKey = new byte[LibsodiumNativeMethods.Ed25519PublicKeyLength];
            byte[] wrongLengthSignature = new byte[LibsodiumNativeMethods.Ed25519SignatureLength - 1];
            ReadOnlyMemory<byte> data = TestData;

            await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
                await LibsodiumCryptographicFunctions.VerifyEd25519Async(
                    data, wrongLengthSignature, arbitraryPublicKey, cancellationToken: TestContext.CancellationToken)
                .ConfigureAwait(false)).ConfigureAwait(false);
        }


        /// <summary>
        /// Positive control pinning the throw-vs-false boundary from the other side: a well-formed-length
        /// signature that is cryptographically wrong (tampered) must make
        /// <see cref="LibsodiumCryptographicFunctions.VerifyEd25519Async"/> return <see langword="false"/>,
        /// never throw. Complements the malformed-length guard tests above, which pin the throw side.
        /// </summary>
        [TestMethod]
        public async Task VerifyEd25519AsyncWithCryptographicallyWrongSignatureReturnsFalseNotThrow()
        {
            var keys = LibsodiumKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            ReadOnlyMemory<byte> data = TestData;
            using var signature = await privateKey.SignAsync(data, LibsodiumCryptographicFunctions.SignEd25519Async, BaseMemoryPool.Shared)
                .ConfigureAwait(false);

            byte[] tamperedSignature = signature.AsReadOnlySpan().ToArray();
            tamperedSignature[0] ^= 0xFF;

            (bool isVerified, CryptoEvent? _) = await LibsodiumCryptographicFunctions.VerifyEd25519Async(
                data, tamperedSignature, publicKey.AsReadOnlyMemory(), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(isVerified, "A well-formed-length but cryptographically wrong signature must return false, not throw.");
        }


        /// <summary>
        /// Asserts an RFC 8032 §7.1 Ed25519 test vector end to end: the seed derives the known-answer
        /// public key via the native binding directly, and the known-answer signature bytes are
        /// reproduced exactly and independently verified through the public
        /// <see cref="LibsodiumCryptographicFunctions"/> surface.
        /// </summary>
        /// <param name="seedHex">The 32-byte RFC 8032 seed, hex-encoded.</param>
        /// <param name="publicKeyHex">The expected 32-byte public key, hex-encoded.</param>
        /// <param name="messageHex">The message to sign, hex-encoded (may be empty).</param>
        /// <param name="signatureHex">The expected 64-byte detached signature, hex-encoded.</param>
        private async Task AssertRfc8032VectorAsync(string seedHex, string publicKeyHex, string messageHex, string signatureHex)
        {
            byte[] seed = Convert.FromHexString(seedHex);
            byte[] expectedPublicKey = Convert.FromHexString(publicKeyHex);
            byte[] message = Convert.FromHexString(messageHex);
            byte[] expectedSignature = Convert.FromHexString(signatureHex);

            Span<byte> derivedPublicKey = stackalloc byte[LibsodiumNativeMethods.Ed25519PublicKeyLength];
            using(IMemoryOwner<byte> secretKeyScratchOwner = LibsodiumNativeMethods.AllocateSecretKeyScratch(
                "libsodium must allocate the Ed25519 secret-key scratch."))
            using(MemoryHandle secretKeyScratchHandle = secretKeyScratchOwner.Memory.Pin())
            {
                nint secretKeyScratch;
                unsafe
                {
                    secretKeyScratch = (nint)secretKeyScratchHandle.Pointer;
                }

                Assert.AreEqual(0, LibsodiumNativeMethods.crypto_sign_seed_keypair(derivedPublicKey, secretKeyScratch, seed));
            }

            Assert.IsTrue(derivedPublicKey.SequenceEqual(expectedPublicKey), "The seed must derive the RFC 8032 known-answer public key.");

            ReadOnlyMemory<byte> dataToSign = message;
            (Signature signature, CryptoEvent? _) = await LibsodiumCryptographicFunctions.SignEd25519Async(
                seed, dataToSign, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            using Signature disposableSignature = signature;

            Assert.IsTrue(
                signature.AsReadOnlySpan().SequenceEqual(expectedSignature),
                "The detached signature must match the RFC 8032 known-answer bytes exactly.");

            (bool isVerified, CryptoEvent? _) = await LibsodiumCryptographicFunctions.VerifyEd25519Async(
                dataToSign, expectedSignature, expectedPublicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(isVerified, "The known-answer signature must verify against the known-answer public key.");
        }
    }
}
