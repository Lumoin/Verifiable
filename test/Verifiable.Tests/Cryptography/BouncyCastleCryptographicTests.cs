using Microsoft.Extensions.Time.Testing;
using Org.BouncyCastle.Crypto.Parameters;
using System.Buffers;
using System.Text;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests BouncyCastle as the cryptographic provider across all supported algorithms,
    /// including classical (Ed25519, ECDSA, X25519, RSA) and post-quantum (ML-DSA, ML-KEM).
    /// </summary>
    [TestClass]
    internal sealed class BouncyCastleCryptographicTests
    {
        public TestContext TestContext { get; set; } = null!;

        private static byte[] TestData { get; } = Encoding.UTF8.GetBytes("BouncyCastle cryptographic test payload.");


        [TestMethod]
        public void Ed25519KeyPairHasNonEmptyMaterial()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.IsGreaterThan(0, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public async Task Ed25519SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctionsAdapter.SignEd25519Async, BouncyCastleCryptographicFunctionsAdapter.VerifyEd25519Async).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task P256SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctionsAdapter.SignP256Async, BouncyCastleCryptographicFunctionsAdapter.VerifyP256Async).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task P384SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateP384Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctionsAdapter.SignP384Async, BouncyCastleCryptographicFunctionsAdapter.VerifyP384Async).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task P521SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateP521Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctionsAdapter.SignP521Async, BouncyCastleCryptographicFunctionsAdapter.VerifyP521Async).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task Secp256k1SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateSecp256k1Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctionsAdapter.SignSecp256k1Async, BouncyCastleCryptographicFunctionsAdapter.VerifySecp256k1Async).ConfigureAwait(false);
        }


        [TestMethod]
        public void X25519KeyPairHasNonEmptyMaterial()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateX25519Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.IsGreaterThan(0, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public async Task X25519SharedSecretDerivationIsSymmetric()
        {
            var aliceKeys = BouncyCastleKeyMaterialCreator.CreateX25519Keys(BaseMemoryPool.Shared);
            using var alicePub = aliceKeys.PublicKey;
            using var alicePriv = aliceKeys.PrivateKey;

            var bobKeys = BouncyCastleKeyMaterialCreator.CreateX25519Keys(BaseMemoryPool.Shared);
            using var bobPub = bobKeys.PublicKey;
            using var bobPriv = bobKeys.PrivateKey;

            using var aliceSecret = await BouncyCastleCryptographicFunctions.DeriveX25519SharedSecretAsync(
                alicePriv.AsReadOnlyMemory(), bobPub.AsReadOnlyMemory(), BaseMemoryPool.Shared).ConfigureAwait(false);
            using var bobSecret = await BouncyCastleCryptographicFunctions.DeriveX25519SharedSecretAsync(
                bobPriv.AsReadOnlyMemory(), alicePub.AsReadOnlyMemory(), BaseMemoryPool.Shared).ConfigureAwait(false);

            Assert.IsTrue(aliceSecret.Memory.Span.SequenceEqual(bobSecret.Memory.Span));
        }


        [TestMethod]
        public async Task Rsa2048SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctionsAdapter.SignRsa2048Async, BouncyCastleCryptographicFunctionsAdapter.VerifyRsa2048Async).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task Rsa4096SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateRsa4096Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctionsAdapter.SignRsa4096Async, BouncyCastleCryptographicFunctionsAdapter.VerifyRsa4096Async).ConfigureAwait(false);
        }


        [TestMethod]
        public void MlDsa44KeyPairHasCorrectPublicKeySize()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateMlDsa44Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.HasCount(1312, publicKey.AsReadOnlySpan());
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public async Task MlDsa44SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateMlDsa44Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctionsAdapter.SignMlDsa44Async, BouncyCastleCryptographicFunctionsAdapter.VerifyMlDsa44Async).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task MlDsa44TamperedSignatureFailsVerification()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateMlDsa44Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertTamperedSignatureFailsAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctionsAdapter.SignMlDsa44Async, BouncyCastleCryptographicFunctionsAdapter.VerifyMlDsa44Async).ConfigureAwait(false);
        }


        [TestMethod]
        public void MlDsa65KeyPairHasCorrectPublicKeySize()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateMlDsa65Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.HasCount(1952, publicKey.AsReadOnlySpan());
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public async Task MlDsa65SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateMlDsa65Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctionsAdapter.SignMlDsa65Async, BouncyCastleCryptographicFunctionsAdapter.VerifyMlDsa65Async).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task MlDsa65WrongKeyDoesNotVerify()
        {
            var aliceKeys = BouncyCastleKeyMaterialCreator.CreateMlDsa65Keys(BaseMemoryPool.Shared);
            using var alicePublicKey = aliceKeys.PublicKey;
            using var alicePrivateKey = aliceKeys.PrivateKey;

            var bobKeys = BouncyCastleKeyMaterialCreator.CreateMlDsa65Keys(BaseMemoryPool.Shared);
            using var bobPublicKey = bobKeys.PublicKey;
            using var bobPrivateKey = bobKeys.PrivateKey;

            ReadOnlyMemory<byte> data = TestData;
            (Signature signature, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.SignMlDsa65Async(alicePrivateKey.AsReadOnlyMemory(), data, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken, timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch)).ConfigureAwait(false);
            using var disposableSignature = signature;

            (bool isValid, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.VerifyMlDsa65Async(data, signature.AsReadOnlyMemory(), bobPublicKey.AsReadOnlyMemory(), cancellationToken: TestContext.CancellationToken, timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch)).ConfigureAwait(false);

            Assert.IsFalse(isValid);
        }


        [TestMethod]
        public void MlDsa87KeyPairHasCorrectPublicKeySize()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateMlDsa87Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.HasCount(2592, publicKey.AsReadOnlySpan());
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public async Task MlDsa87SignatureVerifies()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateMlDsa87Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                BouncyCastleCryptographicFunctionsAdapter.SignMlDsa87Async, BouncyCastleCryptographicFunctionsAdapter.VerifyMlDsa87Async).ConfigureAwait(false);
        }


        [TestMethod]
        public void MlKem512KeyPairHasCorrectPublicKeySize()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateMlKem512Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.HasCount(800, publicKey.AsReadOnlySpan());
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public void MlKem512EncapsulateDecapsulateProducesSameSecret()
        {
            AssertMlKemRoundTrip(
                BouncyCastleKeyMaterialCreator.CreateMlKem512Keys,
                BouncyCastleCryptographicFunctions.EncapsulateMlKem512,
                BouncyCastleCryptographicFunctions.DecapsulateMlKem512);
        }


        [TestMethod]
        public void MlKem768KeyPairHasCorrectPublicKeySize()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateMlKem768Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.HasCount(1184, publicKey.AsReadOnlySpan());
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public void MlKem768EncapsulateDecapsulateProducesSameSecret()
        {
            AssertMlKemRoundTrip(
                BouncyCastleKeyMaterialCreator.CreateMlKem768Keys,
                BouncyCastleCryptographicFunctions.EncapsulateMlKem768,
                BouncyCastleCryptographicFunctions.DecapsulateMlKem768);
        }


        [TestMethod]
        public void MlKem768DifferentKeysProduceDifferentSecrets()
        {
            var aliceKeys = BouncyCastleKeyMaterialCreator.CreateMlKem768Keys(BaseMemoryPool.Shared);
            using var alicePublicKey = aliceKeys.PublicKey;
            using var alicePrivateKey = aliceKeys.PrivateKey;

            var bobKeys = BouncyCastleKeyMaterialCreator.CreateMlKem768Keys(BaseMemoryPool.Shared);
            using var bobPublicKey = bobKeys.PublicKey;
            using var bobPrivateKey = bobKeys.PrivateKey;

            var (ciphertext, senderSecret) = BouncyCastleCryptographicFunctions.EncapsulateMlKem768(
                alicePublicKey.AsReadOnlyMemory(), BaseMemoryPool.Shared);
            using var ct = ciphertext;
            using var ss = senderSecret;

            using var wrongSecret = BouncyCastleCryptographicFunctions.DecapsulateMlKem768(
                bobPrivateKey.AsReadOnlyMemory(), ct.Memory, BaseMemoryPool.Shared);

            Assert.IsFalse(ss.Memory.Span.SequenceEqual(wrongSecret.Memory.Span));
        }


        [TestMethod]
        public void MlKem1024KeyPairHasCorrectPublicKeySize()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateMlKem1024Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.HasCount(1568, publicKey.AsReadOnlySpan());
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public void MlKem1024EncapsulateDecapsulateProducesSameSecret()
        {
            AssertMlKemRoundTrip(
                BouncyCastleKeyMaterialCreator.CreateMlKem1024Keys,
                BouncyCastleCryptographicFunctions.EncapsulateMlKem1024,
                BouncyCastleCryptographicFunctions.DecapsulateMlKem1024);
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.4">RFC 8725 Section 3.4</see>: "This includes
        /// points not on the specified elliptic curve or other invalid points (e.g., [Valenta], Section 7.1).  The
        /// JWS/JWE library itself must validate these inputs before using them, or it must use underlying
        /// cryptographic libraries that do so (or both!)." A P-256 public key is the SEC1 point the verifier reads:
        /// 0x02 or 0x03 followed by the 32-octet coordinate, or 0x04 followed by both coordinates. Presented octets
        /// of one of those lengths that are no such point (the hybrid form 0x06 or 0x07 followed by both coordinates,
        /// a first octet that names no encoding, the uncompressed prefix at the compressed length, the infinity
        /// prefix 0x00 at the compressed length, and an uncompressed point not on the curve), and presented octets of
        /// a length neither encoding has (no octets, and the 32 octets of the coordinate without its prefix), are no
        /// public key a signature verifies under: <see cref="BouncyCastleCryptographicFunctions.VerifyP256Async"/>,
        /// called directly with a correct signature over the data, answers <see langword="false"/> and raises nothing.
        /// </summary>
        /// <param name="shape">The presented public key octets.</param>
        [TestMethod]
        [DataRow("hybrid")]
        [DataRow("firstOctetNamesNoEncoding")]
        [DataRow("uncompressedPrefixAtCompressedLength")]
        [DataRow("infinityPrefixAtCompressedLength")]
        [DataRow("notOnTheCurve")]
        [DataRow("noOctets")]
        [DataRow("coordinateWithoutPrefix")]
        public async Task EcdsaAnswersFalseForPublicKeyOctetsThatAreNoSec1Point(string shape)
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            using Signature signature = await SignP256Async(privateKey).ConfigureAwait(false);
            byte[] compressed = publicKey.AsReadOnlySpan().ToArray();
            Assert.HasCount(33, compressed);
            byte[] uncompressed = EllipticCurveUtilities.NormalizeToUncompressed(compressed, EllipticCurveTypes.NistCurves);

            byte[] presented = shape switch
            {
                "hybrid" => [(byte)(0x06 | (uncompressed[^1] & 0x01)), .. uncompressed[1..]],
                "firstOctetNamesNoEncoding" => [0x05, .. compressed[1..]],
                "uncompressedPrefixAtCompressedLength" => [0x04, .. compressed[1..]],
                "infinityPrefixAtCompressedLength" => new byte[33],
                "notOnTheCurve" => [.. uncompressed[..^1], (byte)(uncompressed[^1] ^ 0x01)],
                "noOctets" => [],
                "coordinateWithoutPrefix" => compressed[1..],
                _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, "No such public key shape.")
            };

            (bool isVerified, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.VerifyP256Async(
                TestData, signature.AsReadOnlyMemory(), presented, new FakeTimeProvider(TestClock.CanonicalEpoch), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(isVerified, $"P-256 public key octets of the shape '{shape}' do not verify through the BouncyCastle verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.4">RFC 8725 Section 3.4</see> asks the
        /// library to validate a presented point before using it; validation refuses what is no point, never a point
        /// in either encoding the verifier reads. A correct signature over the data verifies through
        /// <see cref="BouncyCastleCryptographicFunctions.VerifyP256Async"/>, called directly, under the compressed and
        /// under the uncompressed SEC1 encoding of the same public key.
        /// </summary>
        /// <param name="encoding">The SEC1 encoding of the public key: <c>compressed</c> or <c>uncompressed</c>.</param>
        [TestMethod]
        [DataRow("compressed")]
        [DataRow("uncompressed")]
        public async Task EcdsaVerifiesUnderEitherSec1EncodingOfThePublicKey(string encoding)
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            using Signature signature = await SignP256Async(privateKey).ConfigureAwait(false);
            byte[] compressed = publicKey.AsReadOnlySpan().ToArray();
            byte[] presented = encoding switch
            {
                "compressed" => compressed,
                "uncompressed" => EllipticCurveUtilities.NormalizeToUncompressed(compressed, EllipticCurveTypes.NistCurves),
                _ => throw new ArgumentOutOfRangeException(nameof(encoding), encoding, "No such SEC1 encoding.")
            };

            (bool isVerified, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.VerifyP256Async(
                TestData, signature.AsReadOnlyMemory(), presented, new FakeTimeProvider(TestClock.CanonicalEpoch), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(isVerified, $"A correct signature verifies under the {encoding} public key through the BouncyCastle verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#appendix-A.1.1">RFC 8017 Appendix A.1.1</see>: "An RSA
        /// public key should be represented with the ASN.1 type RSAPublicKey:", the SEQUENCE of the INTEGERs
        /// <c>modulus</c> and <c>publicExponent</c>. DER that carries the RSAPublicKey of a correct signature's public
        /// key and one octet after it, or a SEQUENCE that carries a third INTEGER after the two, is not exactly an
        /// RSAPublicKey, so the second arm of the rule the class summary of
        /// <see cref="BouncyCastleCryptographicFunctions"/> states reads it as the bare modulus its octets spell under
        /// the exponent 65537, and neither reading is a public key the signature verifies under. <c>trailingOctet</c>,
        /// 271 octets ending in the zero octet, spells an even integer, which
        /// <see cref="RsaUtilities.IsValidPublicKey"/> refuses:
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-3.1">RFC 8017 Section 3.1</see>: "In a valid RSA
        /// public key, the RSA modulus n is a product of u distinct odd primes r_i, i = 1, 2, ..., u, where u &gt;= 2,
        /// and the RSA public exponent e is an integer between 3 and n - 1 satisfying GCD(e,\lambda(n)) = 1, where
        /// \lambda(n) = LCM(r_1 - 1, ..., r_u - 1)." <c>thirdInteger</c>, 273 octets ending in the INTEGER 1, spells an
        /// odd integer of 2182 bits, which the check admits; BouncyCastle refuses to construct it when it has a small
        /// prime factor, and otherwise the 256-octet signature is not k octets under it:
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-8.1.2">RFC 8017 Section 8.1.2</see> and
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-8.2.2">Section 8.2.2</see>, step 1: "Length
        /// checking: If the length of the signature S is not k octets, output "invalid signature" and stop." The
        /// BouncyCastle RSASSA-PSS and RSASSA-PKCS1-v1_5 verifiers with SHA-256, called directly, answer
        /// <see langword="false"/> for each and raise nothing.
        /// </summary>
        /// <param name="scheme">The RSA signature scheme: <c>Pss</c> or <c>Pkcs1</c>.</param>
        /// <param name="shape">The presented DER: <c>trailingOctet</c> or <c>thirdInteger</c>.</param>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [TestMethod]
        [DataRow("Pss", "trailingOctet")]
        [DataRow("Pss", "thirdInteger")]
        [DataRow("Pkcs1", "trailingOctet")]
        [DataRow("Pkcs1", "thirdInteger")]
        public async Task RsaAnswersFalseForDerThatIsNotExactlyAnRsaPublicKey(string scheme, string shape)
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            using Signature signature = await SignRsaSha256Async(scheme, privateKey, TestData).ConfigureAwait(false);
            byte[] der = publicKey.AsReadOnlySpan().ToArray();
            (System.Numerics.BigInteger modulus, System.Numerics.BigInteger exponent) = RsaSignatureFixtures.ReadRsaPublicKey(der);

            byte[] presented = shape switch
            {
                "trailingOctet" => [.. der, 0x00],
                "thirdInteger" => RsaSignatureFixtures.EncodeIntegerSequence(modulus, exponent, System.Numerics.BigInteger.One),
                _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, "No such DER shape.")
            };

            bool isVerified = await VerifyRsaAsync("Sha256", scheme, TestData, signature.AsReadOnlyMemory(), presented).ConfigureAwait(false);

            Assert.IsFalse(isVerified, $"The DER shape '{shape}' does not verify through the BouncyCastle {scheme} verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-3.1">RFC 8017 Section 3.1</see>: "For the purposes
        /// of this document, an RSA public key consists of two components:" the modulus n and the public exponent e.
        /// Public key octets that are not exactly a DER RSAPublicKey are read as the bare modulus they spell under the
        /// exponent 65537 (the second arm of the rule the class summary of <see cref="BouncyCastleCryptographicFunctions"/>
        /// states), the form in which this library's certificate verifiers hand the modulus of a certificate of any size
        /// after holding its exponent to 65537 themselves: a correct signature made under a 3072-bit key pair verifies
        /// through the BouncyCastle RSASSA-PSS and RSASSA-PKCS1-v1_5 verifiers with SHA-256, called directly under the
        /// 384 octets of its bare modulus.
        /// </summary>
        /// <param name="scheme">The RSA signature scheme: <c>Pss</c> or <c>Pkcs1</c>.</param>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [TestMethod]
        [DataRow("Pss")]
        [DataRow("Pkcs1")]
        public async Task RsaVerifiesUnderTheBareModulusOfA3072BitKeyPair(string scheme)
        {
            RsaPrivateCrtKeyParameters privateKey = RsaSignatureFixtures.GeneratePrivateKey(3072);
            Assert.AreEqual(3072, privateKey.Modulus.BitLength, "The modulus is 3072 bits.");
            byte[] signature = RsaSignatureFixtures.Sign(scheme, "Sha256", privateKey, TestData);
            byte[] presented = RsaSignatureFixtures.ToOctets(privateKey.Modulus, 384);

            bool isVerified = await VerifyRsaAsync("Sha256", scheme, TestData, signature, presented).ConfigureAwait(false);

            Assert.IsTrue(isVerified, $"A correct signature verifies under the bare 384-octet modulus of a 3072-bit key pair through the BouncyCastle {scheme} verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-3.1">RFC 8017 Section 3.1</see>: "In a valid RSA
        /// public key, the RSA modulus n is a product of u distinct odd primes r_i, i = 1, 2, ..., u, where u &gt;= 2,
        /// and the RSA public exponent e is an integer between 3 and n - 1 satisfying GCD(e,\lambda(n)) = 1, where
        /// \lambda(n) = LCM(r_1 - 1, ..., r_u - 1)." An even octet string of 300 octets, not DER, is read by the second
        /// arm of the rule the class summary of <see cref="BouncyCastleCryptographicFunctions"/> states as the bare
        /// modulus it spells, which is even and so no valid RSA public key: the BouncyCastle
        /// RSASSA-PSS and RSASSA-PKCS1-v1_5 verifiers with SHA-256, called directly with a signature of 256 octets,
        /// answer <see langword="false"/> and raise nothing.
        /// </summary>
        /// <param name="scheme">The RSA signature scheme: <c>Pss</c> or <c>Pkcs1</c>.</param>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [TestMethod]
        [DataRow("Pss")]
        [DataRow("Pkcs1")]
        public async Task RsaAnswersFalseForAnEvenBareModulusOfAnotherLength(string scheme)
        {
            byte[] presented = RsaSignatureFixtures.ToOctets(RsaSignatureFixtures.Modulus2400Bits.Value.Subtract(BcBigInteger.One), 300);
            Assert.AreEqual(0, presented[^1] & 0x01, "The octets spell an even integer.");
            byte[] signature = Enumerable.Repeat((byte)0x01, 256).ToArray();

            bool isVerified = await VerifyRsaAsync("Sha256", scheme, TestData, signature, presented).ConfigureAwait(false);

            Assert.IsFalse(isVerified, $"An even bare modulus of 300 octets does not verify through the BouncyCastle {scheme} verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-8.1.2">RFC 8017 Section 8.1.2</see>
        /// (RSASSA-PSS-VERIFY) and <see href="https://www.rfc-editor.org/rfc/rfc8017#section-8.2.2">Section 8.2.2</see>
        /// (RSASSA-PKCS1-V1_5-VERIFY), step 1: "Length checking: If the length of the signature S is not k octets,
        /// output "invalid signature" and stop." An odd octet string of 300 octets, not DER, is read by the second arm
        /// of the rule the class summary of <see cref="BouncyCastleCryptographicFunctions"/> states as the bare modulus
        /// it spells (a valid RSA public key under 65537, k = 300), under which a signature
        /// of 256 octets is not k octets: the BouncyCastle RSASSA-PSS and RSASSA-PKCS1-v1_5 verifiers with SHA-256,
        /// called directly, answer <see langword="false"/> and raise nothing.
        /// </summary>
        /// <param name="scheme">The RSA signature scheme: <c>Pss</c> or <c>Pkcs1</c>.</param>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [TestMethod]
        [DataRow("Pss")]
        [DataRow("Pkcs1")]
        public async Task RsaAnswersFalseForASignatureThatIsNotTheLengthOfABareModulusOfAnotherLength(string scheme)
        {
            BcBigInteger modulus = RsaSignatureFixtures.Modulus2400Bits.Value;
            Assert.AreEqual(2400, modulus.BitLength, "The modulus is 2400 bits.");
            byte[] presented = RsaSignatureFixtures.ToOctets(modulus, 300);
            Assert.IsTrue(RsaUtilities.IsValidPublicKey(presented, RsaSignatureFixtures.DefaultPublicExponent.ToByteArrayUnsigned()), "The modulus and 65537 are a valid RSA public key.");
            byte[] signature = Enumerable.Repeat((byte)0x01, 256).ToArray();

            bool isVerified = await VerifyRsaAsync("Sha256", scheme, TestData, signature, presented).ConfigureAwait(false);

            Assert.IsFalse(isVerified, $"A signature of 256 octets under a bare modulus of 300 octets does not verify through the BouncyCastle {scheme} verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#appendix-A.1.1">RFC 8017 Appendix A.1.1</see>: "An RSA
        /// public key should be represented with the ASN.1 type RSAPublicKey:", the SEQUENCE of the INTEGERs
        /// <c>modulus</c> and <c>publicExponent</c>. Octets that are exactly a DER RSAPublicKey are that modulus and
        /// that exponent whatever their length, the first arm of the rule the class summary of
        /// <see cref="BouncyCastleCryptographicFunctions"/> states: the DER RSAPublicKey of a 1952-bit key pair under
        /// the exponent 65537 is 256 octets long, and a correct signature made under that key pair verifies through
        /// the BouncyCastle RSASSA-PSS and RSASSA-PKCS1-v1_5 verifiers with SHA-256, called directly under that DER.
        /// </summary>
        /// <param name="scheme">The RSA signature scheme: <c>Pss</c> or <c>Pkcs1</c>.</param>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [TestMethod]
        [DataRow("Pss")]
        [DataRow("Pkcs1")]
        public async Task RsaVerifiesUnderAnRsaPublicKeyWhoseDerIs256Octets(string scheme)
        {
            RsaPrivateCrtKeyParameters privateKey = RsaSignatureFixtures.GeneratePrivateKey(1952);
            Assert.AreEqual(1952, privateKey.Modulus.BitLength, "The modulus is 1952 bits.");
            byte[] presented = RsaSignatureFixtures.EncodeRsaPublicKey(privateKey.Modulus, privateKey.PublicExponent);
            Assert.HasCount(256, presented);
            byte[] signature = RsaSignatureFixtures.Sign(scheme, "Sha256", privateKey, TestData);

            bool isVerified = await VerifyRsaAsync("Sha256", scheme, TestData, signature, presented).ConfigureAwait(false);

            Assert.IsTrue(isVerified, $"A correct signature verifies under a 256-octet DER RSAPublicKey through the BouncyCastle {scheme} verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-2">RFC 7518 Section 2</see>, Base64urlUInt: "The
        /// octet sequence MUST utilize the minimum number of octets needed to represent the value." A bare modulus is
        /// held to the minimum number of octets, so octets that are no DER RSAPublicKey and whose first octet is zero
        /// are no modulus under the second arm of the rule the class summary of
        /// <see cref="BouncyCastleCryptographicFunctions"/> states: the bare modulus of a 2048-bit key pair after one
        /// zero octet (257 octets) and the bare modulus of a 2040-bit key pair after one zero octet (256 octets), each
        /// with a correct signature made under that key pair, do not verify through the BouncyCastle RSASSA-PSS and
        /// RSASSA-PKCS1-v1_5 verifiers with
        /// SHA-256, called directly, which answer <see langword="false"/> and raise nothing.
        /// </summary>
        /// <param name="scheme">The RSA signature scheme: <c>Pss</c> or <c>Pkcs1</c>.</param>
        /// <param name="length">The length of the presented octets: <c>257</c> or <c>256</c>.</param>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [TestMethod]
        [DataRow("Pss", 257)]
        [DataRow("Pss", 256)]
        [DataRow("Pkcs1", 257)]
        [DataRow("Pkcs1", 256)]
        public async Task RsaAnswersFalseForABareModulusAfterALeadingZeroOctet(string scheme, int length)
        {
            int modulusBitLength = length switch
            {
                257 => 2048,
                256 => 2040,
                _ => throw new ArgumentOutOfRangeException(nameof(length), length, "No such length.")
            };

            RsaPrivateCrtKeyParameters privateKey = RsaSignatureFixtures.GeneratePrivateKey(modulusBitLength);
            Assert.AreEqual(modulusBitLength, privateKey.Modulus.BitLength, $"The modulus is {modulusBitLength} bits.");
            byte[] presented = [0x00, .. RsaSignatureFixtures.ToOctets(privateKey.Modulus, length - 1)];
            Assert.HasCount(length, presented);
            byte[] signature = RsaSignatureFixtures.Sign(scheme, "Sha256", privateKey, TestData);

            bool isVerified = await VerifyRsaAsync("Sha256", scheme, TestData, signature, presented).ConfigureAwait(false);

            Assert.IsFalse(isVerified, $"A bare modulus after a leading zero octet, {length} octets, does not verify through the BouncyCastle {scheme} verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-3.1">RFC 8017 Section 3.1</see>: "For the purposes
        /// of this document, an RSA public key consists of two components:" the modulus n and the public exponent e.
        /// Exactly a DER RSAPublicKey is its modulus and exponent, and any other octets are the bare modulus they spell
        /// under the exponent 65537, the two arms of the rule the class summary of
        /// <see cref="BouncyCastleCryptographicFunctions"/> states: a correct signature made under a key pair verifies through the BouncyCastle
        /// RSASSA-PSS and RSASSA-PKCS1-v1_5 verifiers with SHA-256, called directly, under the bare 256-octet modulus
        /// of a 2048-bit key pair, under the DER RSAPublicKey of a 3072-bit key pair and under the bare 512-octet
        /// modulus of a 4096-bit key pair. The other forms are held by <see cref="Rsa2048SignatureVerifies"/>,
        /// <see cref="RsaVerifiesUnderTheBareModulusOfA3072BitKeyPair"/> and <see cref="Rsa4096SignatureVerifies"/>.
        /// </summary>
        /// <param name="scheme">The RSA signature scheme: <c>Pss</c> or <c>Pkcs1</c>.</param>
        /// <param name="modulusBitLength">The bit length of the key pair's modulus.</param>
        /// <param name="form">The public key's form: <c>der</c> or <c>bareModulus</c>.</param>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [TestMethod]
        [DataRow("Pss", 2048, "bareModulus")]
        [DataRow("Pkcs1", 2048, "bareModulus")]
        [DataRow("Pss", 3072, "der")]
        [DataRow("Pkcs1", 3072, "der")]
        [DataRow("Pss", 4096, "bareModulus")]
        [DataRow("Pkcs1", 4096, "bareModulus")]
        public async Task RsaVerifiesUnderTheDerOrTheBareModulusOfAKeyPair(string scheme, int modulusBitLength, string form)
        {
            RsaPrivateCrtKeyParameters privateKey = RsaSignatureFixtures.GeneratePrivateKey(modulusBitLength);
            Assert.AreEqual(modulusBitLength, privateKey.Modulus.BitLength, $"The modulus is {modulusBitLength} bits.");
            byte[] presented = form switch
            {
                "der" => RsaSignatureFixtures.EncodeRsaPublicKey(privateKey.Modulus, privateKey.PublicExponent),
                "bareModulus" => RsaSignatureFixtures.ToOctets(privateKey.Modulus, modulusBitLength / 8),
                _ => throw new ArgumentOutOfRangeException(nameof(form), form, "No such public key form.")
            };

            byte[] signature = RsaSignatureFixtures.Sign(scheme, "Sha256", privateKey, TestData);

            bool isVerified = await VerifyRsaAsync("Sha256", scheme, TestData, signature, presented).ConfigureAwait(false);

            Assert.IsTrue(isVerified, $"A correct signature verifies under the {form} of a {modulusBitLength}-bit key pair through the BouncyCastle {scheme} verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-3.1">RFC 8017 Section 3.1</see>: "In a valid RSA
        /// public key, the RSA modulus n is a product of u distinct odd primes r_i, i = 1, 2, ..., u, where u &gt;= 2,
        /// and the RSA public exponent e is an integer between 3 and n - 1 satisfying GCD(e,\lambda(n)) = 1, where
        /// \lambda(n) = LCM(r_1 - 1, ..., r_u - 1)." An RSAPublicKey whose modulus is even, whose exponent is even
        /// (no even e is coprime to the even \lambda(n)), whose exponent is 0 (not between 3 and n - 1), or whose
        /// modulus has the small prime factor 3 is no valid RSA public key: the BouncyCastle RSASSA-PSS and
        /// RSASSA-PKCS1-v1_5 verifiers with SHA-256, called directly, answer <see langword="false"/> and raise nothing.
        /// </summary>
        /// <param name="scheme">The RSA signature scheme: <c>Pss</c> or <c>Pkcs1</c>.</param>
        /// <param name="shape">The presented parameters: <c>evenModulus</c>, <c>evenExponent</c>, <c>zeroExponent</c> or <c>modulusWithASmallFactor</c>.</param>
        [TestMethod]
        [DataRow("Pss", "evenModulus")]
        [DataRow("Pss", "evenExponent")]
        [DataRow("Pss", "zeroExponent")]
        [DataRow("Pss", "modulusWithASmallFactor")]
        [DataRow("Pkcs1", "evenModulus")]
        [DataRow("Pkcs1", "evenExponent")]
        [DataRow("Pkcs1", "zeroExponent")]
        [DataRow("Pkcs1", "modulusWithASmallFactor")]
        public async Task RsaAnswersFalseForParametersThatAreNoValidRsaPublicKey(string scheme, string shape)
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            using Signature signature = await SignRsaSha256Async(scheme, privateKey, TestData).ConfigureAwait(false);
            (System.Numerics.BigInteger modulus, System.Numerics.BigInteger exponent) = RsaSignatureFixtures.ReadRsaPublicKey(publicKey.AsReadOnlySpan().ToArray());

            byte[] presented = shape switch
            {
                "evenModulus" => RsaSignatureFixtures.EncodeIntegerSequence(modulus - 1, exponent),
                "evenExponent" => RsaSignatureFixtures.EncodeIntegerSequence(modulus, exponent + 1),
                "zeroExponent" => RsaSignatureFixtures.EncodeIntegerSequence(modulus, System.Numerics.BigInteger.Zero),
                "modulusWithASmallFactor" => RsaSignatureFixtures.EncodeIntegerSequence(modulus * 3, exponent),
                _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, "No such parameter shape.")
            };

            bool isVerified = await VerifyRsaAsync("Sha256", scheme, TestData, signature.AsReadOnlyMemory(), presented).ConfigureAwait(false);

            Assert.IsFalse(isVerified, $"The RSA parameters '{shape}' do not verify through the BouncyCastle {scheme} verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-9.1.2">RFC 8017 Section 9.1.2</see>
        /// (EMSA-PSS-VERIFY), step 3: "If emLen &lt; hLen + sLen + 2, output "inconsistent" and stop." With SHA-512 and
        /// the salt of the digest's length, hLen + sLen + 2 is 130 octets; a modulus of 1024 bits (the product of two
        /// primes near 1.5 * 2^511, with no small factor), a valid RSA public key under 65537 at this library's
        /// smallest accepted size, gives emLen 128, so no RSASSA-PSS signature with SHA-512 verifies under it: the
        /// BouncyCastle RSASSA-PSS verifier with SHA-512, called directly with a 128-octet signature between 1 and
        /// n - 1, answers <see langword="false"/> and raises nothing.
        /// </summary>
        [TestMethod]
        public async Task RsaPssAnswersFalseForAModulusTooSmallForTheEncoding()
        {
            BcBigInteger firstPrime = BcBigInteger.Three.ShiftLeft(510).NextProbablePrime();
            BcBigInteger secondPrime = BcBigInteger.Three.ShiftLeft(510).Add(BcBigInteger.ValueOf(1_000_000)).NextProbablePrime();
            BcBigInteger product = firstPrime.Multiply(secondPrime);
            Assert.AreEqual(1024, product.BitLength, "The modulus is 1024 bits.");
            Assert.IsTrue(RsaUtilities.IsValidPublicKey(product.ToByteArrayUnsigned(), RsaSignatureFixtures.DefaultPublicExponent.ToByteArrayUnsigned()), "The modulus and 65537 are a valid RSA public key.");
            Assert.IsLessThan(64 + 64 + 2, (product.BitLength - 1 + 7) / 8, "emLen is below hLen + sLen + 2 for SHA-512.");

            byte[] presented = RsaSignatureFixtures.EncodeRsaPublicKey(product, RsaSignatureFixtures.DefaultPublicExponent);
            byte[] signature = Enumerable.Repeat((byte)0x01, 128).ToArray();

            bool isVerified = await VerifyRsaAsync("Sha512", "Pss", TestData, signature, presented).ConfigureAwait(false);

            Assert.IsFalse(isVerified, "A 1024-bit modulus does not verify through the BouncyCastle Pss verifier with SHA-512.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-5.2.2">RFC 8017 Section 5.2.2</see> (RSAVP1), step
        /// 1: "If the signature representative s is not between 0 and n - 1, output "signature representative out of
        /// range" and stop." 0, 1 and n - 1 are in that range; RSAVP1 maps each to itself (s^e mod n with an odd e), and
        /// none is the encoded message of RSASSA-PSS or RSASSA-PKCS1-v1_5, so a signature of k octets whose value is
        /// one of them does not verify under a valid RSA public key: the BouncyCastle RSASSA-PSS verifiers with
        /// SHA-256, SHA-384 and SHA-512 and the RSASSA-PKCS1-v1_5 verifier with SHA-256, called directly under the
        /// DER RSAPublicKey of a 2048-bit key pair, answer <see langword="false"/> and raise nothing.
        /// </summary>
        /// <param name="scheme">The RSA signature scheme: <c>Pss</c> or <c>Pkcs1</c>.</param>
        /// <param name="digest">The digest: <c>Sha256</c>, <c>Sha384</c> or <c>Sha512</c>.</param>
        /// <param name="representative">The signature's value: <c>zero</c>, <c>one</c> or <c>modulusMinusOne</c>.</param>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [TestMethod]
        [DataRow("Pss", "Sha256", "zero")]
        [DataRow("Pss", "Sha256", "one")]
        [DataRow("Pss", "Sha256", "modulusMinusOne")]
        [DataRow("Pss", "Sha384", "zero")]
        [DataRow("Pss", "Sha384", "one")]
        [DataRow("Pss", "Sha384", "modulusMinusOne")]
        [DataRow("Pss", "Sha512", "zero")]
        [DataRow("Pss", "Sha512", "one")]
        [DataRow("Pss", "Sha512", "modulusMinusOne")]
        [DataRow("Pkcs1", "Sha256", "zero")]
        [DataRow("Pkcs1", "Sha256", "one")]
        [DataRow("Pkcs1", "Sha256", "modulusMinusOne")]
        public async Task RsaAnswersFalseForASignatureRepresentativeThatMapsToItself(string scheme, string digest, string representative)
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            (System.Numerics.BigInteger modulus, System.Numerics.BigInteger _) = RsaSignatureFixtures.ReadRsaPublicKey(publicKey.AsReadOnlySpan().ToArray());
            BcBigInteger value = representative switch
            {
                "zero" => BcBigInteger.Zero,
                "one" => BcBigInteger.One,
                "modulusMinusOne" => new BcBigInteger(1, modulus.ToByteArray(isUnsigned: true, isBigEndian: true)).Subtract(BcBigInteger.One),
                _ => throw new ArgumentOutOfRangeException(nameof(representative), representative, "No such signature representative.")
            };

            byte[] signature = RsaSignatureFixtures.ToOctets(value, 256);

            bool isVerified = await VerifyRsaAsync(digest, scheme, TestData, signature, publicKey.AsReadOnlyMemory()).ConfigureAwait(false);

            Assert.IsFalse(isVerified, $"A signature of value '{representative}' does not verify through the BouncyCastle {scheme} verifier with {digest}.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-8.1.2">RFC 8017 Section 8.1.2</see>
        /// (RSASSA-PSS-VERIFY), step 2.c: "Convert the message representative m to an encoded message EM of length
        /// emLen = \ceil ((modBits - 1)/8) octets, where modBits is the length in bits of the RSA modulus n (see
        /// Section 4.1): EM = I2OSP (m, emLen). Note that emLen will be one less than k if modBits - 1 is divisible by 8
        /// and equal to k otherwise. If I2OSP outputs "integer too large", output "invalid signature" and stop." Under
        /// a 2049-bit modulus k is 257 and emLen 256; the signature s = m^d mod n of the message representative
        /// m = 2^2048 recovers m, which needs 257 octets, so it does not verify: each BouncyCastle RSASSA-PSS verifier,
        /// called directly under the DER RSAPublicKey of that modulus, answers <see langword="false"/> and raises
        /// nothing.
        /// </summary>
        /// <param name="digest">The digest: <c>Sha256</c>, <c>Sha384</c> or <c>Sha512</c>.</param>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [TestMethod]
        [DataRow("Sha256")]
        [DataRow("Sha384")]
        [DataRow("Sha512")]
        public async Task RsaPssAnswersFalseForARepresentativeLongerThanTheEncodedMessage(string digest)
        {
            RsaPrivateCrtKeyParameters privateKey = Modulus2049PrivateKey.Value;
            Assert.AreEqual(2049, privateKey.Modulus.BitLength, "The modulus is 2049 bits.");

            BcBigInteger messageRepresentative = BcBigInteger.One.ShiftLeft(2048);
            BcBigInteger signatureRepresentative = messageRepresentative.ModPow(privateKey.Exponent, privateKey.Modulus);
            Assert.AreEqual(messageRepresentative, signatureRepresentative.ModPow(privateKey.PublicExponent, privateKey.Modulus), "The signature recovers 2^2048.");

            byte[] signature = RsaSignatureFixtures.ToOctets(signatureRepresentative, 257);
            byte[] presented = RsaSignatureFixtures.EncodeRsaPublicKey(privateKey.Modulus, privateKey.PublicExponent);

            bool isVerified = await VerifyRsaAsync(digest, "Pss", TestData, signature, presented).ConfigureAwait(false);

            Assert.IsFalse(isVerified, $"A recovered representative of 257 octets under a 2049-bit modulus does not verify through the BouncyCastle Pss verifier with {digest}.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-8.1.2">RFC 8017 Section 8.1.2</see>, step 2.c:
        /// "Note that emLen will be one less than k if modBits - 1 is divisible by 8 and equal to k otherwise." Under a
        /// 2049-bit modulus emLen is 256, one less than k: a correct RSASSA-PSS signature made under that key pair, with the
        /// digest and MGF1 of the same digest and a salt of the digest's length, verifies through each BouncyCastle
        /// RSASSA-PSS verifier, called directly under the DER RSAPublicKey of that modulus.
        /// </summary>
        /// <param name="digest">The digest: <c>Sha256</c>, <c>Sha384</c> or <c>Sha512</c>.</param>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [TestMethod]
        [DataRow("Sha256")]
        [DataRow("Sha384")]
        [DataRow("Sha512")]
        public async Task RsaPssVerifiesUnderAModulusWhoseEncodedMessageIsOneOctetShorter(string digest)
        {
            RsaPrivateCrtKeyParameters privateKey = Modulus2049PrivateKey.Value;
            Assert.AreEqual(2049, privateKey.Modulus.BitLength, "The modulus is 2049 bits.");

            byte[] signature = RsaSignatureFixtures.Sign("Pss", digest, privateKey, TestData);
            byte[] presented = RsaSignatureFixtures.EncodeRsaPublicKey(privateKey.Modulus, privateKey.PublicExponent);

            bool isVerified = await VerifyRsaAsync(digest, "Pss", TestData, signature, presented).ConfigureAwait(false);

            Assert.IsTrue(isVerified, $"A correct signature under a 2049-bit modulus verifies through the BouncyCastle Pss verifier with {digest}.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-3.1">RFC 8017 Section 3.1</see>: "In a valid RSA
        /// public key, the RSA modulus n is a product of u distinct odd primes r_i, i = 1, 2, ..., u, where u &gt;= 2,
        /// and the RSA public exponent e is an integer between 3 and n - 1 satisfying GCD(e,\lambda(n)) = 1, where
        /// \lambda(n) = LCM(r_1 - 1, ..., r_u - 1)." Under the exponent 1 the RSA function is the identity, so the
        /// encoded message of the data, computed with no private key (the private exponent 1 over the same modulus),
        /// is its own signature: an RSAPublicKey whose exponent is 1 is no valid RSA public key, and the BouncyCastle
        /// RSASSA-PSS and RSASSA-PKCS1-v1_5 verifiers with SHA-256, called directly with that signature, answer
        /// <see langword="false"/> and raise nothing.
        /// </summary>
        /// <param name="scheme">The RSA signature scheme: <c>Pss</c> or <c>Pkcs1</c>.</param>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [TestMethod]
        [DataRow("Pss")]
        [DataRow("Pkcs1")]
        public async Task RsaAnswersFalseForASignatureUnderThePublicExponentOne(string scheme)
        {
            RsaPrivateCrtKeyParameters privateKey = RsaSignatureFixtures.GeneratePrivateKey(2048);
            byte[] encodedMessage = RsaSignatureFixtures.Sign(scheme, "Sha256", new RsaKeyParameters(isPrivate: true, privateKey.Modulus, BcBigInteger.One), TestData);
            byte[] presented = RsaSignatureFixtures.EncodeRsaPublicKey(privateKey.Modulus, BcBigInteger.One);

            bool isVerified = await VerifyRsaAsync("Sha256", scheme, TestData, encodedMessage, presented).ConfigureAwait(false);

            Assert.IsFalse(isVerified, $"The encoded message under the public exponent 1 does not verify through the BouncyCastle {scheme} verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-3.1">RFC 8017 Section 3.1</see>: "In a valid RSA
        /// public key, the RSA modulus n is a product of u distinct odd primes r_i, i = 1, 2, ..., u, where u &gt;= 2,
        /// and the RSA public exponent e is an integer between 3 and n - 1 satisfying GCD(e,\lambda(n)) = 1, where
        /// \lambda(n) = LCM(r_1 - 1, ..., r_u - 1)." The exponent 65537 + 2(p - 1)(q - 1) is not below n and is
        /// congruent to 65537 modulo (p - 1)(q - 1), so a correct signature made under the key pair's private exponent
        /// satisfies it: an RSAPublicKey carrying it is no valid RSA public key, and the BouncyCastle RSASSA-PSS and
        /// RSASSA-PKCS1-v1_5 verifiers with SHA-256, called directly with that signature, answer
        /// <see langword="false"/> and raise nothing.
        /// </summary>
        /// <param name="scheme">The RSA signature scheme: <c>Pss</c> or <c>Pkcs1</c>.</param>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [TestMethod]
        [DataRow("Pss")]
        [DataRow("Pkcs1")]
        public async Task RsaAnswersFalseForAPublicExponentNotBelowTheModulus(string scheme)
        {
            RsaPrivateCrtKeyParameters privateKey = RsaSignatureFixtures.GeneratePrivateKey(2048);
            BcBigInteger totient = privateKey.P.Subtract(BcBigInteger.One).Multiply(privateKey.Q.Subtract(BcBigInteger.One));
            BcBigInteger exponent = privateKey.PublicExponent.Add(totient.ShiftLeft(1));
            Assert.IsGreaterThanOrEqualTo(0, exponent.CompareTo(privateKey.Modulus), "The exponent is not below the modulus.");

            byte[] signature = RsaSignatureFixtures.Sign(scheme, "Sha256", privateKey, TestData);
            byte[] presented = RsaSignatureFixtures.EncodeRsaPublicKey(privateKey.Modulus, exponent);

            bool isVerified = await VerifyRsaAsync("Sha256", scheme, TestData, signature, presented).ConfigureAwait(false);

            Assert.IsFalse(isVerified, $"A public exponent not below the modulus does not verify through the BouncyCastle {scheme} verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8032#section-5.1.3">RFC 8032 Section 5.1.3</see>: "Decoding a
        /// point, given as a 32-octet string, is a little more complicated." and
        /// <see href="https://www.rfc-editor.org/rfc/rfc8032#section-5.1.7">Section 5.1.7</see>, step 1: "Decode the
        /// public key A as point A'.  If any of the decodings fail (including S being out of range), the signature is
        /// invalid." Presented public key octets that are no 32-octet string (none, the first 31 octets of a correct
        /// public key, and the correct public key with one octet after it) are no Ed25519 public key a correct
        /// signature verifies under: <see cref="BouncyCastleCryptographicFunctions.VerifyEd25519Async"/>, called
        /// directly, answers <see langword="false"/> and raises nothing.
        /// </summary>
        /// <param name="length">The length of the presented public key, in octets.</param>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [TestMethod]
        [DataRow(0)]
        [DataRow(31)]
        [DataRow(33)]
        public async Task Ed25519AnswersFalseForAPublicKeyThatIsNot32Octets(int length)
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
            (Signature signature, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.SignEd25519Async(
                privateKey.AsReadOnlyMemory(), TestData, BaseMemoryPool.Shared, timeProvider, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            using(signature)
            {
                byte[] publicKeyOctets = publicKey.AsReadOnlySpan().ToArray();
                Assert.HasCount(32, publicKeyOctets);
                byte[] presented = length switch
                {
                    0 => [],
                    31 => publicKeyOctets[..31],
                    33 => [.. publicKeyOctets, 0x00],
                    _ => throw new ArgumentOutOfRangeException(nameof(length), length, "No such public key length.")
                };

                (bool isVerified, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.VerifyEd25519Async(
                    TestData, signature.AsReadOnlyMemory(), presented, timeProvider, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsFalse(isVerified, $"An Ed25519 public key of {length} octets does not verify through the BouncyCastle verifier.");
            }
        }


        /// <summary>
        /// The 2049-bit RSA key pair the rows on a modulus whose bit length is 1 modulo 8 share, generated once by
        /// BouncyCastle's generator: under it k is 257 octets and the RSASSA-PSS encoded message 256.
        /// </summary>
        private static Lazy<RsaPrivateCrtKeyParameters> Modulus2049PrivateKey { get; } = new(() => RsaSignatureFixtures.GeneratePrivateKey(2049));


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-8.2.2">RFC 8017 Section 8.2.2</see>
        /// (RSASSA-PKCS1-V1_5-VERIFY), step 1: "Length checking: If the length of the signature S is not k octets,
        /// output "invalid signature" and stop." A signature is the k octets of its representative, a leading zero
        /// octet included. Under the RSA key pair of
        /// <see href="https://www.rfc-editor.org/rfc/rfc7515#appendix-A.2">RFC 7515 Appendix A.2</see> (k is 256), the
        /// RSASSA-PKCS1-v1_5 SHA-256 signature of the message <see cref="LeadingZeroMessage"/> starts with a zero
        /// octet: made by the BouncyCastle signing member, it verifies through the BouncyCastle verifier with SHA-256,
        /// called directly under the DER RSAPublicKey of that key pair, and the same signature without its first octet,
        /// 255 octets, does not.
        /// </summary>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [TestMethod]
        public async Task RsaPkcs1VerifiesASignatureWhoseLeadingOctetIsZero()
        {
            BcBigInteger modulus = Rfc7515AppendixA2Integer(Rfc7515AppendixA2Modulus);
            BcBigInteger publicExponent = Rfc7515AppendixA2Integer(Rfc7515AppendixA2PublicExponent);
            byte[] privateKeyDer = RsaSignatureFixtures.EncodeIntegerSequence(
                System.Numerics.BigInteger.Zero,
                RsaSignatureFixtures.ToNumerics(modulus),
                RsaSignatureFixtures.ToNumerics(publicExponent),
                RsaSignatureFixtures.ToNumerics(Rfc7515AppendixA2Integer(Rfc7515AppendixA2PrivateExponent)),
                RsaSignatureFixtures.ToNumerics(Rfc7515AppendixA2Integer(Rfc7515AppendixA2FirstPrime)),
                RsaSignatureFixtures.ToNumerics(Rfc7515AppendixA2Integer(Rfc7515AppendixA2SecondPrime)),
                RsaSignatureFixtures.ToNumerics(Rfc7515AppendixA2Integer(Rfc7515AppendixA2FirstFactorExponent)),
                RsaSignatureFixtures.ToNumerics(Rfc7515AppendixA2Integer(Rfc7515AppendixA2SecondFactorExponent)),
                RsaSignatureFixtures.ToNumerics(Rfc7515AppendixA2Integer(Rfc7515AppendixA2Coefficient)));
            byte[] publicKeyDer = RsaSignatureFixtures.EncodeRsaPublicKey(modulus, publicExponent);
            byte[] data = Encoding.ASCII.GetBytes(LeadingZeroMessage);

            (Signature signature, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.SignRsaSha256Pkcs1Async(
                privateKeyDer, data, BaseMemoryPool.Shared, new FakeTimeProvider(TestClock.CanonicalEpoch), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            using(signature)
            {
                byte[] signatureOctets = signature.AsReadOnlySpan().ToArray();
                Assert.HasCount(256, signatureOctets);
                Assert.AreEqual((byte)0x00, signatureOctets[0], "The signature of the fixed message starts with a zero octet.");

                bool isVerified = await VerifyRsaAsync("Sha256", "Pkcs1", data, signatureOctets, publicKeyDer).ConfigureAwait(false);
                Assert.IsTrue(isVerified, "A signature whose leading octet is zero verifies through the BouncyCastle Pkcs1 verifier.");

                bool isShortenedVerified = await VerifyRsaAsync("Sha256", "Pkcs1", data, signatureOctets.AsMemory(1), publicKeyDer).ConfigureAwait(false);
                Assert.IsFalse(isShortenedVerified, "The same signature without its leading zero octet is not k octets and does not verify.");
            }
        }


        /// <summary>
        /// The ASCII message whose RSASSA-PKCS1-v1_5 SHA-256 signature under the RSA key pair of
        /// <see href="https://www.rfc-editor.org/rfc/rfc7515#appendix-A.2">RFC 7515 Appendix A.2</see> starts with a
        /// zero octet, found once by trying the messages ending in 0, 1, 2 and so on.
        /// </summary>
        private static string LeadingZeroMessage { get; } = "RFC 7515 Appendix A.2 leading zero 38";


        /// <summary>
        /// The <c>n</c> of the RSA key pair of <see href="https://www.rfc-editor.org/rfc/rfc7515#appendix-A.2">RFC 7515
        /// Appendix A.2</see>, base64url, its display line breaks removed.
        /// </summary>
        private static string Rfc7515AppendixA2Modulus { get; } =
            "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx" +
            "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs" +
            "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH" +
            "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV" +
            "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8" +
            "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";


        /// <summary>The <c>e</c> of the RSA key pair of <see href="https://www.rfc-editor.org/rfc/rfc7515#appendix-A.2">RFC 7515 Appendix A.2</see>, base64url.</summary>
        private static string Rfc7515AppendixA2PublicExponent { get; } = "AQAB";


        /// <summary>
        /// The <c>d</c> of the RSA key pair of <see href="https://www.rfc-editor.org/rfc/rfc7515#appendix-A.2">RFC 7515
        /// Appendix A.2</see>, base64url, its display line breaks removed.
        /// </summary>
        private static string Rfc7515AppendixA2PrivateExponent { get; } =
            "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I" +
            "jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0" +
            "BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn" +
            "439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT" +
            "CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh" +
            "BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ";


        /// <summary>
        /// The <c>p</c> of the RSA key pair of <see href="https://www.rfc-editor.org/rfc/rfc7515#appendix-A.2">RFC 7515
        /// Appendix A.2</see>, base64url, its display line breaks removed.
        /// </summary>
        private static string Rfc7515AppendixA2FirstPrime { get; } =
            "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi" +
            "YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG" +
            "BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc";


        /// <summary>
        /// The <c>q</c> of the RSA key pair of <see href="https://www.rfc-editor.org/rfc/rfc7515#appendix-A.2">RFC 7515
        /// Appendix A.2</see>, base64url, its display line breaks removed.
        /// </summary>
        private static string Rfc7515AppendixA2SecondPrime { get; } =
            "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa" +
            "ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA" +
            "-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc";


        /// <summary>
        /// The <c>dp</c> of the RSA key pair of <see href="https://www.rfc-editor.org/rfc/rfc7515#appendix-A.2">RFC 7515
        /// Appendix A.2</see>, base64url, its display line breaks removed.
        /// </summary>
        private static string Rfc7515AppendixA2FirstFactorExponent { get; } =
            "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q" +
            "CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb" +
            "34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0";


        /// <summary>
        /// The <c>dq</c> of the RSA key pair of <see href="https://www.rfc-editor.org/rfc/rfc7515#appendix-A.2">RFC 7515
        /// Appendix A.2</see>, base64url, its display line breaks removed.
        /// </summary>
        private static string Rfc7515AppendixA2SecondFactorExponent { get; } =
            "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa" +
            "7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky" +
            "NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU";


        /// <summary>
        /// The <c>qi</c> of the RSA key pair of <see href="https://www.rfc-editor.org/rfc/rfc7515#appendix-A.2">RFC 7515
        /// Appendix A.2</see>, base64url, its display line breaks removed.
        /// </summary>
        private static string Rfc7515AppendixA2Coefficient { get; } =
            "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o" +
            "y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU" +
            "W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U";


        /// <summary>The non-negative integer a base64url value of the RFC 7515 Appendix A.2 key pair encodes, big-endian.</summary>
        /// <param name="base64Url">The unpadded base64url value.</param>
        /// <returns>The integer.</returns>
        private static BcBigInteger Rfc7515AppendixA2Integer(string base64Url) =>
            new(1, System.Buffers.Text.Base64Url.DecodeFromChars(base64Url));


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8032#section-5.1.7">RFC 8032 Section 5.1.7</see>, step 1:
        /// "Decode the public key A as point A'.  If any of the decodings fail (including S being out of range), the
        /// signature is invalid." Thirty-two octets of 0xFF hold a y coordinate not below p, which no decoding
        /// accepts, and thirty-two octets that encode the neutral point are a point BouncyCastle refuses as a public
        /// key: <see cref="BouncyCastleCryptographicFunctions.VerifyEd25519Async"/>, called directly, answers
        /// <see langword="false"/> and raises nothing.
        /// </summary>
        /// <param name="shape">The presented public key: <c>coordinateNotBelowP</c> or <c>neutralPoint</c>.</param>
        [TestMethod]
        [DataRow("coordinateNotBelowP")]
        [DataRow("neutralPoint")]
        public async Task Ed25519AnswersFalseForThirtyTwoOctetsThatAreNoPublicKey(string shape)
        {
            byte[] presented = shape switch
            {
                "coordinateNotBelowP" => Enumerable.Repeat((byte)0xFF, 32).ToArray(),
                "neutralPoint" => [0x01, .. new byte[31]],
                _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, "No such public key shape.")
            };

            (bool isVerified, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.VerifyEd25519Async(
                TestData, new byte[64], presented, new FakeTimeProvider(TestClock.CanonicalEpoch), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(isVerified, $"The 32 octets '{shape}' do not verify through the BouncyCastle Ed25519 verifier.");
        }


        /// <summary>
        /// <see href="https://csrc.nist.gov/pubs/fips/204/final">FIPS 204</see> fixes the encoded ML-DSA-44 public
        /// key at 1312 octets (the document is not quoted here), and
        /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.4">RFC 8725 Section 3.4</see> says: "The
        /// JWS/JWE library itself must validate these inputs before using them, or it must use underlying
        /// cryptographic libraries that do so (or both!)." Presented octets one shorter or one longer are no ML-DSA-44
        /// public key: <see cref="BouncyCastleCryptographicFunctions.VerifyMlDsa44Async"/>, called directly, answers
        /// <see langword="false"/> and raises nothing.
        /// </summary>
        /// <param name="length">The length of the presented public key, in octets.</param>
        [TestMethod]
        [DataRow(1311)]
        [DataRow(1313)]
        public async Task MlDsa44AnswersFalseForAPublicKeyOfTheWrongLength(int length)
        {
            (bool isVerified, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.VerifyMlDsa44Async(
                TestData, new byte[2420], new byte[length], new FakeTimeProvider(TestClock.CanonicalEpoch), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(isVerified, $"An ML-DSA-44 public key of {length} octets does not verify through the BouncyCastle verifier.");
        }


        /// <summary>Signs <see cref="TestData"/> with the BouncyCastle P-256 signer.</summary>
        /// <param name="privateKey">The P-256 private key.</param>
        /// <returns>The 64-octet signature, which the caller disposes.</returns>
        private async Task<Signature> SignP256Async(PrivateKeyMemory privateKey)
        {
            (Signature signature, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.SignP256Async(
                privateKey.AsReadOnlyMemory(), TestData, BaseMemoryPool.Shared, new FakeTimeProvider(TestClock.CanonicalEpoch), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            return signature;
        }


        /// <summary>Signs <paramref name="data"/> with the BouncyCastle RSA signer of <paramref name="scheme"/> and SHA-256.</summary>
        /// <param name="scheme"><c>Pss</c> for RSASSA-PSS or <c>Pkcs1</c> for RSASSA-PKCS1-v1_5.</param>
        /// <param name="privateKey">The RSA private key.</param>
        /// <param name="data">The data to sign.</param>
        /// <returns>The signature, which the caller disposes.</returns>
        private async Task<Signature> SignRsaSha256Async(string scheme, PrivateKeyMemory privateKey, ReadOnlyMemory<byte> data)
        {
            var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
            (Signature signature, CryptoEvent? _) = scheme switch
            {
                "Pss" => await BouncyCastleCryptographicFunctions.SignRsaSha256PssAsync(privateKey.AsReadOnlyMemory(), data, BaseMemoryPool.Shared, timeProvider, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false),
                "Pkcs1" => await BouncyCastleCryptographicFunctions.SignRsaSha256Pkcs1Async(privateKey.AsReadOnlyMemory(), data, BaseMemoryPool.Shared, timeProvider, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false),
                _ => throw new ArgumentOutOfRangeException(nameof(scheme), scheme, "No such RSA signature scheme.")
            };

            return signature;
        }


        /// <summary>
        /// Verifies with the BouncyCastle RSA verification member of <paramref name="scheme"/> and
        /// <paramref name="digest"/>, called directly.
        /// </summary>
        /// <param name="digest"><c>Sha256</c>, <c>Sha384</c> or <c>Sha512</c>.</param>
        /// <param name="scheme"><c>Pss</c> for RSASSA-PSS or <c>Pkcs1</c> for RSASSA-PKCS1-v1_5.</param>
        /// <param name="data">The signed data.</param>
        /// <param name="signature">The presented signature.</param>
        /// <param name="publicKeyMaterial">The presented public key octets.</param>
        /// <returns>The verifier's answer.</returns>
        private async Task<bool> VerifyRsaAsync(string digest, string scheme, ReadOnlyMemory<byte> data, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial)
        {
            var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
            CancellationToken cancellationToken = TestContext.CancellationToken;
            (bool isVerified, CryptoEvent? _) = (scheme, digest) switch
            {
                ("Pss", "Sha256") => await BouncyCastleCryptographicFunctions.VerifyRsaSha256PssAsync(data, signature, publicKeyMaterial, timeProvider, cancellationToken: cancellationToken).ConfigureAwait(false),
                ("Pss", "Sha384") => await BouncyCastleCryptographicFunctions.VerifyRsaSha384PssAsync(data, signature, publicKeyMaterial, timeProvider, cancellationToken: cancellationToken).ConfigureAwait(false),
                ("Pss", "Sha512") => await BouncyCastleCryptographicFunctions.VerifyRsaSha512PssAsync(data, signature, publicKeyMaterial, timeProvider, cancellationToken: cancellationToken).ConfigureAwait(false),
                ("Pkcs1", "Sha256") => await BouncyCastleCryptographicFunctions.VerifyRsaSha256Pkcs1Async(data, signature, publicKeyMaterial, timeProvider, cancellationToken: cancellationToken).ConfigureAwait(false),
                _ => throw new ArgumentOutOfRangeException(nameof(scheme), scheme, "No such RSA signature scheme and digest.")
            };

            return isVerified;
        }


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


        private async Task AssertTamperedSignatureFailsAsync(
            PrivateKeyMemory privateKey,
            PublicKeyMemory publicKey,
            SigningDelegate sign,
            VerificationDelegate verify)
        {
            ReadOnlyMemory<byte> data = TestData;
            (Signature signature, CryptoEvent? _) = await sign(privateKey.AsReadOnlyMemory(), data, BaseMemoryPool.Shared,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            using var disposableSignature = signature;

            byte[] tamperedBytes = signature.AsReadOnlyMemory().ToArray();
            tamperedBytes[0] ^= 0xFF;
            tamperedBytes[^1] ^= 0xFF;

            (bool isValid, CryptoEvent? _) = await verify(data, tamperedBytes, publicKey.AsReadOnlyMemory(),
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(isValid);
        }


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
