using Microsoft.Extensions.Time.Testing;
using Org.BouncyCastle.Crypto.Parameters;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests Microsoft CNG as the cryptographic provider across all supported algorithms,
    /// including ECDSA (P-256, P-384, P-521, secp256k1) and RSA with multiple hash/padding combinations.
    /// </summary>
    [TestClass]
    internal sealed class MicrosoftCryptographicTests
    {
        public TestContext TestContext { get; set; } = null!;

        private static byte[] TestData { get; } = Encoding.UTF8.GetBytes("Microsoft cryptographic test payload.");


        [TestMethod]
        public void P256KeyPairHasNonEmptyMaterial()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.IsGreaterThan(0, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public async Task P256SignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async, MicrosoftCryptographicFunctionsAdapter.VerifyP256Async).ConfigureAwait(false);
        }


        [TestMethod]
        public void P384KeyPairHasNonEmptyMaterial()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateP384Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.IsGreaterThan(0, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public async Task P384SignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateP384Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctionsAdapter.SignP384Async, MicrosoftCryptographicFunctionsAdapter.VerifyP384Async).ConfigureAwait(false);
        }


        [TestMethod]
        public void P521KeyPairHasNonEmptyMaterial()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateP521Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.IsGreaterThan(0, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public async Task P521SignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateP521Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctionsAdapter.SignP521Async, MicrosoftCryptographicFunctionsAdapter.VerifyP521Async).ConfigureAwait(false);
        }


        [SkipOnMacOSTestMethod]
        public void Secp256k1KeyPairHasNonEmptyMaterial()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateSecp256k1Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.IsGreaterThan(0, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [SkipOnMacOSTestMethod]
        public async Task Secp256k1SignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateSecp256k1Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctionsAdapter.SignSecp256k1Async, MicrosoftCryptographicFunctionsAdapter.VerifySecp256k1Async).ConfigureAwait(false);
        }


        [TestMethod]
        public void Rsa2048KeyPairHasNonEmptyMaterial()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.IsGreaterThan(0, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public async Task Rsa2048SignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctionsAdapter.SignRsa2048Async, MicrosoftCryptographicFunctionsAdapter.VerifyRsa2048Async).ConfigureAwait(false);
        }


        [TestMethod]
        public void Rsa4096KeyPairHasNonEmptyMaterial()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa4096Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            Assert.IsGreaterThan(0, publicKey.AsReadOnlySpan().Length);
            Assert.IsGreaterThan(0, privateKey.AsReadOnlySpan().Length);
        }


        [TestMethod]
        public async Task Rsa4096SignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa4096Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctionsAdapter.SignRsa4096Async, MicrosoftCryptographicFunctionsAdapter.VerifyRsa4096Async).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task RsaSha256Pkcs1SignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctionsAdapter.SignRsaSha256Pkcs1Async, MicrosoftCryptographicFunctionsAdapter.VerifyRsaSha256Pkcs1Async).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task RsaSha256PssSignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctionsAdapter.SignRsaSha256PssAsync, MicrosoftCryptographicFunctionsAdapter.VerifyRsaSha256PssAsync).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task RsaSha384Pkcs1SignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctionsAdapter.SignRsaSha384Pkcs1Async, MicrosoftCryptographicFunctionsAdapter.VerifyRsaSha384Pkcs1Async).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task RsaSha384PssSignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctionsAdapter.SignRsaSha384PssAsync, MicrosoftCryptographicFunctionsAdapter.VerifyRsaSha384PssAsync).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task RsaSha512Pkcs1SignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa4096Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctionsAdapter.SignRsaSha512Pkcs1Async, MicrosoftCryptographicFunctionsAdapter.VerifyRsaSha512Pkcs1Async).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task RsaSha512PssSignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa4096Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertSignAndVerifyAsync(privateKey, publicKey,
                MicrosoftCryptographicFunctionsAdapter.SignRsaSha512PssAsync, MicrosoftCryptographicFunctionsAdapter.VerifyRsaSha512PssAsync).ConfigureAwait(false);
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.4">RFC 8725 Section 3.4</see>: "The JWS/JWE
        /// library itself must validate these inputs before using them, or it must use underlying cryptographic
        /// libraries that do so (or both!)." 33 presented octets whose first octet is 0x04, the uncompressed prefix,
        /// are neither the compressed nor the uncompressed SEC1 encoding of a P-256 point:
        /// <see cref="MicrosoftCryptographicFunctions.VerifyP256Async"/>, called directly with a correct signature over
        /// the data, answers <see langword="false"/> and raises nothing.
        /// </summary>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [TestMethod]
        public async Task MicrosoftEcdsaAnswersFalseForAPublicKeyWhoseLengthAndFirstOctetDisagree()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            using Signature signature = await SignEcdsaAsync("P256", privateKey).ConfigureAwait(false);
            byte[] compressed = publicKey.AsReadOnlySpan().ToArray();
            Assert.HasCount(33, compressed);
            byte[] presented = [0x04, .. compressed[1..]];

            bool isVerified = await VerifyEcdsaAsync("P256", signature.AsReadOnlyMemory(), presented).ConfigureAwait(false);

            Assert.IsFalse(isVerified, "33 octets under the uncompressed prefix do not verify through the Microsoft verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.4">RFC 8725 Section 3.4</see>: "This includes
        /// points not on the specified elliptic curve or other invalid points (e.g., [Valenta], Section 7.1).  The
        /// JWS/JWE library itself must validate these inputs before using them, or it must use underlying
        /// cryptographic libraries that do so (or both!)." A P-256 public key is 0x02 or 0x03 followed by the 32-octet
        /// coordinate, or 0x04 followed by both coordinates, of a point on the curve. Presented octets that are no
        /// such point (the compressed prefix 0x02 followed by both coordinates, the uncompressed point of a P-384
        /// public key, a compressed point whose coordinate is the field prime, an uncompressed point not on the curve,
        /// and the uncompressed point (0, 0)) are no public key a signature verifies under:
        /// <see cref="MicrosoftCryptographicFunctions.VerifyP256Async"/>, called directly with a correct signature over
        /// the data, answers <see langword="false"/> and raises nothing.
        /// </summary>
        /// <param name="shape">The presented public key octets.</param>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [TestMethod]
        [DataRow("compressedPrefixAtUncompressedLength")]
        [DataRow("pointOfAnotherCurve")]
        [DataRow("compressedCoordinateIsThePrime")]
        [DataRow("notOnTheCurve")]
        [DataRow("origin")]
        public async Task EcdsaAnswersFalseForPublicKeyOctetsThatAreNoPointOfTheCurve(string shape)
        {
            var keys = MicrosoftKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            var otherCurveKeys = MicrosoftKeyMaterialCreator.CreateP384Keys(BaseMemoryPool.Shared);
            using var otherCurvePublicKey = otherCurveKeys.PublicKey;
            using var otherCurvePrivateKey = otherCurveKeys.PrivateKey;

            using Signature signature = await SignEcdsaAsync("P256", privateKey).ConfigureAwait(false);
            byte[] compressed = publicKey.AsReadOnlySpan().ToArray();
            Assert.HasCount(33, compressed);
            byte[] uncompressed = EllipticCurveUtilities.NormalizeToUncompressed(compressed, EllipticCurveTypes.P256);

            byte[] presented = shape switch
            {
                "compressedPrefixAtUncompressedLength" => [0x02, .. uncompressed[1..]],
                "pointOfAnotherCurve" => EllipticCurveUtilities.NormalizeToUncompressed(otherCurvePublicKey.AsReadOnlySpan(), EllipticCurveTypes.P384),
                "compressedCoordinateIsThePrime" => [0x02, .. EllipticCurveConstants.P256.PrimeBytes],
                "notOnTheCurve" => [.. uncompressed[..^1], (byte)(uncompressed[^1] ^ 0x01)],
                "origin" => [0x04, .. new byte[64]],
                _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, "No such public key shape.")
            };

            bool isVerified = await VerifyEcdsaAsync("P256", signature.AsReadOnlyMemory(), presented).ConfigureAwait(false);

            Assert.IsFalse(isVerified, $"P-256 public key octets of the shape '{shape}' do not verify through the Microsoft verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.4">RFC 8725 Section 3.4</see> asks the library
        /// to validate a presented point before using it; validation refuses what is no point of the curve, never a
        /// point in either encoding the verifier reads. A correct signature over the data verifies through the
        /// Microsoft verification member of P-256, P-384 and P-521, called directly, under the compressed and under the
        /// uncompressed SEC1 encoding of the same public key.
        /// </summary>
        /// <param name="curve">The curve: <c>P256</c>, <c>P384</c> or <c>P521</c>.</param>
        /// <param name="encoding">The SEC1 encoding of the public key: <c>compressed</c> or <c>uncompressed</c>.</param>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [TestMethod]
        [DataRow("P256", "compressed")]
        [DataRow("P256", "uncompressed")]
        [DataRow("P384", "compressed")]
        [DataRow("P384", "uncompressed")]
        [DataRow("P521", "compressed")]
        [DataRow("P521", "uncompressed")]
        public async Task EcdsaVerifiesUnderEitherSec1EncodingOfThePublicKey(string curve, string encoding)
        {
            await AssertVerifiesUnderSec1EncodingAsync(curve, encoding).ConfigureAwait(false);
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.4">RFC 8725 Section 3.4</see> asks the library
        /// to validate a presented point before using it; validation refuses what is no point of the curve, never a
        /// point in either encoding the verifier reads. A correct secp256k1 signature over the data verifies through
        /// <see cref="MicrosoftCryptographicFunctions.VerifySecp256k1Async"/>, called directly, under the compressed and
        /// under the uncompressed SEC1 encoding of the same public key (on a platform that serves the curve).
        /// </summary>
        /// <param name="encoding">The SEC1 encoding of the public key: <c>compressed</c> or <c>uncompressed</c>.</param>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [SkipOnMacOSTestMethod]
        [DataRow("compressed")]
        [DataRow("uncompressed")]
        public async Task Secp256k1VerifiesUnderEitherSec1EncodingOfThePublicKey(string encoding)
        {
            await AssertVerifiesUnderSec1EncodingAsync("Secp256k1", encoding).ConfigureAwait(false);
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-3.1">RFC 8017 Section 3.1</see>: "In a valid RSA
        /// public key, the RSA modulus n is a product of u distinct odd primes r_i, i = 1, 2, ..., u, where u &gt;= 2,
        /// and the RSA public exponent e is an integer between 3 and n - 1 satisfying GCD(e,\lambda(n)) = 1, where
        /// \lambda(n) = LCM(r_1 - 1, ..., r_u - 1)." Under the exponent 1 the RSA function is the identity, so the
        /// encoded message of the data, computed with no private key (the private exponent 1 over the same modulus),
        /// is its own signature: an RSAPublicKey whose exponent is 1 is no valid RSA public key, and the Microsoft
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

            bool isVerified = await VerifyRsaAsync("Sha256", scheme, encodedMessage, presented).ConfigureAwait(false);

            Assert.IsFalse(isVerified, $"The encoded message under the public exponent 1 does not verify through the Microsoft {scheme} verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-3.1">RFC 8017 Section 3.1</see>: "In a valid RSA
        /// public key, the RSA modulus n is a product of u distinct odd primes r_i, i = 1, 2, ..., u, where u &gt;= 2,
        /// and the RSA public exponent e is an integer between 3 and n - 1 satisfying GCD(e,\lambda(n)) = 1, where
        /// \lambda(n) = LCM(r_1 - 1, ..., r_u - 1)." The exponent 65537 + 2(p - 1)(q - 1) is not below n and is
        /// congruent to 65537 modulo (p - 1)(q - 1), so a correct signature made under the key pair's private exponent
        /// satisfies it: an RSAPublicKey carrying it is no valid RSA public key, and the Microsoft RSASSA-PSS and
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

            bool isVerified = await VerifyRsaAsync("Sha256", scheme, signature, presented).ConfigureAwait(false);

            Assert.IsFalse(isVerified, $"A public exponent not below the modulus does not verify through the Microsoft {scheme} verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-3.1">RFC 8017 Section 3.1</see>: "In a valid RSA
        /// public key, the RSA modulus n is a product of u distinct odd primes r_i, i = 1, 2, ..., u, where u &gt;= 2,
        /// and the RSA public exponent e is an integer between 3 and n - 1 satisfying GCD(e,\lambda(n)) = 1, where
        /// \lambda(n) = LCM(r_1 - 1, ..., r_u - 1)." An RSAPublicKey whose modulus is even, whose exponent is even (no
        /// even e is coprime to the even \lambda(n)), or whose exponent is 0 (not between 3 and n - 1) is no valid RSA
        /// public key: the Microsoft RSASSA-PSS and RSASSA-PKCS1-v1_5 verifiers with SHA-256, called directly with a
        /// correct signature of the key pair, answer <see langword="false"/> and raise nothing.
        /// </summary>
        /// <param name="scheme">The RSA signature scheme: <c>Pss</c> or <c>Pkcs1</c>.</param>
        /// <param name="shape">The presented parameters: <c>evenModulus</c>, <c>evenExponent</c> or <c>zeroExponent</c>.</param>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [TestMethod]
        [DataRow("Pss", "evenModulus")]
        [DataRow("Pss", "evenExponent")]
        [DataRow("Pss", "zeroExponent")]
        [DataRow("Pkcs1", "evenModulus")]
        [DataRow("Pkcs1", "evenExponent")]
        [DataRow("Pkcs1", "zeroExponent")]
        public async Task RsaAnswersFalseForParametersThatAreNoValidRsaPublicKey(string scheme, string shape)
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            using Signature signature = await SignRsaSha256Async(scheme, privateKey).ConfigureAwait(false);
            (System.Numerics.BigInteger modulus, System.Numerics.BigInteger exponent) = RsaSignatureFixtures.ReadRsaPublicKey(publicKey.AsReadOnlySpan().ToArray());

            byte[] presented = shape switch
            {
                "evenModulus" => RsaSignatureFixtures.EncodeIntegerSequence(modulus - 1, exponent),
                "evenExponent" => RsaSignatureFixtures.EncodeIntegerSequence(modulus, exponent + 1),
                "zeroExponent" => RsaSignatureFixtures.EncodeIntegerSequence(modulus, System.Numerics.BigInteger.Zero),
                _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, "No such parameter shape.")
            };

            bool isVerified = await VerifyRsaAsync("Sha256", scheme, signature.AsReadOnlyMemory(), presented).ConfigureAwait(false);

            Assert.IsFalse(isVerified, $"The RSA parameters '{shape}' do not verify through the Microsoft {scheme} verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#appendix-A.1.1">RFC 8017 Appendix A.1.1</see>: "An RSA
        /// public key should be represented with the ASN.1 type RSAPublicKey:", the SEQUENCE of the INTEGERs
        /// <c>modulus</c> and <c>publicExponent</c>. DER that carries the RSAPublicKey of a correct signature's public
        /// key and one octet after it, or a SEQUENCE that carries a third INTEGER after the two, is not exactly an
        /// RSAPublicKey, so the second arm of the rule the class remarks of
        /// <see cref="MicrosoftCryptographicFunctions"/> state reads it as the bare modulus its octets spell under the
        /// exponent 65537, and neither reading is a public key the signature verifies under. <c>trailingOctet</c>, 271
        /// octets ending in the zero octet, spells an even integer, which
        /// <see cref="RsaUtilities.IsValidPublicKey"/> refuses:
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-3.1">RFC 8017 Section 3.1</see>: "In a valid RSA
        /// public key, the RSA modulus n is a product of u distinct odd primes r_i, i = 1, 2, ..., u, where u &gt;= 2,
        /// and the RSA public exponent e is an integer between 3 and n - 1 satisfying GCD(e,\lambda(n)) = 1, where
        /// \lambda(n) = LCM(r_1 - 1, ..., r_u - 1)." <c>thirdInteger</c>, 273 octets ending in the INTEGER 1, spells an
        /// odd integer of 2182 bits, which the check admits and under which the 256-octet signature is not k octets,
        /// which the platform's import and verification answer as not verified:
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-8.1.2">RFC 8017 Section 8.1.2</see> and
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-8.2.2">Section 8.2.2</see>, step 1: "Length
        /// checking: If the length of the signature S is not k octets, output "invalid signature" and stop." The
        /// Microsoft RSASSA-PSS and RSASSA-PKCS1-v1_5 verifiers with SHA-256, called directly, answer
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
            var keys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            using Signature signature = await SignRsaSha256Async(scheme, privateKey).ConfigureAwait(false);
            byte[] der = publicKey.AsReadOnlySpan().ToArray();
            (System.Numerics.BigInteger modulus, System.Numerics.BigInteger exponent) = RsaSignatureFixtures.ReadRsaPublicKey(der);

            byte[] presented = shape switch
            {
                "trailingOctet" => [.. der, 0x00],
                "thirdInteger" => RsaSignatureFixtures.EncodeIntegerSequence(modulus, exponent, System.Numerics.BigInteger.One),
                _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, "No such DER shape.")
            };

            bool isVerified = await VerifyRsaAsync("Sha256", scheme, signature.AsReadOnlyMemory(), presented).ConfigureAwait(false);

            Assert.IsFalse(isVerified, $"The DER shape '{shape}' does not verify through the Microsoft {scheme} verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-3.1">RFC 8017 Section 3.1</see>: "For the purposes
        /// of this document, an RSA public key consists of two components:" the modulus n and the public exponent e.
        /// Public key octets that are not exactly a DER RSAPublicKey are read as the bare modulus they spell under the
        /// exponent 65537 (the second arm of the rule the class remarks of <see cref="MicrosoftCryptographicFunctions"/>
        /// state), the form in which this library's certificate verifiers hand the modulus of a certificate of any size
        /// after holding its exponent to 65537 themselves: a correct signature made under a 3072-bit key pair verifies
        /// through the Microsoft RSASSA-PSS and RSASSA-PKCS1-v1_5 verifiers with SHA-256, called directly under the 384
        /// octets of its bare modulus.
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

            bool isVerified = await VerifyRsaAsync("Sha256", scheme, signature, presented).ConfigureAwait(false);

            Assert.IsTrue(isVerified, $"A correct signature verifies under the bare 384-octet modulus of a 3072-bit key pair through the Microsoft {scheme} verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-3.1">RFC 8017 Section 3.1</see>: "In a valid RSA
        /// public key, the RSA modulus n is a product of u distinct odd primes r_i, i = 1, 2, ..., u, where u &gt;= 2,
        /// and the RSA public exponent e is an integer between 3 and n - 1 satisfying GCD(e,\lambda(n)) = 1, where
        /// \lambda(n) = LCM(r_1 - 1, ..., r_u - 1)." An even octet string of 300 octets, not DER, is read by the second
        /// arm of the rule the class remarks of <see cref="MicrosoftCryptographicFunctions"/> state as the bare modulus
        /// it spells, which is even and so no valid RSA public key: the Microsoft
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

            bool isVerified = await VerifyRsaAsync("Sha256", scheme, signature, presented).ConfigureAwait(false);

            Assert.IsFalse(isVerified, $"An even bare modulus of 300 octets does not verify through the Microsoft {scheme} verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-8.1.2">RFC 8017 Section 8.1.2</see>
        /// (RSASSA-PSS-VERIFY) and <see href="https://www.rfc-editor.org/rfc/rfc8017#section-8.2.2">Section 8.2.2</see>
        /// (RSASSA-PKCS1-V1_5-VERIFY), step 1: "Length checking: If the length of the signature S is not k octets,
        /// output "invalid signature" and stop." An odd octet string of 300 octets, not DER, is read by the second arm
        /// of the rule the class remarks of <see cref="MicrosoftCryptographicFunctions"/> state as the bare modulus it
        /// spells (a valid RSA public key under 65537, k = 300), under which a signature
        /// of 256 octets is not k octets: the Microsoft RSASSA-PSS and RSASSA-PKCS1-v1_5 verifiers with SHA-256, called
        /// directly, answer <see langword="false"/> and raise nothing.
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

            bool isVerified = await VerifyRsaAsync("Sha256", scheme, signature, presented).ConfigureAwait(false);

            Assert.IsFalse(isVerified, $"A signature of 256 octets under a bare modulus of 300 octets does not verify through the Microsoft {scheme} verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-9.1.2">RFC 8017 Section 9.1.2</see>
        /// (EMSA-PSS-VERIFY), step 3: "If emLen &lt; hLen + sLen + 2, output "inconsistent" and stop." With SHA-512 and
        /// the salt of the digest's length, hLen + sLen + 2 is 130 octets; a modulus of 1024 bits (the product of two
        /// primes near 1.5 * 2^511, with no small factor), a valid RSA public key under 65537 at this library's
        /// smallest accepted size, gives emLen 128, so no RSASSA-PSS signature with SHA-512 verifies under it:
        /// <see cref="MicrosoftCryptographicFunctions.VerifyRsaSha512PssAsync"/>, called directly with a 128-octet
        /// signature between 1 and n - 1, answers <see langword="false"/> and raises nothing.
        /// </summary>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [TestMethod]
        public async Task RsaPssAnswersFalseForAModulusTooSmallForTheEncoding()
        {
            BcBigInteger firstPrime = BcBigInteger.Three.ShiftLeft(510).NextProbablePrime();
            BcBigInteger secondPrime = BcBigInteger.Three.ShiftLeft(510).Add(BcBigInteger.ValueOf(1_000_000)).NextProbablePrime();
            BcBigInteger product = firstPrime.Multiply(secondPrime);
            Assert.AreEqual(1024, product.BitLength, "The modulus is 1024 bits.");
            Assert.IsTrue(RsaUtilities.IsValidPublicKey(product.ToByteArrayUnsigned(), RsaSignatureFixtures.DefaultPublicExponent.ToByteArrayUnsigned()), "The modulus and 65537 are a valid RSA public key.");

            byte[] presented = RsaSignatureFixtures.EncodeRsaPublicKey(product, RsaSignatureFixtures.DefaultPublicExponent);
            byte[] signature = Enumerable.Repeat((byte)0x01, 128).ToArray();

            bool isVerified = await VerifyRsaAsync("Sha512", "Pss", signature, presented).ConfigureAwait(false);

            Assert.IsFalse(isVerified, "A 1024-bit modulus does not verify through the Microsoft Pss verifier with SHA-512.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-8.1.2">RFC 8017 Section 8.1.2</see>
        /// (RSASSA-PSS-VERIFY) and <see href="https://www.rfc-editor.org/rfc/rfc8017#section-8.2.2">Section 8.2.2</see>
        /// (RSASSA-PKCS1-V1_5-VERIFY), step 1: "Length checking: If the length of the signature S is not k octets,
        /// output "invalid signature" and stop." A correct signature without its first octet (255 octets) or with a
        /// zero octet before it (257 octets) under a 2048-bit modulus is not k octets: the Microsoft RSASSA-PSS and
        /// RSASSA-PKCS1-v1_5 verifiers with SHA-256, called directly, answer <see langword="false"/> and raise nothing.
        /// </summary>
        /// <param name="scheme">The RSA signature scheme: <c>Pss</c> or <c>Pkcs1</c>.</param>
        /// <param name="length">The length of the presented signature, in octets.</param>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [TestMethod]
        [DataRow("Pss", 255)]
        [DataRow("Pss", 257)]
        [DataRow("Pkcs1", 255)]
        [DataRow("Pkcs1", 257)]
        public async Task RsaAnswersFalseForASignatureThatIsNotTheModulusLength(string scheme, int length)
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            using Signature signature = await SignRsaSha256Async(scheme, privateKey).ConfigureAwait(false);
            byte[] signatureOctets = signature.AsReadOnlySpan().ToArray();
            Assert.HasCount(256, signatureOctets);
            byte[] presented = length switch
            {
                255 => signatureOctets[1..],
                257 => [0x00, .. signatureOctets],
                _ => throw new ArgumentOutOfRangeException(nameof(length), length, "No such signature length.")
            };

            bool isVerified = await VerifyRsaAsync("Sha256", scheme, presented, publicKey.AsReadOnlyMemory()).ConfigureAwait(false);

            Assert.IsFalse(isVerified, $"A signature of {length} octets does not verify through the Microsoft {scheme} verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-5.2.2">RFC 8017 Section 5.2.2</see> (RSAVP1), step
        /// 1: "If the signature representative s is not between 0 and n - 1, output "signature representative out of
        /// range" and stop.", which both verification operations answer as "invalid signature". A signature whose
        /// value is the modulus itself, k octets, is out of that range: the Microsoft RSASSA-PSS and RSASSA-PKCS1-v1_5
        /// verifiers with SHA-256, called directly, answer <see langword="false"/> and raise nothing.
        /// </summary>
        /// <param name="scheme">The RSA signature scheme: <c>Pss</c> or <c>Pkcs1</c>.</param>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [TestMethod]
        [DataRow("Pss")]
        [DataRow("Pkcs1")]
        public async Task RsaAnswersFalseForASignatureNotBelowTheModulus(string scheme)
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            (System.Numerics.BigInteger modulus, System.Numerics.BigInteger _) = RsaSignatureFixtures.ReadRsaPublicKey(publicKey.AsReadOnlySpan().ToArray());
            byte[] presented = modulus.ToByteArray(isUnsigned: true, isBigEndian: true);
            Assert.HasCount(256, presented);

            bool isVerified = await VerifyRsaAsync("Sha256", scheme, presented, publicKey.AsReadOnlyMemory()).ConfigureAwait(false);

            Assert.IsFalse(isVerified, $"A signature equal to the modulus does not verify through the Microsoft {scheme} verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#appendix-A.1.1">RFC 8017 Appendix A.1.1</see> gives the
        /// RSAPublicKey, and this library also reads the bare modulus of a 2048-bit key pair under the exponent 65537, its
        /// own convention: a correct signature verifies through the Microsoft RSASSA-PSS and RSASSA-PKCS1-v1_5
        /// verifiers with SHA-256, called directly, under the DER RSAPublicKey and under the bare 256-octet modulus of
        /// the same public key.
        /// </summary>
        /// <param name="scheme">The RSA signature scheme: <c>Pss</c> or <c>Pkcs1</c>.</param>
        /// <param name="encoding">The public key's encoding: <c>der</c> or <c>bareModulus</c>.</param>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [TestMethod]
        [DataRow("Pss", "der")]
        [DataRow("Pss", "bareModulus")]
        [DataRow("Pkcs1", "der")]
        [DataRow("Pkcs1", "bareModulus")]
        public async Task RsaVerifiesUnderEitherEncodingOfThePublicKey(string scheme, string encoding)
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            using Signature signature = await SignRsaSha256Async(scheme, privateKey).ConfigureAwait(false);
            byte[] der = publicKey.AsReadOnlySpan().ToArray();
            (System.Numerics.BigInteger modulus, System.Numerics.BigInteger _) = RsaSignatureFixtures.ReadRsaPublicKey(der);
            byte[] presented = encoding switch
            {
                "der" => der,
                "bareModulus" => modulus.ToByteArray(isUnsigned: true, isBigEndian: true),
                _ => throw new ArgumentOutOfRangeException(nameof(encoding), encoding, "No such public key encoding.")
            };

            bool isVerified = await VerifyRsaAsync("Sha256", scheme, signature.AsReadOnlyMemory(), presented).ConfigureAwait(false);

            Assert.IsTrue(isVerified, $"A correct signature verifies under the {encoding} public key through the Microsoft {scheme} verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#appendix-A.1.1">RFC 8017 Appendix A.1.1</see>: "An RSA
        /// public key should be represented with the ASN.1 type RSAPublicKey:", the SEQUENCE of the INTEGERs
        /// <c>modulus</c> and <c>publicExponent</c>. Octets that are exactly a DER RSAPublicKey are that modulus and
        /// that exponent whatever their length, the first arm of the rule the class remarks of
        /// <see cref="MicrosoftCryptographicFunctions"/> state: the DER RSAPublicKey of a 1952-bit key pair under the
        /// exponent 65537 is 256 octets long, and a correct signature made under that key pair verifies through the
        /// Microsoft RSASSA-PSS and RSASSA-PKCS1-v1_5 verifiers with SHA-256, called directly under that DER.
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

            bool isVerified = await VerifyRsaAsync("Sha256", scheme, signature, presented).ConfigureAwait(false);

            Assert.IsTrue(isVerified, $"A correct signature verifies under a 256-octet DER RSAPublicKey through the Microsoft {scheme} verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-2">RFC 7518 Section 2</see>, Base64urlUInt: "The
        /// octet sequence MUST utilize the minimum number of octets needed to represent the value." A bare modulus is
        /// held to the minimum number of octets, so octets that are no DER RSAPublicKey and whose first octet is zero
        /// are no modulus under the second arm of the rule the class remarks of
        /// <see cref="MicrosoftCryptographicFunctions"/> state: the bare modulus of a 2048-bit key pair after one
        /// zero octet (257 octets) and the bare
        /// modulus of a 2040-bit key pair after one zero octet (256 octets), each with a correct signature made under
        /// that key pair, do not verify through the Microsoft RSASSA-PSS and RSASSA-PKCS1-v1_5 verifiers with SHA-256,
        /// called directly, which answer <see langword="false"/> and raise nothing.
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

            bool isVerified = await VerifyRsaAsync("Sha256", scheme, signature, presented).ConfigureAwait(false);

            Assert.IsFalse(isVerified, $"A bare modulus after a leading zero octet, {length} octets, does not verify through the Microsoft {scheme} verifier.");
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-3.1">RFC 8017 Section 3.1</see>: "For the purposes
        /// of this document, an RSA public key consists of two components:" the modulus n and the public exponent e.
        /// Exactly a DER RSAPublicKey is its modulus and exponent, and any other octets are the bare modulus they spell
        /// under the exponent 65537, the two arms of the rule the class remarks of
        /// <see cref="MicrosoftCryptographicFunctions"/> state: a correct signature made under a key pair verifies through the Microsoft
        /// RSASSA-PSS and RSASSA-PKCS1-v1_5 verifiers with SHA-256, called directly, under the DER RSAPublicKey of a
        /// 3072-bit key pair and under the bare 512-octet modulus of a 4096-bit key pair. The other forms are held by
        /// <see cref="RsaVerifiesUnderEitherEncodingOfThePublicKey"/> (2048 bits, both forms),
        /// <see cref="RsaVerifiesUnderTheBareModulusOfA3072BitKeyPair"/> and <see cref="Rsa4096SignatureVerifies"/>.
        /// </summary>
        /// <param name="scheme">The RSA signature scheme: <c>Pss</c> or <c>Pkcs1</c>.</param>
        /// <param name="modulusBitLength">The bit length of the key pair's modulus.</param>
        /// <param name="form">The public key's form: <c>der</c> or <c>bareModulus</c>.</param>
        /// <returns>A task that completes when the answer was asserted.</returns>
        [TestMethod]
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

            bool isVerified = await VerifyRsaAsync("Sha256", scheme, signature, presented).ConfigureAwait(false);

            Assert.IsTrue(isVerified, $"A correct signature verifies under the {form} of a {modulusBitLength}-bit key pair through the Microsoft {scheme} verifier.");
        }


        /// <summary>
        /// Signs <see cref="TestData"/> with the Microsoft ECDSA signing member of <paramref name="curve"/>.
        /// </summary>
        /// <param name="curve"><c>P256</c>, <c>P384</c>, <c>P521</c> or <c>Secp256k1</c>.</param>
        /// <param name="privateKey">The private key of the curve.</param>
        /// <returns>The signature, which the caller disposes.</returns>
        private async Task<Signature> SignEcdsaAsync(string curve, PrivateKeyMemory privateKey)
        {
            var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
            CancellationToken cancellationToken = TestContext.CancellationToken;
            (Signature signature, CryptoEvent? _) = curve switch
            {
                "P256" => await MicrosoftCryptographicFunctions.SignP256Async(privateKey.AsReadOnlyMemory(), TestData, BaseMemoryPool.Shared, timeProvider, cancellationToken: cancellationToken).ConfigureAwait(false),
                "P384" => await MicrosoftCryptographicFunctions.SignP384Async(privateKey.AsReadOnlyMemory(), TestData, BaseMemoryPool.Shared, timeProvider, cancellationToken: cancellationToken).ConfigureAwait(false),
                "P521" => await MicrosoftCryptographicFunctions.SignP521Async(privateKey.AsReadOnlyMemory(), TestData, BaseMemoryPool.Shared, timeProvider, cancellationToken: cancellationToken).ConfigureAwait(false),
                "Secp256k1" => await MicrosoftCryptographicFunctions.SignSecp256k1Async(privateKey.AsReadOnlyMemory(), TestData, BaseMemoryPool.Shared, timeProvider, cancellationToken: cancellationToken).ConfigureAwait(false),
                _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "No such curve.")
            };

            return signature;
        }


        /// <summary>
        /// Verifies a signature over <see cref="TestData"/> with the Microsoft ECDSA verification member of
        /// <paramref name="curve"/>, called directly.
        /// </summary>
        /// <param name="curve"><c>P256</c>, <c>P384</c>, <c>P521</c> or <c>Secp256k1</c>.</param>
        /// <param name="signature">The presented signature.</param>
        /// <param name="publicKeyMaterial">The presented public key octets.</param>
        /// <returns>The verifier's answer.</returns>
        private async Task<bool> VerifyEcdsaAsync(string curve, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial)
        {
            var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
            CancellationToken cancellationToken = TestContext.CancellationToken;
            (bool isVerified, CryptoEvent? _) = curve switch
            {
                "P256" => await MicrosoftCryptographicFunctions.VerifyP256Async(TestData, signature, publicKeyMaterial, timeProvider, cancellationToken: cancellationToken).ConfigureAwait(false),
                "P384" => await MicrosoftCryptographicFunctions.VerifyP384Async(TestData, signature, publicKeyMaterial, timeProvider, cancellationToken: cancellationToken).ConfigureAwait(false),
                "P521" => await MicrosoftCryptographicFunctions.VerifyP521Async(TestData, signature, publicKeyMaterial, timeProvider, cancellationToken: cancellationToken).ConfigureAwait(false),
                "Secp256k1" => await MicrosoftCryptographicFunctions.VerifySecp256k1Async(TestData, signature, publicKeyMaterial, timeProvider, cancellationToken: cancellationToken).ConfigureAwait(false),
                _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "No such curve.")
            };

            return isVerified;
        }


        /// <summary>
        /// Signs <see cref="TestData"/> under a fresh key pair of <paramref name="curve"/> and asserts that the
        /// signature verifies through the Microsoft verification member of the curve under the public key in
        /// <paramref name="encoding"/>.
        /// </summary>
        /// <param name="curve"><c>P256</c>, <c>P384</c>, <c>P521</c> or <c>Secp256k1</c>.</param>
        /// <param name="encoding"><c>compressed</c> or <c>uncompressed</c>.</param>
        /// <returns>A task that completes when the answer was asserted.</returns>
        private async Task AssertVerifiesUnderSec1EncodingAsync(string curve, string encoding)
        {
            var keys = curve switch
            {
                "P256" => MicrosoftKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared),
                "P384" => MicrosoftKeyMaterialCreator.CreateP384Keys(BaseMemoryPool.Shared),
                "P521" => MicrosoftKeyMaterialCreator.CreateP521Keys(BaseMemoryPool.Shared),
                "Secp256k1" => MicrosoftKeyMaterialCreator.CreateSecp256k1Keys(BaseMemoryPool.Shared),
                _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "No such curve.")
            };

            EllipticCurveTypes curveType = curve switch
            {
                "P256" => EllipticCurveTypes.P256,
                "P384" => EllipticCurveTypes.P384,
                "P521" => EllipticCurveTypes.P521,
                "Secp256k1" => EllipticCurveTypes.Secp256k1,
                _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "No such curve.")
            };

            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            using Signature signature = await SignEcdsaAsync(curve, privateKey).ConfigureAwait(false);
            byte[] compressed = publicKey.AsReadOnlySpan().ToArray();
            Assert.IsTrue(compressed[0] is 0x02 or 0x03, $"The {curve} public key is the compressed encoding.");
            byte[] presented = encoding switch
            {
                "compressed" => compressed,
                "uncompressed" => EllipticCurveUtilities.NormalizeToUncompressed(compressed, curveType),
                _ => throw new ArgumentOutOfRangeException(nameof(encoding), encoding, "No such SEC1 encoding.")
            };

            bool isVerified = await VerifyEcdsaAsync(curve, signature.AsReadOnlyMemory(), presented).ConfigureAwait(false);

            Assert.IsTrue(isVerified, $"A correct {curve} signature verifies under the {encoding} public key through the Microsoft verifier.");
        }


        /// <summary>Signs <see cref="TestData"/> with the Microsoft RSA signing member of <paramref name="scheme"/> and SHA-256.</summary>
        /// <param name="scheme"><c>Pss</c> for RSASSA-PSS or <c>Pkcs1</c> for RSASSA-PKCS1-v1_5.</param>
        /// <param name="privateKey">The RSA private key.</param>
        /// <returns>The signature, which the caller disposes.</returns>
        private async Task<Signature> SignRsaSha256Async(string scheme, PrivateKeyMemory privateKey)
        {
            var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
            CancellationToken cancellationToken = TestContext.CancellationToken;
            (Signature signature, CryptoEvent? _) = scheme switch
            {
                "Pss" => await MicrosoftCryptographicFunctions.SignRsaSha256PssAsync(privateKey.AsReadOnlyMemory(), TestData, BaseMemoryPool.Shared, timeProvider, cancellationToken: cancellationToken).ConfigureAwait(false),
                "Pkcs1" => await MicrosoftCryptographicFunctions.SignRsaSha256Pkcs1Async(privateKey.AsReadOnlyMemory(), TestData, BaseMemoryPool.Shared, timeProvider, cancellationToken: cancellationToken).ConfigureAwait(false),
                _ => throw new ArgumentOutOfRangeException(nameof(scheme), scheme, "No such RSA signature scheme.")
            };

            return signature;
        }


        /// <summary>
        /// Verifies a signature over <see cref="TestData"/> with the Microsoft RSA verification member of
        /// <paramref name="scheme"/> and <paramref name="digest"/>, called directly.
        /// </summary>
        /// <param name="digest"><c>Sha256</c> or <c>Sha512</c>.</param>
        /// <param name="scheme"><c>Pss</c> for RSASSA-PSS or <c>Pkcs1</c> for RSASSA-PKCS1-v1_5.</param>
        /// <param name="signature">The presented signature.</param>
        /// <param name="publicKeyMaterial">The presented public key octets.</param>
        /// <returns>The verifier's answer.</returns>
        private async Task<bool> VerifyRsaAsync(string digest, string scheme, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial)
        {
            var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
            CancellationToken cancellationToken = TestContext.CancellationToken;
            (bool isVerified, CryptoEvent? _) = (scheme, digest) switch
            {
                ("Pss", "Sha256") => await MicrosoftCryptographicFunctions.VerifyRsaSha256PssAsync(TestData, signature, publicKeyMaterial, timeProvider, cancellationToken: cancellationToken).ConfigureAwait(false),
                ("Pss", "Sha512") => await MicrosoftCryptographicFunctions.VerifyRsaSha512PssAsync(TestData, signature, publicKeyMaterial, timeProvider, cancellationToken: cancellationToken).ConfigureAwait(false),
                ("Pkcs1", "Sha256") => await MicrosoftCryptographicFunctions.VerifyRsaSha256Pkcs1Async(TestData, signature, publicKeyMaterial, timeProvider, cancellationToken: cancellationToken).ConfigureAwait(false),
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
    }
}
