using Microsoft.Extensions.Time.Testing;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using SimpleBase;
using System.Buffers;
using System.Formats.Asn1;
using System.Security.Cryptography;
using Verifiable.Apdu;
using Verifiable.Apdu.Lds;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.OAuth.Dpop;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// RSA conversions retain the supplied public exponent through JWK, COSE and multibase, and both
/// verification providers use that exponent. Invalid exponents are refused at the conversion boundary. A
/// bare modulus, which carries no exponent, means 65537 to both providers.
/// </summary>
[TestClass]
internal sealed class RsaPublicKeyConversionTests
{
    /// <summary>The runner's cancellation and diagnostic context.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// An exponent-three JWK verifies its own signature and refuses a valid exponent-65537 signature
    /// over the same message and modulus. The generator constrains both exponents to be invertible,
    /// so the negative signature comes from a second real private key, not from corrupt signature bytes.
    /// </summary>
    /// <param name="useMicrosoft">Whether to verify through the Microsoft provider rather than BouncyCastle.</param>
    [TestMethod]
    [DataRow(true, DisplayName = "Microsoft verifies the registered exponent")]
    [DataRow(false, DisplayName = "BouncyCastle verifies the registered exponent")]
    public async Task ExponentThreeJwkVerifiesOwnSignatureAndRefusesSameModulusWith65537(bool useMicrosoft)
    {
        RsaKeyPairGenerator generator = new();
        generator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(3 * 65537), new SecureRandom(), 2048, 80));
        AsymmetricCipherKeyPair pair = generator.GenerateKeyPair();
        RsaPrivateCrtKeyParameters generated = Assert.IsInstanceOfType<RsaPrivateCrtKeyParameters>(pair.Private);
        byte[] modulus = generated.Modulus.ToByteArrayUnsigned();
        byte[] privateThree = EncodePrivateKey(generated, 3);
        byte[] private65537 = EncodePrivateKey(generated, 65537);
        byte[] message = "RSA public exponents are part of the registered key."u8.ToArray();
        FakeTimeProvider clock = new(TestClock.CanonicalEpoch);

        try
        {
            Dictionary<string, string> jwk = new(StringComparer.Ordinal)
            {
                [WellKnownJwkMemberNames.Kty] = WellKnownKeyTypeValues.Rsa,
                [WellKnownJwkMemberNames.N] = TestSetup.Base64UrlEncoder(modulus),
                [WellKnownJwkMemberNames.E] = TestSetup.Base64UrlEncoder([0x03])
            };
            using PublicKeyMemory keyThree = DpopJwkUtilities.PublicKeyFromJwk(
                jwk, WellKnownJwaValues.Rs256, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);
            jwk[WellKnownJwkMemberNames.E] = RsaUtilities.DefaultExponent;
            using PublicKeyMemory key65537 = DpopJwkUtilities.PublicKeyFromJwk(
                jwk, WellKnownJwaValues.Rs256, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

            (Signature signatureThree, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.SignRsa2048Async(
                privateThree, message, BaseMemoryPool.Shared, clock, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            using Signature ownedThree = signatureThree;
            (Signature signature65537, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.SignRsa2048Async(
                private65537, message, BaseMemoryPool.Shared, clock, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            using Signature owned65537 = signature65537;

            Assert.IsTrue(await VerifyAsync(useMicrosoft, message, signatureThree, keyThree).ConfigureAwait(false),
                "The exponent-three key must verify its own signature after JWK import.");
            Assert.IsTrue(await VerifyAsync(useMicrosoft, message, signature65537, key65537).ConfigureAwait(false),
                "The negative control must be a valid signature under the same modulus and exponent 65537.");
            Assert.IsFalse(await VerifyAsync(useMicrosoft, message, signature65537, keyThree).ConfigureAwait(false),
                "A signature made with exponent 65537 must not verify under the registered exponent three.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateThree);
            CryptographicOperations.ZeroMemory(private65537);
        }
    }


    /// <summary>JWK import and export preserve both parameters and report the DER representation.</summary>
    /// <param name="modulusLength">The registered modulus width in octets.</param>
    /// <param name="exponent">The public exponent to retain.</param>
    [TestMethod]
    [DataRow(256, 3)]
    [DataRow(256, 17)]
    [DataRow(256, 65537)]
    [DataRow(512, 3)]
    [DataRow(512, 65537)]
    public void JwkRoundTripPreservesPublicExponent(int modulusLength, int exponent)
    {
        byte[] modulus = CreateModulus(modulusLength);
        byte[] exponentBytes = BigInteger.ValueOf(exponent).ToByteArrayUnsigned();
        Dictionary<string, object> jwk = CreateJwk(modulus, exponentBytes);
        (CryptoAlgorithm algorithm, Purpose purpose, EncodingScheme scheme, IMemoryOwner<byte> material) =
            CryptoFormatConversions.DefaultJwkToAlgorithmConverter(jwk, BaseMemoryPool.Shared, TestSetup.Base64UrlDecoder);
        using IMemoryOwner<byte> owner = material;

        Assert.AreEqual(modulusLength == 256 ? CryptoAlgorithm.Rsa2048 : CryptoAlgorithm.Rsa4096, algorithm);
        Assert.AreEqual(Purpose.Verification, purpose);
        Assert.AreEqual(EncodingScheme.Der, scheme);
        AssertDerParameters(owner.Memory, modulus, exponentBytes);

        JsonWebKey roundTripped = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            algorithm, purpose, owner.Memory.Span, TestSetup.Base64UrlEncoder);
        Assert.AreEqual((string)jwk[WellKnownJwkMemberNames.N], roundTripped.N);
        Assert.AreEqual((string)jwk[WellKnownJwkMemberNames.E], roundTripped.E);
    }


    /// <summary>
    /// A public key the library holds as a bare modulus converts to a JWK by the rule both providers read it by: the
    /// modulus with the exponent 65537, since a bare modulus carries none. A DER key keeps its own exponent
    /// (<see cref="JwkRoundTripPreservesPublicExponent"/>). A bare modulus after a leading zero octet is not written in
    /// its minimum number of octets and is refused, as the providers refuse it.
    /// </summary>
    [TestMethod]
    public void ABareModulusConvertsToAJwkUnder65537()
    {
        byte[] modulus = CreateModulus(256);
        JsonWebKey converted = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            CryptoAlgorithm.Rsa2048, Purpose.Verification, modulus, TestSetup.Base64UrlEncoder);

        Assert.AreEqual(TestSetup.Base64UrlEncoder(modulus), converted.N, "The JWK carries the modulus as held.");
        Assert.AreEqual(RsaUtilities.DefaultExponent, converted.E, "A bare modulus means 65537.");

        RsaPublicKeyException exception = Assert.ThrowsExactly<RsaPublicKeyException>(() =>
            CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
                CryptoAlgorithm.Rsa2048, Purpose.Verification, [0x00, .. modulus], TestSetup.Base64UrlEncoder));

        Assert.AreEqual(RsaPublicKeyFailureKind.MalformedEncoding, exception.FailureKind);
    }


    /// <summary>The RSA multicodec classifier uses modulus width, independently of exponent length.</summary>
    /// <param name="modulusLength">The registered modulus width in octets.</param>
    /// <param name="useBase64Url">Whether to carry the multicodec payload as base64url rather than base58btc.</param>
    [TestMethod]
    [DataRow(256, false)]
    [DataRow(256, true)]
    [DataRow(512, false)]
    [DataRow(512, true)]
    public void MultibaseRoundTripPreservesExponentThree(int modulusLength, bool useBase64Url)
    {
        byte[] modulus = CreateModulus(modulusLength);
        byte[] exponent = [0x03];
        byte[] der = EncodeDer(modulus, exponent);
        CryptoAlgorithm expected = modulusLength == 256 ? CryptoAlgorithm.Rsa2048 : CryptoAlgorithm.Rsa4096;
        string multibase = useBase64Url
            ? MultibaseSerializer.Encode(der, MulticodecHeaders.RsaPublicKey, MultibaseAlgorithms.Base64Url,
                TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared)
            : CryptoFormatConversions.DefaultAlgorithmToBase58Converter(
                expected, Purpose.Verification, der, Base58.Bitcoin.Encode, BaseMemoryPool.Shared);

        (CryptoAlgorithm algorithm, Purpose purpose, EncodingScheme scheme, IMemoryOwner<byte> material) =
            CryptoFormatConversions.DefaultBase58ToAlgorithmConverter(multibase, BaseMemoryPool.Shared, TestSetup.Base58Decoder);
        using IMemoryOwner<byte> owner = material;

        Assert.AreEqual(expected, algorithm);
        Assert.AreEqual(Purpose.Verification, purpose);
        Assert.AreEqual(EncodingScheme.Der, scheme);
        AssertDerParameters(owner.Memory, modulus, exponent);
    }


    /// <summary>COSE and JWK produce the same DER public key with exponent three.</summary>
    [TestMethod]
    public void CoseAndJwkPreserveTheSamePublicExponent()
    {
        byte[] modulus = CreateModulus(256);
        byte[] exponent = [0x03];
        CoseKey cose = new(CoseKeyTypes.Rsa, n: modulus, e: exponent);
        using PublicKeyMemory coseKey = cose.ToPublicKeyMemory(BaseMemoryPool.Shared);
        (CryptoAlgorithm _, Purpose _, EncodingScheme _, IMemoryOwner<byte> material) =
            CryptoFormatConversions.DefaultJwkToAlgorithmConverter(
                CreateJwk(modulus, exponent), BaseMemoryPool.Shared, TestSetup.Base64UrlDecoder);
        using IMemoryOwner<byte> owner = material;

        AssertDerParameters(coseKey.AsReadOnlyMemory(), modulus, exponent);
        Assert.IsTrue(coseKey.AsReadOnlySpan().SequenceEqual(owner.Memory.Span));
    }


    /// <summary>Every parameter conversion refuses a degenerate public exponent with its typed reason.</summary>
    /// <param name="exponentHex">The unsigned big-endian exponent; an empty string represents no octets.</param>
    [TestMethod]
    [DataRow("")]
    [DataRow("00")]
    [DataRow("01")]
    [DataRow("02")]
    [DataRow("04")]
    public void InvalidPublicExponentIsRefusedWithReason(string exponentHex)
    {
        byte[] modulus = CreateModulus(256);
        byte[] exponent = Convert.FromHexString(exponentHex);
        Dictionary<string, object> jwk = CreateJwk(modulus, exponent);

        //The conversion refuses before it rents any material, so nothing is left to dispose.
        RsaPublicKeyException fromJwk = Assert.ThrowsExactly<RsaPublicKeyException>(() =>
            CryptoFormatConversions.DefaultJwkToAlgorithmConverter(jwk, BaseMemoryPool.Shared, TestSetup.Base64UrlDecoder));
        Assert.AreEqual(RsaPublicKeyFailureKind.InvalidPublicExponent, fromJwk.FailureKind);

        //DER INTEGER cannot be empty: zero is its corresponding invalid integer value.
        byte[] der = EncodeDer(modulus, exponent.Length == 0 ? [0x00] : exponent);
        RsaPublicKeyException fromDer = Assert.ThrowsExactly<RsaPublicKeyException>(() => RsaPublicKeyEncoding.Decode(der));
        Assert.AreEqual(RsaPublicKeyFailureKind.InvalidPublicExponent, fromDer.FailureKind);

        CoseKey cose = new(CoseKeyTypes.Rsa, n: modulus, e: exponent);
        RsaPublicKeyException fromCose = Assert.ThrowsExactly<RsaPublicKeyException>(() =>
        {
            using PublicKeyMemory key = cose.ToPublicKeyMemory(BaseMemoryPool.Shared);
        });
        Assert.AreEqual(RsaPublicKeyFailureKind.InvalidPublicExponent, fromCose.FailureKind);
    }


    /// <summary>DG15 retains the complete RSA key and refuses an invalid exponent when the file is read.</summary>
    /// <param name="exponent">The exponent carried in the DG15 public key.</param>
    [TestMethod]
    [DataRow(3)]
    [DataRow(1)]
    public void DataGroup15ReadsTheSuppliedPublicExponent(int exponent)
    {
        byte[] modulus = CreateModulus(256);
        byte[] exponentBytes = BigInteger.ValueOf(exponent).ToByteArrayUnsigned();
        using RsaPublicKey key = RsaPublicKey.FromBytes(EncodeDer(modulus, exponentBytes), BaseMemoryPool.Shared);
        using ElementaryFile file = DataGroup15.Write(key, BaseMemoryPool.Shared);

        if(exponent == 3)
        {
            using DataGroup15 parsed = DataGroup15.Parse(file.AsReadOnlySpan(), BaseMemoryPool.Shared);
            AssertDerParameters(parsed.RsaPublicKey.AsReadOnlyMemory(), modulus, exponentBytes);
        }
        else
        {
            RsaPublicKeyException exception = Assert.ThrowsExactly<RsaPublicKeyException>(() =>
            {
                using DataGroup15 parsed = DataGroup15.Parse(file.AsReadOnlySpan(), BaseMemoryPool.Shared);
            });
            Assert.AreEqual(RsaPublicKeyFailureKind.InvalidPublicExponent, exception.FailureKind);
        }
    }


    /// <summary>The upper exponent bound is strict, including when the exponent has more octets than the modulus.</summary>
    /// <param name="largerThanModulus">Whether to use a larger exponent instead of exactly the modulus.</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public void PublicExponentAtOrAboveModulusIsRefused(bool largerThanModulus)
    {
        byte[] modulus = CreateModulus(256);
        byte[] exponent = largerThanModulus ? [0x01, .. modulus] : modulus;
        RsaPublicKeyException exception = Assert.ThrowsExactly<RsaPublicKeyException>(() =>
            RsaPublicKeyEncoding.Encode(modulus, exponent));

        Assert.AreEqual(RsaPublicKeyFailureKind.InvalidPublicExponent, exception.FailureKind);
    }


    /// <summary>Signed DER exponents are validated before conversion to unsigned magnitudes.</summary>
    [TestMethod]
    public void NegativeDerPublicExponentIsRefusedWithReason()
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteIntegerUnsigned(CreateModulus(256));
            writer.WriteInteger(-3);
        }

        RsaPublicKeyException exception = Assert.ThrowsExactly<RsaPublicKeyException>(() =>
            RsaPublicKeyEncoding.Decode(writer.Encode()));

        Assert.AreEqual(RsaPublicKeyFailureKind.InvalidPublicExponent, exception.FailureKind);
    }


    /// <summary>A DER public key must contain exactly the two RSA parameters and no trailing data.</summary>
    /// <param name="insideSequence">Whether the trailing value is inside the sequence or after it.</param>
    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public void DerWithExtraValueIsRefused(bool insideSequence)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteIntegerUnsigned(CreateModulus(256));
            writer.WriteInteger(3);
            if(insideSequence)
            {
                writer.WriteInteger(65537);
            }
        }

        if(!insideSequence)
        {
            writer.WriteInteger(65537);
        }

        RsaPublicKeyException exception = Assert.ThrowsExactly<RsaPublicKeyException>(() =>
            RsaPublicKeyEncoding.Decode(writer.Encode()));

        Assert.AreEqual(RsaPublicKeyFailureKind.MalformedEncoding, exception.FailureKind);
    }


    /// <summary>
    /// Both providers answer a DER public key whose exponent is no valid RSA public exponent as not verified, raising
    /// nothing: a verify body answers presented key octets as a value, and RFC 8017 Section 3.1 holds the exponent to
    /// an odd value with 3 &lt;= e &lt; n before anything is imported.
    /// </summary>
    /// <param name="useMicrosoft">The provider to exercise.</param>
    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public async Task InvalidDerExponentIsRefusedByBothProviders(bool useMicrosoft)
    {
        byte[] modulus = CreateModulus(256);
        byte[] der = EncodeDer(modulus, [0x01]);

        Assert.IsFalse(await VerifyOctetsAsync(useMicrosoft, [], modulus, der).ConfigureAwait(false),
            "A DER public key carrying the exponent one is no RSA public key, so nothing verifies under it.");
    }


    /// <summary>
    /// One rule reads an RSA public key on both providers: a DER <c>RSAPublicKey</c> keeps the exponent it carries,
    /// which is never replaced by 65537, and a bare modulus, which carries none, means 65537. Over one modulus whose
    /// primes admit both exponents, the DER key of exponent three verifies the exponent-three signature and not the
    /// 65537 one, and the bare modulus verifies the 65537 signature and not the exponent-three one, so each half fails
    /// under the other reading.
    /// </summary>
    /// <param name="useMicrosoft">The provider to exercise.</param>
    [TestMethod]
    [DataRow(true, DisplayName = "Microsoft keeps a carried exponent and reads a bare modulus under 65537")]
    [DataRow(false, DisplayName = "BouncyCastle keeps a carried exponent and reads a bare modulus under 65537")]
    public async Task ACarriedExponentIsKeptAndABareModulusMeans65537(bool useMicrosoft)
    {
        RsaKeyPairGenerator generator = new();
        generator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(3 * 65537), new SecureRandom(), 2048, 80));
        AsymmetricCipherKeyPair pair = generator.GenerateKeyPair();
        RsaPrivateCrtKeyParameters generated = Assert.IsInstanceOfType<RsaPrivateCrtKeyParameters>(pair.Private);
        byte[] modulus = generated.Modulus.ToByteArrayUnsigned();
        byte[] carriedThree = EncodeDer(modulus, [0x03]);
        byte[] privateThree = EncodePrivateKey(generated, 3);
        byte[] private65537 = EncodePrivateKey(generated, 65537);
        byte[] message = "A bare modulus carries no exponent of its own."u8.ToArray();
        FakeTimeProvider clock = new(TestClock.CanonicalEpoch);

        try
        {
            (Signature signatureThree, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.SignRsa2048Async(
                privateThree, message, BaseMemoryPool.Shared, clock, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            using Signature ownedThree = signatureThree;
            (Signature signature65537, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.SignRsa2048Async(
                private65537, message, BaseMemoryPool.Shared, clock, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            using Signature owned65537 = signature65537;
            byte[] three = signatureThree.AsReadOnlyMemory().ToArray();
            byte[] sixtyFiveThousand = signature65537.AsReadOnlyMemory().ToArray();

            Assert.IsTrue(await VerifyOctetsAsync(useMicrosoft, message, three, carriedThree).ConfigureAwait(false),
                "The DER key keeps the exponent three it carries.");
            Assert.IsFalse(await VerifyOctetsAsync(useMicrosoft, message, sixtyFiveThousand, carriedThree).ConfigureAwait(false),
                "The exponent the DER key carries is never replaced by 65537.");
            Assert.IsTrue(await VerifyOctetsAsync(useMicrosoft, message, sixtyFiveThousand, modulus).ConfigureAwait(false),
                "A bare modulus means 65537.");
            Assert.IsFalse(await VerifyOctetsAsync(useMicrosoft, message, three, modulus).ConfigureAwait(false),
                "A bare modulus is no key of the exponent three.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateThree);
            CryptographicOperations.ZeroMemory(private65537);
        }
    }


    /// <summary>Verifies a signature over presented public key octets through the selected provider.</summary>
    /// <param name="useMicrosoft">Whether to verify through the Microsoft provider rather than BouncyCastle.</param>
    /// <param name="message">The signed message.</param>
    /// <param name="signature">The signature octets.</param>
    /// <param name="publicKey">The public key octets as presented.</param>
    /// <returns>Whether the provider verified the signature.</returns>
    private async Task<bool> VerifyOctetsAsync(bool useMicrosoft, byte[] message, byte[] signature, byte[] publicKey)
    {
        FakeTimeProvider clock = new(TestClock.CanonicalEpoch);
        (bool verified, CryptoEvent? _) = useMicrosoft
            ? await MicrosoftCryptographicFunctions.VerifyRsa2048Async(
                message, signature, publicKey, clock, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false)
            : await BouncyCastleCryptographicFunctions.VerifyRsa2048Async(
                message, signature, publicKey, clock, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return verified;
    }


    /// <summary>Verifies a signature through the selected provider without changing global registry state.</summary>
    private async Task<bool> VerifyAsync(bool useMicrosoft, ReadOnlyMemory<byte> message, Signature signature, PublicKeyMemory key)
    {
        FakeTimeProvider clock = new(TestClock.CanonicalEpoch);
        (bool verified, CryptoEvent? _) = useMicrosoft
            ? await MicrosoftCryptographicFunctions.VerifyRsa2048Async(
                message, signature.AsReadOnlyMemory(), key.AsReadOnlyMemory(), clock,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false)
            : await BouncyCastleCryptographicFunctions.VerifyRsa2048Async(
                message, signature.AsReadOnlyMemory(), key.AsReadOnlyMemory(), clock,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return verified;
    }


    /// <summary>Builds a private key for the requested exponent over the fixture's same two primes.</summary>
    private static byte[] EncodePrivateKey(RsaPrivateCrtKeyParameters key, int exponent)
    {
        BigInteger e = BigInteger.ValueOf(exponent);
        BigInteger pMinusOne = key.P.Subtract(BigInteger.One);
        BigInteger qMinusOne = key.Q.Subtract(BigInteger.One);
        BigInteger d = e.ModInverse(pMinusOne.Multiply(qMinusOne));
        RsaPrivateKeyStructure privateKey = new(key.Modulus, e, d, key.P, key.Q,
            d.Mod(pMinusOne), d.Mod(qMinusOne), key.Q.ModInverse(key.P));

        return privateKey.GetDerEncoded();
    }


    /// <summary>Creates an odd, full-width modulus for encoding tests that perform no RSA operation.</summary>
    private static byte[] CreateModulus(int length)
    {
        byte[] modulus = new byte[length];
        modulus[0] = 0x80;
        modulus[^1] = 0x01;

        return modulus;
    }


    /// <summary>Builds the mandatory RSA JWK members directly from the supplied parameters.</summary>
    private static Dictionary<string, object> CreateJwk(byte[] modulus, byte[] exponent) => new(StringComparer.Ordinal)
    {
        [WellKnownJwkMemberNames.Kty] = WellKnownKeyTypeValues.Rsa,
        [WellKnownJwkMemberNames.N] = TestSetup.Base64UrlEncoder(modulus),
        [WellKnownJwkMemberNames.E] = TestSetup.Base64UrlEncoder(exponent)
    };


    /// <summary>Encodes fixture parameters independently of the production conversion, including invalid exponents.</summary>
    private static byte[] EncodeDer(byte[] modulus, byte[] exponent)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteIntegerUnsigned(modulus);
            writer.WriteIntegerUnsigned(exponent);
        }

        return writer.Encode();
    }


    /// <summary>Reads both DER integers independently and checks that the whole input was consumed.</summary>
    private static void AssertDerParameters(ReadOnlyMemory<byte> der, byte[] modulus, byte[] exponent)
    {
        AsnReader reader = new(der, AsnEncodingRules.DER);
        AsnReader sequence = reader.ReadSequence();
        byte[] actualModulus = sequence.ReadInteger().ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] actualExponent = sequence.ReadInteger().ToByteArray(isUnsigned: true, isBigEndian: true);

        Assert.AreSequenceEqual(modulus, actualModulus);
        Assert.AreSequenceEqual(exponent, actualExponent);
        Assert.IsFalse(sequence.HasData);
        Assert.IsFalse(reader.HasData);
    }
}
