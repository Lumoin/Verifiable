using System.Buffers;
using System.Formats.Asn1;
using System.Text;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Tests for the RFC 8230 §4 RSA support added to <see cref="CoseKey"/> and
/// <see cref="CoseKeyExtensions.ToPublicKeyMemory"/>: the <c>n</c> (label -1)
/// and <c>e</c> (label -2) parameters, their DER PKCS#1 <c>RSAPublicKey</c>
/// encoding, and the accompanying COSE algorithm plumbing in
/// <see cref="WellKnownCoseAlgorithms"/> and <see cref="CryptoFormatConversions"/>.
/// </summary>
/// <remarks>
/// <para>
/// No CBOR reader is exercised here — the CBOR layer is being replaced, so
/// every <see cref="CoseKey"/> under test is constructed directly from its
/// parsed parameters. RSA key material is minted independently through
/// <see cref="BouncyCastleKeyMaterialCreator"/> (and, for the non-default
/// exponent case, BouncyCastle's low-level RSA generator directly) so the
/// verifier side reconstructs its key ONLY from the <see cref="CoseKey"/>
/// wire fields — never by sharing a BouncyCastle key object across the
/// issuer/verifier firewall.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CoseKeyRsaTests
{
    /// <summary>The <see cref="TestContext"/> MSTest injects for cancellation and diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The payload signed and verified across the sign/verify tests in this class.</summary>
    private static byte[] TestData { get; } = Encoding.UTF8.GetBytes("Verifiable.JCose RSA CoseKey test payload.");

    /// <summary>
    /// The default RSA public exponent, 65537 (0x010001), per RFC 8230 §4 / did:key convention.
    /// Internal rather than private: shared with <see cref="CoseKeyRsaPropertyTests"/>.
    /// </summary>
    internal static ReadOnlyMemory<byte> DefaultPublicExponent { get; } = new byte[] { 0x01, 0x00, 0x01 };


    /// <summary>
    /// A <see cref="CoseKey"/> built from an independently minted RSA-2048 public key's wire
    /// <c>n</c>/<c>e</c> fields converts to a <see cref="PublicKeyMemory"/> tagged
    /// <see cref="CryptoTags.Rsa2048PublicKey"/>.
    /// </summary>
    [TestMethod]
    public void Rsa2048CoseKeyProducesRsa2048TaggedPublicKey()
    {
        var keys = BouncyCastleKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
        using PublicKeyMemory bcPublicKey = keys.PublicKey;
        using PrivateKeyMemory bcPrivateKey = keys.PrivateKey;

        (ReadOnlyMemory<byte> modulus, ReadOnlyMemory<byte> exponent) = ExtractRsaPublicKeyComponents(bcPublicKey.AsReadOnlyMemory());
        CoseKey coseKey = new(kty: CoseKeyTypes.Rsa, n: modulus, e: exponent);

        using PublicKeyMemory reconstructed = coseKey.ToPublicKeyMemory(BaseMemoryPool.Shared);

        Assert.AreEqual(CryptoTags.Rsa2048PublicKey, reconstructed.Tag);
    }


    /// <summary>
    /// A verifier that reconstructs its public key ONLY from a <see cref="CoseKey"/>'s <c>n</c>/<c>e</c>
    /// fields verifies a signature produced by the independently minted BouncyCastle private key
    /// (RS256 = PKCS#1 v1.5 with SHA-256).
    /// </summary>
    [TestMethod]
    public async Task Rsa2048CoseKeyVerifiesIndependentlyMintedSignature()
    {
        var keys = BouncyCastleKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
        using PublicKeyMemory bcPublicKey = keys.PublicKey;
        using PrivateKeyMemory bcPrivateKey = keys.PrivateKey;

        (ReadOnlyMemory<byte> modulus, ReadOnlyMemory<byte> exponent) = ExtractRsaPublicKeyComponents(bcPublicKey.AsReadOnlyMemory());
        CoseKey coseKey = new(kty: CoseKeyTypes.Rsa, n: modulus, e: exponent);
        PublicKeyMemory reconstructed = coseKey.ToPublicKeyMemory(BaseMemoryPool.Shared);

        (Signature signature, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.SignRsa2048Async(
            bcPrivateKey.AsReadOnlyMemory(), TestData, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using var disposableSignature = signature;

        using PublicKey verifierKey = CryptographicKeyFactory.CreatePublicKey(
            reconstructed, "test-rsa2048-cosekey", reconstructed.Tag);

        bool isValid = await verifierKey.VerifyAsync(TestData, signature).ConfigureAwait(false);

        Assert.IsTrue(isValid);
    }


    /// <summary>
    /// The negative twin of <see cref="Rsa2048CoseKeyVerifiesIndependentlyMintedSignature"/>: a
    /// signature valid over the original payload must not verify against a tampered payload.
    /// </summary>
    [TestMethod]
    public async Task Rsa2048CoseKeyRejectsSignatureOverTamperedPayload()
    {
        var keys = BouncyCastleKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
        using PublicKeyMemory bcPublicKey = keys.PublicKey;
        using PrivateKeyMemory bcPrivateKey = keys.PrivateKey;

        (ReadOnlyMemory<byte> modulus, ReadOnlyMemory<byte> exponent) = ExtractRsaPublicKeyComponents(bcPublicKey.AsReadOnlyMemory());
        CoseKey coseKey = new(kty: CoseKeyTypes.Rsa, n: modulus, e: exponent);
        PublicKeyMemory reconstructed = coseKey.ToPublicKeyMemory(BaseMemoryPool.Shared);

        (Signature signature, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.SignRsa2048Async(
            bcPrivateKey.AsReadOnlyMemory(), TestData, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using var disposableSignature = signature;

        using PublicKey verifierKey = CryptographicKeyFactory.CreatePublicKey(
            reconstructed, "test-rsa2048-cosekey", reconstructed.Tag);

        byte[] tamperedPayload = [.. TestData];
        tamperedPayload[0] ^= 0xFF;

        bool isValid = await verifierKey.VerifyAsync(tamperedPayload, signature).ConfigureAwait(false);

        Assert.IsFalse(isValid);
    }


    /// <summary>
    /// The RSA-4096 analog of <see cref="Rsa2048CoseKeyProducesRsa2048TaggedPublicKey"/>: the
    /// larger modulus length routes to <see cref="CryptoTags.Rsa4096PublicKey"/>.
    /// </summary>
    [TestMethod]
    public void Rsa4096CoseKeyProducesRsa4096TaggedPublicKey()
    {
        var keys = BouncyCastleKeyMaterialCreator.CreateRsa4096Keys(BaseMemoryPool.Shared);
        using PublicKeyMemory bcPublicKey = keys.PublicKey;
        using PrivateKeyMemory bcPrivateKey = keys.PrivateKey;

        (ReadOnlyMemory<byte> modulus, ReadOnlyMemory<byte> exponent) = ExtractRsaPublicKeyComponents(bcPublicKey.AsReadOnlyMemory());
        CoseKey coseKey = new(kty: CoseKeyTypes.Rsa, n: modulus, e: exponent);

        using PublicKeyMemory reconstructed = coseKey.ToPublicKeyMemory(BaseMemoryPool.Shared);

        Assert.AreEqual(CryptoTags.Rsa4096PublicKey, reconstructed.Tag);
    }


    /// <summary>
    /// The RSA-4096 analog of <see cref="Rsa2048CoseKeyVerifiesIndependentlyMintedSignature"/>.
    /// </summary>
    [TestMethod]
    public async Task Rsa4096CoseKeyVerifiesIndependentlyMintedSignature()
    {
        var keys = BouncyCastleKeyMaterialCreator.CreateRsa4096Keys(BaseMemoryPool.Shared);
        using PublicKeyMemory bcPublicKey = keys.PublicKey;
        using PrivateKeyMemory bcPrivateKey = keys.PrivateKey;

        (ReadOnlyMemory<byte> modulus, ReadOnlyMemory<byte> exponent) = ExtractRsaPublicKeyComponents(bcPublicKey.AsReadOnlyMemory());
        CoseKey coseKey = new(kty: CoseKeyTypes.Rsa, n: modulus, e: exponent);
        PublicKeyMemory reconstructed = coseKey.ToPublicKeyMemory(BaseMemoryPool.Shared);

        (Signature signature, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.SignRsa4096Async(
            bcPrivateKey.AsReadOnlyMemory(), TestData, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using var disposableSignature = signature;

        using PublicKey verifierKey = CryptographicKeyFactory.CreatePublicKey(
            reconstructed, "test-rsa4096-cosekey", reconstructed.Tag);

        bool isValid = await verifierKey.VerifyAsync(TestData, signature).ConfigureAwait(false);

        Assert.IsTrue(isValid);
    }


    /// <summary>
    /// A non-default public exponent (3, rather than the framework's hardcoded 65537) survives the
    /// round trip through <see cref="CoseKey"/> and <see cref="CoseKeyExtensions.ToPublicKeyMemory"/>.
    /// This proves the DER PKCS#1 encoder carries the actual <c>e</c> rather than silently falling
    /// back to a raw-modulus import path that would hardcode 65537.
    /// </summary>
    [TestMethod]
    public async Task NonDefaultExponentSurvivesKeyBuild()
    {
        var minted = MintRsaKeyPairWithExponent(BigInteger.ValueOf(3));
        using IMemoryOwner<byte> privateKeyDer = minted.PrivateKeyDer;

        CoseKey coseKey = new(kty: CoseKeyTypes.Rsa, n: minted.Modulus, e: minted.Exponent);
        PublicKeyMemory reconstructed = coseKey.ToPublicKeyMemory(BaseMemoryPool.Shared);

        Assert.AreEqual(CryptoTags.Rsa2048PublicKey, reconstructed.Tag);

        (Signature signature, CryptoEvent? _) = await BouncyCastleCryptographicFunctions.SignRsa2048Async(
            privateKeyDer.Memory, TestData, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using var disposableSignature = signature;

        using PublicKey verifierKey = CryptographicKeyFactory.CreatePublicKey(
            reconstructed, "test-rsa2048-custom-exponent", reconstructed.Tag);

        bool isValid = await verifierKey.VerifyAsync(TestData, signature).ConfigureAwait(false);

        Assert.IsTrue(isValid);


        //Mints an RSA-2048 key pair directly through BouncyCastle's low-level generator with a
        //caller-chosen public exponent, bypassing BouncyCastleKeyMaterialCreator (which hardcodes
        //the F4/65537 exponent). Only this single test needs a non-default exponent, so the
        //generator stays local rather than becoming a class-level helper.
        static (ReadOnlyMemory<byte> Modulus, ReadOnlyMemory<byte> Exponent, IMemoryOwner<byte> PrivateKeyDer) MintRsaKeyPairWithExponent(BigInteger publicExponent)
        {
            var generator = new RsaKeyPairGenerator();
            generator.Init(new RsaKeyGenerationParameters(publicExponent, new SecureRandom(), 2048, 25));

            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
            var publicKeyParam = (RsaKeyParameters)keyPair.Public;
            var privateKeyParam = (RsaPrivateCrtKeyParameters)keyPair.Private;

            byte[] modulus = publicKeyParam.Modulus.ToByteArrayUnsigned();
            byte[] exponent = publicKeyParam.Exponent.ToByteArrayUnsigned();

            byte[] privateKeyDer = RsaPrivateKeyStructure.GetInstance(new RsaPrivateKeyStructure(
                privateKeyParam.Modulus,
                privateKeyParam.PublicExponent,
                privateKeyParam.Exponent,
                privateKeyParam.P,
                privateKeyParam.Q,
                privateKeyParam.DP,
                privateKeyParam.DQ,
                privateKeyParam.QInv)).GetDerEncoded();

            IMemoryOwner<byte> privateKeyOwner = BaseMemoryPool.Shared.Rent(privateKeyDer.Length);
            privateKeyDer.CopyTo(privateKeyOwner.Memory.Span);
            Array.Clear(privateKeyDer, 0, privateKeyDer.Length);

            return (modulus, exponent, privateKeyOwner);
        }
    }


    /// <summary>
    /// A modulus length outside the two registered RSA key sizes (256 / 512 bytes) is rejected —
    /// here an RSA-1024 modulus (128 bytes) — rather than silently accepted under a guessed tag.
    /// </summary>
    [TestMethod]
    public void UnsupportedModulusLengthIsRejected()
    {
        byte[] modulus = new byte[128];
        modulus[0] = 0x80;
        CoseKey coseKey = new(kty: CoseKeyTypes.Rsa, n: modulus, e: DefaultPublicExponent);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
            coseKey.ToPublicKeyMemory(BaseMemoryPool.Shared));

        Assert.Contains("128", exception.Message);
    }


    /// <summary>
    /// An RSA <see cref="CoseKey"/> carrying a modulus but no public exponent is rejected — a public
    /// key cannot be reconstructed without both RFC 8230 §4 labels present.
    /// </summary>
    [TestMethod]
    public void RsaCoseKeyWithoutExponentIsRejected()
    {
        byte[] modulus = new byte[256];
        modulus[0] = 0x80;
        CoseKey coseKey = new(kty: CoseKeyTypes.Rsa, n: modulus);

        Assert.ThrowsExactly<ArgumentException>(() =>
            coseKey.ToPublicKeyMemory(BaseMemoryPool.Shared));
    }


    /// <summary>
    /// An RSA <see cref="CoseKey"/> carrying a public exponent but no modulus is rejected.
    /// </summary>
    [TestMethod]
    public void RsaCoseKeyWithoutModulusIsRejected()
    {
        CoseKey coseKey = new(kty: CoseKeyTypes.Rsa, e: DefaultPublicExponent);

        Assert.ThrowsExactly<ArgumentException>(() =>
            coseKey.ToPublicKeyMemory(BaseMemoryPool.Shared));
    }


    /// <summary>
    /// <see cref="CryptoFormatConversions.CoseAlgorithmToCryptoAlgorithm"/> maps every COSE
    /// algorithm identifier it recognises to the corresponding <see cref="CryptoAlgorithm"/>.
    /// </summary>
    [TestMethod]
    public void CoseAlgorithmToCryptoAlgorithmMapsRegisteredAlgorithms()
    {
        Assert.AreEqual(CryptoAlgorithm.P256, CryptoFormatConversions.CoseAlgorithmToCryptoAlgorithm(WellKnownCoseAlgorithms.Es256));
        Assert.AreEqual(CryptoAlgorithm.P384, CryptoFormatConversions.CoseAlgorithmToCryptoAlgorithm(WellKnownCoseAlgorithms.Es384));
        Assert.AreEqual(CryptoAlgorithm.P521, CryptoFormatConversions.CoseAlgorithmToCryptoAlgorithm(WellKnownCoseAlgorithms.Es512));
        Assert.AreEqual(CryptoAlgorithm.RsaSha256, CryptoFormatConversions.CoseAlgorithmToCryptoAlgorithm(WellKnownCoseAlgorithms.Rs256));
        Assert.AreEqual(CryptoAlgorithm.RsaSha256Pss, CryptoFormatConversions.CoseAlgorithmToCryptoAlgorithm(WellKnownCoseAlgorithms.Ps256));
        Assert.AreEqual(CryptoAlgorithm.RsaSha512, CryptoFormatConversions.CoseAlgorithmToCryptoAlgorithm(WellKnownCoseAlgorithms.Rs512));
        Assert.AreEqual(CryptoAlgorithm.RsaSha512Pss, CryptoFormatConversions.CoseAlgorithmToCryptoAlgorithm(WellKnownCoseAlgorithms.Ps512));
        Assert.AreEqual(CryptoAlgorithm.Ed25519, CryptoFormatConversions.CoseAlgorithmToCryptoAlgorithm(WellKnownCoseAlgorithms.EdDsa));
    }


    /// <summary>
    /// <see cref="CryptoFormatConversions.CoseAlgorithmToCryptoAlgorithm"/> returns <see langword="null"/>
    /// for COSE algorithm identifiers it does not map, rather than throwing or guessing.
    /// </summary>
    [TestMethod]
    public void CoseAlgorithmToCryptoAlgorithmReturnsNullForUnregisteredAlgorithms()
    {
        Assert.IsNull(CryptoFormatConversions.CoseAlgorithmToCryptoAlgorithm(0));
        Assert.IsNull(CryptoFormatConversions.CoseAlgorithmToCryptoAlgorithm(1));
        Assert.IsNull(CryptoFormatConversions.CoseAlgorithmToCryptoAlgorithm(-999));
    }


    /// <summary>
    /// <see cref="CryptoFormatConversions.DefaultCoseToTagConverter"/> maps the RSA PKCS#1 v1.5
    /// signing algorithms (RS256/384/512) to <see cref="CryptoTags.Rsa2048PrivateKey"/>, mirroring
    /// the RSA PSS arms for the same purpose.
    /// </summary>
    [TestMethod]
    public void DefaultCoseToTagConverterMapsRsaPkcs1SigningToRsaPrivateKeyTags()
    {
        Tag rs256Tag = CryptoFormatConversions.DefaultCoseToTagConverter(WellKnownCoseAlgorithms.Rs256, Purpose.Signing);
        Tag rs384Tag = CryptoFormatConversions.DefaultCoseToTagConverter(WellKnownCoseAlgorithms.Rs384, Purpose.Signing);
        Tag rs512Tag = CryptoFormatConversions.DefaultCoseToTagConverter(WellKnownCoseAlgorithms.Rs512, Purpose.Signing);

        Assert.AreEqual(CryptoTags.Rsa2048PrivateKey, rs256Tag);
        Assert.AreEqual(CryptoTags.Rsa2048PrivateKey, rs384Tag);
        Assert.AreEqual(CryptoTags.Rsa2048PrivateKey, rs512Tag);
    }


    /// <summary>
    /// <see cref="CryptoFormatConversions.DefaultCoseToTagConverter"/> maps the RSA PKCS#1 v1.5
    /// verification algorithms (RS256/384/512) to <see cref="CryptoTags.Rsa2048PublicKey"/>.
    /// </summary>
    [TestMethod]
    public void DefaultCoseToTagConverterMapsRsaPkcs1VerificationToRsaPublicKeyTags()
    {
        Tag rs256Tag = CryptoFormatConversions.DefaultCoseToTagConverter(WellKnownCoseAlgorithms.Rs256, Purpose.Verification);
        Tag rs384Tag = CryptoFormatConversions.DefaultCoseToTagConverter(WellKnownCoseAlgorithms.Rs384, Purpose.Verification);
        Tag rs512Tag = CryptoFormatConversions.DefaultCoseToTagConverter(WellKnownCoseAlgorithms.Rs512, Purpose.Verification);

        Assert.AreEqual(CryptoTags.Rsa2048PublicKey, rs256Tag);
        Assert.AreEqual(CryptoTags.Rsa2048PublicKey, rs384Tag);
        Assert.AreEqual(CryptoTags.Rsa2048PublicKey, rs512Tag);
    }


    /// <summary>
    /// The <c>IsRs256</c>/<c>IsRs384</c>/<c>IsRs512</c> predicates each identify only their own
    /// algorithm identifier, mirroring the truth-table coverage the ESP/ESB predicates carry.
    /// </summary>
    [TestMethod]
    public void IsRsHelpersIdentifyOnlyTheirOwnVariant()
    {
        Assert.IsTrue(WellKnownCoseAlgorithms.IsRs256(WellKnownCoseAlgorithms.Rs256));
        Assert.IsTrue(WellKnownCoseAlgorithms.IsRs384(WellKnownCoseAlgorithms.Rs384));
        Assert.IsTrue(WellKnownCoseAlgorithms.IsRs512(WellKnownCoseAlgorithms.Rs512));

        Assert.IsFalse(WellKnownCoseAlgorithms.IsRs256(WellKnownCoseAlgorithms.Rs384));
        Assert.IsFalse(WellKnownCoseAlgorithms.IsRs384(WellKnownCoseAlgorithms.Rs512));
        Assert.IsFalse(WellKnownCoseAlgorithms.IsRs512(WellKnownCoseAlgorithms.Rs256));

        //Cross-check: RSA PSS (Ps256) must not satisfy the RSA PKCS#1 (Rs*) helpers.
        Assert.IsFalse(WellKnownCoseAlgorithms.IsRs256(WellKnownCoseAlgorithms.Ps256));
    }


    /// <summary>
    /// Extracts the modulus and public exponent from a DER PKCS#1 <c>RSAPublicKey ::= SEQUENCE
    /// { modulus INTEGER, publicExponent INTEGER }</c> — the wire shape
    /// <see cref="BouncyCastleKeyMaterialCreator"/> emits for RSA public keys — so the wire fields
    /// can be fed into a fresh <see cref="CoseKey"/> without ever sharing the BouncyCastle key
    /// object itself across the issuer/verifier firewall.
    /// </summary>
    /// <param name="derEncodedPublicKey">The DER-encoded PKCS#1 RSA public key.</param>
    /// <returns>The unsigned big-endian modulus and public exponent.</returns>
    private static (ReadOnlyMemory<byte> Modulus, ReadOnlyMemory<byte> Exponent) ExtractRsaPublicKeyComponents(ReadOnlyMemory<byte> derEncodedPublicKey)
    {
        AsnReader sequence = new AsnReader(derEncodedPublicKey, AsnEncodingRules.DER).ReadSequence();
        ReadOnlyMemory<byte> modulus = StripLeadingZero(sequence.ReadIntegerBytes());
        ReadOnlyMemory<byte> exponent = StripLeadingZero(sequence.ReadIntegerBytes());

        return (modulus, exponent);
    }


    /// <summary>
    /// Strips a single leading <c>0x00</c> sign octet from a DER INTEGER's two's-complement
    /// encoding, recovering the unsigned big-endian magnitude RFC 8230 §4 expects for the RSA
    /// <c>n</c>/<c>e</c> labels.
    /// </summary>
    /// <param name="integer">The DER INTEGER's encoded bytes.</param>
    /// <returns>The unsigned magnitude, with any DER sign-padding byte removed.</returns>
    private static ReadOnlyMemory<byte> StripLeadingZero(ReadOnlyMemory<byte> integer) =>
        integer.Length > 1 && integer.Span[0] == 0x00 ? integer[1..] : integer;
}
