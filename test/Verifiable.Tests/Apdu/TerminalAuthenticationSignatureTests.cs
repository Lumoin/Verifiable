using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Apdu.Eac;
using Verifiable.Apdu.Lds;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestDataProviders;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates the Terminal Authentication signature (ICAO Doc 9303 Part 11 §7.1.2): the terminal signs
/// <c>ID_IC || r_IC || Comp(PK_DH,IFD)</c> and the chip verifies it against the terminal certificate's
/// public key. The independent-oracle tests mint their terminal key with the framework's own ECDSA or RSA
/// implementation and either sign or verify with it directly, pinning the library's signing and verification
/// to the spec message against an implementation the library shares no code with. The remaining tests draw
/// terminal and ephemeral key material from <see cref="TestKeyMaterialProvider"/>, since only a valid key
/// pair — not interop with the framework implementation — is under test there.
/// </summary>
[TestClass]
internal sealed class TerminalAuthenticationSignatureTests
{
    /// <summary>The chip identifier ID_IC after Basic Access Control: the MRZ document number including its check digit.</summary>
    private static readonly byte[] ChipIdentifier = System.Text.Encoding.ASCII.GetBytes("L898902C<3");

    /// <summary>The chip's 8-byte challenge r_IC from GET CHALLENGE.</summary>
    private static readonly byte[] ChipChallenge = Convert.FromHexString("0001020304050607");


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task SignsAMessageAnIndependentVerifierAccepts()
    {
        //Oracle-keep: this ECDsa mints the terminal key the library signs with, then independently verifies
        //the library's signature below — proving the library's ECDSA against an implementation it shares no
        //code with.
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] terminalPrivateKey = terminalKey.ExportParameters(includePrivateParameters: true).D!;
        byte[] terminalEphemeralPublicKey = CreateTerminalEphemeralPublicKey();

        using Signature signature = await TerminalAuthenticationSignature.SignAsync(
            terminalPrivateKey, CryptoTags.P256ExchangePublicKey, ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);

        //The independent ECDSA must accept the signature over the §7.1.2 message, proving the library signed
        //exactly ID_IC || r_IC || Comp(PK_DH,IFD) and not some other byte string.
        byte[] expectedMessage = SignedMessage(terminalEphemeralPublicKey);
        bool acceptedByIndependentVerifier = terminalKey.VerifyData(
            expectedMessage, signature.AsReadOnlySpan(), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        Assert.IsTrue(acceptedByIndependentVerifier, "The framework's ECDSA must accept the library's signature over the §7.1.2 message.");
    }


    [TestMethod]
    public async Task VerifiesAnIndependentlyMintedSignature()
    {
        //Oracle-keep: this ECDsa independently signs the §7.1.2 message below so the library's VerifyAsync is
        //proven against a signature it did not produce.
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] terminalEphemeralPublicKey = CreateTerminalEphemeralPublicKey();

        //The independent ECDSA signs the §7.1.2 message; the library must reconstruct the same message and verify it.
        byte[] message = SignedMessage(terminalEphemeralPublicKey);
        byte[] signature = terminalKey.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        using EncodedEcPoint terminalPublicKey = EncodedEcPoint.FromBytes(
            UncompressedPoint(terminalKey), CryptoTags.P256ExchangePublicKey, BaseMemoryPool.Shared);

        bool verified = await TerminalAuthenticationSignature.VerifyAsync(
            terminalPublicKey, signature, ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);

        Assert.IsTrue(verified, "The library must verify an independently minted signature over the §7.1.2 message.");
    }


    [TestMethod]
    public async Task RoundTripsSignAndVerify()
    {
        //The terminal key is mere fixture material here: both signing and verification run through the
        //library, so any matched P-256 exchange key pair suffices.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> terminalKeys = TestKeyMaterialProvider.CreateP256ExchangeKeyMaterial();
        using PublicKeyMemory terminalPublicKeyMemory = terminalKeys.PublicKey;
        using PrivateKeyMemory terminalPrivateKeyMemory = terminalKeys.PrivateKey;
        byte[] terminalEphemeralPublicKey = CreateTerminalEphemeralPublicKey();

        using Signature signature = await TerminalAuthenticationSignature.SignAsync(
            terminalPrivateKeyMemory.AsReadOnlyMemory(), CryptoTags.P256ExchangePublicKey, ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);

        using EncodedEcPoint terminalPublicKey = EncodedEcPoint.FromBytes(
            terminalPublicKeyMemory.AsReadOnlySpan(), CryptoTags.P256ExchangePublicKey, BaseMemoryPool.Shared);

        bool verified = await TerminalAuthenticationSignature.VerifyAsync(
            terminalPublicKey, signature.AsReadOnlyMemory(), ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);

        Assert.IsTrue(verified, "A signature the terminal produces must verify against the terminal public key with the same inputs.");
    }


    [TestMethod]
    public async Task RejectsASignatureOverADifferentChallenge()
    {
        //The terminal key is mere fixture material here: both signing and verification run through the
        //library, so any matched P-256 exchange key pair suffices.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> terminalKeys = TestKeyMaterialProvider.CreateP256ExchangeKeyMaterial();
        using PublicKeyMemory terminalPublicKeyMemory = terminalKeys.PublicKey;
        using PrivateKeyMemory terminalPrivateKeyMemory = terminalKeys.PrivateKey;
        byte[] terminalEphemeralPublicKey = CreateTerminalEphemeralPublicKey();

        using Signature signature = await TerminalAuthenticationSignature.SignAsync(
            terminalPrivateKeyMemory.AsReadOnlyMemory(), CryptoTags.P256ExchangePublicKey, ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);

        using EncodedEcPoint terminalPublicKey = EncodedEcPoint.FromBytes(
            terminalPublicKeyMemory.AsReadOnlySpan(), CryptoTags.P256ExchangePublicKey, BaseMemoryPool.Shared);

        //A replayed signature against a fresh challenge must fail — the challenge binds the signature to this run.
        byte[] differentChallenge = Convert.FromHexString("08090A0B0C0D0E0F");
        bool verified = await TerminalAuthenticationSignature.VerifyAsync(
            terminalPublicKey, signature.AsReadOnlyMemory(), ChipIdentifier, differentChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);

        Assert.IsFalse(verified, "A signature does not verify against a challenge other than the one it was computed over.");
    }


    [TestMethod]
    public async Task RejectsASignatureFromADifferentKey()
    {
        //Wrong-key verification requires two distinct matched key pairs, so both are freshly minted rather
        //than drawn from the cached fixture pair.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> terminalKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory terminalPublicKeyMemory = terminalKeys.PublicKey;
        terminalKeys.PrivateKey.Dispose();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> impostorKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PrivateKeyMemory impostorPrivateKeyMemory = impostorKeys.PrivateKey;
        impostorKeys.PublicKey.Dispose();

        byte[] terminalEphemeralPublicKey = CreateTerminalEphemeralPublicKey();

        //A terminal that does not hold the private key matching its certificate signs with the wrong key.
        using Signature signature = await TerminalAuthenticationSignature.SignAsync(
            impostorPrivateKeyMemory.AsReadOnlyMemory(), CryptoTags.P256ExchangePublicKey, ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);

        using EncodedEcPoint terminalPublicKey = EncodedEcPoint.FromBytes(
            terminalPublicKeyMemory.AsReadOnlySpan(), CryptoTags.P256ExchangePublicKey, BaseMemoryPool.Shared);

        bool verified = await TerminalAuthenticationSignature.VerifyAsync(
            terminalPublicKey, signature.AsReadOnlyMemory(), ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);

        Assert.IsFalse(verified, "A signature made with a key other than the certificate's public key is rejected.");
    }


    [TestMethod]
    public async Task SignsWithAnInjectedPrivateKeyTheChipsVerifierAccepts()
    {
        byte[] terminalEphemeralPublicKey = CreateTerminalEphemeralPublicKey();

        //The terminal's Terminal Authentication key is presented as an injected PrivateKey rather than as raw key
        //bytes — the same seam a hardware-held key (for example a TPM-resident key whose scalar never leaves the
        //device) uses. Here it wraps a software P-256 key bound to the registered signing function; nothing on the
        //chip side can tell a software key from a hardware one.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using PublicKeyMemory terminalPublicKey = keys.PublicKey;
        using PrivateKey terminalKey = CryptographicKeyFactory.CreatePrivateKey(keys.PrivateKey, "terminal-p256", keys.PrivateKey.Tag);

        using Signature signature = await TerminalAuthenticationSignature.SignAsync(
            terminalKey, ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey, BaseMemoryPool.Shared, TestContext.CancellationToken);

        //The chip verifies an injected-key signature exactly as it verifies a raw-key one: with the registered
        //P-256 verifier over the §7.1.2 message, requiring the plain r || s encoding (TR-03111).
        VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(CryptoAlgorithm.P256, Purpose.Verification);
        (bool verified, CryptoEvent? _) = await verify(
            SignedMessage(terminalEphemeralPublicKey), signature.AsReadOnlyMemory(), terminalPublicKey.AsReadOnlyMemory(), null, TestContext.CancellationToken);

        Assert.IsTrue(verified, "A signature from an injected PrivateKey must verify with the chip's registered P-256 verifier over the §7.1.2 message.");
    }


    [TestMethod]
    public async Task SignsAnRsaMessageAnIndependentVerifierAccepts()
    {
        //Oracle-keep: this RSA key mints the terminal key the library signs with, then independently verifies
        //the library's RSA signature below — proving the library's RSA against an implementation it shares no
        //code with.
        using RSA terminalKey = RSA.Create(2048);
        byte[] terminalEphemeralPublicKey = CreateTerminalEphemeralPublicKey();

        using Signature signature = await TerminalAuthenticationSignature.SignWithRsaAsync(
            terminalKey.ExportRSAPrivateKey(), CvcSignatureScheme.RsaPkcs1Sha256, ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);

        //The independent RSA must accept the signature over the §7.1.2 message, proving the library signed
        //exactly ID_IC || r_IC || Comp(PK_DH,IFD) with the certificate's id-TA-RSA scheme and not some other byte string.
        byte[] expectedMessage = SignedMessage(terminalEphemeralPublicKey);
        bool acceptedByIndependentVerifier = terminalKey.VerifyData(
            expectedMessage, signature.AsReadOnlySpan(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        Assert.IsTrue(acceptedByIndependentVerifier, "The framework's RSA must accept the library's RSA signature over the §7.1.2 message.");
    }


    [TestMethod]
    public async Task VerifiesAnIndependentlyMintedRsaSignature()
    {
        //Oracle-keep: this RSA key independently signs the §7.1.2 message below so the library's
        //VerifyWithRsaAsync is proven against a signature it did not produce.
        using RSA terminalKey = RSA.Create(2048);
        byte[] terminalEphemeralPublicKey = CreateTerminalEphemeralPublicKey();

        //The independent RSA signs the §7.1.2 message; the library must reconstruct the same message and verify it.
        byte[] message = SignedMessage(terminalEphemeralPublicKey);
        byte[] signature = terminalKey.SignData(message, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        using RsaPublicKey terminalPublicKey = RsaPublicKey.FromBytes(terminalKey.ExportRSAPublicKey(), BaseMemoryPool.Shared);

        bool verified = await TerminalAuthenticationSignature.VerifyWithRsaAsync(
            terminalPublicKey, CvcSignatureScheme.RsaPkcs1Sha256, signature, ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);

        Assert.IsTrue(verified, "The library must verify an independently minted RSA signature over the §7.1.2 message.");
    }


    [TestMethod]
    public async Task RoundTripsAnRsaPssSignature()
    {
        //Oracle-keep: alongside the library round trip below, this RSA key independently verifies the
        //library's RSA-PSS signature, proving it against an implementation the library shares no code with.
        using RSA terminalKey = RSA.Create(2048);
        byte[] terminalEphemeralPublicKey = CreateTerminalEphemeralPublicKey();

        //The PSS padding branch (id-TA-RSA-PSS-SHA-256), distinct from PKCS#1: the library signs and verifies,
        //and an independent RSA-PSS verify pins the §7.1.2 message for the PSS branch.
        using Signature signature = await TerminalAuthenticationSignature.SignWithRsaAsync(
            terminalKey.ExportRSAPrivateKey(), CvcSignatureScheme.RsaPssSha256, ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);

        using RsaPublicKey terminalPublicKey = RsaPublicKey.FromBytes(terminalKey.ExportRSAPublicKey(), BaseMemoryPool.Shared);
        bool verified = await TerminalAuthenticationSignature.VerifyWithRsaAsync(
            terminalPublicKey, CvcSignatureScheme.RsaPssSha256, signature.AsReadOnlyMemory(), ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);

        byte[] expectedMessage = SignedMessage(terminalEphemeralPublicKey);
        bool acceptedByIndependentVerifier = terminalKey.VerifyData(
            expectedMessage, signature.AsReadOnlySpan(), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        Assert.IsTrue(verified, "The library must verify its own RSA-PSS Terminal Authentication signature.");
        Assert.IsTrue(acceptedByIndependentVerifier, "The framework's RSA-PSS verify must accept the library's signature over the §7.1.2 message.");
    }


    [TestMethod]
    public async Task RejectsAnUnsupportedSha1RsaScheme()
    {
        //Oracle-keep: this RSA key independently produces a valid SHA-1 signature below so the library's
        //fail-closed rejection is proven against a real signature, not merely a malformed one.
        using RSA terminalKey = RSA.Create(2048);
        byte[] terminalEphemeralPublicKey = CreateTerminalEphemeralPublicKey();

        //The SHA-1 id-TA-RSA schemes TR-03110 retires are unmapped, so verification fails closed even over an
        //otherwise valid signature.
        byte[] message = SignedMessage(terminalEphemeralPublicKey);
        byte[] signature = terminalKey.SignData(message, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

        using RsaPublicKey terminalPublicKey = RsaPublicKey.FromBytes(terminalKey.ExportRSAPublicKey(), BaseMemoryPool.Shared);

        bool verified = await TerminalAuthenticationSignature.VerifyWithRsaAsync(
            terminalPublicKey, CvcSignatureScheme.RsaPkcs1Sha1, signature, ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);

        Assert.IsFalse(verified, "A SHA-1 id-TA-RSA scheme is not a supported scheme, so verification fails closed.");
    }


    /// <summary>
    /// The Terminal Authentication signed message <c>ID_IC || r_IC || Comp(PK_DH,IFD)</c>, where
    /// <c>Comp()</c> of the uncompressed ephemeral point is its x-coordinate (the field-width first half).
    /// </summary>
    private static byte[] SignedMessage(byte[] terminalEphemeralPublicKey)
    {
        int fieldWidth = (terminalEphemeralPublicKey.Length - 1) / 2;
        byte[] message = new byte[ChipIdentifier.Length + ChipChallenge.Length + fieldWidth];
        ChipIdentifier.CopyTo(message, 0);
        ChipChallenge.CopyTo(message, ChipIdentifier.Length);
        Array.Copy(terminalEphemeralPublicKey, 1, message, ChipIdentifier.Length + ChipChallenge.Length, fieldWidth);

        return message;
    }


    /// <summary>The key's public point as an uncompressed SEC1 point (<c>0x04 || X || Y</c>).</summary>
    private static byte[] UncompressedPoint(ECDsa key)
    {
        ECParameters parameters = key.ExportParameters(includePrivateParameters: false);
        byte[] x = parameters.Q.X!;
        byte[] y = parameters.Q.Y!;

        byte[] point = new byte[1 + x.Length + y.Length];
        point[0] = 0x04;
        x.CopyTo(point, 1);
        y.CopyTo(point, 1 + x.Length);

        return point;
    }


    /// <summary>
    /// The terminal's ephemeral public key <c>PK_DH,IFD</c> as an uncompressed SEC1 point, for tests where
    /// only its presence and length in the signed message are exercised (any P-256 exchange point serves).
    /// </summary>
    private static byte[] CreateTerminalEphemeralPublicKey()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = TestKeyMaterialProvider.CreateP256ExchangeKeyMaterial();
        byte[] publicKey = keys.PublicKey.AsReadOnlySpan().ToArray();
        keys.PublicKey.Dispose();
        keys.PrivateKey.Dispose();

        return publicKey;
    }
}
