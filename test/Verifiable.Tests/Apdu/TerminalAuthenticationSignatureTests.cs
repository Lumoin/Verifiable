using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Apdu.Eac;
using Verifiable.Apdu.Lds;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates the Terminal Authentication signature (ICAO Doc 9303 Part 11 §7.1.2): the terminal signs
/// <c>ID_IC || r_IC || Comp(PK_DH,IFD)</c> and the chip verifies it against the terminal certificate's
/// public key. The terminal and chip key pairs are minted with the framework's own ECDSA (an independent
/// signer), and the signed-message construction is cross-checked against that same independent ECDSA, so the
/// library's signing and verification are pinned to the spec message rather than only to themselves.
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
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa terminalEphemeralKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        byte[] terminalPrivateKey = terminalKey.ExportParameters(includePrivateParameters: true).D!;
        byte[] terminalEphemeralPublicKey = UncompressedPoint(terminalEphemeralKey);

        using Signature signature = await TerminalAuthenticationSignature.SignAsync(
            terminalPrivateKey, CryptoTags.P256ExchangePublicKey, ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, TestContext.CancellationToken);

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
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa terminalEphemeralKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        byte[] terminalEphemeralPublicKey = UncompressedPoint(terminalEphemeralKey);

        //The independent ECDSA signs the §7.1.2 message; the library must reconstruct the same message and verify it.
        byte[] message = SignedMessage(terminalEphemeralPublicKey);
        byte[] signature = terminalKey.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        using EncodedEcPoint terminalPublicKey = EncodedEcPoint.FromBytes(
            UncompressedPoint(terminalKey), CryptoTags.P256ExchangePublicKey, BaseMemoryPool.Shared);

        bool verified = await TerminalAuthenticationSignature.VerifyAsync(
            terminalPublicKey, signature, ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsTrue(verified, "The library must verify an independently minted signature over the §7.1.2 message.");
    }


    [TestMethod]
    public async Task RoundTripsSignAndVerify()
    {
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa terminalEphemeralKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        byte[] terminalPrivateKey = terminalKey.ExportParameters(includePrivateParameters: true).D!;
        byte[] terminalEphemeralPublicKey = UncompressedPoint(terminalEphemeralKey);

        using Signature signature = await TerminalAuthenticationSignature.SignAsync(
            terminalPrivateKey, CryptoTags.P256ExchangePublicKey, ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, TestContext.CancellationToken);

        using EncodedEcPoint terminalPublicKey = EncodedEcPoint.FromBytes(
            UncompressedPoint(terminalKey), CryptoTags.P256ExchangePublicKey, BaseMemoryPool.Shared);

        bool verified = await TerminalAuthenticationSignature.VerifyAsync(
            terminalPublicKey, signature.AsReadOnlyMemory(), ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsTrue(verified, "A signature the terminal produces must verify against the terminal public key with the same inputs.");
    }


    [TestMethod]
    public async Task RejectsASignatureOverADifferentChallenge()
    {
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa terminalEphemeralKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        byte[] terminalPrivateKey = terminalKey.ExportParameters(includePrivateParameters: true).D!;
        byte[] terminalEphemeralPublicKey = UncompressedPoint(terminalEphemeralKey);

        using Signature signature = await TerminalAuthenticationSignature.SignAsync(
            terminalPrivateKey, CryptoTags.P256ExchangePublicKey, ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, TestContext.CancellationToken);

        using EncodedEcPoint terminalPublicKey = EncodedEcPoint.FromBytes(
            UncompressedPoint(terminalKey), CryptoTags.P256ExchangePublicKey, BaseMemoryPool.Shared);

        //A replayed signature against a fresh challenge must fail — the challenge binds the signature to this run.
        byte[] differentChallenge = Convert.FromHexString("08090A0B0C0D0E0F");
        bool verified = await TerminalAuthenticationSignature.VerifyAsync(
            terminalPublicKey, signature.AsReadOnlyMemory(), ChipIdentifier, differentChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsFalse(verified, "A signature does not verify against a challenge other than the one it was computed over.");
    }


    [TestMethod]
    public async Task RejectsASignatureFromADifferentKey()
    {
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa impostorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa terminalEphemeralKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        byte[] impostorPrivateKey = impostorKey.ExportParameters(includePrivateParameters: true).D!;
        byte[] terminalEphemeralPublicKey = UncompressedPoint(terminalEphemeralKey);

        //A terminal that does not hold the private key matching its certificate signs with the wrong key.
        using Signature signature = await TerminalAuthenticationSignature.SignAsync(
            impostorPrivateKey, CryptoTags.P256ExchangePublicKey, ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, TestContext.CancellationToken);

        using EncodedEcPoint terminalPublicKey = EncodedEcPoint.FromBytes(
            UncompressedPoint(terminalKey), CryptoTags.P256ExchangePublicKey, BaseMemoryPool.Shared);

        bool verified = await TerminalAuthenticationSignature.VerifyAsync(
            terminalPublicKey, signature.AsReadOnlyMemory(), ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsFalse(verified, "A signature made with a key other than the certificate's public key is rejected.");
    }


    [TestMethod]
    public async Task SignsWithAnInjectedPrivateKeyTheChipsVerifierAccepts()
    {
        using ECDsa terminalEphemeralKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] terminalEphemeralPublicKey = UncompressedPoint(terminalEphemeralKey);

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
        bool verified = await verify(
            SignedMessage(terminalEphemeralPublicKey), signature.AsReadOnlyMemory(), terminalPublicKey.AsReadOnlyMemory(), null, TestContext.CancellationToken);

        Assert.IsTrue(verified, "A signature from an injected PrivateKey must verify with the chip's registered P-256 verifier over the §7.1.2 message.");
    }


    [TestMethod]
    public async Task SignsAnRsaMessageAnIndependentVerifierAccepts()
    {
        using RSA terminalKey = RSA.Create(2048);
        using ECDsa terminalEphemeralKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        byte[] terminalEphemeralPublicKey = UncompressedPoint(terminalEphemeralKey);

        using Signature signature = await TerminalAuthenticationSignature.SignWithRsaAsync(
            terminalKey.ExportRSAPrivateKey(), CvcSignatureScheme.RsaPkcs1Sha256, ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, TestContext.CancellationToken);

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
        using RSA terminalKey = RSA.Create(2048);
        using ECDsa terminalEphemeralKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        byte[] terminalEphemeralPublicKey = UncompressedPoint(terminalEphemeralKey);

        //The independent RSA signs the §7.1.2 message; the library must reconstruct the same message and verify it.
        byte[] message = SignedMessage(terminalEphemeralPublicKey);
        byte[] signature = terminalKey.SignData(message, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        using RsaPublicKey terminalPublicKey = RsaPublicKey.FromBytes(terminalKey.ExportRSAPublicKey(), BaseMemoryPool.Shared);

        bool verified = await TerminalAuthenticationSignature.VerifyWithRsaAsync(
            terminalPublicKey, CvcSignatureScheme.RsaPkcs1Sha256, signature, ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsTrue(verified, "The library must verify an independently minted RSA signature over the §7.1.2 message.");
    }


    [TestMethod]
    public async Task RoundTripsAnRsaPssSignature()
    {
        using RSA terminalKey = RSA.Create(2048);
        using ECDsa terminalEphemeralKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        byte[] terminalEphemeralPublicKey = UncompressedPoint(terminalEphemeralKey);

        //The PSS padding branch (id-TA-RSA-PSS-SHA-256), distinct from PKCS#1: the library signs and verifies,
        //and an independent RSA-PSS verify pins the §7.1.2 message for the PSS branch.
        using Signature signature = await TerminalAuthenticationSignature.SignWithRsaAsync(
            terminalKey.ExportRSAPrivateKey(), CvcSignatureScheme.RsaPssSha256, ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, TestContext.CancellationToken);

        using RsaPublicKey terminalPublicKey = RsaPublicKey.FromBytes(terminalKey.ExportRSAPublicKey(), BaseMemoryPool.Shared);
        bool verified = await TerminalAuthenticationSignature.VerifyWithRsaAsync(
            terminalPublicKey, CvcSignatureScheme.RsaPssSha256, signature.AsReadOnlyMemory(), ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, TestContext.CancellationToken);

        byte[] expectedMessage = SignedMessage(terminalEphemeralPublicKey);
        bool acceptedByIndependentVerifier = terminalKey.VerifyData(
            expectedMessage, signature.AsReadOnlySpan(), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        Assert.IsTrue(verified, "The library must verify its own RSA-PSS Terminal Authentication signature.");
        Assert.IsTrue(acceptedByIndependentVerifier, "The framework's RSA-PSS verify must accept the library's signature over the §7.1.2 message.");
    }


    [TestMethod]
    public async Task RejectsAnUnsupportedSha1RsaScheme()
    {
        using RSA terminalKey = RSA.Create(2048);
        using ECDsa terminalEphemeralKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        byte[] terminalEphemeralPublicKey = UncompressedPoint(terminalEphemeralKey);

        //The SHA-1 id-TA-RSA schemes TR-03110 retires are unmapped, so verification fails closed even over an
        //otherwise valid signature.
        byte[] message = SignedMessage(terminalEphemeralPublicKey);
        byte[] signature = terminalKey.SignData(message, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

        using RsaPublicKey terminalPublicKey = RsaPublicKey.FromBytes(terminalKey.ExportRSAPublicKey(), BaseMemoryPool.Shared);

        bool verified = await TerminalAuthenticationSignature.VerifyWithRsaAsync(
            terminalPublicKey, CvcSignatureScheme.RsaPkcs1Sha1, signature, ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, TestContext.CancellationToken);

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
}
