using System.Buffers;
using System.Text;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography.Aead;

/// <summary>
/// Tests for ECDH-1PU One-Pass Unified Model key agreement per
/// <see href="https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04">draft-madden-jose-ecdh-1pu-04</see>,
/// pinned to the Appendix A (P-256, Direct Key Agreement) and Appendix B
/// (X25519, Key Agreement with Key Wrapping, multi-recipient) example computations.
/// Appendix B chains the full DIDComm v2 authcrypt primitive set: two-DH agreement,
/// tag-committed Concat KDF, RFC 3394 key wrap, and A256CBC-HS512 content encryption.
/// </summary>
[TestClass]
internal sealed class Ecdh1PuTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    //Appendix A: P-256 keys in JWK base64url coordinates.
    private const string AppendixAAliceStaticX = "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis";
    private const string AppendixAAliceStaticY = "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE";
    private const string AppendixAAliceEphemeralX = "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0";
    private const string AppendixAAliceEphemeralY = "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps";
    private const string AppendixABobD = "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw";

    private const string AppendixAZ =
        "9E56D91D817135D372834283BF84269CFB316EA3DA806A48F6DAA7798CFE90C4" +
        "E3CA3474384C9F62B30BFD4C688B3E7D4110A1B4BADC3CC54EF7B81241EFD50D";

    private const string AppendixADerivedKey =
        "6CAF13723D14850AD4B42CD6DDE935BFFD2FFF00A9BA70DE05C203A5E1722CA7";

    //Appendix B: X25519 keys in JWK base64url coordinates.
    private const string AppendixBAliceStaticX = "Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4";
    private const string AppendixBAliceEphemeralX = "k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc";
    private const string AppendixBBobD = "1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg";
    private const string AppendixBCharlieD = "Jcv8gklhMjC0b-lsk5onBbppWAx5ncNtbM63Jr9xBQE";

    private const string AppendixBZBob =
        "32810896E0FE4D570ED1ACFCEDF67117DC194ED5DAAC21D8FF7AF3244694897F" +
        "2157612C9048EDFAE77CB2E4237140605967C05C7F77A48EEAF2CF29A5737C4A";

    private const string AppendixBZCharlie =
        "89DCFE4C37C1DC0271F346B5B3B19C3B705CA2A72F9A237785C34406FCB75F10" +
        "78FE63FC661CF8D18F92A8422A6418E4ED5E20A9168185FDEEDCA1C3D8E6A61C";

    private const string AppendixBKekBob = "DF4C37A0668306A11E3D6B0074B5D8DF";
    private const string AppendixBKekCharlie = "57D8126F1B7EC4CCB0584DAC03CB27CC";

    private const string AppendixBCek =
        "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0" +
        "DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0";

    private const string AppendixBIv = "000102030405060708090A0B0C0D0E0F";
    private const string AppendixBTag = "HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ";
    private const string AppendixBCiphertext = "Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw";
    private const string AppendixBEncryptedKeyBob =
        "pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQeU1cSl55cQ0hGezJu2N9IY0QN";
    private const string AppendixBEncryptedKeyCharlie =
        "56GVudgRLIMEElQ7DpXsijJVRSWUSDNdbWkdV3g0GUNq6hcT_GkxwnxlPIWrTXCqRpVKQC8fe4z3PQ2YH2afvjQ28aiCTWFE";

    private const string AppendixBAlg = "ECDH-1PU+A128KW";
    private const string AppendixBApu = "Alice";
    private const string AppendixBApv = "Bob and Charlie";

    //The JWE Protected Header whose base64url encoding is the AAD per Appendix B.4.
    private const string AppendixBProtectedHeaderJson =
        /*lang=json,strict*/ """{"alg":"ECDH-1PU+A128KW","enc":"A256CBC-HS512","apu":"QWxpY2U","apv":"Qm9iIGFuZCBDaGFybGll","epk":{"kty":"OKP","crv":"X25519","x":"k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc"}}""";


    [TestMethod]
    [DataRow("Microsoft")]
    [DataRow("BouncyCastle")]
    public async Task AppendixADecryptSideAgreementReproducesZ(string driver)
    {
        AuthenticatedKeyAgreementDecryptDelegate agreementDelegate = driver switch
        {
            "Microsoft" => MicrosoftKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptP256Async,
            "BouncyCastle" => BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptP256Async,
            _ => throw new ArgumentException($"Unknown driver '{driver}'.", nameof(driver))
        };

        using IMemoryOwner<byte> bobD = TestSetup.Base64UrlDecoder(AppendixABobD, Pool);
        using PublicKeyMemory ephemeralPublic = P256PublicKeyFromJwk(AppendixAAliceEphemeralX, AppendixAAliceEphemeralY);
        using PublicKeyMemory aliceStaticPublic = P256PublicKeyFromJwk(AppendixAAliceStaticX, AppendixAAliceStaticY);

        using SharedSecret z = await agreementDelegate(
            bobD.Memory, ephemeralPublic, aliceStaticPublic, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AppendixAZ, Convert.ToHexString(z.AsReadOnlySpan()),
            $"Z = Ze || Zs must match the Appendix A vector for '{driver}'.");
    }


    [TestMethod]
    public void AppendixADirectModeKdfDerivesVectorKey()
    {
        using ContentEncryptionKey derived = ConcatKdf.Derive(
            Convert.FromHexString(AppendixAZ),
            "A256GCM",
            Encoding.UTF8.GetBytes("Alice"),
            Encoding.UTF8.GetBytes("Bob"),
            keydataLenBits: 256,
            committedTag: [],
            CryptoTags.AesGcmCek,
            Pool);

        using SymmetricKeyMemory derivedKey = derived.UseKey();
        Assert.AreEqual(AppendixADerivedKey, Convert.ToHexString(derivedKey.AsReadOnlySpan()),
            "Direct Key Agreement mode derivation must match the Appendix A vector.");
    }


    [TestMethod]
    [DataRow(AppendixBBobD, AppendixBZBob)]
    [DataRow(AppendixBCharlieD, AppendixBZCharlie)]
    public async Task AppendixBDecryptSideAgreementReproducesZ(string recipientD, string expectedZ)
    {
        using IMemoryOwner<byte> recipientPrivate = TestSetup.Base64UrlDecoder(recipientD, Pool);
        using PublicKeyMemory ephemeralPublic = X25519PublicKeyFromJwk(AppendixBAliceEphemeralX);
        using PublicKeyMemory aliceStaticPublic = X25519PublicKeyFromJwk(AppendixBAliceStaticX);

        using SharedSecret z = await BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptX25519Async(
            recipientPrivate.Memory, ephemeralPublic, aliceStaticPublic, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedZ, Convert.ToHexString(z.AsReadOnlySpan()),
            "Z = Ze || Zs must match the Appendix B vector.");
    }


    [TestMethod]
    [DataRow(AppendixBZBob, AppendixBKekBob)]
    [DataRow(AppendixBZCharlie, AppendixBKekCharlie)]
    public void AppendixBKekDerivationCommitsAuthenticationTag(string zHex, string expectedKekHex)
    {
        using IMemoryOwner<byte> tagBytes = TestSetup.Base64UrlDecoder(AppendixBTag, Pool);

        using ContentEncryptionKey derived = ConcatKdf.Derive(
            Convert.FromHexString(zHex),
            AppendixBAlg,
            Encoding.UTF8.GetBytes(AppendixBApu),
            Encoding.UTF8.GetBytes(AppendixBApv),
            keydataLenBits: 128,
            committedTag: tagBytes.Memory.Span,
            CryptoTags.AesKwKeyEncryptionKey,
            Pool);

        using SymmetricKeyMemory kek = derived.UseKey();
        Assert.AreEqual(expectedKekHex, Convert.ToHexString(kek.AsReadOnlySpan()),
            "The tag-committed Key Agreement with Key Wrapping derivation must match the Appendix B vector.");
    }


    [TestMethod]
    [DataRow("Microsoft", AppendixBKekBob, AppendixBEncryptedKeyBob)]
    [DataRow("Microsoft", AppendixBKekCharlie, AppendixBEncryptedKeyCharlie)]
    [DataRow("BouncyCastle", AppendixBKekBob, AppendixBEncryptedKeyBob)]
    [DataRow("BouncyCastle", AppendixBKekCharlie, AppendixBEncryptedKeyCharlie)]
    public async Task AppendixBWrappedContentEncryptionKeyMatchesVector(string driver, string kekHex, string expectedEncryptedKey)
    {
        KeyWrapDelegate wrapDelegate = driver switch
        {
            "Microsoft" => MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
            "BouncyCastle" => BouncyCastleKeyAgreementFunctions.AesKeyWrapAsync,
            _ => throw new ArgumentException($"Unknown driver '{driver}'.", nameof(driver))
        };

        using SymmetricKeyMemory kek = SymmetricKeyFromHex(kekHex, CryptoTags.AesKwKeyEncryptionKey);
        using SymmetricKeyMemory cek = SymmetricKeyFromHex(AppendixBCek, CryptoTags.AesCbcHmacCek);

        using Ciphertext wrapped = await wrapDelegate(
            kek, cek, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        using IMemoryOwner<byte> expected = TestSetup.Base64UrlDecoder(expectedEncryptedKey, Pool);
        Assert.IsTrue(wrapped.AsReadOnlySpan().SequenceEqual(expected.Memory.Span),
            $"The wrapped content encryption key must match the Appendix B encrypted_key for '{driver}'.");
    }


    [TestMethod]
    public async Task AppendixBUnwrapRecoversContentEncryptionKey()
    {
        using SymmetricKeyMemory kek = SymmetricKeyFromHex(AppendixBKekBob, CryptoTags.AesKwKeyEncryptionKey);
        using IMemoryOwner<byte> wrappedKey = TestSetup.Base64UrlDecoder(AppendixBEncryptedKeyBob, Pool);

        using SymmetricKeyMemory cek = await MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync(
            kek, wrappedKey.Memory, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AppendixBCek, Convert.ToHexString(cek.AsReadOnlySpan()),
            "Unwrapping the Appendix B encrypted_key must recover the vector content encryption key.");
    }


    [TestMethod]
    public async Task AppendixBContentDecryptionMatchesVector()
    {
        //The AAD is ASCII(BASE64URL(UTF8(JWE Protected Header))) per RFC 7516 §5.1 step 14.
        string protectedEncoded = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(AppendixBProtectedHeaderJson));
        byte[] aadBytes = Encoding.ASCII.GetBytes(protectedEncoded);
        IMemoryOwner<byte> aadOwner = Pool.Rent(aadBytes.Length);
        aadBytes.CopyTo(aadOwner.Memory.Span);
        using AdditionalData aad = new(aadOwner, CryptoTags.AesCbcHmacAad);

        using SymmetricKeyMemory cek = SymmetricKeyFromHex(AppendixBCek, CryptoTags.AesCbcHmacCek);

        IMemoryOwner<byte> ivOwner = Pool.Rent(16);
        Convert.FromHexString(AppendixBIv).CopyTo(ivOwner.Memory.Span);
        using Nonce iv = new(ivOwner, CryptoTags.AesCbcHmacIv);

        using IMemoryOwner<byte> ciphertextBytes = TestSetup.Base64UrlDecoder(AppendixBCiphertext, Pool);
        IMemoryOwner<byte> ciphertextOwner = Pool.Rent(ciphertextBytes.Memory.Length);
        ciphertextBytes.Memory.CopyTo(ciphertextOwner.Memory);
        using Ciphertext ciphertext = new(ciphertextOwner, CryptoTags.AesCbcHmacCiphertext);

        using IMemoryOwner<byte> tagBytes = TestSetup.Base64UrlDecoder(AppendixBTag, Pool);
        IMemoryOwner<byte> tagOwner = Pool.Rent(tagBytes.Memory.Length);
        tagBytes.Memory.CopyTo(tagOwner.Memory);
        using AuthenticationTag tag = new(tagOwner, CryptoTags.AesCbcHmacAuthTag);

        using DecryptedContent decrypted = await MicrosoftKeyAgreementFunctions.AesCbcHmacSha512DecryptAsync(
            ciphertext, cek, iv, tag, aad, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual("Three is a magic number.", Encoding.UTF8.GetString(decrypted.AsReadOnlySpan()),
            "A256CBC-HS512 decryption of the Appendix B ciphertext must yield the vector plaintext.");
    }


    [TestMethod]
    [DataRow("MicrosoftToMicrosoft")]
    [DataRow("BouncyCastleToBouncyCastle")]
    [DataRow("MicrosoftToBouncyCastle")]
    [DataRow("BouncyCastleToMicrosoft")]
    public async Task P256RoundTripProducesSameSharedSecretOnBothSides(string direction)
    {
        (AuthenticatedKeyAgreementEncryptDelegate encryptDelegate, AuthenticatedKeyAgreementDecryptDelegate decryptDelegate) = direction switch
        {
            "MicrosoftToMicrosoft" => (
                (AuthenticatedKeyAgreementEncryptDelegate)MicrosoftKeyAgreementFunctions.Ecdh1PuKeyAgreementEncryptP256Async,
                (AuthenticatedKeyAgreementDecryptDelegate)MicrosoftKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptP256Async),
            "BouncyCastleToBouncyCastle" => (
                BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementEncryptP256Async,
                BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptP256Async),
            "MicrosoftToBouncyCastle" => (
                MicrosoftKeyAgreementFunctions.Ecdh1PuKeyAgreementEncryptP256Async,
                BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptP256Async),
            "BouncyCastleToMicrosoft" => (
                BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementEncryptP256Async,
                MicrosoftKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptP256Async),
            _ => throw new ArgumentException($"Unknown direction '{direction}'.", nameof(direction))
        };

        await AssertRoundTripAsync(
            BouncyCastleKeyMaterialCreator.CreateP256ExchangeKeys,
            encryptDelegate,
            decryptDelegate,
            expectedSharedSecretLength: 64).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task X25519RoundTripProducesSameSharedSecretOnBothSides()
    {
        await AssertRoundTripAsync(
            BouncyCastleKeyMaterialCreator.CreateX25519Keys,
            BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementEncryptX25519Async,
            BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptX25519Async,
            expectedSharedSecretLength: 64).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task P384RoundTripProducesSameSharedSecretOnBothSides()
    {
        await AssertRoundTripAsync(
            BouncyCastleKeyMaterialCreator.CreateP384ExchangeKeys,
            MicrosoftKeyAgreementFunctions.Ecdh1PuKeyAgreementEncryptP384Async,
            MicrosoftKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptP384Async,
            expectedSharedSecretLength: 96).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task P521RoundTripProducesSameSharedSecretOnBothSides()
    {
        await AssertRoundTripAsync(
            BouncyCastleKeyMaterialCreator.CreateP521ExchangeKeys,
            MicrosoftKeyAgreementFunctions.Ecdh1PuKeyAgreementEncryptP521Async,
            MicrosoftKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptP521Async,
            expectedSharedSecretLength: 132).ConfigureAwait(false);
    }


    [TestMethod]
    public void RegistryResolvesAuthenticatedAgreementAndKeyWrapDelegates()
    {
        Assert.IsNotNull(KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveAuthenticatedAgreementEncrypt(
            CryptoAlgorithm.X25519, Purpose.Exchange));
        Assert.IsNotNull(KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveAuthenticatedAgreementDecrypt(
            CryptoAlgorithm.P256, Purpose.Exchange));
        Assert.IsNotNull(KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveAuthenticatedKeyDerivation(
            CryptoAlgorithm.X25519, Purpose.Exchange));
        Assert.IsNotNull(KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveKeyWrap(
            CryptoAlgorithm.Aes256, Purpose.Encryption));
        Assert.IsNotNull(KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveKeyUnwrap(
            CryptoAlgorithm.Aes256, Purpose.Encryption));
    }


    private async Task AssertRoundTripAsync(
        Func<MemoryPool<byte>, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> keyCreator,
        AuthenticatedKeyAgreementEncryptDelegate encryptDelegate,
        AuthenticatedKeyAgreementDecryptDelegate decryptDelegate,
        int expectedSharedSecretLength)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> sender = keyCreator(Pool);
        using PublicKeyMemory senderPublic = sender.PublicKey;
        using PrivateKeyMemory senderPrivate = sender.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = keyCreator(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        using EphemeralKeyAgreementResult encryptResult = await senderPrivate.WithKeyBytesAsync(
            static (senderKeyBytes, state) => state.EncryptDelegate(
                state.RecipientPublic, senderKeyBytes, state.Pool, state.CancellationToken),
            (EncryptDelegate: encryptDelegate,
             RecipientPublic: recipientPublic,
             Pool: Pool,
             CancellationToken: TestContext.CancellationToken)).ConfigureAwait(false);

        using SharedSecret decryptSideSecret = await recipientPrivate.WithKeyBytesAsync(
            static (recipientKeyBytes, state) => state.DecryptDelegate(
                recipientKeyBytes, state.Epk, state.SenderPublic, state.Pool, state.CancellationToken),
            (DecryptDelegate: decryptDelegate,
             Epk: encryptResult.EphemeralPublicKey,
             SenderPublic: senderPublic,
             Pool: Pool,
             CancellationToken: TestContext.CancellationToken)).ConfigureAwait(false);

        Assert.AreEqual(expectedSharedSecretLength, decryptSideSecret.Length,
            "Z = Ze || Zs must be twice the curve field size.");
        Assert.IsTrue(
            encryptResult.SharedSecret.AsReadOnlySpan().SequenceEqual(decryptSideSecret.AsReadOnlySpan()),
            "Both sides must derive a byte-identical Z = Ze || Zs.");
    }


    private static PublicKeyMemory P256PublicKeyFromJwk(string xBase64Url, string yBase64Url)
    {
        using IMemoryOwner<byte> x = TestSetup.Base64UrlDecoder(xBase64Url, Pool);
        using IMemoryOwner<byte> y = TestSetup.Base64UrlDecoder(yBase64Url, Pool);

        IMemoryOwner<byte> pointOwner = Pool.Rent(1 + x.Memory.Length + y.Memory.Length);
        pointOwner.Memory.Span[0] = EllipticCurveUtilities.UncompressedCoordinateFormat;
        x.Memory.Span.CopyTo(pointOwner.Memory.Span[1..]);
        y.Memory.Span.CopyTo(pointOwner.Memory.Span[(1 + x.Memory.Length)..]);

        return new PublicKeyMemory(pointOwner, CryptoTags.P256ExchangePublicKey);
    }


    private static PublicKeyMemory X25519PublicKeyFromJwk(string xBase64Url)
    {
        using IMemoryOwner<byte> x = TestSetup.Base64UrlDecoder(xBase64Url, Pool);

        IMemoryOwner<byte> keyOwner = Pool.Rent(x.Memory.Length);
        x.Memory.CopyTo(keyOwner.Memory);

        return new PublicKeyMemory(keyOwner, CryptoTags.X25519PublicKey);
    }


    private static SymmetricKeyMemory SymmetricKeyFromHex(string hex, Tag tag)
    {
        byte[] bytes = Convert.FromHexString(hex);
        IMemoryOwner<byte> owner = Pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);

        return new SymmetricKeyMemory(owner, tag);
    }
}
