using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography.Aead;

/// <summary>
/// The ECDH-1PU §2.1 committing-AEAD guard and the tag-commitment binding. Key Agreement with
/// Key Wrapping commits the JWE Authentication Tag into each recipient's key derivation, which
/// is sound only for a compactly committing AEAD (the AES_CBC_HMAC_SHA2 family). These tests
/// prove the guard fires on both the encrypt boundary
/// (<see cref="GeneralJweEncryptionExtensions.EncryptAuthcryptAsync"/>) and the parse boundary
/// (<see cref="GeneralJweParsing.ParseGeneralJson"/>) for the whole AES-GCM family, and that a
/// tampered authentication tag diverges the derived KEK so the RFC 3394 unwrap integrity check
/// fails before any AEAD content check is reached.
/// </summary>
[TestClass]
internal sealed class JweAuthcryptDecryptGuardTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private static readonly JwtHeaderSerializer JwtHeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    //Appendix B static keys (X25519, JWK base64url coordinates) — reused so the tamper test
    //starts from the known-good ECDH-1PU+A128KW / A256CBC-HS512 Appendix B.11 vector.
    private const string AppendixBAliceStaticX = "Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4";
    private const string AppendixBBobD = "1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg";

    //The complete Appendix B.11 General JSON Serialization (display line breaks removed).
    private const string AppendixBGeneralJson =
        /*lang=json,strict*/ """
        {"protected":"eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjoiUVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFBRnFVQUZhMzlkeUJjIn19","unprotected":{"jku":"https://alice.example.com/keys.jwks"},"recipients":[{"header":{"kid":"bob-key-2"},"encrypted_key":"pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQeU1cSl55cQ0hGezJu2N9IY0QN"},{"header":{"kid":"2021-05-06"},"encrypted_key":"56GVudgRLIMEElQ7DpXsijJVRSWUSDNdbWkdV3g0GUNq6hcT_GkxwnxlPIWrTXCqRpVKQC8fe4z3PQ2YH2afvjQ28aiCTWFE"}],"iv":"AAECAwQFBgcICQoLDA0ODw","ciphertext":"Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw","tag":"HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ"}
        """;

    private const string AppendixBTag = "HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ";
    private const string AppendixBPlaintext = "Three is a magic number.";


    [TestMethod]
    public void ParseRejects_Ecdh1PuKw_PairedWithA256Gcm()
    {
        //An ECDH-1PU+A256KW message naming A256GCM is the multi-recipient insider-forgery
        //vector §2.1 exists to prevent: AES-GCM is not compactly committing, so the tag
        //commitment that authenticates the sender to multiple recipients does not hold. The
        //parse boundary MUST reject it before the content is touched.
        string forged = BuildGeneralJson(
            WellKnownJweAlgorithms.Ecdh1PuA256Kw, WellKnownJweEncryptionAlgorithms.A256Gcm);

        FormatException thrown = Assert.ThrowsExactly<FormatException>(() =>
            GeneralJweParsing.ParseGeneralJson(
                forged,
                WellKnownJweAlgorithms.Ecdh1PuA256Kw,
                WellKnownJweEncryptionAlgorithms.A256Gcm,
                TestSetup.Base64UrlDecoder,
                Pool));

        Assert.Contains("ecdh-1pu-04 §2.1", thrown.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void ParseRejects_Ecdh1PuKw_PairedWithA128Gcm()
    {
        //Same gate with A128GCM: the §2.1 constraint is family-wide across AES-GCM, not
        //A256GCM-specific.
        string forged = BuildGeneralJson(
            WellKnownJweAlgorithms.Ecdh1PuA128Kw, WellKnownJweEncryptionAlgorithms.A128Gcm);

        FormatException thrown = Assert.ThrowsExactly<FormatException>(() =>
            GeneralJweParsing.ParseGeneralJson(
                forged,
                WellKnownJweAlgorithms.Ecdh1PuA128Kw,
                WellKnownJweEncryptionAlgorithms.A128Gcm,
                TestSetup.Base64UrlDecoder,
                Pool));

        Assert.Contains("ecdh-1pu-04 §2.1", thrown.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void ParseRejects_Ecdh1PuKw_PairedWithXc20p()
    {
        //XChaCha20-Poly1305 (XC20P) is not compactly committing either, so the §2.1 gate MUST reject
        //it for ECDH-1PU+A*KW exactly as it rejects the AES-GCM family — XC20P is an anoncrypt-only
        //content cipher (DIDComm v2.1 Appendix C.3 example 1 uses it under ECDH-ES, never ECDH-1PU).
        string forged = BuildGeneralJson(
            WellKnownJweAlgorithms.Ecdh1PuA256Kw, WellKnownJweEncryptionAlgorithms.XC20P);

        FormatException thrown = Assert.ThrowsExactly<FormatException>(() =>
            GeneralJweParsing.ParseGeneralJson(
                forged,
                WellKnownJweAlgorithms.Ecdh1PuA256Kw,
                WellKnownJweEncryptionAlgorithms.XC20P,
                TestSetup.Base64UrlDecoder,
                Pool));

        Assert.Contains("ecdh-1pu-04 §2.1", thrown.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    [DataRow(nameof(WellKnownJweEncryptionAlgorithms.A128Gcm))]
    [DataRow(nameof(WellKnownJweEncryptionAlgorithms.A192Gcm))]
    [DataRow(nameof(WellKnownJweEncryptionAlgorithms.A256Gcm))]
    [DataRow(nameof(WellKnownJweEncryptionAlgorithms.XC20P))]
    public async Task EncryptAuthcrypt_RejectsNonCommittingAeads(string encName)
    {
        //The encrypt-side guard: EncryptAuthcryptAsync MUST reject every non-compactly-committing enc
        //(1PU §2.1) — the whole AES-GCM family and XChaCha20-Poly1305 (XC20P).
        string contentEncryptionAlgorithm = encName switch
        {
            nameof(WellKnownJweEncryptionAlgorithms.A128Gcm) => WellKnownJweEncryptionAlgorithms.A128Gcm,
            nameof(WellKnownJweEncryptionAlgorithms.A192Gcm) => WellKnownJweEncryptionAlgorithms.A192Gcm,
            nameof(WellKnownJweEncryptionAlgorithms.A256Gcm) => WellKnownJweEncryptionAlgorithms.A256Gcm,
            nameof(WellKnownJweEncryptionAlgorithms.XC20P) => WellKnownJweEncryptionAlgorithms.XC20P,
            _ => throw new ArgumentOutOfRangeException(nameof(encName), encName, "Unexpected enc name.")
        };

        //The §2.1 gate rejects on the content algorithm before the AEAD delegate is invoked; the
        //matching delegate is supplied so the test is honest about which cipher each enc names.
        AeadEncryptDelegate aeadEncryptDelegate = encName == nameof(WellKnownJweEncryptionAlgorithms.XC20P)
            ? BouncyCastleKeyAgreementFunctions.XChaCha20Poly1305EncryptAsync
            : BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral =
            BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> sender =
            BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory senderPublic = sender.PublicKey;
        using PrivateKeyMemory senderPrivate = sender.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> bob =
            BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory bobPublic = bob.PublicKey;
        using PrivateKeyMemory bobPrivate = bob.PrivateKey;

        var recipients = new List<GeneralJweRecipientInput>
        {
            new("did:example:bob#key-1", bobPublic)
        };

        ArgumentException thrown = await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await GeneralJweEncryptionExtensions.EncryptAuthcryptAsync(
                Encoding.UTF8.GetBytes(AppendixBPlaintext),
                recipients,
                WellKnownJweAlgorithms.Ecdh1PuA256Kw,
                contentEncryptionAlgorithm,
                protectedHeaderExtras: null,
                new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
                senderPrivate,
                JwtHeaderSerializer,
                TestSetup.Base64UrlEncoder,
                CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                MicrosoftEntropyFunctions.GenerateNonce,
                BouncyCastleKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptX25519Async,
                ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
                MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
                aeadEncryptDelegate,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.Contains("ecdh-1pu-04 §2.1", thrown.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public async Task Authcrypt_TamperedTag_FailsUnwrapBeforeAead()
    {
        //The Appendix B authentication tag is committed into the KDF (1PU §2.1). Flipping one
        //byte of the serialized 'tag' derives a different key encryption key for the recipient,
        //so the RFC 3394 unwrap integrity check fails — the KEK-divergence path — before the
        //AES_CBC_HMAC_SHA2 content tag is ever verified. This is distinct from a content-tag
        //mismatch: a wrong KEK cannot even produce a candidate CEK.
        string tampered = TamperJsonValue(AppendixBGeneralJson, "tag", AppendixBTag);

        using AeadGeneralMessage message = GeneralJweParsing.ParseGeneralJson(
            tampered,
            WellKnownJweAlgorithms.Ecdh1PuA128Kw,
            WellKnownJweEncryptionAlgorithms.A256CbcHs512,
            TestSetup.Base64UrlDecoder,
            Pool);

        using PrivateKeyMemory bobPrivate = X25519PrivateKey(AppendixBBobD);
        using PublicKeyMemory aliceStaticPublic = X25519PublicKey(AppendixBAliceStaticX);

        await Assert.ThrowsExactlyAsync<CryptographicException>(async () =>
            await message.DecryptAuthcryptAsync(
                "bob-key-2",
                bobPrivate,
                aliceStaticPublic,
                BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptX25519Async,
                ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
                MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
                MicrosoftKeyAgreementFunctions.AesCbcHmacSha512DecryptAsync,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }


    //Hand-builds a minimal General JSON JWE whose protected header names the given alg/enc.
    //The protected header carries a structurally valid X25519 epk so it passes the epk shape
    //checks, but the §2.1 gate in ParseAndValidateHeader fires before the epk is decoded and
    //before any iv/ciphertext/tag length validation, so the dummy content parts are never
    //reached. The iv/ciphertext/tag/encrypted_key are arbitrary valid base64url placeholders.
    private static string BuildGeneralJson(string algorithm, string encryption)
    {
        var protectedHeader = new Dictionary<string, object>(3)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Enc] = encryption,
            [WellKnownJoseHeaderNames.Epk] = new Dictionary<string, object>(3)
            {
                [WellKnownJwkMemberNames.Kty] = WellKnownKeyTypeValues.Okp,
                [WellKnownJwkMemberNames.Crv] = "X25519",
                [WellKnownJwkMemberNames.X] = "k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc"
            }
        };

        ReadOnlySpan<byte> headerJson = JwtHeaderSerializer(new JwtHeader(protectedHeader));
        string protectedEncoded = TestSetup.Base64UrlEncoder(headerJson);

        return /*lang=json,strict*/ "{\"protected\":\"" + protectedEncoded + "\","
            + "\"recipients\":[{\"header\":{\"kid\":\"did:example:bob#key-1\"},\"encrypted_key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}],"
            + "\"iv\":\"AAAAAAAAAAAAAAAA\",\"ciphertext\":\"AAAA\",\"tag\":\"AAAAAAAAAAAAAAAAAAAAAA\"}";
    }


    private static PublicKeyMemory X25519PublicKey(string xBase64Url)
    {
        using IMemoryOwner<byte> x = TestSetup.Base64UrlDecoder(xBase64Url, Pool);
        IMemoryOwner<byte> keyOwner = Pool.Rent(x.Memory.Length);
        x.Memory.CopyTo(keyOwner.Memory);

        return new PublicKeyMemory(keyOwner, CryptoTags.X25519PublicKey);
    }


    private static PrivateKeyMemory X25519PrivateKey(string dBase64Url)
    {
        using IMemoryOwner<byte> d = TestSetup.Base64UrlDecoder(dBase64Url, Pool);
        IMemoryOwner<byte> keyOwner = Pool.Rent(d.Memory.Length);
        d.Memory.CopyTo(keyOwner.Memory);

        return new PrivateKeyMemory(keyOwner, CryptoTags.X25519PrivateKey);
    }


    //Flips the first character of a base64url value inside the General JSON to corrupt it
    //while keeping it valid base64url and the same length.
    private static string TamperJsonValue(string json, string member, string originalValue)
    {
        char[] chars = originalValue.ToCharArray();
        chars[0] = chars[0] == 'A' ? 'B' : 'A';
        string tampered = new(chars);

        return json.Replace($"\"{member}\":\"{originalValue}\"", $"\"{member}\":\"{tampered}\"", StringComparison.Ordinal);
    }
}
