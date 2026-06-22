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
/// Tests for the JWE General JSON Serialization (RFC 7516 §7.2) with multi-recipient
/// support: anoncrypt (ECDH-ES+A*KW) and authcrypt (ECDH-1PU+A*KW) for DIDComm v2. The
/// conformance vector is the complete multi-recipient JWE of draft-madden-jose-ecdh-1pu-04
/// Appendix B.11 (X25519, ECDH-1PU+A128KW, A256CBC-HS512, two recipients).
/// </summary>
[TestClass]
internal sealed class GeneralJweTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private static readonly JwtHeaderSerializer JwtHeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    //Appendix B static keys (X25519, JWK base64url coordinates).
    private const string AppendixBAliceStaticX = "Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4";
    private const string AppendixBBobD = "1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg";
    private const string AppendixBCharlieD = "Jcv8gklhMjC0b-lsk5onBbppWAx5ncNtbM63Jr9xBQE";

    //The complete Appendix B.11 General JSON Serialization with the display line breaks
    //inside the base64url values removed. The 'unprotected' { "jku" } member is present in
    //the vector and is ignored by the parser, as RFC 7516 §7.2.1 permits.
    private const string AppendixBGeneralJson =
        /*lang=json,strict*/ """
        {"protected":"eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjoiUVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFBRnFVQUZhMzlkeUJjIn19","unprotected":{"jku":"https://alice.example.com/keys.jwks"},"recipients":[{"header":{"kid":"bob-key-2"},"encrypted_key":"pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQeU1cSl55cQ0hGezJu2N9IY0QN"},{"header":{"kid":"2021-05-06"},"encrypted_key":"56GVudgRLIMEElQ7DpXsijJVRSWUSDNdbWkdV3g0GUNq6hcT_GkxwnxlPIWrTXCqRpVKQC8fe4z3PQ2YH2afvjQ28aiCTWFE"}],"iv":"AAECAwQFBgcICQoLDA0ODw","ciphertext":"Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw","tag":"HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ"}
        """;

    private const string AppendixBPlaintext = "Three is a magic number.";


    [TestMethod]
    [DataRow("bob-key-2", AppendixBBobD)]
    [DataRow("2021-05-06", AppendixBCharlieD)]
    public async Task AppendixBVectorDecryptsForBothRecipients(string kid, string recipientD)
    {
        using AeadGeneralMessage message = GeneralJweParsing.ParseGeneralJson(
            AppendixBGeneralJson,
            WellKnownJweAlgorithms.Ecdh1PuA128Kw,
            WellKnownJweEncryptionAlgorithms.A256CbcHs512,
            TestSetup.Base64UrlDecoder,
            Pool);

        Assert.HasCount(2, message.Recipients, "The Appendix B vector has exactly two recipients.");

        using PrivateKeyMemory recipientPrivate = X25519PrivateKey(recipientD);
        using PublicKeyMemory aliceStaticPublic = X25519PublicKey(AppendixBAliceStaticX);

        using DecryptedContent decrypted = await message.DecryptAuthcryptAsync(
            kid,
            recipientPrivate,
            aliceStaticPublic,
            BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptX25519Async,
            ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512DecryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AppendixBPlaintext, Encoding.UTF8.GetString(decrypted.AsReadOnlySpan()),
            $"Recipient '{kid}' must decrypt the Appendix B vector to the magic-number plaintext.");
    }


    [TestMethod]
    public async Task AuthcryptX25519MultiRecipientRoundTripBouncyCastle()
    {
        await AuthcryptRoundTripAsync(
            BouncyCastleKeyMaterialCreator.CreateX25519Keys,
            BouncyCastleKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptX25519Async,
            BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptX25519Async,
            recipientCount: 3).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task AuthcryptP256MultiRecipientRoundTripMicrosoft()
    {
        await AuthcryptRoundTripAsync(
            MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys,
            MicrosoftKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptP256Async,
            MicrosoftKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptP256Async,
            recipientCount: 2).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task AuthcryptP256MultiRecipientRoundTripCrossDriver()
    {
        //Encrypt side BouncyCastle, decrypt side Microsoft: proves the shared epk and the
        //P-256 shared-secret padding agree across drivers for the multi-recipient seam.
        await AuthcryptRoundTripAsync(
            BouncyCastleKeyMaterialCreator.CreateP256ExchangeKeys,
            BouncyCastleKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptP256Async,
            MicrosoftKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptP256Async,
            recipientCount: 2).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task AnoncryptX25519RoundTripWithA256Gcm()
    {
        await AnoncryptRoundTripAsync(
            BouncyCastleKeyMaterialCreator.CreateX25519Keys,
            BouncyCastleKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptX25519Async,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptX25519Async,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
            recipientCount: 2).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task AnoncryptP256RoundTripWithA256CbcHs512()
    {
        await AnoncryptRoundTripAsync(
            MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys,
            MicrosoftKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptP256Async,
            MicrosoftKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
            WellKnownJweEncryptionAlgorithms.A256CbcHs512,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512EncryptAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512DecryptAsync,
            recipientCount: 2).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task AuthcryptRejectsNonCommittingContentEncryptionAlgorithm()
    {
        //1PU §2.1: Key Agreement with Key Wrapping MUST only be used with the
        //AES_CBC_HMAC_SHA2 family. A256GCM is not compactly committing and must be rejected.
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

        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await GeneralJweEncryptionExtensions.EncryptAuthcryptAsync(
                Encoding.UTF8.GetBytes(AppendixBPlaintext),
                recipients,
                WellKnownJweAlgorithms.Ecdh1PuA256Kw,
                WellKnownJweEncryptionAlgorithms.A256Gcm,
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
                BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);
    }


    [TestMethod]
    public async Task AuthcryptTamperedTagPreventsUnwrapBeforeAeadCheck()
    {
        //The Appendix B authentication tag is committed into the KDF. Tampering it derives a
        //different key encryption key, so the RFC 3394 unwrap integrity check fails — proving
        //the tag is bound before the AEAD content tag is even reached.
        string tampered = TamperJsonValue(AppendixBGeneralJson, "tag", "HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ");

        using AeadGeneralMessage message = GeneralJweParsing.ParseGeneralJson(
            tampered,
            WellKnownJweAlgorithms.Ecdh1PuA128Kw,
            WellKnownJweEncryptionAlgorithms.A256CbcHs512,
            TestSetup.Base64UrlDecoder,
            Pool);

        using PrivateKeyMemory bobPrivate = X25519PrivateKey(AppendixBBobD);
        using PublicKeyMemory aliceStaticPublic = X25519PublicKey(AppendixBAliceStaticX);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await message.DecryptAuthcryptAsync(
                "bob-key-2",
                bobPrivate,
                aliceStaticPublic,
                BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptX25519Async,
                ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
                MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
                MicrosoftKeyAgreementFunctions.AesCbcHmacSha512DecryptAsync,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);
    }


    [TestMethod]
    public void ApvRecipeMatchesSortedHashedKidList()
    {
        //DIDComm v2: apv = base64url(SHA-256(sorted(kids) joined with ".")). The helper sorts
        //alphanumerically, so the input order must not affect the result, and the result must
        //match an independent computation over the sorted-and-joined string.
        string[] kids = ["2021-05-06", "bob-key-2"];
        string apvFromHelper = JweAgreementInfo.ComputeApvFromRecipientKeyIds(
            kids,
            TestSetup.Base64UrlEncoder,
            Pool);

        //Independent reference: sort ordinally, join with '.', SHA-256, base64url.
        string[] sorted = ["2021-05-06", "bob-key-2"];
        Array.Sort(sorted, StringComparer.Ordinal);
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('.', sorted)));
        string expected = TestSetup.Base64UrlEncoder(hash);

        Assert.AreEqual(expected, apvFromHelper, "The apv recipe must equal base64url(SHA-256(sorted kids joined with '.')).");

        //Reversed input order must yield the same apv because the helper sorts.
        string apvReversedInput = JweAgreementInfo.ComputeApvFromRecipientKeyIds(
            ["bob-key-2", "2021-05-06"],
            TestSetup.Base64UrlEncoder,
            Pool);

        Assert.AreEqual(apvFromHelper, apvReversedInput, "apv must be independent of recipient kid input order.");
    }


    [TestMethod]
    public void RegistryResolvesMultiRecipientAgreementDelegates()
    {
        Assert.IsNotNull(KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveMultiRecipientAgreementEncrypt(
            CryptoAlgorithm.X25519, Purpose.Exchange));
        Assert.IsNotNull(KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveMultiRecipientAgreementEncrypt(
            CryptoAlgorithm.P256, Purpose.Exchange));
        Assert.IsNotNull(KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveMultiRecipientAuthenticatedAgreementEncrypt(
            CryptoAlgorithm.X25519, Purpose.Exchange));
        Assert.IsNotNull(KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveMultiRecipientAuthenticatedAgreementEncrypt(
            CryptoAlgorithm.P256, Purpose.Exchange));
    }


    [TestMethod]
    public void ApuRecipeIsBase64UrlOfSenderKeyId()
    {
        const string senderKeyId = "did:example:alice#key-x25519-1";
        string apu = JweAgreementInfo.ComputeApuFromSenderKeyId(senderKeyId, TestSetup.Base64UrlEncoder, Pool);

        string expected = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(senderKeyId));
        Assert.AreEqual(expected, apu, "apu must be base64url(UTF8(skid)).");
    }


    //Drives a full authcrypt round trip: encrypt to N recipients with one shared ephemeral
    //key, serialize to General JSON, reparse, and decrypt every recipient. Also asserts that
    //a non-recipient key fails to find an entry.
    private async Task AuthcryptRoundTripAsync(
        Func<MemoryPool<byte>, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> createKeys,
        MultiRecipientAuthenticatedKeyAgreementEncryptDelegate encryptAgreement,
        AuthenticatedKeyAgreementDecryptDelegate decryptAgreement,
        int recipientCount)
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(/*lang=json,strict*/ "{\"type\":\"https://didcomm.org/basicmessage/2.0/message\"}");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = createKeys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> sender = createKeys(Pool);
        using PublicKeyMemory senderPublic = sender.PublicKey;
        using PrivateKeyMemory senderPrivate = sender.PrivateKey;

        var recipientKeys = new List<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>>();
        var recipientInputs = new List<GeneralJweRecipientInput>();
        try
        {
            for(int i = 0; i < recipientCount; ++i)
            {
                PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> r = createKeys(Pool);
                recipientKeys.Add(r);
                recipientInputs.Add(new GeneralJweRecipientInput($"did:example:recipient-{i}#key-1", r.PublicKey));
            }

            string generalJson;
            using(GeneralJweMessage encrypted = await GeneralJweEncryptionExtensions.EncryptAuthcryptAsync(
                plaintext,
                recipientInputs,
                WellKnownJweAlgorithms.Ecdh1PuA256Kw,
                WellKnownJweEncryptionAlgorithms.A256CbcHs512,
                protectedHeaderExtras: null,
                new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
                senderPrivate,
                JwtHeaderSerializer,
                TestSetup.Base64UrlEncoder,
                CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                MicrosoftEntropyFunctions.GenerateNonce,
                encryptAgreement,
                ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
                MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
                MicrosoftKeyAgreementFunctions.AesCbcHmacSha512EncryptAsync,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false))
            {
                Assert.HasCount(recipientCount, encrypted.Recipients, "Every recipient must get an encrypted_key entry.");
                generalJson = encrypted.ToGeneralJson(TestSetup.Base64UrlEncoder);
            }

            using AeadGeneralMessage parsed = GeneralJweParsing.ParseGeneralJson(
                generalJson,
                WellKnownJweAlgorithms.Ecdh1PuA256Kw,
                WellKnownJweEncryptionAlgorithms.A256CbcHs512,
                TestSetup.Base64UrlDecoder,
                Pool);

            for(int i = 0; i < recipientCount; ++i)
            {
                using PrivateKeyMemory recipientPrivate = recipientKeys[i].PrivateKey;
                using DecryptedContent decrypted = await parsed.DecryptAuthcryptAsync(
                    $"did:example:recipient-{i}#key-1",
                    recipientPrivate,
                    senderPublic,
                    decryptAgreement,
                    ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
                    MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
                    MicrosoftKeyAgreementFunctions.AesCbcHmacSha512DecryptAsync,
                    Pool,
                    TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(decrypted.AsReadOnlySpan().SequenceEqual(plaintext),
                    $"Recipient {i} must recover the original plaintext.");
            }

            //A non-recipient kid has no entry and must fail to select.
            using PrivateKeyMemory outsiderPrivate = createKeys(Pool).PrivateKey;
            await Assert.ThrowsAsync<FormatException>(async () =>
                await parsed.DecryptAuthcryptAsync(
                    "did:example:outsider#key-1",
                    outsiderPrivate,
                    senderPublic,
                    decryptAgreement,
                    ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
                    MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
                    MicrosoftKeyAgreementFunctions.AesCbcHmacSha512DecryptAsync,
                    Pool,
                    TestContext.CancellationToken).ConfigureAwait(false))
                .ConfigureAwait(false);
        }
        finally
        {
            foreach(PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> r in recipientKeys)
            {
                r.PublicKey.Dispose();
            }
        }
    }


    //Drives a full anoncrypt round trip: encrypt to N recipients with one shared ephemeral
    //key (no sender key), serialize to General JSON, reparse, and decrypt every recipient.
    private async Task AnoncryptRoundTripAsync(
        Func<MemoryPool<byte>, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> createKeys,
        MultiRecipientKeyAgreementEncryptDelegate encryptAgreement,
        KeyAgreementDecryptDelegate decryptAgreement,
        string contentEncryptionAlgorithm,
        AeadEncryptDelegate aeadEncrypt,
        AeadDecryptDelegate aeadDecrypt,
        int recipientCount)
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(/*lang=json,strict*/ "{\"type\":\"https://didcomm.org/routing/2.0/forward\"}");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = createKeys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        var recipientKeys = new List<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>>();
        var recipientInputs = new List<GeneralJweRecipientInput>();
        try
        {
            for(int i = 0; i < recipientCount; ++i)
            {
                PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> r = createKeys(Pool);
                recipientKeys.Add(r);
                recipientInputs.Add(new GeneralJweRecipientInput($"did:example:recipient-{i}#key-1", r.PublicKey));
            }

            string generalJson;
            using(GeneralJweMessage encrypted = await GeneralJweEncryptionExtensions.EncryptAnoncryptAsync(
                plaintext,
                recipientInputs,
                WellKnownJweAlgorithms.EcdhEsA256Kw,
                contentEncryptionAlgorithm,
                protectedHeaderExtras: null,
                new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
                JwtHeaderSerializer,
                TestSetup.Base64UrlEncoder,
                CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                MicrosoftEntropyFunctions.GenerateNonce,
                encryptAgreement,
                ConcatKdf.DefaultKeyDerivationDelegate,
                MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
                aeadEncrypt,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false))
            {
                generalJson = encrypted.ToGeneralJson(TestSetup.Base64UrlEncoder);
            }

            using AeadGeneralMessage parsed = GeneralJweParsing.ParseGeneralJson(
                generalJson,
                WellKnownJweAlgorithms.EcdhEsA256Kw,
                contentEncryptionAlgorithm,
                TestSetup.Base64UrlDecoder,
                Pool);

            for(int i = 0; i < recipientCount; ++i)
            {
                using PrivateKeyMemory recipientPrivate = recipientKeys[i].PrivateKey;
                using DecryptedContent decrypted = await parsed.DecryptAnoncryptAsync(
                    $"did:example:recipient-{i}#key-1",
                    recipientPrivate,
                    decryptAgreement,
                    ConcatKdf.DefaultKeyDerivationDelegate,
                    MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
                    aeadDecrypt,
                    Pool,
                    TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(decrypted.AsReadOnlySpan().SequenceEqual(plaintext),
                    $"Anoncrypt recipient {i} must recover the original plaintext with {contentEncryptionAlgorithm}.");
            }
        }
        finally
        {
            foreach(PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> r in recipientKeys)
            {
                r.PublicKey.Dispose();
            }
        }
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
