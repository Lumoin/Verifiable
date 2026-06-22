using System.Buffers;
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
/// Encrypt → serialize → parse → decrypt round trips for the JWE General JSON Serialization
/// (RFC 7516 §7.2) that extend <see cref="GeneralJweTests"/> to the content-encryption sizes
/// (A128/A192 GCM, A128CBC-HS256, A192CBC-HS384) and the wrap sizes (ECDH-ES+A128KW /
/// +A192KW, ECDH-1PU+A192KW) that file omits, plus a non-empty <c>apu</c>/<c>apv</c> KDF path.
/// </summary>
[TestClass]
internal sealed class GeneralJweEncRoundTripTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private static readonly JwtHeaderSerializer JwtHeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);


    [TestMethod]
    public async Task AnoncryptRoundTrip_A128Gcm_EcdhEsA128Kw()
    {
        //P-256 anoncrypt, A128GCM content encryption, ECDH-ES+A128KW (16-byte wrapped CEK).
        await AnoncryptRoundTripAsync(
            MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys,
            MicrosoftKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptP256Async,
            MicrosoftKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
            WellKnownJweAlgorithms.EcdhEsA128Kw,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            MicrosoftKeyAgreementFunctions.AesGcmEncryptAsync,
            MicrosoftKeyAgreementFunctions.AesGcmDecryptAsync).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task AnoncryptRoundTrip_A192Gcm_EcdhEsA192Kw()
    {
        //P-256 anoncrypt, A192GCM content encryption, ECDH-ES+A192KW (24-byte wrapped CEK).
        await AnoncryptRoundTripAsync(
            MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys,
            MicrosoftKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptP256Async,
            MicrosoftKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
            WellKnownJweAlgorithms.EcdhEsA192Kw,
            WellKnownJweEncryptionAlgorithms.A192Gcm,
            MicrosoftKeyAgreementFunctions.AesGcmEncryptAsync,
            MicrosoftKeyAgreementFunctions.AesGcmDecryptAsync).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task AnoncryptRoundTrip_A128CbcHs256_EcdhEsA128Kw()
    {
        //P-256 anoncrypt, A128CBC-HS256 content encryption (32-byte composite CEK),
        //ECDH-ES+A128KW (16-byte KEK).
        await AnoncryptRoundTripAsync(
            MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys,
            MicrosoftKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptP256Async,
            MicrosoftKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
            WellKnownJweAlgorithms.EcdhEsA128Kw,
            WellKnownJweEncryptionAlgorithms.A128CbcHs256,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha256EncryptAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha256DecryptAsync).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task AnoncryptRoundTrip_A192CbcHs384_EcdhEsA192Kw()
    {
        //P-256 anoncrypt, A192CBC-HS384 content encryption (48-byte composite CEK),
        //ECDH-ES+A192KW (24-byte KEK).
        await AnoncryptRoundTripAsync(
            MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys,
            MicrosoftKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptP256Async,
            MicrosoftKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
            WellKnownJweAlgorithms.EcdhEsA192Kw,
            WellKnownJweEncryptionAlgorithms.A192CbcHs384,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha384EncryptAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha384DecryptAsync).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task AuthcryptRoundTrip_A256CbcHs512_Ecdh1PuA192Kw()
    {
        //X25519 authcrypt, A256CBC-HS512 content encryption, ECDH-1PU+A192KW — the +A192KW
        //wrap size GeneralJweTests omits (it exercises +A256KW). The 64-byte composite CEK is
        //wrapped under a 24-byte tag-committed KEK.
        await AuthcryptRoundTripAsync(
            BouncyCastleKeyMaterialCreator.CreateX25519Keys,
            BouncyCastleKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptX25519Async,
            BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptX25519Async,
            WellKnownJweAlgorithms.Ecdh1PuA192Kw,
            protectedHeaderExtras: null,
            assertParsedHeader: null).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task AuthcryptRoundTrip_WithApuApvProtectedHeaderExtras()
    {
        //X25519 authcrypt with ECDH-1PU+A256KW and A256CBC-HS512 (the known-good combo from
        //GeneralJweTests), but driven with a non-null protectedHeaderExtras carrying apu, apv,
        //and skid. This exercises the KDF path with non-empty PartyUInfo/PartyVInfo, not just
        //the null-extras path. After ParseGeneralJson the parsed header must surface the exact
        //apu/apv base64url strings placed into the protected header.
        const string senderKeyId = "did:example:alice#key-x25519-1";
        string apu = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(senderKeyId));
        string apv = JweAgreementInfo.ComputeApvFromRecipientKeyIds(
            ["did:example:recipient-0#key-1", "did:example:recipient-1#key-1"],
            TestSetup.Base64UrlEncoder,
            Pool);

        var extras = new Dictionary<string, object>(3)
        {
            [WellKnownJoseHeaderNames.Apu] = apu,
            [WellKnownJoseHeaderNames.Apv] = apv,
            [WellKnownJoseHeaderNames.Skid] = senderKeyId
        };

        await AuthcryptRoundTripAsync(
            BouncyCastleKeyMaterialCreator.CreateX25519Keys,
            BouncyCastleKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptX25519Async,
            BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptX25519Async,
            WellKnownJweAlgorithms.Ecdh1PuA256Kw,
            extras,
            assertParsedHeader: header =>
            {
                Assert.IsTrue(header.TryGetValue(WellKnownJoseHeaderNames.Apu, out object? parsedApu),
                    "The parsed protected header must surface the 'apu' parameter.");
                Assert.AreEqual(apu, parsedApu as string,
                    "The parsed 'apu' must equal the base64url PartyUInfo placed into the protected header.");

                Assert.IsTrue(header.TryGetValue(WellKnownJoseHeaderNames.Apv, out object? parsedApv),
                    "The parsed protected header must surface the 'apv' parameter.");
                Assert.AreEqual(apv, parsedApv as string,
                    "The parsed 'apv' must equal the base64url PartyVInfo placed into the protected header.");
            }).ConfigureAwait(false);
    }


    //Anoncrypt round trip parameterized over the content encryption algorithm and its AEAD
    //delegate pair: encrypt to two recipients with one shared ephemeral key, serialize to
    //General JSON, reparse, and decrypt every recipient back to the original plaintext.
    private async Task AnoncryptRoundTripAsync(
        Func<MemoryPool<byte>, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> createKeys,
        MultiRecipientKeyAgreementEncryptDelegate encryptAgreement,
        KeyAgreementDecryptDelegate decryptAgreement,
        string keyManagementAlgorithm,
        string contentEncryptionAlgorithm,
        AeadEncryptDelegate aeadEncrypt,
        AeadDecryptDelegate aeadDecrypt)
    {
        const int recipientCount = 2;
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
                keyManagementAlgorithm,
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
                Assert.HasCount(recipientCount, encrypted.Recipients, "Every recipient must get an encrypted_key entry.");
                generalJson = encrypted.ToGeneralJson(TestSetup.Base64UrlEncoder);
            }

            using AeadGeneralMessage parsed = GeneralJweParsing.ParseGeneralJson(
                generalJson,
                keyManagementAlgorithm,
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
                    $"Anoncrypt recipient {i} must recover the original plaintext with {keyManagementAlgorithm}/{contentEncryptionAlgorithm}.");
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


    //Authcrypt round trip parameterized over the key management (wrap) algorithm and an
    //optional protectedHeaderExtras dictionary. The content encryption is fixed at
    //A256CBC-HS512 (a compactly committing AEAD, the only family 1PU §2.1 permits). When
    //assertParsedHeader is non-null it inspects the reparsed protected header.
    private async Task AuthcryptRoundTripAsync(
        Func<MemoryPool<byte>, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> createKeys,
        MultiRecipientAuthenticatedKeyAgreementEncryptDelegate encryptAgreement,
        AuthenticatedKeyAgreementDecryptDelegate decryptAgreement,
        string keyManagementAlgorithm,
        IReadOnlyDictionary<string, object>? protectedHeaderExtras,
        Action<IReadOnlyDictionary<string, object>>? assertParsedHeader)
    {
        const int recipientCount = 2;
        string contentEncryptionAlgorithm = WellKnownJweEncryptionAlgorithms.A256CbcHs512;
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
                keyManagementAlgorithm,
                contentEncryptionAlgorithm,
                protectedHeaderExtras,
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
                keyManagementAlgorithm,
                contentEncryptionAlgorithm,
                TestSetup.Base64UrlDecoder,
                Pool);

            assertParsedHeader?.Invoke(parsed.Header);

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
                    $"Authcrypt recipient {i} must recover the original plaintext with {keyManagementAlgorithm}/{contentEncryptionAlgorithm}.");
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
}
