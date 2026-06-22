using System.Buffers;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.DidComm;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Verifies the DIDComm v2.1 anoncrypt (ECDH-ES key wrapping) pack/unpack pipeline
/// (<see cref="DidCommEncryptedExtensions"/>): pack→unpack round trips across curves
/// (P-256 / X25519) and content-encryption families (A256CBC-HS512 / A256GCM) over both the
/// delegate-taking and registry-resolving overloads, multi-recipient delivery, the common
/// protected-header shape, and the advisory <c>to</c>-addressing signal.
/// </summary>
[TestClass]
internal sealed class DidCommEncryptedAnoncryptRoundTripTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;

    //A non-network resolution context; it only satisfies the SSRF-policy-carrying parameter.
    private static readonly ExchangeContext Context = new();

    //A non-nested anoncrypt message never triggers nested-signature resolution, so this resolver is never
    //invoked; it satisfies the unpack overload's resolver parameter.
    private static readonly DidResolver NestedSignerResolver = new DidResolver(DidMethodSelectors.FromResolvers(
        ("did:example", (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Failure(DidResolutionErrors.NotFound)))));

    //The protected-header serializer, mirroring GeneralJweEncRoundTripTests: the headers are a
    //Dictionary<string, object> the JWE layer hands to this delegate to produce the UTF-8 JSON bytes.
    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private const string MessageId = "1234567890";
    private const string MessageType = "https://example.com/protocols/lets_do_lunch/1.0/proposal";
    private const string AliceDid = "did:example:alice";
    private const string BobDid = "did:example:bob";
    private const string BobKid = "did:example:bob#key-1";


    /// <summary>
    /// The P-256 + A256CBC-HS512 anoncrypt combination round trips through the delegate-taking overloads
    /// and recovers the original plaintext, with the anoncrypt sender-anonymity invariants surfaced.
    /// </summary>
    [TestMethod]
    public async Task DelegateRoundTrip_P256_A256CbcHs512()
    {
        await AssertDelegateRoundTripAsync(
            MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys,
            MicrosoftKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptP256Async,
            MicrosoftKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
            WellKnownJweEncryptionAlgorithms.A256CbcHs512,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512EncryptAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512DecryptAsync).ConfigureAwait(false);
    }


    /// <summary>The P-256 + A256GCM anoncrypt combination round trips through the delegate-taking overloads.</summary>
    [TestMethod]
    public async Task DelegateRoundTrip_P256_A256Gcm()
    {
        await AssertDelegateRoundTripAsync(
            MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys,
            MicrosoftKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptP256Async,
            MicrosoftKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync).ConfigureAwait(false);
    }


    /// <summary>The X25519 + A256CBC-HS512 anoncrypt combination round trips through the delegate-taking overloads.</summary>
    [TestMethod]
    public async Task DelegateRoundTrip_X25519_A256CbcHs512()
    {
        await AssertDelegateRoundTripAsync(
            BouncyCastleKeyMaterialCreator.CreateX25519Keys,
            BouncyCastleKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptX25519Async,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptX25519Async,
            WellKnownJweEncryptionAlgorithms.A256CbcHs512,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512EncryptAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512DecryptAsync).ConfigureAwait(false);
    }


    /// <summary>The X25519 + A256GCM anoncrypt combination round trips through the delegate-taking overloads.</summary>
    [TestMethod]
    public async Task DelegateRoundTrip_X25519_A256Gcm()
    {
        await AssertDelegateRoundTripAsync(
            BouncyCastleKeyMaterialCreator.CreateX25519Keys,
            BouncyCastleKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptX25519Async,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptX25519Async,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync).ConfigureAwait(false);
    }


    /// <summary>The P-256 + A256GCM anoncrypt combination round trips through the registry-resolving overloads.</summary>
    [TestMethod]
    public async Task RegistryRoundTrip_P256_A256Gcm()
    {
        await AssertRegistryRoundTripAsync(MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys, WellKnownJweEncryptionAlgorithms.A256Gcm).ConfigureAwait(false);
    }


    /// <summary>The X25519 + A256GCM anoncrypt combination round trips through the registry-resolving overloads.</summary>
    [TestMethod]
    public async Task RegistryRoundTrip_X25519_A256Gcm()
    {
        await AssertRegistryRoundTripAsync(BouncyCastleKeyMaterialCreator.CreateX25519Keys, WellKnownJweEncryptionAlgorithms.A256Gcm).ConfigureAwait(false);
    }


    /// <summary>
    /// The X25519 + XC20P anoncrypt combination (DIDComm v2.1 Appendix C.3 example 1's profile) round trips
    /// through the delegate-taking overloads, exercising the XChaCha20-Poly1305 ENCRYPT path the C.3 vector
    /// (decrypt only) does not.
    /// </summary>
    [TestMethod]
    public async Task DelegateRoundTrip_X25519_XC20P()
    {
        await AssertDelegateRoundTripAsync(
            BouncyCastleKeyMaterialCreator.CreateX25519Keys,
            BouncyCastleKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptX25519Async,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptX25519Async,
            WellKnownJweEncryptionAlgorithms.XC20P,
            BouncyCastleKeyAgreementFunctions.XChaCha20Poly1305EncryptAsync,
            BouncyCastleKeyAgreementFunctions.XChaCha20Poly1305DecryptAsync).ConfigureAwait(false);
    }


    /// <summary>The X25519 + XC20P anoncrypt combination round trips through the registry-resolving overloads,
    /// which resolve XChaCha20-Poly1305 from the wire <c>enc</c> qualifier.</summary>
    [TestMethod]
    public async Task RegistryRoundTrip_X25519_XC20P()
    {
        await AssertRegistryRoundTripAsync(BouncyCastleKeyMaterialCreator.CreateX25519Keys, WellKnownJweEncryptionAlgorithms.XC20P).ConfigureAwait(false);
    }


    /// <summary>
    /// The registry-resolving pack overload rejects an AES_CBC_HMAC_SHA2 content algorithm — the registry
    /// maps a key-agreement key to AES-GCM, so a CBC <c>enc</c> must use the delegate-taking overload.
    /// </summary>
    [TestMethod]
    public async Task RegistryPackRejectsCbcEnc()
    {
        var message = NewMessage([BobDid]);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        var recipients = new List<GeneralJweRecipientInput> { new(BobKid, recipientPublic) };

        await Assert.ThrowsExactlyAsync<NotSupportedException>(async () =>
            await message.PackAnoncryptAsync(
                recipients,
                WellKnownJweAlgorithms.EcdhEsA256Kw,
                WellKnownJweEncryptionAlgorithms.A256CbcHs512,
                new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
                DidCommMessageJson.Serializer,
                HeaderSerializer,
                TestSetup.Base64UrlEncoder,
                CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                MicrosoftEntropyFunctions.GenerateNonce,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }


    /// <summary>
    /// A message anoncrypted to three recipients decrypts for each of them and recovers the same plaintext,
    /// while an outsider holding a different private key for a valid <c>kid</c> fails to decrypt.
    /// </summary>
    [TestMethod]
    public async Task MultiRecipientRoundTripAndOutsiderRejected()
    {
        const int recipientCount = 3;
        var message = NewMessage([BobDid]);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        var recipientKeys = new List<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>>();
        var recipientInputs = new List<GeneralJweRecipientInput>();
        var recipientKids = new List<string>();
        try
        {
            for(int i = 0; i < recipientCount; ++i)
            {
                PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> r = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
                recipientKeys.Add(r);
                string kid = $"did:example:recipient-{i}#key-1";
                recipientKids.Add(kid);
                recipientInputs.Add(new GeneralJweRecipientInput(kid, r.PublicKey));
            }

            using DidCommEncryptedMessage encrypted = await message.PackAnoncryptAsync(
                recipientInputs,
                WellKnownJweAlgorithms.EcdhEsA256Kw,
                WellKnownJweEncryptionAlgorithms.A256Gcm,
                new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
                DidCommMessageJson.Serializer,
                HeaderSerializer,
                TestSetup.Base64UrlEncoder,
                CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                MicrosoftEntropyFunctions.GenerateNonce,
                BouncyCastleKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptP256Async,
                ConcatKdf.DefaultKeyDerivationDelegate,
                MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
                BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

            for(int i = 0; i < recipientCount; ++i)
            {
                using PrivateKeyMemory recipientPrivate = recipientKeys[i].PrivateKey;
                DidCommEncryptedUnpackResult result = await encrypted.UnpackAnoncryptAsync(
                    recipientKids[i],
                    recipientPrivate,
                    NestedSignerResolver,
                    Context,
                    DidCommMessageJson.Parser,
                    DidCommSignedMessageJson.Parser,
                    TestSetup.Base64UrlDecoder,
                    TestSetup.Base64UrlEncoder,
                    MicrosoftKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
                    ConcatKdf.DefaultKeyDerivationDelegate,
                    MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
                    BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
                    Pool,
                    TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(result.IsUnpacked, $"Recipient {i} MUST unpack. Error: {result.Error}.");
                Assert.AreEqual(DidCommDecryptionError.None, result.Error);
                AssertRecoveredMessage(result.Message, [BobDid]);
            }

            //An outsider with a different keypair but presenting one of the valid kids fails the AEAD/unwrap.
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> outsider = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
            using PublicKeyMemory outsiderPublic = outsider.PublicKey;
            using PrivateKeyMemory outsiderPrivate = outsider.PrivateKey;

            DidCommEncryptedUnpackResult outsiderResult = await encrypted.UnpackAnoncryptAsync(
                recipientKids[0],
                outsiderPrivate,
                NestedSignerResolver,
                Context,
                DidCommMessageJson.Parser,
                DidCommSignedMessageJson.Parser,
                TestSetup.Base64UrlDecoder,
                TestSetup.Base64UrlEncoder,
                MicrosoftKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
                ConcatKdf.DefaultKeyDerivationDelegate,
                MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
                BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(outsiderResult.IsUnpacked, "An outsider key MUST NOT unpack the message.");
            Assert.AreEqual(DidCommDecryptionError.DecryptionFailed, outsiderResult.Error);
            Assert.IsNull(outsiderResult.Message);
        }
        finally
        {
            foreach(PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> r in recipientKeys)
            {
                r.PublicKey.Dispose();
            }
        }
    }


    /// <summary>
    /// The packed envelope's common protected header carries <c>apv</c>, the encrypted media <c>typ</c>,
    /// <c>epk</c>, <c>enc</c>, and <c>alg</c>, and — per the ECDH-ES profile — neither <c>apu</c> nor
    /// <c>skid</c> (anoncrypt has no sender identifier).
    /// </summary>
    [TestMethod]
    public async Task ProtectedHeaderShapeIsAnoncrypt()
    {
        var message = NewMessage([BobDid]);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        var recipients = new List<GeneralJweRecipientInput> { new(BobKid, recipientPublic) };

        using DidCommEncryptedMessage encrypted = await message.PackAnoncryptAsync(
            recipients,
            WellKnownJweAlgorithms.EcdhEsA256Kw,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            DidCommMessageJson.Serializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            BouncyCastleKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        string protectedHeaderJson = DecodeProtectedHeader(encrypted);

        Assert.Contains("\"apv\"", protectedHeaderJson, StringComparison.Ordinal);
        Assert.Contains("\"epk\"", protectedHeaderJson, StringComparison.Ordinal);
        Assert.Contains("\"enc\"", protectedHeaderJson, StringComparison.Ordinal);
        Assert.Contains("\"alg\"", protectedHeaderJson, StringComparison.Ordinal);

        //The typ value carries a '+', which System.Text.Json escapes to + in the serialized JSON;
        //read the value through the JSON reader (which unescapes it) rather than matching the raw string.
        string? protectedEncoded = JwkJsonReader.ExtractStringValue(encrypted.AsReadOnlySpan(), "protected"u8);
        Assert.IsNotNull(protectedEncoded);
        using IMemoryOwner<byte> typHeaderOwner = TestSetup.Base64UrlDecoder(protectedEncoded!, Pool);
        string? typ = JwkJsonReader.ExtractStringValue(typHeaderOwner.Memory.Span, "typ"u8);
        Assert.AreEqual(DidCommMediaTypes.Encrypted, typ, "The anoncrypt protected header typ MUST be the encrypted media type.");

        //ECDH-ES carries no sender: apu and skid MUST be absent (DIDComm v2.1 §ECDH-ES key wrapping).
        Assert.IsFalse(
            protectedHeaderJson.Contains("\"apu\"", StringComparison.Ordinal),
            "An anoncrypt protected header MUST NOT carry 'apu'.");
        Assert.IsFalse(
            protectedHeaderJson.Contains("\"skid\"", StringComparison.Ordinal),
            "An anoncrypt protected header MUST NOT carry 'skid'.");
    }


    /// <summary>
    /// When the recipient's DID appears in <c>to</c>, the advisory addressing signal is set.
    /// </summary>
    [TestMethod]
    public async Task ToAddressing_RecipientListed_IsAddressed()
    {
        DidCommEncryptedUnpackResult result = await ToAddressingRoundTripAsync([BobDid]).ConfigureAwait(false);

        Assert.IsTrue(result.IsUnpacked, $"The message MUST unpack. Error: {result.Error}.");
        Assert.IsTrue(result.IsRecipientAddressedInTo, "The recipient is listed in 'to' and MUST be flagged as addressed.");
    }


    /// <summary>
    /// When <c>to</c> lists a different DID, unpack still succeeds (a blind-copy recipient is legitimate) but
    /// the advisory addressing signal is cleared.
    /// </summary>
    [TestMethod]
    public async Task ToAddressing_RecipientNotListed_UnpacksButNotAddressed()
    {
        DidCommEncryptedUnpackResult result = await ToAddressingRoundTripAsync(["did:example:carol"]).ConfigureAwait(false);

        Assert.IsTrue(result.IsUnpacked, $"A blind-copy recipient MUST still unpack. Error: {result.Error}.");
        Assert.IsFalse(result.IsRecipientAddressedInTo, "The recipient is absent from 'to' and MUST NOT be flagged as addressed.");
    }


    /// <summary>
    /// When the message carries no <c>to</c> header, unpack succeeds and the advisory addressing signal is cleared.
    /// </summary>
    [TestMethod]
    public async Task ToAddressing_NoToHeader_UnpacksButNotAddressed()
    {
        DidCommEncryptedUnpackResult result = await ToAddressingRoundTripAsync(to: null).ConfigureAwait(false);

        Assert.IsTrue(result.IsUnpacked, $"A message without a 'to' header MUST still unpack. Error: {result.Error}.");
        Assert.IsFalse(result.IsRecipientAddressedInTo, "An absent 'to' header MUST NOT be flagged as addressed.");
    }


    //A P-256 anoncrypt pack→unpack to a single Bob recipient, parameterized over the plaintext `to` list.
    //The recipient kid is always BobKid so the addressing check is driven only by the `to` contents.
    private async Task<DidCommEncryptedUnpackResult> ToAddressingRoundTripAsync(IList<string>? to)
    {
        var message = NewMessage(to);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        var recipients = new List<GeneralJweRecipientInput> { new(BobKid, recipientPublic) };

        using DidCommEncryptedMessage encrypted = await message.PackAnoncryptAsync(
            recipients,
            WellKnownJweAlgorithms.EcdhEsA256Kw,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            DidCommMessageJson.Serializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            BouncyCastleKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        return await encrypted.UnpackAnoncryptAsync(
            BobKid,
            recipientPrivate,
            NestedSignerResolver,
            Context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            MicrosoftKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
            BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    //A single-recipient anoncrypt pack→unpack over the delegate-taking overloads, parameterized over the
    //key material creator, the encrypt/decrypt agreement pair, the content encryption algorithm, and the
    //matching AEAD delegate pair. Asserts the recovered plaintext and the anoncrypt sender-anonymity flags.
    private async Task AssertDelegateRoundTripAsync(
        Func<MemoryPool<byte>, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> createKeys,
        MultiRecipientKeyAgreementEncryptDelegate encryptAgreement,
        KeyAgreementDecryptDelegate decryptAgreement,
        string contentEncryptionAlgorithm,
        AeadEncryptDelegate aeadEncrypt,
        AeadDecryptDelegate aeadDecrypt)
    {
        var message = NewMessage([BobDid]);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = createKeys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = createKeys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        var recipients = new List<GeneralJweRecipientInput> { new(BobKid, recipientPublic) };

        using DidCommEncryptedMessage encrypted = await message.PackAnoncryptAsync(
            recipients,
            WellKnownJweAlgorithms.EcdhEsA256Kw,
            contentEncryptionAlgorithm,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            DidCommMessageJson.Serializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            encryptAgreement,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
            aeadEncrypt,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        DidCommEncryptedUnpackResult result = await encrypted.UnpackAnoncryptAsync(
            BobKid,
            recipientPrivate,
            NestedSignerResolver,
            Context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            decryptAgreement,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
            aeadDecrypt,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        AssertAnoncryptSuccess(result, [BobDid]);
    }


    //A single-recipient anoncrypt pack→unpack over the registry-resolving overloads, parameterized over the
    //key material creator and the content encryption algorithm (AES-GCM or XC20P — the families the registry
    //anoncrypt overloads resolve). Asserts the recovered plaintext and anoncrypt flags.
    private async Task AssertRegistryRoundTripAsync(
        Func<MemoryPool<byte>, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> createKeys,
        string contentEncryptionAlgorithm)
    {
        var message = NewMessage([BobDid]);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = createKeys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = createKeys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        var recipients = new List<GeneralJweRecipientInput> { new(BobKid, recipientPublic) };

        using DidCommEncryptedMessage encrypted = await message.PackAnoncryptAsync(
            recipients,
            WellKnownJweAlgorithms.EcdhEsA256Kw,
            contentEncryptionAlgorithm,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            DidCommMessageJson.Serializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        DidCommEncryptedUnpackResult result = await encrypted.UnpackAnoncryptAsync(
            BobKid,
            recipientPrivate,
            NestedSignerResolver,
            Context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        AssertAnoncryptSuccess(result, [BobDid]);
    }


    //A fresh DIDComm message with the shared id/type/from and the given `to` list (null for no header).
    private static DidCommMessage NewMessage(IList<string>? to)
    {
        return new DidCommMessage
        {
            Id = MessageId,
            Type = MessageType,
            From = AliceDid,
            To = to,
            Body = new Dictionary<string, object> { ["messagespecificattribute"] = "and its value" }
        };
    }


    //Asserts a successful anoncrypt unpack: the anoncrypt sender-anonymity invariants and the recovered message.
    private static void AssertAnoncryptSuccess(DidCommEncryptedUnpackResult result, IList<string>? expectedTo)
    {
        Assert.IsTrue(result.IsUnpacked, $"The message MUST unpack. Error: {result.Error}.");
        Assert.AreEqual(DidCommDecryptionError.None, result.Error);
        Assert.AreEqual(DidCommEncryptionMode.Anoncrypt, result.Mode);
        Assert.IsFalse(result.IsSenderAuthenticated, "Anoncrypt MUST NOT authenticate the sender.");
        Assert.IsNull(result.SenderKeyId, "Anoncrypt carries no sender key id.");
        Assert.IsFalse(result.Verified.HasValue, "Anoncrypt authenticates no sender, so it carries NO Verified<T> authenticity proof — only the decrypted Message.");
        Assert.IsNotNull(result.Message, "Anoncrypt still recovers the plaintext as (unauthenticated) data.");
        AssertRecoveredMessage(result.Message, expectedTo);
    }


    //Asserts the recovered plaintext message round-trips the original id/type/from/to/body.
    private static void AssertRecoveredMessage(DidCommMessage? recovered, IList<string>? expectedTo)
    {
        Assert.IsNotNull(recovered);
        Assert.AreEqual(MessageId, recovered!.Id);
        Assert.AreEqual(MessageType, recovered.Type);
        Assert.AreEqual(AliceDid, recovered.From);

        if(expectedTo is null)
        {
            Assert.IsNull(recovered.To);
        }
        else
        {
            Assert.IsNotNull(recovered.To);
            Assert.HasCount(expectedTo.Count, recovered.To!);
            for(int i = 0; i < expectedTo.Count; ++i)
            {
                Assert.AreEqual(expectedTo[i], recovered.To![i]);
            }
        }

        Assert.IsNotNull(recovered.Body);
        Assert.IsTrue(recovered.Body!.TryGetValue("messagespecificattribute", out object? value), "The recovered body MUST carry the attribute.");
        Assert.AreEqual("and its value", value as string);
    }


    //Decodes the wire's base64url `protected` member to its UTF-8 JSON header string.
    private static string DecodeProtectedHeader(DidCommEncryptedMessage encrypted)
    {
        string? protectedEncoded = JwkJsonReader.ExtractStringValue(encrypted.AsReadOnlySpan(), "protected"u8);
        Assert.IsNotNull(protectedEncoded, "The encrypted envelope MUST carry a 'protected' member.");

        using IMemoryOwner<byte> headerOwner = TestSetup.Base64UrlDecoder(protectedEncoded!, Pool);

        return Encoding.UTF8.GetString(headerOwner.Memory.Span);
    }
}
