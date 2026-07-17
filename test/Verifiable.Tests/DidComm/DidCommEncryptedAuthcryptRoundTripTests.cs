using System.Buffers;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Did.Methods;
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
/// Verifies the DIDComm v2.1 authcrypt (ECDH-1PU key wrapping) pack/unpack pipeline
/// (<see cref="DidCommEncryptedExtensions"/>): pack→unpack round trips across curves (X25519 / P-256) over
/// both the delegate-taking and registry-resolving overloads, multi-recipient delivery, the authcrypt
/// common protected-header shape, the advisory <c>to</c> signal, the producer's addressing-consistency
/// guards, and — the authcrypt security crux — the consumer's <c>from</c> ↔ <c>skid</c> binding, the
/// <c>skid</c>-from-<c>apu</c> recovery MUST, and the missing-sender-identifier rejection. The
/// from-≠-skid and skid-absent envelopes are built at the JWE layer (bypassing the producer's own
/// enforcement) so the consumer's checks are proven independently of pack-side behavior.
/// </summary>
[TestClass]
internal sealed class DidCommEncryptedAuthcryptRoundTripTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;

    //A non-network resolution context; it only satisfies the SSRF-policy-carrying parameter.
    private static readonly ExchangeContext Context = new();

    //The protected-header serializer, mirroring the anoncrypt round-trip tests: the headers are a
    //Dictionary<string, object> the JWE layer hands to this delegate to produce the UTF-8 JSON bytes.
    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private const string ExampleDidPrefix = "did:example";
    private const string MessageId = "1234567890";
    private const string MessageType = "https://example.com/protocols/lets_do_lunch/1.0/proposal";
    private const string AliceDid = "did:example:alice";
    private const string AliceX25519Skid = "did:example:alice#key-x25519-1";
    private const string AliceP256Skid = "did:example:alice#key-p256-1";
    private const string MalloryDid = "did:example:mallory";
    private const string MalloryX25519Skid = "did:example:mallory#key-x25519-1";
    private const string BobDid = "did:example:bob";
    private const string BobKid = "did:example:bob#key-x25519-1";


    /// <summary>The X25519 + A256CBC-HS512 authcrypt combination round trips through the delegate-taking overloads, authenticating the sender.</summary>
    [TestMethod]
    public async Task DelegateRoundTrip_X25519()
    {
        await AssertDelegateRoundTripAsync(
            BouncyCastleKeyMaterialCreator.CreateX25519Keys,
            BouncyCastleKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptX25519Async,
            BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptX25519Async,
            AliceX25519Skid).ConfigureAwait(false);
    }


    /// <summary>
    /// The P-256 + A256CBC-HS512 authcrypt combination round trips through the delegate-taking overloads. The
    /// sender key is resolved from a DID-document JWK, which the converter decodes to a COMPRESSED SEC1 point
    /// (tagged <c>EcCompressed</c>); the NIST agreement decompresses it (curve from the tag) before slicing —
    /// proving DID-doc-resolved NIST sender keys authenticate end-to-end, not just X25519.
    /// </summary>
    [TestMethod]
    public async Task DelegateRoundTrip_P256()
    {
        await AssertDelegateRoundTripAsync(
            MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys,
            MicrosoftKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptP256Async,
            MicrosoftKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptP256Async,
            AliceP256Skid).ConfigureAwait(false);
    }


    /// <summary>The X25519 + A256CBC-HS512 authcrypt combination round trips through the registry-resolving overloads (AEAD resolved by the wire <c>enc</c>).</summary>
    [TestMethod]
    public async Task RegistryRoundTrip_X25519()
    {
        DidCommMessage message = NewMessage([BobDid]);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> sender = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory senderPublic = sender.PublicKey;
        using PrivateKeyMemory senderPrivate = sender.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        var recipients = new List<GeneralJweRecipientInput> { new(BobKid, recipientPublic) };

        using DidCommEncryptedMessage encrypted = await message.PackAuthcryptAsync(
            recipients,
            AliceX25519Skid,
            senderPrivate,
            WellKnownJweAlgorithms.Ecdh1PuA256Kw,
            WellKnownJweEncryptionAlgorithms.A256CbcHs512,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            DidCommMessageJson.Serializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        DidResolver resolver = CreateResolver(senderPublic, AliceX25519Skid, AliceDid);

        DidCommEncryptedUnpackResult result = await encrypted.UnpackAuthcryptAsync(
            BobKid,
            recipientPrivate,
            resolver,
            Context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        AssertAuthcryptSuccess(result, AliceX25519Skid, [BobDid]);
    }


    /// <summary>
    /// A message authcrypted to three recipients decrypts for each of them, authenticating the same sender,
    /// while an outsider holding a different private key for a valid <c>kid</c> fails to decrypt.
    /// </summary>
    [TestMethod]
    public async Task MultiRecipientRoundTripAndOutsiderRejected()
    {
        const int recipientCount = 3;
        DidCommMessage message = NewMessage([BobDid]);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> sender = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory senderPublic = sender.PublicKey;
        using PrivateKeyMemory senderPrivate = sender.PrivateKey;

        var recipientKeys = new List<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>>();
        var recipientInputs = new List<GeneralJweRecipientInput>();
        var recipientKids = new List<string>();
        try
        {
            for(int i = 0; i < recipientCount; ++i)
            {
                PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> r = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
                recipientKeys.Add(r);
                string kid = $"did:example:recipient-{i}#key-x25519-1";
                recipientKids.Add(kid);
                recipientInputs.Add(new GeneralJweRecipientInput(kid, r.PublicKey));
            }

            DidResolver resolver = CreateResolver(senderPublic, AliceX25519Skid, AliceDid);

            using DidCommEncryptedMessage encrypted = await message.PackAuthcryptAsync(
                recipientInputs,
                AliceX25519Skid,
                senderPrivate,
                WellKnownJweAlgorithms.Ecdh1PuA256Kw,
                WellKnownJweEncryptionAlgorithms.A256CbcHs512,
                new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
                DidCommMessageJson.Serializer,
                HeaderSerializer,
                TestSetup.Base64UrlEncoder,
                CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                MicrosoftEntropyFunctions.GenerateNonce,
                BouncyCastleKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptX25519Async,
                ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
                MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
                MicrosoftKeyAgreementFunctions.AesCbcHmacSha512EncryptAsync,
                Pool,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            for(int i = 0; i < recipientCount; ++i)
            {
                using PrivateKeyMemory recipientPrivate = recipientKeys[i].PrivateKey;
                DidCommEncryptedUnpackResult result = await UnpackDelegateAsync(
                    encrypted, recipientKids[i], recipientPrivate, resolver,
                    BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptX25519Async).ConfigureAwait(false);

                Assert.IsTrue(result.IsUnpacked, $"Recipient {i} MUST unpack. Error: {result.Error}.");
                Assert.AreEqual(DidCommDecryptionError.None, result.Error);
                Assert.IsTrue(result.IsSenderAuthenticated, "Authcrypt MUST authenticate the sender for every recipient.");
                Assert.AreEqual(AliceX25519Skid, result.SenderKeyId);
                Assert.IsFalse(result.IsRecipientAddressedInTo, $"Recipient {i} is absent from 'to' (a blind-copy recipient) and MUST NOT be flagged as addressed.");
                AssertRecoveredMessage(result.Message, [BobDid]);
            }

            //An outsider with a different keypair but presenting a valid kid fails the AEAD/unwrap chain.
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> outsider = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
            using PublicKeyMemory outsiderPublic = outsider.PublicKey;
            using PrivateKeyMemory outsiderPrivate = outsider.PrivateKey;

            DidCommEncryptedUnpackResult outsiderResult = await UnpackDelegateAsync(
                encrypted, recipientKids[0], outsiderPrivate, resolver,
                BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptX25519Async).ConfigureAwait(false);

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
    /// The packed authcrypt envelope's common protected header carries <c>apv</c>, <c>skid</c>,
    /// <c>apu</c> (= <c>base64url</c> of the <c>skid</c>), the encrypted media <c>typ</c>, <c>epk</c>,
    /// <c>enc</c>, and <c>alg</c> (DIDComm v2.1 §ECDH-1PU key wrapping and common protected headers).
    /// </summary>
    [TestMethod]
    public async Task ProtectedHeaderShapeIsAuthcrypt()
    {
        DidCommMessage message = NewMessage([BobDid]);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> sender = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory senderPublic = sender.PublicKey;
        using PrivateKeyMemory senderPrivate = sender.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        var recipients = new List<GeneralJweRecipientInput> { new(BobKid, recipientPublic) };

        using DidCommEncryptedMessage encrypted = await message.PackAuthcryptAsync(
            recipients,
            AliceX25519Skid,
            senderPrivate,
            WellKnownJweAlgorithms.Ecdh1PuA256Kw,
            WellKnownJweEncryptionAlgorithms.A256CbcHs512,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            DidCommMessageJson.Serializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            BouncyCastleKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptX25519Async,
            ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512EncryptAsync,
            Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string protectedHeaderJson = DecodeProtectedHeader(encrypted);

        Assert.Contains("\"apv\"", protectedHeaderJson, StringComparison.Ordinal);
        Assert.Contains("\"epk\"", protectedHeaderJson, StringComparison.Ordinal);
        Assert.Contains("\"enc\"", protectedHeaderJson, StringComparison.Ordinal);
        Assert.Contains("\"alg\"", protectedHeaderJson, StringComparison.Ordinal);

        //Read the escape-sensitive values through the JSON reader (which unescapes) rather than the raw string.
        string? protectedEncoded = JwkJsonReader.ExtractStringValue(encrypted.AsReadOnlySpan(), "protected"u8);
        Assert.IsNotNull(protectedEncoded);
        using IMemoryOwner<byte> headerOwner = TestSetup.Base64UrlDecoder(protectedEncoded!, Pool);
        ReadOnlySpan<byte> header = headerOwner.Memory.Span;

        Assert.AreEqual(DidCommMediaTypes.Encrypted, JwkJsonReader.ExtractStringValue(header, "typ"u8), "The authcrypt protected header typ MUST be the encrypted media type.");
        Assert.AreEqual(AliceX25519Skid, JwkJsonReader.ExtractStringValue(header, "skid"u8), "The authcrypt protected header MUST carry the skid.");

        string expectedApu = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(AliceX25519Skid));
        Assert.AreEqual(expectedApu, JwkJsonReader.ExtractStringValue(header, "apu"u8), "apu MUST be base64url(skid).");
    }


    /// <summary>When the recipient's DID appears in <c>to</c>, the advisory addressing signal is set.</summary>
    [TestMethod]
    public async Task ToAddressing_RecipientListed_IsAddressed()
    {
        DidCommEncryptedUnpackResult result = await ToAddressingRoundTripAsync([BobDid]).ConfigureAwait(false);

        Assert.IsTrue(result.IsUnpacked, $"The message MUST unpack. Error: {result.Error}.");
        Assert.IsTrue(result.IsRecipientAddressedInTo, "The recipient is listed in 'to' and MUST be flagged as addressed.");
    }


    /// <summary>When <c>to</c> lists a different DID, unpack still succeeds but the advisory addressing signal is cleared.</summary>
    [TestMethod]
    public async Task ToAddressing_RecipientNotListed_UnpacksButNotAddressed()
    {
        DidCommEncryptedUnpackResult result = await ToAddressingRoundTripAsync(["did:example:carol"]).ConfigureAwait(false);

        Assert.IsTrue(result.IsUnpacked, $"A blind-copy recipient MUST still unpack. Error: {result.Error}.");
        Assert.IsFalse(result.IsRecipientAddressedInTo, "The recipient is absent from 'to' and MUST NOT be flagged as addressed.");
    }


    /// <summary>When the message carries no <c>to</c> header, unpack succeeds and the advisory addressing signal is cleared.</summary>
    [TestMethod]
    public async Task ToAddressing_NoToHeader_UnpacksButNotAddressed()
    {
        DidCommEncryptedUnpackResult result = await ToAddressingRoundTripAsync(to: null).ConfigureAwait(false);

        Assert.IsTrue(result.IsUnpacked, $"A message without a 'to' header MUST still unpack. Error: {result.Error}.");
        Assert.IsFalse(result.IsRecipientAddressedInTo, "An absent 'to' header MUST NOT be flagged as addressed.");
    }


    /// <summary>The producer refuses a non-AES_CBC_HMAC_SHA2 content algorithm — authcrypt mandates the CBC-HMAC family (1PU §2.1).</summary>
    [TestMethod]
    public async Task PackRejectsGcmEnc()
    {
        await AssertPackThrowsAsync(NewMessage([BobDid]), AliceX25519Skid, WellKnownJweEncryptionAlgorithms.A256Gcm, [new GeneralJweRecipientInputSpec(BobKid)]).ConfigureAwait(false);
    }


    /// <summary>The producer refuses to emit an authcrypt message without a <c>from</c> header.</summary>
    [TestMethod]
    public async Task PackRejectsMissingFrom()
    {
        DidCommMessage message = new DidCommMessage { Id = MessageId, Type = MessageType };

        await AssertPackThrowsAsync(message, AliceX25519Skid, WellKnownJweEncryptionAlgorithms.A256CbcHs512, [new GeneralJweRecipientInputSpec(BobKid)]).ConfigureAwait(false);
    }


    /// <summary>The producer refuses to emit an authcrypt message whose <c>skid</c> DID disagrees with <c>from</c>.</summary>
    [TestMethod]
    public async Task PackRejectsFromSkidMismatch()
    {
        await AssertPackThrowsAsync(NewMessage([BobDid]), MalloryX25519Skid, WellKnownJweEncryptionAlgorithms.A256CbcHs512, [new GeneralJweRecipientInputSpec(BobKid)]).ConfigureAwait(false);
    }


    /// <summary>The producer refuses an empty recipient list — authcrypt requires at least one recipient.</summary>
    [TestMethod]
    public async Task PackRejectsEmptyRecipients()
    {
        await AssertPackThrowsAsync(NewMessage([BobDid]), AliceX25519Skid, WellKnownJweEncryptionAlgorithms.A256CbcHs512, []).ConfigureAwait(false);
    }


    /// <summary>
    /// A consumer recovers the sender <c>kid</c> from <c>apu</c> when <c>skid</c> is absent, authenticates the
    /// sender, and unpacks (DIDComm v2.1 §ECDH-1PU key wrapping: "authcrypt implementations MUST be able to
    /// resolve the sender kid from the apu header if skid is not set"). The envelope is built at the JWE layer
    /// with <c>skid</c> omitted but <c>apu</c> = <c>base64url</c>(sender kid).
    /// </summary>
    [TestMethod]
    public async Task SkidRecoveredFromApuWhenSkidAbsent()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> sender = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory senderPublic = sender.PublicKey;
        using PrivateKeyMemory senderPrivate = sender.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        using DidCommEncryptedMessage encrypted = await BuildAuthcryptEnvelopeAsync(
            NewMessage([BobDid]), senderPrivate, recipientPublic, BobKid, skid: null, apuSourceValue: AliceX25519Skid).ConfigureAwait(false);

        DidResolver resolver = CreateResolver(senderPublic, AliceX25519Skid, AliceDid);

        DidCommEncryptedUnpackResult result = await UnpackDelegateAsync(
            encrypted, BobKid, recipientPrivate, resolver,
            BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptX25519Async).ConfigureAwait(false);

        Assert.IsTrue(result.IsUnpacked, $"A skid recovered from apu MUST unpack. Error: {result.Error}.");
        Assert.AreEqual(DidCommDecryptionError.None, result.Error);
        Assert.IsTrue(result.IsSenderAuthenticated, "The apu-recovered sender MUST be authenticated.");
        Assert.AreEqual(AliceX25519Skid, result.SenderKeyId, "The authenticated sender key id MUST be the apu-recovered skid.");
    }


    /// <summary>
    /// A plaintext <c>from</c> that does not match the encryption-layer <c>skid</c> DID is rejected
    /// (addressing-consistency MUST). The envelope is built at the JWE layer carrying a plaintext from Alice
    /// but a Mallory <c>skid</c>, encrypted with Mallory's key so decryption succeeds — proving the binding
    /// check fires after a cryptographically valid decryption, not before.
    /// </summary>
    [TestMethod]
    public async Task FromSkidMismatchRejected()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> mallory = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory malloryPublic = mallory.PublicKey;
        using PrivateKeyMemory malloryPrivate = mallory.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        //Plaintext claims Alice; the encryption layer's skid is Mallory, and Mallory's key encrypts it.
        using DidCommEncryptedMessage encrypted = await BuildAuthcryptEnvelopeAsync(
            NewMessage([BobDid]), malloryPrivate, recipientPublic, BobKid, skid: MalloryX25519Skid, apuSourceValue: MalloryX25519Skid).ConfigureAwait(false);

        DidResolver resolver = CreateResolver(malloryPublic, MalloryX25519Skid, MalloryDid);

        DidCommEncryptedUnpackResult result = await UnpackDelegateAsync(
            encrypted, BobKid, recipientPrivate, resolver,
            BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptX25519Async).ConfigureAwait(false);

        Assert.IsFalse(result.IsUnpacked, "A from-≠-skid message MUST NOT unpack (DIDComm v2.1 §Message Layer Addressing Consistency).");
        Assert.AreEqual(DidCommDecryptionError.FromSkidMismatch, result.Error);
        Assert.IsNull(result.Message, "Fail-closed: an addressing-inconsistent message yields no plaintext.");
    }


    /// <summary>
    /// An envelope carrying neither <c>skid</c> nor <c>apu</c> cannot identify the sender and is rejected as
    /// <see cref="DidCommDecryptionError.MissingSenderKeyId"/> before any decryption is attempted.
    /// </summary>
    [TestMethod]
    public async Task MissingSenderIdentifierRejected()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> sender = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory senderPublic = sender.PublicKey;
        using PrivateKeyMemory senderPrivate = sender.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        using DidCommEncryptedMessage encrypted = await BuildAuthcryptEnvelopeAsync(
            NewMessage([BobDid]), senderPrivate, recipientPublic, BobKid, skid: null, apuSourceValue: null).ConfigureAwait(false);

        DidResolver resolver = CreateResolver(senderPublic, AliceX25519Skid, AliceDid);

        DidCommEncryptedUnpackResult result = await UnpackDelegateAsync(
            encrypted, BobKid, recipientPrivate, resolver,
            BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptX25519Async).ConfigureAwait(false);

        Assert.IsFalse(result.IsUnpacked, "An envelope without skid or apu MUST NOT unpack.");
        Assert.AreEqual(DidCommDecryptionError.MissingSenderKeyId, result.Error);
        Assert.IsNull(result.Message, "Fail-closed: an unidentifiable sender yields no plaintext.");
    }


    /// <summary>
    /// A resolved sender keyAgreement verification method that is structurally malformed (an OKP JWK with no
    /// <c>x</c>) makes the key-material converter throw; unpack MUST fail CLOSED with
    /// <see cref="DidCommDecryptionError.SenderResolutionFailed"/> and never let the exception escape — the
    /// sender DID is reached via the attacker-influenced <c>skid</c>, so a malicious sender's malformed
    /// document must not crash the consumer (the unpack contract returns a result on every failure).
    /// </summary>
    [TestMethod]
    public async Task MalformedResolvedSenderKeyRejected()
    {
        (DidCommEncryptedMessage encrypted, PrivateKeyMemory recipientPrivate, PublicKeyMemory senderPublic) = await PackStandardAuthcryptAsync().ConfigureAwait(false);
        try
        {
            DidResolver resolver = CreateResolverWithMalformedKeyAgreement();

            DidCommEncryptedUnpackResult result = await UnpackDelegateAsync(
                encrypted, BobKid, recipientPrivate, resolver,
                BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptX25519Async).ConfigureAwait(false);

            Assert.IsFalse(result.IsUnpacked, "A malformed resolved sender key MUST NOT unpack and MUST NOT throw.");
            Assert.AreEqual(DidCommDecryptionError.SenderResolutionFailed, result.Error);
            Assert.IsNull(result.Message, "Fail-closed: a malformed sender key yields no plaintext.");
        }
        finally
        {
            encrypted.Dispose();
            recipientPrivate.Dispose();
            senderPublic.Dispose();
        }
    }


    /// <summary>
    /// Resolving the sender DID/<c>skid</c> to a DIFFERENT (but keyAgreement-authorized) X25519 key MUST fail
    /// the unpack with <see cref="DidCommDecryptionError.DecryptionFailed"/>: the ECDH-1PU agreement derives a
    /// wrong <c>Zs</c>, so the KEK is wrong and the RFC 3394 unwrap fails. This pins sender authentication to
    /// the resolved key material actually being the static key bound into the agreement — not merely to
    /// resolution succeeding (DIDComm v2.1 §ECDH-1PU key wrapping).
    /// </summary>
    [TestMethod]
    public async Task WrongResolvedSenderKeyRejected()
    {
        (DidCommEncryptedMessage encrypted, PrivateKeyMemory recipientPrivate, PublicKeyMemory senderPublic) = await PackStandardAuthcryptAsync().ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> wrong = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory wrongPublic = wrong.PublicKey;
        using PrivateKeyMemory wrongPrivate = wrong.PrivateKey;
        try
        {
            //Correct DID and skid, but a different X25519 key under keyAgreement than the one that signed-in
            //the 1PU agreement at pack time.
            DidResolver resolver = CreateResolver(wrongPublic, AliceX25519Skid, AliceDid);

            DidCommEncryptedUnpackResult result = await UnpackDelegateAsync(
                encrypted, BobKid, recipientPrivate, resolver,
                BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptX25519Async).ConfigureAwait(false);

            Assert.IsFalse(result.IsUnpacked, "A wrong (but authorized) sender key MUST NOT unpack.");
            Assert.AreEqual(DidCommDecryptionError.DecryptionFailed, result.Error);
            Assert.IsNull(result.Message, "Fail-closed: authentication is pinned to the resolved key material.");
        }
        finally
        {
            encrypted.Dispose();
            recipientPrivate.Dispose();
            senderPublic.Dispose();
        }
    }


    /// <summary>
    /// When both <c>skid</c> and <c>apu</c> are present in the protected header but name different keys, the
    /// consumer MUST reject the envelope as <see cref="DidCommDecryptionError.MalformedEnvelope"/> — the spec
    /// requires <c>apu</c> = <c>base64url</c>(<c>skid</c>) (DIDComm v2.1 §ECDH-1PU key wrapping), enforced on
    /// consume. The envelope is built at the JWE layer with a Mallory <c>apu</c> against an Alice <c>skid</c>.
    /// </summary>
    [TestMethod]
    public async Task SkidApuDisagreementRejected()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> sender = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory senderPublic = sender.PublicKey;
        using PrivateKeyMemory senderPrivate = sender.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        using DidCommEncryptedMessage encrypted = await BuildAuthcryptEnvelopeAsync(
            NewMessage([BobDid]), senderPrivate, recipientPublic, BobKid, skid: AliceX25519Skid, apuSourceValue: MalloryX25519Skid).ConfigureAwait(false);

        DidResolver resolver = CreateResolver(senderPublic, AliceX25519Skid, AliceDid);

        DidCommEncryptedUnpackResult result = await UnpackDelegateAsync(
            encrypted, BobKid, recipientPrivate, resolver,
            BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptX25519Async).ConfigureAwait(false);

        Assert.IsFalse(result.IsUnpacked, "A skid/apu disagreement MUST NOT unpack (apu MUST be base64url(skid)).");
        Assert.AreEqual(DidCommDecryptionError.MalformedEnvelope, result.Error);
        Assert.IsNull(result.Message, "Fail-closed: an inconsistent skid/apu yields no plaintext.");
    }


    /// <summary>
    /// The registry-resolving pack overload also refuses a non-AES_CBC_HMAC_SHA2 content algorithm: authcrypt
    /// mandates the CBC-HMAC family (1PU §2.1), and the GCM rejection MUST hold on the registry path too, not
    /// only the delegate-taking overload.
    /// </summary>
    [TestMethod]
    public async Task RegistryPackRejectsGcmEnc()
    {
        DidCommMessage message = NewMessage([BobDid]);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> sender = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory senderPublic = sender.PublicKey;
        using PrivateKeyMemory senderPrivate = sender.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        var recipients = new List<GeneralJweRecipientInput> { new(BobKid, recipientPublic) };

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await message.PackAuthcryptAsync(
                recipients,
                AliceX25519Skid,
                senderPrivate,
                WellKnownJweAlgorithms.Ecdh1PuA256Kw,
                WellKnownJweEncryptionAlgorithms.A256Gcm,
                new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
                DidCommMessageJson.Serializer,
                HeaderSerializer,
                TestSetup.Base64UrlEncoder,
                CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                MicrosoftEntropyFunctions.GenerateNonce,
                Pool,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }


    //A single-recipient authcrypt pack→unpack over the delegate-taking overloads, parameterized over the key
    //material creator, the encrypt/decrypt authenticated agreement pair, and the sender skid (which selects
    //the curve via the keypair). Asserts the recovered plaintext and the authcrypt sender-authentication flags.
    private async Task AssertDelegateRoundTripAsync(
        Func<MemoryPool<byte>, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> createKeys,
        MultiRecipientAuthenticatedKeyAgreementEncryptDelegate encryptAgreement,
        AuthenticatedKeyAgreementDecryptDelegate decryptAgreement,
        string skid)
    {
        DidCommMessage message = NewMessage([BobDid]);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = createKeys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> sender = createKeys(Pool);
        using PublicKeyMemory senderPublic = sender.PublicKey;
        using PrivateKeyMemory senderPrivate = sender.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = createKeys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        var recipients = new List<GeneralJweRecipientInput> { new(BobKid, recipientPublic) };

        using DidCommEncryptedMessage encrypted = await message.PackAuthcryptAsync(
            recipients,
            skid,
            senderPrivate,
            WellKnownJweAlgorithms.Ecdh1PuA256Kw,
            WellKnownJweEncryptionAlgorithms.A256CbcHs512,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            DidCommMessageJson.Serializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            encryptAgreement,
            ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512EncryptAsync,
            Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        DidResolver resolver = CreateResolver(senderPublic, skid, AliceDid);

        DidCommEncryptedUnpackResult result = await UnpackDelegateAsync(
            encrypted, BobKid, recipientPrivate, resolver, decryptAgreement).ConfigureAwait(false);

        AssertAuthcryptSuccess(result, skid, [BobDid]);
    }


    //A P-256/X25519 authcrypt pack→unpack to a single Bob recipient, parameterized over the plaintext `to`.
    private async Task<DidCommEncryptedUnpackResult> ToAddressingRoundTripAsync(IList<string>? to)
    {
        DidCommMessage message = NewMessage(to);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> sender = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory senderPublic = sender.PublicKey;
        using PrivateKeyMemory senderPrivate = sender.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        var recipients = new List<GeneralJweRecipientInput> { new(BobKid, recipientPublic) };

        using DidCommEncryptedMessage encrypted = await message.PackAuthcryptAsync(
            recipients,
            AliceX25519Skid,
            senderPrivate,
            WellKnownJweAlgorithms.Ecdh1PuA256Kw,
            WellKnownJweEncryptionAlgorithms.A256CbcHs512,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            DidCommMessageJson.Serializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            BouncyCastleKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptX25519Async,
            ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512EncryptAsync,
            Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        DidResolver resolver = CreateResolver(senderPublic, AliceX25519Skid, AliceDid);

        return await UnpackDelegateAsync(
            encrypted, BobKid, recipientPrivate, resolver,
            BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptX25519Async).ConfigureAwait(false);
    }


    //Builds an authcrypt envelope at the JWE layer with caller-controlled skid/apu so the consumer's binding
    //and sender-recovery checks can be exercised independently of the producer's own enforcement. The sender
    //and recipient are X25519; apuSourceValue (when non-null) is UTF-8 encoded and base64url'd into apu.
    private async Task<DidCommEncryptedMessage> BuildAuthcryptEnvelopeAsync(
        DidCommMessage plaintextMessage,
        PrivateKeyMemory senderPrivate,
        PublicKeyMemory recipientPublic,
        string recipientKid,
        string? skid,
        string? apuSourceValue)
    {
        using DidCommPlaintextMessage plaintext = plaintextMessage.PackPlaintext(DidCommMessageJson.Serializer, Pool);

        string agreementPartyVInfo = JweAgreementInfo.ComputeApvFromRecipientKeyIds([recipientKid], TestSetup.Base64UrlEncoder, Pool);

        var extras = new Dictionary<string, object>
        {
            [WellKnownJoseHeaderNames.Apv] = agreementPartyVInfo,
            [WellKnownJoseHeaderNames.Typ] = DidCommMediaTypes.Encrypted
        };

        if(skid is not null)
        {
            extras[WellKnownJoseHeaderNames.Skid] = skid;
        }

        if(apuSourceValue is not null)
        {
            extras[WellKnownJoseHeaderNames.Apu] = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(apuSourceValue));
        }

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        var recipients = new List<GeneralJweRecipientInput> { new(recipientKid, recipientPublic) };

        string wire;
        using(GeneralJweMessage jwe = await GeneralJweEncryptionExtensions.EncryptAuthcryptAsync(
            plaintext.AsReadOnlyMemory(),
            recipients,
            WellKnownJweAlgorithms.Ecdh1PuA256Kw,
            WellKnownJweEncryptionAlgorithms.A256CbcHs512,
            extras,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            senderPrivate,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            BouncyCastleKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptX25519Async,
            ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512EncryptAsync,
            Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            wire = jwe.ToGeneralJson(TestSetup.Base64UrlEncoder);
        }

        return DidCommEncryptedMessage.Create(Encoding.UTF8.GetBytes(wire), BufferTags.Json, Pool);
    }


    //Unpacks via the delegate-taking authcrypt overload with the given decrypt agreement (curve-specific).
    private ValueTask<DidCommEncryptedUnpackResult> UnpackDelegateAsync(
        DidCommEncryptedMessage encrypted,
        string recipientKid,
        PrivateKeyMemory recipientPrivate,
        DidResolver resolver,
        AuthenticatedKeyAgreementDecryptDelegate decryptAgreement)
    {
        return encrypted.UnpackAuthcryptAsync(
            recipientKid,
            recipientPrivate,
            resolver,
            Context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            decryptAgreement,
            ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512DecryptAsync,
            Pool,
            cancellationToken: TestContext.CancellationToken);
    }


    //Asserts the producer throws ArgumentException for the given message/skid/enc/recipient-kid spec. Fresh
    //X25519 ephemeral/sender keys are minted; recipient public keys are generated per spec entry.
    private async Task AssertPackThrowsAsync(DidCommMessage message, string skid, string contentEncryptionAlgorithm, IReadOnlyList<GeneralJweRecipientInputSpec> recipientSpecs)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> sender = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory senderPublic = sender.PublicKey;
        using PrivateKeyMemory senderPrivate = sender.PrivateKey;

        var recipientKeys = new List<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>>();
        var recipients = new List<GeneralJweRecipientInput>();
        try
        {
            foreach(GeneralJweRecipientInputSpec spec in recipientSpecs)
            {
                PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> r = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
                recipientKeys.Add(r);
                recipients.Add(new GeneralJweRecipientInput(spec.KeyId, r.PublicKey));
            }

            await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
                await message.PackAuthcryptAsync(
                    recipients,
                    skid,
                    senderPrivate,
                    WellKnownJweAlgorithms.Ecdh1PuA256Kw,
                    contentEncryptionAlgorithm,
                    new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
                    DidCommMessageJson.Serializer,
                    HeaderSerializer,
                    TestSetup.Base64UrlEncoder,
                    CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                    MicrosoftEntropyFunctions.GenerateNonce,
                    BouncyCastleKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptX25519Async,
                    ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
                    MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
                    MicrosoftKeyAgreementFunctions.AesCbcHmacSha512EncryptAsync,
                    Pool,
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }
        finally
        {
            foreach(PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> r in recipientKeys)
            {
                r.PublicKey.Dispose();
                r.PrivateKey.Dispose();
            }
        }
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


    //Asserts a successful authcrypt unpack: the sender-authentication invariants and the recovered message.
    private static void AssertAuthcryptSuccess(DidCommEncryptedUnpackResult result, string expectedSkid, IList<string>? expectedTo)
    {
        Assert.IsTrue(result.IsUnpacked, $"The message MUST unpack. Error: {result.Error}.");
        Assert.AreEqual(DidCommDecryptionError.None, result.Error);
        Assert.AreEqual(DidCommEncryptionMode.Authcrypt, result.Mode);
        Assert.IsTrue(result.IsSenderAuthenticated, "Authcrypt MUST authenticate the sender.");
        Assert.AreEqual(expectedSkid, result.SenderKeyId, "The authenticated sender key id MUST be the skid.");
        Assert.IsTrue(result.Verified.HasValue, "Authcrypt authenticates the sender, so the result MUST carry a Verified<T> authenticity proof.");
        Assert.AreSame(result.Message, result.Verified.GetValueOrDefault().Value, "The Verified proof MUST wrap the recovered message.");
        Assert.IsFalse(result.IsSignedInner, "A non-nested authcrypt message is not signed inner.");
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


    //Builds a resolver returning a sender DID document whose keyAgreement key is the sender's public key.
    private static DidResolver CreateResolver(PublicKeyMemory senderPublic, string skid, string did)
    {
        var document = new DidDocument
        {
            Id = new GenericDidMethod(did),
            VerificationMethod = [SenderVerificationMethod(skid, did, senderPublic)],
            KeyAgreement = [new KeyAgreementMethod(skid)]
        };

        return new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Success(document, new DidDocumentMetadata())))));
    }


    //Packs a standard single-recipient X25519 / A256CBC-HS512 authcrypt message (Alice -> Bob, skid =
    //AliceX25519Skid) and returns the wire artifact, the recipient private key, and the sender PUBLIC key so
    //the caller can build a resolver doc. The caller owns and disposes all three returned values; the
    //ephemeral keys, the sender private key, and the recipient public key are disposed here.
    private async Task<(DidCommEncryptedMessage Encrypted, PrivateKeyMemory RecipientPrivate, PublicKeyMemory SenderPublic)> PackStandardAuthcryptAsync()
    {
        DidCommMessage message = NewMessage([BobDid]);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> sender = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PrivateKeyMemory senderPrivate = sender.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;

        var recipients = new List<GeneralJweRecipientInput> { new(BobKid, recipientPublic) };

        DidCommEncryptedMessage encrypted = await message.PackAuthcryptAsync(
            recipients,
            AliceX25519Skid,
            senderPrivate,
            WellKnownJweAlgorithms.Ecdh1PuA256Kw,
            WellKnownJweEncryptionAlgorithms.A256CbcHs512,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            DidCommMessageJson.Serializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            BouncyCastleKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptX25519Async,
            ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512EncryptAsync,
            Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return (encrypted, recipient.PrivateKey, sender.PublicKey);
    }


    //Builds a resolver returning Alice's DID document whose skid keyAgreement method is structurally
    //malformed (an OKP JWK with no x coordinate), so the key-material converter throws when the consumer
    //tries to resolve the sender public key.
    private static DidResolver CreateResolverWithMalformedKeyAgreement()
    {
        var malformed = new VerificationMethod
        {
            Id = AliceX25519Skid,
            Type = "JsonWebKey2020",
            Controller = AliceDid,
            KeyFormat = new PublicKeyJwk { Header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Kty] = WellKnownKeyTypeValues.Okp, [WellKnownJwkMemberNames.Crv] = WellKnownCurveValues.X25519 } }
        };

        var document = new DidDocument
        {
            Id = new GenericDidMethod(AliceDid),
            VerificationMethod = [malformed],
            KeyAgreement = [new KeyAgreementMethod(AliceX25519Skid)]
        };

        return new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Success(document, new DidDocumentMetadata())))));
    }


    //Builds a keyAgreement verification method JWK from the sender's public key bytes: an OKP/X25519 key
    //carries the raw 32-byte x; an EC key carries the x/y halves of the uncompressed SEC1 point
    //(0x04||X||Y). For EC the converter re-encodes these coordinates to a compressed point that the NIST
    //agreement must decompress, so this exercises the real DID-doc resolution path end to end.
    private static VerificationMethod SenderVerificationMethod(string kid, string did, PublicKeyMemory senderPublic)
    {
        CryptoAlgorithm algorithm = senderPublic.Tag.Get<CryptoAlgorithm>();
        ReadOnlySpan<byte> keySpan = senderPublic.AsReadOnlySpan();

        Dictionary<string, object> jwk;
        if(algorithm.Equals(CryptoAlgorithm.X25519))
        {
            //OKP carries the raw 32-byte key as x (no SEC1 prefix, so no coordinate slicing).
            jwk = new Dictionary<string, object>
            {
                [WellKnownJwkMemberNames.Kty] = WellKnownKeyTypeValues.Okp,
                [WellKnownJwkMemberNames.Crv] = WellKnownCurveValues.X25519,
                [WellKnownJwkMemberNames.X] = TestSetup.Base64UrlEncoder(keySpan)
            };
        }
        else
        {
            //EC splits the uncompressed SEC1 point into its x/y halves via the shared utility rather than
            //hand-rolled offsets.
            string curve = algorithm.Equals(CryptoAlgorithm.P256) ? WellKnownCurveValues.P256
                : algorithm.Equals(CryptoAlgorithm.P384) ? WellKnownCurveValues.P384
                : WellKnownCurveValues.P521;

            jwk = new Dictionary<string, object>
            {
                [WellKnownJwkMemberNames.Kty] = WellKnownKeyTypeValues.Ec,
                [WellKnownJwkMemberNames.Crv] = curve,
                [WellKnownJwkMemberNames.X] = TestSetup.Base64UrlEncoder(EllipticCurveUtilities.SliceXCoordinate(keySpan)),
                [WellKnownJwkMemberNames.Y] = TestSetup.Base64UrlEncoder(EllipticCurveUtilities.SliceYCoordinate(keySpan))
            };
        }

        return new VerificationMethod
        {
            Id = kid,
            Type = "JsonWebKey2020",
            Controller = did,
            KeyFormat = new PublicKeyJwk { Header = jwk }
        };
    }


    //A recipient kid specification for the pack-rejection helper; the public key is generated per test.
    private readonly record struct GeneralJweRecipientInputSpec(string KeyId);
}
