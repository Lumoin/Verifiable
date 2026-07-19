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
using Verifiable.DidComm.Transport;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Proves the DIDComm transport seam is genuinely channel-pluggable: an anoncrypt message packs to
/// channel-independent bytes plus a media type, is delivered over a REAL WebSocket through the transport-neutral
/// <see cref="DidCommSendDelegate"/> (the library carries no <c>System.Net</c>), is classified on receipt by
/// <see cref="DidCommInbound"/>, and decrypts byte-for-byte — no library change versus the HTTPS path
/// (DIDComm Messaging v2.1 §Transports, §WebSockets).
/// </summary>
[TestClass]
internal sealed class DidCommWebSocketTransportTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;

    //A non-network resolution context; it only satisfies the SSRF-policy-carrying parameter (the WebSocket path
    //does not route through OutboundFetch, so no scheme/host policy applies to the loopback wss:// endpoint).
    private static readonly ExchangeContext Context = new();

    //A non-nested anoncrypt message never triggers nested-signature resolution; this satisfies the parameter.
    private static readonly DidResolver NestedSignerResolver = new DidResolver(DidMethodSelectors.FromResolvers(
        ("did:example", (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Failure(DidResolutionErrors.NotFound)))));

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private const string MessageId = "ws-1234567890";
    private const string MessageType = "https://example.com/protocols/lets_do_lunch/1.0/proposal";
    private const string AliceDid = "did:example:alice";
    private const string BobDid = "did:example:bob";
    private const string BobKid = "did:example:bob#key-1";


    /// <summary>
    /// A P-256 + A256GCM anoncrypt message round trips over a genuine WebSocket: it is delivered through the
    /// transport-neutral send seam, the bytes cross the socket unchanged, the inbound classifier identifies it as
    /// anoncrypt from the conveyed media type, and Bob decrypts the original plaintext.
    /// </summary>
    [TestMethod]
    public async Task AnoncryptRoundTripsOverWebSocketTransport()
    {
        var message = new DidCommMessage
        {
            Id = MessageId,
            Type = MessageType,
            From = AliceDid,
            To = [BobDid],
            Body = new Dictionary<string, object> { ["messagespecificattribute"] = "and its value" }
        };

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
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Deliver over a real WebSocket through the transport-neutral send seam — the SAME message.TransmitAsync the
        //HTTPS path uses, handed a WebSocket DidCommSendDelegate instead of the HTTPS one.
        await using DidCommWebSocketInbox inbox = await DidCommWebSocketInbox.StartAsync(cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        DidCommSendDelegate send = DidCommWebSocketInbox.CreateSendDelegate(inbox.Certificate);

        DidCommTransmitResult transmit = await encrypted.TransmitAsync(inbox.Endpoint, Context, send, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(transmit.IsAccepted, $"The WebSocket inbox MUST accept the delivery. Error: {transmit.Error}.");
        Assert.AreEqual(DidCommTransmitError.None, transmit.Error);
        Assert.IsNull(transmit.TransportStatusCode, "A WebSocket delivery carries no numeric transport status.");

        DidCommWebSocketDelivery delivery = await inbox.ReceivedAsync(cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(DidCommMediaTypes.Encrypted, delivery.MediaType, "The receiver MUST see the encrypted media type the transport conveyed.");
        Assert.IsTrue(
            delivery.Bytes.AsSpan().SequenceEqual(encrypted.AsReadOnlySpan()),
            "The bytes that crossed the socket MUST equal the packed envelope byte-for-byte.");

        //Dispatch by the inbound classifier — the receive-side counterpart to the send seam.
        DidCommMessageClass classification = DidCommInbound.Classify(delivery.MediaType, delivery.Bytes, TestSetup.Base64UrlDecoder, Pool);
        Assert.AreEqual(DidCommMessageClass.Anoncrypt, classification, "An ECDH-ES envelope MUST classify as anoncrypt.");

        using DidCommEncryptedMessage received = DidCommEncryptedMessage.Create(delivery.Bytes, BufferTags.Json, Pool);
        DidCommEncryptedUnpackResult unpacked = await received.UnpackAnoncryptAsync(
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
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(unpacked.IsUnpacked, $"Bob MUST decrypt the message that crossed the WebSocket. Error: {unpacked.Error}.");
        Assert.AreEqual(DidCommEncryptionMode.Anoncrypt, unpacked.Mode);
        Assert.IsNotNull(unpacked.Message);
        Assert.AreEqual(MessageId, unpacked.Message!.Id);
        Assert.AreEqual(AliceDid, unpacked.Message.From);
        Assert.IsNotNull(unpacked.Message.Body);
        Assert.IsTrue(unpacked.Message.Body!.TryGetValue("messagespecificattribute", out object? value), "The recovered body MUST carry the attribute.");
        Assert.AreEqual("and its value", value as string);

        //Trust rides on the envelope, not the socket (DIDComm v2.1 §WebSockets L1136): a wrong key MUST fail to
        //decrypt the very bytes that crossed the clean, unauthenticated socket — the accepted delivery confers no trust.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> outsider = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory outsiderPublic = outsider.PublicKey;
        using PrivateKeyMemory outsiderPrivate = outsider.PrivateKey;

        DidCommEncryptedUnpackResult outsiderResult = await received.UnpackAnoncryptAsync(
            BobKid,
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
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outsiderResult.IsUnpacked, "Clean WebSocket delivery confers no trust: a wrong key MUST fail to decrypt the bytes that crossed the socket.");
    }
}
