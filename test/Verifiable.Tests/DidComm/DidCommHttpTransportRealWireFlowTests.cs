using System;
using System.Buffers;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.DidComm;
using Verifiable.DidComm.Transport;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Real-wire capstone for the DIDComm v2.1 HTTPS transport (<see cref="DidCommHttpTransport"/>): a packed
/// message crosses a genuine loopback socket end to end — pack, POST via a real <see cref="HttpClient"/>-backed
/// <see cref="OutboundTransportDelegate"/>, receive at a Kestrel inbox, classify the arrived envelope by its
/// transport-conveyed media type (<see cref="DidCommInbound.Classify"/>), and decrypt exactly the bytes that
/// crossed the wire — plus the transport-failure leg the same POST convention produces on a non-2xx response
/// (<see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#https">DIDComm Messaging v2.1 §HTTPS</see>).
/// </summary>
/// <remarks>
/// The WebSocket leg of the same transport-neutral send seam is proven end to end over a real socket by
/// <see cref="DidCommWebSocketTransportTests"/>; this class is the HTTPS analogue, composed over the same
/// <see cref="MinimalHttpHost"/> Kestrel POST-capture pattern <see cref="DidCommRoutingForwardTests"/> uses for
/// its own cross-wire delivery test. Unit-level coverage of the §HTTPS wire conventions (POST, Content-Type,
/// status mapping) without a socket lives in <see cref="DidCommHttpTransportTests"/>, which is unaffected.
/// </remarks>
[TestClass]
internal sealed class DidCommHttpTransportRealWireFlowTests
{
    /// <summary>The test framework's per-test context, including the cooperative cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The shared memory pool backing every pooled carrier this class allocates.</summary>
    private static MemoryPool<byte> Pool { get; } = BaseMemoryPool.Shared;

    /// <summary>The sender DID stamped into the packed message's <c>from</c> field.</summary>
    private const string AliceDid = "did:example:alice";

    /// <summary>The recipient DID stamped into the packed message's <c>to</c> array.</summary>
    private const string BobDid = "did:example:bob";

    /// <summary>Bob's key identifier, the recipient key the anoncrypt envelope targets.</summary>
    private const string BobKid = "did:example:bob#key-1";

    /// <summary>The packed message's <c>id</c> field.</summary>
    private const string MessageId = "http-real-wire-1234567890";

    /// <summary>The packed message's <c>type</c> field.</summary>
    private const string MessageType = "https://example.com/protocols/lets_do_lunch/1.0/proposal";

    /// <summary>The attribute name under which the message body carries its test value.</summary>
    private const string BodyAttribute = "messagespecificattribute";

    /// <summary>The value stored under <see cref="BodyAttribute"/> in the message body.</summary>
    private const string BodyValue = "and its value";

    /// <summary>A non-network resolution context; it only satisfies the SSRF-policy-carrying parameter.</summary>
    private static ExchangeContext Context { get; } = new();

    /// <summary>
    /// A non-nested anoncrypt message never triggers nested-signature resolution, so this resolver is
    /// never invoked; it satisfies the unpack overload's resolver parameter.
    /// </summary>
    private static DidResolver NestedSignerResolver { get; } = new(DidMethodSelectors.FromResolvers(
        ("did:example", (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Failure(DidResolutionErrors.NotFound)))));

    /// <summary>Serializes a JWT header dictionary to UTF-8 JSON bytes for the anoncrypt envelope's protected header.</summary>
    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);


    /// <summary>
    /// The full receiver pipeline over a real socket: Alice packs an anoncrypt message for Bob, the HTTPS
    /// transport (<see cref="DidCommHttpTransport.CreateSendDelegate"/>) POSTs it to a Kestrel loopback inbox
    /// over a genuine <see cref="HttpClient"/>, the inbox's captured media type and body classify as
    /// <see cref="DidCommMessageClass.Anoncrypt"/>, and Bob decrypts exactly the bytes that crossed the wire.
    /// </summary>
    [TestMethod]
    public async Task AnoncryptMessageRoundTripsOverHttpsTransport()
    {
        string? receivedContentType = null;
        IMemoryOwner<byte>? receivedBodyOwner = null;
        ReadOnlyMemory<byte> receivedBody = ReadOnlyMemory<byte>.Empty;
        await using MinimalHttpHost inbox = await MinimalHttpHost.StartAsync(
            (request, cancellationToken) =>
            {
                receivedContentType = request.ContentType;
                receivedBodyOwner = Pool.Rent(Encoding.UTF8.GetByteCount(request.Body));
                int written = Encoding.UTF8.GetBytes(request.Body, receivedBodyOwner.Memory.Span);
                receivedBody = receivedBodyOwner.Memory[..written];

                return Task.FromResult(new MinimalHttpResponse { StatusCode = 202 });
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        (DidCommEncryptedMessage packed, PrivateKeyMemory recipientPrivate) =
            await PackAnoncryptForBobAsync(TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using HttpClient httpClient = new();
            DidCommTransmitResult transmit = await packed.TransmitAsync(
                inbox.BaseAddress,
                NewLoopbackContext(),
                DidCommHttpTransport.CreateSendDelegate(BuildPostTransport(httpClient)),
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(transmit.IsAccepted, $"Bob's inbox MUST accept the POST. Status: {transmit.TransportStatusCode}, error: {transmit.Error}.");
            Assert.AreEqual(202, transmit.TransportStatusCode);
            Assert.AreEqual(DidCommEncryptedMessage.MediaType, receivedContentType, "The receiver MUST see the encrypted media type as Content-Type.");
            Assert.IsNotNull(receivedBodyOwner);
            Assert.IsTrue(
                receivedBody.Span.SequenceEqual(packed.AsReadOnlySpan()),
                "The bytes that crossed the socket MUST equal the packed message byte-for-byte.");

            //The receiver dispatches purely from what the transport conveyed: the media type Content-Type carried,
            //plus the arrived envelope's own protected-header alg — no out-of-band knowledge of "this is anoncrypt".
            DidCommMessageClass messageClass = DidCommInbound.Classify(receivedContentType, receivedBody.Span, TestSetup.Base64UrlDecoder, Pool);
            Assert.AreEqual(DidCommMessageClass.Anoncrypt, messageClass, "The arrived media type and protected-header alg MUST classify as anoncrypt.");

            using DidCommEncryptedMessage received = DidCommEncryptedMessage.Create(receivedBody.Span, BufferTags.Json, Pool);
            DidCommEncryptedUnpackResult unpacked = await received.UnpackAnoncryptAsync(
                BobKid, recipientPrivate, NestedSignerResolver, Context, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
                TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(unpacked.IsUnpacked, $"Bob MUST decrypt the message that crossed the wire. Error: {unpacked.Error}.");
            Assert.AreEqual(DidCommDecryptionError.None, unpacked.Error);
            Assert.IsNotNull(unpacked.Message);
            Assert.AreEqual(MessageId, unpacked.Message!.Id);
            Assert.AreEqual(AliceDid, unpacked.Message.From);
            Assert.IsTrue(unpacked.Message.Body!.TryGetValue(BodyAttribute, out object? value));
            Assert.AreEqual(BodyValue, value as string);
        }
        finally
        {
            packed.Dispose();
            recipientPrivate.Dispose();
            receivedBodyOwner?.Dispose();
        }
    }


    /// <summary>
    /// The transport-failure leg over the same real socket: the inbox answers with a non-2xx status, and the
    /// HTTPS transport reports the exact <see cref="DidCommTransmitResult"/> failure shape — not accepted,
    /// <see cref="DidCommTransmitError.Rejected"/>, carrying the transport's numeric status
    /// (DIDComm v2.1 §HTTPS: "A successful message receipt MUST return a code in the 2xx HTTPS Status Code range").
    /// </summary>
    [TestMethod]
    public async Task NonSuccessStatusYieldsExactRejectedShape()
    {
        await using MinimalHttpHost inbox = await MinimalHttpHost.StartAsync(
            (request, cancellationToken) => Task.FromResult(new MinimalHttpResponse { StatusCode = 404 }),
            TestContext.CancellationToken).ConfigureAwait(false);

        (DidCommEncryptedMessage packed, PrivateKeyMemory recipientPrivate) =
            await PackAnoncryptForBobAsync(TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using HttpClient httpClient = new();
            DidCommTransmitResult transmit = await packed.TransmitAsync(
                inbox.BaseAddress,
                NewLoopbackContext(),
                DidCommHttpTransport.CreateSendDelegate(BuildPostTransport(httpClient)),
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(transmit.IsAccepted, "A 404 response MUST NOT be accepted.");
            Assert.AreEqual(DidCommTransmitError.Rejected, transmit.Error);
            Assert.AreEqual(404, transmit.TransportStatusCode);
        }
        finally
        {
            packed.Dispose();
            recipientPrivate.Dispose();
        }
    }


    /// <summary>
    /// Anoncrypts a fresh message from Alice to Bob (P-256, A256GCM, registry-resolving overloads) and
    /// returns the packed envelope plus Bob's private key, which the caller disposes once the unpack
    /// completes.
    /// </summary>
    private static async Task<(DidCommEncryptedMessage Packed, PrivateKeyMemory RecipientPrivate)> PackAnoncryptForBobAsync(CancellationToken cancellationToken)
    {
        var message = new DidCommMessage
        {
            Id = MessageId,
            Type = MessageType,
            From = AliceDid,
            To = [BobDid],
            Body = new Dictionary<string, object> { [BodyAttribute] = BodyValue }
        };

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        var recipients = new List<GeneralJweRecipientInput> { new(BobKid, recipientPublic) };

        DidCommEncryptedMessage packed = await message.PackAnoncryptAsync(
            recipients,
            WellKnownJweAlgorithms.EcdhEsA256Kw,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            DidCommMessageJson.Serializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            Pool,
            cancellationToken).ConfigureAwait(false);

        return (packed, recipientPrivate);
    }


    /// <summary>
    /// A fresh context whose policy permits http loopback so the genuine http://127.0.0.1:{port}/ inbox URL
    /// is allowed; production keeps <see cref="OutboundFetchPolicy.SecureDefault"/>, which denies a loopback
    /// target before any network contact.
    /// </summary>
    private static ExchangeContext NewLoopbackContext()
    {
        var context = new ExchangeContext();
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault with
        {
            AllowedSchemes = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "http", "https" },
            BlockPrivateAndLoopback = false
        });

        return context;
    }


    /// <summary>
    /// A single-hop <see cref="HttpClient"/> transport for the POST: it carries the body and Content-Type
    /// and does not follow redirects (<c>OutboundFetch</c> owns the redirect loop). Test glue — the library
    /// carries no <c>System.Net</c>. The request body is sent straight from the message's pooled memory
    /// (<see cref="ReadOnlyMemoryContent"/>, no array copy).
    /// </summary>
    private static OutboundTransportDelegate BuildPostTransport(HttpClient httpClient)
    {
        return async (request, context, cancellationToken) =>
        {
            using var httpRequest = new HttpRequestMessage(new HttpMethod(request.Method), request.Target);
            if(request.Body is { } body)
            {
                var content = new ReadOnlyMemoryContent(body.Memory);
                if(request.Headers.TryGetValue("Content-Type", out string? contentType))
                {
                    content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
                }

                httpRequest.Content = content;
            }

            using HttpResponseMessage httpResponse = await httpClient
                .SendAsync(httpRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);

            return new OutboundResponse { StatusCode = (int)httpResponse.StatusCode };
        };
    }
}
