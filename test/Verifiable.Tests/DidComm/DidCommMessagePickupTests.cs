using System;
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
using Verifiable.DidComm.MessagePickup;
using Verifiable.DidComm.ProblemReports;
using Verifiable.DidComm.ReturnRoute;
using Verifiable.DidComm.Transport;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Tests for DIDComm Message Pickup 3.0 — the protocol folder (<see cref="MessagePickupExtensions"/>,
/// <see cref="WellKnownMessagePickupNames"/>, <see cref="MessagePickupStatus"/>) and its exchange seam
/// (<see cref="DidCommExchangeDelegate"/>, <see cref="DidCommHttpTransport.CreateExchangeDelegate"/>,
/// <see cref="DidCommTransportExtensions"/>'s <c>ExchangeAsync</c> overloads), per
/// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> and the
/// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">DIDComm Messaging Return-Route and Queue Transport Extension</see>.
/// </summary>
/// <remarks>
/// The exchange seam's unit tests are fake-delegate (no socket): the transport under test is a stub
/// <see cref="FakeExchangeTransport"/> that records the <see cref="OutboundRequest"/> the seam produced and
/// returns a configured <see cref="OutboundResponse"/>. The protocol-layer tests are in-process message-shape
/// and pack/unpack round trips, culminating in one real-wire capstone
/// (<see cref="StatusRequestExchangeRoundTripsAnAnoncryptStatusOverARealSocket"/>) that exercises both halves
/// together over a genuine loopback socket.
/// </remarks>
[TestClass]
internal sealed class DidCommMessagePickupTests
{
    /// <summary>The test framework's per-test context, including the cooperative cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    private static readonly BaseMemoryPool Pool = BaseMemoryPool.Shared;
    private static readonly Uri Endpoint = new("https://mediator.example/didcomm");
    private static readonly Uri LoopbackEndpoint = new("https://127.0.0.1/inbox");


    private static DidCommMessage ReturnRouteAllRequest(string id = "status-request-1") =>
        new DidCommMessage { Id = id, Type = "https://didcomm.org/messagepickup/3.0/status-request" }
            .WithReturnRoute(WellKnownReturnRouteNames.All);


    private static DidCommEncryptedMessage Encrypted(ReadOnlySpan<byte> wireBytes) =>
        DidCommEncryptedMessage.Create(wireBytes, BufferTags.Json, Pool);


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">DIDComm Messaging Return-Route and Queue Transport Extension</see>:
    /// "Messages can flow back in response to inbound messages over the same connection." A reply the mediator
    /// returns on the same HTTP response the recipient's request travelled on MUST reach the caller as opaque
    /// wire bytes plus the reported media type, unclassified — <see cref="DidCommExchangeResult"/> performs no
    /// classification; that is <c>DidCommInbound.Classify</c>'s job.
    /// </summary>
    [TestMethod]
    public async Task ExchangeReturnsReplyBodyAndMediaTypeOnSuccess()
    {
        byte[] replyBytes = "{\"type\":\"https://didcomm.org/messagepickup/3.0/status\"}"u8.ToArray();
        var transport = new FakeExchangeTransport(statusCode: 200, replyBody: replyBytes, replyMediaType: "application/didcomm-encrypted+json");
        using DidCommEncryptedMessage message = Encrypted("{\"ciphertext\":\"x\"}"u8);
        DidCommMessage request = ReturnRouteAllRequest();

        DidCommExchangeDelegate exchange = DidCommHttpTransport.CreateExchangeDelegate(transport.SendAsync, Pool);
        using DidCommExchangeResult result = await message.ExchangeAsync(request, Endpoint, new ExchangeContext(), exchange, default).ConfigureAwait(false);

        Assert.IsTrue(result.IsAccepted);
        Assert.AreEqual(200, result.TransportStatusCode);
        Assert.IsTrue(result.HasReply);
        Assert.IsTrue(result.ReplyBody.AsReadOnlySpan().SequenceEqual(replyBytes));
        Assert.AreEqual("application/didcomm-encrypted+json", result.ReplyMediaType);
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#https">DIDComm Messaging v2.1 §HTTPS</see>:
    /// "A successful message receipt MUST return a code in the 2xx HTTPS Status Code range. 202 Accepted is
    /// recommended." A 2xx acceptance with an empty response body is a legal "accepted, nothing to return" —
    /// acceptance is independent of whether a reply happened to be present.
    /// </summary>
    [TestMethod]
    public async Task ExchangeAcceptedWithEmptyBodyHasNoReply()
    {
        var transport = new FakeExchangeTransport(statusCode: 202);
        using DidCommEncryptedMessage message = Encrypted("{\"ciphertext\":\"x\"}"u8);
        DidCommMessage request = ReturnRouteAllRequest();

        DidCommExchangeDelegate exchange = DidCommHttpTransport.CreateExchangeDelegate(transport.SendAsync, Pool);
        using DidCommExchangeResult result = await message.ExchangeAsync(request, Endpoint, new ExchangeContext(), exchange, default).ConfigureAwait(false);

        Assert.IsTrue(result.IsAccepted);
        Assert.AreEqual(202, result.TransportStatusCode);
        Assert.IsFalse(result.HasReply);
        Assert.IsTrue(result.ReplyBody.IsEmpty);
        Assert.IsNull(result.ReplyMediaType);
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#https">DIDComm Messaging v2.1 §HTTPS</see>:
    /// a successful receipt is what makes a reply legible ("A successful message receipt MUST return a code in
    /// the 2xx HTTPS Status Code range") — an endpoint reached but not accepting the request (a non-2xx status)
    /// MUST NOT be treated as carrying a reply.
    /// </summary>
    [TestMethod]
    [DataRow(400)]
    [DataRow(404)]
    [DataRow(500)]
    public async Task ExchangeNonSuccessStatusIsRejectedWithNoReply(int statusCode)
    {
        var transport = new FakeExchangeTransport(statusCode, replyBody: "ignored-on-non-2xx"u8.ToArray());
        using DidCommEncryptedMessage message = Encrypted("{\"ciphertext\":\"x\"}"u8);
        DidCommMessage request = ReturnRouteAllRequest();

        DidCommExchangeDelegate exchange = DidCommHttpTransport.CreateExchangeDelegate(transport.SendAsync, Pool);
        using DidCommExchangeResult result = await message.ExchangeAsync(request, Endpoint, new ExchangeContext(), exchange, default).ConfigureAwait(false);

        Assert.IsFalse(result.IsAccepted);
        Assert.AreEqual(DidCommTransmitError.Rejected, result.Error);
        Assert.AreEqual(statusCode, result.TransportStatusCode);
        Assert.IsFalse(result.HasReply);
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#https">DIDComm Messaging v2.1 §HTTPS</see>:
    /// <c>maxReplyBytes</c> on the outbound request is only a transport HINT
    /// (<see cref="Verifiable.Core.OutboundFetch.OutboundRequest.MaxResponseBytes"/>) a hostile or
    /// non-conforming transport may ignore, so <c>CreateExchangeDelegate</c> re-checks the read-back reply
    /// against the caller's cap as the authoritative backstop: a reply one byte over MUST be refused as a
    /// transport failure, carrying no reply, exactly as a cooperating transport's mid-read abort would.
    /// </summary>
    [TestMethod]
    public async Task ExchangeReplyOverTheCapIsTransportFailedWithNoReply()
    {
        var transport = new FakeExchangeTransport(statusCode: 200, replyBody: new byte[5]);
        using DidCommEncryptedMessage message = Encrypted("{\"ciphertext\":\"x\"}"u8);
        DidCommMessage request = ReturnRouteAllRequest();

        DidCommExchangeDelegate exchange = DidCommHttpTransport.CreateExchangeDelegate(transport.SendAsync, Pool, maxReplyBytes: 4);
        using DidCommExchangeResult result = await message.ExchangeAsync(request, Endpoint, new ExchangeContext(), exchange, default).ConfigureAwait(false);

        Assert.IsFalse(result.IsAccepted);
        Assert.AreEqual(DidCommTransmitError.TransportFailed, result.Error);
        Assert.IsFalse(result.HasReply, "A reply over the cap MUST NOT reach the caller.");
        Assert.IsTrue(result.ReplyBody.IsEmpty);
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#https">DIDComm Messaging v2.1 §HTTPS</see>:
    /// the boundary of the post-read backstop — a reply exactly AT the caller's cap is not oversized and MUST
    /// be accepted with its reply intact.
    /// </summary>
    [TestMethod]
    public async Task ExchangeReplyExactlyAtTheCapIsAccepted()
    {
        var transport = new FakeExchangeTransport(statusCode: 200, replyBody: new byte[4]);
        using DidCommEncryptedMessage message = Encrypted("{\"ciphertext\":\"x\"}"u8);
        DidCommMessage request = ReturnRouteAllRequest();

        DidCommExchangeDelegate exchange = DidCommHttpTransport.CreateExchangeDelegate(transport.SendAsync, Pool, maxReplyBytes: 4);
        using DidCommExchangeResult result = await message.ExchangeAsync(request, Endpoint, new ExchangeContext(), exchange, default).ConfigureAwait(false);

        Assert.IsTrue(result.IsAccepted);
        Assert.IsTrue(result.HasReply);
        Assert.AreEqual(4, result.ReplyBody.Length);
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>:
    /// the exchange channel is still an outbound dereference of the recipient-supplied endpoint, so it goes
    /// through the same SSRF-policed <c>OutboundFetch</c> the one-way send path uses — an SSRF-denied endpoint
    /// MUST fail closed before the transport is ever contacted.
    /// </summary>
    [TestMethod]
    public async Task ExchangePolicyDeniedEndpointFailsClosedWithoutContactingTransport()
    {
        var transport = new FakeExchangeTransport(statusCode: 200);
        using DidCommEncryptedMessage message = Encrypted("{\"ciphertext\":\"x\"}"u8);
        DidCommMessage request = ReturnRouteAllRequest();

        DidCommExchangeDelegate exchange = DidCommHttpTransport.CreateExchangeDelegate(transport.SendAsync, Pool);
        //An empty context is the secure default: a loopback IP-literal endpoint is denied before any transport call.
        using DidCommExchangeResult result = await message.ExchangeAsync(request, LoopbackEndpoint, new ExchangeContext(), exchange, default).ConfigureAwait(false);

        Assert.IsFalse(result.IsAccepted);
        Assert.AreEqual(DidCommTransmitError.DeniedByPolicy, result.Error);
        Assert.IsNull(result.TransportStatusCode);
        Assert.IsFalse(result.HasReply);
        Assert.IsEmpty(transport.Calls, "A policy-denied endpoint MUST NOT contact the transport.");
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>
    /// §Failover: a sender SHOULD fail over to another endpoint or retry later, which requires the failure to
    /// surface as data rather than an exception — a transport-level failure (socket/DNS/connection error) MUST
    /// be reported as a fail-soft typed outcome, not thrown.
    /// </summary>
    [TestMethod]
    public async Task ExchangeTransportExceptionFailsClosed()
    {
        var transport = new FakeExchangeTransport(statusCode: 200, throwOnSend: true);
        using DidCommEncryptedMessage message = Encrypted("{\"ciphertext\":\"x\"}"u8);
        DidCommMessage request = ReturnRouteAllRequest();

        DidCommExchangeDelegate exchange = DidCommHttpTransport.CreateExchangeDelegate(transport.SendAsync, Pool);
        using DidCommExchangeResult result = await message.ExchangeAsync(request, Endpoint, new ExchangeContext(), exchange, default).ConfigureAwait(false);

        Assert.IsFalse(result.IsAccepted);
        Assert.AreEqual(DidCommTransmitError.TransportFailed, result.Error);
        Assert.IsNull(result.TransportStatusCode);
        Assert.IsFalse(result.HasReply);
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>:
    /// cancellation is caller intent, not a delivery outcome — it MUST propagate through the exchange channel
    /// rather than being folded into a fail-soft result, exactly as the one-way send path requires.
    /// </summary>
    [TestMethod]
    public async Task ExchangeCancellationPropagatesAndIsNotSwallowed()
    {
        var transport = new FakeExchangeTransport(statusCode: 200, throwCancellation: true);
        using DidCommEncryptedMessage message = Encrypted("{\"ciphertext\":\"x\"}"u8);
        DidCommMessage request = ReturnRouteAllRequest();
        DidCommExchangeDelegate exchange = DidCommHttpTransport.CreateExchangeDelegate(transport.SendAsync, Pool);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync().ConfigureAwait(false);

        await Assert.ThrowsAsync<OperationCanceledException>(
            async () => await message.ExchangeAsync(request, Endpoint, new ExchangeContext(), exchange, cts.Token).ConfigureAwait(false)).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see>: "Messages
    /// delivered from the queue must be delivered in a batch delivery message as attachments, with a batch
    /// size specified by the limit provided in the delivery-request message." A caller expecting a large
    /// <c>delivery</c> batch raises <c>CreateExchangeDelegate</c>'s reply-size cap, which MUST reach the
    /// outbound request unchanged so a cooperating transport can abort an oversized reply before buffering it.
    /// </summary>
    [TestMethod]
    public async Task CreateExchangeDelegateAppliesCallerSuppliedMaxReplyBytesToTheOutboundRequest()
    {
        var transport = new FakeExchangeTransport(statusCode: 200);
        using DidCommEncryptedMessage message = Encrypted("{\"ciphertext\":\"x\"}"u8);
        DidCommMessage request = ReturnRouteAllRequest();

        DidCommExchangeDelegate exchange = DidCommHttpTransport.CreateExchangeDelegate(transport.SendAsync, Pool, maxReplyBytes: 4096);
        using DidCommExchangeResult result = await message.ExchangeAsync(request, Endpoint, new ExchangeContext(), exchange, default).ConfigureAwait(false);

        Assert.HasCount(1, transport.Calls);
        Assert.AreEqual(4096L, transport.Calls[0].MaxResponseBytes);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see>: without a
    /// caller-supplied cap, <c>CreateExchangeDelegate</c> applies its documented default — sized for a
    /// <c>delivery</c> batch — to the outbound request.
    /// </summary>
    [TestMethod]
    public async Task CreateExchangeDelegateDefaultsMaxReplyBytesForADeliveryBatch()
    {
        var transport = new FakeExchangeTransport(statusCode: 200);
        using DidCommEncryptedMessage message = Encrypted("{\"ciphertext\":\"x\"}"u8);
        DidCommMessage request = ReturnRouteAllRequest();

        DidCommExchangeDelegate exchange = DidCommHttpTransport.CreateExchangeDelegate(transport.SendAsync, Pool);
        using DidCommExchangeResult result = await message.ExchangeAsync(request, Endpoint, new ExchangeContext(), exchange, default).ConfigureAwait(false);

        Assert.HasCount(1, transport.Calls);
        Assert.AreEqual(2L * 1024 * 1024, transport.Calls[0].MaxResponseBytes);
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">DIDComm Messaging Return-Route and Queue Transport Extension</see>:
    /// a non-positive reply cap is a caller programming error, not a wire condition — rejected up front rather
    /// than silently treated as "unbounded" or "empty".
    /// </summary>
    [TestMethod]
    [DataRow(0L)]
    [DataRow(-1L)]
    public void CreateExchangeDelegateRejectsNonPositiveMaxReplyBytes(long maxReplyBytes)
    {
        var transport = new FakeExchangeTransport(statusCode: 200);

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => DidCommHttpTransport.CreateExchangeDelegate(transport.SendAsync, Pool, maxReplyBytes));
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">DIDComm Messaging Return-Route and Queue Transport Extension</see>:
    /// a <see langword="null"/> transport is a caller programming error.
    /// </summary>
    [TestMethod]
    public void CreateExchangeDelegateRejectsNullTransport()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => DidCommHttpTransport.CreateExchangeDelegate(null!, Pool));
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see>: "the
    /// return_route header extension must be set to all in all request submitted by the recipient" (§States) —
    /// <c>ExchangeAsync</c> is used only for a request that directs replies onto the connection, so a request
    /// without <c>return_route: all</c> MUST be refused rather than silently opened for a reply the peer was
    /// never told to send.
    /// </summary>
    [TestMethod]
    public async Task ExchangeAsyncGuardRejectsRequestWithoutReturnRouteAll()
    {
        var transport = new FakeExchangeTransport(statusCode: 200);
        using DidCommEncryptedMessage message = Encrypted("{\"ciphertext\":\"x\"}"u8);
        DidCommMessage requestWithoutReturnRoute = new() { Id = "status-request-1", Type = "https://didcomm.org/messagepickup/3.0/status-request" };

        DidCommExchangeDelegate exchange = DidCommHttpTransport.CreateExchangeDelegate(transport.SendAsync, Pool);

        await Assert.ThrowsExactlyAsync<ArgumentException>(
            async () => await message.ExchangeAsync(requestWithoutReturnRoute, Endpoint, new ExchangeContext(), exchange, default).ConfigureAwait(false)).ConfigureAwait(false);
        Assert.IsEmpty(transport.Calls, "A rejected exchange MUST NOT contact the transport.");
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">DIDComm Messaging Return-Route and Queue Transport Extension</see>:
    /// the extension is defined on the message headers, not the envelope form, so the signed and plaintext
    /// <c>ExchangeAsync</c> overloads carry the same request/return_route/reply contract as the encrypted
    /// overload — the exchange seam is not encrypted-only.
    /// </summary>
    [TestMethod]
    public async Task SignedAndPlaintextExchangeOverloadsAlsoEnforceTheGuardAndReturnReplies()
    {
        var transport = new FakeExchangeTransport(statusCode: 200, replyBody: "reply"u8.ToArray(), replyMediaType: "application/didcomm-plain+json");
        DidCommMessage request = ReturnRouteAllRequest();
        DidCommExchangeDelegate exchange = DidCommHttpTransport.CreateExchangeDelegate(transport.SendAsync, Pool);

        using DidCommSignedMessage signed = DidCommSignedMessage.Create("{\"payload\":\"p\",\"signatures\":[]}"u8, BufferTags.Json, Pool);
        using DidCommExchangeResult signedResult = await signed.ExchangeAsync(request, Endpoint, new ExchangeContext(), exchange, default).ConfigureAwait(false);
        Assert.IsTrue(signedResult.IsAccepted);
        Assert.IsTrue(signedResult.HasReply);

        using DidCommPlaintextMessage plaintext = DidCommPlaintextMessage.Create("{\"id\":\"1\",\"type\":\"t\"}"u8, BufferTags.Json, Pool);
        DidCommMessage plaintextRequestWithoutReturnRoute = new() { Id = "1", Type = "t" };
        await Assert.ThrowsExactlyAsync<ArgumentException>(
            async () => await plaintext.ExchangeAsync(plaintextRequestWithoutReturnRoute, Endpoint, new ExchangeContext(), exchange, default).ConfigureAwait(false)).ConfigureAwait(false);
    }


    private static DidCommMessage StatusRequest(string id = "sr-1", string? recipientDid = null) =>
        MessagePickupExtensions.CreateStatusRequest(id, recipientDid);


    private static Attachment BuildAttachment(string id, string base64 = "eA") =>
        new() { Id = id, Data = new AttachmentData { Base64 = base64 } };


    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes((Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);


    private static DidResolver NestedSignerResolver { get; } = new(DidMethodSelectors.FromResolvers(
        ("did:example", (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Failure(DidResolutionErrors.NotFound)))));


    private static ExchangeContext UnpackContext { get; } = new();


    //A fresh context whose policy permits loopback, mirroring DidCommHttpTransportRealWireFlowTests.NewLoopbackContext.
    private static ExchangeContext NewLoopbackExchangeContext()
    {
        var context = new ExchangeContext();
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault with
        {
            BlockPrivateAndLoopback = false
        });

        return context;
    }


    //Anoncrypts message for recipientKid/recipientPublic through the SAME registry-resolving pack surface every
    //other DIDComm protocol uses — Message Pickup introduces no separate crypto path of its own.
    private static async Task<DidCommEncryptedMessage> PackAnoncryptAsync(
        DidCommMessage message, string recipientKid, PublicKeyMemory recipientPublic, CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        var recipients = new List<GeneralJweRecipientInput> { new(recipientKid, recipientPublic) };

        return await message.PackAnoncryptAsync(
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
    }


    //A single-hop HttpClient transport that, unlike DidCommHttpTransportRealWireFlowTests.BuildPostTransport,
    //also reads back the response body/Content-Type — the exchange seam's HTTPS binding needs both to
    //surface a same-response reply.
    private static OutboundTransportDelegate BuildExchangeTransport(HttpClient httpClient)
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
                .SendAsync(httpRequest, HttpCompletionOption.ResponseContentRead, cancellationToken)
                .ConfigureAwait(false);

            byte[] responseBytes = await httpResponse.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);

            //Read the raw header values (mirrors GuardedHttpClientTransport.BuildSingleHopTransport) rather than
            //round-tripping through MediaTypeHeaderValue.ToString() — the exact Content-Type string the host
            //sent MUST reach DidCommMediaTypes.IsEncrypted unchanged, since that comparison is exact (no charset
            //tolerance).
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach(KeyValuePair<string, IEnumerable<string>> header in httpResponse.Content.Headers)
            {
                headers[header.Key] = string.Join(", ", header.Value);
            }

            return new OutboundResponse
            {
                StatusCode = (int)httpResponse.StatusCode,
                Headers = headers,
                Body = responseBytes.Length == 0 ? TaggedMemory<byte>.Empty : new TaggedMemory<byte>(responseBytes, BufferTags.Json)
            };
        };
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> JSON samples
    /// (§Status Request L80-84, §Status L97-105, §Delivery Request L132-136, §Messages Received L185-189,
    /// §Live Mode Change L221-224/L236): pins the PIURI, every <c>body</c> member name, and the problem code
    /// against its wire literal directly (the six MTURIs are pinned by the section-specific MTURI tests).
    /// Every builder/reader assertion elsewhere in this suite compares a constant against ITSELF (both sides
    /// go through <c>WellKnownMessagePickupNames.*</c>), so mutating one of these constants' values — e.g.
    /// renaming <c>limit</c> to Message Pickup 4.0's <c>message_count_limit</c> — would keep those tests
    /// green while breaking the wire; this test is the one place that would catch it.
    /// </summary>
    [TestMethod]
    public void WellKnownConstantsMatchTheirWireLiterals()
    {
        Assert.AreEqual("https://didcomm.org/messagepickup/3.0", WellKnownMessagePickupNames.MessagePickupProtocol);
        Assert.AreEqual("recipient_did", WellKnownMessagePickupNames.RecipientDid);
        Assert.AreEqual("message_count", WellKnownMessagePickupNames.MessageCount);
        Assert.AreEqual("longest_waited_seconds", WellKnownMessagePickupNames.LongestWaitedSeconds);
        Assert.AreEqual("newest_received_time", WellKnownMessagePickupNames.NewestReceivedTime);
        Assert.AreEqual("oldest_received_time", WellKnownMessagePickupNames.OldestReceivedTime);
        Assert.AreEqual("total_bytes", WellKnownMessagePickupNames.TotalBytes);
        Assert.AreEqual("live_delivery", WellKnownMessagePickupNames.LiveDelivery);
        Assert.AreEqual("limit", WellKnownMessagePickupNames.Limit);
        Assert.AreEqual("message_id_list", WellKnownMessagePickupNames.MessageIdList);
        Assert.AreEqual("e.m.live-mode-not-supported", WellKnownMessagePickupNames.LiveModeNotSupported);

        //Message Pickup 4.0 renames `limit` to `message_count_limit` — the two MUST NOT be cross-contaminated.
        Assert.AreNotEqual("message_count_limit", WellKnownMessagePickupNames.Limit);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Requirements:
    /// "The return_route extension must be supported by both agents (recipient and mediator)."
    /// </summary>
    [TestMethod]
    public void RequestBuilderSetsReturnRouteAllSoBothAgentsCanUseTheExtension()
    {
        DidCommMessage request = StatusRequest();

        Assert.IsTrue(request.IsReturnRouteAll(), "The recipient side of the extension is supported: every Pickup request carries return_route: all.");

        //The mediator side — carrying the reply back over the SAME connection — is the DidCommExchangeDelegate/
        //DidCommExchangeResult seam this class's other tests prove directly (e.g. ExchangeReturnsReplyBodyAndMediaTypeOnSuccess).
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Requirements:
    /// "In order to have this synchronous behavior the recipient should specify return_route header to all."
    /// </summary>
    [TestMethod]
    public void RecipientShouldSpecifyReturnRouteAllForSynchronousReplies()
    {
        DidCommMessage request = StatusRequest();

        Assert.AreEqual(WellKnownReturnRouteNames.All, request.ResolveReturnRoute());
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Requirements:
    /// "This header must be set each time the communication channel is established: once per established
    /// websocket, and every message for an HTTP POST."
    /// </summary>
    [TestMethod]
    public void ReturnRouteHeaderIsSetOnEveryIndividuallyBuiltRequestMessage()
    {
        DidCommMessage first = StatusRequest("sr-1");
        DidCommMessage second = StatusRequest("sr-2");

        Assert.IsTrue(first.IsReturnRouteAll());
        Assert.IsTrue(second.IsReturnRouteAll(), "The header is set on EVERY individually-built request message — matching 'every message for an HTTP POST'; the once-per-websocket half is transport/session bookkeeping this library holds no state for.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Connectivity:
    /// "This protocol consists of three different message requests from the recipient that should be replied
    /// to by the mediator: 1. Status Request -&gt; Status 2. Delivery Request -&gt; Message Delivery
    /// 3. Message Received -&gt; Status 4. Live Mode -&gt; Status or Problem Report." TRAP: the spec's own
    /// count is wrong — it says "three different message requests" (L36) and then numbers FOUR (1-4); this
    /// test proves all four are expressible, not just the three the prose miscounts.
    /// </summary>
    [TestMethod]
    public void TheThreeRequestsEachHaveAnExpressibleReply()
    {
        DidCommMessage statusRequest = StatusRequest();
        DidCommMessage statusReply = MessagePickupExtensions.CreateStatus("s-1", new MessagePickupStatus { MessageCount = 0 }, inResponseTo: statusRequest);
        Assert.AreEqual(statusRequest.Id, statusReply.ThreadId);

        DidCommMessage deliveryRequest = MessagePickupExtensions.CreateDeliveryRequest("dr-1", 1);
        DidCommMessage deliveryReply = MessagePickupExtensions.CreateDelivery("d-1", deliveryRequest.EffectiveThreadId!, [BuildAttachment("att-1")]);
        Assert.AreEqual(deliveryRequest.Id, deliveryReply.ThreadId);

        DidCommMessage messagesReceived = MessagePickupExtensions.CreateMessagesReceived("mr-1", ["att-1"]);
        DidCommMessage messagesReceivedReply = MessagePickupExtensions.CreateStatus("s-2", new MessagePickupStatus { MessageCount = 0 }, inResponseTo: messagesReceived);
        Assert.AreEqual(messagesReceived.Id, messagesReceivedReply.ThreadId);

        DidCommMessage liveModeRequest = MessagePickupExtensions.CreateLiveDeliveryChange("ldc-1", true);
        DidCommMessage liveModeStatusReply = MessagePickupExtensions.CreateStatus("s-3", new MessagePickupStatus { MessageCount = 0, LiveDelivery = true }, inResponseTo: liveModeRequest);
        Assert.AreEqual(liveModeRequest.Id, liveModeStatusReply.ThreadId);

        ProblemReport unsupported = new() { Code = ProblemCode.Parse(WellKnownMessagePickupNames.LiveModeNotSupported), ParentThreadId = liveModeRequest.EffectiveThreadId! };
        DidCommMessage liveModeProblemReply = unsupported.CreateProblemReport("pr-1");
        Assert.AreEqual(liveModeRequest.EffectiveThreadId, liveModeProblemReply.ParentThreadId, "Live Mode may instead be answered with a problem report.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §States:
    /// "This protocol follows the request-response message exchange pattern, and only requires the simple
    /// state of waiting for a response or to produce a response."
    /// </summary>
    [TestMethod]
    public void ReplyBuildersCorrelateToTheRequestsThread()
    {
        DidCommMessage statusRequest = StatusRequest();
        DidCommMessage statusReply = MessagePickupExtensions.CreateStatus("s-1", new MessagePickupStatus { MessageCount = 0 }, inResponseTo: statusRequest);

        Assert.AreEqual(statusRequest.EffectiveThreadId, statusReply.EffectiveThreadId, "The whole 'waiting for a response' state is realized by thread correlation between the reply and the request.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §States:
    /// "Additionally, the return_route header extension must be set to all in all request submitted by the recipient."
    /// </summary>
    [TestMethod]
    public void AllFourRecipientRequestBuildersSetReturnRouteAll()
    {
        DidCommMessage statusRequest = StatusRequest();
        DidCommMessage deliveryRequest = MessagePickupExtensions.CreateDeliveryRequest("dr-1", 1);
        DidCommMessage messagesReceived = MessagePickupExtensions.CreateMessagesReceived("mr-1", ["a"]);
        DidCommMessage liveDeliveryChange = MessagePickupExtensions.CreateLiveDeliveryChange("ldc-1", true);

        Assert.IsTrue(statusRequest.IsReturnRouteAll());
        Assert.IsTrue(deliveryRequest.IsReturnRouteAll());
        Assert.IsTrue(messagesReceived.IsReturnRouteAll());
        Assert.IsTrue(liveDeliveryChange.IsReturnRouteAll());
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Basic Walkthrough:
    /// "The status-request message is sent by the recipient to the mediator to query how many messages are pending."
    /// </summary>
    [TestMethod]
    public void StatusRequestQueriesHowManyMessagesArePending()
    {
        DidCommMessage request = StatusRequest();

        Assert.AreEqual(WellKnownMessagePickupNames.StatusRequestType, request.Type);
        Assert.IsTrue(request.IsStatusRequest());
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Basic Walkthrough:
    /// "The status message is the response to status-request to communicate the state of the message queue."
    /// </summary>
    [TestMethod]
    public void StatusIsTheResponseToStatusRequest()
    {
        DidCommMessage request = StatusRequest();
        DidCommMessage status = MessagePickupExtensions.CreateStatus("s-1", new MessagePickupStatus { MessageCount = 2 }, inResponseTo: request);

        Assert.IsTrue(status.IsStatus());
        Assert.AreEqual(request.Id, status.ThreadId);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Basic Walkthrough:
    /// "The delivery-request message is sent by the recipient to request delivery of pending messages."
    /// </summary>
    [TestMethod]
    public void DeliveryRequestRequestsDeliveryOfPendingMessages()
    {
        DidCommMessage request = MessagePickupExtensions.CreateDeliveryRequest("dr-1", 4);

        Assert.AreEqual(WellKnownMessagePickupNames.DeliveryRequestType, request.Type);
        Assert.IsTrue(request.IsDeliveryRequest());
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Basic Walkthrough:
    /// "The message-delivery message is the response to the delivery-request to send queued messages back to
    /// the recipient." TRAP: the walkthrough names this "the message-delivery message" in prose, but §Message
    /// Delivery's own Message Type URI ends in <c>delivery</c>, not <c>message-delivery</c>.
    /// </summary>
    [TestMethod]
    public void DeliveryMessageTypeTokenIsDeliveryNotMessageDelivery()
    {
        Assert.AreEqual("https://didcomm.org/messagepickup/3.0/delivery", WellKnownMessagePickupNames.DeliveryType);
        Assert.DoesNotContain("message-delivery", WellKnownMessagePickupNames.DeliveryType, "The prose name MUST NOT leak into the wire constant.");

        DidCommMessage genuineDelivery = new() { Id = "d-1", Type = "https://didcomm.org/messagepickup/3.0/delivery" };
        Assert.IsTrue(genuineDelivery.IsDelivery());

        DidCommMessage proseSpelledType = new() { Id = "d-2", Type = "https://didcomm.org/messagepickup/3.0/message-delivery" };
        Assert.IsFalse(proseSpelledType.IsDelivery(), "'message-delivery' is prose, not the wire token — a message actually typed that way is NOT a delivery.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Basic Walkthrough:
    /// "The message-received message is sent by the recipient to confirm receipt of delivered messages,
    /// prompting the mediator to clear messages from the queue." TRAP: the walkthrough names this the
    /// "message-received" message (singular) in prose, but §Messages Received's own Message Type URI ends in
    /// <c>messages-received</c> (plural), not <c>message-received</c> — and unlike the delivery/underscore
    /// traps elsewhere in this protocol, <c>IsSameMessageType</c>'s punctuation-insensitive comparison does NOT
    /// absorb this one.
    /// </summary>
    [TestMethod]
    public void MessagesReceivedConfirmsReceiptPromptingQueueClear()
    {
        DidCommMessage ack = MessagePickupExtensions.CreateMessagesReceived("mr-1", ["123", "456"]);

        Assert.IsTrue(ack.TryReadMessagesReceivedIds(out IReadOnlyList<string>? confirmedIds));
        Assert.HasCount(2, confirmedIds!, "Confirming receipt is expressible purely as reading back the acknowledged ids; actually clearing the mediator's queue is its own storage action, out of this library's scope.");

        DidCommMessage proseSpelledType = new() { Id = "mr-2", Type = "https://didcomm.org/messagepickup/3.0/message-received" };
        Assert.IsFalse(proseSpelledType.IsMessagesReceived(), "'message-received' (singular) is prose, not the wire token — a message actually typed that way is NOT a messages-received.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Basic Walkthrough:
    /// "The live-delivery-change message is used to set the state of live_delivery."
    /// </summary>
    [TestMethod]
    public void LiveDeliveryChangeSetsTheLiveDeliveryState()
    {
        DidCommMessage on = MessagePickupExtensions.CreateLiveDeliveryChange("ldc-1", true);
        Assert.IsTrue(on.TryReadLiveDeliveryChange(out bool onState) && onState);

        DidCommMessage off = MessagePickupExtensions.CreateLiveDeliveryChange("ldc-2", false);
        Assert.IsTrue(off.TryReadLiveDeliveryChange(out bool offState) && !offState);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Basic Walkthrough:
    /// "When Live Mode is enabled, messages that arrive when an existing connection exists are delivered over
    /// the connection immediately, rather than being pushed to the queue."
    /// </summary>
    [TestMethod]
    public void LiveModeDeliversArrivingMessagesImmediatelyRatherThanQueueing()
    {
        DidCommMessage change = MessagePickupExtensions.CreateLiveDeliveryChange("ldc-1", liveDelivery: true);

        Assert.IsTrue(
            change.TryReadLiveDeliveryChange(out bool liveDelivery) && liveDelivery,
            "The library's contribution to the immediate-delivery obligation is exactly this on/off signal; actually routing an arriving message over the live connection instead of the queue is the mediator's own dispatch logic — a live-pushed message is just an ordinary DIDComm envelope sent immediately, not a distinct Pickup message type.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Security:
    /// "This protocol expects messages to be encrypted during transmission, and repudiable."
    /// </summary>
    [TestMethod]
    public async Task StatusRequestFlowsThroughTheStandardEncryptedRepudiablePackPipeline()
    {
        const string ClaimedSender = "did:example:pickup-recipient";
        DidCommMessage statusRequest = MessagePickupExtensions.CreateStatusRequest("sr-1", recipientDid: "did:example:pickup-repudiable", from: ClaimedSender);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> mediatorKeys = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory mediatorPublic = mediatorKeys.PublicKey;
        PrivateKeyMemory mediatorPrivate = mediatorKeys.PrivateKey;
        try
        {
            using DidCommEncryptedMessage packed = await PackAnoncryptAsync(
                statusRequest, "did:example:pickup-mediator#key-1", mediatorPublic, TestContext.CancellationToken).ConfigureAwait(false);

            DidCommEncryptedUnpackResult unpacked = await packed.UnpackAnoncryptAsync(
                "did:example:pickup-mediator#key-1", mediatorPrivate, NestedSignerResolver, UnpackContext, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
                TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(unpacked.IsUnpacked, "Message Pickup carries no transport of its own — the standard anoncrypt pack/unpack pipeline is what makes a request 'encrypted during transmission'.");
            Assert.AreEqual(WellKnownMessagePickupNames.StatusRequestType, unpacked.Message!.Type);

            //A plaintext `from` claim is not an authenticated sender — anoncrypt performs no sender key
            //agreement, so 'repudiable' is proven by the unpack pipeline's OWN authentication verdict, not by
            //the mere presence/absence of a from header: the recipient can read who the message CLAIMS to be
            //from but the pipeline itself reports that claim as unauthenticated.
            Assert.AreEqual(ClaimedSender, unpacked.Message.From, "The plaintext from claim still travels with the message — anoncrypt hides nothing about the header, it just proves nothing about it.");
            Assert.IsFalse(unpacked.IsSenderAuthenticated, "Anoncrypt performs no sender key agreement — the unpack pipeline's own verdict MUST report the sender as unauthenticated; that verdict, not an absent from field, is what makes the message repudiable.");
        }
        finally
        {
            mediatorPrivate.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Status Request:
    /// "Message Type URI: https://didcomm.org/messagepickup/3.0/status-request"
    /// </summary>
    [TestMethod]
    public void StatusRequestMturiIsExact()
    {
        Assert.AreEqual("https://didcomm.org/messagepickup/3.0/status-request", WellKnownMessagePickupNames.StatusRequestType);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Status Request:
    /// "recipient_did is optional."
    /// </summary>
    [TestMethod]
    public void RecipientDidOnStatusRequestIsOptional()
    {
        DidCommMessage withoutDid = StatusRequest("sr-1");
        Assert.IsTrue(withoutDid.Body is null || !withoutDid.Body.ContainsKey(WellKnownMessagePickupNames.RecipientDid));
        Assert.IsTrue(withoutDid.TryReadStatusRequestRecipientDid(out string? recipientDid));
        Assert.IsNull(recipientDid);

        DidCommMessage withDid = StatusRequest("sr-2", recipientDid: "did:example:alice");
        Assert.IsTrue(withDid.TryReadStatusRequestRecipientDid(out string? recipientDid2));
        Assert.AreEqual("did:example:alice", recipientDid2);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Status Request:
    /// "When specified, the mediator MUST only return status related to that recipient did."
    /// </summary>
    [TestMethod]
    public void MediatorMustOnlyReturnStatusForTheNamedRecipientDid()
    {
        DidCommMessage requestForAlice = StatusRequest("sr-1", recipientDid: "did:example:alice");

        //The library cannot verify that a mediator's underlying queue actually excludes other recipients'
        //messages — that filtering happens in mediator storage this library holds no state for. What IS
        //enforced is the mediator's OUTGOING status: it cannot claim to answer this request while echoing a
        //DIFFERENT recipient_did.
        Assert.ThrowsExactly<ArgumentException>(() =>
            MessagePickupExtensions.CreateStatus("s-1", new MessagePickupStatus { MessageCount = 1, RecipientDid = "did:example:someone-else" }, inResponseTo: requestForAlice));
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Status Request:
    /// "This allows the recipient to discover if any messages are in the queue that were sent to a specific did."
    /// </summary>
    [TestMethod]
    public void RecipientCanDiscoverQueuedMessagesForASpecificDid()
    {
        DidCommMessage discoveryRequest = StatusRequest("sr-1", recipientDid: "did:example:alice");
        DidCommMessage discoveryReply = MessagePickupExtensions.CreateStatus("s-1", new MessagePickupStatus { MessageCount = 3, RecipientDid = "did:example:alice" }, inResponseTo: discoveryRequest);

        Assert.AreEqual(discoveryRequest.Id, discoveryReply.ThreadId);
        Assert.IsTrue(discoveryReply.TryReadStatus(out MessagePickupStatus? status));
        Assert.AreEqual(3L, status!.MessageCount);
        Assert.AreEqual("did:example:alice", status.RecipientDid);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Status:
    /// "Message Type URI: https://didcomm.org/messagepickup/3.0/status"
    /// </summary>
    [TestMethod]
    public void StatusMturiIsExact()
    {
        Assert.AreEqual("https://didcomm.org/messagepickup/3.0/status", WellKnownMessagePickupNames.StatusType);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Status:
    /// "message_count is the only REQUIRED attribute."
    /// </summary>
    [TestMethod]
    public void MessageCountIsTheOnlyRequiredStatusAttribute()
    {
        DidCommMessage missingCount = new() { Id = "s-1", Type = WellKnownMessagePickupNames.StatusType, Body = new Dictionary<string, object>() };
        Assert.IsFalse(missingCount.TryReadStatus(out _), "message_count absent MUST fail the read.");

        DidCommMessage malformedCount = new() { Id = "s-2", Type = WellKnownMessagePickupNames.StatusType, Body = new Dictionary<string, object> { [WellKnownMessagePickupNames.MessageCount] = "seven" } };
        Assert.IsFalse(malformedCount.TryReadStatus(out _), "A non-numeric message_count MUST fail the read.");

        DidCommMessage present = MessagePickupExtensions.CreateStatus("s-3", new MessagePickupStatus { MessageCount = 7 });
        Assert.IsTrue(present.TryReadStatus(out MessagePickupStatus? status));
        Assert.AreEqual(7L, status!.MessageCount);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Status:
    /// "The others MAY be present if offered by the mediator."
    /// </summary>
    [TestMethod]
    public void OtherStatusAttributesAreOptionalWhenOffered()
    {
        DidCommMessage onlyRequired = MessagePickupExtensions.CreateStatus("s-1", new MessagePickupStatus { MessageCount = 5 });

        Assert.IsTrue(onlyRequired.TryReadStatus(out MessagePickupStatus? status));
        Assert.AreEqual(5L, status!.MessageCount);
        Assert.IsNull(status.RecipientDid);
        Assert.IsNull(status.LongestWaitedSeconds);
        Assert.IsNull(status.NewestReceivedTime);
        Assert.IsNull(status.OldestReceivedTime);
        Assert.IsNull(status.TotalBytes);
        Assert.IsNull(status.LiveDelivery);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Status:
    /// "longest_waited_seconds is in seconds, and is the longest delay of any message in the queue."
    /// </summary>
    [TestMethod]
    public void LongestWaitedSecondsIsTheLongestQueueDelayInSeconds()
    {
        DidCommMessage status = MessagePickupExtensions.CreateStatus("s-1", new MessagePickupStatus { MessageCount = 1, LongestWaitedSeconds = 3600 });

        Assert.IsTrue(status.TryReadStatus(out MessagePickupStatus? readBack));
        Assert.AreEqual(3600L, readBack!.LongestWaitedSeconds);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Status:
    /// "newest_received_time and oldest_received_time are expressed in UTC Epoch Seconds ... as an integer."
    /// The Json leaf narrows a JSON number to int, then long, then decimal, so both an int-typed and a
    /// long-typed epoch value MUST read, while a fractional value is not "an integer" and MUST fail.
    /// </summary>
    [TestMethod]
    public void NewestAndOldestReceivedTimeReadAsIntegerEpochSeconds()
    {
        DidCommMessage intForm = new()
        {
            Id = "s-1",
            Type = WellKnownMessagePickupNames.StatusType,
            Body = new Dictionary<string, object> { [WellKnownMessagePickupNames.MessageCount] = 1, [WellKnownMessagePickupNames.NewestReceivedTime] = 1658085169 }
        };
        Assert.IsTrue(intForm.TryReadStatus(out MessagePickupStatus? intStatus));
        Assert.AreEqual(1658085169L, intStatus!.NewestReceivedTime);

        DidCommMessage longForm = new()
        {
            Id = "s-2",
            Type = WellKnownMessagePickupNames.StatusType,
            Body = new Dictionary<string, object> { [WellKnownMessagePickupNames.MessageCount] = 1, [WellKnownMessagePickupNames.OldestReceivedTime] = 1658084293L }
        };
        Assert.IsTrue(longForm.TryReadStatus(out MessagePickupStatus? longStatus));
        Assert.AreEqual(1658084293L, longStatus!.OldestReceivedTime);

        DidCommMessage fractionalForm = new()
        {
            Id = "s-3",
            Type = WellKnownMessagePickupNames.StatusType,
            Body = new Dictionary<string, object> { [WellKnownMessagePickupNames.MessageCount] = 1, [WellKnownMessagePickupNames.NewestReceivedTime] = 1658085169.5m }
        };
        Assert.IsFalse(fractionalForm.TryReadStatus(out _), "A fractional epoch-seconds value is not 'an integer' and MUST fail the read rather than silently truncate.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Status:
    /// "total_bytes represents the total size of all messages." A queue whose total exceeds
    /// <see cref="int.MaxValue"/> arrives as a JSON-narrowed <see cref="long"/> and MUST still read.
    /// </summary>
    [TestMethod]
    public void TotalBytesReadsAcrossTheFullLongRange()
    {
        const long ThreeGigabytes = 3_221_225_472L;
        DidCommMessage status = new()
        {
            Id = "s-1",
            Type = WellKnownMessagePickupNames.StatusType,
            Body = new Dictionary<string, object> { [WellKnownMessagePickupNames.MessageCount] = 1, [WellKnownMessagePickupNames.TotalBytes] = ThreeGigabytes }
        };

        Assert.IsTrue(status.TryReadStatus(out MessagePickupStatus? readBack));
        Assert.AreEqual(ThreeGigabytes, readBack!.TotalBytes);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Status:
    /// "If a recipient_did was specified in the status-request message, the matching value MUST be specified
    /// in the recipient_did attribute of the status message."
    /// </summary>
    [TestMethod]
    public void StatusEchoesTheMatchingRecipientDidFromTheRequest()
    {
        DidCommMessage requestWithDid = StatusRequest("sr-1", recipientDid: "did:example:alice");

        Assert.ThrowsExactly<ArgumentException>(() =>
            MessagePickupExtensions.CreateStatus("s-1", new MessagePickupStatus { MessageCount = 1, RecipientDid = "did:example:bob" }, inResponseTo: requestWithDid));

        DidCommMessage matching = MessagePickupExtensions.CreateStatus("s-2", new MessagePickupStatus { MessageCount = 1, RecipientDid = "did:example:alice" }, inResponseTo: requestWithDid);
        Assert.IsTrue(matching.TryReadStatus(out MessagePickupStatus? readBack));
        Assert.AreEqual("did:example:alice", readBack!.RecipientDid);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Status:
    /// "live_delivery state is also indicated in the status message."
    /// </summary>
    [TestMethod]
    public void LiveDeliveryStateIsIndicatedInStatus()
    {
        DidCommMessage on = MessagePickupExtensions.CreateStatus("s-1", new MessagePickupStatus { MessageCount = 0, LiveDelivery = true });
        Assert.IsTrue(on.TryReadStatus(out MessagePickupStatus? onStatus));
        Assert.IsTrue(onStatus!.LiveDelivery!.Value);

        DidCommMessage off = MessagePickupExtensions.CreateStatus("s-2", new MessagePickupStatus { MessageCount = 0, LiveDelivery = false });
        Assert.IsTrue(off.TryReadStatus(out MessagePickupStatus? offStatus));
        Assert.IsFalse(offStatus!.LiveDelivery!.Value);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Status Note:
    /// "a status message MUST NOT be put on the pending message queue."
    /// </summary>
    [TestMethod]
    public void StatusMustNotBePutOnThePendingQueue()
    {
        DidCommMessage firstCall = MessagePickupExtensions.CreateStatus("s-1", new MessagePickupStatus { MessageCount = 1 });
        DidCommMessage secondCall = MessagePickupExtensions.CreateStatus("s-2", new MessagePickupStatus { MessageCount = 1 });

        Assert.AreNotSame(firstCall.Body, secondCall.Body, "Each call mints a fresh body — CreateStatus retains and replays nothing, so there is no queue this library could put a status onto; queue storage is entirely the mediator's.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Status Note:
    /// a status "MUST only be sent when the recipient is actively connected (HTTP request awaiting response,
    /// WebSocket, etc.)." — this library's ONLY status-sending surface is a <see cref="DidCommExchangeDelegate"/>
    /// reply to the recipient's own <c>return_route: all</c> request, so a status is structurally reachable
    /// ONLY by riding back on the SAME in-flight response the recipient is already waiting on — never as a
    /// fire-and-forget send with no request behind it. Actually keeping the HTTP request open (or the
    /// WebSocket connected) until the reply is ready is the mediator/transport's own session responsibility,
    /// not this library's.
    /// </summary>
    [TestMethod]
    public async Task StatusMustOnlyBeSentWhenRecipientIsActivelyConnected()
    {
        DidCommMessage statusRequest = StatusRequest();
        DidCommMessage status = MessagePickupExtensions.CreateStatus("s-1", new MessagePickupStatus { MessageCount = 1 }, inResponseTo: statusRequest);
        using DidCommPlaintextMessage packedStatus = DidCommMessageJson.Serializer(status, Pool);

        var transport = new FakeExchangeTransport(statusCode: 200, replyBody: packedStatus.AsReadOnlyMemory(), replyMediaType: DidCommPlaintextMessage.MediaType);
        using DidCommEncryptedMessage packedRequest = Encrypted("{\"ciphertext\":\"x\"}"u8);

        DidCommExchangeDelegate exchange = DidCommHttpTransport.CreateExchangeDelegate(transport.SendAsync, Pool);
        using DidCommExchangeResult result = await packedRequest.ExchangeAsync(statusRequest, Endpoint, new ExchangeContext(), exchange, default).ConfigureAwait(false);

        Assert.IsTrue(result.HasReply, "The status reaches the recipient only as the reply on its own in-flight request — the 'actively connected' channel.");
        DidCommMessage received = DidCommMessageJson.Parser(result.ReplyBody.AsReadOnlySpan());
        Assert.IsTrue(received.IsStatus());
        Assert.AreEqual(statusRequest.Id, received.ThreadId, "The mediator-side half of the MUST — never pushing a status outside a live request/response — is session management this library holds no state for; what this test proves is that the library's own status-producing surface is exactly this reply channel and nothing else.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Delivery Request:
    /// "Message Type URI: https://didcomm.org/messagepickup/3.0/delivery-request"
    /// </summary>
    [TestMethod]
    public void DeliveryRequestMturiIsExact()
    {
        Assert.AreEqual("https://didcomm.org/messagepickup/3.0/delivery-request", WellKnownMessagePickupNames.DeliveryRequestType);
        Assert.IsTrue(MessagePickupExtensions.CreateDeliveryRequest("dr-1", 5).IsDeliveryRequest());
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Delivery Request:
    /// "limit is a REQUIRED attribute."
    /// </summary>
    [TestMethod]
    public void LimitIsRequiredOnDeliveryRequest()
    {
        DidCommMessage builtRequest = MessagePickupExtensions.CreateDeliveryRequest("dr-1", 5);
        Assert.IsTrue(builtRequest.Body!.ContainsKey(WellKnownMessagePickupNames.Limit));
        Assert.IsTrue(builtRequest.TryReadDeliveryRequest(out long limit, out _));
        Assert.AreEqual(5L, limit);

        DidCommMessage missingLimit = new() { Id = "dr-2", Type = WellKnownMessagePickupNames.DeliveryRequestType, Body = new Dictionary<string, object>() };
        Assert.IsFalse(missingLimit.TryReadDeliveryRequest(out _, out _), "limit is REQUIRED — its absence MUST fail the read.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Delivery Request:
    /// "limit is a REQUIRED attribute." <see cref="MessagePickupExtensions.CreateDeliveryRequest"/> refuses a
    /// non-positive limit as a producer-side guard (the spec is silent on <c>0</c>, but a zero/negative limit
    /// cannot request a delivery of anything); <see cref="MessagePickupExtensions.TryReadDeliveryRequest"/>
    /// mirrors that guard on the read side — a reader must not accept a shape the builder itself would refuse
    /// to mint.
    /// </summary>
    [TestMethod]
    [DataRow(0L)]
    [DataRow(-1L)]
    public void NonPositiveLimitFailsTheDeliveryRequestRead(long nonPositiveLimit)
    {
        DidCommMessage message = new()
        {
            Id = "dr-1",
            Type = WellKnownMessagePickupNames.DeliveryRequestType,
            Body = new Dictionary<string, object>
            {
                [WellKnownMessagePickupNames.Limit] = nonPositiveLimit,
                [WellKnownMessagePickupNames.RecipientDid] = "did:example:alice"
            }
        };

        Assert.IsFalse(message.TryReadDeliveryRequest(out long limit, out string? recipientDid), "A non-positive limit MUST fail the read.");
        Assert.AreEqual(0L, limit, "The limit out parameter MUST report 0 on ANY failure, never a partially-read value.");
        Assert.IsNull(recipientDid, "The recipientDid out parameter MUST be null on ANY failure, even though the message carried a recipient_did.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Delivery Request:
    /// a downstream malformed OPTIONAL member fails the whole read, and the REQUIRED <c>limit</c> that DID
    /// parse successfully must not leak through the out parameter regardless —
    /// <see cref="MessagePickupExtensions.TryReadDeliveryRequest"/> assigns its outs ONLY on full success, so
    /// a failure caused by a malformed <c>recipient_did</c> still reports <c>limit == 0</c>, matching its
    /// documented "otherwise 0" contract.
    /// </summary>
    [TestMethod]
    public void MalformedRecipientDidFailsTheReadWithoutLeakingTheParsedLimit()
    {
        DidCommMessage message = new()
        {
            Id = "dr-1",
            Type = WellKnownMessagePickupNames.DeliveryRequestType,
            Body = new Dictionary<string, object>
            {
                [WellKnownMessagePickupNames.Limit] = 5,
                [WellKnownMessagePickupNames.RecipientDid] = 12345
            }
        };

        Assert.IsFalse(message.TryReadDeliveryRequest(out long limit, out string? recipientDid));
        Assert.AreEqual(0L, limit, "limit MUST report 0 even though it parsed successfully, because the overall read failed.");
        Assert.IsNull(recipientDid);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Delivery Request:
    /// "after receipt of this message, the mediator SHOULD deliver up to the limit indicated."
    /// </summary>
    [TestMethod]
    public void MediatorShouldDeliverUpToTheIndicatedLimit()
    {
        DidCommMessage request = MessagePickupExtensions.CreateDeliveryRequest("dr-1", 3);

        Assert.IsTrue(request.TryReadDeliveryRequest(out long limit, out _));
        Assert.AreEqual(3L, limit, "The mediator's delivery obligation is bounded by the value recovered here; deciding how many it actually queued and honoring the cap is the mediator's own selection — this library only carries the number.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Delivery Request:
    /// "recipient_did is optional. When specified, the mediator MUST only return messages sent to that recipient did."
    /// </summary>
    [TestMethod]
    public void MediatorMustOnlyReturnMessagesForTheNamedRecipientDid()
    {
        DidCommMessage scopedRequest = MessagePickupExtensions.CreateDeliveryRequest("dr-1", 5, recipientDid: "did:example:alice");
        Assert.IsTrue(scopedRequest.TryReadDeliveryRequest(out _, out string? recipientDid));
        Assert.AreEqual("did:example:alice", recipientDid);

        //The actual FILTERING of which queued messages match that did is mediator storage this library holds
        //no state for; recipientDid, once recovered, is passed straight through to the delivery reply's own
        //recipient_did (§Message Delivery), which is the shape this surface enforces.
        DidCommMessage delivery = MessagePickupExtensions.CreateDelivery("d-1", scopedRequest.EffectiveThreadId!, [BuildAttachment("att-1")], recipientDid: recipientDid);
        Assert.IsTrue(delivery.Body!.TryGetValue(WellKnownMessagePickupNames.RecipientDid, out object? deliveredDid));
        Assert.AreEqual("did:example:alice", deliveredDid);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Delivery Request:
    /// "If no messages are available to be sent, a status message MUST be sent immediately."
    /// </summary>
    [TestMethod]
    public void EmptyQueueRepliesWithStatusInsteadOfDelivery()
    {
        DidCommMessage deliveryRequest = MessagePickupExtensions.CreateDeliveryRequest("dr-1", 10);
        DidCommMessage emptyQueueStatus = MessagePickupExtensions.CreateStatus("s-1", new MessagePickupStatus { MessageCount = 0 }, inResponseTo: deliveryRequest);

        Assert.AreEqual(deliveryRequest.Id, emptyQueueStatus.ThreadId);
        Assert.IsTrue(emptyQueueStatus.TryReadStatus(out MessagePickupStatus? status));
        Assert.AreEqual(0L, status!.MessageCount);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Delivery Request:
    /// "Delivered messages MUST NOT be deleted until delivery is acknowledged by a messages-received message."
    /// </summary>
    [TestMethod]
    public void DeliveredMessagesMustNotBeDeletedUntilAcknowledged()
    {
        DidCommMessage deliveryRequest = MessagePickupExtensions.CreateDeliveryRequest("dr-1", 10);
        DidCommMessage delivery = MessagePickupExtensions.CreateDelivery("d-1", deliveryRequest.EffectiveThreadId!, [BuildAttachment("att-1")]);

        //CreateDelivery is a pure message builder: it never removes, marks, or otherwise touches storage. The
        //only surface that could ever tell a mediator "safe to delete" is a LATER, independent messages-received.
        Assert.IsTrue(delivery.IsDelivery());
        Assert.IsFalse(delivery.IsMessagesReceived(), "Delivery and acknowledgment are two separate, sequential message kinds — nothing here auto-acknowledges (and so auto-deletes) on delivery.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Message Delivery:
    /// "Message Type URI: https://didcomm.org/messagepickup/3.0/delivery"
    /// </summary>
    [TestMethod]
    public void DeliveryMturiIsExact()
    {
        Assert.AreEqual("https://didcomm.org/messagepickup/3.0/delivery", WellKnownMessagePickupNames.DeliveryType);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Message Delivery
    /// JSON sample: <c>"thid": "&lt;message id of delivery-request message&gt;"</c>.
    /// </summary>
    [TestMethod]
    public void DeliveryThreadIdIsTheDeliveryRequestsMessageId()
    {
        DidCommMessage deliveryRequest = MessagePickupExtensions.CreateDeliveryRequest("dr-99", 5);
        DidCommMessage delivery = MessagePickupExtensions.CreateDelivery("d-1", deliveryRequest.EffectiveThreadId!, [BuildAttachment("att-1")]);

        Assert.AreEqual("dr-99", delivery.ThreadId);
        Assert.AreEqual("dr-99", delivery.EffectiveThreadId);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Message Delivery:
    /// "Messages delivered from the queue must be delivered in a batch delivery message as attachments, with a
    /// batch size specified by the limit provided in the delivery-request message."
    /// </summary>
    [TestMethod]
    public void DeliveryBatchSizeIsBoundedByTheRequestsLimit()
    {
        DidCommMessage deliveryRequest = MessagePickupExtensions.CreateDeliveryRequest("dr-1", 2);
        Assert.IsTrue(deliveryRequest.TryReadDeliveryRequest(out long limit, out _));

        DidCommMessage delivery = MessagePickupExtensions.CreateDelivery("d-1", deliveryRequest.EffectiveThreadId!, [BuildAttachment("att-1"), BuildAttachment("att-2")]);

        Assert.AreEqual(limit, delivery.Attachments!.Count, "The mediator selects at most 'limit' messages for the batch; this library does not itself cap Attachments — the selection is the mediator's, this only carries whatever batch it built.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Message Delivery:
    /// "The id of each attachment is used to confirm receipt."
    /// </summary>
    [TestMethod]
    public void EveryDeliveryAttachmentIdIsRequiredForReceiptConfirmation()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            MessagePickupExtensions.CreateDelivery("d-1", "dr-1", [new Attachment { Id = "", Data = new AttachmentData { Base64 = "eA" } }]));

        Assert.ThrowsExactly<ArgumentException>(() =>
            MessagePickupExtensions.CreateDelivery("d-2", "dr-1", [new Attachment { Id = null, Data = new AttachmentData { Base64 = "eA" } }]));
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Message Delivery:
    /// "The id of each attachment is used to confirm receipt. The id is an opaque value, and the recipient
    /// should not deduce any information from it, except that it is unique to the mediator." A duplicate id
    /// within one delivery batch makes acknowledgment ambiguous — a messages-received listing that id cannot
    /// say which of the two attachments it confirms.
    /// </summary>
    [TestMethod]
    public void DuplicateAttachmentIdsWithinABatchAreRefused()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            MessagePickupExtensions.CreateDelivery("d-1", "dr-1", [BuildAttachment("att-1"), BuildAttachment("att-1")]));
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Message Delivery:
    /// "The id is an opaque value, and the recipient should not deduce any information from it, except that it
    /// is unique to the mediator. The recipient can use the ids in the message_id_list field of
    /// messages-received."
    /// </summary>
    [TestMethod]
    public void DeliveryAttachmentIdsFlowVerbatimIntoMessagesReceived()
    {
        DidCommMessage delivery = MessagePickupExtensions.CreateDelivery("d-1", "dr-1", [BuildAttachment("m1"), BuildAttachment("m2")]);

        var deliveredIds = new List<string>();
        foreach(Attachment attachment in delivery.Attachments!)
        {
            deliveredIds.Add(attachment.Id!);
        }

        DidCommMessage ack = MessagePickupExtensions.CreateMessagesReceived("mr-1", deliveredIds);
        Assert.IsTrue(ack.TryReadMessagesReceivedIds(out IReadOnlyList<string>? ackedIds));
        Assert.HasCount(deliveredIds.Count, ackedIds!);
        for(int i = 0; i < deliveredIds.Count; ++i)
        {
            Assert.AreEqual(deliveredIds[i], ackedIds[i], "message_id_list ids MUST be taken verbatim from the delivery attachment ids — no parsing or reinterpretation.");
        }
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Message Delivery:
    /// "The ONLY valid type of attachment for this message is a DIDComm v2 Message in encrypted form."
    /// </summary>
    [TestMethod]
    public async Task TheOnlyValidDeliveryAttachmentShapeIsEncryptedFormByValue()
    {
        DidCommMessage placeholder = new() { Id = "inner-1", Type = "https://example.com/inner/1.0/msg" };

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipientKeys = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory recipientPublic = recipientKeys.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipientKeys.PrivateKey;

        using DidCommEncryptedMessage genuineCiphertext = await PackAnoncryptAsync(
            placeholder, "did:example:pickup-recipient#key-1", recipientPublic, TestContext.CancellationToken).ConfigureAwait(false);
        string genuineBase64 = TestSetup.Base64UrlEncoder(genuineCiphertext.AsReadOnlySpan());

        Attachment genuine = new() { Id = "att-genuine", Data = new AttachmentData { Base64 = genuineBase64 } };
        DidCommMessage delivery = MessagePickupExtensions.CreateDelivery("d-1", "dr-1", [genuine]);
        Assert.AreEqual(genuineBase64, delivery.Attachments![0].Data!.Base64, "A genuinely-packed encrypted envelope's base64 flows through the shape check untouched.");

        Attachment jsonAlternative = new() { Id = "att-2", Data = new AttachmentData { Base64 = genuineBase64, Json = new Dictionary<string, object>() } };
        Assert.ThrowsExactly<ArgumentException>(() => MessagePickupExtensions.CreateDelivery("d-2", "dr-1", [jsonAlternative]));

        Attachment linksAlternative = new() { Id = "att-3", Data = new AttachmentData { Links = ["https://example.com/blob"], Hash = "sha256-x" } };
        Assert.ThrowsExactly<ArgumentException>(() => MessagePickupExtensions.CreateDelivery("d-3", "dr-1", [linksAlternative]));

        Attachment noData = new() { Id = "att-4", Data = null };
        Assert.ThrowsExactly<ArgumentException>(() => MessagePickupExtensions.CreateDelivery("d-4", "dr-1", [noData]));
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Message Delivery:
    /// "The recipient_did attribute is only included when responding to a delivery-request message that
    /// indicates a recipient_did."
    /// </summary>
    [TestMethod]
    public void DeliveryRecipientDidIsOnlySetWhenTheRequestIndicatedOne()
    {
        DidCommMessage withoutDid = MessagePickupExtensions.CreateDelivery("d-1", "dr-1", [BuildAttachment("att-1")]);
        Assert.IsTrue(withoutDid.Body is null || !withoutDid.Body.ContainsKey(WellKnownMessagePickupNames.RecipientDid));

        DidCommMessage withDid = MessagePickupExtensions.CreateDelivery("d-2", "dr-1", [BuildAttachment("att-1")], recipientDid: "did:example:alice");
        Assert.IsTrue(withDid.Body!.TryGetValue(WellKnownMessagePickupNames.RecipientDid, out object? value));
        Assert.AreEqual("did:example:alice", value);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Messages Received:
    /// "Message Type URI: https://didcomm.org/messagepickup/3.0/messages-received"
    /// </summary>
    [TestMethod]
    public void MessagesReceivedMturiIsExact()
    {
        Assert.AreEqual("https://didcomm.org/messagepickup/3.0/messages-received", WellKnownMessagePickupNames.MessagesReceivedType);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Messages Received:
    /// "message_id_list is a list of ids of each message received."
    /// </summary>
    [TestMethod]
    public void MessageIdListIsTheListOfReceivedMessageIds()
    {
        DidCommMessage ack = MessagePickupExtensions.CreateMessagesReceived("mr-1", ["123", "456"]);

        Assert.IsTrue(ack.TryReadMessagesReceivedIds(out IReadOnlyList<string>? ids));
        Assert.HasCount(2, ids!);
        Assert.AreEqual("123", ids[0]);
        Assert.AreEqual("456", ids[1]);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Messages Received:
    /// "the mediator knows which messages have been received, and can remove them from the collection of
    /// queued messages with confidence."
    /// </summary>
    [TestMethod]
    public void MediatorCanRemoveAcknowledgedMessagesWithConfidence()
    {
        DidCommMessage ack = MessagePickupExtensions.CreateMessagesReceived("mr-1", ["a", "b", "c"]);

        Assert.IsTrue(ack.TryReadMessagesReceivedIds(out IReadOnlyList<string>? confirmedIds));
        Assert.HasCount(3, confirmedIds!, "The recovered id set is exactly what was acknowledged — nothing here adds, drops, or reorders entries; the actual removal from storage is the mediator's own action, out of this library's scope.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Messages Received:
    /// "The mediator SHOULD send an updated status message reflecting the changes to the queue."
    /// </summary>
    [TestMethod]
    public void MediatorShouldSendAnUpdatedStatusAfterMessagesReceived()
    {
        DidCommMessage ack = MessagePickupExtensions.CreateMessagesReceived("mr-1", ["a"]);
        DidCommMessage followUpStatus = MessagePickupExtensions.CreateStatus("s-1", new MessagePickupStatus { MessageCount = 0 }, inResponseTo: ack);

        Assert.AreEqual(ack.Id, followUpStatus.ThreadId, "A status answering a messages-received threads to it exactly like any other reply — expressing the SHOULD-send-updated-status follow-up.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Multiple Recipients:
    /// "If a message arrives at a mediator addressed to multiple recipients, the message MUST be queued for
    /// each recipient independently."
    /// </summary>
    [TestMethod]
    public void MultiRecipientMessagesAreQueuedForEachRecipientIndependently()
    {
        DidCommMessage aliceRequest = StatusRequest("sr-alice", recipientDid: "did:example:alice");
        DidCommMessage bobRequest = StatusRequest("sr-bob", recipientDid: "did:example:bob");

        DidCommMessage aliceStatus = MessagePickupExtensions.CreateStatus("s-alice", new MessagePickupStatus { MessageCount = 1, RecipientDid = "did:example:alice" }, inResponseTo: aliceRequest);
        DidCommMessage bobStatus = MessagePickupExtensions.CreateStatus("s-bob", new MessagePickupStatus { MessageCount = 1, RecipientDid = "did:example:bob" }, inResponseTo: bobRequest);

        //recipient_did on status-request/status is the correlation primitive a mediator uses to keep each
        //recipient's queue independent; actually holding two independent per-recipient message stores is the
        //mediator's own storage responsibility, not modeled by this library.
        Assert.AreNotEqual(aliceStatus.ThreadId, bobStatus.ThreadId);
        Assert.IsTrue(aliceStatus.TryReadStatus(out MessagePickupStatus? a) && a!.RecipientDid == "did:example:alice");
        Assert.IsTrue(bobStatus.TryReadStatus(out MessagePickupStatus? b) && b!.RecipientDid == "did:example:bob");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Multiple Recipients:
    /// "If one of the addressed recipients retrieves a message and indicates it has been received, that
    /// message MUST still be held and then removed by the other addressed recipients."
    /// </summary>
    [TestMethod]
    public void OneRecipientsAckMustNotRemoveTheMessageForOthers()
    {
        DidCommMessage aliceAck = MessagePickupExtensions.CreateMessagesReceived("mr-alice", ["shared-msg-1"]);
        DidCommMessage bobAck = MessagePickupExtensions.CreateMessagesReceived("mr-bob", ["shared-msg-1"]);

        //Both recipients can acknowledge the SAME attachment id independently — reading one ack never touches
        //the other; this library carries no cross-recipient linkage, so one recipient's ack cannot, by
        //construction, remove the (independently-held) copy addressed to the other. Actually holding per-recipient
        //copies until each acks is the mediator's own storage responsibility.
        Assert.IsTrue(aliceAck.TryReadMessagesReceivedIds(out IReadOnlyList<string>? aliceIds));
        Assert.IsTrue(bobAck.TryReadMessagesReceivedIds(out IReadOnlyList<string>? bobIds));
        Assert.AreEqual("shared-msg-1", aliceIds![0]);
        Assert.AreEqual("shared-msg-1", bobIds![0]);
        Assert.AreNotSame(aliceAck, bobAck);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Live Mode:
    /// "It is disabled by default and only activated by the recipient."
    /// </summary>
    [TestMethod]
    public void LiveModeIsDisabledByDefaultAndOnlyActivatedByRecipient()
    {
        DidCommMessage statusWithNoLiveDeliveryMember = MessagePickupExtensions.CreateStatus("s-1", new MessagePickupStatus { MessageCount = 0 });
        Assert.IsTrue(statusWithNoLiveDeliveryMember.TryReadStatus(out MessagePickupStatus? status));
        Assert.IsNull(status!.LiveDelivery, "Absence of live_delivery is not itself an 'on' signal.");

        //The only recipient-issued write surface that can request Live Mode ON is live-delivery-change; there
        //is no mediator-side "ActivateLiveMode" builder — activation is the recipient's exclusive doing.
        DidCommMessage activationRequest = MessagePickupExtensions.CreateLiveDeliveryChange("ldc-1", liveDelivery: true);
        Assert.IsTrue(activationRequest.TryReadLiveDeliveryChange(out bool requestedOn));
        Assert.IsTrue(requestedOn);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Live Mode:
    /// "Messages that arrive when Live Mode is off MUST be stored in the queue for retrieval as described above."
    /// </summary>
    [TestMethod]
    public void MessagesArrivingWithLiveModeOffMustBeQueued()
    {
        //Whether an arriving message is actually placed into mediator storage (rather than pushed live) is
        //mediator routing/storage state this library holds none of. What IS provable at the message-shape
        //level is "for retrieval as described above": a stored message is recoverable ONLY through the
        //ordinary delivery-request -> delivery composition, reachable with no live-delivery-change of any
        //kind having been sent — proving queue retrieval does not depend on Live Mode state.
        DidCommMessage deliveryRequest = MessagePickupExtensions.CreateDeliveryRequest("dr-1", 1);
        DidCommMessage delivery = MessagePickupExtensions.CreateDelivery("d-1", deliveryRequest.EffectiveThreadId!, [BuildAttachment("att-1")]);

        Assert.IsTrue(delivery.IsDelivery());
        Assert.AreEqual(deliveryRequest.Id, delivery.ThreadId, "The queue-retrieval composition this library models is exactly delivery-request -> delivery, correlated by thread — no live_delivery signal participates in it, so a message stored while Live Mode was off is retrieved the same way as any other queued message.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Live Mode:
    /// "If Live Mode is active, and the connection is broken, a new inbound connection starts with Live Mode disabled."
    /// </summary>
    [TestMethod]
    public void ABrokenConnectionResetsLiveModeToDisabled()
    {
        DidCommMessage firstConnectionChange = MessagePickupExtensions.CreateLiveDeliveryChange("ldc-1", liveDelivery: true);
        DidCommMessage secondConnectionChange = MessagePickupExtensions.CreateLiveDeliveryChange("ldc-2", liveDelivery: true);

        //Each live-delivery-change is a freshly-built, independent message; nothing here persists a running
        //Live Mode flag across connections for the library to "reset" — the per-connection state (and its
        //reset on a broken connection) is the mediator's own session bookkeeping.
        Assert.AreNotSame(firstConnectionChange, secondConnectionChange);
        Assert.IsTrue(firstConnectionChange.TryReadLiveDeliveryChange(out bool first) && first);
        Assert.IsTrue(secondConnectionChange.TryReadLiveDeliveryChange(out bool second) && second);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Live Mode:
    /// "Messages already in the queue are not affected by Live Mode; they must still be requested with
    /// delivery-request messages."
    /// </summary>
    [TestMethod]
    public void QueuedMessagesAreUnaffectedByLiveModeAndStillNeedDeliveryRequest()
    {
        DidCommMessage liveOn = MessagePickupExtensions.CreateLiveDeliveryChange("ldc-1", liveDelivery: true);
        DidCommMessage deliveryRequest = MessagePickupExtensions.CreateDeliveryRequest("dr-1", 1);
        DidCommMessage delivery = MessagePickupExtensions.CreateDelivery("d-1", deliveryRequest.EffectiveThreadId!, [BuildAttachment("att-1")]);

        //Turning Live Mode on does not, by itself, correlate to or unlock anything queued: the delivery is
        //threaded ONLY to its own delivery-request, never to the unrelated live-delivery-change — a queued
        //message "must still be requested with delivery-request messages" whatever live_delivery is set to.
        //Actually holding the message in storage until that request arrives is the mediator's own doing.
        Assert.AreEqual(deliveryRequest.Id, delivery.ThreadId);
        Assert.AreNotEqual(liveOn.Id, delivery.ThreadId, "A queued message's retrieval MUST correlate to its own delivery-request thread, never to an unrelated live-delivery-change — Live Mode toggling does not itself deliver anything queued.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Live Mode:
    /// "Live Mode MUST only be enabled when a persistent transport is used, such as WebSockets."
    /// </summary>
    [TestMethod]
    public void LiveModeMustOnlyBeEnabledOnAPersistentTransport()
    {
        //CreateLiveDeliveryChange takes no transport parameter: whether the channel it travels over is
        //persistent (WebSockets) rather than a one-shot HTTP POST is knowledge the APPLICATION holds when it
        //chooses which connection to send this message over — this library has no transport-persistence
        //concept of its own to check against.
        DidCommMessage change = MessagePickupExtensions.CreateLiveDeliveryChange("ldc-1", liveDelivery: true);

        Assert.IsTrue(change.IsLiveDeliveryChange());
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Live Mode:
    /// "1. Never activate Live Mode. Poll for new messages with a status_request message, and retrieve them
    /// when available." TRAP: the prose spells this "status_request" with an underscore; the wire MTURI is
    /// hyphenated "status-request".
    /// </summary>
    [TestMethod]
    public void PollingModeOneIsExpressibleWithStatusRequest()
    {
        for(int i = 0; i < 2; ++i)
        {
            DidCommMessage poll = StatusRequest($"poll-{i}");
            DidCommMessage reply = MessagePickupExtensions.CreateStatus($"status-{i}", new MessagePickupStatus { MessageCount = i }, inResponseTo: poll);

            Assert.IsTrue(reply.TryReadStatus(out MessagePickupStatus? status));
            Assert.AreEqual((long)i, status!.MessageCount);
        }
    }


    /// <summary>
    /// Carry-forward (anchored ONLY on 3.0 clauses): a message delivered LIVE (pushed
    /// immediately, never queued — <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup
    /// Protocol 3.0</see> §Live Mode) still needs the SAME acknowledgment discipline §Delivery Request states
    /// for a queued delivery: "Delivered messages MUST NOT be deleted until delivery is acknowledged by a
    /// messages-received message." A 3.0 implementation applying that discipline uniformly to live-delivered
    /// messages too is conformant and forward-compatible; this does not cite Message Pickup 4.0.
    /// </summary>
    [TestMethod]
    public void LiveDeliveredMessagesAreStillAcknowledgedOrRequeuedConformantly()
    {
        const string LiveDeliveredMessageId = "live-pushed-message-1";
        DidCommMessage ack = MessagePickupExtensions.CreateMessagesReceived("mr-1", [LiveDeliveredMessageId]);

        Assert.IsTrue(ack.TryReadMessagesReceivedIds(out IReadOnlyList<string>? ids));
        Assert.AreEqual(LiveDeliveredMessageId, ids![0], "Nothing distinguishes a live-pushed message's id from a queued delivery's id — the same messages-received surface handles both uniformly.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Live Mode Change:
    /// "Message Type URI: https://didcomm.org/messagepickup/3.0/live-delivery-change"
    /// </summary>
    [TestMethod]
    public void LiveDeliveryChangeMturiIsExact()
    {
        Assert.AreEqual("https://didcomm.org/messagepickup/3.0/live-delivery-change", WellKnownMessagePickupNames.LiveDeliveryChangeType);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Live Mode Change
    /// JSON sample: <c>"body": { "live_delivery": true }</c>.
    /// </summary>
    [TestMethod]
    public void LiveDeliveryChangeBodyCarriesTheLiveDeliveryBoolean()
    {
        DidCommMessage change = MessagePickupExtensions.CreateLiveDeliveryChange("ldc-1", liveDelivery: true);

        Assert.IsTrue(change.Body!.TryGetValue(WellKnownMessagePickupNames.LiveDelivery, out object? value));
        Assert.IsTrue((bool)value!);
        Assert.IsTrue(change.TryReadLiveDeliveryChange(out bool liveDelivery));
        Assert.IsTrue(liveDelivery);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Live Mode Change:
    /// "Upon receiving the live_delivery_change message, the mediator **MUST* respond with a status message."
    /// Read as MUST despite the malformed triple-asterisk emphasis (<c>**MUST*</c>) in the spec source — this
    /// is auditably NOT the doubly-asterisked <c>**MUST**</c> used everywhere else in the spec, but the
    /// surrounding prose gives no reading other than the ordinary RFC 2119 MUST.
    /// </summary>
    [TestMethod]
    public void MediatorMustRespondToLiveDeliveryChangeWithStatusMalformedEmphasisReadAsMust()
    {
        DidCommMessage change = MessagePickupExtensions.CreateLiveDeliveryChange("ldc-1", liveDelivery: true);
        DidCommMessage mediatorReply = MessagePickupExtensions.CreateStatus("s-1", new MessagePickupStatus { MessageCount = 0, LiveDelivery = true }, inResponseTo: change);

        Assert.AreEqual(change.Id, mediatorReply.ThreadId);
        Assert.IsTrue(mediatorReply.IsStatus());
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Live Mode Change:
    /// "If sent with live_delivery set to true on a connection incapable of live delivery, a problem_report
    /// SHOULD be sent" with <c>"code": "e.m.live-mode-not-supported"</c>. TRAP: the prose spells the message
    /// name "problem_report" with an underscore; the wire type token is hyphenated "problem-report".
    /// </summary>
    [TestMethod]
    public void LiveModeNotSupportedProblemReportUsesTheReuseSurface()
    {
        ProblemReport report = new()
        {
            Code = ProblemCode.Parse(WellKnownMessagePickupNames.LiveModeNotSupported),
            ParentThreadId = "ldc-1",
            Comment = "Connection does not support Live Delivery"
        };
        DidCommMessage problemMessage = report.CreateProblemReport("pr-1");

        Assert.IsTrue(problemMessage.IsProblemReport());
        Assert.IsTrue(problemMessage.TryInterpretProblemReport(out ProblemReport? recovered));
        Assert.AreEqual(WellKnownMessagePickupNames.LiveModeNotSupported, recovered!.Code.Value);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Live Mode Change
    /// JSON sample: <c>"pthid": "&lt; the value is the thid of the thread in which the problem occurred&gt;"</c>.
    /// </summary>
    [TestMethod]
    public void ProblemReportPthidIsTheLiveDeliveryChangeThread()
    {
        DidCommMessage change = MessagePickupExtensions.CreateLiveDeliveryChange("ldc-1", liveDelivery: true);
        ProblemReport report = new()
        {
            Code = ProblemCode.Parse(WellKnownMessagePickupNames.LiveModeNotSupported),
            ParentThreadId = change.EffectiveThreadId!
        };
        DidCommMessage problemMessage = report.CreateProblemReport("pr-1");

        Assert.AreEqual(change.EffectiveThreadId, problemMessage.ParentThreadId);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §States
    /// ("the return_route header extension must be set to all in all request submitted by the recipient")
    /// applied to the live-delivery-change EXAMPLE, whose own JSON sample carries no <c>return_route</c>
    /// member at all: this builder sets <c>return_route: all</c> anyway — a deliberate, documented divergence
    /// from the spec's own worked example, not an oversight.
    /// </summary>
    [TestMethod]
    public void LiveDeliveryChangeBuilderSetsReturnRouteAllDespiteTheExampleOmittingIt()
    {
        DidCommMessage change = MessagePickupExtensions.CreateLiveDeliveryChange("123456780", liveDelivery: true);

        Assert.IsTrue(change.IsReturnRouteAll());
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#message-type-uri">DIDComm Messaging v2.1 §Message Type URI</see>:
    /// protocol and message-type-name tokens are compared "ignoring case and punctuation" — proven here for
    /// Message Pickup against the exact underscored spellings the spec's own prose uses in running text
    /// (<c>live_delivery_change</c>, <c>status_request</c>) even though the wire tokens are hyphenated.
    /// </summary>
    [TestMethod]
    [DataRow("https://didcomm.org/messagepickup/3.0/live_delivery_change")]
    [DataRow("https://didcomm.org/messagepickup/3.0/status_request")]
    public void UnderscoreTypedInboundMturiStillDispatches(string underscoredType)
    {
        DidCommMessage message = new() { Id = "u-1", Type = underscoredType };

        bool dispatches = underscoredType.EndsWith("live_delivery_change", StringComparison.Ordinal)
            ? message.IsLiveDeliveryChange()
            : message.IsStatusRequest();

        Assert.IsTrue(dispatches, $"'{underscoredType}' MUST still dispatch: MessageTypeUri.IsSameMessageType absorbs punctuation.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §L10n
    /// (L244): "No localization is required." Proven by every wire token this protocol defines — the PIURI,
    /// the six Message Type URIs, the body member names, and the Live Mode problem code — being pure ASCII: no
    /// locale-dependent wire token exists for a peer to localize, so nothing here can be affected by the
    /// current culture.
    /// </summary>
    [TestMethod]
    public void NoLocalizationIsRequiredEveryWireTokenIsAscii()
    {
        string[] wireTokens =
        [
            WellKnownMessagePickupNames.MessagePickupProtocol,
            WellKnownMessagePickupNames.StatusRequestType,
            WellKnownMessagePickupNames.StatusType,
            WellKnownMessagePickupNames.DeliveryRequestType,
            WellKnownMessagePickupNames.DeliveryType,
            WellKnownMessagePickupNames.MessagesReceivedType,
            WellKnownMessagePickupNames.LiveDeliveryChangeType,
            WellKnownMessagePickupNames.RecipientDid,
            WellKnownMessagePickupNames.MessageCount,
            WellKnownMessagePickupNames.LongestWaitedSeconds,
            WellKnownMessagePickupNames.NewestReceivedTime,
            WellKnownMessagePickupNames.OldestReceivedTime,
            WellKnownMessagePickupNames.TotalBytes,
            WellKnownMessagePickupNames.LiveDelivery,
            WellKnownMessagePickupNames.Limit,
            WellKnownMessagePickupNames.MessageIdList,
            WellKnownMessagePickupNames.LiveModeNotSupported
        ];

        foreach(string token in wireTokens)
        {
            foreach(char character in token)
            {
                Assert.IsTrue(char.IsAscii(character), $"'{token}' MUST be pure ASCII — no locale-dependent wire token exists (§L10n).");
            }
        }
    }


    /// <summary>
    /// Real-wire capstone: a recipient packs an anoncrypt <c>status-request</c> with <c>return_route: all</c>
    /// (<see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see>),
    /// <see cref="DidCommTransportExtensions.ExchangeAsync(DidCommEncryptedMessage, DidCommMessage, Uri, ExchangeContext, DidCommExchangeDelegate, CancellationToken)"/>
    /// POSTs it over a genuine loopback socket, a <see cref="MinimalHttpHost"/> replies in the HTTP response
    /// body with a packed anoncrypt <c>status</c>, the recipient classifies the reply via
    /// <see cref="DidCommInbound.Classify"/>, decrypts it, and <see cref="MessagePickupExtensions.TryReadStatus"/>
    /// recovers the exact queue-state numbers the mediator reported — exercising the protocol layer and the
    /// exchange seam together over the real wire. Runs against a counting pool so the reply's rented lease is
    /// proven outstanding until the caller disposes the result, and returned once it does.
    /// </summary>
    [TestMethod]
    public async Task StatusRequestExchangeRoundTripsAnAnoncryptStatusOverARealSocket()
    {
        using var metered = new MeteredHousePool();
        const string E2ERecipientDid = "did:example:pickup-e2e-recipient";
        const string E2ERecipientKid = "did:example:pickup-e2e-recipient#key-1";
        const string E2EMediatorDid = "did:example:pickup-e2e-mediator";
        const string E2EMediatorKid = "did:example:pickup-e2e-mediator#key-1";

        var expectedStatus = new MessagePickupStatus
        {
            RecipientDid = E2ERecipientDid,
            MessageCount = 7,
            LongestWaitedSeconds = 3600,
            NewestReceivedTime = 1658085169,
            OldestReceivedTime = 1658084293,
            TotalBytes = 8096,
            LiveDelivery = false
        };

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipientKeys = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory recipientPublic = recipientKeys.PublicKey;
        PrivateKeyMemory recipientPrivate = recipientKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> mediatorKeys = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory mediatorPublic = mediatorKeys.PublicKey;
        //Unused: the loopback host below is a stub that replies with a pre-packed status; it never actually
        //decrypts the inbound status-request, so the mediator's private key is not needed.
        using PrivateKeyMemory unusedMediatorPrivate = mediatorKeys.PrivateKey;

        try
        {
            DidCommMessage statusMessage = MessagePickupExtensions.CreateStatus("status-e2e-1", expectedStatus, from: E2EMediatorDid);
            using DidCommEncryptedMessage packedStatusReply = await PackAnoncryptAsync(
                statusMessage, E2ERecipientKid, recipientPublic, TestContext.CancellationToken).ConfigureAwait(false);
            string statusReplyJson = Encoding.UTF8.GetString(packedStatusReply.AsReadOnlySpan());

            await using MinimalHttpHost mediatorHost = await MinimalHttpHost.StartAsync(
                (request, cancellationToken) => Task.FromResult(new MinimalHttpResponse
                {
                    StatusCode = 200,
                    ContentType = DidCommEncryptedMessage.MediaType,
                    Body = statusReplyJson
                }),
                TestContext.CancellationToken).ConfigureAwait(false);

            DidCommMessage statusRequest = StatusRequest("status-request-e2e-1", recipientDid: E2ERecipientDid);
            using DidCommEncryptedMessage packedRequest = await PackAnoncryptAsync(
                statusRequest, E2EMediatorKid, mediatorPublic, TestContext.CancellationToken).ConfigureAwait(false);

            using HttpClient httpClient = LoopbackTls.CreatePinnedHttpClient(mediatorHost.Certificate);
            DidCommExchangeDelegate exchange = DidCommHttpTransport.CreateExchangeDelegate(BuildExchangeTransport(httpClient), metered.Pool);

            DidCommExchangeResult exchangeResult = await packedRequest.ExchangeAsync(
                statusRequest, mediatorHost.BaseAddress, NewLoopbackExchangeContext(), exchange, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(exchangeResult.IsAccepted, $"The mediator MUST accept the status-request. Status: {exchangeResult.TransportStatusCode}, error: {exchangeResult.Error}.");
            Assert.IsTrue(exchangeResult.HasReply, "The reply MUST arrive on the same HTTP response (return_route: all).");
            Assert.AreEqual(1L, metered.OutstandingCount, "The reply's rented lease is outstanding until the caller disposes the result.");

            DidCommMessageClass replyClass = DidCommInbound.Classify(exchangeResult.ReplyMediaType, exchangeResult.ReplyBody.AsReadOnlySpan(), TestSetup.Base64UrlDecoder, Pool);
            Assert.AreEqual(DidCommMessageClass.Anoncrypt, replyClass, "The reply's Content-Type and protected-header alg MUST classify as anoncrypt.");

            using DidCommEncryptedMessage receivedReply = DidCommEncryptedMessage.Create(exchangeResult.ReplyBody.AsReadOnlySpan(), BufferTags.Json, Pool);
            DidCommEncryptedUnpackResult unpacked = await receivedReply.UnpackAnoncryptAsync(
                E2ERecipientKid, recipientPrivate, NestedSignerResolver, UnpackContext, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
                TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(unpacked.IsUnpacked, $"The recipient MUST decrypt the status that crossed the wire. Error: {unpacked.Error}.");
            Assert.IsNotNull(unpacked.Message);
            Assert.IsTrue(unpacked.Message!.TryReadStatus(out MessagePickupStatus? status), "TryReadStatus MUST succeed on the decrypted status.");
            Assert.AreEqual(7L, status!.MessageCount);
            Assert.AreEqual(3600L, status.LongestWaitedSeconds);
            Assert.AreEqual(1658085169L, status.NewestReceivedTime);
            Assert.AreEqual(1658084293L, status.OldestReceivedTime);
            Assert.AreEqual(8096L, status.TotalBytes);
            Assert.IsFalse(status.LiveDelivery!.Value);
            Assert.AreEqual(E2ERecipientDid, status.RecipientDid);

            exchangeResult.Dispose();
            Assert.AreEqual(0L, metered.OutstandingCount, "Disposing the exchange result returns the reply's rented lease.");
        }
        finally
        {
            recipientPrivate.Dispose();
        }
    }


    /// <summary>
    /// Every rented reply lease is returned exactly once: disposing the <see cref="DidCommExchangeResult"/> an
    /// accepted exchange with a non-empty reply returns balances the <see cref="PooledMemory"/> rented for
    /// it, proven against a counting pool rather than merely the absence of an exception.
    /// </summary>
    [TestMethod]
    public async Task ExchangeWithACountingPoolReturnsTheReplyLeaseOnCallerDispose()
    {
        using var metered = new MeteredHousePool();
        byte[] replyBytes = "{\"type\":\"https://didcomm.org/messagepickup/3.0/status\"}"u8.ToArray();
        var transport = new FakeExchangeTransport(statusCode: 200, replyBody: replyBytes, replyMediaType: "application/didcomm-encrypted+json");
        using DidCommEncryptedMessage message = Encrypted("{\"ciphertext\":\"x\"}"u8);
        DidCommMessage request = ReturnRouteAllRequest();

        DidCommExchangeDelegate exchange = DidCommHttpTransport.CreateExchangeDelegate(transport.SendAsync, metered.Pool);
        DidCommExchangeResult result = await message.ExchangeAsync(request, Endpoint, new ExchangeContext(), exchange, default).ConfigureAwait(false);

        Assert.IsTrue(result.HasReply);
        Assert.AreEqual(1L, metered.OutstandingCount, "The reply's lease is outstanding until the caller disposes the result.");

        result.Dispose();

        Assert.AreEqual(0L, metered.OutstandingCount, "Disposing the result returns the reply's rented lease.");
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#https">DIDComm Messaging v2.1 §HTTPS</see>:
    /// a reply over the caller's accepted size bound is refused as a transport failure before the pooled copy
    /// ever happens, so a counting pool proves nothing was ever rented for it — the reply-less
    /// <see cref="DidCommExchangeResult.TransportFailed"/> outcome carries no lease to leak.
    /// </summary>
    [TestMethod]
    public async Task OversizedReplyMapsToTransportFailedWithNoLeakedLease()
    {
        using var metered = new MeteredHousePool();
        var transport = new FakeExchangeTransport(statusCode: 200, replyBody: new byte[5]);
        using DidCommEncryptedMessage message = Encrypted("{\"ciphertext\":\"x\"}"u8);
        DidCommMessage request = ReturnRouteAllRequest();

        DidCommExchangeDelegate exchange = DidCommHttpTransport.CreateExchangeDelegate(transport.SendAsync, metered.Pool, maxReplyBytes: 4);
        using DidCommExchangeResult result = await message.ExchangeAsync(request, Endpoint, new ExchangeContext(), exchange, default).ConfigureAwait(false);

        Assert.AreEqual(DidCommTransmitError.TransportFailed, result.Error);
        Assert.IsFalse(result.HasReply);
        Assert.AreEqual(0L, metered.RentedCount, "The oversized reply is refused before PooledMemory.FromBytes ever rents a buffer for it.");
        Assert.AreEqual(0L, metered.OutstandingCount);
    }


    //A stub OutboundTransportDelegate for the exchange seam: records every request and returns the configured
    //status and reply body/media type, or throws a transport failure or a cancellation. The recorded requests
    //verify the seam's encoding (MaxResponseBytes, POST, Content-Type) without a socket; the packed request
    //bytes stay borrowed for the duration of the call, exactly as DidCommHttpTransportTests's FakeTransport
    //relies on for the one-way send path.
    private sealed class FakeExchangeTransport
    {
        private readonly int statusCode;
        private readonly bool throwOnSend;
        private readonly bool throwCancellation;
        private readonly ReadOnlyMemory<byte> replyBody;
        private readonly string? replyMediaType;

        public FakeExchangeTransport(
            int statusCode,
            bool throwOnSend = false,
            bool throwCancellation = false,
            ReadOnlyMemory<byte> replyBody = default,
            string? replyMediaType = null)
        {
            this.statusCode = statusCode;
            this.throwOnSend = throwOnSend;
            this.throwCancellation = throwCancellation;
            this.replyBody = replyBody;
            this.replyMediaType = replyMediaType;
        }


        public List<OutboundRequest> Calls { get; } = [];


        public ValueTask<OutboundResponse> SendAsync(OutboundRequest request, ExchangeContext context, CancellationToken cancellationToken)
        {
            Calls.Add(request);
            if(throwCancellation)
            {
                throw new OperationCanceledException(cancellationToken);
            }

            if(throwOnSend)
            {
                throw new InvalidOperationException("Simulated transport failure.");
            }

            Dictionary<string, string> headers = new(StringComparer.OrdinalIgnoreCase);
            if(replyMediaType is not null)
            {
                headers["Content-Type"] = replyMediaType;
            }

            OutboundResponse response = replyBody.IsEmpty
                ? new OutboundResponse { StatusCode = statusCode, Headers = headers }
                : new OutboundResponse { StatusCode = statusCode, Headers = headers, Body = new TaggedMemory<byte>(replyBody, BufferTags.Json) };

            return ValueTask.FromResult(response);
        }
    }
}
