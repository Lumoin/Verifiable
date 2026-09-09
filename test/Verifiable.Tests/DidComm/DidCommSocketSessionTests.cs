using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.WebSockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.DidComm;
using Verifiable.DidComm.DiscoverFeatures;
using Verifiable.DidComm.MessagePickup;
using Verifiable.DidComm.ProblemReports;
using Verifiable.DidComm.ReturnRoute;
using Verifiable.DidComm.Transport;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.Foundation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Tests for the DIDComm WebSocket session seam (<see cref="DidCommSocketSession"/>,
/// <see cref="DidCommSocketSessionOptions"/>, <see cref="DidCommSessionSendDelegate"/>,
/// <see cref="DidCommSessionInboundDelegate"/>, <see cref="DidCommInboundFrameResult"/>): the per-connection
/// conventions and state a persistent, role-symmetric duplex channel needs on top of the one-shot
/// <see cref="DidCommSendDelegate"/>/<see cref="DidCommExchangeDelegate"/> pair, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>,
/// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see>,
/// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>, and the
/// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">DIDComm Messaging Return-Route and Queue Transport Extension</see>.
/// </summary>
/// <remarks>
/// <para>
/// Most tests here are fake-delegate (no socket): <see cref="FakeSessionTransport"/> and
/// <see cref="RecordingUnsolicited"/> stand in for the application-owned socket and its pump, letting a test
/// simulate a reply "arriving" by calling <see cref="DidCommSocketSession.AcceptInboundFrameAsync"/> directly.
/// One capstone test (<see cref="LiveModeRoundTripsOverARealLoopbackWebSocketSession"/>) drives a genuine
/// loopback <c>wss://</c> connection end to end via <see cref="DidCommDuplexMediatorHost"/>/
/// <see cref="DidCommDuplexWalletConnection"/>.
/// </para>
/// <para>
/// <strong>A gate test may USE racing, but may only FAIL when the code is wrong.</strong>
/// <see cref="SettledThenCorrelatedFallThroughReturnsTheOrphansLease"/> and
/// <see cref="CancellationAbandonmentReturnsTheLeaseOfAReplyThatRacedTheCancellation"/> race a narrow internal
/// window on purpose, but assert only the deterministic lease invariant every iteration — whether the raced
/// target path was actually observed within a run is a scheduler property, logged as a diagnostic, never
/// asserted.
/// </para>
/// </remarks>
[TestClass]
internal sealed class DidCommSocketSessionTests
{
    /// <summary>The test framework's per-test context, including the cooperative cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    private static BaseMemoryPool Pool { get; } = BaseMemoryPool.Shared;

    /// <summary>The suite's fixed clock, passed to every <see cref="DidCommSocketSession"/> construction in this class.</summary>
    private static FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static DidResolver NestedSignerResolver { get; } = new(DidMethodSelectors.FromResolvers(
        ("did:example", (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Failure(DidResolutionErrors.NotFound)))));

    private static ExchangeContext UnpackContext { get; } = new();


    //Anoncrypts message for recipientKid/recipientPublic through the SAME registry-resolving pack surface
    //every other DIDComm protocol uses — this seam introduces no separate crypto path of its own.
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
            MicrosoftEntropyFunctionsAdapter.GenerateNonce,
            Pool,
            cancellationToken).ConfigureAwait(false);
    }


    //An encrypted envelope shaped like an anoncrypt frame (top-level `ciphertext` + a decodable `protected`
    //header with an ECDH-ES alg) — enough for DidCommInbound.Classify's envelope-shape path, with no crypto
    //machinery needed (Classify never decrypts, only reads the protected header).
    private static byte[] AnoncryptEnvelopeShapeBytes()
    {
        string header = "{\"alg\":\"ECDH-ES+A256KW\",\"enc\":\"A256GCM\"}";
        string protectedEncoded = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header));

        return Encoding.UTF8.GetBytes($"{{\"protected\":\"{protectedEncoded}\",\"ciphertext\":\"x\"}}");
    }


    //A DidCommSessionSendDelegate stand-in: records every call (bytes copied out, since the buffer is only
    //borrowed for the call's duration) and returns a configurable outcome, or throws to simulate a transport
    //failure/cancellation AFTER Respond ran — mirrors DidCommMessagePickupTests.FakeExchangeTransport for the
    //session seam. Respond runs first so a test can correlate a reply from inside the send before the throw
    //flags fire, forcing the exact interleaving ExchangeAsync's exceptional-exit custody path needs to prove.
    private sealed class FakeSessionTransport
    {
        public List<(byte[] Message, string? MediaType)> Sent { get; } = [];

        public bool ThrowOnSend { get; set; }

        public bool ThrowCancellation { get; set; }

        public Func<byte[], string?, DidCommTransmitResult>? Respond { get; set; }


        public ValueTask<DidCommTransmitResult> SendAsync(ReadOnlyMemory<byte> message, string? mediaType, CancellationToken cancellationToken)
        {
            byte[] copy = message.ToArray();
            Sent.Add((copy, mediaType));

            DidCommTransmitResult result = Respond?.Invoke(copy, mediaType) ?? DidCommTransmitResult.Accepted();

            if(ThrowCancellation)
            {
                throw new OperationCanceledException(cancellationToken);
            }

            if(ThrowOnSend)
            {
                throw new WebSocketException("Simulated mid-send transport failure.");
            }

            return ValueTask.FromResult(result);
        }
    }


    //A DidCommSessionInboundDelegate stand-in: records every uncorrelated frame handed to it, copied out
    //since the buffer is only borrowed for the call's duration.
    private sealed class RecordingUnsolicited
    {
        public List<byte[]> Frames { get; } = [];


        public ValueTask HandleAsync(ReadOnlyMemory<byte> frame, CancellationToken cancellationToken)
        {
            Frames.Add(frame.ToArray());

            return ValueTask.CompletedTask;
        }
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>
    /// §Delivery: "DIDComm Transports serve only as message delivery. No information about the effects or
    /// results from a message is transmitted over the same connection." The session performs NO
    /// interpretation of frame content at all — arbitrary non-JSON, non-DIDComm bytes still deliver cleanly;
    /// only the caller-supplied, out-of-band correlation id governs routing, never anything read out of the
    /// bytes themselves.
    /// </summary>
    [TestMethod]
    public async Task SessionServesOnlyDeliveryNeverInterpretsFrameContentAsEffectsOrResults()
    {
        var fake = new FakeSessionTransport();
        var unsolicited = new RecordingUnsolicited();
        await using var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, Pool, TimeProvider);

        byte[] garbage = [0x00, 0x01, 0x02, 0xFF, 0xFE];
        DidCommInboundFrameResult result = await session.AcceptInboundFrameAsync(garbage, null, default).ConfigureAwait(false);

        Assert.AreEqual(DidCommInboundFrameDisposition.DispatchedUnsolicited, result.Disposition, "Non-DIDComm, non-JSON bytes still deliver cleanly — the session decodes nothing; routing is purely the caller-supplied correlation id.");
        Assert.HasCount(1, unsolicited.Frames);
        Assert.IsTrue(unsolicited.Frames[0].AsSpan().SequenceEqual(garbage));
        Assert.IsEmpty(fake.Sent, "Dispatching an inbound frame MUST NOT itself cause anything to be sent back over the connection — no information about effects or results rides the connection from the session's own accept path; only an explicit, separate SendAsync/ExchangeAsync call transmits anything.");

        DidCommMessage plaintext = new() { Id = "garbage-send-1", Type = "https://example.com/protocols/lets_do_lunch/1.0/proposal" };
        DidCommTransmitResult sendResult = await session.SendAsync(garbage, DidCommEncryptedMessage.MediaType, plaintext, default).ConfigureAwait(false);
        Assert.IsTrue(sendResult.IsAccepted, "SendAsync also carries arbitrary bytes without interpreting them — pure delivery, no effect/result semantics.");
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>
    /// §Transport Requirements: "Each transport MUST define: ... how IANA media types of the content are
    /// provided, e.g., through Content-Type header, etc." The seam's own answer — grounded in measured wire
    /// evidence — is that a raw WebSocket provides NONE: <see cref="DidCommInbound.Classify"/>
    /// falls back to envelope-shape classification, exactly the mechanism this seam's unsolicited dispatch
    /// relies on. The "one complete message per frame, text send" half of the same requirement is exercised
    /// live over a real socket by <see cref="LiveModeRoundTripsOverARealLoopbackWebSocketSession"/> below.
    /// </summary>
    [TestMethod]
    public void TransportRequirementMediaTypeConveyanceIsEnvelopeClassificationWithNoContentType()
    {
        byte[] envelope = AnoncryptEnvelopeShapeBytes();

        DidCommMessageClass classification = DidCommInbound.Classify(null, envelope, TestSetup.Base64UrlDecoder, Pool);

        Assert.AreEqual(DidCommMessageClass.Anoncrypt, classification, "With no content type at all, the seam's dispatch mechanism classifies purely by envelope shape.");
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>
    /// §WebSockets: "Each message MUST be transmitted individually; if encryption or signing are used, the
    /// unit of encryption or signing is one message only."
    /// </summary>
    [TestMethod]
    public async Task SendAsyncTransmitsEachMessageIndividuallyNeverBatched()
    {
        var fake = new FakeSessionTransport();
        var unsolicited = new RecordingUnsolicited();
        await using var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, Pool, TimeProvider);

        byte[] first = "{\"ciphertext\":\"first\"}"u8.ToArray();
        byte[] second = "{\"ciphertext\":\"second\"}"u8.ToArray();
        DidCommMessage plaintext = new() { Id = "one-1", Type = "https://example.com/protocols/lets_do_lunch/1.0/proposal" };

        await session.SendAsync(first, DidCommEncryptedMessage.MediaType, plaintext, default).ConfigureAwait(false);
        await session.SendAsync(second, DidCommEncryptedMessage.MediaType, plaintext, default).ConfigureAwait(false);

        Assert.HasCount(2, fake.Sent, "Two SendAsync calls MUST produce two independent transmissions — never coalesced into one frame.");
        Assert.IsTrue(fake.Sent[0].Message.AsSpan().SequenceEqual(first), "Each transmitted frame carries EXACTLY one message's bytes, not a batch.");
        Assert.IsTrue(fake.Sent[1].Message.AsSpan().SequenceEqual(second));
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>
    /// §WebSockets: "The trust of each message MUST be associated with DIDComm encryption or signing, not
    /// from the socket connection itself." Proven at the level the clause actually makes a claim about —
    /// DECRYPTED CONTENT, not merely routing disposition (a dispatch decision alone says nothing about
    /// trust: garbage bytes dispatch unsolicited identically to a genuine envelope): the IDENTICAL anoncrypt
    /// envelope, decrypted once alongside a session carrying a negotiated subprotocol AND Live Mode enabled,
    /// and once alongside a session carrying neither, yields byte-identical plaintext either way — the
    /// decrypt path never takes the session as an input at all, so this connection-level state is provably
    /// irrelevant to envelope trust.
    /// </summary>
    [TestMethod]
    public async Task SessionRoutingIsIndependentOfNegotiatedSubprotocolTrustComesFromTheEnvelopeNotTheSocket()
    {
        const string RecipientKid = "did:example:subprotocol-irrelevant#key-1";
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        DidCommMessage plaintext = new()
        {
            Id = "subprotocol-irrelevant-1",
            Type = "https://example.com/protocols/lets_do_lunch/1.0/proposal",
            Body = new Dictionary<string, object> { ["messagespecificattribute"] = "unaffected by session state" }
        };
        using DidCommEncryptedMessage packed = await PackAnoncryptAsync(plaintext, RecipientKid, recipientPublic, default).ConfigureAwait(false);
        byte[] envelope = packed.AsReadOnlySpan().ToArray();

        var fakeWith = new FakeSessionTransport();
        var unsolicitedWith = new RecordingUnsolicited();
        await using var sessionWith = new DidCommSocketSession(
            fakeWith.SendAsync, new DidCommSocketSessionOptions { NegotiatedSubprotocol = "didcomm/v2" }, unsolicitedWith.HandleAsync, Pool, TimeProvider);
        sessionWith.SetLiveDelivery(true);

        var fakeWithout = new FakeSessionTransport();
        var unsolicitedWithout = new RecordingUnsolicited();
        await using var sessionWithout = new DidCommSocketSession(
            fakeWithout.SendAsync, new DidCommSocketSessionOptions(), unsolicitedWithout.HandleAsync, Pool, TimeProvider);

        DidCommInboundFrameResult resultWith = await sessionWith.AcceptInboundFrameAsync(envelope, null, default).ConfigureAwait(false);
        DidCommInboundFrameResult resultWithout = await sessionWithout.AcceptInboundFrameAsync(envelope, null, default).ConfigureAwait(false);
        Assert.AreEqual(resultWithout.Disposition, resultWith.Disposition, "Routing MUST be identical regardless of the negotiated subprotocol/Live Mode session state.");
        Assert.HasCount(1, unsolicitedWith.Frames);
        Assert.HasCount(1, unsolicitedWithout.Frames);

        using DidCommEncryptedMessage receivedWith = DidCommEncryptedMessage.Create(unsolicitedWith.Frames[0], BufferTags.Json, Pool);
        DidCommEncryptedUnpackResult unpackedWith = await receivedWith.UnpackAnoncryptAsync(
            RecipientKid, recipientPrivate, NestedSignerResolver, UnpackContext, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: default).ConfigureAwait(false);

        using DidCommEncryptedMessage receivedWithout = DidCommEncryptedMessage.Create(unsolicitedWithout.Frames[0], BufferTags.Json, Pool);
        DidCommEncryptedUnpackResult unpackedWithout = await receivedWithout.UnpackAnoncryptAsync(
            RecipientKid, recipientPrivate, NestedSignerResolver, UnpackContext, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: default).ConfigureAwait(false);

        Assert.IsTrue(unpackedWith.IsUnpacked, "Decryption is independent of any session state and MUST succeed identically either way.");
        Assert.IsTrue(unpackedWithout.IsUnpacked);
        Assert.AreEqual(unpackedWith.Message!.Id, unpackedWithout.Message!.Id);
        Assert.IsTrue(unpackedWith.Message.Body!.TryGetValue("messagespecificattribute", out object? valueWith));
        Assert.IsTrue(unpackedWithout.Message.Body!.TryGetValue("messagespecificattribute", out object? valueWithout));
        Assert.AreEqual("unaffected by session state", valueWith as string);
        Assert.AreEqual(valueWith, valueWithout, "The SAME envelope decrypts to byte-identical plaintext whether the session alongside it carries a subprotocol + Live Mode on, or neither — session state is provably irrelevant to envelope trust.");
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>
    /// §WebSockets: "Websockets are used only for one-way transmission from sender to receiver; responses
    /// don't flow back the other way on the socket" — the default the return-route extension excepts.
    /// <see cref="DidCommSocketSession.ExchangeAsync"/> exists ONLY under that exception: a request that does
    /// not direct <c>return_route: all</c> is refused before anything is sent.
    /// </summary>
    [TestMethod]
    public async Task ExchangeAsyncGuardRejectsRequestWithoutReturnRouteAll()
    {
        var fake = new FakeSessionTransport();
        var unsolicited = new RecordingUnsolicited();
        await using var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, Pool, TimeProvider);

        DidCommMessage requestWithoutReturnRoute = new() { Id = "no-return-route-1", Type = WellKnownMessagePickupNames.StatusRequestType };

        await Assert.ThrowsExactlyAsync<ArgumentException>(
            async () => await session.ExchangeAsync("{\"ciphertext\":\"x\"}"u8.ToArray(), requestWithoutReturnRoute, default).ConfigureAwait(false)).ConfigureAwait(false);
        Assert.IsEmpty(fake.Sent, "A rejected exchange MUST NOT contact the transport — the one-way default is preserved for anything outside the return-route exception.");
    }


    /// <summary>
    /// The library's own thread-id reads guard <c>is not { Length: &gt; 0 }</c>: an empty (not merely
    /// null) <see cref="DidCommMessage.EffectiveThreadId"/> is refused the same as a missing one — a
    /// whitespace/empty thread id has nothing meaningful to correlate against, per the
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">DIDComm Messaging Return-Route and Queue Transport Extension</see>.
    /// </summary>
    [TestMethod]
    public async Task ExchangeAsyncGuardRejectsRequestWithEmptyEffectiveThreadId()
    {
        var fake = new FakeSessionTransport();
        var unsolicited = new RecordingUnsolicited();
        await using var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, Pool, TimeProvider);

        DidCommMessage emptyThreadRequest = new DidCommMessage { Id = "", Type = WellKnownMessagePickupNames.StatusRequestType }
            .WithReturnRoute(WellKnownReturnRouteNames.All);
        Assert.AreEqual(string.Empty, emptyThreadRequest.EffectiveThreadId, "Sanity: an empty Id with no ThreadId yields an empty (not null) EffectiveThreadId.");

        await Assert.ThrowsExactlyAsync<ArgumentException>(
            async () => await session.ExchangeAsync("{\"ciphertext\":\"x\"}"u8.ToArray(), emptyThreadRequest, default).ConfigureAwait(false)).ConfigureAwait(false);
        Assert.IsEmpty(fake.Sent);
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>
    /// §WebSockets: "Using Secure Websockets (wss://) with TLS 1.2 or greater with a cipher suite providing
    /// Perfect Forward Secrecy (PFS) allows a transmission to benefit from PFS that's already available at
    /// the transport level." The loopback harness the capstone below runs over binds <c>wss://</c>
    /// exclusively, with a single explicit HTTPS <c>Listen</c> call and no plaintext fallback — proven by
    /// something only a REAL TLS handshake produces, not merely a URI scheme string: connecting a genuine
    /// <see cref="System.Net.WebSockets.ClientWebSocket"/> invokes the certificate validation callback at
    /// all, and the certificate it presents matches the harness's own certificate byte-for-byte.
    /// </summary>
    [TestMethod]
    public async Task MediatorHostBindsSecureWebSocketSchemeOnly()
    {
        await using DidCommDuplexMediatorHost mediatorHost = await DidCommDuplexMediatorHost.StartAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual("wss", mediatorHost.Endpoint.Scheme, "The loopback harness binds wss:// exclusively — no plaintext ws:// fallback exists on this host at all.");

        await using DidCommDuplexWalletConnection walletConnection =
            await DidCommDuplexWalletConnection.ConnectAsync(mediatorHost.Endpoint, mediatorHost.Certificate, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(walletConnection.DidInvokeCertificatePinningCallback, "A genuine TLS handshake invokes the certificate validation callback — a stub or a plaintext connection would not.");
        Assert.IsTrue(walletConnection.DidMatchPinnedCertificate, "The certificate the handshake actually presented MUST be the harness's own — proof the connection is genuinely secured to THIS listener, not merely that a URI happens to say wss.");
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>
    /// §WebSockets: "When using STOMP over WebSocket, the content-type header is
    /// application/didcomm-encrypted+json as in the HTTPS message" — the ONE spec-pinned per-frame
    /// conveyance, and this seam does not implement STOMP. Negative: on the raw-WS path this seam DOES
    /// implement, it attaches no content type of its own anywhere — <see cref="DidCommSocketSession.SendAsync"/>
    /// forwards EXACTLY the caller's own value unchanged, and <see cref="DidCommSocketSession.ExchangeAsync"/>
    /// (which has no independent media-type input) passes <see langword="null"/> — a decidable "no media
    /// type" — rather than inventing one.
    /// </summary>
    [TestMethod]
    public async Task SessionAttachesNoContentTypeOfItsOwnAnywhereOnTheWire()
    {
        var fake = new FakeSessionTransport();
        var unsolicited = new RecordingUnsolicited();
        await using var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, Pool, TimeProvider);

        DidCommMessage plaintext = new() { Id = "content-type-1", Type = "https://example.com/protocols/lets_do_lunch/1.0/proposal" };
        await session.SendAsync("{\"ciphertext\":\"x\"}"u8.ToArray(), "application/my-custom-type", plaintext, default).ConfigureAwait(false);
        Assert.AreEqual("application/my-custom-type", fake.Sent[0].MediaType, "SendAsync forwards EXACTLY the caller's own value — never substitutes or normalizes it.");

        DidCommMessage request = MessagePickupExtensions.CreateStatusRequest("content-type-2");
        ValueTask<DidCommExchangeResult> pending = session.ExchangeAsync("{\"ciphertext\":\"y\"}"u8.ToArray(), request, default);
        await session.AcceptInboundFrameAsync("{\"ciphertext\":\"reply\"}"u8.ToArray(), request.EffectiveThreadId, default).ConfigureAwait(false);
        using DidCommExchangeResult result = await pending.ConfigureAwait(false);
        Assert.IsNull(fake.Sent[1].MediaType, "ExchangeAsync has no independent media-type input of its own, so it passes null — a decidable 'no media type' rather than an empty string standing in for one — nothing is attached.");
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>
    /// §Agent Constraint Disclosure: "When a max_receive_bytes constraint is specified, any received message
    /// that exceeds the agent's stated maximum may be discarded. ... The associated Problem Code is
    /// me.res.storage.message_too_big." The session enforces the cap FIRST — even a frame whose correlation
    /// id matches an outstanding exchange is refused before correlation is attempted, so the exchange stays
    /// outstanding rather than being incorrectly completed with an over-cap "reply" — and the refusal
    /// carries the exact wire-literal problem code §Agent Constraint Disclosure names, ready for the EXISTING report-problem
    /// surface (<see cref="DidCommProblemReportExtensions.CreateProblemReport"/>) to compose.
    /// </summary>
    [TestMethod]
    public async Task MaxReceiveBytesCapIsEnforcedBeforeCorrelationAndCarriesTheWireLiteralProblemCode()
    {
        var fake = new FakeSessionTransport();
        var unsolicited = new RecordingUnsolicited();
        var options = new DidCommSocketSessionOptions { MaxReceiveBytes = 8 };
        await using var session = new DidCommSocketSession(fake.SendAsync, options, unsolicited.HandleAsync, Pool, TimeProvider);

        DidCommMessage request = MessagePickupExtensions.CreateStatusRequest("cap-thid-1");
        ValueTask<DidCommExchangeResult> pending = session.ExchangeAsync("{\"ciphertext\":\"x\"}"u8.ToArray(), request, default);

        byte[] overCapReply = new byte[16];
        DidCommInboundFrameResult refusal = await session.AcceptInboundFrameAsync(overCapReply, request.EffectiveThreadId, default).ConfigureAwait(false);

        Assert.IsTrue(refusal.IsRefused, "The cap MUST be enforced FIRST — before any correlation lookup.");
        Assert.AreEqual(WellKnownProblemCodes.MessageTooBig, refusal.ProblemCode);
        Assert.AreEqual("me.res.storage.message_too_big", refusal.ProblemCode, "Pins the exact wire literal §Agent Constraint Disclosure names.");

        //The exchange stayed outstanding — the over-cap frame did NOT complete it — so a subsequent,
        //correctly-sized reply for the SAME thread id still correlates.
        byte[] properReply = new byte[4];
        DidCommInboundFrameResult correlated = await session.AcceptInboundFrameAsync(properReply, request.EffectiveThreadId, default).ConfigureAwait(false);
        Assert.AreEqual(DidCommInboundFrameDisposition.Correlated, correlated.Disposition);

        using DidCommExchangeResult result = await pending.ConfigureAwait(false);
        Assert.IsTrue(result.IsAccepted);
        Assert.AreEqual(4, result.ReplyBody.Length);
    }


    /// <summary>
    /// DISCOVERED DEFECT (reported, not fixed — <see cref="ProblemCode"/> lives outside the files this
    /// session seam is scoped to touch): §Agent Constraint Disclosure names the <c>max_receive_bytes</c> problem code verbatim as
    /// <c>me.res.storage.message_too_big</c> — an underscored token — while
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#problem-codes">DIDComm Messaging v2.1 §Problem Codes</see>
    /// requires every token to be "lower kebab-case", which <see cref="ProblemCode.TryParse"/> enforces
    /// strictly (hyphens only, no underscore). The two clauses of the SAME spec are mutually inconsistent for
    /// this one code, so <see cref="WellKnownProblemCodes.MessageTooBig"/> — which correctly matches that clause's
    /// literal — cannot round-trip through <see cref="ProblemCode.Parse"/>/<see cref="DidCommProblemReportExtensions.CreateProblemReport"/>
    /// today. This pins the fact rather than hiding it.
    /// </summary>
    [TestMethod]
    public void MessageTooBigWireLiteralDoesNotParseAsAProblemCodeSpecInconsistency()
    {
        Assert.IsFalse(
            ProblemCode.TryParse(WellKnownProblemCodes.MessageTooBig, out _),
            "The spec's own §Agent Constraint Disclosure example code uses an underscore, which the general §Problem Codes lower-kebab-case grammar rejects — a genuine spec-internal inconsistency, not a bug in this test's expectation.");
    }


    /// <summary>
    /// The reachable-route composition (the test half of the spec-grammar defect above):
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#agent-constraint-disclosure">DIDComm Messaging v2.1 §Agent Constraint Disclosure</see>
    /// sanctions a transport-level error as the alternative to a wire problem report ("it is also appropriate
    /// to emit an error at the transport level, such as HTTP 413 Request Too Large") when a reply channel
    /// may not be available. For THIS code that alternative is the only one actually reachable: composing a
    /// wire <see cref="ProblemReport"/> from the refusal via <see cref="ProblemCode.Parse"/> throws before
    /// anything could be built, because the literal itself violates §Problem Codes' grammar — but the
    /// transport-level route never needs to parse the string at all, so it composes cleanly. Also asserts, at
    /// the ACTUAL refusal returned by <see cref="DidCommSocketSession.AcceptInboundFrameAsync"/> (not merely
    /// the bare constant), that the refusal carries the verbatim wire literal that route surfaces. §Agent Constraint Disclosure also
    /// notes agents MAY diagnose a suspected cap refusal via Route Tracing — that is a peer-to-peer DIDComm
    /// troubleshooting protocol run over ordinary messages, not a surface this library or this seam
    /// implements or participates in.
    /// </summary>
    [TestMethod]
    public async Task MessageTooBigRefusalComposesOnlyThroughTheTransportLevelErrorRouteNeverTheProblemReportRoute()
    {
        var fake = new FakeSessionTransport();
        var unsolicited = new RecordingUnsolicited();
        var options = new DidCommSocketSessionOptions { MaxReceiveBytes = 8 };
        await using var session = new DidCommSocketSession(fake.SendAsync, options, unsolicited.HandleAsync, Pool, TimeProvider);

        byte[] overCapFrame = new byte[16];
        DidCommInboundFrameResult refusal = await session.AcceptInboundFrameAsync(overCapFrame, null, default).ConfigureAwait(false);
        Assert.IsTrue(refusal.IsRefused);
        Assert.AreEqual("me.res.storage.message_too_big", refusal.ProblemCode, "The refusal carries the exact wire literal §Agent Constraint Disclosure names, for the transport-level route to surface.");

        //The problem-report route: unreachable for this one code — composing throws before a report could
        //ever be built, because the literal cannot parse into a ProblemCode.
        Assert.ThrowsExactly<FormatException>(() => ProblemCode.Parse(refusal.ProblemCode!));

        //The transport-level route: reachable, because it never needs to parse the string at all — the
        //application surfaces it directly, exactly as an HTTP transport would surface a 413.
        string transportLevelDiagnostic = $"transport-level refusal: {refusal.ProblemCode}";
        Assert.Contains(refusal.ProblemCode!, transportLevelDiagnostic, "The verbatim wire literal flows unmodified into the transport-level error surface — the ONE route this defect leaves reachable.");
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>
    /// §Agent Constraint Disclosure JSON samples: the query <c>{ "feature-type": "constraint", "match":
    /// "max_receive_bytes" }</c> and the disclose <c>{ "feature-type": "constraint", "id":
    /// "max_receive_bytes", "max_receive_bytes": "65536" }</c>. A session's configured
    /// <see cref="DidCommSocketSessionOptions.MaxReceiveBytes"/> is discoverable via the EXISTING Discover
    /// Features surface (<see cref="DiscoverFeaturesExtensions"/>) — no new discovery mechanism is added,
    /// only a session that actually carries the number.
    /// </summary>
    [TestMethod]
    public void MaxReceiveBytesConstraintIsDiscoverableViaTheExistingDiscoverFeaturesSurface()
    {
        var options = new DidCommSocketSessionOptions { MaxReceiveBytes = 65536 };

        var query = new DiscoverFeaturesQuery
        {
            Queries = [new FeatureQuery { FeatureType = "constraint", Match = "max_receive_bytes" }]
        };
        DidCommMessage queryMessage = query.CreateDiscoverFeaturesQuery("yWd8wfYzhmuXX3hmLNaV5bVbAjbWaU");
        string queryJson = PackToJson(queryMessage);
        Assert.Contains("\"feature-type\":\"constraint\"", queryJson);
        Assert.Contains("\"match\":\"max_receive_bytes\"", queryJson, "Matches the spec's own worked query sample verbatim.");

        var disclose = new DiscoverFeaturesDisclose
        {
            Disclosures =
            [
                new FeatureDisclosure
                {
                    FeatureType = "constraint",
                    Id = "max_receive_bytes",
                    AdditionalFields = new Dictionary<string, object>
                    {
                        ["max_receive_bytes"] = options.MaxReceiveBytes!.Value.ToString(CultureInfo.InvariantCulture)
                    }
                }
            ]
        };
        DidCommMessage discloseMessage = disclose.CreateDiscoverFeaturesDisclose("disclose-max-receive-bytes", threadId: queryMessage.Id);
        string discloseJson = PackToJson(discloseMessage);
        Assert.Contains("\"id\":\"max_receive_bytes\"", discloseJson);
        Assert.Contains("\"max_receive_bytes\":\"65536\"", discloseJson, "Matches the spec's own worked disclose sample verbatim — the session's configured cap flows directly onto the wire.");
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">DIDComm Messaging Return-Route and Queue Transport Extension</see>
    /// §Return Route Header: "all: Send all messages for this DID over the connection [it arrived on]." The
    /// session's correlated exchange realizes this directly: a <c>return_route: all</c> request's reply,
    /// delivered back over the SAME session via <see cref="DidCommSocketSession.AcceptInboundFrameAsync"/>,
    /// completes the exchange that sent it.
    /// </summary>
    [TestMethod]
    public async Task ExchangeAsyncCorrelatesTheReplyOverTheSameConnectionForAReturnRouteAllRequest()
    {
        var fake = new FakeSessionTransport();
        var unsolicited = new RecordingUnsolicited();
        await using var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, Pool, TimeProvider);

        DidCommMessage request = MessagePickupExtensions.CreateStatusRequest("all-thid-1");
        ValueTask<DidCommExchangeResult> pending = session.ExchangeAsync("{\"ciphertext\":\"req\"}"u8.ToArray(), request, default);

        byte[] reply = "{\"ciphertext\":\"reply\"}"u8.ToArray();
        DidCommInboundFrameResult accepted = await session.AcceptInboundFrameAsync(reply, request.EffectiveThreadId, default).ConfigureAwait(false);

        Assert.AreEqual(DidCommInboundFrameDisposition.Correlated, accepted.Disposition);
        using DidCommExchangeResult result = await pending.ConfigureAwait(false);
        Assert.IsTrue(result.IsAccepted);
        Assert.IsTrue(result.ReplyBody.AsReadOnlySpan().SequenceEqual(reply), "The exact bytes that arrived over the connection become the exchange's reply.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Requirements
    /// and <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Requirements: "This header must be set each time the communication channel is established: once per
    /// established websocket, and every message for an HTTP POST." Over a session, the recipient-side latch
    /// (via <see cref="DidCommSocketSession.SendAsync"/>/<see cref="DidCommSocketSession.ExchangeAsync"/>) is
    /// set ONCE for the socket's whole lifetime — never re-derived per message, unlike HTTP.
    /// </summary>
    [TestMethod]
    public async Task IsReturnRouteEstablishedLatchesOnceForTheWholeSocketLifetime()
    {
        var fake = new FakeSessionTransport();
        var unsolicited = new RecordingUnsolicited();
        await using var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, Pool, TimeProvider);

        Assert.IsFalse(session.IsReturnRouteEstablished, "Not established before anything is sent.");

        DidCommMessage first = MessagePickupExtensions.CreateStatusRequest("latch-1");
        ValueTask<DidCommExchangeResult> pendingFirst = session.ExchangeAsync("{\"ciphertext\":\"1\"}"u8.ToArray(), first, default);
        await session.AcceptInboundFrameAsync("{\"ciphertext\":\"r1\"}"u8.ToArray(), first.EffectiveThreadId, default).ConfigureAwait(false);
        using DidCommExchangeResult resultFirst = await pendingFirst.ConfigureAwait(false);
        Assert.IsTrue(session.IsReturnRouteEstablished, "Latches on the FIRST all-bearing message.");

        //A SECOND all-bearing message over the SAME socket does not need to (and does not) re-set anything —
        //the header is set ONCE per established websocket, not per message as HTTP requires.
        DidCommMessage second = MessagePickupExtensions.CreateStatusRequest("latch-2");
        ValueTask<DidCommExchangeResult> pendingSecond = session.ExchangeAsync("{\"ciphertext\":\"2\"}"u8.ToArray(), second, default);
        await session.AcceptInboundFrameAsync("{\"ciphertext\":\"r2\"}"u8.ToArray(), second.EffectiveThreadId, default).ConfigureAwait(false);
        using DidCommExchangeResult resultSecond = await pendingSecond.ConfigureAwait(false);
        Assert.IsTrue(session.IsReturnRouteEstablished, "Stays true — idempotent, not toggled or re-derived.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Live Mode:
    /// "If Live Mode is active, and the connection is broken, a new inbound connection starts with Live Mode
    /// disabled." A fresh session's flag is false — the per-connection lifetime of THIS object is the reset,
    /// so a brand-new session (standing in for the new connection after a break) starts disabled regardless
    /// of what the prior, now-broken connection's session had settled on.
    /// </summary>
    [TestMethod]
    public async Task NewSessionStartsWithLiveDeliveryDisabled()
    {
        var fakeFirst = new FakeSessionTransport();
        var unsolicitedFirst = new RecordingUnsolicited();
        await using var firstSession = new DidCommSocketSession(fakeFirst.SendAsync, new DidCommSocketSessionOptions(), unsolicitedFirst.HandleAsync, Pool, TimeProvider);
        Assert.IsFalse(firstSession.IsLiveDeliveryEnabled);
        firstSession.SetLiveDelivery(true);
        Assert.IsTrue(firstSession.IsLiveDeliveryEnabled);
        await firstSession.DisposeAsync().ConfigureAwait(false);

        var fakeSecond = new FakeSessionTransport();
        var unsolicitedSecond = new RecordingUnsolicited();
        await using var secondSession = new DidCommSocketSession(fakeSecond.SendAsync, new DidCommSocketSessionOptions(), unsolicitedSecond.HandleAsync, Pool, TimeProvider);
        Assert.IsFalse(secondSession.IsLiveDeliveryEnabled, "A brand-new session after a broken connection starts disabled again, regardless of the prior connection's state.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Basic
    /// Walkthrough / §Live Mode: "When Live Mode is enabled, messages that arrive when an existing connection
    /// exists are delivered over the connection immediately, rather than being pushed to the queue." Proven
    /// as a genuine composition, not an incidental truth: the IDENTICAL dispatch decision runs twice against
    /// the SAME arriving message, once with <see cref="DidCommSocketSession.IsLiveDeliveryEnabled"/> true and
    /// once with it false, and the two outcomes DIFFER (send path vs. queue path) — the flag is the only free
    /// variable, so it alone is what determined the routing. Deciding WHICH path to take is this flag;
    /// actually holding a queue is the application's own storage, out of scope here.
    /// </summary>
    [TestMethod]
    public async Task LiveModeOnRoutesArrivingMessageToTheSessionsSendPathRatherThanAQueue()
    {
        byte[] arriving = "{\"ciphertext\":\"arriving\"}"u8.ToArray();
        DidCommMessage arrivingPlaintext = new() { Id = "arriving-1", Type = "https://example.com/protocols/lets_do_lunch/1.0/proposal" };

        //The mediator's own dispatch DECISION — modeled exactly as the library states the boundary: the flag
        //alone decides push-vs-queue; the queue itself is application storage this library never touches. Run
        //identically with Live Mode off, then on, so the flag is the only variable between the two runs.
        async Task<(bool SentOverSession, int QueueDepth)> RunDispatchDecisionAsync(bool isLiveDeliveryEnabled)
        {
            var fake = new FakeSessionTransport();
            var unsolicited = new RecordingUnsolicited();
            await using var mediatorSession = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, Pool, TimeProvider);
            mediatorSession.SetLiveDelivery(isLiveDeliveryEnabled);

            var queue = new List<byte[]>();
            if(mediatorSession.IsLiveDeliveryEnabled)
            {
                DidCommTransmitResult sent = await mediatorSession.SendAsync(arriving, DidCommEncryptedMessage.MediaType, arrivingPlaintext, default).ConfigureAwait(false);
                Assert.IsTrue(sent.IsAccepted);
            }
            else
            {
                queue.Add(arriving);
            }

            return (fake.Sent.Count == 1, queue.Count);
        }

        (bool sentOverSessionWhenOff, int queueDepthWhenOff) = await RunDispatchDecisionAsync(isLiveDeliveryEnabled: false).ConfigureAwait(false);
        (bool sentOverSessionWhenOn, int queueDepthWhenOn) = await RunDispatchDecisionAsync(isLiveDeliveryEnabled: true).ConfigureAwait(false);

        Assert.IsFalse(sentOverSessionWhenOff, "Live Mode OFF: the message MUST NOT go over the session's send path.");
        Assert.AreEqual(1, queueDepthWhenOff, "Live Mode OFF: the message MUST go to the queue.");
        Assert.IsTrue(sentOverSessionWhenOn, "Live Mode ON: the message MUST go over the session's send path.");
        Assert.AreEqual(0, queueDepthWhenOn, "Live Mode ON: the message MUST NOT go to the queue.");
        Assert.AreNotEqual(sentOverSessionWhenOff, sentOverSessionWhenOn, "The two outcomes of the SAME composition MUST differ — the Live Mode flag is the only variable between the two runs, so it alone determines the routing.");
    }


    /// <summary>
    /// Matches a public member declaration, capturing its name — a method (including <c>async</c>), a
    /// property, a field, an <c>event</c>, or a <c>const</c> — across every modifier combination this
    /// declaration head can carry (<c>static</c>, <c>async</c>, <c>virtual</c>, <c>override</c>,
    /// <c>sealed</c>, <c>new</c>, <c>required</c>, <c>readonly</c>, <c>event</c>, <c>const</c>, in any order
    /// and count) and every terminator its declaration line can end the name on: <c>(</c> for a method, <c>{</c>
    /// for a property, and <c>=</c> or a bare <c>;</c> for a field, event, or const.
    /// </summary>
    private static Regex PublicMemberDeclarationPattern { get; } = new(
        @"(?m)^\s*public\s+(?:(?:static|async|virtual|override|sealed|new|required|readonly|event|const)\s+)*[\w<>\[\],\.\?]+\??\s+(\w+)\s*[\(\{=;]",
        RegexOptions.Compiled);


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Live Mode:
    /// "Live Mode MUST only be enabled when a persistent transport is used, such as WebSockets." Structural:
    /// <see cref="DidCommSocketSession.SetLiveDelivery"/> exists only on the persistent-channel construct.
    /// This test proves BOTH halves of the claim: the positive, reachable path over
    /// <see cref="DidCommSocketSession"/> by ordinary compiled code, AND the negative — that the one-shot
    /// HTTP surfaces (<see cref="DidCommExchangeResult"/>, <see cref="DidCommTransportExtensions"/>) declare no
    /// live-mode member. No compile-time C# construct can express "this type has no member named X" — a
    /// positive-only test proving the one reachable path would still be true even if a live-mode member
    /// accidentally leaked onto the HTTP surface too, so the absence itself needs its own targeted check: a
    /// source-text scan of each HTTP-surface type's own public member declaration lines, asserting none of
    /// their names contains "Live" (case-insensitive) — the declaration lines only, not the surrounding doc
    /// comments and prose, which legitimately use ordinary words such as "delivered" that themselves contain
    /// the substring — with no runtime reflection over the loaded type.
    /// </summary>
    [TestMethod]
    public async Task LiveModeIsReachableOnlyThroughThePersistentSocketSession()
    {
        var fake = new FakeSessionTransport();
        var unsolicited = new RecordingUnsolicited();
        await using var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, Pool, TimeProvider);

        Assert.IsFalse(session.IsLiveDeliveryEnabled);
        session.SetLiveDelivery(true);
        Assert.IsTrue(session.IsLiveDeliveryEnabled, "Live Mode is a member of the persistent DidCommSocketSession construct.");

        string repositoryRoot = SourceHygieneScanner.FindRepositoryRoot();
        string[] oneShotHttpSurfaceFiles =
        [
            "src/Verifiable.DidComm/Transport/DidCommExchangeResult.cs",
            "src/Verifiable.DidComm/Transport/DidCommTransportExtensions.cs",
        ];

        foreach(string relativePath in oneShotHttpSurfaceFiles)
        {
            string text = await File.ReadAllTextAsync(Path.Combine(repositoryRoot, relativePath), TestContext.CancellationToken).ConfigureAwait(false);
            string[] liveLookingMembers = [.. PublicMemberDeclarationPattern.Matches(text)
                .Select(static m => m.Groups[1].Value)
                .Where(static name => name.Contains("Live", StringComparison.OrdinalIgnoreCase))];

            Assert.IsEmpty(
                liveLookingMembers,
                $"{relativePath} — the one-shot HTTP exchange surface — MUST declare no live-mode member at all; nothing there has an equivalent to call.");
        }
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Live Mode,
    /// mode 2 (§Live Mode): "Retrieve all messages from queue, and then activate Live Mode. This simplifies
    /// message processing logic in the recipient." Expressible over the session: the queue retrieval
    /// (delivery-request -&gt; delivery) completes as an ordinary correlated exchange while
    /// <see cref="DidCommSocketSession.IsLiveDeliveryEnabled"/> stays false, and only the SUBSEQUENT
    /// live-delivery-change flips it — retrieve-then-activate is a simple sequencing of two exchanges over
    /// the same session, not a distinct code path. Tied to OBSERVABLE state, not merely the recipient's own
    /// still-unset local flag (which is trivially false before anyone has set it): the mediator-side fake
    /// reports a genuine, wire-parsed <see cref="MessagePickupStatus"/> with <c>live_delivery: false</c> in a
    /// status query taken right after retrieval — before activation — and only the status queried AFTER
    /// activation reports it flipped to <see langword="true"/>.
    /// </summary>
    [TestMethod]
    public async Task Mode2RetrieveThenActivateLiveModeIsExpressibleOverTheSession()
    {
        var fake = new FakeSessionTransport();
        var unsolicited = new RecordingUnsolicited();
        await using var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, Pool, TimeProvider);

        DidCommMessage deliveryRequest = MessagePickupExtensions.CreateDeliveryRequest("dr-mode2", 10);
        ValueTask<DidCommExchangeResult> deliveryPending = session.ExchangeAsync("{\"ciphertext\":\"dr\"}"u8.ToArray(), deliveryRequest, default);
        await session.AcceptInboundFrameAsync("{\"ciphertext\":\"delivery\"}"u8.ToArray(), deliveryRequest.EffectiveThreadId, default).ConfigureAwait(false);
        using DidCommExchangeResult deliveryResult = await deliveryPending.ConfigureAwait(false);
        Assert.IsTrue(deliveryResult.IsAccepted);
        Assert.IsFalse(session.IsLiveDeliveryEnabled, "Retrieval completes BEFORE Live Mode is ever activated in mode 2.");

        //A status query right after retrieval, before activation: the mediator's own reported state — a
        //genuine, wire-parsed MessagePickupStatus, not the recipient's own not-yet-set local flag — is still
        //live_delivery: false.
        DidCommMessage statusBeforeActivationRequest = MessagePickupExtensions.CreateStatusRequest("status-before-activation-mode2");
        ValueTask<DidCommExchangeResult> statusBeforeActivationPending = session.ExchangeAsync("{\"ciphertext\":\"sr\"}"u8.ToArray(), statusBeforeActivationRequest, default);
        DidCommMessage statusBeforeActivationReply = MessagePickupExtensions.CreateStatus(
            "status-reply-before-activation-mode2", new MessagePickupStatus { MessageCount = 0, LiveDelivery = false }, inResponseTo: statusBeforeActivationRequest);
        using DidCommPlaintextMessage packedStatusBeforeActivation = statusBeforeActivationReply.PackPlaintext(DidCommMessageJson.Serializer, Pool);
        await session.AcceptInboundFrameAsync(packedStatusBeforeActivation.AsReadOnlySpan().ToArray(), statusBeforeActivationRequest.EffectiveThreadId, default).ConfigureAwait(false);
        using DidCommExchangeResult statusBeforeActivationResult = await statusBeforeActivationPending.ConfigureAwait(false);
        Assert.IsTrue(statusBeforeActivationResult.IsAccepted);
        DidCommMessage parsedStatusBeforeActivation = DidCommMessageJson.Parser(statusBeforeActivationResult.ReplyBody.AsReadOnlySpan());
        Assert.IsTrue(parsedStatusBeforeActivation.TryReadStatus(out MessagePickupStatus? statusBeforeActivation));
        Assert.IsFalse(statusBeforeActivation!.LiveDelivery, "Retrieval completed while the mediator's OWN reported state was still live_delivery: false.");

        DidCommMessage activate = MessagePickupExtensions.CreateLiveDeliveryChange("ldc-mode2", liveDelivery: true);
        ValueTask<DidCommExchangeResult> activatePending = session.ExchangeAsync("{\"ciphertext\":\"ldc\"}"u8.ToArray(), activate, default);
        session.SetLiveDelivery(true);
        DidCommMessage statusAfterActivationReply = MessagePickupExtensions.CreateStatus(
            "status-reply-after-activation-mode2", new MessagePickupStatus { MessageCount = 0, LiveDelivery = true }, inResponseTo: activate);
        using DidCommPlaintextMessage packedStatusAfterActivation = statusAfterActivationReply.PackPlaintext(DidCommMessageJson.Serializer, Pool);
        await session.AcceptInboundFrameAsync(packedStatusAfterActivation.AsReadOnlySpan().ToArray(), activate.EffectiveThreadId, default).ConfigureAwait(false);
        using DidCommExchangeResult activateResult = await activatePending.ConfigureAwait(false);

        Assert.IsTrue(activateResult.IsAccepted);
        Assert.IsTrue(session.IsLiveDeliveryEnabled, "Live Mode activates only AFTER retrieval completed.");
        DidCommMessage parsedStatusAfterActivation = DidCommMessageJson.Parser(activateResult.ReplyBody.AsReadOnlySpan());
        Assert.IsTrue(parsedStatusAfterActivation.TryReadStatus(out MessagePickupStatus? statusAfterActivation));
        Assert.IsTrue(statusAfterActivation!.LiveDelivery, "The mediator's OWN reported state flips to live_delivery: true only AFTER the activation exchange.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Live Mode,
    /// mode 3 (§Live Mode): "Activate Live Mode immediately upon connecting to the mediator. Retrieve messages
    /// from queue as possible. When receiving a message delivered live, the queue may be queried for any
    /// waiting messages delivered to the same did for processing." Expressible over the session: Live Mode
    /// activates BEFORE any retrieval, an uncorrelated live arrival dispatches unsolicited, and the
    /// recipient's own follow-up queue query is an ordinary correlated exchange over the SAME, already-live
    /// session.
    /// </summary>
    [TestMethod]
    public async Task Mode3ActivateImmediatelyThenQueryQueueOnLiveArrivalIsExpressibleOverTheSession()
    {
        var fake = new FakeSessionTransport();
        var liveFrames = new List<byte[]>();
        DidCommSessionInboundDelegate unsolicited = (frame, cancellationToken) =>
        {
            liveFrames.Add(frame.ToArray());

            return ValueTask.CompletedTask;
        };
        await using var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited, Pool, TimeProvider);

        //Activate Live Mode immediately upon connecting — BEFORE any retrieval (mode 3's defining trait).
        DidCommMessage activate = MessagePickupExtensions.CreateLiveDeliveryChange("ldc-mode3", liveDelivery: true);
        ValueTask<DidCommExchangeResult> activatePending = session.ExchangeAsync("{\"ciphertext\":\"ldc\"}"u8.ToArray(), activate, default);
        session.SetLiveDelivery(true);
        await session.AcceptInboundFrameAsync("{\"ciphertext\":\"status\"}"u8.ToArray(), activate.EffectiveThreadId, default).ConfigureAwait(false);
        using DidCommExchangeResult activateResult = await activatePending.ConfigureAwait(false);
        Assert.IsTrue(session.IsLiveDeliveryEnabled, "Live Mode is active BEFORE anything is retrieved.");

        //A message arrives live (uncorrelated).
        DidCommInboundFrameResult liveResult = await session.AcceptInboundFrameAsync("{\"ciphertext\":\"live-message\"}"u8.ToArray(), null, default).ConfigureAwait(false);
        Assert.AreEqual(DidCommInboundFrameDisposition.DispatchedUnsolicited, liveResult.Disposition);
        Assert.HasCount(1, liveFrames);

        //The recipient's own follow-up decision, upon receiving it, is to query the queue for anything else
        //waiting — an ordinary correlated exchange over the same already-live session.
        DidCommMessage followUpQuery = MessagePickupExtensions.CreateDeliveryRequest("dr-mode3-followup", 10);
        ValueTask<DidCommExchangeResult> followUpPending = session.ExchangeAsync("{\"ciphertext\":\"dr\"}"u8.ToArray(), followUpQuery, default);
        await session.AcceptInboundFrameAsync("{\"ciphertext\":\"delivery\"}"u8.ToArray(), followUpQuery.EffectiveThreadId, default).ConfigureAwait(false);
        using DidCommExchangeResult followUpResult = await followUpPending.ConfigureAwait(false);
        Assert.IsTrue(followUpResult.IsAccepted, "Mode 3's queue-query-on-live-arrival is expressible as an ordinary correlated exchange over the already-live session.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Live Mode
    /// Change: "Upon receiving the live_delivery_change message, the mediator **MUST* respond with a status
    /// message." Over the session, the enable request is a correlated <see cref="DidCommSocketSession.ExchangeAsync"/>
    /// exactly like any other Pickup request/reply — the addition here is only the session context
    /// (<see cref="DidCommSocketSession.SetLiveDelivery"/> alongside the reply correlating).
    /// </summary>
    [TestMethod]
    public async Task LiveDeliveryChangeEnableCorrelatesToAStatusReplyOverTheSession()
    {
        var fake = new FakeSessionTransport();
        var unsolicited = new RecordingUnsolicited();
        await using var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, Pool, TimeProvider);

        DidCommMessage change = MessagePickupExtensions.CreateLiveDeliveryChange("ldc-1", liveDelivery: true);
        ValueTask<DidCommExchangeResult> pending = session.ExchangeAsync("{\"ciphertext\":\"change\"}"u8.ToArray(), change, default);

        session.SetLiveDelivery(true);
        DidCommMessage statusReply = MessagePickupExtensions.CreateStatus("s-1", new MessagePickupStatus { MessageCount = 0, LiveDelivery = true }, inResponseTo: change);
        DidCommInboundFrameResult accepted = await session.AcceptInboundFrameAsync("{\"ciphertext\":\"status\"}"u8.ToArray(), statusReply.EffectiveThreadId, default).ConfigureAwait(false);

        Assert.AreEqual(DidCommInboundFrameDisposition.Correlated, accepted.Disposition);
        using DidCommExchangeResult result = await pending.ConfigureAwait(false);
        Assert.IsTrue(result.IsAccepted);
        Assert.IsTrue(session.IsLiveDeliveryEnabled);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Live Mode
    /// Change: "If sent with live_delivery set to true on a connection incapable of live delivery, a
    /// problem_report SHOULD be sent" with <c>"code": "e.m.live-mode-not-supported"</c>. On a SESSION-LESS
    /// transport (a plain HTTP exchange, no <see cref="DidCommSocketSession"/> involved at all) the EXISTING
    /// Pickup problem-report surface composes the response unchanged — a persistent channel gets session
    /// context, but nothing about the one-shot path changes.
    /// </summary>
    [TestMethod]
    public void LiveModeNotSupportedComposesOnASessionlessTransportUnchanged()
    {
        DidCommMessage change = MessagePickupExtensions.CreateLiveDeliveryChange("ldc-sessionless-1", liveDelivery: true);
        ProblemReport report = new()
        {
            Code = ProblemCode.Parse(WellKnownMessagePickupNames.LiveModeNotSupported),
            ParentThreadId = change.EffectiveThreadId!,
            Comment = "Connection does not support Live Delivery"
        };
        DidCommMessage problemMessage = report.CreateProblemReport("pr-sessionless-1");

        Assert.IsTrue(problemMessage.IsProblemReport());
        Assert.AreEqual(change.EffectiveThreadId, problemMessage.ParentThreadId);

        //No DidCommSocketSession is constructed anywhere in this test — the existing HTTP-era surface is
        //sufficient by itself; nothing about the session type participates.
    }


    /// <summary>
    /// Session contracts — cap boundary: a frame exactly AT <see cref="DidCommSocketSessionOptions.MaxReceiveBytes"/>
    /// is accepted, one byte over is refused — the reader/producer RANGE-symmetry requirement (a reader
    /// enforces the identical bound a producer-side guard validates), applied to the
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#agent-constraint-disclosure">DIDComm Messaging v2.1 §Agent Constraint Disclosure</see>
    /// cap: "any received message that exceeds the agent's stated maximum may be discarded." The cap measures
    /// "the total length of the DIDComm header plus the size of the message payload that an agent is willing
    /// to receive" — on the wire, the whole encrypted envelope IS that total, so the frame's own length is
    /// exactly the quantity this boundary pins.
    /// </summary>
    [TestMethod]
    public async Task AcceptInboundFrameAsyncCapBoundaryAtCapAcceptedOneOverRefused()
    {
        var fake = new FakeSessionTransport();
        var unsolicited = new RecordingUnsolicited();
        var options = new DidCommSocketSessionOptions { MaxReceiveBytes = 10 };
        await using var session = new DidCommSocketSession(fake.SendAsync, options, unsolicited.HandleAsync, Pool, TimeProvider);

        byte[] atCap = new byte[10];
        DidCommInboundFrameResult atCapResult = await session.AcceptInboundFrameAsync(atCap, null, default).ConfigureAwait(false);
        Assert.IsFalse(atCapResult.IsRefused, "Exactly at the cap MUST be accepted, not refused.");

        byte[] overCap = new byte[11];
        DidCommInboundFrameResult overCapResult = await session.AcceptInboundFrameAsync(overCap, null, default).ConfigureAwait(false);
        Assert.IsTrue(overCapResult.IsRefused, "One byte over the cap MUST be refused.");
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">DIDComm Messaging Return-Route and Queue Transport Extension</see>
    /// §Return Route Header: "Websocket transports are capable of receiving multiple messages over a single
    /// connection." Session contracts — correlation completes the RIGHT exchange among interleaved traffic:
    /// with two exchanges outstanding at once, correlation resolves each to its OWN reply no matter what
    /// order frames arrive in, and an interleaved unsolicited frame disturbs neither.
    /// </summary>
    [TestMethod]
    public async Task CorrelationCompletesTheRightExchangeAmongInterleavedTraffic()
    {
        var fake = new FakeSessionTransport();
        var unsolicited = new RecordingUnsolicited();
        await using var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, Pool, TimeProvider);

        DidCommMessage requestA = MessagePickupExtensions.CreateStatusRequest("interleave-a");
        DidCommMessage requestB = MessagePickupExtensions.CreateStatusRequest("interleave-b");
        ValueTask<DidCommExchangeResult> pendingA = session.ExchangeAsync("{\"ciphertext\":\"a-req\"}"u8.ToArray(), requestA, default);
        ValueTask<DidCommExchangeResult> pendingB = session.ExchangeAsync("{\"ciphertext\":\"b-req\"}"u8.ToArray(), requestB, default);

        byte[] replyB = "{\"ciphertext\":\"b-reply\"}"u8.ToArray();
        byte[] unsolicitedFrame = "{\"ciphertext\":\"live\"}"u8.ToArray();
        byte[] replyA = "{\"ciphertext\":\"a-reply\"}"u8.ToArray();

        //Mixed order: B's reply first, then an unrelated unsolicited frame, then A's reply.
        await session.AcceptInboundFrameAsync(replyB, requestB.EffectiveThreadId, default).ConfigureAwait(false);
        await session.AcceptInboundFrameAsync(unsolicitedFrame, null, default).ConfigureAwait(false);
        await session.AcceptInboundFrameAsync(replyA, requestA.EffectiveThreadId, default).ConfigureAwait(false);

        using DidCommExchangeResult resultA = await pendingA.ConfigureAwait(false);
        using DidCommExchangeResult resultB = await pendingB.ConfigureAwait(false);

        Assert.IsTrue(resultA.ReplyBody.AsReadOnlySpan().SequenceEqual(replyA), "A's exchange MUST resolve with A's own reply, never B's.");
        Assert.IsTrue(resultB.ReplyBody.AsReadOnlySpan().SequenceEqual(replyB), "B's exchange MUST resolve with B's own reply, never A's.");
        Assert.HasCount(1, unsolicited.Frames, "The interleaved unsolicited frame reached the unsolicited delegate exactly once, disturbing neither exchange.");
        Assert.IsTrue(unsolicited.Frames[0].AsSpan().SequenceEqual(unsolicitedFrame));
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">DIDComm Messaging Return-Route and Queue Transport Extension</see>
    /// §Return Route Header: "all: Send all messages for this DID over the connection." Only a frame that
    /// actually correlates to a request directing that is part of "all messages for this DID" tied to an
    /// outstanding exchange; everything else — a <see langword="null"/> correlation id, or one matching
    /// nothing outstanding — falls outside that directive and MUST dispatch unsolicited rather than being
    /// silently dropped or mistakenly treated as a match.
    /// </summary>
    [TestMethod]
    public async Task UncorrelatedOrNullThreadIdFramesAlwaysDispatchUnsolicited()
    {
        var fake = new FakeSessionTransport();
        var unsolicited = new RecordingUnsolicited();
        await using var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, Pool, TimeProvider);

        byte[] nullThidFrame = "{\"ciphertext\":\"a\"}"u8.ToArray();
        DidCommInboundFrameResult nullResult = await session.AcceptInboundFrameAsync(nullThidFrame, null, default).ConfigureAwait(false);
        Assert.AreEqual(DidCommInboundFrameDisposition.DispatchedUnsolicited, nullResult.Disposition);

        byte[] unmatchedThidFrame = "{\"ciphertext\":\"b\"}"u8.ToArray();
        DidCommInboundFrameResult unmatchedResult = await session.AcceptInboundFrameAsync(unmatchedThidFrame, "no-such-thread", default).ConfigureAwait(false);
        Assert.AreEqual(DidCommInboundFrameDisposition.DispatchedUnsolicited, unmatchedResult.Disposition);

        Assert.HasCount(2, unsolicited.Frames);
        Assert.IsTrue(unsolicited.Frames[0].AsSpan().SequenceEqual(nullThidFrame));
        Assert.IsTrue(unsolicited.Frames[1].AsSpan().SequenceEqual(unmatchedThidFrame));
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">DIDComm Messaging Return-Route and Queue Transport Extension</see>
    /// §Return Route Header: "all: Send all messages for this DID over the connection." When no reply for
    /// this exchange ever arrives on that connection, the directive simply never gets fulfilled — the
    /// session's own failure mode for that case is <see cref="DidCommSocketSessionOptions.ExchangeTimeout"/>
    /// elapsing and completing the exchange as <see cref="DidCommExchangeResult.TransportFailed"/>, never a
    /// thrown exception.
    /// </summary>
    [TestMethod]
    public async Task ExchangeAsyncTimeoutCompletesAsTransportFailed()
    {
        var fake = new FakeSessionTransport();
        var unsolicited = new RecordingUnsolicited();
        var options = new DidCommSocketSessionOptions { ExchangeTimeout = TimeSpan.FromMilliseconds(30) };

        //This test proves the session's own timeout genuinely elapses in real time — System.TimeProvider.System
        //is the deliberate choice here, not a hidden default, since a FakeTimeProvider never advances on its own.
        await using var session = new DidCommSocketSession(fake.SendAsync, options, unsolicited.HandleAsync, Pool, System.TimeProvider.System);

        DidCommMessage request = MessagePickupExtensions.CreateStatusRequest("timeout-1");
        using DidCommExchangeResult result = await session.ExchangeAsync("{\"ciphertext\":\"x\"}"u8.ToArray(), request, default).ConfigureAwait(false);

        Assert.IsFalse(result.IsAccepted);
        Assert.AreEqual(DidCommTransmitError.TransportFailed, result.Error);
        Assert.IsFalse(result.HasReply);
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>
    /// §WebSockets: "responses don't flow back the other way on the socket" outside the return-route
    /// exception — and once the socket itself is gone, there is no connection left for a reply to flow back
    /// on at all. Session contracts — disposal: <see cref="DidCommSocketSession.DisposeAsync"/> completes
    /// every OUTSTANDING exchange as <see cref="DidCommExchangeResult.TransportFailed"/> rather than leaving
    /// a caller waiting forever on a reply channel that no longer exists.
    /// </summary>
    [TestMethod]
    public async Task DisposeAsyncCompletesOutstandingExchangesAsTransportFailed()
    {
        var fake = new FakeSessionTransport();
        var unsolicited = new RecordingUnsolicited();
        var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, Pool, TimeProvider);

        DidCommMessage request = MessagePickupExtensions.CreateStatusRequest("dispose-1");
        ValueTask<DidCommExchangeResult> pending = session.ExchangeAsync("{\"ciphertext\":\"x\"}"u8.ToArray(), request, default);

        await session.DisposeAsync().ConfigureAwait(false);

        using DidCommExchangeResult result = await pending.ConfigureAwait(false);
        Assert.IsFalse(result.IsAccepted);
        Assert.AreEqual(DidCommTransmitError.TransportFailed, result.Error);
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">DIDComm Messaging Return-Route and Queue Transport Extension</see>
    /// §Return Route Header: "all: Send all messages for this DID over the connection." A caller that
    /// cancels the wait for that reply is withdrawing its own request, not observing a transport failure —
    /// session contracts — cancellation: genuine caller cancellation rethrows through
    /// <see cref="DidCommSocketSession.ExchangeAsync"/> — it is never folded into a fail-soft
    /// <see cref="DidCommExchangeResult.TransportFailed"/> result the way a timeout is.
    /// </summary>
    [TestMethod]
    public async Task ExchangeAsyncCancellationRethrows()
    {
        var fake = new FakeSessionTransport();
        var unsolicited = new RecordingUnsolicited();
        await using var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, Pool, TimeProvider);

        DidCommMessage request = MessagePickupExtensions.CreateStatusRequest("cancel-1");
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync().ConfigureAwait(false);

        await Assert.ThrowsAsync<OperationCanceledException>(
            async () => await session.ExchangeAsync("{\"ciphertext\":\"x\"}"u8.ToArray(), request, cts.Token).ConfigureAwait(false)).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>
    /// §WebSockets: "The trust of each message MUST be associated with DIDComm encryption or signing, not
    /// from the socket connection itself." Session contracts —
    /// <see cref="DidCommSocketSession.NegotiatedSubprotocol"/> is recorded verbatim from
    /// <see cref="DidCommSocketSessionOptions.NegotiatedSubprotocol"/> and is provably non-dispatching: it
    /// merely echoes back the exact string the application's handshake negotiated, and there is no code path
    /// on <see cref="DidCommSocketSession.AcceptInboundFrameAsync"/>/<see cref="DidCommSocketSession.SendAsync"/>
    /// that could branch on it even in principle — a connection-level attribute participates in NOTHING about
    /// trust or routing.
    /// </summary>
    [TestMethod]
    public async Task NegotiatedSubprotocolIsRecordedVerbatimAndNeverDispatchedOn()
    {
        var fake = new FakeSessionTransport();
        var unsolicited = new RecordingUnsolicited();
        const string Subprotocol = "didcomm-messaging;v=2";
        await using var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions { NegotiatedSubprotocol = Subprotocol }, unsolicited.HandleAsync, Pool, TimeProvider);
        Assert.AreEqual(Subprotocol, session.NegotiatedSubprotocol, "Recorded verbatim.");

        await using var sessionWithNoSubprotocol = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, Pool, TimeProvider);
        Assert.IsNull(sessionWithNoSubprotocol.NegotiatedSubprotocol);

        byte[] frame = "{\"ciphertext\":\"x\"}"u8.ToArray();
        DidCommInboundFrameResult result = await session.AcceptInboundFrameAsync(frame, null, default).ConfigureAwait(false);
        Assert.AreEqual(DidCommInboundFrameDisposition.DispatchedUnsolicited, result.Disposition);
    }


    /// <summary>
    /// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see> §Requirements
    /// and <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Requirements: "This header must be set each time the communication channel is established: once per
    /// established websocket, and every message for an HTTP POST." Session contracts —
    /// <see cref="DidCommSocketSession.MarkReturnRouteEstablished"/> (the mediator-side latch) is idempotent:
    /// a second and later call is a documented no-op, not an error, matching "once per established websocket."
    /// </summary>
    [TestMethod]
    public async Task MarkReturnRouteEstablishedIsIdempotentAfterTheFirstCall()
    {
        var fake = new FakeSessionTransport();
        var unsolicited = new RecordingUnsolicited();
        await using var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, Pool, TimeProvider);

        Assert.IsFalse(session.IsReturnRouteEstablished);
        session.MarkReturnRouteEstablished();
        Assert.IsTrue(session.IsReturnRouteEstablished);

        session.MarkReturnRouteEstablished();
        session.MarkReturnRouteEstablished();
        Assert.IsTrue(session.IsReturnRouteEstablished, "Repeated calls are a no-op, never an error and never toggling back off.");
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">DIDComm Messaging Return-Route and Queue Transport Extension</see>
    /// §Return Route Header: "Websocket transports are capable of receiving multiple messages over a single
    /// connection." Session contracts — thread-safety smoke: many concurrent senders, each with its own
    /// outstanding exchange, plus one simulated reader pump completing every one of them concurrently on that
    /// single connection, produce no cross-talk or corruption — every exchange resolves with its OWN reply.
    /// </summary>
    [TestMethod]
    public async Task ConcurrentSendersAndOneReaderAreThreadSafeOnASharedSession()
    {
        var fake = new FakeSessionTransport();
        var unsolicited = new RecordingUnsolicited();
        await using var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, Pool, TimeProvider);

        const int Concurrency = 16;
        var requests = new DidCommMessage[Concurrency];

        //ValueTask instances must be consumed exactly once and never stored across multiple statements
        //(CA2012); converting to Task immediately is the documented escape hatch for fanning out several
        //in-flight awaitables like this.
        var pendingExchanges = new Task<DidCommExchangeResult>[Concurrency];
        for(int i = 0; i < Concurrency; ++i)
        {
            requests[i] = MessagePickupExtensions.CreateStatusRequest($"concurrent-{i}");
            pendingExchanges[i] = session.ExchangeAsync(Encoding.UTF8.GetBytes($"{{\"ciphertext\":\"req-{i}\"}}"), requests[i], default).AsTask();
        }

        //A single simulated reader pump completes every outstanding exchange with its OWN matching reply,
        //concurrently, exactly as one real socket pump racing many senders would.
        var completions = new Task[Concurrency];
        for(int i = 0; i < Concurrency; ++i)
        {
            int index = i;
            completions[index] = Task.Run(async () =>
            {
                byte[] reply = Encoding.UTF8.GetBytes($"{{\"ciphertext\":\"reply-{index}\"}}");
                await session.AcceptInboundFrameAsync(reply, requests[index].EffectiveThreadId, default).ConfigureAwait(false);
            }, TestContext.CancellationToken);
        }

        await Task.WhenAll(completions).ConfigureAwait(false);

        for(int i = 0; i < Concurrency; ++i)
        {
            using DidCommExchangeResult result = await pendingExchanges[i].ConfigureAwait(false);
            Assert.IsTrue(result.IsAccepted, $"Exchange {i} MUST complete successfully.");
            string expected = $"{{\"ciphertext\":\"reply-{i}\"}}";
            Assert.AreEqual(expected, Encoding.UTF8.GetString(result.ReplyBody.AsReadOnlySpan()), $"Exchange {i} MUST resolve with its OWN reply, never another's — no cross-talk under concurrency.");
        }
    }


    /// <summary>
    /// The critical borrowed-frame fix: <see cref="DidCommSocketSession.AcceptInboundFrameAsync"/> COPIES a
    /// correlated frame rather than aliasing the caller's buffer. The awaiter reads the exchange's reply
    /// AFTER this call returns (the completion runs its continuations asynchronously), so a pooling pump
    /// that immediately reuses its buffer for the next frame would otherwise corrupt a reply already handed
    /// to the exchange.
    /// </summary>
    [TestMethod]
    public async Task AcceptInboundFrameAsyncCopiesTheCorrelatedFrameRatherThanAliasingThePumpsBuffer()
    {
        var fake = new FakeSessionTransport();
        var unsolicited = new RecordingUnsolicited();
        await using var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, Pool, TimeProvider);

        DidCommMessage request = MessagePickupExtensions.CreateStatusRequest("copy-not-alias-1");
        ValueTask<DidCommExchangeResult> pending = session.ExchangeAsync("{\"ciphertext\":\"req\"}"u8.ToArray(), request, default);

        byte[] pumpBuffer = "{\"ciphertext\":\"original\"}"u8.ToArray();
        byte[] original = pumpBuffer.AsSpan().ToArray();

        DidCommInboundFrameResult accepted = await session.AcceptInboundFrameAsync(pumpBuffer, request.EffectiveThreadId, default).ConfigureAwait(false);
        Assert.AreEqual(DidCommInboundFrameDisposition.Correlated, accepted.Disposition);

        //Simulates a pooling pump recycling its buffer for the NEXT frame immediately after the call returns
        //— exactly the moment a borrowed (not copied) reply would be corrupted.
        pumpBuffer.AsSpan().Fill(0xFF);

        using DidCommExchangeResult result = await pending.ConfigureAwait(false);
        Assert.IsTrue(result.IsAccepted);
        Assert.IsTrue(result.ReplyBody.AsReadOnlySpan().SequenceEqual(original), "The exchange MUST resolve with the ORIGINAL bytes — a copy taken during AcceptInboundFrameAsync, not a live alias of the pump's now-overwritten buffer.");
    }


    /// <summary>
    /// The dispose/register race fix: <see cref="DidCommSocketSession.ExchangeAsync"/>'s check-then-register
    /// and <see cref="DidCommSocketSession.DisposeAsync"/>'s flag-then-drain can interleave as
    /// check-not-disposed / drain-finds-nothing / register — without the publish-then-recheck fix, that
    /// registration would wait forever. The burst and the disposal each start on their own thread-pool
    /// threads: an exchange started on the test thread runs synchronously through registration before the
    /// fake send's first (already-completed) await, so a same-thread arrangement would publish every
    /// registration before the disposal even began and never generate the window under test. Every exchange
    /// MUST terminate — resolved non-accepted, or faulted with <see cref="ObjectDisposedException"/> when it
    /// observed the flag at entry — and never hang.
    /// </summary>
    [TestMethod]
    public async Task DisposeRacingABurstOfRegisteringExchangesNeverLeavesAnyExchangeWaitingForever()
    {
        const int Iterations = 50;
        const int BurstSize = 8;

        for(int iteration = 0; iteration < Iterations; ++iteration)
        {
            var fake = new FakeSessionTransport();
            var unsolicited = new RecordingUnsolicited();

            //Disposed both by the racing disposeTask below AND by this scope's own await using — double
            //dispose is a guarded no-op on the session, so the second call is harmless and gives the
            //iteration a deterministic owner.
            await using var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, Pool, TimeProvider);

            var exchanges = new Task<DidCommExchangeResult>[BurstSize];
            for(int i = 0; i < BurstSize; ++i)
            {
                DidCommMessage request = MessagePickupExtensions.CreateStatusRequest($"dispose-burst-{iteration}-{i}");
                byte[] packed = Encoding.UTF8.GetBytes($"{{\"ciphertext\":\"req-{iteration}-{i}\"}}");
                exchanges[i] = Task.Run(() => session.ExchangeAsync(packed, request, default).AsTask(), TestContext.CancellationToken);
            }

            Task disposeTask = Task.Run(() => session.DisposeAsync().AsTask(), TestContext.CancellationToken);

            //Bounded, not indefinite: an exchange that lost the publish-then-recheck race would otherwise
            //hang this await forever rather than merely failing an assertion. WhenAll itself may fault with
            //ObjectDisposedException from an exchange that observed the flag at entry — a valid terminal
            //outcome; the per-task loop below is the real assertion.
            Task everything = Task.WhenAll([.. exchanges, disposeTask]);
            try
            {
                await everything.WaitAsync(TimeSpan.FromSeconds(5), TestContext.CancellationToken).ConfigureAwait(false);
            }
            catch(ObjectDisposedException)
            {
                //A valid terminal outcome named by the comment above WhenAll: an exchange that observed the
                //dispose flag at entry faults the aggregate with this exception, and the per-task loop below
                //is the real assertion over each exchange's own outcome.
            }

            foreach(Task<DidCommExchangeResult> exchange in exchanges)
            {
                Assert.IsTrue(exchange.IsCompleted, $"Iteration {iteration}: an exchange racing DisposeAsync MUST terminate, never hang.");
                if(exchange.IsFaulted)
                {
                    Assert.IsInstanceOfType<ObjectDisposedException>(
                        exchange.Exception!.GetBaseException(),
                        $"Iteration {iteration}: a faulted exchange is valid ONLY as ObjectDisposedException from the entry check.");
                }
                else
                {
                    using DidCommExchangeResult result = await exchange.ConfigureAwait(false);
                    Assert.IsFalse(result.IsAccepted, $"Iteration {iteration}: an exchange that lost the registration window MUST resolve non-accepted.");
                }
            }
        }
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">DIDComm Messaging Return-Route and Queue Transport Extension §Return Route Header</see>
    /// ("all: Send all messages for this DID over the connection"): the registration is live for the whole
    /// duration of the send, so a reply can correlate BEFORE the send even reports its outcome. When the
    /// send then reports failure, the already-claimed reply MUST be delivered to the exchange caller rather
    /// than discarded — the pump was told <see cref="DidCommInboundFrameDisposition.Correlated"/>, so the
    /// frame has exactly one owner and losing it would contradict that disposition. The interleaving is
    /// forced deterministically: the fake transport correlates the reply from INSIDE the send, then returns
    /// a transport failure.
    /// </summary>
    [TestMethod]
    public async Task ReplyCorrelatingDuringAFailingSendIsDeliveredToTheCallerNotDiscarded()
    {
        var unsolicited = new RecordingUnsolicited();
        var fake = new FakeSessionTransport();
        byte[] replyFrame = Encoding.UTF8.GetBytes("{\"ciphertext\":\"reply-that-raced-the-failing-send\"}");
        DidCommInboundFrameResult? pumpDisposition = null;

        await using var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, Pool, TimeProvider);

        fake.Respond = (_, _) =>
        {
            pumpDisposition = session.AcceptInboundFrameAsync(replyFrame, "send-fail-race-1", CancellationToken.None)
                .AsTask().GetAwaiter().GetResult();

            return DidCommTransmitResult.TransportFailed();
        };

        DidCommMessage request = MessagePickupExtensions.CreateStatusRequest("send-fail-race-1");

        using DidCommExchangeResult result = await session.ExchangeAsync(
            Encoding.UTF8.GetBytes("{\"ciphertext\":\"request\"}"), request, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(pumpDisposition);
        Assert.AreEqual(DidCommInboundFrameDisposition.Correlated, pumpDisposition.Disposition, "The frame was claimed by the outstanding exchange.");
        Assert.IsTrue(result.IsAccepted, "The claimed reply MUST reach the exchange caller although the send reported failure.");
        Assert.IsTrue(result.ReplyBody.AsReadOnlySpan().SequenceEqual(replyFrame), "The delivered reply is the raced frame's bytes.");
        Assert.IsEmpty(unsolicited.Frames, "The frame was consumed by the exchange, so nothing dispatches unsolicited.");
    }


    /// <summary>
    /// The registration is live for the whole duration of the send, exactly as
    /// <see cref="ReplyCorrelatingDuringAFailingSendIsDeliveredToTheCallerNotDiscarded"/> forces — but here the
    /// send delegate THROWS instead of returning a failure, after the reply already correlated. The caller
    /// never receives the settled result (the exception propagates instead), so nothing but
    /// <see cref="DidCommSocketSession.ExchangeAsync"/>'s own exceptional-exit dispose can return its lease.
    /// Covers both a <see cref="WebSocketException"/> shape (a mid-send transport fault) and an
    /// <see cref="OperationCanceledException"/> shape (a non-caller-token cancellation surfacing from inside
    /// the send delegate itself), since either can escape the try body the same way.
    /// </summary>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task ReplyCorrelatingDuringAThrowingSendStillReturnsItsLeaseOnRethrow(bool isCancellationShape)
    {
        using var metered = new MeteredHousePool();
        var unsolicited = new RecordingUnsolicited();
        var fake = new FakeSessionTransport { ThrowCancellation = isCancellationShape, ThrowOnSend = !isCancellationShape };
        byte[] replyFrame = Encoding.UTF8.GetBytes($"{{\"ciphertext\":\"reply-that-raced-the-throwing-send-{isCancellationShape}\"}}");
        DidCommMessage request = MessagePickupExtensions.CreateStatusRequest($"throwing-send-race-{isCancellationShape}");
        DidCommInboundFrameResult? pumpDisposition = null;

        await using var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, metered.Pool, TimeProvider);

        fake.Respond = (_, _) =>
        {
            pumpDisposition = session.AcceptInboundFrameAsync(replyFrame, request.EffectiveThreadId, CancellationToken.None)
                .AsTask().GetAwaiter().GetResult();

            return DidCommTransmitResult.Accepted();
        };

        if(isCancellationShape)
        {
            await Assert.ThrowsExactlyAsync<OperationCanceledException>(
                async () => await session.ExchangeAsync(Encoding.UTF8.GetBytes("{\"ciphertext\":\"request\"}"), request, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }
        else
        {
            await Assert.ThrowsExactlyAsync<WebSocketException>(
                async () => await session.ExchangeAsync(Encoding.UTF8.GetBytes("{\"ciphertext\":\"request\"}"), request, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }

        Assert.IsNotNull(pumpDisposition);
        Assert.AreEqual(DidCommInboundFrameDisposition.Correlated, pumpDisposition.Disposition, "The frame correlated genuinely before the send's own exception propagated.");
        Assert.AreEqual(0L, metered.OutstandingCount, "ExchangeAsync's own exceptional-exit dispose must return the correlated reply's lease even though an exception, not the caller, ends the exchange.");
    }


    /// <summary>
    /// The timeout-window fix: a reply that loses the race with its own exchange's timeout is delivered
    /// UNSOLICITED, never silently dropped. Races <see cref="DidCommSocketSession.AcceptInboundFrameAsync"/>
    /// carrying the exchange's own thread id against that exchange's short <see cref="DidCommSocketSessionOptions.ExchangeTimeout"/>,
    /// repeated with many rapid attempts per iteration to stress the narrow window between the timeout
    /// settling the registration and <see cref="DidCommSocketSession.ExchangeAsync"/> removing it: whichever
    /// side actually claims the registration, the frame's disposition MUST be consistent with where it went
    /// — either genuinely correlated (and then the exchange's own result MUST carry it), or unsolicited (and
    /// then the unsolicited delegate MUST have received it). Neither side may silently discard it, which an
    /// unchecked <c>TrySetResult</c> would otherwise allow.
    /// </summary>
    [TestMethod]
    public async Task LateReplyRacingItsOwnExchangeTimeoutIsDeliveredUnsolicitedNeverDropped()
    {
        const int Iterations = 30;
        const int SpinAttempts = 200;

        for(int iteration = 0; iteration < Iterations; ++iteration)
        {
            var fake = new FakeSessionTransport();
            var unsolicited = new RecordingUnsolicited();
            var options = new DidCommSocketSessionOptions { ExchangeTimeout = TimeSpan.FromMilliseconds(15) };

            //This test proves the session's own timeout genuinely elapses in real time — System.TimeProvider.System
            //is the deliberate choice here, not a hidden default, since a FakeTimeProvider never advances on its own.
            await using var session = new DidCommSocketSession(fake.SendAsync, options, unsolicited.HandleAsync, Pool, System.TimeProvider.System);

            DidCommMessage request = MessagePickupExtensions.CreateStatusRequest($"late-reply-{iteration}");
            Task<DidCommExchangeResult> exchange = session.ExchangeAsync(
                Encoding.UTF8.GetBytes($"{{\"ciphertext\":\"req-{iteration}\"}}"), request, default).AsTask();

            string? threadId = request.EffectiveThreadId;
            byte[] lateReply = Encoding.UTF8.GetBytes($"{{\"ciphertext\":\"late-{iteration}\"}}");
            var correlatedResults = new List<DidCommInboundFrameResult>();

            Task spinner = Task.Run(async () =>
            {
                //Starts only once the exchange's own timeout is expected to be close to firing, then hammers
                //the SAME thread id in a tight loop — trying to land inside the narrow gap between the
                //timeout settling the registration and the exchange removing it.
                await Task.Delay(TimeSpan.FromMilliseconds(15), TestContext.CancellationToken).ConfigureAwait(false);
                for(int attempt = 0; attempt < SpinAttempts; ++attempt)
                {
                    DidCommInboundFrameResult result = await session.AcceptInboundFrameAsync(lateReply, threadId, default).ConfigureAwait(false);
                    if(result.Disposition == DidCommInboundFrameDisposition.Correlated)
                    {
                        correlatedResults.Add(result);
                    }
                }
            }, TestContext.CancellationToken);

            await Task.WhenAll(exchange, spinner).ConfigureAwait(false);
            using DidCommExchangeResult exchangeResult = await exchange.ConfigureAwait(false);

            //At most one attempt can ever claim a single outstanding registration.
            Assert.IsLessThanOrEqualTo(1, correlatedResults.Count, $"Iteration {iteration}: only ONE frame can ever claim a single outstanding exchange.");

            if(correlatedResults.Count == 1)
            {
                Assert.IsTrue(exchangeResult.IsAccepted, $"Iteration {iteration}: a disposition reported Correlated MUST mean the exchange actually received that reply.");
                Assert.IsTrue(exchangeResult.ReplyBody.AsReadOnlySpan().SequenceEqual(lateReply), $"Iteration {iteration}: the correlated reply bytes must be exactly what was accepted.");
            }
            else
            {
                Assert.IsFalse(exchangeResult.IsAccepted, $"Iteration {iteration}: with nothing correlating, the exchange resolved via its own timeout.");
                Assert.IsTrue(unsolicited.Frames.Exists(receivedFrame => receivedFrame.AsSpan().SequenceEqual(lateReply)), $"Iteration {iteration}: the late reply MUST have reached the unsolicited delegate rather than being silently dropped.");
            }
        }
    }


    /// <summary>
    /// Every rented reply lease is returned exactly once, even when <see cref="DidCommSocketSession.AcceptInboundFrameAsync"/>
    /// mints a pooled copy for a frame whose exchange already settled on its own: races the same way
    /// <see cref="LateReplyRacingItsOwnExchangeTimeoutIsDeliveredUnsolicitedNeverDropped"/> does, tracking
    /// rents against a counting pool per iteration. The lease invariant
    /// (<c>metered.OutstandingCount == 0</c>) is asserted on EVERY iteration regardless of which side of the
    /// race won — that is what makes this a gate test. Whether the orphaned-mint-then-dispose path
    /// (<see cref="DidCommInboundFrameDisposition.Correlated"/>'s <c>TrySetResult</c> losing against an
    /// already-settled exchange) actually fired within the run is a SCHEDULER property, not a code property,
    /// so it is only a logged diagnostic — see the class remarks' rule that a gate test may use racing but
    /// may only FAIL when the code is wrong.
    /// </summary>
    /// <remarks>
    /// The window this races — the exchange settling its own timeout internally, versus removing its
    /// registration a moment later — is inherently narrow: the two happen adjacently in
    /// <see cref="DidCommSocketSession.ExchangeAsync"/>'s own control flow. Arming is a unit test counting an
    /// injected clock forward, never a wall-clock read: a per-iteration <see cref="FakeTimeProvider"/> drives
    /// the session's own <see cref="System.Threading.CancellationTokenSource"/>-realized timeout, advanced
    /// past <see cref="DidCommSocketSessionOptions.ExchangeTimeout"/> on its own task so the advance and the
    /// hammering spinner below race each other for real through thread-pool scheduling rather than through
    /// proximity to a real deadline. Measured at ~300 iterations under 16-way contention, the target path
    /// fires on most but not all runs; the deterministic proof that an exceptional exit disposes a
    /// settled-but-raced reply lives in <see cref="ReplyCorrelatingDuringAThrowingSendStillReturnsItsLeaseOnRethrow"/>.
    /// </remarks>
    [TestMethod]
    public async Task SettledThenCorrelatedFallThroughReturnsTheOrphansLease()
    {
        const int Iterations = 300;
        const int MaxHammerAttempts = 20_000;
        long orphanedMints = 0;

        for(int iteration = 0; iteration < Iterations; ++iteration)
        {
            using var metered = new MeteredHousePool();
            var fake = new FakeSessionTransport();
            var unsolicited = new RecordingUnsolicited();
            var options = new DidCommSocketSessionOptions { ExchangeTimeout = TimeSpan.FromMilliseconds(15) };
            var fakeClock = new FakeTimeProvider(TestClock.CanonicalEpoch);
            await using var session = new DidCommSocketSession(fake.SendAsync, options, unsolicited.HandleAsync, metered.Pool, fakeClock);

            DidCommMessage request = MessagePickupExtensions.CreateStatusRequest($"orphan-lease-{iteration}");
            Task<DidCommExchangeResult> exchange = session.ExchangeAsync(
                Encoding.UTF8.GetBytes($"{{\"ciphertext\":\"req-{iteration}\"}}"), request, default).AsTask();

            string? threadId = request.EffectiveThreadId;
            byte[] lateReply = Encoding.UTF8.GetBytes($"{{\"ciphertext\":\"late-{iteration}\"}}");
            int correlatedCount = 0;

            //Arms the session's internal timeout deterministically by advancing the injected clock past
            //ExchangeTimeout, on its own task, so it races the hammering spinner below through real thread
            //scheduling instead of through proximity to a wall-clock deadline.
            Task armer = Task.Run(() => fakeClock.Advance(options.ExchangeTimeout!.Value), TestContext.CancellationToken);

            Task spinner = Task.Run(async () =>
            {
                for(int attempt = 0; attempt < MaxHammerAttempts && !exchange.IsCompleted; ++attempt)
                {
                    DidCommInboundFrameResult result = await session.AcceptInboundFrameAsync(lateReply, threadId, default).ConfigureAwait(false);
                    if(result.Disposition == DidCommInboundFrameDisposition.Correlated)
                    {
                        ++correlatedCount;
                    }
                }
            }, TestContext.CancellationToken);

            await Task.WhenAll(exchange, armer, spinner).ConfigureAwait(false);
            DidCommExchangeResult exchangeResult = await exchange.ConfigureAwait(false);

            //At most one rent of this exact size happens this iteration — TryRemove on the registration is
            //destructive, so only the SINGLE attempt (in AcceptInboundFrameAsync or ExchangeAsync's own
            //finally) that wins it can ever reach the copy. A rent with correlatedCount still 0 is exactly
            //that attempt's copy having lost TrySetResult and been disposed by the fallback.
            long rentsThisIteration = metered.RentedCountOfSize(lateReply.Length);
            if(rentsThisIteration > 0 && correlatedCount == 0)
            {
                ++orphanedMints;
            }

            exchangeResult.Dispose();

            Assert.AreEqual(0L, metered.OutstandingCount, $"Iteration {iteration}: the rent this iteration — the exchange's own reply, or an orphan's — must be returned either way.");
        }

        TestContext.WriteLine($"Diagnostic (not asserted): the orphaned-mint-then-dispose path fired {orphanedMints} of {Iterations} iteration(s) — a scheduler property, not a code property; the lease invariant above holds every iteration regardless.");
    }


    /// <summary>
    /// Every rented reply lease is returned exactly once even when a caller's own cancellation wins the race
    /// against a reply that correlated genuinely: <see cref="DidCommSocketSession.ExchangeAsync"/> rethrows
    /// <see cref="OperationCanceledException"/> without ever handing the reply to the caller, so its lease can
    /// only be returned by the internal dispose-before-rethrow this abandonment requires. Races the same real
    /// way the timeout case does (documented on <see cref="DidCommSocketSession"/>'s own <c>WaitForCorrelatedReplyAsync</c>:
    /// "the token can enter the canceled state at essentially the same instant AcceptInboundFrameAsync's
    /// TrySetResult settles completion with a genuine correlated reply"). The lease invariant
    /// (<c>metered.OutstandingCount == 0</c>) is asserted on EVERY iteration regardless of which side of the
    /// race won — that is what makes this a gate test. Whether a genuinely correlated reply actually coincided
    /// with a genuinely thrown cancellation within the run is a SCHEDULER property, not a code property, so it
    /// is only a logged diagnostic — see the class remarks' rule that a gate test may use racing but may only
    /// FAIL when the code is wrong.
    /// </summary>
    /// <remarks>
    /// The settled-but-still-registered window this races — settle and the registration's removal are
    /// adjacent in <see cref="DidCommSocketSession.ExchangeAsync"/>'s own control flow — is inherently narrow.
    /// The spinner arms itself at the observed EDGE of the cancellation instead of relying on scheduling
    /// alignment: it busy-waits on <see cref="CancellationTokenSource.IsCancellationRequested"/> itself —
    /// which flips before any registered callback runs — using <see cref="Thread.SpinWait(int)"/> rather than
    /// <see cref="SpinWait.SpinOnce"/> so edge detection is never surrendered to the scheduler under load, and
    /// only then hammers, continuing until the exchange itself resolves. Measured at ~300 iterations under
    /// 16-way contention, a genuinely correlated reply coincides with a genuinely thrown cancellation on
    /// roughly nine of ten iterations, so the logged diagnostic is non-zero on every observed run — it
    /// stays a diagnostic rather than an assertion because it is a scheduler property either way; the
    /// deterministic proof that an exceptional exit disposes a settled-but-raced reply lives in
    /// <see cref="ReplyCorrelatingDuringAThrowingSendStillReturnsItsLeaseOnRethrow"/>.
    /// </remarks>
    [TestMethod]
    public async Task CancellationAbandonmentReturnsTheLeaseOfAReplyThatRacedTheCancellation()
    {
        const int Iterations = 300;
        const int MaxHammerAttempts = 20_000;
        long abandonedCorrelations = 0;

        for(int iteration = 0; iteration < Iterations; ++iteration)
        {
            using var metered = new MeteredHousePool();
            var fake = new FakeSessionTransport();
            var unsolicited = new RecordingUnsolicited();
            await using var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, metered.Pool, TimeProvider);

            DidCommMessage request = MessagePickupExtensions.CreateStatusRequest($"cancel-lease-{iteration}");
            using var cts = new CancellationTokenSource();
            Task<DidCommExchangeResult> exchange = session.ExchangeAsync(
                Encoding.UTF8.GetBytes($"{{\"ciphertext\":\"req-{iteration}\"}}"), request, cts.Token).AsTask();

            string? threadId = request.EffectiveThreadId;
            byte[] reply = Encoding.UTF8.GetBytes($"{{\"ciphertext\":\"reply-{iteration}\"}}");
            int correlatedCount = 0;

            var spinnerReady = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            Task spinner = Task.Run(async () =>
            {
                spinnerReady.SetResult();

                //Armed at the observed edge of the cancellation itself, not a fixed delay: IsCancellationRequested
                //flips before any registered callback runs, so spinning on it gives the hammering loop the
                //earliest possible start against the internal settle-then-remove sequence it races.
                while(!cts.IsCancellationRequested)
                {
                    Thread.SpinWait(64);
                }

                for(int attempt = 0; attempt < MaxHammerAttempts && !exchange.IsCompleted; ++attempt)
                {
                    DidCommInboundFrameResult result = await session.AcceptInboundFrameAsync(reply, threadId, default).ConfigureAwait(false);
                    if(result.Disposition == DidCommInboundFrameDisposition.Correlated)
                    {
                        ++correlatedCount;
                    }
                }
            }, TestContext.CancellationToken);

            await spinnerReady.Task.ConfigureAwait(false);
            await cts.CancelAsync().ConfigureAwait(false);

            DidCommExchangeResult? result = null;
            bool wasCancelled = false;
            try
            {
                result = await exchange.ConfigureAwait(false);
            }
            catch(OperationCanceledException)
            {
                wasCancelled = true;
            }

            await spinner.ConfigureAwait(false);

            Assert.IsLessThanOrEqualTo(1, correlatedCount, $"Iteration {iteration}: only ONE frame can ever claim a single outstanding exchange.");

            if(wasCancelled && correlatedCount == 1)
            {
                //The reply correlated genuinely, but the caller's own cancellation still won the race for the
                //exchange's returned task — the reply is abandoned, and its lease can only have come back via
                //ExchangeAsync's own dispose-before-rethrow, since this caller never received the result.
                ++abandonedCorrelations;
            }

            result?.Dispose();

            Assert.AreEqual(0L, metered.OutstandingCount, $"Iteration {iteration}: whichever side won, the reply's rented lease must be returned — by this caller when the exchange returned it, or internally when it was abandoned to cancellation.");
        }

        TestContext.WriteLine($"Diagnostic (not asserted): a genuinely correlated reply coincided with a genuinely thrown cancellation {abandonedCorrelations} of {Iterations} iteration(s) — a scheduler property, not a code property; the lease invariant above holds every iteration regardless.");
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#agent-constraint-disclosure">DIDComm Messaging v2.1 §Agent Constraint Disclosure</see>:
    /// <c>max_receive_bytes</c> is "the total length of the DIDComm header plus the size of the message
    /// payload that an agent is willing to receive" — a length that cannot be zero or negative, so
    /// <see cref="DidCommSocketSessionOptions.MaxReceiveBytes"/> rejects both up front — the reader/producer
    /// range-symmetry requirement, applied to this producer-side guard.
    /// </summary>
    [TestMethod]
    [DataRow(0L)]
    [DataRow(-1L)]
    public void MaxReceiveBytesRejectsNonPositiveValues(long nonPositiveBytes)
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => _ = new DidCommSocketSessionOptions { MaxReceiveBytes = nonPositiveBytes });
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports §Transport Requirements</see>
    /// ("Each transport MUST define" its conventions — this option is part of this seam's definition):
    /// <see cref="DidCommSocketSessionOptions.ExchangeTimeout"/> rejects a negative value unless it is
    /// exactly <see cref="Timeout.InfiniteTimeSpan"/>: any other negative wait would otherwise surface only
    /// deep inside <see cref="DidCommSocketSession.ExchangeAsync"/>'s timeout machinery, after the frame
    /// already went on the wire, rather than at the point the caller misconfigured it.
    /// </summary>
    [TestMethod]
    [DataRow(-2L)]
    [DataRow(-1000L)]
    public void ExchangeTimeoutRejectsNegativeValuesOtherThanTheInfiniteSentinel(long negativeMilliseconds)
    {
        TimeSpan negative = TimeSpan.FromMilliseconds(negativeMilliseconds);

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => _ = new DidCommSocketSessionOptions { ExchangeTimeout = negative });
    }


    /// <summary>
    /// <see cref="DidCommSocketSessionOptions.ExchangeTimeout"/> rejects a value above the largest delay
    /// <see cref="CancellationTokenSource"/> supports (<c>uint.MaxValue - 1</c> milliseconds, about 49.7
    /// days): the range guard covers BOTH invalid ends, so neither end can surface as an undocumented
    /// exception from inside <see cref="DidCommSocketSession.ExchangeAsync"/> after the frame already went
    /// on the wire.
    /// </summary>
    [TestMethod]
    public void ExchangeTimeoutRejectsValuesAboveTheCancellationTokenSourceMaximum()
    {
        TimeSpan oversized = TimeSpan.FromDays(60);

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => _ = new DidCommSocketSessionOptions { ExchangeTimeout = oversized });
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports §Transport Requirements</see>
    /// ("Each transport MUST define" its conventions): the one negative <see cref="TimeSpan"/>
    /// <see cref="DidCommSocketSessionOptions.ExchangeTimeout"/>
    /// MUST accept: <see cref="Timeout.InfiniteTimeSpan"/> itself, the sentinel
    /// <see cref="DidCommSocketSession.ExchangeAsync"/> treats as "wait indefinitely" — the range-symmetry
    /// guard must not reject the one negative value that is actually meaningful.
    /// </summary>
    [TestMethod]
    public void ExchangeTimeoutAcceptsTheInfiniteSentinel()
    {
        var options = new DidCommSocketSessionOptions { ExchangeTimeout = Timeout.InfiniteTimeSpan };

        Assert.AreEqual(Timeout.InfiniteTimeSpan, options.ExchangeTimeout);
    }


    /// <summary>
    /// <see cref="DidCommSocketSessionOptions"/> is a scalar-only record realizing this seam's own answer to
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>
    /// §Transport Requirements ("Each transport MUST define" its own conventions) —
    /// <see cref="DidCommSocketSessionOptions.MaxReceiveBytes"/>/<see cref="DidCommSocketSessionOptions.NegotiatedSubprotocol"/>/
    /// <see cref="DidCommSocketSessionOptions.ExchangeTimeout"/> are all value types or strings, so its
    /// equality MUST be the synthesized record equality with both <c>Equals</c> AND <c>operator==</c>
    /// agreeing; omitting the operator is the record-equality trap a scalar record must never fall into.
    /// </summary>
    [TestMethod]
    public void DidCommSocketSessionOptionsUsesSynthesizedScalarEquality()
    {
        var a = new DidCommSocketSessionOptions { MaxReceiveBytes = 65536, NegotiatedSubprotocol = "didcomm", ExchangeTimeout = TimeSpan.FromSeconds(30) };
        var b = new DidCommSocketSessionOptions { MaxReceiveBytes = 65536, NegotiatedSubprotocol = "didcomm", ExchangeTimeout = TimeSpan.FromSeconds(30) };
        var different = a with { MaxReceiveBytes = 1024 };

        Assert.AreEqual(a, b);
        Assert.IsTrue(a == b, "Records synthesize BOTH Equals and operator== — omitting the operator would let them disagree; this asserts they agree.");
        Assert.AreNotEqual(a, different);
        Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>
    /// §WebSockets: "The trust of each message MUST be associated with DIDComm encryption or signing, not
    /// from the socket connection itself." The adversarial demonstration this trust boundary predicts: a
    /// HOSTILE party who is NOT the wallet's intended mediator, but who knows the wallet's PUBLIC key (public
    /// by anoncrypt's own design — anyone may encrypt to it) and has learned or guessed the outstanding
    /// thread id, CAN mint an envelope that decrypts cleanly and correlates to that SAME outstanding exchange
    /// exactly like a genuine reply would. This is the routing reality the docs warn about, not a bug: NO
    /// library-side guard is added here, because none is possible without breaking anoncrypt's own
    /// repudiable posture (anyone may encrypt to a public key; that is the protocol's whole point) — the
    /// mitigation lives entirely at the APPLICATION's own authentication boundary: a channel-level guarantee
    /// (TLS pinning, an authenticated upgrade) or an authcrypt/signature check performed after unpack, never
    /// the session's correlation.
    /// </summary>
    [TestMethod]
    public async Task HostileAnoncryptFrameCarryingAGuessedOutstandingThreadIdDoesCorrelate()
    {
        const string WalletKid = "did:example:adversarial-wallet#key-1";
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> wallet = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory walletPublic = wallet.PublicKey;
        using PrivateKeyMemory walletPrivate = wallet.PrivateKey;

        var fake = new FakeSessionTransport();
        var unsolicited = new RecordingUnsolicited();
        await using var session = new DidCommSocketSession(fake.SendAsync, new DidCommSocketSessionOptions(), unsolicited.HandleAsync, Pool, TimeProvider);

        //The wallet's own outstanding request — its thid is the "secret" a hostile party must guess or learn.
        DidCommMessage request = MessagePickupExtensions.CreateStatusRequest("guessed-thid-1");
        ValueTask<DidCommExchangeResult> pending = session.ExchangeAsync("{\"ciphertext\":\"req\"}"u8.ToArray(), request, default);

        //The hostile frame: minted by an attacker who is NOT the mediator, using nothing but the wallet's
        //PUBLIC key and the guessed thread id — no shared secret, no authentication, and no library surface
        //this attacker needs to compromise.
        DidCommMessage hostileReply = new()
        {
            Id = "hostile-reply-1",
            Type = WellKnownMessagePickupNames.StatusType,
            ThreadId = request.EffectiveThreadId,
            From = "did:example:attacker",
            Body = new Dictionary<string, object> { ["messagespecificattribute"] = "not really from the mediator" }
        };
        using DidCommEncryptedMessage hostileEnvelope = await PackAnoncryptAsync(hostileReply, WalletKid, walletPublic, default).ConfigureAwait(false);
        byte[] hostileBytes = hostileEnvelope.AsReadOnlySpan().ToArray();

        //The application's own unpack recovers a thid from this frame exactly as it would for a genuine
        //mediator reply — the session cannot tell the two apart, because correlation is routing, never
        //sender authentication.
        string? recoveredThreadId = await TryRecoverThreadIdAsync(hostileBytes, WalletKid, walletPrivate, default).ConfigureAwait(false);
        Assert.AreEqual(request.EffectiveThreadId, recoveredThreadId, "The hostile envelope decrypts cleanly and its thid is recoverable exactly like a genuine reply's — anoncrypt authenticates nobody.");

        DidCommInboundFrameResult accepted = await session.AcceptInboundFrameAsync(hostileBytes, recoveredThreadId, default).ConfigureAwait(false);
        Assert.AreEqual(DidCommInboundFrameDisposition.Correlated, accepted.Disposition, "The session correlates the hostile frame to the wallet's own outstanding exchange — the library cannot distinguish a guessed/leaked thid from a genuine one, because thid-matching is deliberately not an authentication mechanism.");

        using DidCommExchangeResult result = await pending.ConfigureAwait(false);
        Assert.IsTrue(result.IsAccepted);
        Assert.IsTrue(result.ReplyBody.AsReadOnlySpan().SequenceEqual(hostileBytes), "The exchange resolves with the HOSTILE bytes — proof that correlation alone conferred acceptance. No library-side guard is possible here without breaking anoncrypt's own repudiable posture, so the mitigation is entirely the application's own authentication boundary.");
    }


    private static string PackToJson(DidCommMessage message)
    {
        using DidCommPlaintextMessage packed = message.PackPlaintext(DidCommMessageJson.Serializer, Pool);

        return Encoding.UTF8.GetString(packed.AsReadOnlySpan());
    }


    //The wallet's own pump does the unpack the session delegates to it (the session cannot decrypt to learn
    //thid on its own — see DidCommSocketSession's documented decrypt boundary). Any frame that fails to
    //unpack as anoncrypt to this key is not something the wallet can correlate, so it is treated as having
    //no correlation id (dispatches unsolicited). The thid this recovers is routing, not authentication: a
    //frame that successfully unpacks and happens to carry a thid matching an outstanding exchange correlates
    //regardless of who actually sent it — correlation confers no sender authentication (DIDComm Messaging
    //v2.1 §Transports §WebSockets), so any trust this test's wallet places in a correlated reply comes from
    //the anoncrypt unpack succeeding at all, never from the thid match itself.
    private static async Task<string?> TryRecoverThreadIdAsync(byte[] frame, string kid, PrivateKeyMemory privateKey, CancellationToken cancellationToken)
    {
        try
        {
            using DidCommEncryptedMessage encrypted = DidCommEncryptedMessage.Create(frame, BufferTags.Json, Pool);
            DidCommEncryptedUnpackResult unpacked = await encrypted.UnpackAnoncryptAsync(
                kid, privateKey, NestedSignerResolver, UnpackContext, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
                TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            return unpacked.IsUnpacked ? unpacked.Message!.EffectiveThreadId : null;
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch
        {
            //frame is untrusted wire input from the other side of the duplex pair; any failure to unpack
            //it means no correlation thread id is recoverable, cancellation excepted above.
            return null;
        }
    }


    //Collects the frame TYPE every inbound frame actually arrived as, on the pump's OWN background task,
    //rather than asserting on it there: an assertion failure inside a background pump task faults that task
    //silently until something later observes it, which would surface as a confusing, indirect failure
    //instead of a clean one — so this only records, and the test thread asserts on the collected list after
    //the pumps have stopped (pinning the seam's own text-send framing posture per §Transport Requirements).
    private static async Task RunMediatorPumpAsync(
        DidCommDuplexMediatorHost host, DidCommSocketSession session, List<WebSocketMessageType> observedFrameTypes, CancellationToken cancellationToken)
    {
        try
        {
            while(true)
            {
                (WebSocketMessageType frameType, byte[] frame) = await host.ReceiveFrameAsync(cancellationToken).ConfigureAwait(false);
                observedFrameTypes.Add(frameType);

                //The mediator never itself holds an outstanding ExchangeAsync in this protocol — every
                //inbound frame from the wallet dispatches to the mediator's OWN unsolicited handler, which
                //performs the actual protocol dispatch (decrypt, decide, reply).
                await session.AcceptInboundFrameAsync(frame, null, cancellationToken).ConfigureAwait(false);
            }
        }
        catch(OperationCanceledException)
        {
            //Pump shutdown — the test cancels this token once it is done driving the connection.
        }
        catch(WebSocketException) when(cancellationToken.IsCancellationRequested)
        {
            //Both pumps share one cancellation token. Cancelling a pending ReceiveAsync on ONE side of this
            //duplex pair can abort the underlying connection abruptly rather than complete a graceful
            //WebSocket close handshake, which the OTHER side then observes as a WebSocketException instead
            //of the expected OperationCanceledException — still an intentional shutdown once cancellation
            //was actually requested, not a genuine transport failure.
        }
    }


    private static async Task RunWalletPumpAsync(
        DidCommDuplexWalletConnection connection, DidCommSocketSession session, string walletKid, PrivateKeyMemory walletPrivate,
        List<WebSocketMessageType> observedFrameTypes, CancellationToken cancellationToken)
    {
        try
        {
            while(true)
            {
                (WebSocketMessageType frameType, byte[] frame) = await connection.ReceiveFrameAsync(cancellationToken).ConfigureAwait(false);
                observedFrameTypes.Add(frameType);
                string? correlationThreadId = await TryRecoverThreadIdAsync(frame, walletKid, walletPrivate, cancellationToken).ConfigureAwait(false);
                await session.AcceptInboundFrameAsync(frame, correlationThreadId, cancellationToken).ConfigureAwait(false);
            }
        }
        catch(OperationCanceledException)
        {
            //The expected shutdown path: the caller cancels this token once it is done driving the
            //connection, and ReceiveFrameAsync surfaces that as a cancellation the pump simply exits on.
        }
        catch(WebSocketException) when(cancellationToken.IsCancellationRequested)
        {
            //See RunMediatorPumpAsync's identical catch: the shared cancellation token can surface as either
            //exception depending on which side's abort the OTHER side observes first.
        }
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports §Transport Requirements</see>:
    /// "Each transport MUST define: ... how to actually send messages" — this seam's definition
    /// (<see cref="DidCommSessionInboundDelegate"/>'s remarks) is asymmetric:
    /// <see cref="DidCommSessionSendDelegate"/> always SENDS a text frame, but an implementation feeding
    /// frames to <see cref="DidCommSocketSession.AcceptInboundFrameAsync"/> is BINARY-TOLERANT-ACCEPT, since
    /// a peer that sends binary measurably exists. Proven on the real wire: a frame sent deliberately as
    /// <see cref="WebSocketMessageType.Binary"/> — never as the seam's own Text convention — still dispatches
    /// IDENTICALLY to a Text frame carrying the same bytes.
    /// </summary>
    [TestMethod]
    public async Task AcceptInboundFrameAsyncDispatchesABinaryTypedFrameIdenticallyToATextTypedFrame()
    {
        await using DidCommDuplexMediatorHost mediatorHost = await DidCommDuplexMediatorHost.StartAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await using DidCommDuplexWalletConnection walletConnection =
            await DidCommDuplexWalletConnection.ConnectAsync(mediatorHost.Endpoint, mediatorHost.Certificate, TestContext.CancellationToken).ConfigureAwait(false);

        var unsolicited = new RecordingUnsolicited();
        await using var mediatorSession = new DidCommSocketSession(mediatorHost.CreateSendDelegate(), new DidCommSocketSessionOptions(), unsolicited.HandleAsync, Pool, TimeProvider);

        byte[] frame = "{\"ciphertext\":\"binary-tolerant\"}"u8.ToArray();
        await walletConnection.SendRawFrameAsync(frame, WebSocketMessageType.Binary, TestContext.CancellationToken).ConfigureAwait(false);

        (WebSocketMessageType receivedType, byte[] receivedFrame) = await mediatorHost.ReceiveFrameAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(WebSocketMessageType.Binary, receivedType, "This test's own send deliberately used a Binary frame to exercise the tolerant-accept path — a sanity check on the test itself, not the seam.");

        DidCommInboundFrameResult result = await mediatorSession.AcceptInboundFrameAsync(receivedFrame, null, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(DidCommInboundFrameDisposition.DispatchedUnsolicited, result.Disposition, "A Binary-typed frame dispatches IDENTICALLY to a Text-typed one — the session reads only bytes, never the WebSocket frame type.");
        Assert.HasCount(1, unsolicited.Frames);
        Assert.IsTrue(unsolicited.Frames[0].AsSpan().SequenceEqual(frame));
    }


    /// <summary>
    /// E2E capstone: a full Live Mode round over a REAL loopback <c>wss://</c> connection. A wallet
    /// <see cref="DidCommSocketSession"/> connects to an in-process mediator harness
    /// (<see cref="DidCommDuplexMediatorHost"/>/<see cref="DidCommDuplexWalletConnection"/>), sends an
    /// anoncrypt <c>status-request</c> (<c>return_route: all</c>) via
    /// <see cref="DidCommSocketSession.ExchangeAsync"/> — the packed <c>status</c> correlates back on the
    /// socket; <c>live-delivery-change(true)</c> correlates to an updated <c>status</c>; the mediator then
    /// pushes a live-delivered encrypted message that arrives via the wallet's unsolicited delegate,
    /// classifies via the content-type-absent <see cref="DidCommInbound.Classify"/>, and decrypts with
    /// project crypto; the wallet acks with <c>messages-received</c>, correlating to a final, updated
    /// <c>status</c>. Every hop asserts the bytes that crossed the socket. Anchors: §WebSockets (one message
    /// per frame; trust from the envelope, not the socket; wss/TLS), Message Pickup 3.0 §Requirements (the
    /// once-per-websocket return-route latch) and §Live Mode, per
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>
    /// and <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see>.
    /// </summary>
    [TestMethod]
    public async Task LiveModeRoundTripsOverARealLoopbackWebSocketSession()
    {
        const string WalletDid = "did:example:e2e-wallet";
        const string WalletKid = "did:example:e2e-wallet#key-1";
        const string MediatorDid = "did:example:e2e-mediator";
        const string MediatorKid = "did:example:e2e-mediator#key-1";

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> walletKeys = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory walletPublic = walletKeys.PublicKey;
        using PrivateKeyMemory walletPrivate = walletKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> mediatorKeys = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory mediatorPublic = mediatorKeys.PublicKey;
        using PrivateKeyMemory mediatorPrivate = mediatorKeys.PrivateKey;

        try
        {
            await using DidCommDuplexMediatorHost mediatorHost = await DidCommDuplexMediatorHost.StartAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual("wss", mediatorHost.Endpoint.Scheme, "§WebSockets: wss:// with TLS.");

            await using DidCommDuplexWalletConnection walletConnection =
                await DidCommDuplexWalletConnection.ConnectAsync(mediatorHost.Endpoint, mediatorHost.Certificate, TestContext.CancellationToken).ConfigureAwait(false);

            //§WebSockets' wss guidance, proven by something only a REAL TLS handshake produces: the certificate validation
            //callback actually ran, and it saw the harness's own certificate byte-for-byte.
            Assert.IsTrue(walletConnection.DidInvokeCertificatePinningCallback, "A genuine TLS handshake invokes the certificate validation callback.");
            Assert.IsTrue(walletConnection.DidMatchPinnedCertificate, "The presented certificate MUST be the mediator's own.");

            long mediatorMessageCount = 3;
            var mediatorSentFrames = new List<byte[]>();
            var liveDeliveredSignal = new TaskCompletionSource<(DidCommMessage Message, byte[] RawFrame)>(TaskCreationOptions.RunContinuationsAsynchronously);

            DidCommSocketSession mediatorSession = null!;

            //This handler's assertions run on the pump's OWN background task (RunMediatorPumpAsync), not the
            //test thread: a failure here would fault that task rather than surface as a clean assertion
            //failure at an await on the test thread. Left as-is rather than restructured to collect-then-
            //assert: the decrypt-and-branch-and-reply flow below is too tightly coupled (each branch's reply
            //depends on the immediately preceding decode) to defer without fragmenting it far more than the
            //value justifies. TestContext.CancellationToken still bounds every exchange this delegate's
            //replies unblock, so a fault here fails loud via that cancellation rather than hanging forever.
            DidCommSessionInboundDelegate mediatorUnsolicited = async (frame, cancellationToken) =>
            {
                byte[] copy = frame.ToArray();

                using DidCommEncryptedMessage encrypted = DidCommEncryptedMessage.Create(copy, BufferTags.Json, Pool);
                DidCommEncryptedUnpackResult unpacked = await encrypted.UnpackAnoncryptAsync(
                    MediatorKid, mediatorPrivate, NestedSignerResolver, UnpackContext, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
                    TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: cancellationToken).ConfigureAwait(false);
                Assert.IsTrue(unpacked.IsUnpacked, "The mediator MUST decrypt every inbound wallet request.");
                DidCommMessage request = unpacked.Message!;

                if(request.IsReturnRouteAll())
                {
                    mediatorSession.MarkReturnRouteEstablished();
                }

                DidCommMessage? statusReply = null;
                if(request.IsStatusRequest())
                {
                    statusReply = MessagePickupExtensions.CreateStatus(
                        "status-reply-1", new MessagePickupStatus { MessageCount = mediatorMessageCount, LiveDelivery = mediatorSession.IsLiveDeliveryEnabled },
                        inResponseTo: request, from: MediatorDid);
                }
                else if(request.IsLiveDeliveryChange())
                {
                    Assert.IsTrue(request.TryReadLiveDeliveryChange(out bool desired));
                    mediatorSession.SetLiveDelivery(desired);
                    statusReply = MessagePickupExtensions.CreateStatus(
                        "status-reply-2", new MessagePickupStatus { MessageCount = mediatorMessageCount, LiveDelivery = desired },
                        inResponseTo: request, from: MediatorDid);
                }
                else if(request.IsMessagesReceived())
                {
                    Assert.IsTrue(request.TryReadMessagesReceivedIds(out IReadOnlyList<string>? ids));
                    mediatorMessageCount = Math.Max(0, mediatorMessageCount - ids!.Count);
                    statusReply = MessagePickupExtensions.CreateStatus(
                        "status-reply-3", new MessagePickupStatus { MessageCount = mediatorMessageCount, LiveDelivery = mediatorSession.IsLiveDeliveryEnabled },
                        inResponseTo: request, from: MediatorDid);
                }

                if(statusReply is not null)
                {
                    using DidCommEncryptedMessage packedReply = await PackAnoncryptAsync(statusReply, WalletKid, walletPublic, cancellationToken).ConfigureAwait(false);
                    byte[] replyBytes = packedReply.AsReadOnlySpan().ToArray();
                    mediatorSentFrames.Add(replyBytes);
                    await mediatorSession.SendAsync(replyBytes, DidCommEncryptedMessage.MediaType, statusReply, cancellationToken).ConfigureAwait(false);
                }
            };

            mediatorSession = new DidCommSocketSession(mediatorHost.CreateSendDelegate(), new DidCommSocketSessionOptions(), mediatorUnsolicited, Pool, TimeProvider);

            //Unlike mediatorUnsolicited above, this handler's two checks are cheap to defer to the test
            //thread: rather than asserting here (which would fault this handler's pump task instead of
            //surfacing at the test's own await), a failure completes liveDeliveredSignal with an exception,
            //so it throws at the "await liveDeliveredSignal.Task" below as a clean, direct failure.
            DidCommSessionInboundDelegate walletUnsolicited = async (frame, cancellationToken) =>
            {
                byte[] copy = frame.ToArray();
                DidCommMessageClass classification = DidCommInbound.Classify(null, copy, TestSetup.Base64UrlDecoder, Pool);
                if(classification != DidCommMessageClass.Anoncrypt)
                {
                    liveDeliveredSignal.TrySetException(new InvalidOperationException(
                        $"The live-delivered push MUST classify via the content-type-absent envelope-shape path, but classified {classification}."));

                    return;
                }

                using DidCommEncryptedMessage encrypted = DidCommEncryptedMessage.Create(copy, BufferTags.Json, Pool);
                DidCommEncryptedUnpackResult unpacked = await encrypted.UnpackAnoncryptAsync(
                    WalletKid, walletPrivate, NestedSignerResolver, UnpackContext, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
                    TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: cancellationToken).ConfigureAwait(false);
                if(!unpacked.IsUnpacked)
                {
                    liveDeliveredSignal.TrySetException(new InvalidOperationException("The wallet MUST decrypt the live-delivered push with project crypto."));

                    return;
                }

                liveDeliveredSignal.TrySetResult((unpacked.Message!, copy));
            };

            var walletSession = new DidCommSocketSession(walletConnection.CreateSendDelegate(), new DidCommSocketSessionOptions(), walletUnsolicited, Pool, TimeProvider);

            var mediatorObservedFrameTypes = new List<WebSocketMessageType>();
            var walletObservedFrameTypes = new List<WebSocketMessageType>();

            using var pumpCts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
            Task mediatorPump = RunMediatorPumpAsync(mediatorHost, mediatorSession, mediatorObservedFrameTypes, pumpCts.Token);
            Task walletPump = RunWalletPumpAsync(walletConnection, walletSession, WalletKid, walletPrivate, walletObservedFrameTypes, pumpCts.Token);

            try
            {
                //1) status-request -> status, correlated over the socket.
                DidCommMessage statusRequest = MessagePickupExtensions.CreateStatusRequest("status-request-e2e-1", from: WalletDid);
                using DidCommEncryptedMessage packedStatusRequest = await PackAnoncryptAsync(statusRequest, MediatorKid, mediatorPublic, TestContext.CancellationToken).ConfigureAwait(false);
                using DidCommExchangeResult statusResult = await walletSession.ExchangeAsync(packedStatusRequest.AsReadOnlySpan().ToArray(), statusRequest, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(statusResult.IsAccepted, $"The status-request MUST be accepted. Error: {statusResult.Error}.");
                Assert.IsTrue(statusResult.HasReply);
                Assert.IsTrue(statusResult.ReplyBody.AsReadOnlySpan().SequenceEqual(mediatorSentFrames[^1]), "The exact bytes the mediator sent MUST be the bytes the exchange resolves with.");
                Assert.IsTrue(walletSession.IsReturnRouteEstablished, "Once per established websocket: latches on the wallet's first all-bearing send.");

                DidCommMessageClass statusClass = DidCommInbound.Classify(null, statusResult.ReplyBody.AsReadOnlySpan(), TestSetup.Base64UrlDecoder, Pool);
                Assert.AreEqual(DidCommMessageClass.Anoncrypt, statusClass);
                using DidCommEncryptedMessage receivedStatus = DidCommEncryptedMessage.Create(statusResult.ReplyBody.AsReadOnlySpan(), BufferTags.Json, Pool);
                DidCommEncryptedUnpackResult statusUnpacked = await receivedStatus.UnpackAnoncryptAsync(
                    WalletKid, walletPrivate, NestedSignerResolver, UnpackContext, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
                    TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(statusUnpacked.IsUnpacked);
                Assert.IsTrue(statusUnpacked.Message!.TryReadStatus(out MessagePickupStatus? status1));
                Assert.AreEqual(3L, status1!.MessageCount);

                //The mediator marks its own latch BEFORE it ever sends the reply the exchange above just
                //awaited, so by the time that reply has correlated back, the mark is already visible — no
                //extra synchronization needed.
                Assert.IsTrue(mediatorSession.IsReturnRouteEstablished, "Once per established websocket: latches on the mediator's receipt of the first all-bearing message.");

                //2) live-delivery-change(true) -> status, correlated.
                DidCommMessage liveChangeOn = MessagePickupExtensions.CreateLiveDeliveryChange("live-change-e2e-1", liveDelivery: true, from: WalletDid);
                using DidCommEncryptedMessage packedLiveChangeOn = await PackAnoncryptAsync(liveChangeOn, MediatorKid, mediatorPublic, TestContext.CancellationToken).ConfigureAwait(false);
                using DidCommExchangeResult liveChangeResult = await walletSession.ExchangeAsync(packedLiveChangeOn.AsReadOnlySpan().ToArray(), liveChangeOn, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(liveChangeResult.IsAccepted);
                Assert.IsTrue(liveChangeResult.ReplyBody.AsReadOnlySpan().SequenceEqual(mediatorSentFrames[^1]));
                using DidCommEncryptedMessage receivedLiveStatus = DidCommEncryptedMessage.Create(liveChangeResult.ReplyBody.AsReadOnlySpan(), BufferTags.Json, Pool);
                DidCommEncryptedUnpackResult liveStatusUnpacked = await receivedLiveStatus.UnpackAnoncryptAsync(
                    WalletKid, walletPrivate, NestedSignerResolver, UnpackContext, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
                    TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(liveStatusUnpacked.IsUnpacked);
                Assert.IsTrue(liveStatusUnpacked.Message!.TryReadStatus(out MessagePickupStatus? liveStatus));
                Assert.IsTrue(liveStatus!.LiveDelivery);
                walletSession.SetLiveDelivery(liveStatus.LiveDelivery!.Value);
                Assert.IsTrue(mediatorSession.IsLiveDeliveryEnabled);
                Assert.IsTrue(walletSession.IsLiveDeliveryEnabled);

                //3) The mediator pushes a live-delivered message — uncorrelated to anything the wallet has
                //outstanding — which arrives via the wallet's unsolicited delegate.
                DidCommMessage livePush = new()
                {
                    Id = "live-push-e2e-1",
                    Type = "https://example.com/protocols/lets_do_lunch/1.0/proposal",
                    From = MediatorDid,
                    To = [WalletDid],
                    Body = new Dictionary<string, object> { ["messagespecificattribute"] = "urgent delivery" }
                };
                using DidCommEncryptedMessage packedLivePush = await PackAnoncryptAsync(livePush, WalletKid, walletPublic, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] livePushBytes = packedLivePush.AsReadOnlySpan().ToArray();
                DidCommTransmitResult pushSend = await mediatorSession.SendAsync(livePushBytes, DidCommEncryptedMessage.MediaType, livePush, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(pushSend.IsAccepted);

                (DidCommMessage liveDelivered, byte[] liveDeliveredRawFrame) = await liveDeliveredSignal.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual("live-push-e2e-1", liveDelivered.Id);
                Assert.IsTrue(liveDelivered.Body!.TryGetValue("messagespecificattribute", out object? attribute));
                Assert.AreEqual("urgent delivery", attribute as string);
                Assert.IsTrue(liveDeliveredRawFrame.AsSpan().SequenceEqual(livePushBytes), "The exact bytes the mediator pushed MUST be the bytes that arrived at the wallet's unsolicited delegate.");

                //4) wallet acks with messages-received -> an updated status, correlated.
                DidCommMessage ack = MessagePickupExtensions.CreateMessagesReceived("messages-received-e2e-1", [liveDelivered.Id!], from: WalletDid);
                using DidCommEncryptedMessage packedAck = await PackAnoncryptAsync(ack, MediatorKid, mediatorPublic, TestContext.CancellationToken).ConfigureAwait(false);
                using DidCommExchangeResult ackResult = await walletSession.ExchangeAsync(packedAck.AsReadOnlySpan().ToArray(), ack, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(ackResult.IsAccepted);
                Assert.IsTrue(ackResult.ReplyBody.AsReadOnlySpan().SequenceEqual(mediatorSentFrames[^1]));
                using DidCommEncryptedMessage receivedFinalStatus = DidCommEncryptedMessage.Create(ackResult.ReplyBody.AsReadOnlySpan(), BufferTags.Json, Pool);
                DidCommEncryptedUnpackResult finalStatusUnpacked = await receivedFinalStatus.UnpackAnoncryptAsync(
                    WalletKid, walletPrivate, NestedSignerResolver, UnpackContext, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
                    TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(finalStatusUnpacked.IsUnpacked);
                Assert.IsTrue(finalStatusUnpacked.Message!.TryReadStatus(out MessagePickupStatus? finalStatus));
                Assert.AreEqual(2L, finalStatus!.MessageCount, "The acknowledged live-pushed message MUST be reflected in the mediator's next reported status.");

                //§Transport Requirements/§WebSockets: DidCommSessionSendDelegate always SENDS as one complete text frame — pinned
                //here on the real wire in BOTH directions, not merely documented. Asserted on the TEST thread
                //against the pumps' collected observations rather than inside the pump tasks themselves.
                Assert.IsNotEmpty(mediatorObservedFrameTypes, "The mediator's pump MUST have received at least one frame from the wallet.");
                Assert.IsTrue(mediatorObservedFrameTypes.TrueForAll(type => type == WebSocketMessageType.Text), "Every frame the mediator received arrived as Text — the seam's own send convention, pinned on the real wire.");
                Assert.IsNotEmpty(walletObservedFrameTypes, "The wallet's pump MUST have received at least one frame from the mediator.");
                Assert.IsTrue(walletObservedFrameTypes.TrueForAll(type => type == WebSocketMessageType.Text), "Every frame the wallet received arrived as Text — the seam's own send convention, pinned on the real wire.");
            }
            finally
            {
                //The pumps MUST stop before the sessions/connections they read through are disposed —
                //cancelling first and awaiting their completion keeps ReceiveFrameAsync from racing teardown.
                await pumpCts.CancelAsync().ConfigureAwait(false);
                await Task.WhenAll(mediatorPump, walletPump).ConfigureAwait(false);
                await walletSession.DisposeAsync().ConfigureAwait(false);
                await mediatorSession.DisposeAsync().ConfigureAwait(false);
            }
        }
        finally
        {
            walletPrivate.Dispose();
            mediatorPrivate.Dispose();
        }
    }
}
