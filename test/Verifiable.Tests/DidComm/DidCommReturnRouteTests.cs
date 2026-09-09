using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Resolvers;
using Verifiable.DidComm;
using Verifiable.DidComm.ReturnRoute;
using Verifiable.DidComm.Routing;
using Verifiable.Foundation;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Tests for the DIDComm Messaging Return-Route and Queue Transport extension
/// (<see cref="DidCommReturnRouteExtensions"/>): the <c>return_route</c>/<c>return_route_thread</c> root-level
/// headers, their default/resolution semantics, the producer-side closed-set and companion validation, the
/// receiver-side fail-safe for an unsatisfiable <c>thread</c> directive, the pack/unpack round trip and the
/// converter's non-string-token posture, the extension's forward-envelope scope exclusion, and that the Queue
/// Transport URI is observable but never treated as a dispatchable delivery target.
/// </summary>
[TestClass]
internal sealed class DidCommReturnRouteTests
{
    /// <summary>The test context, for cancellation and diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;

    private static BaseMemoryPool Pool { get; } = BaseMemoryPool.Shared;
    private static ExchangeContext Context { get; } = new();

    private const string DidPrefix = "did:example";
    private const string Recipient = "did:example:recipient";
    private const string MessageType = "https://example.com/protocols/lets_do_lunch/1.0/proposal";


    private static DidCommMessage Message(string id = "msg-1") => new() { Id = id, Type = MessageType };


    private static DidCommMessage RoundTrip(DidCommMessage message)
    {
        using DidCommPlaintextMessage packed = message.PackPlaintext(DidCommMessageJson.Serializer, Pool);

        return packed.UnpackPlaintext(DidCommMessageJson.Parser);
    }


    private static string PackToJson(DidCommMessage message)
    {
        using DidCommPlaintextMessage packed = message.PackPlaintext(DidCommMessageJson.Serializer, Pool);

        return Encoding.UTF8.GetString(packed.AsReadOnlySpan());
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">Return-Route and Queue Transport Extension §Return Route Header</see>:
    /// "none: Default. No messages should be returned over this connection. If return_route is omitted, this
    /// is the default value."
    /// </summary>
    [TestMethod]
    public void NoneIsTheDefaultWhenHeaderIsOmitted()
    {
        DidCommMessage message = Message();

        Assert.IsNull(message.ReturnRoute, "No return_route was set.");
        Assert.AreEqual(WellKnownReturnRouteNames.None, message.ResolveReturnRoute());
        Assert.IsFalse(message.IsReturnRouteAll());
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#message-headers">DIDComm Messaging v2.1 §Message Headers</see>:
    /// software that does not understand a header MUST ignore it and MUST NOT fail because of its inclusion —
    /// applied to <c>return_route</c> by resolving any value other than the well-known ones to
    /// <see cref="WellKnownReturnRouteNames.None"/> rather than throwing.
    /// </summary>
    [TestMethod]
    public void UnrecognizedValueResolvesToNoneWithoutThrowing()
    {
        DidCommMessage message = Message();
        message.ReturnRoute = "some-future-directive-nobody-here-understands";

        string resolved = message.ResolveReturnRoute();

        Assert.AreEqual(WellKnownReturnRouteNames.None, resolved, "An unrecognized directive MUST resolve to 'none', never throw.");
        Assert.IsFalse(message.IsReturnRouteAll());
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">Return-Route and Queue Transport Extension §Return Route Header</see>:
    /// "thread: Send all messages matching the DID and thread specified in the return_route_thread attribute"
    /// — without that attribute the directive cannot be honored. <see cref="DidCommReturnRouteExtensions.WithReturnRoute"/>
    /// itself refuses to mint this combination, but an inbound message is untrusted wire input and can carry
    /// it anyway (a peer that DOES understand return_route but sends it malformed, or a hand-built message);
    /// resolution MUST fail safe to <c>none</c> rather than reporting an unsatisfiable <c>thread</c> — an
    /// unsatisfiable directive must never cause a connection hold.
    /// </summary>
    [TestMethod]
    public void ThreadWithoutCompanionResolvesNoneOnReceipt()
    {
        DidCommMessage noCompanion = Message();
        noCompanion.ReturnRoute = WellKnownReturnRouteNames.Thread;

        Assert.AreEqual(WellKnownReturnRouteNames.None, noCompanion.ResolveReturnRoute(), "thread with no return_route_thread at all MUST resolve to none.");

        DidCommMessage whitespaceCompanion = Message();
        whitespaceCompanion.ReturnRoute = WellKnownReturnRouteNames.Thread;
        whitespaceCompanion.ReturnRouteThread = "   ";

        Assert.AreEqual(WellKnownReturnRouteNames.None, whitespaceCompanion.ResolveReturnRoute(), "thread with an all-whitespace return_route_thread MUST also resolve to none.");
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">Return-Route and Queue Transport Extension §Return Route Header</see>:
    /// the value list is CLOSED — "none: Default. ... all: ... thread: ..." — and the wire is case-sensitive
    /// (§Return Route Header gives the three tokens in lowercase, and no case-folding is described). A
    /// producer MUST NOT mint a directive off that set or with different casing: no conformant peer would
    /// honor it, so <see cref="DidCommReturnRouteExtensions.WithReturnRoute"/> refuses it at the source rather
    /// than shipping it. (Consumer-side tolerance for an unrecognized inbound value is
    /// <see cref="UnrecognizedValueResolvesToNoneWithoutThrowing"/> and
    /// <see cref="UnrecognizedValueSurvivesRoundTripVerbatim"/> — unaffected by this producer-side guard.)
    /// </summary>
    [TestMethod]
    public void OffSetAndCaseVariantDirectivesAreRefused()
    {
        Assert.ThrowsExactly<ArgumentException>(() => Message().WithReturnRoute("All"));
        Assert.ThrowsExactly<ArgumentException>(() => Message().WithReturnRoute("THREAD", "thread-1"));
        Assert.ThrowsExactly<ArgumentException>(() => Message().WithReturnRoute("hold-everything"));
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">Return-Route and Queue Transport Extension §Return Route Header</see>:
    /// an all-whitespace <c>return_route_thread</c> names no real thread, so it is refused exactly like a null
    /// or empty one for a <c>thread</c> directive; conversely a non-<c>thread</c> directive still only refuses
    /// a companion that carries actual (non-whitespace) content — whitespace/empty is tolerated there.
    /// </summary>
    [TestMethod]
    public void WhitespaceCompanionThreadIsRefusedForThread()
    {
        Assert.ThrowsExactly<ArgumentException>(() => Message().WithReturnRoute(WellKnownReturnRouteNames.Thread, "   "));
        Assert.ThrowsExactly<ArgumentException>(() => Message().WithReturnRoute(WellKnownReturnRouteNames.Thread, "\t\n"));
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">Return-Route and Queue Transport Extension §Return Route Header</see>:
    /// "all: Send all messages for this DID over the connection." / "thread: Send all messages matching the
    /// DID and thread specified in the return_route_thread attribute."
    /// </summary>
    [TestMethod]
    public void AllAndThreadResolveToThemselves()
    {
        DidCommMessage all = Message().WithReturnRoute(WellKnownReturnRouteNames.All);
        Assert.AreEqual(WellKnownReturnRouteNames.All, all.ResolveReturnRoute());
        Assert.IsTrue(all.IsReturnRouteAll());

        DidCommMessage thread = Message().WithReturnRoute(WellKnownReturnRouteNames.Thread, "thread-7");
        Assert.AreEqual(WellKnownReturnRouteNames.Thread, thread.ResolveReturnRoute());
        Assert.IsFalse(thread.IsReturnRouteAll(), "'thread' is not 'all'.");
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">Return-Route and Queue Transport Extension §Return Route Header</see>:
    /// "thread: Send all messages matching the DID and thread specified in the return_route_thread
    /// attribute" — a <c>thread</c> directive with no thread to match against cannot be honored, so the
    /// producer seam refuses to mint one.
    /// </summary>
    [TestMethod]
    public void ThreadWithoutCompanionThreadIsRefused()
    {
        Assert.ThrowsExactly<ArgumentException>(() => Message().WithReturnRoute(WellKnownReturnRouteNames.Thread));
        Assert.ThrowsExactly<ArgumentException>(() => Message().WithReturnRoute(WellKnownReturnRouteNames.Thread, ""));
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">Return-Route and Queue Transport Extension §Return Route Header</see>:
    /// a <c>thread</c> directive names the thread it is scoped to via <c>return_route_thread</c>; supplying
    /// one is accepted and lands on the typed member.
    /// </summary>
    [TestMethod]
    public void ThreadWithCompanionThreadIsAccepted()
    {
        DidCommMessage message = Message().WithReturnRoute(WellKnownReturnRouteNames.Thread, "thread-9");

        Assert.AreEqual(WellKnownReturnRouteNames.Thread, message.ReturnRoute);
        Assert.AreEqual("thread-9", message.ReturnRouteThread);
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">Return-Route and Queue Transport Extension §Return Route Header</see>:
    /// <c>return_route_thread</c> only has meaning when the directive is <c>thread</c> — "matching the DID and
    /// thread specified in the return_route_thread attribute" is <c>thread</c>-scoped language, so
    /// <c>none</c>/<c>all</c> carrying a thread value is a producer error.
    /// </summary>
    [TestMethod]
    public void NonThreadValueCarryingCompanionThreadIsRefused()
    {
        Assert.ThrowsExactly<ArgumentException>(() => Message().WithReturnRoute(WellKnownReturnRouteNames.All, "thread-1"));
        Assert.ThrowsExactly<ArgumentException>(() => Message().WithReturnRoute(WellKnownReturnRouteNames.None, "thread-1"));
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">Return-Route and Queue Transport Extension §Return Route Header</see>:
    /// a whitespace-only companion on a non-<c>thread</c> directive is treated as absent — the producer
    /// tolerates it but persists <see langword="null"/>, so the message never carries a
    /// <c>return_route_thread</c> the directive gives no meaning to. Nothing whitespace-shaped reaches the
    /// wire.
    /// </summary>
    [TestMethod]
    public void WhitespaceCompanionOnNonThreadIsTreatedAsAbsent()
    {
        DidCommMessage message = Message().WithReturnRoute(WellKnownReturnRouteNames.All, "   ");

        Assert.IsNull(message.ReturnRouteThread, "A whitespace-only companion on a non-thread directive is absent, never persisted.");
        Assert.IsFalse(PackToJson(message).Contains("return_route_thread", StringComparison.Ordinal), "No return_route_thread member may reach the wire.");
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">Return-Route and Queue Transport Extension §Return Route Header</see>:
    /// a <c>return_route</c> carried only in <see cref="DidCommMessage.AdditionalHeaders"/> (a hand-constructed
    /// message; the read path always consumes the key into the typed member) still reaches the wire — the
    /// writer's duplicate-key guard suppresses a bag entry only when the TYPED member was actually written,
    /// and when both are set the typed member wins with no duplicate JSON member emitted.
    /// </summary>
    [TestMethod]
    public void BagOnlyReturnRouteStillReachesTheWireAndTypedWinsOverBag()
    {
        DidCommMessage bagOnly = Message();
        bagOnly.AdditionalHeaders = new Dictionary<string, object> { [WellKnownReturnRouteNames.ReturnRoute] = WellKnownReturnRouteNames.All };
        string bagOnlyJson = PackToJson(bagOnly);

        Assert.IsTrue(bagOnlyJson.Contains("\"return_route\":\"all\"", StringComparison.Ordinal), "A bag-only return_route must still be written.");

        DidCommMessage both = Message().WithReturnRoute(WellKnownReturnRouteNames.All);
        both.AdditionalHeaders = new Dictionary<string, object> { [WellKnownReturnRouteNames.ReturnRoute] = "thread" };
        string bothJson = PackToJson(both);

        int occurrenceCount = bothJson.Split("\"return_route\"", StringSplitOptions.None).Length - 1;
        Assert.AreEqual(1, occurrenceCount, "Exactly one return_route member may be emitted when the typed member shadows a bag entry.");
        Assert.IsTrue(bothJson.Contains("\"return_route\":\"all\"", StringComparison.Ordinal), "The typed member's value wins over the bag entry.");
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">Return-Route and Queue Transport Extension</see>
    /// (design: <c>return_route</c> is a root-level plaintext message member, a sibling of <c>id</c>/<c>type</c>/
    /// <c>body</c> — not a JWE header, not an envelope member): the header round-trips through pack/unpack
    /// verbatim, together with its <c>return_route_thread</c> companion.
    /// </summary>
    [TestMethod]
    public void HeaderRoundTripsAtRootLevel()
    {
        DidCommMessage message = Message().WithReturnRoute(WellKnownReturnRouteNames.Thread, "thread-42");

        string json = PackToJson(message);
        Assert.Contains("\"return_route\":\"thread\"", json, "return_route MUST serialize as a top-level sibling of body.");
        Assert.Contains("\"return_route_thread\":\"thread-42\"", json, "return_route_thread MUST serialize as a top-level sibling of body.");

        DidCommMessage roundTripped = RoundTrip(message);
        Assert.AreEqual("thread", roundTripped.ReturnRoute, "return_route MUST land on the typed member.");
        Assert.AreEqual("thread-42", roundTripped.ReturnRouteThread, "return_route_thread MUST land on the typed member.");

        //Recognized headers must not also leak into the extension-header bag (asserted unconditionally so the
        //check cannot be silently skipped when the bag happens to be null).
        IDictionary<string, object>? extras = roundTripped.AdditionalHeaders;
        Assert.IsTrue(
            extras is null || (!extras.ContainsKey(WellKnownReturnRouteNames.ReturnRoute) && !extras.ContainsKey(WellKnownReturnRouteNames.ReturnRouteThread)),
            "Recognized return_route/return_route_thread headers MUST NOT fall into AdditionalHeaders.");
    }


    /// <summary>
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#message-headers">DIDComm Messaging v2.1 §Message Headers</see>:
    /// software that does not understand a header MUST ignore it and MUST NOT fail — proven here at the wire
    /// level: an unrecognized <c>return_route</c> value survives a plaintext pack/unpack round trip verbatim
    /// rather than being coerced or dropped. The value is set directly on <see cref="DidCommMessage.ReturnRoute"/>
    /// (bypassing <see cref="DidCommReturnRouteExtensions.WithReturnRoute"/>, whose closed-set producer guard
    /// refuses to mint it) to simulate wire input from a peer this library does not control.
    /// </summary>
    [TestMethod]
    public void UnrecognizedValueSurvivesRoundTripVerbatim()
    {
        DidCommMessage message = Message();
        message.ReturnRoute = "a-value-this-library-has-never-heard-of";

        DidCommMessage roundTripped = RoundTrip(message);

        Assert.AreEqual("a-value-this-library-has-never-heard-of", roundTripped.ReturnRoute, "An unrecognized value MUST survive the round trip verbatim.");
        Assert.AreEqual(WellKnownReturnRouteNames.None, roundTripped.ResolveReturnRoute(), "Resolution still treats an unrecognized value as 'none'.");
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">Return-Route and Queue Transport Extension §Return Route Header</see>
    /// (design: <c>return_route</c>/<c>return_route_thread</c> are string-valued headers): a non-string JSON
    /// token — a number here — is rejected by <see cref="Verifiable.Json.Converters.DidCommMessageConverter"/>
    /// with its own documented <see cref="JsonException"/>, matching this converter's posture for every other
    /// wire-level type violation (e.g. a fractional <c>created_time</c>) rather than letting
    /// <see cref="System.Text.Json.JsonElement.GetString"/>'s bare <see cref="InvalidOperationException"/>
    /// escape.
    /// </summary>
    [TestMethod]
    public void NonStringReturnRouteTokenThrowsJsonException()
    {
        const string ReturnRouteIsNumber = """
            {
               "id":"msg-1",
               "type":"https://example.com/protocols/lets_do_lunch/1.0/proposal",
               "return_route":42
            }
            """;

        const string ReturnRouteThreadIsObject = """
            {
               "id":"msg-1",
               "type":"https://example.com/protocols/lets_do_lunch/1.0/proposal",
               "return_route":"thread",
               "return_route_thread":{}
            }
            """;

        Assert.ThrowsExactly<JsonException>(() =>
            DidCommPlaintextExtensions.UnpackPlaintext(Encoding.UTF8.GetBytes(ReturnRouteIsNumber), DidCommMessageJson.Parser));

        Assert.ThrowsExactly<JsonException>(() =>
            DidCommPlaintextExtensions.UnpackPlaintext(Encoding.UTF8.GetBytes(ReturnRouteThreadIsObject), DidCommMessageJson.Parser));
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">Return-Route and Queue Transport Extension §Scope</see>:
    /// "This extension is not valid when routing keys are in use." This holds STRUCTURALLY rather than by any
    /// runtime check: <see cref="RoutingForwardExtensions.CreateForward(string, string, DidCommEncryptedMessage, Verifiable.Cryptography.EncodeDelegate, string?, long?)"/>
    /// takes the forwarded message as a <see cref="DidCommEncryptedMessage"/> — opaque packed bytes, never a
    /// parsed <see cref="DidCommMessage"/> — so there is no code path by which an inner message's headers,
    /// including <c>return_route</c>, could be read back out and copied onto the outer envelope. This test
    /// pins that structure at the wire level rather than proving a dynamic invariant that the type signature
    /// already forecloses: it fails the day <c>CreateForward</c> is changed to accept (and propagate) a
    /// structured inner message instead of opaque bytes.
    /// </summary>
    [TestMethod]
    public void ReturnRouteNeverAppearsOnForwardEnvelope()
    {
        DidCommMessage inner = new DidCommMessage { Id = "inner-1", Type = MessageType }
            .WithReturnRoute(WellKnownReturnRouteNames.All);

        //CreateForward never inspects the wrapped payload — it treats it as an opaque blob — so packing the
        //inner plaintext (rather than actually encrypting it) still proves the invariant: whatever the
        //wrapped bytes are, the forward ENVELOPE's own headers never carry return_route.
        using DidCommPlaintextMessage innerPacked = inner.PackPlaintext(DidCommMessageJson.Serializer, Pool);
        using DidCommEncryptedMessage opaqueForwardedBlob = DidCommEncryptedMessage.Create(innerPacked.AsReadOnlySpan(), BufferTags.Json, Pool);

        DidCommMessage forward = RoutingForwardExtensions.CreateForward(
            "did:example:nexthop", "fwd-1", opaqueForwardedBlob, TestSetup.Base64UrlEncoder);

        //Assert on the OUTER envelope's actual serialized wire bytes, not the in-memory property — the
        //property is trivially null by construction (CreateForward never assigns it), so checking it alone
        //cannot fail even if a future change wired the header through some OTHER path onto the same object.
        //Checking for the bare member name (not a specific value) also catches propagation of ANY return_route
        //value, not just the "all" this test happens to set on the inner message.
        string forwardJson = PackToJson(forward);
        Assert.DoesNotContain("\"return_route\"", forwardJson, "The outer forward envelope's serialized JSON MUST carry no return_route member, at any value.");
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">Return-Route and Queue Transport Extension §Queue Transport</see>:
    /// "The Queue Transport is a special form of transport where messages are held at the sender for pickup
    /// by the recipient" — a hold-at-sender marker, not a destination. A DID document declaring ONLY the
    /// Queue Transport contributes no dispatchable target, but the declaration MUST still surface
    /// (<see cref="DidCommDeliveryTargetResolution.DeclaresQueueTransport"/>) — dropping it silently would
    /// erase a signal a sender is REQUIRED to act on.
    /// </summary>
    [TestMethod]
    public async Task QueueTransportUriIsObservableButNotDispatchable()
    {
        DidCommDeliveryTargetResolution resolution = await ResolveForQueueDocumentAsync(WellKnownReturnRouteNames.QueueTransportUri).ConfigureAwait(false);

        Assert.IsEmpty(resolution.Targets, "The Queue Transport is a hold-at-sender marker, not a dispatchable target.");
        Assert.IsTrue(resolution.DeclaresQueueTransport, "The declaration MUST still surface, even though it contributes no target.");
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">Return-Route and Queue Transport Extension §Queue Transport</see>:
    /// a Queue Transport declaration alongside a real endpoint MUST NOT displace it — the real endpoint is the
    /// sole dispatchable target, at index 0 regardless of document order, while the declaration is still
    /// reported through the flag.
    /// </summary>
    [TestMethod]
    public async Task QueueTransportDeclarationDoesNotDisplaceDispatchableTarget()
    {
        var queueService = new Service
        {
            Type = WellKnownDidCommServiceNames.DidCommMessagingServiceType,
            ServiceEndpoint = WellKnownReturnRouteNames.QueueTransportUri
        };
        var realService = new Service
        {
            Type = WellKnownDidCommServiceNames.DidCommMessagingServiceType,
            ServiceEndpoint = "https://real.example/didcomm"
        };
        var document = new DidDocument { Id = new GenericDidMethod(Recipient), Service = [queueService, realService] };

        DidCommDeliveryTargetResolution resolution = await ResolveAsync(document).ConfigureAwait(false);

        Assert.HasCount(1, resolution.Targets, "The Queue Transport declaration contributes no target of its own.");
        Assert.AreEqual("https://real.example/didcomm", resolution.Targets[0].TransportUri);
        Assert.IsTrue(resolution.DeclaresQueueTransport, "The Queue Transport declaration is still reported, alongside the dispatchable target.");
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">Return-Route and Queue Transport Extension §Queue Transport</see>:
    /// a document that declares no Queue Transport endpoint MUST report
    /// <see cref="DidCommDeliveryTargetResolution.DeclaresQueueTransport"/> as <see langword="false"/> — the
    /// flag is a positive signal raised only when a <c>didcomm/v2</c> endpoint actually names the Queue
    /// Transport URI, never a default assumed in its absence.
    /// </summary>
    [TestMethod]
    public async Task NoQueueTransportDeclarationLeavesFlagFalse()
    {
        DidCommDeliveryTargetResolution resolution = await ResolveForQueueDocumentAsync("https://real.example/didcomm").ConfigureAwait(false);

        Assert.HasCount(1, resolution.Targets);
        Assert.IsFalse(resolution.DeclaresQueueTransport, "No endpoint declared the Queue Transport URI.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.1">RFC 3986 §3.1</see>: "Although schemes
    /// are case-insensitive, the canonical form is lowercase and documents that specify schemes must do so
    /// with lowercase letters." A Queue Transport URI differing only in scheme case is still recognized.
    /// </summary>
    [TestMethod]
    public async Task QueueTransportSchemeCaseVariantIsRecognized()
    {
        DidCommDeliveryTargetResolution resolution = await ResolveForQueueDocumentAsync("DIDComm:transport/queue").ConfigureAwait(false);

        Assert.IsEmpty(resolution.Targets);
        Assert.IsTrue(resolution.DeclaresQueueTransport, "A scheme-case variant of the Queue Transport URI MUST still be recognized (RFC 3986 §3.1: the scheme is case-insensitive).");
    }


    /// <summary>
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">Return-Route and Queue Transport Extension §Queue Transport</see>:
    /// the Queue Transport URI is <c>didcomm:transport/queue</c> — an opaque URI whose remainder (everything
    /// after the scheme) has no defined case-folding (RFC 3986 §3.1 case-folds only the scheme). A case
    /// variant of that remainder is a DIFFERENT opaque string and MUST NOT be silently equated with the real
    /// Queue Transport URI; it is treated as an ordinary (if unusual) dispatchable target instead.
    /// </summary>
    [TestMethod]
    public async Task QueueTransportPathCaseVariantIsNotRecognized()
    {
        const string PathCaseVariant = "didcomm:TRANSPORT/QUEUE";

        DidCommDeliveryTargetResolution resolution = await ResolveForQueueDocumentAsync(PathCaseVariant).ConfigureAwait(false);

        Assert.HasCount(1, resolution.Targets, "A path-case variant MUST NOT be silently equated with the Queue Transport URI, so it is an ordinary dispatchable target.");
        Assert.AreEqual(PathCaseVariant, resolution.Targets[0].TransportUri);
        Assert.IsFalse(resolution.DeclaresQueueTransport);
    }


    //Resolves delivery targets for a DID document whose sole DIDCommMessaging service endpoint is uri.
    private async Task<DidCommDeliveryTargetResolution> ResolveForQueueDocumentAsync(string uri)
    {
        var service = new Service
        {
            Type = WellKnownDidCommServiceNames.DidCommMessagingServiceType,
            ServiceEndpoint = uri
        };
        var document = new DidDocument { Id = new GenericDidMethod(Recipient), Service = [service] };

        return await ResolveAsync(document).ConfigureAwait(false);
    }


    private async Task<DidCommDeliveryTargetResolution> ResolveAsync(DidDocument document)
    {
        DidResolver resolver = new(DidMethodSelectors.FromResolvers(
            (DidPrefix, (did, _, _, _) => ValueTask.FromResult(
                string.Equals(did, Recipient, StringComparison.Ordinal)
                    ? DidResolutionResult.Success(document, new DidDocumentMetadata())
                    : DidResolutionResult.Failure(DidResolutionErrors.NotFound)))));

        return await DidCommServiceEndpointExtensions
            .ResolveDeliveryTargetsAsync(Recipient, resolver, Context, TestContext.CancellationToken).ConfigureAwait(false);
    }
}
