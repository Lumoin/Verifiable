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
using Verifiable.DidComm.CoordinateMediation;
using Verifiable.DidComm.DiscoverFeatures;
using Verifiable.DidComm.ProblemReports;
using Verifiable.DidComm.ReturnRoute;
using Verifiable.DidComm.Routing;
using Verifiable.DidComm.Transport;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Tests for DIDComm Coordinate Mediation 2.0 — the protocol folder (<see cref="CoordinateMediationExtensions"/>,
/// <see cref="WellKnownCoordinateMediationNames"/>, and the body records <see cref="KeylistUpdateEntry"/>,
/// <see cref="KeylistUpdateResult"/>, <see cref="KeylistKey"/>, <see cref="KeylistPaginate"/>,
/// <see cref="KeylistPagination"/>), per
/// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>.
/// </summary>
/// <remarks>
/// Composition with EXISTING surfaces is proven directly rather than duplicated: the recipient-discovery
/// walkthrough composes with <see cref="DiscoverFeaturesExtensions"/>, the mediator role composes with
/// <see cref="RoutingForwardExtensions"/>, and out-of-protocol errors compose with
/// <see cref="DidCommProblemReportExtensions"/>. The exchange seam itself (<see cref="DidCommExchangeDelegate"/>,
/// <see cref="DidCommHttpTransport.CreateExchangeDelegate"/>) is Message Pickup 3.0's contribution and is
/// exercised here only by the one real-wire capstone
/// (<see cref="MediateRequestExchangeRoundTripsAnAnoncryptMediateGrantOverARealSocket"/>) — its own battery of
/// unit tests lives in <c>DidCommMessagePickupTests</c>.
/// </remarks>
[TestClass]
internal sealed class DidCommCoordinateMediationTests
{
    /// <summary>The test framework's per-test context, including the cooperative cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    private static readonly BaseMemoryPool Pool = BaseMemoryPool.Shared;


    private static DidCommMessage MediateRequest(string id = "mr-1", string? from = null) =>
        CoordinateMediationExtensions.CreateMediateRequest(id, from);


    private static DidCommMessage ParseJson(string json) =>
        DidCommMessageJson.Parser(Encoding.UTF8.GetBytes(json));


    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes((Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);


    private static DidResolver NestedSignerResolver { get; } = new(DidMethodSelectors.FromResolvers(
        ("did:example", (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Failure(DidResolutionErrors.NotFound)))));


    private static ExchangeContext UnpackContext { get; } = new();


    //A fresh context whose policy permits loopback, mirroring DidCommMessagePickupTests.NewLoopbackExchangeContext.
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
    //other DIDComm protocol uses — Coordinate Mediation introduces no separate crypto path of its own.
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


    //A single-hop HttpClient transport that reads back the response body/Content-Type — mirrors
    //DidCommMessagePickupTests.BuildExchangeTransport, the exchange seam's HTTPS binding.
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
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// pins the PIURI, all 13 <c>body</c> member names, and the 6 closed <c>action</c>/<c>result</c> values
    /// against their wire literals directly (the 7 MTURIs are pinned by their per-section exact tests), plus
    /// the CM 3.0 negatives: 2.0's <c>keylist-*</c> family MUST NOT read as 3.0's <c>recipient-*</c> rename.
    /// </summary>
    [TestMethod]
    public void WellKnownConstantsMatchTheirWireLiteralsAndRejectCM3Vocabulary()
    {
        Assert.AreEqual("https://didcomm.org/coordinate-mediation/2.0", WellKnownCoordinateMediationNames.CoordinateMediationProtocol);
        Assert.AreEqual("routing_did", WellKnownCoordinateMediationNames.RoutingDid);
        Assert.AreEqual("updates", WellKnownCoordinateMediationNames.Updates);
        Assert.AreEqual("updated", WellKnownCoordinateMediationNames.Updated);
        Assert.AreEqual("recipient_did", WellKnownCoordinateMediationNames.RecipientDid);
        Assert.AreEqual("action", WellKnownCoordinateMediationNames.Action);
        Assert.AreEqual("result", WellKnownCoordinateMediationNames.Result);
        Assert.AreEqual("keys", WellKnownCoordinateMediationNames.Keys);
        Assert.AreEqual("paginate", WellKnownCoordinateMediationNames.Paginate);
        Assert.AreEqual("pagination", WellKnownCoordinateMediationNames.Pagination);
        Assert.AreEqual("limit", WellKnownCoordinateMediationNames.Limit);
        Assert.AreEqual("offset", WellKnownCoordinateMediationNames.Offset);
        Assert.AreEqual("count", WellKnownCoordinateMediationNames.Count);
        Assert.AreEqual("remaining", WellKnownCoordinateMediationNames.Remaining);

        Assert.AreEqual("add", WellKnownCoordinateMediationNames.ActionAdd);
        Assert.AreEqual("remove", WellKnownCoordinateMediationNames.ActionRemove);
        Assert.AreEqual("client_error", WellKnownCoordinateMediationNames.ResultClientError);
        Assert.AreEqual("server_error", WellKnownCoordinateMediationNames.ResultServerError);
        Assert.AreEqual("no_change", WellKnownCoordinateMediationNames.ResultNoChange);
        Assert.AreEqual("success", WellKnownCoordinateMediationNames.ResultSuccess);

        //Coordinate Mediation 3.0 renamed the keylist-* vocabulary to recipient-*; this library is 2.0 and
        //every constant here MUST carry the keylist- spelling, never the 3.0 rename.
        foreach(string mturi in new[]
        {
            WellKnownCoordinateMediationNames.KeylistUpdateType,
            WellKnownCoordinateMediationNames.KeylistUpdateResponseType,
            WellKnownCoordinateMediationNames.KeylistQueryType,
            WellKnownCoordinateMediationNames.KeylistType
        })
        {
            Assert.Contains("/keylist", mturi, "Every 2.0 keylist-family MTURI MUST use the keylist- prefix.");
            Assert.DoesNotContain("recipient-", mturi, "3.0's recipient- rename MUST NOT appear on a 2.0 constant.");
        }

        //Version-independent form: a 3.0 comparand would never equal a 2.0 constant regardless of the
        //keylist/recipient rename, so the negative could never fail — using the SAME 2.0 version segment as
        //KeylistType means a mutation collapsing "keylist" to "recipient" actually fails this assertion.
        Assert.AreNotEqual("https://didcomm.org/coordinate-mediation/2.0/recipient", WellKnownCoordinateMediationNames.KeylistType, "The bare 'recipient' rename (no hyphen) is CM 3.0's keylist equivalent.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Motivation: "The Recipient must know which endpoint and routing key(s) to share, and the Mediator
    /// needs to know which keys should be routed via this relationship." Proven by the two message shapes that
    /// carry each half: a mediate-grant carries the endpoint/routing_did the recipient learns, and a
    /// keylist-update is how the mediator learns which keys route via this relationship — actually EXCHANGING
    /// these over a connection is composed via the exchange seam's own capstone; the mediator's routing
    /// decision itself is out of this library's scope.
    /// </summary>
    [TestMethod]
    public void MotivationInformationExchangeIsProvenByGrantAndKeylistUpdate()
    {
        DidCommMessage request = MediateRequest("mr-1");
        DidCommMessage grant = request.CreateMediateGrant("g-1", "did:example:mediator-routing");
        Assert.IsTrue(grant.TryReadMediateGrantRoutingDid(out string? routingDid));
        Assert.AreEqual("did:example:mediator-routing", routingDid, "The recipient learns which endpoint/routing key to use.");

        DidCommMessage keylistUpdate = CoordinateMediationExtensions.CreateKeylistUpdate(
            "ku-1", [new KeylistUpdateEntry { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionAdd }]);
        Assert.IsTrue(keylistUpdate.TryReadKeylistUpdates(out IReadOnlyList<KeylistUpdateEntry>? entries));
        Assert.AreEqual("did:example:alice-key-1", entries![0].RecipientDid, "The mediator learns which key should be routed via this relationship.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Roles: "mediator: The agent that will be receiving forward messages on behalf of the recipient." and
    /// "recipient: The agent for whom the forward message payload is intended." Composition with the EXISTING
    /// <see cref="RoutingForwardExtensions"/>: a <c>recipient_did</c> registered through a Coordinate Mediation
    /// <c>keylist-update</c> is exactly the DID the Routing Protocol 2.0's <c>forward</c> message addresses as
    /// its <c>next</c> — the two roles are the two ends of the SAME forward.
    /// </summary>
    [TestMethod]
    public void MediatorReceivesForwardOnBehalfOfTheRecipientItIsIntendedFor()
    {
        const string RegisteredRecipientDid = "did:example:cm-forward-recipient";

        DidCommMessage keylistUpdate = CoordinateMediationExtensions.CreateKeylistUpdate(
            "ku-1", [new KeylistUpdateEntry { RecipientDid = RegisteredRecipientDid, Action = WellKnownCoordinateMediationNames.ActionAdd }]);
        Assert.IsTrue(keylistUpdate.TryReadKeylistUpdates(out IReadOnlyList<KeylistUpdateEntry>? entries));

        using DidCommEncryptedMessage innerPlaceholder = DidCommEncryptedMessage.Create("{\"ciphertext\":\"x\"}"u8, BufferTags.Json, Pool);
        DidCommMessage forward = RoutingForwardExtensions.CreateForward(entries![0].RecipientDid, "fwd-1", innerPlaceholder, TestSetup.Base64UrlEncoder);

        Assert.IsTrue(forward.IsForward(), "The mediator builds/receives exactly this forward — 'receiving forward messages on behalf of the recipient'.");
        Assert.AreEqual(RegisteredRecipientDid, forward.GetForwardNext(), "The forward's next IS the recipient the payload is intended for — the same DID the recipient registered via keylist-update.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Requirements: "The return_route extension must be supported by both agents (recipient and mediator)."
    /// </summary>
    [TestMethod]
    public async Task ReturnRouteExtensionMustBeSupportedByBothAgents()
    {
        DidCommMessage request = MediateRequest("mr-1");
        Assert.IsTrue(request.IsReturnRouteAll(), "The recipient side of the extension is supported: every CM request carries return_route: all.");

        //The mediator side: ExchangeAsync — the seam that realizes mediator-side return-route support —
        //refuses to hand a request lacking return_route: all to the exchange delegate at all. The real-wire
        //capstone's Assert.IsTrue(exchangeResult.HasReply, ...) is only reachable because THIS guard passed
        //first — an antecedent that failed it would never reach the mediator's reply channel.
        DidCommMessage requestWithoutReturnRoute = new() { Id = "mr-no-return-route", Type = WellKnownCoordinateMediationNames.MediateRequestType };
        using DidCommEncryptedMessage placeholder = DidCommEncryptedMessage.Create("{\"ciphertext\":\"x\"}"u8, BufferTags.Json, Pool);
        DidCommExchangeDelegate neverInvoked = (_, _, _, _, _) =>
            throw new InvalidOperationException("The exchange delegate MUST NOT be invoked when the return_route guard rejects the request.");

        await Assert.ThrowsExactlyAsync<ArgumentException>(
            async () => await placeholder.ExchangeAsync(
                requestWithoutReturnRoute, new Uri("https://mediator.example/didcomm"), new ExchangeContext(), neverInvoked, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Requirements: "In order to have this synchronous behavior the recipient should specify return_route
    /// header to all."
    /// </summary>
    [TestMethod]
    public void RecipientShouldSpecifyReturnRouteAllForSynchronousReplies()
    {
        DidCommMessage request = MediateRequest("mr-1");

        Assert.AreEqual(WellKnownReturnRouteNames.All, request.ResolveReturnRoute());
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Requirements: "This header must be set each time the communication channel is established: once per
    /// established websocket, and every message for an HTTP POST."
    /// </summary>
    [TestMethod]
    public void ReturnRouteHeaderIsSetOnEveryIndividuallyBuiltRequestMessage()
    {
        DidCommMessage first = MediateRequest("mr-1");
        DidCommMessage second = CoordinateMediationExtensions.CreateKeylistQuery("kq-1");

        Assert.IsTrue(first.IsReturnRouteAll());
        Assert.IsTrue(second.IsReturnRouteAll(), "The header is set on EVERY individually-built request message; the once-per-websocket half is transport/session bookkeeping this library holds no state for.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Connectivity: "This protocol consists of three different message requests from the recipient that
    /// should be replied by the mediator: 1. Mediate Request -&gt; Mediate Grant or Mediate Deny 2. Keylist
    /// Update -&gt; Keylist Update Response 3. Keylist Query -&gt; Keylist."
    /// </summary>
    [TestMethod]
    public void TheThreeRequestKindsEachHaveAnExpressibleMediatorReply()
    {
        DidCommMessage mediateRequest = MediateRequest("mr-1");
        DidCommMessage grant = mediateRequest.CreateMediateGrant("g-1", "did:example:mediator-routing");
        Assert.AreEqual(mediateRequest.Id, grant.ThreadId);

        DidCommMessage deny = mediateRequest.CreateMediateDeny("d-1");
        Assert.AreEqual(mediateRequest.Id, deny.ThreadId);

        DidCommMessage keylistUpdate = CoordinateMediationExtensions.CreateKeylistUpdate(
            "ku-1", [new KeylistUpdateEntry { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionAdd }]);
        DidCommMessage keylistUpdateResponse = keylistUpdate.CreateKeylistUpdateResponse(
            "kur-1", [new KeylistUpdateResult { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionAdd, Result = WellKnownCoordinateMediationNames.ResultSuccess }]);
        Assert.AreEqual(keylistUpdate.Id, keylistUpdateResponse.ThreadId);

        DidCommMessage keylistQuery = CoordinateMediationExtensions.CreateKeylistQuery("kq-1");
        DidCommMessage keylist = keylistQuery.CreateKeylist("kl-1", [new KeylistKey { RecipientDid = "did:example:alice-key-1" }]);
        Assert.AreEqual(keylistQuery.Id, keylist.ThreadId);
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §States: "This protocol follows the request-response message exchange pattern, and only requerires the
    /// simple state of waiting for a response or to produce a response." [the spec source spells "requires" as
    /// "requerires"; quoted verbatim].
    /// </summary>
    [TestMethod]
    public void RequestResponsePatternCorrelatesViaThread()
    {
        DidCommMessage keylistUpdate = CoordinateMediationExtensions.CreateKeylistUpdate(
            "ku-1", [new KeylistUpdateEntry { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionAdd }]);
        DidCommMessage response = keylistUpdate.CreateKeylistUpdateResponse(
            "kur-1", [new KeylistUpdateResult { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionAdd, Result = WellKnownCoordinateMediationNames.ResultSuccess }]);

        Assert.AreEqual(keylistUpdate.EffectiveThreadId, response.EffectiveThreadId, "The 'waiting for a response' state is realized entirely by thread correlation between the reply and the request.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Basic Walkthrough: "A recipient may discover an agent capable of routing using the Discover Features
    /// Protocol 2.0." Composition with the EXISTING <see cref="DiscoverFeaturesExtensions"/>: the recipient
    /// queries for the Coordinate Mediation PIURI, the candidate mediator discloses support, and only then
    /// does the recipient send a mediate-request.
    /// </summary>
    [TestMethod]
    public void RecipientMayDiscoverARoutingCapableMediatorViaDiscoverFeatures()
    {
        var query = new DiscoverFeaturesQuery
        {
            Queries = [new FeatureQuery { FeatureType = WellKnownDiscoverFeaturesNames.Protocol, Match = WellKnownCoordinateMediationNames.CoordinateMediationProtocol }]
        };
        DidCommMessage queryMessage = query.CreateDiscoverFeaturesQuery("df-q-1", from: "did:example:cm-recipient");
        Assert.IsTrue(queryMessage.IsDiscoverFeaturesQuery());

        IReadOnlyList<FeatureDisclosure> catalog =
            [new FeatureDisclosure { FeatureType = WellKnownDiscoverFeaturesNames.Protocol, Id = WellKnownCoordinateMediationNames.CoordinateMediationProtocol, Roles = ["mediator"] }];
        DiscoverFeaturesDisclose disclose = query.MatchDisclosures(catalog);

        Assert.HasCount(1, disclose.Disclosures);
        Assert.AreEqual(WellKnownCoordinateMediationNames.CoordinateMediationProtocol, disclose.Disclosures[0].Id, "The candidate mediator discloses support for the exact Coordinate Mediation PIURI.");

        //Only once the protocol is confirmed supported does the walkthrough have the recipient initiate.
        DidCommMessage mediateRequest = CoordinateMediationExtensions.CreateMediateRequest("mr-1");
        Assert.IsTrue(mediateRequest.IsMediateRequest());
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Basic Walkthrough: "If protocol is supported with the mediator, a recipient may send a mediate-request
    /// to initiate a routing relationship."
    /// </summary>
    [TestMethod]
    public void RecipientMaySendMediateRequestToInitiateARoutingRelationship()
    {
        DidCommMessage request = MediateRequest("mr-1");

        Assert.IsTrue(request.IsMediateRequest());
        Assert.IsTrue(request.IsReturnRouteAll());
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Basic Walkthrough: "If the mediator is willing to route messages, it will respond with a mediate-grant
    /// message, otherwise with a mediate-deny message." The DECISION of which reply to send is the mediator's
    /// own seam — this library keeps both replies independently buildable from the SAME antecedent request.
    /// </summary>
    [TestMethod]
    public void MediatorRespondsGrantOrDenyBasedOnWillingnessToRoute()
    {
        DidCommMessage request = MediateRequest("mr-1");

        DidCommMessage grant = request.CreateMediateGrant("g-1", "did:example:mediator-routing");
        Assert.IsTrue(grant.IsMediateGrant());
        Assert.AreEqual(request.Id, grant.ThreadId);

        DidCommMessage deny = request.CreateMediateDeny("d-1");
        Assert.IsTrue(deny.IsMediateDeny());
        Assert.AreEqual(request.Id, deny.ThreadId);
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Basic Walkthrough: "The recipient will share the routing information in the grant message with other
    /// contacts." Affordance: actually distributing routing_did to other contacts is application behavior out
    /// of this library's scope; what the library provides is the routing_did recovered plain and ready to
    /// hand off.
    /// </summary>
    [TestMethod]
    public void RecipientCanShareTheGrantsRoutingInformationWithOtherContacts()
    {
        DidCommMessage request = MediateRequest("mr-1");
        DidCommMessage grant = request.CreateMediateGrant("g-1", "did:example:mediator-routing");

        Assert.IsTrue(grant.TryReadMediateGrantRoutingDid(out string? routingDid));
        Assert.AreEqual("did:example:mediator-routing", routingDid, "The recovered value is a plain string the recipient's application is free to pass to any other contact.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Basic Walkthrough: "When a new key is used by the recipient, it must be registered with the mediator
    /// to enable route identification. This is done with a keylist-update message."
    /// </summary>
    [TestMethod]
    public void NewKeyUsedByRecipientMustBeRegisteredViaKeylistUpdate()
    {
        DidCommMessage update = CoordinateMediationExtensions.CreateKeylistUpdate(
            "ku-1", [new KeylistUpdateEntry { RecipientDid = "did:example:alice-newkey-1", Action = WellKnownCoordinateMediationNames.ActionAdd }]);

        Assert.IsTrue(update.IsKeylistUpdate());
        Assert.IsTrue(update.TryReadKeylistUpdates(out IReadOnlyList<KeylistUpdateEntry>? entries));
        Assert.AreEqual(WellKnownCoordinateMediationNames.ActionAdd, entries![0].Action);
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Basic Walkthrough: "The keylist-update and keylist-query methods are used over time to identify and
    /// remove keys that are no longer in use by the recipient." Proven across the full add-&gt;query-&gt;remove
    /// lifecycle for the same key.
    /// </summary>
    [TestMethod]
    public void KeylistUpdateAndQueryManageKeyLifecycleOverTime()
    {
        const string Key = "did:example:alice-lifecycle-key";

        DidCommMessage add = CoordinateMediationExtensions.CreateKeylistUpdate(
            "ku-add", [new KeylistUpdateEntry { RecipientDid = Key, Action = WellKnownCoordinateMediationNames.ActionAdd }]);
        Assert.IsTrue(add.TryReadKeylistUpdates(out IReadOnlyList<KeylistUpdateEntry>? added));
        Assert.AreEqual(WellKnownCoordinateMediationNames.ActionAdd, added![0].Action);

        DidCommMessage query = CoordinateMediationExtensions.CreateKeylistQuery("kq-1");
        DidCommMessage keylist = query.CreateKeylist("kl-1", [new KeylistKey { RecipientDid = Key }]);
        Assert.IsTrue(keylist.TryReadKeylistKeys(out IReadOnlyList<KeylistKey>? keys, out _));
        Assert.AreEqual(Key, keys![0].RecipientDid, "The queried keylist confirms the key added earlier is registered.");

        DidCommMessage remove = CoordinateMediationExtensions.CreateKeylistUpdate(
            "ku-remove", [new KeylistUpdateEntry { RecipientDid = Key, Action = WellKnownCoordinateMediationNames.ActionRemove }]);
        Assert.IsTrue(remove.TryReadKeylistUpdates(out IReadOnlyList<KeylistUpdateEntry>? removed));
        Assert.AreEqual(WellKnownCoordinateMediationNames.ActionRemove, removed![0].Action, "The SAME key surface (keylist-update) identifies removal too — 'used over time to identify and remove'.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Design By Contract: "No protocol specific errors exist. Any errors related to headers or other core
    /// features are documented in the appropriate places." Coordinate Mediation mints no problem-code constant
    /// of its own (compare Message Pickup's <c>e.m.live-mode-not-supported</c>); an application-level error
    /// composes with the EXISTING <see cref="DidCommProblemReportExtensions"/> report-problem/2.0 surface using
    /// an application-chosen code.
    /// </summary>
    [TestMethod]
    public void NoProtocolSpecificErrorsExistErrorsComposeWithReportProblem()
    {
        DidCommMessage request = MediateRequest("mr-1");
        ProblemReport applicationError = new()
        {
            Code = ProblemCode.Parse("e.m.mediation-currently-unavailable"),
            ParentThreadId = request.EffectiveThreadId!
        };
        DidCommMessage problemMessage = applicationError.CreateProblemReport("pr-1");

        Assert.IsTrue(problemMessage.IsProblemReport());
        Assert.AreEqual(request.EffectiveThreadId, problemMessage.ParentThreadId, "Coordinate Mediation contributes NO code of its own — the boundary is the request's thread, carried by the generic surface.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Security: "This protocol expects messages to be encrypted during transmission, and repudiable."
    /// </summary>
    [TestMethod]
    public async Task MediateRequestFlowsThroughTheStandardEncryptedRepudiablePipeline()
    {
        const string ClaimedSender = "did:example:cm-recipient";
        DidCommMessage mediateRequest = CoordinateMediationExtensions.CreateMediateRequest("mr-repudiable-1", from: ClaimedSender);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> mediatorKeys = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory mediatorPublic = mediatorKeys.PublicKey;
        PrivateKeyMemory mediatorPrivate = mediatorKeys.PrivateKey;
        try
        {
            using DidCommEncryptedMessage packed = await PackAnoncryptAsync(
                mediateRequest, "did:example:cm-mediator#key-1", mediatorPublic, TestContext.CancellationToken).ConfigureAwait(false);

            DidCommEncryptedUnpackResult unpacked = await packed.UnpackAnoncryptAsync(
                "did:example:cm-mediator#key-1", mediatorPrivate, NestedSignerResolver, UnpackContext, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
                TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(unpacked.IsUnpacked, "Coordinate Mediation carries no transport of its own — the standard anoncrypt pack/unpack pipeline is what makes a request 'encrypted during transmission'.");
            Assert.AreEqual(WellKnownCoordinateMediationNames.MediateRequestType, unpacked.Message!.Type);

            Assert.AreEqual(ClaimedSender, unpacked.Message.From, "The plaintext from claim still travels with the message — anoncrypt hides nothing about the header, it just proves nothing about it.");
            Assert.IsFalse(unpacked.IsSenderAuthenticated, "Anoncrypt performs no sender key agreement — the unpack pipeline's own verdict MUST report the sender as unauthenticated; that verdict is what makes the message repudiable.");
        }
        finally
        {
            mediatorPrivate.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Mediate Request: "Message Type URI: https://didcomm.org/coordinate-mediation/2.0/mediate-request"
    /// </summary>
    [TestMethod]
    public void MediateRequestMturiIsExact()
    {
        Assert.AreEqual("https://didcomm.org/coordinate-mediation/2.0/mediate-request", WellKnownCoordinateMediationNames.MediateRequestType);
        Assert.IsTrue(MediateRequest("mr-1").IsMediateRequest());
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Mediate Request: "This message serves as a request from the recipient to the mediator, asking for the
    /// permission (and routing information) to publish the endpoint as a mediator."
    /// </summary>
    [TestMethod]
    public void MediateRequestAsksPermissionForMediationAndRoutingInformation()
    {
        DidCommMessage request = CoordinateMediationExtensions.CreateMediateRequest("mr-1", from: "did:example:cm-recipient");

        Assert.IsTrue(request.IsMediateRequest());
        Assert.AreEqual("did:example:cm-recipient", request.From);

        //The permission asked for is answerable with exactly the routing information the request asked for.
        DidCommMessage grant = request.CreateMediateGrant("g-1", "did:example:mediator-routing");
        Assert.IsTrue(grant.TryReadMediateGrantRoutingDid(out string? routingDid));
        Assert.AreEqual("did:example:mediator-routing", routingDid);
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Mediate Request JSON sample (L75-81): the sample carries no <c>body</c> member at all and sets
    /// <c>return_route: all</c> — bodyless is the wire shape, not an empty <c>{}</c>.
    /// </summary>
    [TestMethod]
    public void MediateRequestCarriesNoBodyAndSetsReturnRouteAll()
    {
        DidCommMessage request = MediateRequest("mr-1");

        Assert.IsNull(request.Body, "The mediate-request sample carries no body member at all.");
        Assert.IsTrue(request.IsReturnRouteAll());
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Mediate Deny: "Message Type URI: https://didcomm.org/coordinate-mediation/2.0/mediate-deny"
    /// </summary>
    [TestMethod]
    public void MediateDenyMturiIsExact()
    {
        Assert.AreEqual("https://didcomm.org/coordinate-mediation/2.0/mediate-deny", WellKnownCoordinateMediationNames.MediateDenyType);
        Assert.IsTrue(MediateRequest("mr-1").CreateMediateDeny("d-1").IsMediateDeny());
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Mediate Deny: "This message serves as notification of the mediator denying the recipient's request for
    /// mediation."
    /// </summary>
    [TestMethod]
    public void MediateDenyIsNotificationOfDenial()
    {
        DidCommMessage request = MediateRequest("mr-1");
        DidCommMessage deny = request.CreateMediateDeny("d-1");

        Assert.IsTrue(deny.IsMediateDeny());
        Assert.AreEqual(request.Id, deny.ThreadId);

        //A mediate-deny answers THIS mediate-request specifically, so the antecedent type is validated exactly
        //as CreateMediateGrant does.
        DidCommMessage notARequest = CoordinateMediationExtensions.CreateMediateRequest("mr-2").CreateMediateGrant("g-2", "did:example:mediator-x");
        Assert.ThrowsExactly<ArgumentException>(() => notARequest.CreateMediateDeny("d-2"));
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Mediate Deny JSON sample (L88-93): TRAP — the sample carries a trailing comma after the <c>type</c>
    /// member, which is not valid JSON; the corrected fixture below removes it. The wire shape is
    /// <c>{id, type}</c> — no body.
    /// </summary>
    [TestMethod]
    public void MediateDenyCarriesNoBodyTrailingCommaTrapFixture()
    {
        const string CorrectedSample = """
            {
                "id": "123456780",
                "type": "https://didcomm.org/coordinate-mediation/2.0/mediate-deny"
            }
            """;

        DidCommMessage parsed = ParseJson(CorrectedSample);

        Assert.IsTrue(parsed.IsMediateDeny());
        Assert.IsNull(parsed.Body);

        DidCommMessage deny = MediateRequest("mr-1").CreateMediateDeny("d-1");
        Assert.IsNull(deny.Body, "The mediate-deny sample carries no body member at all — the builder half of the same claim.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Mediate Grant: "Message Type URI: https://didcomm.org/coordinate-mediation/2.0/mediate-grant"
    /// </summary>
    [TestMethod]
    public void MediateGrantMturiIsExact()
    {
        Assert.AreEqual("https://didcomm.org/coordinate-mediation/2.0/mediate-grant", WellKnownCoordinateMediationNames.MediateGrantType);
        Assert.IsTrue(MediateRequest("mr-1").CreateMediateGrant("g-1", "did:example:mediator-routing").IsMediateGrant());
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Mediate Grant: "A mediate grant message is a signal from the mediator to the recipient that permission
    /// is given to distribute the included information as an inbound route."
    /// </summary>
    [TestMethod]
    public void MediateGrantIsPermissionToDistributeAnInboundRoute()
    {
        DidCommMessage request = MediateRequest("mr-1");
        DidCommMessage grant = request.CreateMediateGrant("g-1", "did:example:mediator-routing");

        Assert.IsTrue(grant.IsMediateGrant());
        Assert.AreEqual(request.Id, grant.ThreadId);

        //A mediate-grant answers THIS mediate-request specifically, so the antecedent type is validated.
        DidCommMessage notARequest = CoordinateMediationExtensions.CreateMediateRequest("mr-2").CreateMediateDeny("d-2");
        Assert.ThrowsExactly<ArgumentException>(() => notARequest.CreateMediateGrant("g-2", "did:example:mediator-x"));
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Mediate Grant: "routing_did: DID of the mediator where forwarded messages should be sent." The builder
    /// REQUIRES it non-whitespace; the reader fails without it — the one member the message exists to carry.
    /// </summary>
    [TestMethod]
    public void RoutingDidIsTheMemberTheMessageExistsToCarry()
    {
        DidCommMessage request = MediateRequest("mr-1");

        Assert.ThrowsExactly<ArgumentException>(() => request.CreateMediateGrant("g-1", ""));
        Assert.ThrowsExactly<ArgumentException>(() => request.CreateMediateGrant("g-1", "   "));

        DidCommMessage grant = request.CreateMediateGrant("g-1", "did:example:mediator-routing");
        Assert.IsTrue(grant.Body!.ContainsKey(WellKnownCoordinateMediationNames.RoutingDid));
        Assert.IsTrue(grant.TryReadMediateGrantRoutingDid(out string? routingDid));
        Assert.AreEqual("did:example:mediator-routing", routingDid);

        DidCommMessage missingRoutingDid = new() { Id = "g-2", Type = WellKnownCoordinateMediationNames.MediateGrantType, Body = new Dictionary<string, object>() };
        Assert.IsFalse(missingRoutingDid.TryReadMediateGrantRoutingDid(out string? missing));
        Assert.IsNull(missing, "routingDid MUST be null when the member is absent.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Mediate Grant: "The recipient may use this DID as an enpoint as explained in [Using a DID as an
    /// endpoint] section of the specification." [sic — the spec source spells it "enpoint"; quoted verbatim],
    /// linking to
    /// <see href="https://identity.foundation/didcomm-messaging/spec/#using-a-did-as-an-endpoint">DIDComm Messaging §Using a DID as an endpoint</see>.
    /// </summary>
    [TestMethod]
    public void RecipientMayUseRoutingDidAsAnEndpoint()
    {
        DidCommMessage request = MediateRequest("mr-1");
        DidCommMessage grant = request.CreateMediateGrant("g-1", "did:peer:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6");

        Assert.IsTrue(grant.TryReadMediateGrantRoutingDid(out string? routingDid));
        Assert.IsTrue(routingDid!.StartsWith("did:", StringComparison.Ordinal), "routing_did is recoverable as a plain DID string, usable as an endpoint per the linked core-spec section.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Mediate Grant NOTE: "After receiving a mediate-grant message the recipient should update his
    /// recipient_did with a keylist-update message and add DIDs. In order for the mediator to start accepting
    /// Forward Message for those DIDs."
    /// </summary>
    [TestMethod]
    public void AfterGrantRecipientShouldKeylistUpdateAddItsDids()
    {
        DidCommMessage request = MediateRequest("mr-1");
        DidCommMessage grant = request.CreateMediateGrant("g-1", "did:example:mediator-routing");
        Assert.IsTrue(grant.TryReadMediateGrantRoutingDid(out string? routingDid));
        Assert.IsNotNull(routingDid, "The grant precedes the follow-up keylist-update in this walkthrough sequence.");

        DidCommMessage keylistUpdate = CoordinateMediationExtensions.CreateKeylistUpdate(
            "ku-1", [new KeylistUpdateEntry { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionAdd }]);
        Assert.IsTrue(keylistUpdate.TryReadKeylistUpdates(out IReadOnlyList<KeylistUpdateEntry>? entries));
        Assert.AreEqual(WellKnownCoordinateMediationNames.ActionAdd, entries![0].Action, "The follow-up keylist-update ADDS the recipient's DIDs so the mediator starts accepting forward messages for them.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist Update: "Message Type URI: https://didcomm.org/coordinate-mediation/2.0/keylist-update"
    /// </summary>
    [TestMethod]
    public void KeylistUpdateMturiIsExact()
    {
        Assert.AreEqual("https://didcomm.org/coordinate-mediation/2.0/keylist-update", WellKnownCoordinateMediationNames.KeylistUpdateType);
        Assert.IsTrue(CoordinateMediationExtensions.CreateKeylistUpdate(
            "ku-1", [new KeylistUpdateEntry { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionAdd }]).IsKeylistUpdate());
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist Update: "Used to notify the mediator of keys in use by the recipient."
    /// </summary>
    [TestMethod]
    public void KeylistUpdateNotifiesTheMediatorOfKeysInUse()
    {
        DidCommMessage update = CoordinateMediationExtensions.CreateKeylistUpdate(
            "ku-1", [new KeylistUpdateEntry { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionAdd }]);

        Assert.IsTrue(update.IsKeylistUpdate());

        //The mediator is notified of exactly the key in use, read back through the SAME surface it would use.
        Assert.IsTrue(update.TryReadKeylistUpdates(out IReadOnlyList<KeylistUpdateEntry>? notified));
        Assert.AreEqual("did:example:alice-key-1", notified![0].RecipientDid);
        Assert.AreEqual(WellKnownCoordinateMediationNames.ActionAdd, notified[0].Action);
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist Update JSON sample (L125-131): <c>body.updates</c> is a list of <c>{recipient_did, action}</c>
    /// entries; the producer requires at least one.
    /// </summary>
    [TestMethod]
    public void KeylistUpdateBodyUpdatesIsAListOfEntries()
    {
        Assert.ThrowsExactly<ArgumentException>(() => CoordinateMediationExtensions.CreateKeylistUpdate("ku-1", []));

        DidCommMessage update = CoordinateMediationExtensions.CreateKeylistUpdate("ku-2",
        [
            new KeylistUpdateEntry { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionAdd },
            new KeylistUpdateEntry { RecipientDid = "did:example:alice-key-2", Action = WellKnownCoordinateMediationNames.ActionRemove }
        ]);
        Assert.IsTrue(update.TryReadKeylistUpdates(out IReadOnlyList<KeylistUpdateEntry>? entries));
        Assert.HasCount(2, entries!);
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist Update: "recipient_did: DID subject of the update."
    /// </summary>
    [TestMethod]
    public void RecipientDidIsTheDidSubjectOfTheUpdate()
    {
        DidCommMessage update = CoordinateMediationExtensions.CreateKeylistUpdate(
            "ku-1", [new KeylistUpdateEntry { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionAdd }]);
        Assert.IsTrue(update.TryReadKeylistUpdates(out IReadOnlyList<KeylistUpdateEntry>? entries));
        Assert.AreEqual("did:example:alice-key-1", entries![0].RecipientDid);

        Assert.ThrowsExactly<ArgumentException>(() => CoordinateMediationExtensions.CreateKeylistUpdate(
            "ku-2", [new KeylistUpdateEntry { RecipientDid = "   ", Action = WellKnownCoordinateMediationNames.ActionAdd }]));
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist Update: "action: one of add or remove." CLOSED for the producer; the reader returns an inbound
    /// value VERBATIM rather than rejecting it — an unrecognized value from another implementation is not this
    /// library's malformation to reject.
    /// </summary>
    [TestMethod]
    public void ActionIsClosedForProducersAndVerbatimForReaders()
    {
        Assert.ThrowsExactly<ArgumentException>(() => CoordinateMediationExtensions.CreateKeylistUpdate(
            "ku-1", [new KeylistUpdateEntry { RecipientDid = "did:example:alice-key-1", Action = "not-add-or-remove" }]));

        //§Keylist Update (L138) spells the closed set lowercase and exact ("add" / "remove"); the comparison
        //is Ordinal, so a case or whitespace variant is refused exactly like any other non-member value.
        foreach(string variant in new[] { "Add", "REMOVE", " add", "add " })
        {
            Assert.ThrowsExactly<ArgumentException>(() => CoordinateMediationExtensions.CreateKeylistUpdate(
                "ku-variant", [new KeylistUpdateEntry { RecipientDid = "did:example:alice-key-1", Action = variant }]));
        }

        DidCommMessage handCrafted = new()
        {
            Id = "ku-2",
            Type = WellKnownCoordinateMediationNames.KeylistUpdateType,
            Body = new Dictionary<string, object>
            {
                [WellKnownCoordinateMediationNames.Updates] = new List<object>
                {
                    new Dictionary<string, object>
                    {
                        [WellKnownCoordinateMediationNames.RecipientDid] = "did:example:bob-key-1",
                        [WellKnownCoordinateMediationNames.Action] = "an-unrecognized-value-from-a-future-version"
                    }
                }
            }
        };

        Assert.IsTrue(handCrafted.TryReadKeylistUpdates(out IReadOnlyList<KeylistUpdateEntry>? entries), "An unrecognized inbound action value MUST NOT fail the read — the reader is verbatim, not validating.");
        Assert.AreEqual("an-unrecognized-value-from-a-future-version", entries![0].Action);
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist Update JSON sample: <c>"return_route": "all"</c>.
    /// </summary>
    [TestMethod]
    public void KeylistUpdateSampleSetsReturnRouteAll()
    {
        DidCommMessage update = CoordinateMediationExtensions.CreateKeylistUpdate(
            "ku-1", [new KeylistUpdateEntry { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionAdd }]);

        Assert.IsTrue(update.IsReturnRouteAll());
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist Update JSON sample (L127): TRAP — the sample wraps its <c>recipient_did</c> value in
    /// backticks rather than quotes, which is not valid JSON; the corrected fixture below quotes it.
    /// </summary>
    [TestMethod]
    public void KeylistUpdateBacktickDidTrapFixture()
    {
        const string CorrectedSample = """
            {
                "id": "123456780",
                "type": "https://didcomm.org/coordinate-mediation/2.0/keylist-update",
                "body": {
                    "updates":  [
                        {
                            "recipient_did": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
                            "action": "add"
                        }
                    ]
                },
                "return_route": "all"
            }
            """;

        DidCommMessage parsed = ParseJson(CorrectedSample);

        Assert.IsTrue(parsed.IsKeylistUpdate());
        Assert.IsTrue(parsed.TryReadKeylistUpdates(out IReadOnlyList<KeylistUpdateEntry>? entries));
        Assert.AreEqual("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH", entries![0].RecipientDid);
        Assert.IsTrue(parsed.IsReturnRouteAll());
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist Response: "Message Type URI: https://didcomm.org/coordinate-mediation/2.0/keylist-update-response".
    /// TRAP: the section HEADING reads "Keylist Response" while the wire token is
    /// <c>keylist-update-response</c> — <c>…/2.0/keylist-response</c> MUST NOT dispatch.
    /// </summary>
    [TestMethod]
    public void KeylistUpdateResponseMturiIsExactAndKeylistResponseHeadingDoesNotDispatch()
    {
        Assert.AreEqual("https://didcomm.org/coordinate-mediation/2.0/keylist-update-response", WellKnownCoordinateMediationNames.KeylistUpdateResponseType);

        DidCommMessage genuine = new() { Id = "kur-1", Type = WellKnownCoordinateMediationNames.KeylistUpdateResponseType };
        Assert.IsTrue(genuine.IsKeylistUpdateResponse());

        DidCommMessage headingSpelledType = new() { Id = "kur-2", Type = "https://didcomm.org/coordinate-mediation/2.0/keylist-response" };
        Assert.IsFalse(headingSpelledType.IsKeylistUpdateResponse(), "'keylist-response' is the section HEADING, not the wire token — it MUST NOT dispatch.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist Response: "Confirmation of requested keylist updates."
    /// </summary>
    [TestMethod]
    public void KeylistUpdateResponseIsConfirmationOfRequestedUpdates()
    {
        DidCommMessage update = CoordinateMediationExtensions.CreateKeylistUpdate(
            "ku-1", [new KeylistUpdateEntry { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionAdd }]);
        DidCommMessage response = update.CreateKeylistUpdateResponse(
            "kur-1", [new KeylistUpdateResult { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionAdd, Result = WellKnownCoordinateMediationNames.ResultSuccess }]);

        Assert.IsTrue(response.IsKeylistUpdateResponse());
        Assert.AreEqual(update.Id, response.ThreadId);

        //A keylist-update-response answers THIS keylist-update specifically, so the antecedent type is validated.
        DidCommMessage notAnUpdate = CoordinateMediationExtensions.CreateKeylistQuery("kq-1");
        Assert.ThrowsExactly<ArgumentException>(() => notAnUpdate.CreateKeylistUpdateResponse(
            "kur-2", [new KeylistUpdateResult { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionAdd, Result = WellKnownCoordinateMediationNames.ResultSuccess }]));
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist Response JSON sample (L150-157): TRAP — the sample wraps <c>recipient_did</c> in backticks,
    /// carries <c>//</c> comments after <c>action</c>/<c>result</c>, and is missing a comma between them,
    /// none of which is valid JSON; the corrected fixture below fixes all three.
    /// </summary>
    [TestMethod]
    public void KeylistUpdateResponseBodyUpdatedTrapFixture()
    {
        const string CorrectedSample = """
            {
                "id": "123456780",
                "type": "https://didcomm.org/coordinate-mediation/2.0/keylist-update-response",
                "body": {
                    "updated":  [
                        {
                            "recipient_did": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
                            "action": "add",
                            "result": "success"
                        }
                    ]
                }
            }
            """;

        DidCommMessage parsed = ParseJson(CorrectedSample);

        Assert.IsTrue(parsed.IsKeylistUpdateResponse());
        Assert.IsTrue(parsed.TryReadKeylistUpdateResults(out IReadOnlyList<KeylistUpdateResult>? results));
        Assert.AreEqual("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH", results![0].RecipientDid);
        Assert.AreEqual(WellKnownCoordinateMediationNames.ActionAdd, results[0].Action);
        Assert.AreEqual(WellKnownCoordinateMediationNames.ResultSuccess, results[0].Result);
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist Response: "action: one of add or remove" — the response echoes the update's action.
    /// </summary>
    [TestMethod]
    public void KeylistUpdateResponseActionEchoesAddOrRemove()
    {
        DidCommMessage update = CoordinateMediationExtensions.CreateKeylistUpdate(
            "ku-1", [new KeylistUpdateEntry { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionRemove }]);
        DidCommMessage response = update.CreateKeylistUpdateResponse(
            "kur-1", [new KeylistUpdateResult { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionRemove, Result = WellKnownCoordinateMediationNames.ResultSuccess }]);

        Assert.IsTrue(response.TryReadKeylistUpdateResults(out IReadOnlyList<KeylistUpdateResult>? results));
        Assert.AreEqual(WellKnownCoordinateMediationNames.ActionRemove, results![0].Action);

        Assert.ThrowsExactly<ArgumentException>(() => update.CreateKeylistUpdateResponse(
            "kur-2", [new KeylistUpdateResult { RecipientDid = "did:example:alice-key-1", Action = "neither-add-nor-remove", Result = WellKnownCoordinateMediationNames.ResultSuccess }]));
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist Response: "result: one of client_error, server_error, no_change, success; describes the
    /// resulting state of the keylist update." CLOSED for the producer; the reader returns an inbound value
    /// VERBATIM.
    /// </summary>
    [TestMethod]
    public void KeylistUpdateResponseResultIsClosedForProducersAndVerbatimForReaders()
    {
        DidCommMessage update = CoordinateMediationExtensions.CreateKeylistUpdate(
            "ku-1", [new KeylistUpdateEntry { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionAdd }]);

        Assert.ThrowsExactly<ArgumentException>(() => update.CreateKeylistUpdateResponse(
            "kur-1", [new KeylistUpdateResult { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionAdd, Result = "not-one-of-the-four" }]));

        //§Keylist Response (L164) spells the closed result set lowercase and exact; the comparison is Ordinal.
        foreach(string variant in new[] { "Success", "no_change " })
        {
            Assert.ThrowsExactly<ArgumentException>(() => update.CreateKeylistUpdateResponse(
                $"kur-variant-{variant}", [new KeylistUpdateResult { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionAdd, Result = variant }]));
        }

        foreach(string result in new[]
        {
            WellKnownCoordinateMediationNames.ResultClientError,
            WellKnownCoordinateMediationNames.ResultServerError,
            WellKnownCoordinateMediationNames.ResultNoChange,
            WellKnownCoordinateMediationNames.ResultSuccess
        })
        {
            DidCommMessage response = update.CreateKeylistUpdateResponse(
                $"kur-{result}", [new KeylistUpdateResult { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionAdd, Result = result }]);
            Assert.IsTrue(response.TryReadKeylistUpdateResults(out IReadOnlyList<KeylistUpdateResult>? results));
            Assert.AreEqual(result, results![0].Result);
        }

        DidCommMessage handCrafted = new()
        {
            Id = "kur-x",
            Type = WellKnownCoordinateMediationNames.KeylistUpdateResponseType,
            Body = new Dictionary<string, object>
            {
                [WellKnownCoordinateMediationNames.Updated] = new List<object>
                {
                    new Dictionary<string, object>
                    {
                        [WellKnownCoordinateMediationNames.RecipientDid] = "did:example:bob-key-1",
                        [WellKnownCoordinateMediationNames.Action] = WellKnownCoordinateMediationNames.ActionAdd,
                        [WellKnownCoordinateMediationNames.Result] = "an-unrecognized-future-result"
                    }
                }
            }
        };
        Assert.IsTrue(handCrafted.TryReadKeylistUpdateResults(out IReadOnlyList<KeylistUpdateResult>? verbatim), "An unrecognized inbound result value MUST NOT fail the read.");
        Assert.AreEqual("an-unrecognized-future-result", verbatim![0].Result);
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §States (L41) + DIDComm v2.1 §Threading: the keylist-update-response correlates to its keylist-update.
    /// </summary>
    [TestMethod]
    public void KeylistUpdateResponseCorrelatesToItsKeylistUpdate()
    {
        DidCommMessage update = CoordinateMediationExtensions.CreateKeylistUpdate(
            "ku-77", [new KeylistUpdateEntry { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionAdd }]);
        DidCommMessage response = update.CreateKeylistUpdateResponse(
            "kur-1", [new KeylistUpdateResult { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionAdd, Result = WellKnownCoordinateMediationNames.ResultSuccess }]);

        Assert.AreEqual("ku-77", response.ThreadId);
        Assert.AreEqual("ku-77", response.EffectiveThreadId);
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist Query: "Message Type URI: https://didcomm.org/coordinate-mediation/2.0/keylist-query"
    /// </summary>
    [TestMethod]
    public void KeylistQueryMturiIsExact()
    {
        Assert.AreEqual("https://didcomm.org/coordinate-mediation/2.0/keylist-query", WellKnownCoordinateMediationNames.KeylistQueryType);
        Assert.IsTrue(CoordinateMediationExtensions.CreateKeylistQuery("kq-1").IsKeylistQuery());
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist Query: "Query mediator for a list of keys registered for this connection."
    /// </summary>
    [TestMethod]
    public void KeylistQueryQueriesKeysRegisteredForThisConnection()
    {
        DidCommMessage query = CoordinateMediationExtensions.CreateKeylistQuery("kq-1");
        Assert.IsTrue(query.IsKeylistQuery());

        //"registered for this connection": the connection scope IS the query's own thread — the mediator's
        //answering keylist correlates to THIS query, not to some global list. Which keys are actually
        //registered per connection is the mediator's own registry, out of this library's scope; what the
        //library provides is the correlated pairing and the keys reading back exactly as given.
        DidCommMessage keylist = query.CreateKeylist("kl-1", [new KeylistKey { RecipientDid = "did:example:alice-key-1" }]);
        Assert.AreEqual(query.Id, keylist.ThreadId, "The keylist answers THIS connection's query — thread correlation IS the connection scope.");
        Assert.IsTrue(keylist.TryReadKeylistKeys(out IReadOnlyList<KeylistKey>? keys, out _));
        Assert.AreEqual("did:example:alice-key-1", keys![0].RecipientDid);
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist Query: "paginate: is optional, and if present must include limit and offset." Absence: the
    /// reader returns TRUE with a null paginate.
    /// </summary>
    [TestMethod]
    public void PaginateIsOptionalOnKeylistQuery()
    {
        DidCommMessage withoutPaginate = CoordinateMediationExtensions.CreateKeylistQuery("kq-1");
        Assert.IsNull(withoutPaginate.Body, "No paginate MUST mean no body member at all, not an empty {} object.");
        Assert.IsTrue(withoutPaginate.TryReadKeylistQueryPaginate(out KeylistPaginate? paginate));
        Assert.IsNull(paginate);

        DidCommMessage withPaginate = CoordinateMediationExtensions.CreateKeylistQuery("kq-2", new KeylistPaginate { Limit = 30, Offset = 0 });
        Assert.IsTrue(withPaginate.TryReadKeylistQueryPaginate(out KeylistPaginate? present));
        Assert.IsNotNull(present);
        Assert.AreEqual(30L, present!.Limit);
        Assert.AreEqual(0L, present.Offset);
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist Query: "paginate: is optional, and if present must include limit and offset." The record shape
    /// enforces this on build; the reader fails a paginate object missing either member; numerics read through
    /// the shared <see cref="DidCommBodyNumbers"/> helper — int and long both read, a fractional value fails.
    /// </summary>
    [TestMethod]
    public void PaginateIfPresentMustIncludeLimitAndOffset()
    {
        Assert.ThrowsExactly<ArgumentException>(() => CoordinateMediationExtensions.CreateKeylistQuery("kq-1", new KeylistPaginate { Limit = 0, Offset = 0 }));
        Assert.ThrowsExactly<ArgumentException>(() => CoordinateMediationExtensions.CreateKeylistQuery("kq-2", new KeylistPaginate { Limit = 10, Offset = -1 }));

        DidCommMessage missingOffset = new()
        {
            Id = "kq-3",
            Type = WellKnownCoordinateMediationNames.KeylistQueryType,
            Body = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Paginate] = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Limit] = 30 } }
        };
        Assert.IsFalse(missingOffset.TryReadKeylistQueryPaginate(out KeylistPaginate? partial));
        Assert.IsNull(partial);

        DidCommMessage longForm = new()
        {
            Id = "kq-4",
            Type = WellKnownCoordinateMediationNames.KeylistQueryType,
            Body = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Paginate] = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Limit] = 30L, [WellKnownCoordinateMediationNames.Offset] = 0L } }
        };
        Assert.IsTrue(longForm.TryReadKeylistQueryPaginate(out KeylistPaginate? longRead));
        Assert.AreEqual(30L, longRead!.Limit);

        DidCommMessage fractional = new()
        {
            Id = "kq-5",
            Type = WellKnownCoordinateMediationNames.KeylistQueryType,
            Body = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Paginate] = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Limit] = 30.5m, [WellKnownCoordinateMediationNames.Offset] = 0 } }
        };
        Assert.IsFalse(fractional.TryReadKeylistQueryPaginate(out KeylistPaginate? fractionalRead));
        Assert.IsNull(fractionalRead, "A fractional limit is not integral and MUST fail the read.");

        //Reader/producer range symmetry: CreateKeylistQuery refuses limit <= 0 and offset < 0, so the reader
        //MUST refuse exactly the shapes the producer would never mint.
        DidCommMessage zeroLimit = new()
        {
            Id = "kq-6",
            Type = WellKnownCoordinateMediationNames.KeylistQueryType,
            Body = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Paginate] = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Limit] = 0, [WellKnownCoordinateMediationNames.Offset] = 0 } }
        };
        Assert.IsFalse(zeroLimit.TryReadKeylistQueryPaginate(out KeylistPaginate? zeroLimitRead), "A non-positive limit MUST fail the read.");
        Assert.IsNull(zeroLimitRead);

        DidCommMessage negativeLimit = new()
        {
            Id = "kq-7",
            Type = WellKnownCoordinateMediationNames.KeylistQueryType,
            Body = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Paginate] = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Limit] = -1, [WellKnownCoordinateMediationNames.Offset] = 0 } }
        };
        Assert.IsFalse(negativeLimit.TryReadKeylistQueryPaginate(out KeylistPaginate? negativeLimitRead));
        Assert.IsNull(negativeLimitRead);

        DidCommMessage negativeOffset = new()
        {
            Id = "kq-8",
            Type = WellKnownCoordinateMediationNames.KeylistQueryType,
            Body = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Paginate] = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Limit] = 30, [WellKnownCoordinateMediationNames.Offset] = -1 } }
        };
        Assert.IsFalse(negativeOffset.TryReadKeylistQueryPaginate(out KeylistPaginate? negativeOffsetRead), "A negative offset MUST fail the read.");
        Assert.IsNull(negativeOffsetRead);
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist Query JSON sample (L171-183): parsed from the wire, <c>limit</c>/<c>offset</c> arrive as JSON
    /// numbers the Json leaf narrows to <see cref="int"/> — pinning that this is the wire path actually
    /// exercised, the way <see cref="KeysListIsRequiredAndMayBeEmptyBacktickTrapFixture"/> already does for
    /// <c>count</c>/<c>offset</c>/<c>remaining</c>.
    /// </summary>
    [TestMethod]
    public void KeylistQuerySampleParsesWithIntNarrowedPaginate()
    {
        const string Sample = """
            {
                "id": "123456780",
                "type": "https://didcomm.org/coordinate-mediation/2.0/keylist-query",
                "body": {
                    "paginate": {
                        "limit": 30,
                        "offset": 0
                    }
                },
                "return_route": "all"
            }
            """;

        DidCommMessage parsed = ParseJson(Sample);

        Assert.IsTrue(parsed.IsKeylistQuery());
        Assert.IsTrue(parsed.TryReadKeylistQueryPaginate(out KeylistPaginate? paginate));
        Assert.AreEqual(30L, paginate!.Limit);
        Assert.AreEqual(0L, paginate.Offset);
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist Query JSON sample: <c>"return_route": "all"</c>.
    /// </summary>
    [TestMethod]
    public void KeylistQuerySampleSetsReturnRouteAll()
    {
        DidCommMessage query = CoordinateMediationExtensions.CreateKeylistQuery("kq-1", new KeylistPaginate { Limit = 30, Offset = 0 });

        Assert.IsTrue(query.IsReturnRouteAll());
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist: "Message Type URI: https://didcomm.org/coordinate-mediation/2.0/keylist"
    /// </summary>
    [TestMethod]
    public void KeylistMturiIsExact()
    {
        Assert.AreEqual("https://didcomm.org/coordinate-mediation/2.0/keylist", WellKnownCoordinateMediationNames.KeylistType);

        DidCommMessage query = CoordinateMediationExtensions.CreateKeylistQuery("kq-1");
        Assert.IsTrue(query.CreateKeylist("kl-1", []).IsKeylist());
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist: "Response to key list query, containing retrieved keys."
    /// </summary>
    [TestMethod]
    public void KeylistIsTheResponseToKeylistQueryContainingRetrievedKeys()
    {
        DidCommMessage query = CoordinateMediationExtensions.CreateKeylistQuery("kq-1");
        DidCommMessage keylist = query.CreateKeylist("kl-1", [new KeylistKey { RecipientDid = "did:example:alice-key-1" }]);

        Assert.IsTrue(keylist.IsKeylist());
        Assert.AreEqual(query.Id, keylist.ThreadId);

        DidCommMessage notAQuery = CoordinateMediationExtensions.CreateKeylistUpdate(
            "ku-1", [new KeylistUpdateEntry { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionAdd }]);
        Assert.ThrowsExactly<ArgumentException>(() => notAQuery.CreateKeylist("kl-2", [new KeylistKey { RecipientDid = "did:example:alice-key-1" }]));
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist JSON sample (L198-202): <c>body.keys</c> is a list of <c>{recipient_did}</c> entries — empty
    /// is legal on both produce ("no keys registered" is a legitimate answer) and read. TRAP: the sample wraps
    /// its <c>recipient_did</c> value in backticks rather than quotes, which is not valid JSON; the corrected
    /// fixture below quotes it.
    /// </summary>
    [TestMethod]
    public void KeysListIsRequiredAndMayBeEmptyBacktickTrapFixture()
    {
        DidCommMessage query = CoordinateMediationExtensions.CreateKeylistQuery("kq-1");
        DidCommMessage emptyKeylist = query.CreateKeylist("kl-1", []);
        Assert.IsTrue(emptyKeylist.TryReadKeylistKeys(out IReadOnlyList<KeylistKey>? emptyKeys, out _));
        Assert.IsEmpty(emptyKeys!, "No keys registered is a legitimate answer, both to produce and to read.");

        const string CorrectedSample = """
            {
                "id": "123456780",
                "type": "https://didcomm.org/coordinate-mediation/2.0/keylist",
                "body": {
                    "keys": [
                        {
                            "recipient_did": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
                        }
                    ],
                    "pagination": {
                        "count": 30,
                        "offset": 30,
                        "remaining": 100
                    }
                }
            }
            """;

        DidCommMessage parsed = ParseJson(CorrectedSample);
        Assert.IsTrue(parsed.IsKeylist());
        Assert.IsTrue(parsed.TryReadKeylistKeys(out IReadOnlyList<KeylistKey>? keys, out KeylistPagination? pagination));
        Assert.AreEqual("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH", keys![0].RecipientDid);
        Assert.IsNotNull(pagination);
        Assert.AreEqual(30L, pagination!.Count);
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist: "pagination: is optional, and if present must include count, offset and remaining." Absence:
    /// the reader returns null.
    /// </summary>
    [TestMethod]
    public void PaginationIsOptionalOnKeylist()
    {
        DidCommMessage query = CoordinateMediationExtensions.CreateKeylistQuery("kq-1");
        DidCommMessage withoutPagination = query.CreateKeylist("kl-1", [new KeylistKey { RecipientDid = "did:example:alice-key-1" }]);

        Assert.IsTrue(withoutPagination.TryReadKeylistKeys(out _, out KeylistPagination? pagination));
        Assert.IsNull(pagination);
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist: "pagination: is optional, and if present must include count, offset and remaining." The
    /// record shape enforces this on build (with a negative-member producer guard); the reader fails a
    /// pagination object missing a member; numerics read through the shared <see cref="DidCommBodyNumbers"/> helper.
    /// </summary>
    [TestMethod]
    public void PaginationIfPresentMustIncludeCountOffsetAndRemaining()
    {
        DidCommMessage query = CoordinateMediationExtensions.CreateKeylistQuery("kq-1");

        Assert.ThrowsExactly<ArgumentException>(() => query.CreateKeylist(
            "kl-1", [new KeylistKey { RecipientDid = "did:example:alice-key-1" }], new KeylistPagination { Count = -1, Offset = 0, Remaining = 0 }));
        Assert.ThrowsExactly<ArgumentException>(() => query.CreateKeylist(
            "kl-2", [new KeylistKey { RecipientDid = "did:example:alice-key-1" }], new KeylistPagination { Count = 0, Offset = -1, Remaining = 0 }));
        Assert.ThrowsExactly<ArgumentException>(() => query.CreateKeylist(
            "kl-3", [new KeylistKey { RecipientDid = "did:example:alice-key-1" }], new KeylistPagination { Count = 0, Offset = 0, Remaining = -1 }));

        DidCommMessage keylist = query.CreateKeylist(
            "kl-4", [new KeylistKey { RecipientDid = "did:example:alice-key-1" }], new KeylistPagination { Count = 30, Offset = 30, Remaining = 100 });
        Assert.IsTrue(keylist.TryReadKeylistKeys(out _, out KeylistPagination? pagination));
        Assert.AreEqual(30L, pagination!.Count);
        Assert.AreEqual(30L, pagination.Offset);
        Assert.AreEqual(100L, pagination.Remaining);

        DidCommMessage partial = new()
        {
            Id = "kl-5",
            Type = WellKnownCoordinateMediationNames.KeylistType,
            Body = new Dictionary<string, object>
            {
                [WellKnownCoordinateMediationNames.Keys] = new List<object>(),
                [WellKnownCoordinateMediationNames.Pagination] = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Count] = 30, [WellKnownCoordinateMediationNames.Offset] = 0 }
            }
        };
        Assert.IsFalse(partial.TryReadKeylistKeys(out _, out KeylistPagination? partialPagination), "A pagination object missing 'remaining' MUST fail the read.");
        Assert.IsNull(partialPagination);

        //Reader/producer range symmetry: CreateKeylist refuses a negative count/offset/remaining, so the
        //reader MUST refuse exactly the shapes the producer would never mint.
        DidCommMessage negativeCount = new()
        {
            Id = "kl-6",
            Type = WellKnownCoordinateMediationNames.KeylistType,
            Body = new Dictionary<string, object>
            {
                [WellKnownCoordinateMediationNames.Keys] = new List<object>(),
                [WellKnownCoordinateMediationNames.Pagination] = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Count] = -1, [WellKnownCoordinateMediationNames.Offset] = 0, [WellKnownCoordinateMediationNames.Remaining] = 0 }
            }
        };
        Assert.IsFalse(negativeCount.TryReadKeylistKeys(out IReadOnlyList<KeylistKey>? negativeCountKeys, out KeylistPagination? negativeCountPagination), "A negative count MUST fail the read.");
        Assert.IsNull(negativeCountKeys);
        Assert.IsNull(negativeCountPagination);

        DidCommMessage negativePaginationOffset = new()
        {
            Id = "kl-7",
            Type = WellKnownCoordinateMediationNames.KeylistType,
            Body = new Dictionary<string, object>
            {
                [WellKnownCoordinateMediationNames.Keys] = new List<object>(),
                [WellKnownCoordinateMediationNames.Pagination] = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Count] = 0, [WellKnownCoordinateMediationNames.Offset] = -1, [WellKnownCoordinateMediationNames.Remaining] = 0 }
            }
        };
        Assert.IsFalse(negativePaginationOffset.TryReadKeylistKeys(out IReadOnlyList<KeylistKey>? negativeOffsetKeys, out KeylistPagination? negativeOffsetPagination));
        Assert.IsNull(negativeOffsetKeys);
        Assert.IsNull(negativeOffsetPagination);

        DidCommMessage negativeRemaining = new()
        {
            Id = "kl-8",
            Type = WellKnownCoordinateMediationNames.KeylistType,
            Body = new Dictionary<string, object>
            {
                [WellKnownCoordinateMediationNames.Keys] = new List<object>(),
                [WellKnownCoordinateMediationNames.Pagination] = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Count] = 0, [WellKnownCoordinateMediationNames.Offset] = 0, [WellKnownCoordinateMediationNames.Remaining] = -1 }
            }
        };
        Assert.IsFalse(negativeRemaining.TryReadKeylistKeys(out IReadOnlyList<KeylistKey>? negativeRemainingKeys, out KeylistPagination? negativeRemainingPagination), "A negative remaining MUST fail the read.");
        Assert.IsNull(negativeRemainingKeys);
        Assert.IsNull(negativeRemainingPagination);
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §States (L41) + DIDComm v2.1 §Threading: the keylist correlates to its keylist-query request.
    /// </summary>
    [TestMethod]
    public void KeylistCorrelatesToItsKeylistQuery()
    {
        DidCommMessage query = CoordinateMediationExtensions.CreateKeylistQuery("kq-42");
        DidCommMessage keylist = query.CreateKeylist("kl-1", [new KeylistKey { RecipientDid = "did:example:alice-key-1" }]);

        Assert.AreEqual("kq-42", keylist.ThreadId);
        Assert.AreEqual("kq-42", keylist.EffectiveThreadId);
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §States (L41) + DIDComm v2.1 §Threading: a response answers a SPECIFIC antecedent via thread
    /// correlation, so an antecedent with no usable thread — its
    /// <see cref="DidCommMessage.EffectiveThreadId"/> is <see langword="null"/> (no <c>id</c>/<c>thid</c> at
    /// all) or empty (an empty <c>id</c> off the wire, which <see cref="DidCommMessage.EffectiveThreadId"/>
    /// documents as malformed, not a real thread) — cannot be answered; each of the four response builders
    /// refuses both shapes rather than silently minting a reply that starts a brand-new thread.
    /// </summary>
    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    public void AntecedentWithNoUsableThreadFailsAllFourResponseBuilders(string? antecedentId)
    {
        DidCommMessage threadlessMediateRequest = new() { Id = antecedentId, Type = WellKnownCoordinateMediationNames.MediateRequestType };
        Assert.ThrowsExactly<ArgumentException>(() => threadlessMediateRequest.CreateMediateGrant("g-1", "did:example:mediator-routing"));
        Assert.ThrowsExactly<ArgumentException>(() => threadlessMediateRequest.CreateMediateDeny("d-1"));

        DidCommMessage threadlessKeylistUpdate = new() { Id = antecedentId, Type = WellKnownCoordinateMediationNames.KeylistUpdateType };
        Assert.ThrowsExactly<ArgumentException>(() => threadlessKeylistUpdate.CreateKeylistUpdateResponse(
            "kur-1", [new KeylistUpdateResult { RecipientDid = "did:example:alice-key-1", Action = WellKnownCoordinateMediationNames.ActionAdd, Result = WellKnownCoordinateMediationNames.ResultSuccess }]));

        DidCommMessage threadlessKeylistQuery = new() { Id = antecedentId, Type = WellKnownCoordinateMediationNames.KeylistQueryType };
        Assert.ThrowsExactly<ArgumentException>(() => threadlessKeylistQuery.CreateKeylist("kl-1", [new KeylistKey { RecipientDid = "did:example:alice-key-1" }]));
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Mediate Grant (L111): "routing_did: DID of the mediator where forwarded messages should be sent." —
    /// out-param honesty: every failure path of
    /// <see cref="CoordinateMediationExtensions.TryReadMediateGrantRoutingDid"/> MUST leave <c>routingDid</c>
    /// null — proven across "wrong message type", "missing member", "non-string member", and
    /// "whitespace-only member".
    /// </summary>
    [TestMethod]
    public void TryReadMediateGrantRoutingDidZeroesOutOnEveryFailurePath()
    {
        DidCommMessage wrongType = new() { Id = "x-1", Type = WellKnownCoordinateMediationNames.MediateDenyType };
        Assert.IsFalse(wrongType.TryReadMediateGrantRoutingDid(out string? a));
        Assert.IsNull(a);

        DidCommMessage missingMember = new() { Id = "x-2", Type = WellKnownCoordinateMediationNames.MediateGrantType, Body = new Dictionary<string, object>() };
        Assert.IsFalse(missingMember.TryReadMediateGrantRoutingDid(out string? b));
        Assert.IsNull(b);

        DidCommMessage nonString = new() { Id = "x-3", Type = WellKnownCoordinateMediationNames.MediateGrantType, Body = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.RoutingDid] = 12345 } };
        Assert.IsFalse(nonString.TryReadMediateGrantRoutingDid(out string? c));
        Assert.IsNull(c);

        DidCommMessage whitespace = new() { Id = "x-4", Type = WellKnownCoordinateMediationNames.MediateGrantType, Body = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.RoutingDid] = "   " } };
        Assert.IsFalse(whitespace.TryReadMediateGrantRoutingDid(out string? d));
        Assert.IsNull(d);
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist Update (L125-138): <c>body.updates</c> is a list of <c>{recipient_did, action}</c> entries —
    /// out-param honesty: every failure path of
    /// <see cref="CoordinateMediationExtensions.TryReadKeylistUpdates"/> MUST leave <c>updates</c> null —
    /// including the malformed-LATER-member case, where the FIRST entry parses cleanly but the SECOND is
    /// missing <c>action</c>: the whole read MUST fail, and the successfully-parsed first entry MUST NOT leak
    /// through the out parameter.
    /// </summary>
    [TestMethod]
    public void TryReadKeylistUpdatesZeroesOutOnEveryFailurePathIncludingAMalformedLaterEntry()
    {
        DidCommMessage wrongType = new() { Id = "x-1", Type = WellKnownCoordinateMediationNames.KeylistQueryType };
        Assert.IsFalse(wrongType.TryReadKeylistUpdates(out IReadOnlyList<KeylistUpdateEntry>? a));
        Assert.IsNull(a);

        DidCommMessage empty = new()
        {
            Id = "x-2",
            Type = WellKnownCoordinateMediationNames.KeylistUpdateType,
            Body = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Updates] = new List<object>() }
        };
        Assert.IsFalse(empty.TryReadKeylistUpdates(out IReadOnlyList<KeylistUpdateEntry>? b));
        Assert.IsNull(b);

        DidCommMessage malformedLaterEntry = new()
        {
            Id = "x-3",
            Type = WellKnownCoordinateMediationNames.KeylistUpdateType,
            Body = new Dictionary<string, object>
            {
                [WellKnownCoordinateMediationNames.Updates] = new List<object>
                {
                    new Dictionary<string, object> { [WellKnownCoordinateMediationNames.RecipientDid] = "did:example:alice-key-1", [WellKnownCoordinateMediationNames.Action] = WellKnownCoordinateMediationNames.ActionAdd },
                    new Dictionary<string, object> { [WellKnownCoordinateMediationNames.RecipientDid] = "did:example:alice-key-2" }
                }
            }
        };
        Assert.IsFalse(malformedLaterEntry.TryReadKeylistUpdates(out IReadOnlyList<KeylistUpdateEntry>? c));
        Assert.IsNull(c, "A malformed SECOND entry MUST fail the whole read — the successfully-parsed first entry MUST NOT leak through.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist Response (L150-164): <c>body.updated</c> is a list of <c>{recipient_did, action, result}</c>
    /// entries — out-param honesty: every failure path of
    /// <see cref="CoordinateMediationExtensions.TryReadKeylistUpdateResults"/> MUST leave <c>updated</c> null —
    /// including the malformed-LATER-member case, where the FIRST entry parses cleanly but the SECOND is
    /// missing <c>result</c>.
    /// </summary>
    [TestMethod]
    public void TryReadKeylistUpdateResultsZeroesOutOnEveryFailurePathIncludingAMalformedLaterEntry()
    {
        DidCommMessage wrongType = new() { Id = "x-1", Type = WellKnownCoordinateMediationNames.KeylistUpdateType };
        Assert.IsFalse(wrongType.TryReadKeylistUpdateResults(out IReadOnlyList<KeylistUpdateResult>? a));
        Assert.IsNull(a);

        DidCommMessage empty = new()
        {
            Id = "x-2",
            Type = WellKnownCoordinateMediationNames.KeylistUpdateResponseType,
            Body = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Updated] = new List<object>() }
        };
        Assert.IsFalse(empty.TryReadKeylistUpdateResults(out IReadOnlyList<KeylistUpdateResult>? b));
        Assert.IsNull(b);

        DidCommMessage malformedLaterEntry = new()
        {
            Id = "x-3",
            Type = WellKnownCoordinateMediationNames.KeylistUpdateResponseType,
            Body = new Dictionary<string, object>
            {
                [WellKnownCoordinateMediationNames.Updated] = new List<object>
                {
                    new Dictionary<string, object>
                    {
                        [WellKnownCoordinateMediationNames.RecipientDid] = "did:example:alice-key-1",
                        [WellKnownCoordinateMediationNames.Action] = WellKnownCoordinateMediationNames.ActionAdd,
                        [WellKnownCoordinateMediationNames.Result] = WellKnownCoordinateMediationNames.ResultSuccess
                    },
                    new Dictionary<string, object>
                    {
                        [WellKnownCoordinateMediationNames.RecipientDid] = "did:example:alice-key-2",
                        [WellKnownCoordinateMediationNames.Action] = WellKnownCoordinateMediationNames.ActionAdd
                    }
                }
            }
        };
        Assert.IsFalse(malformedLaterEntry.TryReadKeylistUpdateResults(out IReadOnlyList<KeylistUpdateResult>? c));
        Assert.IsNull(c, "A malformed SECOND entry (missing result) MUST fail the whole read — the successfully-parsed first entry MUST NOT leak through.");
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist Query (L186): "paginate: is optional, and if present must include limit and offset." —
    /// out-param honesty: every failure path of
    /// <see cref="CoordinateMediationExtensions.TryReadKeylistQueryPaginate"/> MUST leave <c>paginate</c> null.
    /// </summary>
    [TestMethod]
    public void TryReadKeylistQueryPaginateZeroesOutOnEveryFailurePath()
    {
        DidCommMessage wrongType = new() { Id = "x-1", Type = WellKnownCoordinateMediationNames.KeylistUpdateType };
        Assert.IsFalse(wrongType.TryReadKeylistQueryPaginate(out KeylistPaginate? a));
        Assert.IsNull(a);

        DidCommMessage notAnObject = new()
        {
            Id = "x-2",
            Type = WellKnownCoordinateMediationNames.KeylistQueryType,
            Body = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Paginate] = "not-an-object" }
        };
        Assert.IsFalse(notAnObject.TryReadKeylistQueryPaginate(out KeylistPaginate? b));
        Assert.IsNull(b);
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §Keylist (L213): "pagination: is optional, and if present must include count, offset and remaining." —
    /// out-param honesty: every failure path of
    /// <see cref="CoordinateMediationExtensions.TryReadKeylistKeys"/> MUST leave BOTH <c>keys</c> and
    /// <c>pagination</c> null — including when <c>keys</c> itself parses cleanly but a present
    /// <c>pagination</c> is malformed (missing <c>remaining</c>): the whole read MUST fail, and the
    /// successfully-parsed <c>keys</c> list MUST NOT leak through.
    /// </summary>
    [TestMethod]
    public void TryReadKeylistKeysZeroesOutOnEveryFailurePathIncludingMalformedPagination()
    {
        DidCommMessage wrongType = new() { Id = "x-1", Type = WellKnownCoordinateMediationNames.KeylistUpdateType };
        Assert.IsFalse(wrongType.TryReadKeylistKeys(out IReadOnlyList<KeylistKey>? a, out KeylistPagination? aPagination));
        Assert.IsNull(a);
        Assert.IsNull(aPagination);

        DidCommMessage malformedPagination = new()
        {
            Id = "x-2",
            Type = WellKnownCoordinateMediationNames.KeylistType,
            Body = new Dictionary<string, object>
            {
                [WellKnownCoordinateMediationNames.Keys] = new List<object> { new Dictionary<string, object> { [WellKnownCoordinateMediationNames.RecipientDid] = "did:example:alice-key-1" } },
                [WellKnownCoordinateMediationNames.Pagination] = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Count] = 1, [WellKnownCoordinateMediationNames.Offset] = 0 }
            }
        };
        Assert.IsFalse(malformedPagination.TryReadKeylistKeys(out IReadOnlyList<KeylistKey>? b, out KeylistPagination? bPagination));
        Assert.IsNull(b, "keys MUST NOT leak even though it parsed successfully — the overall read failed on pagination.");
        Assert.IsNull(bPagination);

        //An object-shaped "keys" MUST fail closed rather than read TRUE with an empty list: a JSON object
        //reads back as a Dictionary<string, object>, which is ALSO IEnumerable (its KeyValuePair enumerator),
        //so an unguarded reader would enumerate it as zero elements and wrongly succeed.
        DidCommMessage objectShapedKeys = new()
        {
            Id = "x-3",
            Type = WellKnownCoordinateMediationNames.KeylistType,
            Body = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Keys] = new Dictionary<string, object>() }
        };
        Assert.IsFalse(objectShapedKeys.TryReadKeylistKeys(out IReadOnlyList<KeylistKey>? c, out KeylistPagination? cPagination), "An object-shaped 'keys' member is not a JSON array and MUST fail the read.");
        Assert.IsNull(c);
        Assert.IsNull(cPagination);
    }


    /// <summary>
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>
    /// §L10n (L217): "No localization is required." Proven by every wire token this protocol defines — the
    /// PIURI, the seven Message Type URIs, the thirteen body member names, and the six closed
    /// <c>action</c>/<c>result</c> values — being pure ASCII: no locale-dependent wire token exists for a peer
    /// to localize, so nothing here can be affected by the current culture.
    /// </summary>
    [TestMethod]
    public void NoLocalizationIsRequiredEveryWireTokenIsAscii()
    {
        string[] wireTokens =
        [
            WellKnownCoordinateMediationNames.CoordinateMediationProtocol,
            WellKnownCoordinateMediationNames.MediateRequestType,
            WellKnownCoordinateMediationNames.MediateDenyType,
            WellKnownCoordinateMediationNames.MediateGrantType,
            WellKnownCoordinateMediationNames.KeylistUpdateType,
            WellKnownCoordinateMediationNames.KeylistUpdateResponseType,
            WellKnownCoordinateMediationNames.KeylistQueryType,
            WellKnownCoordinateMediationNames.KeylistType,
            WellKnownCoordinateMediationNames.RoutingDid,
            WellKnownCoordinateMediationNames.Updates,
            WellKnownCoordinateMediationNames.Updated,
            WellKnownCoordinateMediationNames.RecipientDid,
            WellKnownCoordinateMediationNames.Action,
            WellKnownCoordinateMediationNames.Result,
            WellKnownCoordinateMediationNames.Keys,
            WellKnownCoordinateMediationNames.Paginate,
            WellKnownCoordinateMediationNames.Pagination,
            WellKnownCoordinateMediationNames.Limit,
            WellKnownCoordinateMediationNames.Offset,
            WellKnownCoordinateMediationNames.Count,
            WellKnownCoordinateMediationNames.Remaining,
            WellKnownCoordinateMediationNames.ActionAdd,
            WellKnownCoordinateMediationNames.ActionRemove,
            WellKnownCoordinateMediationNames.ResultClientError,
            WellKnownCoordinateMediationNames.ResultServerError,
            WellKnownCoordinateMediationNames.ResultNoChange,
            WellKnownCoordinateMediationNames.ResultSuccess
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
    /// Real-wire capstone: a recipient packs an anoncrypt <c>mediate-request</c> with <c>return_route: all</c>
    /// (<see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>),
    /// <see cref="DidCommTransportExtensions.ExchangeAsync(DidCommEncryptedMessage, DidCommMessage, Uri, ExchangeContext, DidCommExchangeDelegate, CancellationToken)"/>
    /// POSTs it over a genuine loopback socket, a <see cref="MinimalHttpHost"/> replies in the HTTP response
    /// body with a packed anoncrypt <c>mediate-grant</c>, the recipient classifies the reply via
    /// <see cref="DidCommInbound.Classify"/>, decrypts it, and
    /// <see cref="CoordinateMediationExtensions.TryReadMediateGrantRoutingDid"/> recovers the granted
    /// <c>routing_did</c> — exercising the protocol layer and Message Pickup 3.0's exchange seam together over
    /// the real wire.
    /// </summary>
    [TestMethod]
    public async Task MediateRequestExchangeRoundTripsAnAnoncryptMediateGrantOverARealSocket()
    {
        const string E2ERecipientDid = "did:example:cm-e2e-recipient";
        const string E2ERecipientKid = "did:example:cm-e2e-recipient#key-1";
        const string E2EMediatorDid = "did:example:cm-e2e-mediator";
        const string E2EMediatorKid = "did:example:cm-e2e-mediator#key-1";
        const string ExpectedRoutingDid = "did:peer:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6";

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipientKeys = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory recipientPublic = recipientKeys.PublicKey;
        PrivateKeyMemory recipientPrivate = recipientKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> mediatorKeys = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory mediatorPublic = mediatorKeys.PublicKey;
        //Unused: the loopback host below is a stub that replies with a pre-packed grant; it never actually
        //decrypts the inbound mediate-request, so the mediator's private key is not needed.
        using PrivateKeyMemory unusedMediatorPrivate = mediatorKeys.PrivateKey;

        try
        {
            DidCommMessage mediateRequest = MediateRequest("mediate-request-e2e-1", from: E2ERecipientDid);
            DidCommMessage mediateGrantMessage = mediateRequest.CreateMediateGrant("mediate-grant-e2e-1", ExpectedRoutingDid, from: E2EMediatorDid);
            using DidCommEncryptedMessage packedGrantReply = await PackAnoncryptAsync(
                mediateGrantMessage, E2ERecipientKid, recipientPublic, TestContext.CancellationToken).ConfigureAwait(false);
            string grantReplyJson = Encoding.UTF8.GetString(packedGrantReply.AsReadOnlySpan());

            await using MinimalHttpHost mediatorHost = await MinimalHttpHost.StartAsync(
                (request, cancellationToken) => Task.FromResult(new MinimalHttpResponse
                {
                    StatusCode = 200,
                    ContentType = DidCommEncryptedMessage.MediaType,
                    Body = grantReplyJson
                }),
                TestContext.CancellationToken).ConfigureAwait(false);

            using DidCommEncryptedMessage packedRequest = await PackAnoncryptAsync(
                mediateRequest, E2EMediatorKid, mediatorPublic, TestContext.CancellationToken).ConfigureAwait(false);

            using HttpClient httpClient = LoopbackTls.CreatePinnedHttpClient(mediatorHost.Certificate);
            DidCommExchangeDelegate exchange = DidCommHttpTransport.CreateExchangeDelegate(BuildExchangeTransport(httpClient), Pool);

            using DidCommExchangeResult exchangeResult = await packedRequest.ExchangeAsync(
                mediateRequest, mediatorHost.BaseAddress, NewLoopbackExchangeContext(), exchange, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(exchangeResult.IsAccepted, $"The mediator MUST accept the mediate-request. Status: {exchangeResult.TransportStatusCode}, error: {exchangeResult.Error}.");
            Assert.IsTrue(exchangeResult.HasReply, "The reply MUST arrive on the same HTTP response (return_route: all).");

            DidCommMessageClass replyClass = DidCommInbound.Classify(exchangeResult.ReplyMediaType, exchangeResult.ReplyBody.AsReadOnlySpan(), TestSetup.Base64UrlDecoder, Pool);
            Assert.AreEqual(DidCommMessageClass.Anoncrypt, replyClass, "The reply's Content-Type and protected-header alg MUST classify as anoncrypt.");

            using DidCommEncryptedMessage receivedReply = DidCommEncryptedMessage.Create(exchangeResult.ReplyBody.AsReadOnlySpan(), BufferTags.Json, Pool);
            DidCommEncryptedUnpackResult unpacked = await receivedReply.UnpackAnoncryptAsync(
                E2ERecipientKid, recipientPrivate, NestedSignerResolver, UnpackContext, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
                TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(unpacked.IsUnpacked, $"The recipient MUST decrypt the mediate-grant that crossed the wire. Error: {unpacked.Error}.");
            Assert.IsNotNull(unpacked.Message);
            Assert.IsTrue(unpacked.Message!.TryReadMediateGrantRoutingDid(out string? routingDid), "TryReadMediateGrantRoutingDid MUST succeed on the decrypted grant.");
            Assert.AreEqual(ExpectedRoutingDid, routingDid);
        }
        finally
        {
            recipientPrivate.Dispose();
        }
    }
}
