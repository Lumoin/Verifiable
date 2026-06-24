using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Resolvers;
using Verifiable.DidComm;
using Verifiable.DidComm.Routing;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Tests for the DIDComm v2.1 DIDCommMessaging service endpoint surface (chunk G): parsing the declared endpoints
/// (<see cref="DidCommServiceEndpointExtensions.GetDidCommServiceEndpoints"/>) across the single-object, array, and
/// bare-string forms, and the sender-facing delivery resolution
/// (<see cref="DidCommServiceEndpointExtensions.ResolveDeliveryTargetsAsync"/>) including the mediator-DID
/// indirection and failover ordering. Also covers that the routing-forward
/// <see cref="RoutingForwardExtensions.ResolveRoutingKeysAsync"/> now prepends the mediator DID for a DID-uri endpoint.
/// </summary>
/// <remarks>
/// These exercise pure parsing and resolution logic, so the DID documents are crafted in memory and resolved by a
/// map-backed fake resolver — no keys or crypto are involved (the forward wrap that consumes the routing keys is
/// covered by <see cref="DidCommRoutingForwardTests"/>).
/// </remarks>
[TestClass]
internal sealed class DidCommServiceEndpointTests
{
    private static readonly ExchangeContext Context = new();

    private const string DidPrefix = "did:example";
    private const string Recipient = "did:example:recipient";
    private const string Mediator = "did:example:mediator";
    private const string AnotherMediatorKey = "did:example:anothermediator#somekey";

    private static readonly string[] OneRoutingKey = ["did:example:m1"];
    private static readonly string[] M2RoutingKey = ["did:example:m2"];
    private static readonly string[] TwoRoutingKeys = ["did:example:m1", "did:example:m2"];


    // ---- parsing -------------------------------------------------------------------------------

    [TestMethod]
    public void ParsesObjectArrayAndBareForms()
    {
        DidDocument document = Document(Recipient,
            ObjectService("https://a.example/didcomm", routingKeys: OneRoutingKey),
            ArrayService(
                ("https://b.example/didcomm", null),
                ("https://c.example/didcomm", M2RoutingKey)),
            BareStringService("https://d.example/didcomm"));

        IReadOnlyList<DidCommServiceEndpoint> endpoints = document.GetDidCommServiceEndpoints();

        Assert.AreEqual(
            "https://a.example/didcomm|https://b.example/didcomm|https://c.example/didcomm|https://d.example/didcomm",
            string.Join("|", endpoints.Select(e => e.Uri)),
            "All three serviceEndpoint forms parse, in document order.");
        Assert.AreEqual("did:example:m1", string.Join("|", endpoints[0].RoutingKeys));
        Assert.IsEmpty(endpoints[1].RoutingKeys, "An array endpoint with no routingKeys has none.");
        Assert.AreEqual("did:example:m2", string.Join("|", endpoints[2].RoutingKeys));
    }


    [TestMethod]
    public void SkipsEndpointWithoutUri()
    {
        var noUri = new Service
        {
            Type = WellKnownDidCommServiceNames.DidCommMessagingServiceType,
            ServiceEndpointMap = new Dictionary<string, object> { ["routingKeys"] = new List<string> { "did:example:m1" } }
        };

        Assert.IsEmpty(Document(Recipient, noUri).GetDidCommServiceEndpoints(), "An endpoint with no uri (REQUIRED) is skipped.");
    }


    [TestMethod]
    public void FiltersByDidCommV2Accept()
    {
        DidDocument document = Document(Recipient,
            ObjectService("https://v2.example", accept: [WellKnownRoutingNames.Profile]),
            ObjectService("https://other.example", accept: ["didcomm/aip2;env=rfc587"]),
            ObjectService("https://absent.example", accept: null));

        IReadOnlyList<DidCommServiceEndpoint> endpoints = document.GetDidCommServiceEndpoints();

        Assert.AreEqual(
            "https://v2.example|https://absent.example",
            string.Join("|", endpoints.Select(e => e.Uri)),
            "A present accept without didcomm/v2 is excluded; an absent accept is included.");
    }


    // ---- delivery resolution -------------------------------------------------------------------

    [TestMethod]
    public async Task DirectEndpointResolvesToTransportTarget()
    {
        DidResolver resolver = MapResolver((Recipient, Document(Recipient, ObjectService("https://example.com/path", routingKeys: ["did:example:m1"]))));

        IReadOnlyList<DidCommDeliveryTarget> targets = await DidCommServiceEndpointExtensions
            .ResolveDeliveryTargetsAsync(Recipient, resolver, Context, default).ConfigureAwait(false);

        Assert.HasCount(1, targets);
        Assert.AreEqual("https://example.com/path", targets[0].TransportUri);
        Assert.AreEqual("did:example:m1", string.Join("|", targets[0].RoutingKeys));
    }


    [TestMethod]
    public async Task MediatorDidUriPrependsMediatorAndUsesItsTransport()
    {
        //Spec Example 2: the recipient's endpoint uri is a mediator DID; the mediator's endpoint is a transport URI.
        DidResolver resolver = MapResolver(
            (Recipient, Document(Recipient, ObjectService(Mediator, routingKeys: [AnotherMediatorKey]))),
            (Mediator, Document(Mediator, ObjectService("https://mediator.example/didcomm"))));

        IReadOnlyList<DidCommDeliveryTarget> targets = await DidCommServiceEndpointExtensions
            .ResolveDeliveryTargetsAsync(Recipient, resolver, Context, default).ConfigureAwait(false);

        Assert.HasCount(1, targets);
        Assert.AreEqual("https://mediator.example/didcomm", targets[0].TransportUri, "The transport URI is the mediator's.");
        Assert.AreEqual(
            $"{Mediator}|{AnotherMediatorKey}",
            string.Join("|", targets[0].RoutingKeys),
            "The mediator DID is PREPENDED to the recipient's routingKeys (the outer forward wraps for the mediator's keyAgreement keys).");
    }


    [TestMethod]
    public async Task MediatorWithNonAbsoluteTransportUriDropsTarget()
    {
        //A mediator (a second untrusted DID document) advertising a non-absolute transport uri yields no usable
        //target — the same absolute-URI guard the direct branch applies, ported to the mediator branch. The uri
        //carries no scheme, so it is non-absolute on every platform (a leading-slash path would be a valid
        //absolute file URI on Unix, hence not portable for this assertion).
        DidResolver resolver = MapResolver(
            (Recipient, Document(Recipient, ObjectService(Mediator, routingKeys: [AnotherMediatorKey]))),
            (Mediator, Document(Mediator, ObjectService("not-an-absolute-uri"))));

        IReadOnlyList<DidCommDeliveryTarget> targets = await DidCommServiceEndpointExtensions
            .ResolveDeliveryTargetsAsync(Recipient, resolver, Context, default).ConfigureAwait(false);

        Assert.IsEmpty(targets, "A mediator transport uri that is not an absolute URI MUST drop the target, not carry a bogus one.");
    }


    [TestMethod]
    public async Task RecursiveAlternativeEndpointIsSkipped()
    {
        //The mediator's own endpoint uri is ALSO a DID — a recursive alternative endpoint the spec says SHOULD NOT
        //occur. That target is skipped (fail-soft, no throw), not followed for a second hop.
        DidResolver resolver = MapResolver(
            (Recipient, Document(Recipient, ObjectService(Mediator, routingKeys: [AnotherMediatorKey]))),
            (Mediator, Document(Mediator, ObjectService("did:example:deepermediator"))));

        IReadOnlyList<DidCommDeliveryTarget> targets = await DidCommServiceEndpointExtensions
            .ResolveDeliveryTargetsAsync(Recipient, resolver, Context, default).ConfigureAwait(false);

        Assert.IsEmpty(targets, "A recursive alternative endpoint yields no usable target, without throwing.");
    }


    [TestMethod]
    public async Task MultipleEndpointsReturnedInPreferenceOrder()
    {
        DidResolver resolver = MapResolver((Recipient, Document(Recipient,
            ArrayService(
                ("https://first.example", OneRoutingKey),
                ("https://second.example", null)))));

        IReadOnlyList<DidCommDeliveryTarget> targets = await DidCommServiceEndpointExtensions
            .ResolveDeliveryTargetsAsync(Recipient, resolver, Context, default).ConfigureAwait(false);

        Assert.AreEqual(
            "https://first.example|https://second.example",
            string.Join("|", targets.Select(t => t.TransportUri)),
            "Endpoints are returned in the document's preference order, for failover.");
    }


    [TestMethod]
    public async Task FailSoftOnUnresolvableRecipientAndMediator()
    {
        //Unresolvable recipient -> no targets, no throw.
        DidResolver empty = MapResolver();
        Assert.IsEmpty(await DidCommServiceEndpointExtensions.ResolveDeliveryTargetsAsync(Recipient, empty, Context, default).ConfigureAwait(false));

        //A mediator-DID endpoint whose mediator has no didcomm/v2 service -> that target skipped.
        DidResolver mediatorWithoutService = MapResolver(
            (Recipient, Document(Recipient, ObjectService(Mediator))),
            (Mediator, Document(Mediator)));
        Assert.IsEmpty(await DidCommServiceEndpointExtensions.ResolveDeliveryTargetsAsync(Recipient, mediatorWithoutService, Context, default).ConfigureAwait(false));
    }


    [TestMethod]
    public async Task DirectDeliveryTargetCarriesAcceptAndScheme()
    {
        //A sender chooses the transport and profile from the resolved target: the uri scheme selects the
        //transport (DIDComm v2.1 §Service Endpoint: the uri "MUST contain a URI for a transport specified in the
        //[transports] section"), and accept lists the media types in preference order (L1387-1390). Both were
        //dropped at resolution before; they are carried now.
        string[] accept = [WellKnownRoutingNames.Profile, "didcomm/aip2;env=rfc587"];
        DidResolver resolver = MapResolver((Recipient, Document(Recipient, ObjectService("wss://recipient.example/inbox", accept: accept))));

        IReadOnlyList<DidCommDeliveryTarget> targets = await DidCommServiceEndpointExtensions
            .ResolveDeliveryTargetsAsync(Recipient, resolver, Context, default).ConfigureAwait(false);

        Assert.HasCount(1, targets);
        Assert.AreEqual("wss", targets[0].Scheme, "The delivery target exposes the uri scheme so a sender dispatches to the matching transport.");
        Assert.IsNotNull(targets[0].Accept);
        Assert.AreEqual(
            "didcomm/v2|didcomm/aip2;env=rfc587",
            string.Join("|", targets[0].Accept!),
            "The endpoint's accept media types are carried in preference order.");
    }


    [TestMethod]
    public async Task MediatorDeliveryTargetCarriesMediatorAcceptAndScheme()
    {
        //For a mediator-DID endpoint, the target is the mediator's transport, so its accept/scheme are the ones
        //carried (accept is scoped to "sending a message to the endpoint", and the outer forward is delivered to
        //the mediator).
        DidResolver resolver = MapResolver(
            (Recipient, Document(Recipient, ObjectService(Mediator))),
            (Mediator, Document(Mediator, ObjectService("wss://mediator.example/inbox", accept: [WellKnownRoutingNames.Profile]))));

        IReadOnlyList<DidCommDeliveryTarget> targets = await DidCommServiceEndpointExtensions
            .ResolveDeliveryTargetsAsync(Recipient, resolver, Context, default).ConfigureAwait(false);

        Assert.HasCount(1, targets);
        Assert.AreEqual("wss", targets[0].Scheme, "The mediator endpoint's scheme is carried.");
        Assert.AreEqual("didcomm/v2", string.Join("|", targets[0].Accept!), "The mediator endpoint's accept is carried (it is the transport delivered to).");
    }


    [TestMethod]
    public void SchemeDerivesFromTransportUriOrNullWhenNotAbsolute()
    {
        Assert.AreEqual("wss", new DidCommDeliveryTarget { TransportUri = "wss://host/inbox" }.Scheme);
        Assert.AreEqual("https", new DidCommDeliveryTarget { TransportUri = "https://host/inbox" }.Scheme);
        Assert.AreEqual("didcomm", new DidCommDeliveryTarget { TransportUri = "didcomm://example" }.Scheme);
        Assert.IsNull(new DidCommDeliveryTarget { TransportUri = "not-an-absolute-uri" }.Scheme, "A non-absolute transport uri has no scheme.");
    }


    // ---- routing-forward reconciliation (the closed E divergence) ------------------------------

    [TestMethod]
    public async Task ResolveRoutingKeysPrependsMediatorForDidUriEndpoint()
    {
        //The routing-forward resolver now delegates to the delivery resolution: for a DID-uri endpoint it prepends
        //the mediator DID (so the outer forward wraps for the mediator's keyAgreement keys) rather than the
        //mediator's own routingKeys — closing the DID-uri divergence chunk E deferred.
        DidResolver resolver = MapResolver(
            (Recipient, Document(Recipient, ObjectService(Mediator, routingKeys: [AnotherMediatorKey]))),
            (Mediator, Document(Mediator, ObjectService("https://mediator.example/didcomm"))));

        IReadOnlyList<string> keys = await RoutingForwardExtensions
            .ResolveRoutingKeysAsync(Recipient, resolver, Context, default).ConfigureAwait(false);

        Assert.AreEqual($"{Mediator}|{AnotherMediatorKey}", string.Join("|", keys));
    }


    [TestMethod]
    public async Task ResolveRoutingKeysReadsDirectRoutingKeys()
    {
        //The non-DID-uri path is unchanged: the recipient's own routingKeys, in order.
        DidResolver resolver = MapResolver((Recipient, Document(Recipient,
            ObjectService("https://example.com/didcomm", routingKeys: TwoRoutingKeys))));

        IReadOnlyList<string> keys = await RoutingForwardExtensions
            .ResolveRoutingKeysAsync(Recipient, resolver, Context, default).ConfigureAwait(false);

        Assert.AreEqual("did:example:m1|did:example:m2", string.Join("|", keys));
    }


    // ---- fail-soft parsing over untrusted documents --------------------------------------------

    [TestMethod]
    public void NonStringUriIsSkipped()
    {
        var service = new Service
        {
            Type = WellKnownDidCommServiceNames.DidCommMessagingServiceType,
            ServiceEndpointMap = new Dictionary<string, object>
            {
                [WellKnownDidCommServiceNames.Uri] = 42,
                [WellKnownDidCommServiceNames.Accept] = new List<string> { WellKnownRoutingNames.Profile }
            }
        };

        Assert.IsEmpty(Document(Recipient, service).GetDidCommServiceEndpoints(), "A non-string uri is skipped, not thrown on.");
    }


    [TestMethod]
    public void ScalarStringRoutingKeysIsDroppedNotSplitIntoChars()
    {
        //A routingKeys that is a JSON string scalar (not an array) must NOT be shredded into chars.
        var service = new Service
        {
            Type = WellKnownDidCommServiceNames.DidCommMessagingServiceType,
            ServiceEndpointMap = new Dictionary<string, object>
            {
                [WellKnownDidCommServiceNames.Uri] = "https://example.com/path",
                [WellKnownDidCommServiceNames.RoutingKeys] = "did:example:m1"
            }
        };

        IReadOnlyList<DidCommServiceEndpoint> endpoints = Document(Recipient, service).GetDidCommServiceEndpoints();
        Assert.HasCount(1, endpoints);
        Assert.IsEmpty(endpoints[0].RoutingKeys, "A scalar-string routingKeys is dropped, not split into chars.");
    }


    [TestMethod]
    public void NonStringRoutingKeyElementsAreDropped()
    {
        var service = new Service
        {
            Type = WellKnownDidCommServiceNames.DidCommMessagingServiceType,
            ServiceEndpointMap = new Dictionary<string, object>
            {
                [WellKnownDidCommServiceNames.Uri] = "https://example.com/path",
                [WellKnownDidCommServiceNames.RoutingKeys] = new List<object?> { "did:example:m1", 7, null, new Dictionary<string, object>() }
            }
        };

        IReadOnlyList<DidCommServiceEndpoint> endpoints = Document(Recipient, service).GetDidCommServiceEndpoints();
        Assert.AreEqual("did:example:m1", string.Join("|", endpoints[0].RoutingKeys), "Non-string routingKeys elements are dropped; valid strings kept.");
    }


    [TestMethod]
    public void ParsesBareStringElementInArrayForm()
    {
        var service = new Service
        {
            Type = WellKnownDidCommServiceNames.DidCommMessagingServiceType,
            ServiceEndpoints = new List<object>
            {
                "https://bare-in-array.example",
                new Dictionary<string, object> { [WellKnownDidCommServiceNames.Uri] = "https://obj-in-array.example" }
            }
        };

        Assert.AreEqual(
            "https://bare-in-array.example|https://obj-in-array.example",
            string.Join("|", Document(Recipient, service).GetDidCommServiceEndpoints().Select(e => e.Uri)),
            "A bare-string element and an object element in the array form both parse, in order.");
    }


    [TestMethod]
    public void SkipsArrayElementWithoutUri()
    {
        var service = new Service
        {
            Type = WellKnownDidCommServiceNames.DidCommMessagingServiceType,
            ServiceEndpoints = new List<object>
            {
                new Dictionary<string, object> { [WellKnownDidCommServiceNames.Uri] = "https://a.example" },
                new Dictionary<string, object> { [WellKnownDidCommServiceNames.RoutingKeys] = new List<string> { "did:example:m1" } },
                new Dictionary<string, object> { [WellKnownDidCommServiceNames.Uri] = "https://c.example" }
            }
        };

        Assert.AreEqual(
            "https://a.example|https://c.example",
            string.Join("|", Document(Recipient, service).GetDidCommServiceEndpoints().Select(e => e.Uri)),
            "An array element with no uri is skipped mid-list; the others survive.");
    }


    [TestMethod]
    public async Task MixedDirectAndMediatorEndpointsResolveIndependently()
    {
        DidResolver resolver = MapResolver(
            (Recipient, Document(Recipient,
                ObjectService("https://direct.example", routingKeys: OneRoutingKey),
                ObjectService(Mediator))),
            (Mediator, Document(Mediator, ObjectService("https://mediator.example/didcomm"))));

        IReadOnlyList<DidCommDeliveryTarget> targets = await DidCommServiceEndpointExtensions
            .ResolveDeliveryTargetsAsync(Recipient, resolver, Context, default).ConfigureAwait(false);

        Assert.HasCount(2, targets);
        Assert.AreEqual("https://direct.example", targets[0].TransportUri);
        Assert.AreEqual("did:example:m1", string.Join("|", targets[0].RoutingKeys));
        Assert.AreEqual("https://mediator.example/didcomm", targets[1].TransportUri);
        Assert.AreEqual(Mediator, string.Join("|", targets[1].RoutingKeys), "The mediator endpoint prepends the mediator DID (no recipient routingKeys here).");
    }


    // ---- helpers -------------------------------------------------------------------------------

    private static DidDocument Document(string did, params Service[] services) =>
        new() { Id = new GenericDidMethod(did), Service = services.Length > 0 ? services : null };


    //A DIDCommMessaging service in the single-object form; defaults accept to [didcomm/v2] unless overridden.
    private static Service ObjectService(string uri, IEnumerable<string>? routingKeys = null, IEnumerable<string>? accept = null)
    {
        var map = new Dictionary<string, object> { [WellKnownDidCommServiceNames.Uri] = uri };

        IEnumerable<string> acceptValues = accept ?? [WellKnownRoutingNames.Profile];
        map[WellKnownDidCommServiceNames.Accept] = new List<string>(acceptValues);

        if(routingKeys is not null)
        {
            map[WellKnownDidCommServiceNames.RoutingKeys] = new List<string>(routingKeys);
        }

        return new Service { Type = WellKnownDidCommServiceNames.DidCommMessagingServiceType, ServiceEndpointMap = map };
    }


    //A DIDCommMessaging service in the array-of-objects form; each (uri, routingKeys) becomes one endpoint object,
    //defaulting accept to [didcomm/v2].
    private static Service ArrayService(params (string Uri, string[]? RoutingKeys)[] endpoints)
    {
        var list = new List<object>();
        foreach((string uri, string[]? routingKeys) in endpoints)
        {
            var map = new Dictionary<string, object>
            {
                [WellKnownDidCommServiceNames.Uri] = uri,
                [WellKnownDidCommServiceNames.Accept] = new List<string> { WellKnownRoutingNames.Profile }
            };

            if(routingKeys is not null)
            {
                map[WellKnownDidCommServiceNames.RoutingKeys] = new List<string>(routingKeys);
            }

            list.Add(map);
        }

        return new Service { Type = WellKnownDidCommServiceNames.DidCommMessagingServiceType, ServiceEndpoints = list };
    }


    private static Service BareStringService(string uri) =>
        new() { Type = WellKnownDidCommServiceNames.DidCommMessagingServiceType, ServiceEndpoint = uri };


    //A resolver mapping the given DIDs to crafted documents; any other did:example identifier is NotFound.
    private static DidResolver MapResolver(params (string Did, DidDocument Document)[] documents)
    {
        var map = new Dictionary<string, DidDocument>(StringComparer.Ordinal);
        foreach((string did, DidDocument document) in documents)
        {
            map[did] = document;
        }

        return new DidResolver(DidMethodSelectors.FromResolvers(
            (DidPrefix, (did, _, _, _) => ValueTask.FromResult(
                map.TryGetValue(did, out DidDocument? document)
                    ? DidResolutionResult.Success(document, new DidDocumentMetadata())
                    : DidResolutionResult.Failure(DidResolutionErrors.NotFound)))));
    }
}
