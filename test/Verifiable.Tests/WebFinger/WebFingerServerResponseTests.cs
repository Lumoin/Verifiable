using System.Text;
using Verifiable.Core;
using Verifiable.Json;
using Verifiable.WebFinger;

namespace Verifiable.Tests.WebFinger;

/// <summary>
/// Server-bound conformance tests for the
/// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4">RFC 7033 §4</see>
/// <c>GET /.well-known/webfinger</c> endpoint (<see cref="WebFingerEndpoints"/>), driven through the
/// REAL shipped dispatch path — <see cref="EndpointServer.DispatchAsync"/> via
/// <see cref="WebFingerHttpApplication.BuildServer"/> — never a hand-called <c>BuildInputAsync</c>.
/// These are the server-response rows of the conformance matrix (T4); the client-side rows live in the
/// existing WebFinger test files under this directory, and the firewalled real-wire rows live in
/// <see cref="WebFingerCrossWireFlowTests"/>.
/// </summary>
[TestClass]
internal sealed class WebFingerServerResponseTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string Resource = "acct:alice@example.com";

    private const string PublishedHref = "did:webs:example.com:EKTh4PkRBiNWHQd263Eueu39gWmg7AfIfnEmNy6jinGR";


    /// <summary>WF-12: §4.2 MUST — an absent <c>resource</c> parameter yields 400.</summary>
    [TestMethod]
    public async Task WF12_AbsentResourceParameterYields400()
    {
        using EndpointServer server = WebFingerHttpApplication.BuildServer(StaticResolver(BuildDescriptor(Resource)));

        ServerHttpResponse response = await Dispatch(server, new RequestFields()).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, "§4.2 MUST: an absent 'resource' parameter yields 400.");
    }


    /// <summary>WF-11: §4.2 MUST — a <c>resource</c> repeated in the request fails the exactly-one read and yields 400, the same as an absent one.</summary>
    [TestMethod]
    public async Task WF11_RepeatedResourceParameterYields400()
    {
        using EndpointServer server = WebFingerHttpApplication.BuildServer(StaticResolver(BuildDescriptor(Resource)));

        RequestFields fields = new();
        fields.Add(WellKnownWebFingerValues.ResourceParameterName, "acct:alice@example.com");
        fields.Add(WellKnownWebFingerValues.ResourceParameterName, "acct:bob@example.com");

        ServerHttpResponse response = await Dispatch(server, fields).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode,
            "§4.2 MUST: 'resource' present exactly once — a repeated value fails the exactly-one read.");
    }


    /// <summary>WF-13: §4.2 MUST — the resolver returning <see langword="null"/> yields 404 (no information for the resource).</summary>
    [TestMethod]
    public async Task WF13_ResolverReturningNullYields404()
    {
        using EndpointServer server = WebFingerHttpApplication.BuildServer(StaticResolver(null));

        ServerHttpResponse response = await Dispatch(server, ResourceFields(Resource)).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode, "§4.2 MUST: no information for the resource yields 404.");
    }


    /// <summary>
    /// WF-17/WF-29/WF-31/WF-32/WF-34/WF-37/WF-38/WF-44/WF-45: a normal query yields 200 with the
    /// <c>application/jrd+json</c> media type and a body that round-trips through the shipped parser —
    /// carrying a <c>subject</c> that DIFFERS from the requested resource (WF-29), non-empty
    /// <c>aliases</c> (WF-31), <c>properties</c> including a null-valued entry (WF-32), a populated
    /// <c>links</c> array (WF-34) whose entry carries <c>type</c> (WF-37), <c>href</c> (WF-38), multiple
    /// <c>titles</c> (WF-44), and link-level <c>properties</c> including a null-valued entry (WF-45).
    /// Every OPTIONAL/SHOULD member the endpoint serializes round-trips unchanged.
    /// </summary>
    [TestMethod]
    public async Task WF17_FullDescriptorRoundTripsThroughTheShippedParser()
    {
        JsonResourceDescriptor descriptor = BuildDescriptor("acct:alice.canonical@example.org");
        using EndpointServer server = WebFingerHttpApplication.BuildServer(StaticResolver(descriptor));

        ServerHttpResponse response = await Dispatch(server, ResourceFields(Resource)).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode);
        Assert.AreEqual(WellKnownWebFingerValues.JrdMediaType, response.ContentType,
            "WF-17: §4.2 MUST — the response carries the JRD media type.");

        JsonResourceDescriptor parsed = ParseBody(response);

        Assert.AreEqual("acct:alice.canonical@example.org", parsed.Subject,
            "WF-29: subject MAY differ from the requested resource and MUST be preserved verbatim.");
        Assert.HasCount(1, parsed.Aliases, "WF-31: aliases round-trip.");
        Assert.AreEqual("acct:alice.alias@example.com", parsed.Aliases[0]);
        Assert.AreEqual("Alice Example", parsed.Properties["http://example.com/ns/name"]);
        Assert.IsTrue(parsed.Properties.ContainsKey("http://example.com/ns/unset"));
        Assert.IsNull(parsed.Properties["http://example.com/ns/unset"],
            "WF-32: a null-valued property is preserved distinctly from an absent key.");
        Assert.HasCount(1, parsed.Links, "WF-34: the links array round-trips.");

        WebFingerLink link = parsed.Links[0];
        Assert.AreEqual(WebFingerLinkRelationTypes.Did, link.Rel);
        Assert.AreEqual("application/did+ld+json", link.Type, "WF-37: link type round-trips.");
        Assert.AreEqual(PublishedHref, link.Href, "WF-38: link href round-trips.");
        Assert.AreEqual("Alice's DID", link.Titles["en-us"]);
        Assert.AreEqual("Alice", link.Titles["und"]);
        Assert.HasCount(2, link.Titles, "WF-44: multiple titles round-trip.");
        Assert.AreEqual("value", link.Properties["http://example.com/ns/link-prop"]);
        Assert.IsTrue(link.Properties.ContainsKey("http://example.com/ns/link-prop-unset"));
        Assert.IsNull(link.Properties["http://example.com/ns/link-prop-unset"],
            "WF-45: a null-valued link property is preserved distinctly from an absent key.");
    }


    /// <summary>WF-19: §4.2 MUST — an unsupported <c>Accept</c> header is silently ignored; the endpoint still answers 200 JRD, never 406.</summary>
    [TestMethod]
    public async Task WF19_UnsupportedAcceptHeaderStillYieldsTheJrdNeverA406()
    {
        using EndpointServer server = WebFingerHttpApplication.BuildServer(StaticResolver(BuildDescriptor(Resource)));

        RequestHeaders headers = new(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["Accept"] = ["application/xrd+xml"]
        });

        ServerHttpResponse response = await Dispatch(server, ResourceFields(Resource), headers).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, "§4.2 MUST: an unrecognised Accept value is silently ignored, never a 406.");
        Assert.AreEqual(WellKnownWebFingerValues.JrdMediaType, response.ContentType);
    }


    /// <summary>
    /// WF-20/WF-21/WF-51 (N/A, documented): the library never redirects a WebFinger query — every
    /// outcome is a direct response over the original connection, so there is no hosted-topology
    /// redirect to assert a scheme on.
    /// </summary>
    [TestMethod]
    public async Task WF20_WF21_WF51_TheEndpointNeverRedirects()
    {
        using EndpointServer server = WebFingerHttpApplication.BuildServer(StaticResolver(BuildDescriptor(Resource)));

        ServerHttpResponse response = await Dispatch(server, ResourceFields(Resource)).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode);
        Assert.IsNull(response.Location, "WF-20/WF-21/WF-51: the endpoint never redirects — there is no hosted-topology forwarding to a distinct hosted service URI.");
    }


    /// <summary>
    /// WF-27 (N/A, documented vacuous): §4.3 "MUST ignore rel if unsupported" has no unsupported case
    /// to hit, because rel support is unconditional (WF-26) — an unrecognised relation type is threaded
    /// through to the resolver exactly like any other, never rejected by the endpoint.
    /// </summary>
    [TestMethod]
    public async Task WF27_AnUnrecognisedRelationTypeIsThreadedThroughNeverRejected()
    {
        using EndpointServer server = WebFingerHttpApplication.BuildServer(StaticResolver(BuildDescriptor(Resource)));

        RequestFields fields = ResourceFields(Resource);
        fields.Add(WellKnownWebFingerValues.RelParameterName, "urn:example:not-a-registered-relation-type");

        ServerHttpResponse response = await Dispatch(server, fields).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            "WF-27: an unrecognised/unsupported rel value MUST NOT be rejected by the endpoint.");
    }


    /// <summary>WF-25: a resolver link whose <c>rel</c> does not match the requested filter passes through unchanged — the endpoint applies no filtering of its own.</summary>
    [TestMethod]
    public async Task WF25_NonMatchingLinksPassThroughUnchanged()
    {
        const string unrelatedRelation = "urn:webfinger:something-else";
        JsonResourceDescriptor descriptor = new()
        {
            Subject = Resource,
            Links = [new WebFingerLink { Rel = unrelatedRelation }]
        };
        using EndpointServer server = WebFingerHttpApplication.BuildServer(StaticResolver(descriptor));

        RequestFields fields = ResourceFields(Resource);
        fields.Add(WellKnownWebFingerValues.RelParameterName, WebFingerLinkRelationTypes.Did);

        ServerHttpResponse response = await Dispatch(server, fields).ConfigureAwait(false);

        JsonResourceDescriptor parsed = ParseBody(response);
        Assert.HasCount(1, parsed.Links,
            "WF-25: the endpoint MUST pass a non-matching link through unchanged — filtering by rel is the resolver's job, not the endpoint's.");
        Assert.AreEqual(unrelatedRelation, parsed.Links[0].Rel);
    }


    /// <summary>WF-26: the resolver receives every <c>rel</c> occurrence the request carried.</summary>
    [TestMethod]
    public async Task WF26_TheResolverReceivesEveryRelOccurrenceTheRequestCarried()
    {
        List<string>? captured = null;
        ResolveWebFingerResourceDelegate resolve = (resource, relFilters, registration, context, ct) =>
        {
            captured = [.. relFilters];
            return ValueTask.FromResult<JsonResourceDescriptor?>(BuildDescriptor(resource));
        };
        using EndpointServer server = WebFingerHttpApplication.BuildServer(resolve);

        RequestFields fields = ResourceFields(Resource);
        fields.Add(WellKnownWebFingerValues.RelParameterName, WebFingerLinkRelationTypes.Did);
        fields.Add(WellKnownWebFingerValues.RelParameterName, "http://openid.net/specs/connect/1.0/issuer");

        _ = await Dispatch(server, fields).ConfigureAwait(false);

        Assert.IsNotNull(captured);
        Assert.HasCount(2, captured);
        Assert.AreEqual(WebFingerLinkRelationTypes.Did, captured[0]);
        Assert.AreEqual("http://openid.net/specs/connect/1.0/issuer", captured[1]);
    }


    /// <summary>WF-35/WF-36: a serialized link always carries a single, present <c>rel</c> — structural on <see cref="WebFingerLink.Rel"/>, proven here through the wire round-trip.</summary>
    [TestMethod]
    public async Task WF35_WF36_ASerializedLinkCarriesExactlyOnePresentRel()
    {
        using EndpointServer server = WebFingerHttpApplication.BuildServer(StaticResolver(BuildDescriptor(Resource)));

        ServerHttpResponse response = await Dispatch(server, ResourceFields(Resource)).ConfigureAwait(false);

        JsonResourceDescriptor parsed = ParseBody(response);
        Assert.HasCount(1, parsed.Links);
        Assert.IsFalse(string.IsNullOrEmpty(parsed.Links[0].Rel), "WF-36: rel MUST be present.");
        Assert.AreEqual(WebFingerLinkRelationTypes.Did, parsed.Links[0].Rel, "WF-35: rel is exactly one relation type.");
    }


    /// <summary>WF-46: the §5 CORS header is present on the 200, the 400, and the 404 alike.</summary>
    [TestMethod]
    public async Task WF46_AccessControlAllowOriginIsPresentOnSuccessBadRequestAndNotFound()
    {
        using EndpointServer successServer = WebFingerHttpApplication.BuildServer(StaticResolver(BuildDescriptor(Resource)));
        ServerHttpResponse okResponse = await Dispatch(successServer, ResourceFields(Resource)).ConfigureAwait(false);
        AssertHasCorsHeader(okResponse);

        ServerHttpResponse badRequestResponse = await Dispatch(successServer, new RequestFields()).ConfigureAwait(false);
        AssertHasCorsHeader(badRequestResponse);

        using EndpointServer notFoundServer = WebFingerHttpApplication.BuildServer(StaticResolver(null));
        ServerHttpResponse notFoundResponse = await Dispatch(notFoundServer, ResourceFields(Resource)).ConfigureAwait(false);
        AssertHasCorsHeader(notFoundResponse);
    }


    /// <summary>WF-47: the default (unwired CORS resolver) Access-Control-Allow-Origin value is the wildcard.</summary>
    [TestMethod]
    public async Task WF47_DefaultAccessControlAllowOriginIsTheWildcard()
    {
        using EndpointServer server = WebFingerHttpApplication.BuildServer(StaticResolver(BuildDescriptor(Resource)));

        ServerHttpResponse response = await Dispatch(server, ResourceFields(Resource)).ConfigureAwait(false);

        Assert.AreEqual(
            WellKnownWebFingerValues.AccessControlAllowOriginWildcard,
            response.Headers[WellKnownWebFingerValues.AccessControlAllowOriginHeaderName]);
    }


    /// <summary>WF-48/WF-49: a wired <see cref="ResolveCorsOriginDelegate"/> produces its specific origin, never the wildcard.</summary>
    [TestMethod]
    public async Task WF48_WF49_AWiredCorsResolverProducesTheSpecificOriginNeverTheWildcard()
    {
        const string trustedOrigin = "https://intranet.example.internal";
        using EndpointServer server = WebFingerHttpApplication.BuildServer(
            StaticResolver(BuildDescriptor(Resource)),
            static (registration, context, ct) => ValueTask.FromResult(trustedOrigin));

        ServerHttpResponse response = await Dispatch(server, ResourceFields(Resource)).ConfigureAwait(false);

        string corsHeader = response.Headers[WellKnownWebFingerValues.AccessControlAllowOriginHeaderName];
        Assert.AreEqual(trustedOrigin, corsHeader);
        Assert.AreNotEqual(WellKnownWebFingerValues.AccessControlAllowOriginWildcard, corsHeader,
            "WF-48/WF-49: a deployment restricting access MUST see its specific origin, never the wildcard.");
    }


    /// <summary>WF-50: the resolver reads a per-request signal off <see cref="ExchangeContext"/> and answers two requests differently — §6 MAY vary the response per client factors.</summary>
    [TestMethod]
    public async Task WF50_TheResolverMayVaryTheResponsePerRequestContext()
    {
        const string signalKey = "test.webfinger.signal";
        ResolveWebFingerResourceDelegate resolve = (resource, relFilters, registration, context, ct) =>
        {
            string signal = context.TryGetValue(signalKey, out object? value) && value is string s ? s : "default";
            return ValueTask.FromResult<JsonResourceDescriptor?>(new JsonResourceDescriptor { Subject = $"acct:{signal}@example.com" });
        };
        using EndpointServer server = WebFingerHttpApplication.BuildServer(resolve);

        ExchangeContext contextA = new() { [signalKey] = "alice" };
        ExchangeContext contextB = new() { [signalKey] = "bob" };

        ServerHttpResponse responseA = await server.DispatchAsync(
            BuildRequest(ResourceFields(Resource)), contextA, TestContext.CancellationToken).ConfigureAwait(false);
        ServerHttpResponse responseB = await server.DispatchAsync(
            BuildRequest(ResourceFields(Resource)), contextB, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual(responseA.Body, responseB.Body,
            "WF-50: two requests differing only in a per-request context signal MAY receive different responses.");
        Assert.Contains("alice", responseA.Body);
        Assert.Contains("bob", responseB.Body);
    }


    /// <summary>
    /// Regression (adversarial finding): a GET to a path OTHER than <c>/.well-known/webfinger</c> does not
    /// match the endpoint and yields 404, even when the resolver would answer — proving the path-match branch
    /// (<c>WebFingerEndpoints.MatchesRequest</c>) is load-bearing: a "match any GET" mutation would fail here.
    /// </summary>
    [TestMethod]
    public async Task ARequestToAnotherPathDoesNotMatchAndYields404()
    {
        using EndpointServer server = WebFingerHttpApplication.BuildServer(StaticResolver(BuildDescriptor(Resource)));

        IncomingRequest wrongPath = new(
            Path: "/.well-known/not-webfinger",
            Method: WellKnownHttpMethods.Get,
            Fields: ResourceFields(Resource),
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty);

        ServerHttpResponse response = await server.DispatchAsync(
            wrongPath, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode,
            "The endpoint MUST match only the well-known WebFinger path — another path is not served, even with a resolver that would answer.");
    }


    /// <summary>
    /// WF-12 (malformed): §4.2 MUST — a present-but-empty <c>resource</c> is malformed and yields 400 before
    /// the resolver is consulted, not forwarded as an empty query target.
    /// </summary>
    [TestMethod]
    public async Task WF12_EmptyResourceParameterYields400()
    {
        bool resolverConsulted = false;
        ResolveWebFingerResourceDelegate resolve = (resource, relFilters, registration, context, ct) =>
        {
            resolverConsulted = true;
            return ValueTask.FromResult<JsonResourceDescriptor?>(BuildDescriptor(resource));
        };
        using EndpointServer server = WebFingerHttpApplication.BuildServer(resolve);

        RequestFields fields = new();
        fields.Add(WellKnownWebFingerValues.ResourceParameterName, string.Empty);

        ServerHttpResponse response = await Dispatch(server, fields).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, "§4.2 MUST: a present-but-empty 'resource' is malformed → 400.");
        Assert.IsFalse(resolverConsulted, "A malformed 'resource' MUST be rejected before the resolver is consulted.");
    }


    /// <summary>
    /// WF-46 regression (adversarial finding): §5 MUST — the Access-Control-Allow-Origin header rides EVERY
    /// response, including one produced when the application resolver THROWS. The endpoint guards the resolver
    /// call so a fault becomes a CORS-stamped 500, not a header-less error.
    /// </summary>
    [TestMethod]
    public async Task WF46_CorsHeaderIsPresentEvenWhenTheResolverThrows()
    {
        ResolveWebFingerResourceDelegate faulting =
            (resource, relFilters, registration, context, ct) => throw new InvalidOperationException("resolver failure");
        using EndpointServer server = WebFingerHttpApplication.BuildServer(faulting);

        ServerHttpResponse response = await Dispatch(server, ResourceFields(Resource)).ConfigureAwait(false);

        Assert.AreEqual(500, response.StatusCode, "A resolver fault surfaces as a server error.");
        AssertHasCorsHeader(response);
    }


    /// <summary>Builds a full descriptor exercising every OPTIONAL/SHOULD member (aliases, properties incl. a null value, one link with type/href/titles/link-properties incl. a null value).</summary>
    private static JsonResourceDescriptor BuildDescriptor(string subject) => new()
    {
        Subject = subject,
        Aliases = ["acct:alice.alias@example.com"],
        Properties = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["http://example.com/ns/name"] = "Alice Example",
            ["http://example.com/ns/unset"] = null
        },
        Links =
        [
            new WebFingerLink
            {
                Rel = WebFingerLinkRelationTypes.Did,
                Type = "application/did+ld+json",
                Href = PublishedHref,
                Titles = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["en-us"] = "Alice's DID",
                    ["und"] = "Alice"
                },
                Properties = new Dictionary<string, string?>(StringComparer.Ordinal)
                {
                    ["http://example.com/ns/link-prop"] = "value",
                    ["http://example.com/ns/link-prop-unset"] = null
                }
            }
        ]
    };


    /// <summary>A <see cref="ResolveWebFingerResourceDelegate"/> that ignores its input and always answers <paramref name="descriptor"/>.</summary>
    private static ResolveWebFingerResourceDelegate StaticResolver(JsonResourceDescriptor? descriptor) =>
        (resource, relFilters, registration, context, ct) => ValueTask.FromResult(descriptor);


    /// <summary>Builds a <see cref="RequestFields"/> carrying only the <c>resource</c> parameter.</summary>
    private static RequestFields ResourceFields(string resource)
    {
        RequestFields fields = new();
        fields.Add(WellKnownWebFingerValues.ResourceParameterName, resource);
        return fields;
    }


    /// <summary>Builds a GET request against the well-known WebFinger path with the given fields and headers.</summary>
    private static IncomingRequest BuildRequest(RequestFields fields, RequestHeaders? headers = null) =>
        new(
            Path: WellKnownWebFingerValues.WellKnownPath,
            Method: WellKnownHttpMethods.Get,
            Fields: fields,
            Headers: headers ?? RequestHeaders.Empty,
            RouteValues: RouteValues.Empty);


    /// <summary>Dispatches a fresh request against <paramref name="server"/> through the real <see cref="EndpointServer.DispatchAsync"/>.</summary>
    private ValueTask<ServerHttpResponse> Dispatch(EndpointServer server, RequestFields fields, RequestHeaders? headers = null) =>
        server.DispatchAsync(BuildRequest(fields, headers), new ExchangeContext(), TestContext.CancellationToken);


    /// <summary>WF-46: asserts the §5 CORS header is present on <paramref name="response"/>.</summary>
    private static void AssertHasCorsHeader(ServerHttpResponse response) =>
        Assert.IsTrue(response.Headers.ContainsKey(WellKnownWebFingerValues.AccessControlAllowOriginHeaderName),
            "§5 MUST: every response — success or failure — carries Access-Control-Allow-Origin.");


    /// <summary>Parses a response body through the shipped JRD parser, wrapping the UTF-8 bytes in the tracked carrier.</summary>
    private static JsonResourceDescriptor ParseBody(ServerHttpResponse response)
    {
        TaggedMemory<byte> bytes = new(Encoding.UTF8.GetBytes(response.Body), BufferTags.Json);
        JsonResourceDescriptor? parsed = WebFingerJrdJsonParsing.ParseJrd(bytes.Span);

        Assert.IsNotNull(parsed, "The endpoint's own serialized body MUST parse through the shipped JRD parser.");

        return parsed!;
    }
}
