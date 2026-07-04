using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.DidWebs;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.WebFinger;

namespace Verifiable.Tests.WebFinger;

/// <summary>
/// A REAL two-node firewalled cross-wire WebFinger flow: Node A is the real
/// <see cref="EndpointServer.DispatchAsync"/> path (through <see cref="WebFingerHttpApplication"/>)
/// hosted over a genuine HTTPS loopback socket; Node B is the real
/// <see cref="WebFingerClient.BuildResolving"/> resolve delegate, driven by an
/// <see cref="HttpClient"/>-backed <see cref="OutboundTransportDelegate"/> through the guarded
/// <see cref="OutboundFetch"/> chokepoint. Mirrors the proven pattern in
/// <c>Verifiable.Tests.Resolver.WebVhCrossWireFlowTests</c>, adapted for RFC 7033's HTTPS-only client
/// (no scheme rebasing transport is needed: <see cref="WebFingerResolveDelegate"/> takes the query host
/// as an explicit parameter, so it is pointed directly at Node A's real loopback authority).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Firewall discipline.</strong> Node B receives NOTHING from Node A except the bytes that
/// crossed the socket. Node A's resolver constructs a fresh <see cref="JsonResourceDescriptor"/> inside
/// its own delegate closure, on Node A's side of the dispatch; Node B never touches that object or any
/// reference to it — it reconstructs its own <see cref="JsonResourceDescriptor"/> purely by parsing the
/// HTTP response bytes through <see cref="WebFingerJrdJsonParsing.ParseJrd"/>. The only thing shared
/// between the two halves of a test method is a literal string constant (the published DID) that both
/// sides independently reference — exactly the relationship a real handle-to-DID discovery has, not an
/// in-memory backchannel.
/// </para>
/// <para>
/// <strong>HTTPS loopback + certificate trust.</strong> Node A (<see cref="WebFingerHttpApplication.Host"/>)
/// binds Kestrel to the loopback socket with <c>UseHttps</c> and a fresh self-signed leaf certificate —
/// there is no plaintext HTTP listener on that node at all, so the transport cannot silently fall back to
/// an insecure connection. Node B's <see cref="HttpClient"/> is built with a
/// <c>ServerCertificateCustomValidationCallback</c> that pins to that EXACT certificate (byte-for-byte,
/// via <see cref="CryptographicOperations.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>) —
/// RFC 7033 §9.1's "verify the certificate is valid" MUST, satisfied by explicit pinning rather than a CA
/// chain (there is no CA in this loopback topology) and never by disabling validation.
/// </para>
/// </remarks>
[TestClass]
internal sealed class WebFingerCrossWireFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string PublishedDid = "did:webs:example.com:EKTh4PkRBiNWHQd263Eueu39gWmg7AfIfnEmNy6jinGR";


    /// <summary>
    /// The full happy-path cross-wire flow: Node A publishes a JRD whose sole link is the subject's DID
    /// under <see cref="WebFingerLinkRelationTypes.Did"/>; Node B resolves it purely from the wire and
    /// recovers the same href. Proves WF-1/WF-14/WF-64/WF-65 (the whole exchange is HTTPS, no HTTP leg
    /// exists at all), WF-46/WF-47 (the CORS header rides the wire with the default wildcard),
    /// WF-13's positive counterpart (a real 200 over the socket), and WF-66's positive half (the pinned
    /// certificate is accepted). Closes the loop by feeding the resolved href into the REAL
    /// <see cref="WebsDidResolver"/>.
    /// </summary>
    [TestMethod]
    public async Task ResolvesAWebsHrefAcrossTheWireAndClosesTheLoopIntoDidWebsResolution()
    {
        const string resource = "acct:alice@example.com";

        using EndpointServer server = WebFingerHttpApplication.BuildServer(
            static (queryResource, relFilters, registration, context, ct) => ValueTask.FromResult<JsonResourceDescriptor?>(
                new JsonResourceDescriptor
                {
                    Subject = queryResource,
                    Links = [new WebFingerLink { Rel = WebFingerLinkRelationTypes.Did, Href = PublishedDid }]
                }));

        await using WebFingerHttpApplication.Host nodeA = await WebFingerHttpApplication.Host.StartAsync(
            server, TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient httpClient = CreatePinnedHttpClient(nodeA.Certificate);
        TransportSpy spy = new(GuardedHttpClientTransport.BuildSingleHopTransport(httpClient));
        WebFingerResolveDelegate resolve = WebFingerClient.BuildResolving(spy.Delegate, WebFingerJrdJsonParsing.ParseJrd);

        string host = $"{nodeA.BaseAddress.Host}:{nodeA.BaseAddress.Port}";
        ExchangeContext context = NewLoopbackContext();

        WebFingerResolutionResult result = await resolve(
            resource, host, [WebFingerLinkRelationTypes.Did], context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"Resolution across the wire MUST succeed. Error: {result.Error?.Code}.");

        //Node B reconstructed this purely from the wire bytes — see the type remarks for the firewall
        //discipline; only the literal PublishedDid constant is shared between the two sides.
        string? resolvedHref = WebFingerClient.FindLinkHref(result.Jrd!, WebFingerLinkRelationTypes.Did);
        Assert.AreEqual(PublishedDid, resolvedHref, "The resolved href MUST equal the DID Node A published.");

        Assert.IsNotNull(spy.LastRequest);
        Assert.AreEqual(Uri.UriSchemeHttps, spy.LastRequest!.Target.Scheme,
            "WF-1/WF-14/WF-64/WF-65: the whole exchange MUST be https — Node A has no plaintext HTTP listener, so there is no http leg to fall back to.");

        Assert.IsNotNull(spy.LastResponse);
        Assert.IsTrue(spy.LastResponse!.TryGetHeader("Content-Type", out string? contentType));
        Assert.StartsWith(WellKnownWebFingerValues.JrdMediaType, contentType!,
            "The Content-Type over the wire MUST be application/jrd+json.");
        Assert.IsTrue(
            spy.LastResponse.TryGetHeader(WellKnownWebFingerValues.AccessControlAllowOriginHeaderName, out string? corsHeader),
            "WF-46: the Access-Control-Allow-Origin header MUST be present over the wire.");
        Assert.AreEqual(WellKnownWebFingerValues.AccessControlAllowOriginWildcard, corsHeader,
            "WF-47: the default value is the wildcard.");

        Assert.IsTrue(
            nodeA.WasRequestedWithQueryContaining($"{WellKnownWebFingerValues.ResourceParameterName}="),
            "The 'resource' query parameter MUST have crossed the real socket.");
        Assert.IsTrue(
            nodeA.WasRequestedWithQueryContaining($"{WellKnownWebFingerValues.RelParameterName}="),
            "The 'rel' query parameter MUST have crossed the real socket.");

        //CLOSE THE LOOP: feed the resolved handle -> DID string into the REAL did:webs resolver.
        //WebFinger discovery slots directly into the existing DID pipeline; it is not an isolated
        //round trip.
        string didDocumentUrl = WebsDidResolver.Resolve(resolvedHref!);
        string keriEventStreamUrl = WebsDidResolver.ResolveKeriEventStreamUrl(resolvedHref!);

        Assert.AreEqual(
            "https://example.com/EKTh4PkRBiNWHQd263Eueu39gWmg7AfIfnEmNy6jinGR/did.json", didDocumentUrl,
            "The resolved handle -> DID MUST transform to its did:webs document URL exactly like any other did:webs identifier.");
        Assert.AreEqual(
            "https://example.com/EKTh4PkRBiNWHQd263Eueu39gWmg7AfIfnEmNy6jinGR/keri.cesr", keriEventStreamUrl);
    }


    /// <summary>WF-13 (negative): a resolver with no information for the resource yields a real 404 over the socket, which the client maps to <see cref="WebFingerResolutionErrors.NotFound"/>.</summary>
    [TestMethod]
    public async Task WF13_ResolverReturningNullYieldsARealNotFoundOverTheSocket()
    {
        using EndpointServer server = WebFingerHttpApplication.BuildServer(
            static (resource, relFilters, registration, context, ct) => ValueTask.FromResult<JsonResourceDescriptor?>(null));

        await using WebFingerHttpApplication.Host nodeA = await WebFingerHttpApplication.Host.StartAsync(
            server, TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient httpClient = CreatePinnedHttpClient(nodeA.Certificate);
        OutboundTransportDelegate transport = GuardedHttpClientTransport.BuildSingleHopTransport(httpClient);
        WebFingerResolveDelegate resolve = WebFingerClient.BuildResolving(transport, WebFingerJrdJsonParsing.ParseJrd);

        string host = $"{nodeA.BaseAddress.Host}:{nodeA.BaseAddress.Port}";
        WebFingerResolutionResult result = await resolve(
            "acct:nobody@example.com", host, [], NewLoopbackContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "WF-13: a resolver with no information for the resource MUST NOT resolve.");
        Assert.AreEqual(WebFingerResolutionErrors.NotFound, result.Error);
        Assert.IsTrue(nodeA.WasRequestedWithQueryContaining($"{WellKnownWebFingerValues.ResourceParameterName}="),
            "The 404 MUST have come from a real request over the socket, not an in-memory transport.");
    }


    /// <summary>
    /// WF-11 (negative): a request whose query string carries <c>resource</c> twice — constructed
    /// directly rather than through <see cref="WebFingerClient.ComputeQueryUri"/>, which structurally
    /// emits it exactly once — reaches Node A's own §4.2 defence and yields a real 400 over the socket.
    /// </summary>
    [TestMethod]
    public async Task WF11_ARepeatedResourceParameterYieldsARealBadRequestOverTheSocket()
    {
        using EndpointServer server = WebFingerHttpApplication.BuildServer(
            static (resource, relFilters, registration, context, ct) => ValueTask.FromResult<JsonResourceDescriptor?>(
                new JsonResourceDescriptor { Subject = resource }));

        await using WebFingerHttpApplication.Host nodeA = await WebFingerHttpApplication.Host.StartAsync(
            server, TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient httpClient = CreatePinnedHttpClient(nodeA.Certificate);

        Uri target = new(
            $"{nodeA.BaseAddress.Scheme}://{nodeA.BaseAddress.Host}:{nodeA.BaseAddress.Port}{WellKnownWebFingerValues.WellKnownPath}"
            + "?resource=acct%3Aalice%40example.com&resource=acct%3Abob%40example.com");

        using HttpResponseMessage response = await httpClient.GetAsync(target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode,
            "WF-11: a 'resource' parameter repeated in the query string MUST yield a real 400 over the socket.");
    }


    /// <summary>
    /// WF-66 (negative): the transport is pinned to a TRUSTED node's certificate but dials a different
    /// node presenting an UNtrusted (different) self-signed leaf — the certificate MUST NOT be accepted,
    /// and resolution MUST fail rather than silently proceeding. No validation is ever disabled to make
    /// this pass; the trusted node is never contacted at all.
    /// </summary>
    [TestMethod]
    public async Task WF66_AnUntrustedCertificateIsNeverAcceptedAndResolutionFails()
    {
        using EndpointServer trustedServer = WebFingerHttpApplication.BuildServer(
            static (resource, relFilters, registration, context, ct) => ValueTask.FromResult<JsonResourceDescriptor?>(
                new JsonResourceDescriptor { Subject = resource }));
        using EndpointServer impostorServer = WebFingerHttpApplication.BuildServer(
            static (resource, relFilters, registration, context, ct) => ValueTask.FromResult<JsonResourceDescriptor?>(
                new JsonResourceDescriptor { Subject = resource }));

        await using WebFingerHttpApplication.Host trustedNode = await WebFingerHttpApplication.Host.StartAsync(
            trustedServer, TestContext.CancellationToken).ConfigureAwait(false);
        await using WebFingerHttpApplication.Host impostorNode = await WebFingerHttpApplication.Host.StartAsync(
            impostorServer, TestContext.CancellationToken).ConfigureAwait(false);

        //Pin to the TRUSTED node's certificate, then dial the IMPOSTOR node, which presents a different
        //self-signed leaf.
        using HttpClient httpClient = CreatePinnedHttpClient(trustedNode.Certificate);
        OutboundTransportDelegate transport = GuardedHttpClientTransport.BuildSingleHopTransport(httpClient);
        WebFingerResolveDelegate resolve = WebFingerClient.BuildResolving(transport, WebFingerJrdJsonParsing.ParseJrd);

        string impostorHost = $"{impostorNode.BaseAddress.Host}:{impostorNode.BaseAddress.Port}";
        WebFingerResolutionResult result = await resolve(
            "acct:alice@example.com", impostorHost, [], NewLoopbackContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "WF-66: an untrusted (non-pinned) certificate MUST NOT be accepted.");
        Assert.AreEqual(WebFingerResolutionErrors.TransportFailure, result.Error);
        Assert.AreEqual(0, impostorNode.TotalRequests,
            "The TLS handshake MUST fail before the impostor node ever answers an application-layer request.");
    }


    /// <summary>
    /// A fresh <see cref="ExchangeContext"/> whose policy allows loopback so the genuine
    /// <c>https://127.0.0.1:{port}</c> target the test points the client at is permitted — mirroring
    /// <c>WebVhCrossWireFlowTests.NewLoopbackContext</c>. Production keeps
    /// <see cref="OutboundFetchPolicy.SecureDefault"/>, under which a loopback target is denied before
    /// any network contact.
    /// </summary>
    private static ExchangeContext NewLoopbackContext()
    {
        ExchangeContext context = new();
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault with { BlockPrivateAndLoopback = false });

        return context;
    }


    /// <summary>
    /// Builds an <see cref="HttpClient"/> whose TLS validation pins to <paramref name="pinnedCertificate"/>
    /// byte-for-byte — RFC 7033 §9.1's "verify the certificate is valid" MUST, satisfied by explicit
    /// pinning (there is no CA in this loopback topology) rather than by disabling validation.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "HttpClient takes ownership of the handler (default disposeHandler: true) and disposes it when the returned client is disposed via the caller's using declaration.")]
    private static HttpClient CreatePinnedHttpClient(X509Certificate2 pinnedCertificate) =>
        new(new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (requestMessage, certificate, chain, sslPolicyErrors) =>
                certificate is not null
                && CryptographicOperations.FixedTimeEquals(certificate.RawData, pinnedCertificate.RawData)
        });


    /// <summary>
    /// Wraps a single-hop <see cref="OutboundTransportDelegate"/> to record the last request/response
    /// pair the guarded fetch drove through it, without altering the exchange — used to assert wire-level
    /// details (scheme, headers) the <see cref="WebFingerResolutionResult"/> itself does not carry.
    /// </summary>
    private sealed class TransportSpy
    {
        private readonly OutboundTransportDelegate inner;


        /// <summary>Wraps <paramref name="inner"/>, recording every request/response pair it drives.</summary>
        public TransportSpy(OutboundTransportDelegate inner)
        {
            this.inner = inner;
        }


        /// <summary>The last request the wrapped transport sent.</summary>
        public OutboundRequest? LastRequest { get; private set; }

        /// <summary>The last response the wrapped transport received.</summary>
        public OutboundResponse? LastResponse { get; private set; }

        /// <summary>The wrapped transport delegate to hand to the guarded fetch.</summary>
        public OutboundTransportDelegate Delegate => InvokeAsync;


        private async ValueTask<OutboundResponse> InvokeAsync(
            OutboundRequest request, ExchangeContext context, CancellationToken cancellationToken)
        {
            LastRequest = request;
            OutboundResponse response = await inner(request, context, cancellationToken).ConfigureAwait(false);
            LastResponse = response;

            return response;
        }
    }
}
