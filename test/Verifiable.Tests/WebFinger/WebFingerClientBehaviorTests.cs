using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.Json;
using Verifiable.WebFinger;

namespace Verifiable.Tests.WebFinger;

/// <summary>
/// Tests for <see cref="WebFingerClient.BuildResolving"/> — the resolve delegate that computes the query URI,
/// drives the guarded <see cref="OutboundFetch"/> chokepoint, and parses the response with the shipped JRD
/// parser (<see cref="WebFingerJrdJsonParsing.ParseJrd"/>). The single-hop transport is an IN-MEMORY fake (no
/// real socket, matching the established <c>did:web</c>/<c>did:webvh</c> resolver test pattern) so the happy
/// path, the error mapping, and the §4.2/§9.1 "accept failure, never retry" behaviors are exercised
/// deterministically.
/// </summary>
[TestClass]
internal sealed class WebFingerClientBehaviorTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string Resource = "acct:alice@example.com";
    private const string Host = "example.com";
    private const string QueryUrl = "https://example.com/.well-known/webfinger?resource=acct%3Aalice%40example.com";


    /// <summary>The happy path: a 200 response carrying a well-formed JRD resolves to a Success result.</summary>
    [TestMethod]
    public async Task ResolvesSuccessfullyAndParsesTheJrdBody()
    {
        const string jrdJson = """
        {"subject":"acct:alice@example.com","links":[{"rel":"urn:webfinger:did","href":"did:webs:example.com:AID"}]}
        """;
        FakeTransport transport = FakeTransport.RespondingWith(QueryUrl, 200, jrdJson);

        WebFingerResolutionResult result = await Resolve(transport).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"Resolution MUST succeed. Error: {result.Error?.Code}.");
        Assert.IsNotNull(result.Jrd);
        Assert.AreEqual("acct:alice@example.com", result.Jrd!.Subject);
        Assert.AreEqual("did:webs:example.com:AID", WebFingerClient.FindLinkHref(result.Jrd, WebFingerLinkRelationTypes.Did));
    }


    /// <summary>A non-200 response at the WebFinger resource maps to <see cref="WebFingerResolutionErrors.NotFound"/>.</summary>
    [TestMethod]
    public async Task NonSuccessStatusYieldsNotFound()
    {
        FakeTransport transport = FakeTransport.RespondingWith(QueryUrl, 404, null);

        WebFingerResolutionResult result = await Resolve(transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(WebFingerResolutionErrors.NotFound, result.Error);
    }


    /// <summary>A 200 response whose body is not well-formed JSON maps to <see cref="WebFingerResolutionErrors.InvalidJrd"/>.</summary>
    [TestMethod]
    public async Task MalformedBodyYieldsInvalidJrd()
    {
        FakeTransport transport = FakeTransport.RespondingWith(QueryUrl, 200, "{ this is not a valid JRD");

        WebFingerResolutionResult result = await Resolve(transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(WebFingerResolutionErrors.InvalidJrd, result.Error);
    }


    /// <summary>
    /// WF-15: a transport that throws (an HTTPS connection that cannot be established) yields a
    /// <see cref="WebFingerResolutionResult.Failure"/> carrying <see cref="WebFingerResolutionErrors.TransportFailure"/> —
    /// the exception never escapes <see cref="WebFingerClient.BuildResolving"/> to the caller.
    /// </summary>
    [TestMethod]
    public async Task WF15_TransportFailureYieldsFailureResultWithoutThrowing()
    {
        FakeTransport transport = FakeTransport.ThrowingWith(new InvalidOperationException("simulated TLS handshake failure"));

        WebFingerResolutionResult result = await Resolve(transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(WebFingerResolutionErrors.TransportFailure, result.Error);
    }


    /// <summary>
    /// WF-16: the transport is invoked EXACTLY ONCE regardless of outcome — no retry, and in particular no
    /// second (non-HTTPS) request is ever constructed after a failure.
    /// </summary>
    [TestMethod]
    public async Task WF16_TransportIsInvokedExactlyOnceWithNoRetryAndNoHttpFallback()
    {
        FakeTransport transport = FakeTransport.ThrowingWith(new InvalidOperationException("simulated connection refusal"));

        _ = await Resolve(transport).ConfigureAwait(false);

        Assert.HasCount(1, transport.Calls, "The transport MUST be invoked exactly once — no retry.");
        Assert.AreEqual(Uri.UriSchemeHttps, transport.Calls[0].Target.Scheme,
            "The single call MUST be https; no second, non-secure request is ever constructed.");
    }


    /// <summary>
    /// WF-18: resolution succeeds without the client setting any <c>Accept</c> header — <c>Accept</c> is MAY,
    /// not required, for the client to send.
    /// </summary>
    [TestMethod]
    public async Task WF18_ResolutionSucceedsWithoutTheClientSettingAnAcceptHeader()
    {
        FakeTransport transport = FakeTransport.RespondingWith(QueryUrl, 200, """{"subject":"acct:alice@example.com"}""");

        WebFingerResolutionResult result = await Resolve(transport).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.HasCount(1, transport.Calls);
        Assert.IsFalse(transport.Calls[0].Headers.ContainsKey("Accept"),
            "The client MUST NOT need to set Accept for resolution to succeed.");
    }


    /// <summary>Runs the resolve delegate against the fake transport under the secure-default outbound-fetch policy.</summary>
    private async Task<WebFingerResolutionResult> Resolve(FakeTransport transport)
    {
        ExchangeContext context = new();
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        WebFingerResolveDelegate resolver = WebFingerClient.BuildResolving(transport.Delegate, WebFingerJrdJsonParsing.ParseJrd);

        return await resolver(Resource, Host, [], context, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// A single-hop, in-memory fake transport: either returns a canned (status, body) for a known URL (a 404
    /// for any other), or throws a canned exception to simulate an unreachable HTTPS endpoint. Every call is
    /// recorded so a test can assert invocation count and the exact request shape. Response bodies are carried
    /// as <see cref="TaggedMemory{T}"/>, mirroring the production <see cref="OutboundResponse"/> shape.
    /// </summary>
    private sealed class FakeTransport
    {
        private readonly Dictionary<string, (int Status, string? Body)> routes = new(StringComparer.Ordinal);
        private readonly Exception? failure;


        private FakeTransport(Exception? failure)
        {
            this.failure = failure;
        }


        public List<OutboundRequest> Calls { get; } = [];


        public static FakeTransport RespondingWith(string url, int status, string? body)
        {
            FakeTransport transport = new(failure: null);
            transport.routes[url] = (status, body);

            return transport;
        }


        public static FakeTransport ThrowingWith(Exception exception) => new(exception);


        public OutboundTransportDelegate Delegate => (request, context, cancellationToken) =>
        {
            Calls.Add(request);

            if(failure is not null)
            {
                throw failure;
            }

            if(!routes.TryGetValue(request.Target.AbsoluteUri, out (int Status, string? Body) route))
            {
                route = (404, null);
            }

            TaggedMemory<byte> body = route.Body is null
                ? TaggedMemory<byte>.Empty
                : new TaggedMemory<byte>(Encoding.UTF8.GetBytes(route.Body), BufferTags.Json);

            return ValueTask.FromResult(new OutboundResponse { StatusCode = route.Status, Body = body });
        };
    }
}
