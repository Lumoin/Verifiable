using System.Net;
using System.Net.Http;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.OAuth.Federation;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Tests for <see cref="FederationHttpClientTransport"/> — the
/// HttpClient-backed delegate wiring lives in test infrastructure per
/// the library's transport-agnostic discipline.
/// </summary>
[TestClass]
internal sealed class FederationHttpClientTransportTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task FetchEntityStatementRoundTripsViaMockHandler()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));

        //Mint a real signed Entity Configuration via the test ring; the
        //mock HTTP handler will serve its compact JWS in response to a
        //fetch request.
        MintedStatement minted = await FederationTestRing.MintEntityConfigurationAsync(
            subject, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using CannedJwsHandler handler = new(minted.CompactJws);
        using HttpClient httpClient = new(handler, disposeHandler: false);

        FetchEntityStatementDelegate fetch =
            FederationHttpClientTransport.BuildFetchEntityStatement(httpClient);

        FetchedEntityStatement? result = await fetch(
            subject.Identifier,
            new Uri("https://example.test/.well-known/openid-federation"),
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result, "Mock handler should produce a parseable fetched statement.");
        Assert.AreEqual(subject.Identifier.Value, result.Statement.Issuer.Value);
        Assert.AreEqual(subject.Identifier.Value, result.Statement.Subject.Value,
            "Subject EC has iss == sub by definition.");
        Assert.AreEqual(minted.CompactJws, result.CompactJws);
    }


    [TestMethod]
    public async Task FetchEntityStatementReturnsNullOn404()
    {
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));

        using NotFoundHandler handler = new();
        using HttpClient httpClient = new(handler, disposeHandler: false);

        FetchEntityStatementDelegate fetch =
            FederationHttpClientTransport.BuildFetchEntityStatement(httpClient);

        FetchedEntityStatement? result = await fetch(
            subject.Identifier,
            new Uri("https://example.test/.well-known/openid-federation"),
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(result, "404 response should produce null.");
    }


    [TestMethod]
    public async Task FetchEntityStatementBlocksRedirectToInternalAddress()
    {
        //Proof that the guarded OutboundFetch governs the real HttpClient path:
        //a fetch that 302s to a link-local/metadata address is blocked per-hop,
        //and the internal target is never contacted.
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));

        using RedirectHandler handler = new(
            new Uri("https://169.254.169.254/.well-known/openid-federation"));
        using HttpClient httpClient = new(handler, disposeHandler: false);

        FetchEntityStatementDelegate fetch =
            FederationHttpClientTransport.BuildFetchEntityStatement(httpClient);

        ExchangeContext context = new();
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault with
        {
            Redirects = RedirectMode.PolicyChecked,
            MaxRedirects = 3,
        });

        FetchedEntityStatement? result = await fetch(
            subject.Identifier,
            new Uri("https://example.test/.well-known/openid-federation"),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(result,
            "A fetch that redirects to a link-local/metadata address must be blocked, not followed.");
        Assert.AreEqual(1, handler.RequestCount,
            "Only the initial endpoint is contacted; the internal redirect target is never reached.");
    }


    /// <summary>
    /// Handler that returns a fixed compact JWS body with the
    /// trust-mark-friendly entity-statement media type for any GET.
    /// </summary>
    private sealed class CannedJwsHandler: HttpMessageHandler
    {
        private readonly string compactJws;

        public CannedJwsHandler(string compactJws)
        {
            this.compactJws = compactJws;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            //Content-Type at the HTTP level is application/entity-statement+jwt
            //per §8.1. The parser does not enforce the HTTP media type — it
            //relies on the JWT 'typ' header for cross-JWT confusion defense
            //per RFC 8725 — so this canned handler is content-type agnostic.
            HttpResponseMessage response = new(HttpStatusCode.OK)
            {
                Content = new StringContent(compactJws, System.Text.Encoding.UTF8),
            };
            return Task.FromResult(response);
        }
    }


    private sealed class NotFoundHandler: HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }


    /// <summary>
    /// Handler that 302-redirects every request to a fixed <c>Location</c> and
    /// counts how many requests it received — used to prove the guarded fetch
    /// blocks a redirect to an internal address before contacting it.
    /// </summary>
    private sealed class RedirectHandler: HttpMessageHandler
    {
        private readonly Uri location;

        public RedirectHandler(Uri location)
        {
            this.location = location;
        }

        public int RequestCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestCount++;
            HttpResponseMessage response = new(HttpStatusCode.Found)
            {
                Content = new StringContent(string.Empty),
            };
            response.Headers.Location = location;
            return Task.FromResult(response);
        }
    }
}
