using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Core;

/// <summary>
/// Unit tests for <see cref="OutboundFetch.FetchAsync"/> — the policy-guarded
/// redirect loop — driven by a fake single-hop transport. Proves the loop
/// re-validates every redirect hop against the policy (so a redirect to an
/// internal address is blocked), honours the redirect mode and hop cap, and
/// rewrites the method/body per HTTP redirect semantics.
/// </summary>
[TestClass]
internal sealed class OutboundFetchTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task DeniedTargetIsNotContacted()
    {
        FakeTransport transport = new();
        ExchangeContext context = Context(OutboundFetchPolicy.SecureDefault);

        OutboundFetchResult result = await OutboundFetch.FetchAsync(
            Get("http://example.com/"), context, transport.Delegate, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(OutboundFetchOutcome.DeniedByPolicy, result.Outcome,
            "http is denied by the secure default before any network call.");
        Assert.IsEmpty(transport.Calls, "A denied target must never reach the transport.");
    }


    [TestMethod]
    public async Task TerminalResponseIsFetched()
    {
        FakeTransport transport = new(); //default route: 200.
        ExchangeContext context = Context(OutboundFetchPolicy.SecureDefault);

        OutboundFetchResult result = await OutboundFetch.FetchAsync(
            Get("https://example.com/meta"), context, transport.Delegate, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(OutboundFetchOutcome.Fetched, result.Outcome);
        Assert.AreEqual(200, result.Response!.StatusCode);
        Assert.AreEqual(0, result.RedirectCount);
        Assert.HasCount(1, transport.Calls);
    }


    [TestMethod]
    public async Task RedirectIsNotFollowedUnderNoneMode()
    {
        FakeTransport transport = new(new()
        {
            ["https://a.example/"] = (302, "https://b.example/"),
        });
        ExchangeContext context = Context(OutboundFetchPolicy.SecureDefault); //Redirects = None.

        OutboundFetchResult result = await OutboundFetch.FetchAsync(
            Get("https://a.example/"), context, transport.Delegate, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(OutboundFetchOutcome.RedirectNotFollowed, result.Outcome);
        Assert.HasCount(1, transport.Calls);
    }


    [TestMethod]
    public async Task RedirectIsFollowedUnderPolicyCheckedMode()
    {
        FakeTransport transport = new(new()
        {
            ["https://a.example/"] = (302, "https://b.example/"),
            ["https://b.example/"] = (200, null),
        });
        ExchangeContext context = Context(OutboundFetchPolicy.SecureDefault with
        {
            Redirects = RedirectMode.PolicyChecked,
            MaxRedirects = 3,
        });

        OutboundFetchResult result = await OutboundFetch.FetchAsync(
            Get("https://a.example/"), context, transport.Delegate, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(OutboundFetchOutcome.Fetched, result.Outcome);
        Assert.AreEqual(1, result.RedirectCount);
        Assert.AreEqual(new Uri("https://b.example/"), result.FinalUri);
    }


    [TestMethod]
    public async Task RedirectToInternalAddressIsBlockedPerHop()
    {
        //The key proof: even with redirects enabled, a hop to an internal/
        //metadata address is re-validated and denied.
        FakeTransport transport = new(new()
        {
            ["https://ok.example/"] = (302, "https://169.254.169.254/latest/meta-data/"),
        });
        ExchangeContext context = Context(OutboundFetchPolicy.SecureDefault with
        {
            Redirects = RedirectMode.PolicyChecked,
            MaxRedirects = 3,
        });

        OutboundFetchResult result = await OutboundFetch.FetchAsync(
            Get("https://ok.example/"), context, transport.Delegate, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(OutboundFetchOutcome.DeniedByPolicy, result.Outcome,
            "A redirect to a link-local/metadata address is denied by the per-hop re-validation.");
        Assert.HasCount(1, transport.Calls, "The internal redirect target is never contacted.");
        Assert.AreEqual(new Uri("https://169.254.169.254/latest/meta-data/"), result.FinalUri);
    }


    [TestMethod]
    public async Task ExceedingMaxRedirectsStops()
    {
        FakeTransport transport = new(new()
        {
            ["https://a.example/"] = (302, "https://b.example/"),
            ["https://b.example/"] = (302, "https://c.example/"),
        });
        ExchangeContext context = Context(OutboundFetchPolicy.SecureDefault with
        {
            Redirects = RedirectMode.PolicyChecked,
            MaxRedirects = 1,
        });

        OutboundFetchResult result = await OutboundFetch.FetchAsync(
            Get("https://a.example/"), context, transport.Delegate, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(OutboundFetchOutcome.TooManyRedirects, result.Outcome);
    }


    [TestMethod]
    public async Task SameOriginModeAllowsSameOriginAndBlocksCrossOrigin()
    {
        FakeTransport sameOrigin = new(new()
        {
            ["https://a.example/x"] = (302, "https://a.example/y"),
            ["https://a.example/y"] = (200, null),
        });
        ExchangeContext context = Context(OutboundFetchPolicy.SecureDefault with
        {
            Redirects = RedirectMode.SameOrigin,
            MaxRedirects = 3,
        });

        OutboundFetchResult allowed = await OutboundFetch.FetchAsync(
            Get("https://a.example/x"), context, sameOrigin.Delegate, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(OutboundFetchOutcome.Fetched, allowed.Outcome, "Same-origin redirect is followed.");

        FakeTransport crossOrigin = new(new()
        {
            ["https://a.example/"] = (302, "https://b.example/"),
        });
        OutboundFetchResult blocked = await OutboundFetch.FetchAsync(
            Get("https://a.example/"), context, crossOrigin.Delegate, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(OutboundFetchOutcome.DeniedByPolicy, blocked.Outcome,
            "A cross-origin redirect is blocked under SameOrigin mode.");
    }


    [TestMethod]
    public async Task PostBodyPreservedOn308ButBodyDropRejectedOn303()
    {
        ExchangeContext context = Context(OutboundFetchPolicy.SecureDefault with
        {
            Redirects = RedirectMode.PolicyChecked,
            MaxRedirects = 3,
        });

        FakeTransport preserve = new(new()
        {
            ["https://a.example/"] = (308, "https://b.example/"),
            ["https://b.example/"] = (200, null),
        });
        _ = await OutboundFetch.FetchAsync(
            Post("https://a.example/"), context, preserve.Delegate, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual("POST", preserve.Calls[1].Method, "308 preserves the method.");
        Assert.IsNotNull(preserve.Calls[1].Body, "308 preserves the body.");

        //A 303 (like 301/302) would rewrite a body-bearing POST to a bodyless GET, silently dropping the body
        //while still reporting success — a one-way POST would deliver nothing. That is now REJECTED rather than
        //body-dropped: only a body-preserving redirect (307/308) may follow a request that carries a body, so
        //the redirect is not taken (only the original call is made) and the caller must re-resolve explicitly.
        FakeTransport rejectBodyDrop = new(new()
        {
            ["https://a.example/"] = (303, "https://b.example/"),
            ["https://b.example/"] = (200, null),
        });
        OutboundFetchResult result = await OutboundFetch.FetchAsync(
            Post("https://a.example/"), context, rejectBodyDrop.Delegate, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(OutboundFetchOutcome.DeniedByPolicy, result.Outcome, "A 303 of a body-bearing POST is rejected, not body-dropped.");
        Assert.HasCount(1, rejectBodyDrop.Calls);
    }


    private static ExchangeContext Context(OutboundFetchPolicy policy)
    {
        ExchangeContext context = new();
        context.SetOutboundFetchPolicy(policy);
        return context;
    }


    private static OutboundRequest Get(string url) =>
        new() { Target = new Uri(url), Method = "GET" };


    private static OutboundRequest Post(string url) =>
        new()
        {
            Target = new Uri(url),
            Method = "POST",
            Body = new TaggedMemory<byte>(new byte[] { 1, 2, 3 }, Tag.Empty),
        };


    private sealed class FakeTransport
    {
        private readonly Dictionary<string, (int Status, string? Location)> routes;

        public FakeTransport() : this(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)) { }

        public FakeTransport(Dictionary<string, (int Status, string? Location)> routes)
        {
            this.routes = routes;
        }

        public List<OutboundRequest> Calls { get; } = [];

        public OutboundTransportDelegate Delegate => (request, context, cancellationToken) =>
        {
            Calls.Add(request);

            if(!routes.TryGetValue(request.Target.AbsoluteUri, out (int Status, string? Location) route))
            {
                route = (200, null);
            }

            Dictionary<string, string> headers = new(StringComparer.OrdinalIgnoreCase);
            if(route.Location is not null)
            {
                headers["Location"] = route.Location;
            }

            return ValueTask.FromResult(new OutboundResponse
            {
                StatusCode = route.Status,
                Headers = headers,
                Body = new TaggedMemory<byte>(new byte[] { 9 }, Tag.Empty),
            });
        };
    }
}
