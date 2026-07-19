using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// CIMD §5.2 metadata-caching real-wire suite (slice E2, contract D12 second half, item (d)):
/// every scenario drives two independent PAR flows against the same registered CIMD client over a
/// real <see cref="MinimalHttpHost"/> TLS loopback socket, scripting the <c>Cache-Control</c>
/// response header (or the response sequence) the second flow's fetch decision depends on. The
/// pinned <see cref="FakeTimeProvider"/> is the only clock the resolver's freshness decisions ever
/// read — production code never consults the wall clock here.
/// </summary>
/// <remarks>
/// Covers CIMD-02-clause-ledger rows 030, 036-040, 061 per
/// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-5.2">
/// draft-ietf-oauth-client-id-metadata-document-02 §5.2</see> and §9.1. Adversarial, SSRF,
/// discrimination, display-seam, and logo-prefetch coverage lives in the sibling
/// <see cref="ClientIdMetadataDocumentAdversarialFlowTests"/>. Every test builds its own hosts, so
/// the suite is parallel-safe.
/// </remarks>
[TestClass]
internal sealed class ClientIdMetadataDocumentCachingFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");

    private static ImmutableHashSet<CapabilityIdentifier> AuthCodeCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization);


    /// <summary>
    /// CIMD-036/061: a <c>max-age</c> response is still fresh at the second flow, so the second PAR
    /// attempt makes zero extra fetches — the cached resolution is served without touching the
    /// document host again.
    /// </summary>
    [TestMethod]
    public async Task MaxAgeFreshSecondFlowMakesZeroExtraFetches()
    {
        Uri? documentUri = null;
        SequencedResponseHandler handler = new(_ => FreshDocumentResponse(() => documentUri!, maxAgeSeconds: 300));
        await using MinimalHttpHost documentHost = await MinimalHttpHost.StartAsync(
            handler.HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        documentUri = new Uri(documentHost.BaseAddress, "/app");

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using TestHostShell app = new(timeProvider);
        app.WireCimdMaterialization("default", documentHost.Certificate);

        (OAuthClient client, ClientRegistration registration) = await RegisterCimdClientAsync(
            app, documentUri, TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult firstFlow = await client.AuthCode.StartParAsync(
            registration, RedirectUri, OAuthFormEncodedFields.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, firstFlow.Outcome,
            $"The first flow must fetch and succeed. ErrorDescription={firstFlow.ErrorDescription}");
        Assert.AreEqual(1, handler.CallCount);

        AuthCodeFlowEndpointResult secondFlow = await client.AuthCode.StartParAsync(
            registration, RedirectUri, OAuthFormEncodedFields.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, secondFlow.Outcome,
            $"The second flow must also succeed, from the cache. ErrorDescription={secondFlow.ErrorDescription}");
        Assert.AreEqual(1, handler.CallCount,
            "CIMD-036/061: a fresh cache entry must serve the second flow with zero extra fetches.");
    }


    /// <summary>CIMD-030: once the clock advances past the cached freshness lifetime, the next flow re-fetches.</summary>
    [TestMethod]
    public async Task ClockPastTtlSecondFlowRefetches()
    {
        Uri? documentUri = null;
        SequencedResponseHandler handler = new(_ => FreshDocumentResponse(() => documentUri!, maxAgeSeconds: 300));
        await using MinimalHttpHost documentHost = await MinimalHttpHost.StartAsync(
            handler.HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        documentUri = new Uri(documentHost.BaseAddress, "/app");

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using TestHostShell app = new(timeProvider);
        app.WireCimdMaterialization("default", documentHost.Certificate);

        (OAuthClient client, ClientRegistration registration) = await RegisterCimdClientAsync(
            app, documentUri, TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult firstFlow = await client.AuthCode.StartParAsync(
            registration, RedirectUri, OAuthFormEncodedFields.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, firstFlow.Outcome,
            $"ErrorDescription={firstFlow.ErrorDescription}");
        Assert.AreEqual(1, handler.CallCount);

        timeProvider.Advance(TimeSpan.FromSeconds(301));

        AuthCodeFlowEndpointResult secondFlow = await client.AuthCode.StartParAsync(
            registration, RedirectUri, OAuthFormEncodedFields.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, secondFlow.Outcome,
            $"ErrorDescription={secondFlow.ErrorDescription}");
        Assert.AreEqual(2, handler.CallCount,
            "CIMD-030: a flow after the cached lifetime elapses must re-fetch the document.");
    }


    /// <summary>CIMD-037 (respect cache headers): a <c>no-store</c> response is never cached, so every flow re-fetches.</summary>
    [TestMethod]
    public async Task NoStoreRefetchesEveryFlow()
    {
        Uri? documentUri = null;
        SequencedResponseHandler handler = new(_ => new MinimalHttpResponse
        {
            StatusCode = 200,
            ContentType = "application/json",
            Body = BuildDocumentJson(documentUri!.OriginalString, [RedirectUri]),
            Headers = new Dictionary<string, string> { ["Cache-Control"] = "no-store" }
        });
        await using MinimalHttpHost documentHost = await MinimalHttpHost.StartAsync(
            handler.HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        documentUri = new Uri(documentHost.BaseAddress, "/app");

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using TestHostShell app = new(timeProvider);
        app.WireCimdMaterialization("default", documentHost.Certificate);

        (OAuthClient client, ClientRegistration registration) = await RegisterCimdClientAsync(
            app, documentUri, TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult firstFlow = await client.AuthCode.StartParAsync(
            registration, RedirectUri, OAuthFormEncodedFields.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, firstFlow.Outcome,
            $"ErrorDescription={firstFlow.ErrorDescription}");
        Assert.AreEqual(1, handler.CallCount);

        AuthCodeFlowEndpointResult secondFlow = await client.AuthCode.StartParAsync(
            registration, RedirectUri, OAuthFormEncodedFields.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, secondFlow.Outcome,
            $"ErrorDescription={secondFlow.ErrorDescription}");
        Assert.AreEqual(2, handler.CallCount,
            "CIMD-037: Cache-Control: no-store must never be cached — every flow re-fetches.");
    }


    /// <summary>
    /// CIMD-038: a huge <c>max-age</c> is clamped by <see cref="ClientIdMetadataDocumentResolverOptions.MaximumCacheLifetime"/>
    /// rather than honored literally — a clock advance well within the huge max-age but past the
    /// clamp still triggers a re-fetch.
    /// </summary>
    [TestMethod]
    public async Task HugeMaxAgeClampedByMaximumCacheLifetimeOption()
    {
        Uri? documentUri = null;
        SequencedResponseHandler handler = new(_ => FreshDocumentResponse(() => documentUri!, maxAgeSeconds: 999_999));
        await using MinimalHttpHost documentHost = await MinimalHttpHost.StartAsync(
            handler.HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        documentUri = new Uri(documentHost.BaseAddress, "/app");

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using TestHostShell app = new(timeProvider);
        app.WireCimdMaterialization(
            "default", documentHost.Certificate,
            new ClientIdMetadataDocumentResolverOptions { MaximumCacheLifetime = TimeSpan.FromSeconds(60) });

        (OAuthClient client, ClientRegistration registration) = await RegisterCimdClientAsync(
            app, documentUri, TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult firstFlow = await client.AuthCode.StartParAsync(
            registration, RedirectUri, OAuthFormEncodedFields.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, firstFlow.Outcome,
            $"ErrorDescription={firstFlow.ErrorDescription}");
        Assert.AreEqual(1, handler.CallCount);

        timeProvider.Advance(TimeSpan.FromSeconds(61));

        AuthCodeFlowEndpointResult secondFlow = await client.AuthCode.StartParAsync(
            registration, RedirectUri, OAuthFormEncodedFields.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, secondFlow.Outcome,
            $"ErrorDescription={secondFlow.ErrorDescription}");
        Assert.AreEqual(2, handler.CallCount,
            "CIMD-038: a max-age far beyond MaximumCacheLifetime must be clamped down, not honored literally.");
    }


    /// <summary>CIMD-039: an error response is never cached — the second flow re-fetches and succeeds.</summary>
    [TestMethod]
    public async Task ErrorThenValidSecondFlowSucceeds()
    {
        Uri? documentUri = null;
        SequencedResponseHandler handler = new(index => index switch
        {
            0 => new MinimalHttpResponse { StatusCode = 500 },
            _ => new MinimalHttpResponse
            {
                StatusCode = 200,
                ContentType = "application/json",
                Body = BuildDocumentJson(documentUri!.OriginalString, [RedirectUri])
            }
        });
        await using MinimalHttpHost documentHost = await MinimalHttpHost.StartAsync(
            handler.HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        documentUri = new Uri(documentHost.BaseAddress, "/app");

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using TestHostShell app = new(timeProvider);
        app.WireCimdMaterialization("default", documentHost.Certificate);

        (OAuthClient client, ClientRegistration registration) = await RegisterCimdClientAsync(
            app, documentUri, TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult firstFlow = await client.AuthCode.StartParAsync(
            registration, RedirectUri, OAuthFormEncodedFields.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, firstFlow.Outcome,
            "CIMD-033: the first flow must abort on the 500 response.");

        AuthCodeFlowEndpointResult secondFlow = await client.AuthCode.StartParAsync(
            registration, RedirectUri, OAuthFormEncodedFields.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, secondFlow.Outcome,
            $"CIMD-039: the error must not have been cached — the second flow must re-fetch and succeed. " +
            $"ErrorDescription={secondFlow.ErrorDescription}");
        Assert.AreEqual(2, handler.CallCount);
    }


    /// <summary>CIMD-040: an invalid document is never cached — the second flow re-fetches and succeeds.</summary>
    [TestMethod]
    public async Task InvalidDocumentThenValidSecondFlowSucceeds()
    {
        Uri? documentUri = null;
        SequencedResponseHandler handler = new(index => index switch
        {
            0 => new MinimalHttpResponse
            {
                StatusCode = 200,
                ContentType = "application/json",
                Body = """{"client_secret":"leaked"}"""
            },
            _ => new MinimalHttpResponse
            {
                StatusCode = 200,
                ContentType = "application/json",
                Body = BuildDocumentJson(documentUri!.OriginalString, [RedirectUri])
            }
        });
        await using MinimalHttpHost documentHost = await MinimalHttpHost.StartAsync(
            handler.HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        documentUri = new Uri(documentHost.BaseAddress, "/app");

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using TestHostShell app = new(timeProvider);
        app.WireCimdMaterialization("default", documentHost.Certificate);

        (OAuthClient client, ClientRegistration registration) = await RegisterCimdClientAsync(
            app, documentUri, TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult firstFlow = await client.AuthCode.StartParAsync(
            registration, RedirectUri, OAuthFormEncodedFields.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, firstFlow.Outcome,
            "CIMD-022: the first flow must abort — the document carries a client_secret.");

        AuthCodeFlowEndpointResult secondFlow = await client.AuthCode.StartParAsync(
            registration, RedirectUri, OAuthFormEncodedFields.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, secondFlow.Outcome,
            $"CIMD-040: the invalid document must not have been cached — the second flow must re-fetch and " +
            $"succeed. ErrorDescription={secondFlow.ErrorDescription}");
        Assert.AreEqual(2, handler.CallCount);
    }


    /// <summary>Registers a fresh CIMD stub for <paramref name="documentUri"/> and the matching OAuth client wrapper.</summary>
    private static async Task<(OAuthClient Client, ClientRegistration Registration)> RegisterCimdClientAsync(
        TestHostShell app, Uri documentUri, CancellationToken cancellationToken)
    {
        ClientRecord stub = app.RegisterCimdStubClient(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce);
        (OAuthClient client, ClientRegistration registration, _) = await app.CreateOAuthClientAndRegistrationAsync(
            stub, RedirectUri.OriginalString, PolicyProfile.Rfc6749WithPkce, cancellationToken).ConfigureAwait(false);

        return (client, registration);
    }


    //A conformant document served with a max-age Cache-Control directive. documentUriAccessor is
    //a deferred accessor because the client_id must equal the document host's own bound address,
    //known only after MinimalHttpHost.StartAsync returns — later than the handler closure captures.
    private static MinimalHttpResponse FreshDocumentResponse(Func<Uri> documentUriAccessor, int maxAgeSeconds) =>
        new()
        {
            StatusCode = 200,
            ContentType = "application/json",
            Body = BuildDocumentJson(documentUriAccessor().OriginalString, [RedirectUri]),
            Headers = new Dictionary<string, string> { ["Cache-Control"] = $"max-age={maxAgeSeconds}" }
        };


    //Builds a conformant-shaped Client ID Metadata Document (§4) — the same shape the sibling
    //adversarial suite's BuildDocumentJson produces, kept as its own copy per this file's narrower
    //needs (client_id and redirect_uris only).
    private static string BuildDocumentJson(string clientId, IReadOnlyList<Uri> redirectUris)
    {
        string uris = string.Join(',', redirectUris.Select(static uri => $"\"{uri.OriginalString}\""));

        return $$"""{"client_id":"{{clientId}}","redirect_uris":[{{uris}}]}""";
    }


    /// <summary>
    /// A single-hop <see cref="MinimalHttpHandlerDelegate"/> that plays back a sequence of
    /// responses by call index (sticking to the last factory result once the caller's switch
    /// expression falls through to its default arm), counting every call. The factory is invoked
    /// lazily per call so it can reference state (the document host's own bound address) not yet
    /// known when the handler is constructed.
    /// </summary>
    private sealed class SequencedResponseHandler
    {
        private readonly Func<int, MinimalHttpResponse> responseFactory;
        private int callIndex;

        public SequencedResponseHandler(Func<int, MinimalHttpResponse> responseFactory)
        {
            this.responseFactory = responseFactory;
        }

        public int CallCount => Volatile.Read(ref callIndex);

        public Task<MinimalHttpResponse> HandleAsync(MinimalHttpRequest request, CancellationToken cancellationToken)
        {
            int index = Interlocked.Increment(ref callIndex) - 1;

            return Task.FromResult(responseFactory(index));
        }
    }
}
