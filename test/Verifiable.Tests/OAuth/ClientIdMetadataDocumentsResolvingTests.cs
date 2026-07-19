using System.Collections.Generic;
using System.Text;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.Foundation;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for <see cref="ClientIdMetadataDocuments.BuildResolving"/> — the Client ID Metadata
/// Document fetch-validate-cache pipeline (draft-ietf-oauth-client-id-metadata-document-02
/// §5). The single-hop transport is scripted (the established outbound-fetch-consumer test
/// pattern, mirroring <c>WebDidResolverResolvingTests</c>), so the guarded fetch, the
/// conformance checks, the client_id match, the additional-validation hook, logo prefetch, and
/// caching are all exercised deterministically without a live network.
/// </summary>
[TestClass]
internal sealed class ClientIdMetadataDocumentsResolvingTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string ClientMetadataUrl = "https://client.example.com/app";
    private const string LogoUrl = "https://client.example.com/logo.png";
    private const string JwksUrl = "https://client.example.com/jwks.json";


    /// <summary>An SSRF-blocked target (a loopback IP literal) is denied before any transport call.</summary>
    [TestMethod]
    public async Task PolicyDenialHappensBeforeAnyTransportCall()
    {
        ScriptedTransport transport = new();

        ClientIdMetadataResolution resolution = await ResolveAsync(
            "https://127.0.0.1/app", transport).ConfigureAwait(false);

        Assert.AreEqual(ClientIdMetadataResolutionOutcome.PolicyDenied, resolution.Outcome);
        Assert.IsEmpty(transport.Calls, "SecureDefault MUST deny a loopback target before any transport call.");
    }


    /// <summary>Any status other than exactly 200 is a fetch failure (CIMD-018/032/033).</summary>
    [TestMethod]
    public async Task NonTwoHundredStatusIsFetchFailed()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 404);

        ClientIdMetadataResolution resolution = await ResolveAsync(ClientMetadataUrl, transport).ConfigureAwait(false);

        Assert.AreEqual(ClientIdMetadataResolutionOutcome.FetchFailed, resolution.Outcome);
    }


    /// <summary>
    /// A redirect answer is refused rather than followed (CIMD-034: SecureDefault's
    /// <see cref="RedirectMode.None"/> never follows a 3xx).
    /// </summary>
    [TestMethod]
    public async Task RedirectAnswerIsRefused()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 302, headers: Headers(("Location", "https://client.example.com/elsewhere")));

        ClientIdMetadataResolution resolution = await ResolveAsync(ClientMetadataUrl, transport).ConfigureAwait(false);

        Assert.AreEqual(ClientIdMetadataResolutionOutcome.FetchFailed, resolution.Outcome);
        Assert.HasCount(1, transport.Calls, "The redirect response itself required one transport call; it must not be followed with a second.");
    }


    /// <summary>A response larger than the configured cap is a fetch failure (CIMD-059), regardless of what the transport reports.</summary>
    [TestMethod]
    public async Task OversizedBodyIsFetchFailed()
    {
        ScriptedTransport transport = new();
        string oversizedBody = $$"""{"client_id":"{{ClientMetadataUrl}}","client_name":"{{new string('x', 200)}}"}""";
        transport.Enqueue(ClientMetadataUrl, 200, oversizedBody, contentType: "application/json");

        ClientIdMetadataResolution resolution = await ResolveAsync(
            ClientMetadataUrl, transport, options: new ClientIdMetadataDocumentResolverOptions { MaximumDocumentBytes = 32 })
            .ConfigureAwait(false);

        Assert.AreEqual(ClientIdMetadataResolutionOutcome.FetchFailed, resolution.Outcome);
    }


    /// <summary>A content type that is neither application/json nor a +json suffix is an invalid document (CIMD-019).</summary>
    [TestMethod]
    public async Task WrongContentTypeIsInvalidDocument()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, ValidDocumentJson(ClientMetadataUrl), contentType: "text/html");

        ClientIdMetadataResolution resolution = await ResolveAsync(ClientMetadataUrl, transport).ConfigureAwait(false);

        Assert.AreEqual(ClientIdMetadataResolutionOutcome.InvalidDocument, resolution.Outcome);
    }


    /// <summary>An application/&lt;AS-defined&gt;+json structured suffix is accepted (CIMD-019).</summary>
    [TestMethod]
    public async Task StructuredPlusJsonContentTypeIsAccepted()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, ValidDocumentJson(ClientMetadataUrl), contentType: "application/example+json");

        ClientIdMetadataResolution resolution = await ResolveAsync(ClientMetadataUrl, transport).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved, $"A +json structured suffix MUST be accepted. Defect: {resolution.Defect}");
    }


    /// <summary>The document's client_id MUST ordinal-equal the URL it was fetched from (CIMD-013/014/015/016).</summary>
    [TestMethod]
    public async Task ClientIdMismatchIsInvalidDocument()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, ValidDocumentJson("https://someone-else.example.com/app"), contentType: "application/json");

        ClientIdMetadataResolution resolution = await ResolveAsync(ClientMetadataUrl, transport).ConfigureAwait(false);

        Assert.AreEqual(ClientIdMetadataResolutionOutcome.InvalidDocument, resolution.Outcome);
        Assert.AreEqual("https://someone-else.example.com/app", resolution.DocumentClientId);
    }


    /// <summary>
    /// The ordinal client_id comparison is exact — a default-port suffix the spec's own example
    /// calls non-equivalent (CIMD-008/016) is rejected, not silently normalized away.
    /// </summary>
    [TestMethod]
    public async Task DefaultPortSuffixIsNotEquivalentForClientIdMatch()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, ValidDocumentJson("https://client.example.com:443/app"), contentType: "application/json");

        ClientIdMetadataResolution resolution = await ResolveAsync(ClientMetadataUrl, transport).ConfigureAwait(false);

        Assert.AreEqual(ClientIdMetadataResolutionOutcome.InvalidDocument, resolution.Outcome);
    }


    /// <summary>A CIMD-020 application-supplied additional restriction can reject an otherwise-conformant document.</summary>
    [TestMethod]
    public async Task AdditionalDocumentValidationRejectionIsInvalidDocument()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, ValidDocumentJson(ClientMetadataUrl), contentType: "application/json");

        ClientIdMetadataDocumentResolverOptions options = new()
        {
            AdditionalDocumentValidation = static (document, uri, context, ct) => ValueTask.FromResult(false)
        };

        ClientIdMetadataResolution resolution = await ResolveAsync(ClientMetadataUrl, transport, options).ConfigureAwait(false);

        Assert.AreEqual(ClientIdMetadataResolutionOutcome.InvalidDocument, resolution.Outcome);
    }


    /// <summary>A CIMD-020 additional restriction that accepts the document lets resolution proceed to Resolved.</summary>
    [TestMethod]
    public async Task AdditionalDocumentValidationAcceptanceResolves()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, ValidDocumentJson(ClientMetadataUrl), contentType: "application/json");

        ClientIdMetadataDocumentResolverOptions options = new()
        {
            AdditionalDocumentValidation = static (document, uri, context, ct) =>
                ValueTask.FromResult(string.Equals(uri.OriginalString, ClientMetadataUrl, StringComparison.Ordinal))
        };

        ClientIdMetadataResolution resolution = await ResolveAsync(ClientMetadataUrl, transport, options).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved);
    }


    /// <summary>A fresh cache hit answers without dialing the transport again (CIMD-036/061).</summary>
    [TestMethod]
    public async Task FreshCacheHitDoesNotRedial()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, ValidDocumentJson(ClientMetadataUrl),
            contentType: "application/json", headers: Headers(("Cache-Control", "max-age=300")));

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        ResolveClientMetadataDelegate resolve = ClientIdMetadataDocuments.BuildResolving(
            transport.Delegate, new ClientIdMetadataDocumentResolverOptions(), timeProvider);

        ClientIdMetadataResolution first = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);
        ClientIdMetadataResolution second = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);

        Assert.IsTrue(first.IsResolved);
        Assert.IsTrue(second.IsResolved);
        Assert.HasCount(1, transport.Calls, "A fresh cache hit must not re-dial the transport.");
    }


    /// <summary>A stale cache entry re-fetches after the freshness lifetime elapses (CIMD-030).</summary>
    [TestMethod]
    public async Task StaleCacheEntryReFetches()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, ValidDocumentJson(ClientMetadataUrl),
            contentType: "application/json", headers: Headers(("Cache-Control", "max-age=300")));
        transport.Enqueue(ClientMetadataUrl, 200, ValidDocumentJson(ClientMetadataUrl),
            contentType: "application/json", headers: Headers(("Cache-Control", "max-age=300")));

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        ResolveClientMetadataDelegate resolve = ClientIdMetadataDocuments.BuildResolving(
            transport.Delegate, new ClientIdMetadataDocumentResolverOptions(), timeProvider);

        ClientIdMetadataResolution first = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);
        timeProvider.Advance(TimeSpan.FromSeconds(301));
        ClientIdMetadataResolution second = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);

        Assert.IsTrue(first.IsResolved);
        Assert.IsTrue(second.IsResolved);
        Assert.HasCount(2, transport.Calls, "A stale cache entry must trigger a re-fetch.");
    }


    /// <summary>
    /// A huge <c>max-age</c> is clamped to <see cref="ClientIdMetadataDocumentResolverOptions.MaximumCacheLifetime"/>
    /// rather than honored literally (CIMD-038).
    /// </summary>
    [TestMethod]
    public async Task MaxAgeIsClampedByMaximumCacheLifetimeOption()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, ValidDocumentJson(ClientMetadataUrl),
            contentType: "application/json", headers: Headers(("Cache-Control", "max-age=999999")));
        transport.Enqueue(ClientMetadataUrl, 200, ValidDocumentJson(ClientMetadataUrl),
            contentType: "application/json", headers: Headers(("Cache-Control", "max-age=999999")));

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        ClientIdMetadataDocumentResolverOptions options = new() { MaximumCacheLifetime = TimeSpan.FromSeconds(60) };
        ResolveClientMetadataDelegate resolve = ClientIdMetadataDocuments.BuildResolving(
            transport.Delegate, options, timeProvider);

        ClientIdMetadataResolution first = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);
        timeProvider.Advance(TimeSpan.FromSeconds(61));
        ClientIdMetadataResolution second = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);

        Assert.IsTrue(first.IsResolved);
        Assert.IsTrue(second.IsResolved);
        Assert.HasCount(2, transport.Calls,
            "A max-age far beyond MaximumCacheLifetime must be clamped down, not honored literally.");
    }


    /// <summary>A 500-then-200 sequence proves an error response was never cached (CIMD-039).</summary>
    [TestMethod]
    public async Task ErrorResponseIsNeverCached()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 500);
        transport.Enqueue(ClientMetadataUrl, 200, ValidDocumentJson(ClientMetadataUrl), contentType: "application/json");

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        ResolveClientMetadataDelegate resolve = ClientIdMetadataDocuments.BuildResolving(
            transport.Delegate, new ClientIdMetadataDocumentResolverOptions(), timeProvider);

        ClientIdMetadataResolution first = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);
        ClientIdMetadataResolution second = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);

        Assert.AreEqual(ClientIdMetadataResolutionOutcome.FetchFailed, first.Outcome);
        Assert.IsTrue(second.IsResolved, $"The second call must re-fetch and succeed. Defect: {second.Defect}");
        Assert.HasCount(2, transport.Calls);
    }


    /// <summary>An invalid-then-valid sequence proves an invalid document was never cached (CIMD-040).</summary>
    [TestMethod]
    public async Task InvalidDocumentIsNeverCached()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, """{"client_secret":"leaked"}""", contentType: "application/json");
        transport.Enqueue(ClientMetadataUrl, 200, ValidDocumentJson(ClientMetadataUrl), contentType: "application/json");

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        ResolveClientMetadataDelegate resolve = ClientIdMetadataDocuments.BuildResolving(
            transport.Delegate, new ClientIdMetadataDocumentResolverOptions(), timeProvider);

        ClientIdMetadataResolution first = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);
        ClientIdMetadataResolution second = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);

        Assert.AreEqual(ClientIdMetadataResolutionOutcome.InvalidDocument, first.Outcome);
        Assert.IsTrue(second.IsResolved, $"The second call must re-fetch and succeed. Defect: {second.Defect}");
        Assert.HasCount(2, transport.Calls);
    }


    /// <summary>Logo prefetch (CIMD-060) fetches logo_uri through the same guarded policy and returns its bytes.</summary>
    [TestMethod]
    public async Task LogoPrefetchSucceedsWhenEnabled()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, DocumentWithLogoJson(ClientMetadataUrl, LogoUrl), contentType: "application/json");
        byte[] logoBytes = [0x89, 0x50, 0x4E, 0x47];
        transport.Enqueue(LogoUrl, 200, logoBytes, contentType: "image/png");

        ClientIdMetadataResolution resolution = await ResolveAsync(
            ClientMetadataUrl, transport, options: new ClientIdMetadataDocumentResolverOptions { PrefetchLogo = true })
            .ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved);
        Assert.IsNotNull(resolution.PrefetchedLogo);
        CollectionAssert.AreEqual(logoBytes, resolution.PrefetchedLogo!.Value.ToArray());
        Assert.AreEqual("image/png", resolution.PrefetchedLogoContentType);
        Assert.Contains(LogoUrl, transport.Calls.ConvertAll(static c => c.Target.AbsoluteUri));
    }


    /// <summary>A failed logo prefetch is SHOULD-tier and never fails the surrounding document resolution.</summary>
    [TestMethod]
    public async Task LogoPrefetchFailureIsNonFatal()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, DocumentWithLogoJson(ClientMetadataUrl, LogoUrl), contentType: "application/json");
        transport.Enqueue(LogoUrl, 500);

        ClientIdMetadataResolution resolution = await ResolveAsync(
            ClientMetadataUrl, transport, options: new ClientIdMetadataDocumentResolverOptions { PrefetchLogo = true })
            .ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved, $"A failed logo prefetch must not fail document resolution. Defect: {resolution.Defect}");
        Assert.IsNull(resolution.PrefetchedLogo);
    }


    /// <summary>Logo prefetch is opt-in: disabled by default, no logo fetch happens even when logo_uri is present.</summary>
    [TestMethod]
    public async Task LogoIsNotPrefetchedWhenDisabled()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, DocumentWithLogoJson(ClientMetadataUrl, LogoUrl), contentType: "application/json");

        ClientIdMetadataResolution resolution = await ResolveAsync(ClientMetadataUrl, transport).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved);
        Assert.IsNull(resolution.PrefetchedLogo);
        Assert.DoesNotContain(LogoUrl, transport.Calls.ConvertAll(static c => c.Target.AbsoluteUri));
    }


    /// <summary>
    /// A <c>Cache-Control: no-cache</c> response is never served fresh even when the deployment
    /// configures a <see cref="ClientIdMetadataDocumentResolverOptions.MinimumCacheLifetime"/> floor:
    /// the floor must not manufacture freshness the headers denied (RFC 9111 §5.2.2.4), so the second
    /// flow re-fetches (CIMD-030/037).
    /// </summary>
    [TestMethod]
    public async Task NoCacheIsNotCachedEvenWithAMinimumCacheLifetimeFloor()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, ValidDocumentJson(ClientMetadataUrl),
            contentType: "application/json", headers: Headers(("Cache-Control", "no-cache")));
        transport.Enqueue(ClientMetadataUrl, 200, ValidDocumentJson(ClientMetadataUrl),
            contentType: "application/json", headers: Headers(("Cache-Control", "no-cache")));

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        ClientIdMetadataDocumentResolverOptions options = new() { MinimumCacheLifetime = TimeSpan.FromMinutes(5) };
        ResolveClientMetadataDelegate resolve = ClientIdMetadataDocuments.BuildResolving(
            transport.Delegate, options, timeProvider);

        ClientIdMetadataResolution first = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);
        ClientIdMetadataResolution second = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);

        Assert.IsTrue(first.IsResolved);
        Assert.IsTrue(second.IsResolved);
        Assert.HasCount(2, transport.Calls,
            "A no-cache response must revalidate before reuse; a MinimumCacheLifetime floor must not cache it.");
    }


    /// <summary>
    /// A document with no cache headers IS eligible for a
    /// <see cref="ClientIdMetadataDocumentResolverOptions.MinimumCacheLifetime"/> floor (CIMD-038): the
    /// second flow within the floor is a cache hit — distinguishing an absent expiration signal from an
    /// explicit no-cache.
    /// </summary>
    [TestMethod]
    public async Task NoCacheHeadersAreEligibleForTheMinimumCacheLifetimeFloor()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, ValidDocumentJson(ClientMetadataUrl), contentType: "application/json");

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        ClientIdMetadataDocumentResolverOptions options = new() { MinimumCacheLifetime = TimeSpan.FromMinutes(5) };
        ResolveClientMetadataDelegate resolve = ClientIdMetadataDocuments.BuildResolving(
            transport.Delegate, options, timeProvider);

        ClientIdMetadataResolution first = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);
        timeProvider.Advance(TimeSpan.FromMinutes(1));
        ClientIdMetadataResolution second = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);

        Assert.IsTrue(first.IsResolved);
        Assert.IsTrue(second.IsResolved);
        Assert.HasCount(1, transport.Calls,
            "A document with no cache directives is heuristic-eligible for the configured floor.");
    }


    /// <summary>
    /// A private_key_jwt client that advertises a <c>jwks_uri</c> instead of an inline <c>jwks</c> — the
    /// spec's own §8.2 example — has its key set discovered through the same guarded fetch and folded
    /// inline so the token endpoint can authenticate it (CIMD-048/050).
    /// </summary>
    [TestMethod]
    public async Task JwksUriConfidentialClientHasItsKeySetDiscoveredInline()
    {
        const string jwksJson = """{"keys":[{"kty":"EC","crv":"P-256","kid":"k1","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}""";

        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, PrivateKeyJwtWithJwksUriDocument(ClientMetadataUrl, JwksUrl),
            contentType: "application/json");
        transport.Enqueue(JwksUrl, 200, jwksJson, contentType: "application/json");

        ClientIdMetadataResolution resolution = await ResolveAsync(ClientMetadataUrl, transport).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved, $"Resolution must succeed. Defect: {resolution.Defect}");
        Assert.IsNotNull(resolution.Document!.Jwks, "The jwks_uri key set must be discovered and folded inline.");
        Assert.Contains("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", resolution.Document.Jwks!, StringComparison.Ordinal);
        Assert.Contains(JwksUrl, transport.Calls.ConvertAll(static c => c.Target.AbsoluteUri));
    }


    /// <summary>
    /// A jwks_uri discovery failure is fail-closed but non-fatal to the resolution: the document still
    /// resolves (the authorization front channel proceeds) with no inline key, so the token endpoint
    /// later rejects the client for want of a key (CIMD-050).
    /// </summary>
    [TestMethod]
    public async Task JwksUriDiscoveryFailureLeavesTheKeySetUnsetButResolves()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, PrivateKeyJwtWithJwksUriDocument(ClientMetadataUrl, JwksUrl),
            contentType: "application/json");
        transport.Enqueue(JwksUrl, 500);

        ClientIdMetadataResolution resolution = await ResolveAsync(ClientMetadataUrl, transport).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved, $"A jwks_uri discovery failure must not fail resolution. Defect: {resolution.Defect}");
        Assert.IsNull(resolution.Document!.Jwks, "A failed jwks_uri discovery must leave the inline key set unset.");
    }


    //Runs the resolving delegate once against a freshly built resolver over the scripted transport.
    private async Task<ClientIdMetadataResolution> ResolveAsync(
        string clientMetadataUri,
        ScriptedTransport transport,
        ClientIdMetadataDocumentResolverOptions? options = null)
    {
        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        ResolveClientMetadataDelegate resolve = ClientIdMetadataDocuments.BuildResolving(
            transport.Delegate, options ?? new ClientIdMetadataDocumentResolverOptions(), timeProvider);

        return await Resolve(resolve, clientMetadataUri).ConfigureAwait(false);
    }


    private async Task<ClientIdMetadataResolution> Resolve(ResolveClientMetadataDelegate resolve, string clientMetadataUri)
    {
        ExchangeContext context = new();
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        return await resolve(new Uri(clientMetadataUri, UriKind.Absolute), context, TestContext.CancellationToken)
            .ConfigureAwait(false);
    }


    private static string ValidDocumentJson(string clientId) =>
        $$"""{"client_id":"{{clientId}}"}""";


    private static string DocumentWithLogoJson(string clientId, string logoUri) =>
        $$"""{"client_id":"{{clientId}}","logo_uri":"{{logoUri}}"}""";


    private static string PrivateKeyJwtWithJwksUriDocument(string clientId, string jwksUri) =>
        $$"""{"client_id":"{{clientId}}","token_endpoint_auth_method":"private_key_jwt","jwks_uri":"{{jwksUri}}"}""";


    private static Dictionary<string, string> Headers(params (string Name, string Value)[] headers)
    {
        Dictionary<string, string> result = new(StringComparer.OrdinalIgnoreCase);
        foreach((string name, string value) in headers)
        {
            result[name] = value;
        }

        return result;
    }


    //A single-hop transport that plays back a scripted sequence of (status, body, headers) per
    //absolute URL — each call to a routed URL dequeues the next scripted response, sticking to
    //the last one once the sequence is exhausted; an unrouted URL is a 404. Bodies are carried as
    //TaggedMemory<byte>, mirroring the production OutboundResponse shape.
    private sealed class ScriptedTransport
    {
        private readonly Dictionary<string, List<ScriptedResponse>> routes = new(StringComparer.Ordinal);
        private readonly Dictionary<string, int> callIndex = new(StringComparer.Ordinal);


        public List<OutboundRequest> Calls { get; } = [];


        public void Enqueue(
            string url, int status, string? body = null, string? contentType = null,
            IReadOnlyDictionary<string, string>? headers = null)
        {
            Dictionary<string, string> merged = headers is null
                ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase);

            if(contentType is not null)
            {
                merged["Content-Type"] = contentType;
            }

            byte[]? bodyBytes = body is null ? null : Encoding.UTF8.GetBytes(body);
            EnqueueRoute(url, status, bodyBytes, merged);
        }


        public void Enqueue(
            string url, int status, byte[] body, string? contentType = null,
            IReadOnlyDictionary<string, string>? headers = null)
        {
            Dictionary<string, string> merged = headers is null
                ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase);

            if(contentType is not null)
            {
                merged["Content-Type"] = contentType;
            }

            EnqueueRoute(url, status, body, merged);
        }


        private void EnqueueRoute(string url, int status, byte[]? body, IReadOnlyDictionary<string, string> headers)
        {
            if(!routes.TryGetValue(url, out List<ScriptedResponse>? list))
            {
                list = [];
                routes[url] = list;
            }

            list.Add(new ScriptedResponse(status, body, headers));
        }


        public OutboundTransportDelegate Delegate => (request, context, cancellationToken) =>
        {
            Calls.Add(request);

            string url = request.Target.AbsoluteUri;
            ScriptedResponse response;
            if(routes.TryGetValue(url, out List<ScriptedResponse>? list) && list.Count > 0)
            {
                int index = callIndex.TryGetValue(url, out int current) ? current : 0;
                response = list[Math.Min(index, list.Count - 1)];
                callIndex[url] = index + 1;
            }
            else
            {
                response = new ScriptedResponse(404, null, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));
            }

            TaggedMemory<byte> responseBody = response.Body is null
                ? TaggedMemory<byte>.Empty
                : new TaggedMemory<byte>(response.Body, BufferTags.Json);

            return ValueTask.FromResult(new OutboundResponse
            {
                StatusCode = response.Status,
                Headers = response.Headers,
                Body = responseBody
            });
        };


        private sealed record ScriptedResponse(int Status, byte[]? Body, IReadOnlyDictionary<string, string> Headers);
    }
}
