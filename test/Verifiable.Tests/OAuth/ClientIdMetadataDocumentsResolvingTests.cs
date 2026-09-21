using Microsoft.Extensions.Time.Testing;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Outbound;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for <see cref="ClientIdMetadataDocuments.ResolveAsync"/> — the Client ID Metadata
/// Document fetch-validate attempt (draft-ietf-oauth-client-id-metadata-document-02 §5) — and for
/// <see cref="ClientMetadataResolutionCache"/>, the reference application-layer cache built on top
/// of it and of <see cref="JwksUriResolver.ResolveAsync"/>. The single-hop transport is scripted (the
/// established outbound-fetch-consumer test pattern, mirroring <c>WebDidResolverResolvingTests</c>),
/// so the guarded fetch, the conformance checks, the client_id match, the additional-validation hook,
/// logo prefetch, and caching are all exercised deterministically without a live network.
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
        ResolveClientMetadataDelegate resolve = NewCache(transport, timeProvider).ResolveDocumentAsync;

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
        ResolveClientMetadataDelegate resolve = NewCache(transport, timeProvider).ResolveDocumentAsync;

        ClientIdMetadataResolution first = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);
        timeProvider.Advance(TimeSpan.FromSeconds(301));
        ClientIdMetadataResolution second = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);

        Assert.IsTrue(first.IsResolved);
        Assert.IsTrue(second.IsResolved);
        Assert.HasCount(2, transport.Calls, "A stale cache entry must trigger a re-fetch.");
    }


    /// <summary>
    /// A huge <c>max-age</c> is clamped to the cache's own configured maximum lifetime rather than
    /// honored literally (CIMD-038) — the clamp bound is now the caller's cache option, not a library
    /// option, since caching itself is an application-layer concern.
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
        ClientMetadataResolutionCache cache = NewCache(
            transport, timeProvider, documentMaximumCacheLifetime: TimeSpan.FromSeconds(60));
        ResolveClientMetadataDelegate resolve = cache.ResolveDocumentAsync;

        ClientIdMetadataResolution first = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);
        timeProvider.Advance(TimeSpan.FromSeconds(61));
        ClientIdMetadataResolution second = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);

        Assert.IsTrue(first.IsResolved);
        Assert.IsTrue(second.IsResolved);
        Assert.HasCount(2, transport.Calls,
            "A max-age far beyond MaximumCacheLifetime must be clamped down, not honored literally.");
    }


    /// <summary>An error response's attempt reports a freshness that is not storable (CIMD-039).</summary>
    [TestMethod]
    public async Task ErrorResponseIsNeverCached()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 500);

        ClientIdMetadataResolution resolution = await ResolveAsync(ClientMetadataUrl, transport).ConfigureAwait(false);

        Assert.AreEqual(ClientIdMetadataResolutionOutcome.FetchFailed, resolution.Outcome);
        Assert.IsFalse(resolution.Freshness.IsStorable, "An error response must report a freshness that is not storable.");
    }


    /// <summary>An invalid document's attempt reports a freshness that is not storable (CIMD-040).</summary>
    [TestMethod]
    public async Task InvalidDocumentIsNeverCached()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, """{"client_secret":"leaked"}""", contentType: "application/json");

        ClientIdMetadataResolution resolution = await ResolveAsync(ClientMetadataUrl, transport).ConfigureAwait(false);

        Assert.AreEqual(ClientIdMetadataResolutionOutcome.InvalidDocument, resolution.Outcome);
        Assert.IsFalse(resolution.Freshness.IsStorable, "An invalid document must report a freshness that is not storable.");
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
        Assert.AreSequenceEqual(logoBytes, resolution.PrefetchedLogo.Value.ToArray());
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
    /// A <c>Cache-Control: no-cache</c> response's attempt reports that it must be revalidated before
    /// reuse, so a caller's own minimum-cache-lifetime floor cannot manufacture freshness the headers
    /// denied (RFC 9111 §5.2.2.4, CIMD-030/037).
    /// </summary>
    [TestMethod]
    public async Task NoCacheIsNotCachedEvenWithAMinimumCacheLifetimeFloor()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, ValidDocumentJson(ClientMetadataUrl),
            contentType: "application/json", headers: Headers(("Cache-Control", "no-cache")));

        ClientIdMetadataResolution resolution = await ResolveAsync(ClientMetadataUrl, transport).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved, $"Defect: {resolution.Defect}");
        Assert.IsTrue(resolution.Freshness.MustRevalidate,
            "A no-cache response must report that it must be revalidated before reuse.");
    }


    /// <summary>
    /// A document with no cache headers IS eligible for the cache's own configured minimum-lifetime
    /// floor (CIMD-038): the second flow within the floor is a cache hit — distinguishing an absent
    /// expiration signal from an explicit no-cache.
    /// </summary>
    [TestMethod]
    public async Task NoCacheHeadersAreEligibleForTheMinimumCacheLifetimeFloor()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, ValidDocumentJson(ClientMetadataUrl), contentType: "application/json");

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        ClientMetadataResolutionCache cache = NewCache(
            transport, timeProvider, documentMinimumCacheLifetime: TimeSpan.FromMinutes(5));
        ResolveClientMetadataDelegate resolve = cache.ResolveDocumentAsync;

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
    /// spec's own §8.2 example — has its key set discovered through the wired resolution seam and folded
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

        ClientIdMetadataResolution resolution = await ResolveAsync(
            ClientMetadataUrl, transport, WithDirectJwksResolver(transport)).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved, $"Resolution must succeed. Defect: {resolution.Defect}");
        Assert.IsTrue(resolution.HasJwksUriKeySet, "A jwks_uri-discovered key set must be reported as such.");
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

        ClientIdMetadataResolution resolution = await ResolveAsync(
            ClientMetadataUrl, transport, WithDirectJwksResolver(transport)).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved, $"A jwks_uri discovery failure must not fail resolution. Defect: {resolution.Defect}");
        Assert.IsNull(resolution.Document!.Jwks, "A failed jwks_uri discovery must leave the inline key set unset.");
    }


    /// <summary>
    /// A <c>jwks_uri</c> that answers nothing cacheable is dialled again no sooner than the reference
    /// cache's own key-set retry floor, however many resolutions arrive meanwhile. A cached document
    /// whose key set is refreshed per resolution would otherwise put one outbound request on a host
    /// the client names for every authorization request that reaches it, which
    /// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-4">RFC 9111 §4</see>'s reuse rules
    /// exist to bound.
    /// </summary>
    [TestMethod]
    public async Task AKeySetThatAnswersNothingCacheableIsNotRedialledPerResolution()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, PrivateKeyJwtWithJwksUriDocument(ClientMetadataUrl, JwksUrl),
            contentType: "application/json", headers: Headers(("Cache-Control", "max-age=3600")));
        transport.Enqueue(JwksUrl, 500);
        transport.Enqueue(JwksUrl, 500);
        transport.Enqueue(JwksUrl, 500);

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        ResolveClientMetadataDelegate resolve = NewCache(transport, timeProvider).ResolveDocumentAsync;

        ClientIdMetadataResolution first = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);
        ClientIdMetadataResolution second = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);
        ClientIdMetadataResolution third = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);

        Assert.IsTrue(first.IsResolved, $"Defect: {first.Defect}");
        Assert.IsTrue(second.IsResolved, $"Defect: {second.Defect}");
        Assert.IsTrue(third.IsResolved, $"Defect: {third.Defect}");
        Assert.HasCount(1, transport.Calls.FindAll(c => c.Target.AbsoluteUri == JwksUrl),
            "Three resolutions served from one cached document must not put three requests on the " +
            "client's jwks_uri host.");
    }


    /// <summary>
    /// The discovered key set is cached under its OWN <c>jwks_uri</c> and its freshness is computed
    /// from that response's OWN <c>Cache-Control</c> header, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-5.2">RFC 9111 §5.2</see>: a second
    /// resolution within that lifetime answers without a second dial to <c>jwks_uri</c>, and a
    /// resolution after it lapses re-dials — even though the enclosing document's own cache entry is
    /// still fresh throughout.
    /// </summary>
    [TestMethod]
    public async Task DiscoveredKeySetIsServedFromItsOwnCacheThenRefetchesOnceItsOwnFreshnessLapses()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, PrivateKeyJwtWithJwksUriDocument(ClientMetadataUrl, JwksUrl),
            contentType: "application/json", headers: Headers(("Cache-Control", "max-age=3600")));
        transport.Enqueue(JwksUrl, 200, JwksWithKey(RotationKeyIdV1, RotationKeyXV1, RotationKeyYV1),
            contentType: "application/json", headers: Headers(("Cache-Control", "max-age=300")));
        transport.Enqueue(JwksUrl, 200, JwksWithKey(RotationKeyIdV2, RotationKeyXV2, RotationKeyYV2),
            contentType: "application/json", headers: Headers(("Cache-Control", "max-age=300")));

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        ResolveClientMetadataDelegate resolve = NewCache(transport, timeProvider).ResolveDocumentAsync;

        ClientIdMetadataResolution first = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);
        ClientIdMetadataResolution second = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);

        Assert.IsTrue(first.IsResolved, $"Defect: {first.Defect}");
        Assert.IsTrue(second.IsResolved, $"Defect: {second.Defect}");
        Assert.HasCount(1, transport.Calls.FindAll(c => c.Target.AbsoluteUri == JwksUrl),
            "A second resolution within the key set's own freshness must not re-dial jwks_uri.");

        timeProvider.Advance(TimeSpan.FromSeconds(301));
        ClientIdMetadataResolution third = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);

        Assert.IsTrue(third.IsResolved, $"Defect: {third.Defect}");
        Assert.HasCount(2, transport.Calls.FindAll(c => c.Target.AbsoluteUri == JwksUrl),
            "A resolution after the key set's OWN freshness lapses must re-dial jwks_uri, " +
            "even though the enclosing document is still cached.");
    }


    /// <summary>
    /// The point of this seam: a document whose own cache lifetime is long and a key set whose own
    /// cache lifetime is short. After the key set's lifetime lapses but well inside the document's, a
    /// resolution sees the ROTATED key set, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-5.2">RFC 9111 §5.2</see> applied to
    /// the key set's OWN response rather than the document's.
    /// </summary>
    [TestMethod]
    public async Task RotatedKeySetBecomesVisibleOnItsOwnScheduleNotTheDocuments()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, PrivateKeyJwtWithJwksUriDocument(ClientMetadataUrl, JwksUrl),
            contentType: "application/json", headers: Headers(("Cache-Control", "max-age=3600")));
        transport.Enqueue(JwksUrl, 200, JwksWithKey(RotationKeyIdV1, RotationKeyXV1, RotationKeyYV1),
            contentType: "application/json", headers: Headers(("Cache-Control", "max-age=300")));
        transport.Enqueue(JwksUrl, 200, JwksWithKey(RotationKeyIdV2, RotationKeyXV2, RotationKeyYV2),
            contentType: "application/json", headers: Headers(("Cache-Control", "max-age=300")));

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        ResolveClientMetadataDelegate resolve = NewCache(transport, timeProvider).ResolveDocumentAsync;

        ClientIdMetadataResolution first = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);
        Assert.Contains(RotationKeyIdV1, first.Document!.Jwks!, StringComparison.Ordinal);

        timeProvider.Advance(TimeSpan.FromSeconds(301));
        ClientIdMetadataResolution second = await Resolve(resolve, ClientMetadataUrl).ConfigureAwait(false);

        Assert.IsTrue(second.IsResolved, $"Defect: {second.Defect}");
        Assert.Contains(RotationKeyIdV2, second.Document!.Jwks!, StringComparison.Ordinal,
            "Once the key set's OWN freshness lapses, a resolution must see the rotated key — " +
            "the document's own (still-fresh) cache entry must not pin the old key.");
        Assert.DoesNotContain(RotationKeyIdV1, second.Document.Jwks!, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-4.2.4">RFC 9111 §4.2.4</see>: "A
    /// cache MUST NOT generate a stale response unless it is disconnected or doing so is explicitly
    /// permitted by the client or origin server." Once a key set's freshness lapses and the re-attempt
    /// fails, the reference cache must not keep answering with the stale entry it already had.
    /// </summary>
    [TestMethod]
    public async Task ReferenceCacheNeverServesStaleKeySetAfterFailedReattempt()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(JwksUrl, 200, JwksWithKey(RotationKeyIdV1, RotationKeyXV1, RotationKeyYV1),
            contentType: "application/json", headers: Headers(("Cache-Control", "max-age=300")));
        transport.Enqueue(JwksUrl, 500);

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        ClientMetadataResolutionCache cache = NewCache(transport, timeProvider);

        JwksUriResolution first = await cache.ResolveJwksAsync(
            new Uri(JwksUrl), NewContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(first.IsResolved, $"Defect: {first.Defect}");

        timeProvider.Advance(TimeSpan.FromSeconds(301));
        JwksUriResolution second = await cache.ResolveJwksAsync(
            new Uri(JwksUrl), NewContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(second.IsResolved,
            "A failed re-attempt after the key set's freshness lapses must not keep serving the stale key.");
        Assert.IsNull(second.Jwks);
    }


    /// <summary>
    /// A key set whose body is not a well-formed JSON value is refused: RFC 7517 §5's
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-5">"The JSON object MUST have a
    /// 'keys' member, with its value being an array of JWKs"</see> presupposes a well-formed JSON
    /// object, and a document repeating a member name within one key is not one
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 §4</see>). The client
    /// fails closed: the document itself still resolves, but no key set is folded in.
    /// </summary>
    [TestMethod]
    public async Task MalformedJwksBodyIsRefusedAndLeavesTheKeySetUnset()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, PrivateKeyJwtWithJwksUriDocument(ClientMetadataUrl, JwksUrl),
            contentType: "application/json");
        transport.Enqueue(JwksUrl, 200, MalformedDuplicateMemberJwksJson, contentType: "application/json");

        ClientIdMetadataResolution resolution = await ResolveAsync(
            ClientMetadataUrl, transport, WithDirectJwksResolver(transport)).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved,
            $"A malformed key set must not fail the surrounding document resolution. Defect: {resolution.Defect}");
        Assert.IsNull(resolution.Document!.Jwks, "A malformed JWK Set document must never be folded in as the client's key set.");
    }


    /// <summary>
    /// The key-set size cap is the caller's own — the same double-application pattern
    /// draft-ietf-oauth-client-id-metadata-document-02 Section 8.7 applies to the document itself —
    /// and a key set exceeding it is refused rather than folded in.
    /// </summary>
    [TestMethod]
    public async Task JwksExceedingTheSizeCapIsRefused()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, PrivateKeyJwtWithJwksUriDocument(ClientMetadataUrl, JwksUrl),
            contentType: "application/json");
        transport.Enqueue(JwksUrl, 200, OversizedJwksJson(), contentType: "application/json");

        ClientIdMetadataResolution resolution = await ResolveAsync(
            ClientMetadataUrl, transport, WithDirectJwksResolver(transport)).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved,
            $"An oversized key set must not fail the surrounding document resolution. Defect: {resolution.Defect}");
        Assert.IsNull(resolution.Document!.Jwks, "A key set exceeding the configured maximum size must never be folded in.");
    }


    /// <summary>
    /// The <c>jwks_uri</c> fetch is policed by the SAME SSRF policy as every other guarded fetch this
    /// resolver drives (draft-ietf-oauth-client-id-metadata-document-02 Section 8.6): a loopback
    /// <c>jwks_uri</c> is denied before any transport call, exactly as
    /// <see cref="PolicyDenialHappensBeforeAnyTransportCall"/> proves for the document URL itself.
    /// </summary>
    [TestMethod]
    public async Task JwksUriDeniedByPolicyIsNeverDialled()
    {
        const string LoopbackJwksUri = "https://127.0.0.1/jwks.json";

        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, PrivateKeyJwtWithJwksUriDocument(ClientMetadataUrl, LoopbackJwksUri),
            contentType: "application/json");

        ClientIdMetadataResolution resolution = await ResolveAsync(
            ClientMetadataUrl, transport, WithDirectJwksResolver(transport)).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved,
            $"A policy-denied key set fetch must not fail the surrounding document resolution. Defect: {resolution.Defect}");
        Assert.IsNull(resolution.Document!.Jwks);
        Assert.IsEmpty(transport.Calls.FindAll(static c => c.Target.Host == "127.0.0.1"),
            "SecureDefault MUST deny a loopback jwks_uri before any transport call.");
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-8.2">
    /// draft-ietf-oauth-client-id-metadata-document-02 §8.2</see>'s <c>jwks_uri</c> discovery is an
    /// application-wired seam: with no key-set resolver supplied, the document still resolves (the
    /// front channel proceeds) but its <c>jwks_uri</c> is never dereferenced — the same non-fatal
    /// path a discovery failure already takes.
    /// </summary>
    [TestMethod]
    public async Task NoResolverWiredNeverDialsJwksUri()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, PrivateKeyJwtWithJwksUriDocument(ClientMetadataUrl, JwksUrl),
            contentType: "application/json");

        ClientIdMetadataResolution resolution = await ResolveAsync(ClientMetadataUrl, transport).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved, $"Defect: {resolution.Defect}");
        Assert.IsNull(resolution.Document!.Jwks, "With no resolver wired, the jwks_uri must never be dereferenced.");
        Assert.DoesNotContain(JwksUrl, transport.Calls.ConvertAll(static c => c.Target.AbsoluteUri));
    }


    /// <summary>The key-set attempt reports the storable lifetime a <c>max-age</c> response header implies.</summary>
    [TestMethod]
    public async Task JwksUriAttemptReportsStorableFreshnessFromMaxAge()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(JwksUrl, 200, JwksWithKey(RotationKeyIdV1, RotationKeyXV1, RotationKeyYV1),
            contentType: "application/json", headers: Headers(("Cache-Control", "max-age=300")));

        JwksUriResolution resolution = await ResolveJwksAsync(JwksUrl, transport).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved, $"Defect: {resolution.Defect}");
        Assert.IsTrue(resolution.Freshness.IsStorable);
        Assert.AreEqual(TimeSpan.FromSeconds(300), resolution.Freshness.FreshnessLifetime);
    }


    /// <summary>The key-set attempt reports a resolved but not-storable freshness for a <c>no-store</c> response.</summary>
    [TestMethod]
    public async Task JwksUriAttemptReportsNoStoreAsNotStorable()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(JwksUrl, 200, JwksWithKey(RotationKeyIdV1, RotationKeyXV1, RotationKeyYV1),
            contentType: "application/json", headers: Headers(("Cache-Control", "no-store")));

        JwksUriResolution resolution = await ResolveJwksAsync(JwksUrl, transport).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved, $"Defect: {resolution.Defect}");
        Assert.IsFalse(resolution.Freshness.IsStorable, "A no-store response must report a freshness that is not storable.");
    }


    /// <summary>The key-set attempt reports a not-storable freshness for a failed fetch.</summary>
    [TestMethod]
    public async Task JwksUriAttemptReportsFetchFailureAsNotStorable()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(JwksUrl, 500);

        JwksUriResolution resolution = await ResolveJwksAsync(JwksUrl, transport).ConfigureAwait(false);

        Assert.AreEqual(JwksUriResolutionOutcome.FetchFailed, resolution.Outcome);
        Assert.IsFalse(resolution.Freshness.IsStorable, "A failed fetch must report a freshness that is not storable.");
    }


    /// <summary>A content type that is neither application/json nor a +json suffix is an invalid document.</summary>
    [TestMethod]
    public async Task JwksUriWrongContentTypeIsInvalidDocument()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(JwksUrl, 200, JwksWithKey(RotationKeyIdV1, RotationKeyXV1, RotationKeyYV1), contentType: "text/html");

        JwksUriResolution resolution = await ResolveJwksAsync(JwksUrl, transport).ConfigureAwait(false);

        Assert.AreEqual(JwksUriResolutionOutcome.InvalidDocument, resolution.Outcome);
    }


    /// <summary>A 200 response carrying no Content-Type header is refused the same way a wrong one is.</summary>
    [TestMethod]
    public async Task JwksUriMissingContentTypeIsInvalidDocument()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(JwksUrl, 200, JwksWithKey(RotationKeyIdV1, RotationKeyXV1, RotationKeyYV1));

        JwksUriResolution resolution = await ResolveJwksAsync(JwksUrl, transport).ConfigureAwait(false);

        Assert.AreEqual(JwksUriResolutionOutcome.InvalidDocument, resolution.Outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.3.1">RFC 9110 §8.3.1</see>: "The
    /// type/subtype MAY be followed by semicolon-delimited parameters." A charset parameter does not
    /// change the media type the gate compares against.
    /// </summary>
    [TestMethod]
    public async Task JwksUriContentTypeParameterIsAccepted()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(JwksUrl, 200, JwksWithKey(RotationKeyIdV1, RotationKeyXV1, RotationKeyYV1),
            contentType: "application/json; charset=utf-8");

        JwksUriResolution resolution = await ResolveJwksAsync(JwksUrl, transport).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved, $"A charset parameter must not affect the media-type comparison. Defect: {resolution.Defect}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-8.5.1">RFC 7517 §8.5.1</see> registers
    /// the <c>application/jwk-set+json</c> media type for a JWK Set; the <c>+json</c> structured suffix
    /// is accepted alongside the bare <c>application/json</c> media type.
    /// </summary>
    [TestMethod]
    public async Task JwksUriStructuredSuffixContentTypeIsAccepted()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(JwksUrl, 200, JwksWithKey(RotationKeyIdV1, RotationKeyXV1, RotationKeyYV1),
            contentType: "application/jwk-set+json");

        JwksUriResolution resolution = await ResolveJwksAsync(JwksUrl, transport).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved, $"RFC 7517 §8.5.1's application/jwk-set+json must be accepted. Defect: {resolution.Defect}");
    }


    /// <summary>
    /// The document attempt reports the same storable-lifetime freshness reporting as the key-set
    /// attempt, and reports no discovered key set for a document naming no <c>jwks_uri</c>.
    /// </summary>
    [TestMethod]
    public async Task DocumentAttemptReportsStorableFreshnessFromHeaders()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, ValidDocumentJson(ClientMetadataUrl),
            contentType: "application/json", headers: Headers(("Cache-Control", "max-age=300")));

        ClientIdMetadataResolution resolution = await ResolveAsync(ClientMetadataUrl, transport).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved, $"Defect: {resolution.Defect}");
        Assert.IsTrue(resolution.Freshness.IsStorable);
        Assert.AreEqual(TimeSpan.FromSeconds(300), resolution.Freshness.FreshnessLifetime);
        Assert.IsFalse(resolution.HasJwksUriKeySet, "A document with no jwks_uri must not report a discovered key set.");
    }


    /// <summary>The document attempt reports a discovered key set for a private_key_jwt document naming a jwks_uri.</summary>
    [TestMethod]
    public async Task DocumentAttemptReportsKeySetDiscoveredFromJwksUri()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(ClientMetadataUrl, 200, PrivateKeyJwtWithJwksUriDocument(ClientMetadataUrl, JwksUrl),
            contentType: "application/json");
        transport.Enqueue(JwksUrl, 200, JwksWithKey(RotationKeyIdV1, RotationKeyXV1, RotationKeyYV1),
            contentType: "application/json");

        ClientIdMetadataResolution resolution = await ResolveAsync(
            ClientMetadataUrl, transport, WithDirectJwksResolver(transport)).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved, $"Defect: {resolution.Defect}");
        Assert.IsTrue(resolution.HasJwksUriKeySet,
            "A private_key_jwt document naming a jwks_uri instead of an inline jwks must report the key set as discovered.");
    }


    /// <summary>A resolved key-set answer from the refresh helper replaces the resolution's key set.</summary>
    [TestMethod]
    public async Task RefreshHelperReplacesKeySetOnResolvedAnswer()
    {
        const string RefreshedJwksJson = """{"keys":[{"kty":"EC","crv":"P-256","kid":"refreshed"}]}""";
        ClientIdMetadataResolution resolution = ResolutionWithJwksUriDocument("original");

        static ValueTask<JwksUriResolution> ResolveJwksUriAsync(Uri uri, ExchangeContext context, CancellationToken ct) =>
            ValueTask.FromResult(new JwksUriResolution { Outcome = JwksUriResolutionOutcome.Resolved, Jwks = RefreshedJwksJson });

        ClientIdMetadataResolution refreshed = await ClientIdMetadataDocuments.RefreshJwksAsync(
            resolution, ResolveJwksUriAsync, NewContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(RefreshedJwksJson, refreshed.Document!.Jwks);
    }


    /// <summary>A <c>NotRefreshed</c> answer from the refresh helper leaves the resolution unchanged.</summary>
    [TestMethod]
    public async Task RefreshHelperLeavesResolutionUnchangedOnNotRefreshed()
    {
        ClientIdMetadataResolution resolution = ResolutionWithJwksUriDocument("original");

        static ValueTask<JwksUriResolution> ResolveJwksUriAsync(Uri uri, ExchangeContext context, CancellationToken ct) =>
            ValueTask.FromResult(new JwksUriResolution { Outcome = JwksUriResolutionOutcome.NotRefreshed });

        ClientIdMetadataResolution refreshed = await ClientIdMetadataDocuments.RefreshJwksAsync(
            resolution, ResolveJwksUriAsync, NewContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual("original", refreshed.Document!.Jwks);
    }


    /// <summary>A failed answer from the refresh helper leaves the resolution unchanged.</summary>
    [TestMethod]
    public async Task RefreshHelperLeavesResolutionUnchangedOnFailedAnswer()
    {
        ClientIdMetadataResolution resolution = ResolutionWithJwksUriDocument("original");

        static ValueTask<JwksUriResolution> ResolveJwksUriAsync(Uri uri, ExchangeContext context, CancellationToken ct) =>
            ValueTask.FromResult(new JwksUriResolution { Outcome = JwksUriResolutionOutcome.FetchFailed, Defect = "boom" });

        ClientIdMetadataResolution refreshed = await ClientIdMetadataDocuments.RefreshJwksAsync(
            resolution, ResolveJwksUriAsync, NewContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual("original", refreshed.Document!.Jwks);
    }


    private static ClientIdMetadataResolution ResolutionWithJwksUriDocument(string? existingJwks) =>
        new()
        {
            Outcome = ClientIdMetadataResolutionOutcome.Resolved,
            Document = new() { ClientId = ClientMetadataUrl, JwksUri = new Uri(JwksUrl), Jwks = existingJwks },
            HasJwksUriKeySet = true
        };


    //Builds the reference application-layer cache under test, over the scripted transport and pinned clock.
    private static ClientMetadataResolutionCache NewCache(
        ScriptedTransport transport,
        TimeProvider timeProvider,
        TimeSpan? documentMinimumCacheLifetime = null,
        TimeSpan? documentMaximumCacheLifetime = null) =>
        new(
            transport.Delegate,
            new ClientIdMetadataDocumentResolverOptions(),
            new JwksUriResolverOptions(),
            timeProvider,
            documentMinimumCacheLifetime: documentMinimumCacheLifetime,
            documentMaximumCacheLifetime: documentMaximumCacheLifetime);


    //A key-set resolution seam that dials JwksUriResolver.ResolveAsync directly over the SAME scripted
    //transport, with no cache in front of it — what a document-attempt test wires when it only needs
    //jwks_uri to be dereferenced once, not the reference cache's own storage behavior.
    private static ClientIdMetadataDocumentResolverOptions WithDirectJwksResolver(ScriptedTransport transport) =>
        new() { ResolveJwksUri = DirectJwksResolver(transport) };


    private static ResolveJwksUriDelegate DirectJwksResolver(ScriptedTransport transport) =>
        (jwksUri, context, cancellationToken) =>
            JwksUriResolver.ResolveAsync(jwksUri, context, transport.Delegate, new JwksUriResolverOptions(), cancellationToken);


    //Runs the document attempt once directly against a scripted transport, with no cache in front.
    private async Task<ClientIdMetadataResolution> ResolveAsync(
        string clientMetadataUri,
        ScriptedTransport transport,
        ClientIdMetadataDocumentResolverOptions? options = null) =>
        await ClientIdMetadataDocuments.ResolveAsync(
            new Uri(clientMetadataUri, UriKind.Absolute), NewContext(), transport.Delegate,
            options ?? new ClientIdMetadataDocumentResolverOptions(), TestContext.CancellationToken)
            .ConfigureAwait(false);


    //Runs the key-set attempt once directly against a scripted transport, with no cache in front.
    private async Task<JwksUriResolution> ResolveJwksAsync(
        string jwksUri, ScriptedTransport transport, JwksUriResolverOptions? options = null) =>
        await JwksUriResolver.ResolveAsync(
            new Uri(jwksUri, UriKind.Absolute), NewContext(), transport.Delegate,
            options ?? new JwksUriResolverOptions(), TestContext.CancellationToken)
            .ConfigureAwait(false);


    private async Task<ClientIdMetadataResolution> Resolve(ResolveClientMetadataDelegate resolve, string clientMetadataUri) =>
        await resolve(new Uri(clientMetadataUri, UriKind.Absolute), NewContext(), TestContext.CancellationToken)
            .ConfigureAwait(false);


    private static ExchangeContext NewContext()
    {
        ExchangeContext context = [];
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        return context;
    }


    private static string ValidDocumentJson(string clientId) =>
        $$"""{"client_id":"{{clientId}}"}""";


    private static string DocumentWithLogoJson(string clientId, string logoUri) =>
        $$"""{"client_id":"{{clientId}}","logo_uri":"{{logoUri}}"}""";


    private static string PrivateKeyJwtWithJwksUriDocument(string clientId, string jwksUri) =>
        $$"""{"client_id":"{{clientId}}","token_endpoint_auth_method":"private_key_jwt","jwks_uri":"{{jwksUri}}"}""";


    private const string RotationKeyIdV1 = "rotation-key-v1";
    private const string RotationKeyXV1 = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
    private const string RotationKeyYV1 = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

    private const string RotationKeyIdV2 = "rotation-key-v2";
    private const string RotationKeyXV2 = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";
    private const string RotationKeyYV2 = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";


    //A single-key JWK Set carrying one EC P-256 key under the given identifier and coordinates — the
    //same shape the resolver's own well-formedness/"keys" checks accept.
    private static string JwksWithKey(string keyId, string x, string y) =>
        $$"""{"keys":[{"kty":"EC","crv":"P-256","kid":"{{keyId}}","x":"{{x}}","y":"{{y}}"}]}""";


    //RFC 8259 §4: a JWK object repeating "kid" is not exactly one well-formed JSON value, even though
    //a first-match scanner that never checks for duplicates would still find "keys" and a "kid" value.
    private const string MalformedDuplicateMemberJwksJson =
        """{"keys":[{"kty":"EC","crv":"P-256","kid":"dup","kid":"dup","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}""";


    //A well-formed, otherwise-valid JWK Set padded past the resolver's default 5120-byte cap with an
    //oversized (but harmless, since well-formedness never validates a JWK's own field semantics)
    //x5c-shaped filler member.
    private static string OversizedJwksJson() =>
        $$"""{"keys":[{"kty":"EC","crv":"P-256","kid":"k1","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","x5c":"{{new string('a', 6000)}}"}]}""";


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
        private Dictionary<string, List<ScriptedResponse>> Routes { get; } = new(StringComparer.Ordinal);
        private Dictionary<string, int> CallIndex { get; } = new(StringComparer.Ordinal);


        public List<OutboundRequest> Calls { get; } = [];


        public void Enqueue(
            string url, int status, string? body = null, string? contentType = null,
            IReadOnlyDictionary<string, string>? headers = null)
        {
            Dictionary<string, string> merged = headers is null
                ? new(StringComparer.OrdinalIgnoreCase)
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
                ? new(StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase);

            if(contentType is not null)
            {
                merged["Content-Type"] = contentType;
            }

            EnqueueRoute(url, status, body, merged);
        }


        private void EnqueueRoute(string url, int status, byte[]? body, IReadOnlyDictionary<string, string> headers)
        {
            if(!Routes.TryGetValue(url, out List<ScriptedResponse>? list))
            {
                list = [];
                Routes[url] = list;
            }

            list.Add(new ScriptedResponse(status, body, headers));
        }


        public OutboundTransportDelegate Delegate => (request, context, cancellationToken) =>
        {
            Calls.Add(request);

            string url = request.Target.AbsoluteUri;
            ScriptedResponse response;
            if(Routes.TryGetValue(url, out List<ScriptedResponse>? list) && list.Count > 0)
            {
                int index = CallIndex.TryGetValue(url, out int current) ? current : 0;
                response = list[Math.Min(index, list.Count - 1)];
                CallIndex[url] = index + 1;
            }
            else
            {
                response = new ScriptedResponse(404, null, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));
            }

            TaggedMemory<byte> responseBody = response.Body is null
                ? TaggedMemory<byte>.Empty
                : new TaggedMemory<byte>(response.Body, BufferTags.Json);

            var headerBuilder = new HttpHeaderSet.Builder();
            foreach(KeyValuePair<string, string> header in response.Headers)
            {
                _ = headerBuilder.Add(header.Key, header.Value);
            }

            return ValueTask.FromResult(new OutboundResponse
            {
                StatusCode = response.Status,
                Headers = headerBuilder.Build(),
                Body = responseBody
            });
        };


        private sealed record ScriptedResponse(int Status, byte[]? Body, IReadOnlyDictionary<string, string> Headers);
    }
}
