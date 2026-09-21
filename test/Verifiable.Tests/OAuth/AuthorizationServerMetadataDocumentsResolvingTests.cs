using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Outbound;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for <see cref="OAuthResponseParsers.ParseAuthorizationServerMetadata"/>, for
/// <see cref="AuthorizationServerMetadataDocuments.ResolveAsync"/> — the authorization server
/// metadata fetch-validate attempt (<see href="https://www.rfc-editor.org/rfc/rfc8414#section-3">RFC
/// 8414 §3</see>) — and for <see cref="AuthorizationServerMetadataResolutionCache"/>, the reference
/// application-layer cache built on top of it. The single-hop transport is scripted for the unit and
/// attempt tests (the established outbound-fetch-consumer test pattern), and the real-wire test
/// resolves against <see cref="TestHostShell"/>'s own served metadata over an actual HTTPS loopback
/// listener.
/// </summary>
[TestClass]
internal sealed class AuthorizationServerMetadataDocumentsResolvingTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string Issuer = "https://as.example.com";
    private const string MetadataUrl = "https://as.example.com/.well-known/oauth-authorization-server";


    /// <summary>
    /// The full <see href="https://www.rfc-editor.org/rfc/rfc8414#section-3.2">RFC 8414 §3.2</see>
    /// non-normative example response parses member by member, including a member the record does
    /// not carry (<c>service_documentation</c>, <c>ui_locales_supported</c>).
    /// </summary>
    [TestMethod]
    public void ParserParsesRfc8414Section32ExampleMemberByMember()
    {
        const string body = """
            {
             "issuer":
               "https://server.example.com",
             "authorization_endpoint":
               "https://server.example.com/authorize",
             "token_endpoint":
               "https://server.example.com/token",
             "token_endpoint_auth_methods_supported":
               ["client_secret_basic", "private_key_jwt"],
             "token_endpoint_auth_signing_alg_values_supported":
               ["RS256", "ES256"],
             "userinfo_endpoint":
               "https://server.example.com/userinfo",
             "jwks_uri":
               "https://server.example.com/jwks.json",
             "registration_endpoint":
               "https://server.example.com/register",
             "scopes_supported":
               ["openid", "profile", "email", "address",
                "phone", "offline_access"],
             "response_types_supported":
               ["code", "code token"],
             "service_documentation":
               "http://server.example.com/service_documentation.html",
             "ui_locales_supported":
               ["en-US", "en-GB", "en-CA", "fr-FR", "fr-CA"]
            }
            """;

        Result<AuthorizationServerMetadata, OAuthParseError> result =
            OAuthResponseParsers.ParseAuthorizationServerMetadata(new HttpResponseData { Body = body, StatusCode = 200 });

        Assert.IsTrue(result.IsSuccess, $"Defect: {result.Error}");
        AuthorizationServerMetadata metadata = result.Value;
        Assert.AreEqual("https://server.example.com", metadata.Issuer.OriginalString);
        Assert.AreEqual("https://server.example.com/authorize", metadata.AuthorizationEndpoint?.OriginalString);
        Assert.AreEqual("https://server.example.com/token", metadata.TokenEndpoint?.OriginalString);
        Assert.AreEqual("https://server.example.com/userinfo", metadata.UserInfoEndpoint?.OriginalString);
        Assert.AreEqual("https://server.example.com/jwks.json", metadata.JwksUri?.OriginalString);
        Assert.AreEqual("https://server.example.com/register", metadata.RegistrationEndpoint?.OriginalString);
        Assert.AreSequenceEqual(ExampleTokenEndpointAuthMethodsSupported, metadata.TokenEndpointAuthMethodsSupported);
        Assert.AreSequenceEqual(ExampleTokenEndpointAuthSigningAlgValuesSupported, metadata.TokenEndpointAuthSigningAlgValuesSupported);
        Assert.AreSequenceEqual(ExampleScopesSupported, metadata.ScopesSupported);
        Assert.AreSequenceEqual(ExampleResponseTypesSupported, metadata.ResponseTypesSupported);
    }


    /// <summary>The RFC 8414 §3.2 example's <c>token_endpoint_auth_methods_supported</c> value.</summary>
    private static IReadOnlyList<string> ExampleTokenEndpointAuthMethodsSupported { get; } =
        ["client_secret_basic", "private_key_jwt"];

    /// <summary>The RFC 8414 §3.2 example's <c>token_endpoint_auth_signing_alg_values_supported</c> value.</summary>
    private static IReadOnlyList<string> ExampleTokenEndpointAuthSigningAlgValuesSupported { get; } =
        ["RS256", "ES256"];

    /// <summary>The RFC 8414 §3.2 example's <c>scopes_supported</c> value.</summary>
    private static IReadOnlyList<string> ExampleScopesSupported { get; } =
        ["openid", "profile", "email", "address", "phone", "offline_access"];

    /// <summary>The RFC 8414 §3.2 example's <c>response_types_supported</c> value.</summary>
    private static IReadOnlyList<string> ExampleResponseTypesSupported { get; } =
        ["code", "code token"];

    /// <summary>The two-value list <see cref="ParserRoundTripsATwoValueSupportedList"/> round-trips.</summary>
    private static IReadOnlyList<string> RoundTripScopes { get; } = ["openid", "profile"];


    /// <summary>RFC 8414 §2 makes <c>issuer</c> REQUIRED; a body without it is malformed.</summary>
    [TestMethod]
    public void ParserRejectsBodyWithoutIssuerAsMalformed()
    {
        Result<AuthorizationServerMetadata, OAuthParseError> result = OAuthResponseParsers.ParseAuthorizationServerMetadata(
            new HttpResponseData { Body = """{"token_endpoint":"https://server.example.com/token"}""", StatusCode = 200 });

        Assert.IsFalse(result.IsSuccess);
        _ = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
    }


    /// <summary>An endpoint member present but not an absolute URI is an invalid field naming the member.</summary>
    [TestMethod]
    public void ParserRejectsNonAbsoluteEndpointAsInvalidFieldNamingMember()
    {
        Result<AuthorizationServerMetadata, OAuthParseError> result = OAuthResponseParsers.ParseAuthorizationServerMetadata(
            new HttpResponseData
            {
                Body = """{"issuer":"https://server.example.com","token_endpoint":"not-a-uri"}""",
                StatusCode = 200
            });

        Assert.IsFalse(result.IsSuccess);
        OAuthInvalidFieldValue invalid = Assert.IsInstanceOfType<OAuthInvalidFieldValue>(result.Error);
        Assert.AreEqual(AuthorizationServerMetadataParameterNames.TokenEndpoint, invalid.FieldName);
    }


    /// <summary>
    /// RFC 8414 §3.2: "Other claims MAY also be returned." A member the record does not carry is
    /// ignored rather than failing the parse.
    /// </summary>
    [TestMethod]
    public void ParserIgnoresAnUnknownMember()
    {
        Result<AuthorizationServerMetadata, OAuthParseError> result = OAuthResponseParsers.ParseAuthorizationServerMetadata(
            new HttpResponseData
            {
                Body = """{"issuer":"https://server.example.com","service_documentation":"http://server.example.com/docs.html"}""",
                StatusCode = 200
            });

        Assert.IsTrue(result.IsSuccess, $"Defect: {result.Error}");
        Assert.AreEqual("https://server.example.com", result.Value.Issuer.OriginalString);
    }


    /// <summary>A <c>*_supported</c> list of two values round-trips through the array reader.</summary>
    [TestMethod]
    public void ParserRoundTripsATwoValueSupportedList()
    {
        Result<AuthorizationServerMetadata, OAuthParseError> result = OAuthResponseParsers.ParseAuthorizationServerMetadata(
            new HttpResponseData
            {
                Body = """{"issuer":"https://server.example.com","scopes_supported":["openid","profile"]}""",
                StatusCode = 200
            });

        Assert.IsTrue(result.IsSuccess, $"Defect: {result.Error}");
        Assert.AreSequenceEqual(RoundTripScopes, result.Value.ScopesSupported);
    }


    /// <summary>An absent OPTIONAL boolean member reads as <see langword="false"/>.</summary>
    [TestMethod]
    public void ParserReadsAnAbsentBooleanAsFalse()
    {
        Result<AuthorizationServerMetadata, OAuthParseError> result = OAuthResponseParsers.ParseAuthorizationServerMetadata(
            new HttpResponseData { Body = """{"issuer":"https://server.example.com"}""", StatusCode = 200 });

        Assert.IsTrue(result.IsSuccess, $"Defect: {result.Error}");
        Assert.IsFalse(result.Value.RequirePushedAuthorizationRequests);
    }


    /// <summary>RFC 8414 §3.1's first worked example: a root issuer has no path insertion.</summary>
    [TestMethod]
    public async Task MetadataUrlForRootIssuerHasNoPathInsertion()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson(Issuer), contentType: "application/json");

        _ = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        Assert.HasCount(1, transport.Calls);
        Assert.AreEqual(MetadataUrl, transport.Calls[0].Target.AbsoluteUri);
    }


    /// <summary>
    /// RFC 8414 §3.1's second worked example, with the "any terminating '/' MUST be removed" rule
    /// exercised through the attempt: a path-bearing issuer carrying a trailing slash still inserts
    /// the suffix before the bare path component.
    /// </summary>
    [TestMethod]
    public async Task MetadataUrlForPathIssuerInsertsSuffixWithTrailingSlashRemoved()
    {
        const string PathIssuer = "https://as.example.com/tenant1/";
        const string ExpectedUrl = "https://as.example.com/.well-known/oauth-authorization-server/tenant1";

        ScriptedTransport transport = new();
        transport.Enqueue(ExpectedUrl, 200, ValidDocumentJson(PathIssuer), contentType: "application/json");

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(PathIssuer, transport).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved, $"Defect: {resolution.Defect}");
        Assert.HasCount(1, transport.Calls);
        Assert.AreEqual(ExpectedUrl, transport.Calls[0].Target.AbsoluteUri);
    }


    /// <summary>RFC 8414 §2 requires an <c>https</c> issuer; a plain-<c>http</c> issuer never dials.</summary>
    [TestMethod]
    public async Task HttpIssuerNeverDials()
    {
        ScriptedTransport transport = new();

        AuthorizationServerMetadataResolution resolution = await ResolveAsync("http://as.example.com", transport).ConfigureAwait(false);

        Assert.AreEqual(AuthorizationServerMetadataResolutionOutcome.InvalidIssuer, resolution.Outcome);
        Assert.IsEmpty(transport.Calls, "A plain-http issuer must never reach the transport.");
    }


    /// <summary>An SSRF-blocked target (a loopback IP literal) is denied before any transport call.</summary>
    [TestMethod]
    public async Task PolicyDeniedIssuerNeverDials()
    {
        ScriptedTransport transport = new();

        AuthorizationServerMetadataResolution resolution = await ResolveAsync("https://127.0.0.1", transport).ConfigureAwait(false);

        Assert.AreEqual(AuthorizationServerMetadataResolutionOutcome.PolicyDenied, resolution.Outcome);
        Assert.IsEmpty(transport.Calls, "SecureDefault MUST deny a loopback target before any transport call.");
    }


    /// <summary>RFC 8414 §3.2: "A successful response MUST use the 200 OK HTTP status code." Any other status is a fetch failure.</summary>
    [TestMethod]
    public async Task NonTwoHundredStatusIsFetchFailed()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 404);

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        Assert.AreEqual(AuthorizationServerMetadataResolutionOutcome.FetchFailed, resolution.Outcome);
    }


    /// <summary>
    /// RFC 8414 §3.2 requires exactly the <c>application/json</c> content type — unlike a CIMD or
    /// JWKS fetch, no <c>+json</c> structured-suffix is accepted here.
    /// </summary>
    [TestMethod]
    public async Task WrongContentTypeIsInvalidDocument()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson(Issuer), contentType: "text/html");

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        Assert.AreEqual(AuthorizationServerMetadataResolutionOutcome.InvalidDocument, resolution.Outcome);
    }


    /// <summary>
    /// RFC 8414 §3.3: "the issuer value returned MUST be identical ... If these values are not
    /// identical, the data contained in the response MUST NOT be used." A default-port suffix the
    /// spec's own comparison rule treats as non-equivalent is refused with the distinct
    /// <see cref="AuthorizationServerMetadataResolutionOutcome.IssuerMismatch"/> outcome, not folded
    /// into <see cref="AuthorizationServerMetadataResolutionOutcome.InvalidDocument"/>.
    /// </summary>
    [TestMethod]
    public async Task DefaultPortSuffixIssuerMismatchIsADistinctOutcome()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson("https://as.example.com:443"), contentType: "application/json");

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        Assert.AreEqual(AuthorizationServerMetadataResolutionOutcome.IssuerMismatch, resolution.Outcome);
    }


    /// <summary>RFC 8414 §3.3's issuer match is code-point ordinal; a trailing slash is not equivalent.</summary>
    [TestMethod]
    public async Task TrailingSlashIssuerMismatchIsADistinctOutcome()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson(Issuer + "/"), contentType: "application/json");

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        Assert.AreEqual(AuthorizationServerMetadataResolutionOutcome.IssuerMismatch, resolution.Outcome);
    }


    /// <summary>A resolved attempt reports the freshness a <c>max-age</c> response header implies (RFC 9111 §5.2).</summary>
    [TestMethod]
    public async Task ResolvedAttemptReportsMaxAgeFreshness()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson(Issuer), contentType: "application/json",
            headers: Headers(("Cache-Control", "max-age=300")));

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved, $"Defect: {resolution.Defect}");
        Assert.IsTrue(resolution.Freshness.IsStorable);
        Assert.AreEqual(TimeSpan.FromSeconds(300), resolution.Freshness.FreshnessLifetime);
    }


    /// <summary>A failed attempt reports a freshness that is not storable, so a caller cannot infer a cacheable lifetime.</summary>
    [TestMethod]
    public async Task FailedAttemptReportsNonStorableFreshness()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 500);

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        Assert.AreEqual(AuthorizationServerMetadataResolutionOutcome.FetchFailed, resolution.Outcome);
        Assert.IsFalse(resolution.Freshness.IsStorable, "A failed fetch must report a freshness that is not storable.");
    }


    /// <summary>
    /// The house's real-wire E2E for a normative clause: <see cref="TestHostShell"/> publishes its own
    /// metadata at the RFC 8414 §3 default location, over a real HTTPS loopback listener, and the
    /// attempt resolves it — the issuer matches and the token endpoint equals the shell's own.
    /// </summary>
    [TestMethod]
    public async Task RealWire_ResolvesMetadataFromTestHostShell()
    {
        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using TestHostShell app = new(timeProvider);

        using VerifierKeyMaterial material = await app.RegisterClientAsync(
            "real-wire-as-metadata-client",
            new Uri("https://client.example.com"),
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint),
            profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        ClientRecord aligned = app.AlignRegistrationToHostHttpBase("default", material.Registration);
        HostedAuthorizationServer hosted = app.Host("default");
        Uri issuer = aligned.IssuerUri!;

        OutboundTransportDelegate transport = GuardedHttpClientTransport.BuildSingleHopTransport(hosted.SharedHttpClient!);
        ExchangeContext context = [];
        context.SetOutboundFetchPolicy(TestHostShell.LoopbackOutboundFetchPolicy);

        AuthorizationServerMetadataResolution resolution = await AuthorizationServerMetadataDocuments.ResolveAsync(
            issuer, WellKnownPaths.OAuthAuthorizationServer, context, transport,
            new AuthorizationServerMetadataResolverOptions(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved, $"Defect: {resolution.Defect}");
        Assert.IsTrue(AuthorizationServerMetadataValidation.IsIssuerMatch(resolution.Metadata!, issuer),
            "The real-wire document's issuer must match the identifier the metadata URL was derived from.");

        Uri expectedTokenEndpoint = TestHostShell.ComposeEndpointUri(
            hosted.HttpBaseAddress!, aligned.TenantId.Value, WellKnownEndpointNames.AuthCodeToken);
        Assert.AreEqual(expectedTokenEndpoint, resolution.Metadata!.TokenEndpoint);
    }


    /// <summary>A fresh cache hit answers without dialing the transport again.</summary>
    [TestMethod]
    public async Task ReferenceCacheFreshHitDoesNotRedial()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson(Issuer), contentType: "application/json",
            headers: Headers(("Cache-Control", "max-age=300")));

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        AuthorizationServerMetadataResolutionCache cache = NewCache(transport, timeProvider);

        AuthorizationServerMetadataResolution first = await cache.ResolveAsync(new Uri(Issuer), NewContext(), TestContext.CancellationToken).ConfigureAwait(false);
        AuthorizationServerMetadataResolution second = await cache.ResolveAsync(new Uri(Issuer), NewContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(Issuer, first.Metadata!.Issuer.OriginalString);
        Assert.AreEqual(Issuer, second.Metadata!.Issuer.OriginalString);
        Assert.HasCount(1, transport.Calls, "A fresh cache hit must not re-dial the transport.");
    }


    /// <summary>A stale cache entry re-fetches after the freshness lifetime elapses.</summary>
    [TestMethod]
    public async Task ReferenceCacheStaleEntryReFetches()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson(Issuer), contentType: "application/json",
            headers: Headers(("Cache-Control", "max-age=300")));
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson(Issuer), contentType: "application/json",
            headers: Headers(("Cache-Control", "max-age=300")));

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        AuthorizationServerMetadataResolutionCache cache = NewCache(transport, timeProvider);

        _ = await cache.ResolveAsync(new Uri(Issuer), NewContext(), TestContext.CancellationToken).ConfigureAwait(false);
        timeProvider.Advance(TimeSpan.FromSeconds(301));
        _ = await cache.ResolveAsync(new Uri(Issuer), NewContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(2, transport.Calls, "A stale cache entry must trigger a re-fetch.");
    }


    /// <summary>
    /// RFC 9111 §4.2.4: "A cache MUST NOT generate a stale response unless it is disconnected or
    /// doing so is explicitly permitted by the client or origin server." Once the cached entry goes
    /// stale and the re-attempt fails, the reference cache must not keep answering with it — it drops
    /// the entry and returns the non-resolved resolution as a value, the channel
    /// <see cref="ResolveAuthorizationServerMetadataDelegate"/> shares with its two siblings.
    /// </summary>
    [TestMethod]
    public async Task ReferenceCacheFailedReattemptDoesNotServeStaleRecord()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson(Issuer), contentType: "application/json",
            headers: Headers(("Cache-Control", "max-age=300")));
        transport.Enqueue(MetadataUrl, 500);

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        AuthorizationServerMetadataResolutionCache cache = NewCache(transport, timeProvider);

        AuthorizationServerMetadataResolution first = await cache.ResolveAsync(new Uri(Issuer), NewContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(Issuer, first.Metadata!.Issuer.OriginalString);

        timeProvider.Advance(TimeSpan.FromSeconds(301));

        AuthorizationServerMetadataResolution second = await cache.ResolveAsync(new Uri(Issuer), NewContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(second.IsResolved);
        Assert.AreEqual(AuthorizationServerMetadataResolutionOutcome.FetchFailed, second.Outcome);
        Assert.IsNull(second.Metadata, "A non-resolved re-attempt must not serve the stale record.");
    }


    /// <summary>Builds the reference application-layer cache under test, over the scripted transport and pinned clock.</summary>
    private static AuthorizationServerMetadataResolutionCache NewCache(ScriptedTransport transport, TimeProvider timeProvider) =>
        new(transport.Delegate, WellKnownPaths.OAuthAuthorizationServer, new AuthorizationServerMetadataResolverOptions(), timeProvider);


    /// <summary>Runs the attempt once directly against a scripted transport, with no cache in front.</summary>
    private async Task<AuthorizationServerMetadataResolution> ResolveAsync(
        string issuer, ScriptedTransport transport, AuthorizationServerMetadataResolverOptions? options = null) =>
        await AuthorizationServerMetadataDocuments.ResolveAsync(
            new Uri(issuer, UriKind.Absolute), WellKnownPaths.OAuthAuthorizationServer, NewContext(), transport.Delegate,
            options ?? new AuthorizationServerMetadataResolverOptions(), TestContext.CancellationToken)
            .ConfigureAwait(false);


    /// <summary>A fresh <see cref="ExchangeContext"/> with the SecureDefault outbound-fetch policy.</summary>
    private static ExchangeContext NewContext()
    {
        ExchangeContext context = [];
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        return context;
    }


    /// <summary>A minimal, otherwise-conformant metadata document body naming only <paramref name="issuer"/>.</summary>
    private static string ValidDocumentJson(string issuer) =>
        $$"""{"issuer":"{{issuer}}"}""";


    /// <summary>Builds a case-insensitive header map from name/value pairs, for a scripted response.</summary>
    private static Dictionary<string, string> Headers(params (string Name, string Value)[] headers)
    {
        Dictionary<string, string> result = new(StringComparer.OrdinalIgnoreCase);
        foreach((string name, string value) in headers)
        {
            result[name] = value;
        }

        return result;
    }


    /// <summary>
    /// A single-hop transport that plays back a scripted sequence of (status, body, headers) per
    /// absolute URL — each call to a routed URL dequeues the next scripted response, sticking to
    /// the last one once the sequence is exhausted; an unrouted URL is a 404. Bodies are carried as
    /// <see cref="TaggedMemory{T}"/>, mirroring the production <see cref="OutboundResponse"/> shape.
    /// Mirrors the private <c>ScriptedTransport</c> in <c>ClientIdMetadataDocumentsResolvingTests</c>,
    /// which is file-private and not itself reusable across test files.
    /// </summary>
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
