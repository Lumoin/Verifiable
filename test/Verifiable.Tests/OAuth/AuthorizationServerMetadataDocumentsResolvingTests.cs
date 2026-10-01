using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Outbound;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for <see cref="AuthorizationServerMetadataJson.Parse"/>, for
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
    /// <summary>The runner's per-test cancellation context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The requested issuer used by scripted resolutions.</summary>
    private const string Issuer = "https://as.example.com";

    /// <summary>The issuer's RFC 8414 well-known location.</summary>
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

        Result<AuthorizationServerMetadata, AuthorizationServerMetadataParseError> result =
            AuthorizationServerMetadataJson.Parse(Encoding.UTF8.GetBytes(body));

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
        Result<AuthorizationServerMetadata, AuthorizationServerMetadataParseError> result = AuthorizationServerMetadataJson.Parse(
            Encoding.UTF8.GetBytes("""{"token_endpoint":"https://server.example.com/token"}"""));

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(AuthorizationServerMetadataUnreadableReason.MissingIssuer, result.Error.Reason);
    }


    /// <summary>An endpoint member present but not an absolute URI is an invalid field naming the member.</summary>
    [TestMethod]
    public void ParserRejectsNonAbsoluteEndpointAsInvalidFieldNamingMember()
    {
        Result<AuthorizationServerMetadata, AuthorizationServerMetadataParseError> result = AuthorizationServerMetadataJson.Parse(
            Encoding.UTF8.GetBytes("""{"issuer":"https://server.example.com","token_endpoint":"not-a-uri"}"""));

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(AuthorizationServerMetadataUnreadableReason.InvalidUri, result.Error.Reason);
        Assert.AreEqual(AuthorizationServerMetadataParameterNames.TokenEndpoint, result.Error.MemberName);
    }


    /// <summary>
    /// RFC 8414 §3.2: "Other claims MAY also be returned." A member the record does not carry is
    /// ignored rather than failing the parse.
    /// </summary>
    [TestMethod]
    public void ParserIgnoresAnUnknownMember()
    {
        Result<AuthorizationServerMetadata, AuthorizationServerMetadataParseError> result = AuthorizationServerMetadataJson.Parse(
            Encoding.UTF8.GetBytes("""{"issuer":"https://server.example.com","service_documentation":"http://server.example.com/docs.html"}"""));

        Assert.IsTrue(result.IsSuccess, $"Defect: {result.Error}");
        Assert.AreEqual("https://server.example.com", result.Value.Issuer.OriginalString);
    }


    /// <summary>A <c>*_supported</c> list of two values round-trips through the array reader.</summary>
    [TestMethod]
    public void ParserRoundTripsATwoValueSupportedList()
    {
        Result<AuthorizationServerMetadata, AuthorizationServerMetadataParseError> result = AuthorizationServerMetadataJson.Parse(
            Encoding.UTF8.GetBytes("""{"issuer":"https://server.example.com","scopes_supported":["openid","profile"]}"""));

        Assert.IsTrue(result.IsSuccess, $"Defect: {result.Error}");
        Assert.AreSequenceEqual(RoundTripScopes, result.Value.ScopesSupported);
    }


    /// <summary>An absent OPTIONAL boolean member reads as <see langword="false"/>.</summary>
    [TestMethod]
    public void ParserReadsAnAbsentBooleanAsFalse()
    {
        Result<AuthorizationServerMetadata, AuthorizationServerMetadataParseError> result = AuthorizationServerMetadataJson.Parse(
            Encoding.UTF8.GetBytes("""{"issuer":"https://server.example.com"}"""));

        Assert.IsTrue(result.IsSuccess, $"Defect: {result.Error}");
        Assert.IsFalse(result.Value.RequirePushedAuthorizationRequests);
    }


    /// <summary>RFC 8414 §3.1's first worked example: a root issuer has no path insertion.</summary>
    [TestMethod]
    public async Task MetadataUrlForRootIssuerHasNoPathInsertion()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson(Issuer), contentType: WellKnownMediaTypes.Application.Json);

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
        transport.Enqueue(ExpectedUrl, 200, ValidDocumentJson(PathIssuer), contentType: WellKnownMediaTypes.Application.Json);

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(PathIssuer, transport).ConfigureAwait(false);

        AuthorizationServerMetadataResolved resolved =
            Assert.IsInstanceOfType<AuthorizationServerMetadataResolved>(resolution);
        Assert.HasCount(1, transport.Calls);
        Assert.AreEqual(ExpectedUrl, transport.Calls[0].Target.AbsoluteUri);
        Assert.AreEqual(ExpectedUrl, resolved.MetadataLocation.OriginalString);
    }


    /// <summary>RFC 8414 §2 requires an <c>https</c> issuer; a plain-<c>http</c> issuer never dials.</summary>
    [TestMethod]
    public async Task HttpIssuerNeverDials()
    {
        ScriptedTransport transport = new();

        AuthorizationServerMetadataResolution resolution = await ResolveAsync("http://as.example.com", transport).ConfigureAwait(false);

        AuthorizationServerMetadataInvalidIssuer invalid =
            Assert.IsInstanceOfType<AuthorizationServerMetadataInvalidIssuer>(resolution);
        Assert.AreEqual("http://as.example.com", invalid.Issuer.OriginalString);
        Assert.IsEmpty(transport.Calls, "A plain-http issuer must never reach the transport.");
    }


    /// <summary>An SSRF-blocked target (a loopback IP literal) is denied before any transport call.</summary>
    [TestMethod]
    public async Task PolicyDeniedIssuerNeverDials()
    {
        ScriptedTransport transport = new();

        AuthorizationServerMetadataResolution resolution = await ResolveAsync("https://127.0.0.1", transport).ConfigureAwait(false);

        AuthorizationServerMetadataPolicyDenied denied =
            Assert.IsInstanceOfType<AuthorizationServerMetadataPolicyDenied>(resolution);
        Assert.AreEqual("https://127.0.0.1/.well-known/oauth-authorization-server", denied.Target.OriginalString);
        Assert.IsEmpty(transport.Calls, "SecureDefault MUST deny a loopback target before any transport call.");
    }


    /// <summary>RFC 8414 §3.2: "A successful response MUST use the 200 OK HTTP status code." Any other terminal status is reported with its code.</summary>
    [TestMethod]
    public async Task NonTwoHundredStatusIsNotAnsweredWithStatus()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 404);

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        AuthorizationServerMetadataNotAnswered notAnswered =
            Assert.IsInstanceOfType<AuthorizationServerMetadataNotAnswered>(resolution);
        Assert.AreEqual(404, notAnswered.StatusCode);
    }


    /// <summary>
    /// RFC 8414 §3.2 requires exactly the <c>application/json</c> content type — unlike a CIMD or
    /// JWKS fetch, no <c>+json</c> structured-suffix is accepted here.
    /// </summary>
    [TestMethod]
    public async Task WrongContentTypeIsUnsupportedMediaType()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson(Issuer), contentType: "text/html");

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        AuthorizationServerMetadataUnsupportedMediaType unsupported =
            Assert.IsInstanceOfType<AuthorizationServerMetadataUnsupportedMediaType>(resolution);
        Assert.AreEqual("text/html", unsupported.ContentType);
    }


    /// <summary>
    /// RFC 8414 §3.3: "the issuer value returned MUST be identical ... If these values are not
    /// identical, the data contained in the response MUST NOT be used." A default-port suffix the
    /// spec's own comparison rule treats as non-equivalent is refused with the distinct
    /// <see cref="AuthorizationServerMetadataIssuerMismatch"/> outcome, not folded
    /// into <see cref="AuthorizationServerMetadataUnreadable"/>.
    /// </summary>
    [TestMethod]
    public async Task DefaultPortSuffixIssuerMismatchIsADistinctOutcome()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson("https://as.example.com:443"), contentType: WellKnownMediaTypes.Application.Json);

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        _ = Assert.IsInstanceOfType<AuthorizationServerMetadataIssuerMismatch>(resolution);
    }


    /// <summary>RFC 8414 §3.3's issuer match is code-point ordinal; a trailing slash is not equivalent.</summary>
    [TestMethod]
    public async Task TrailingSlashIssuerMismatchIsADistinctOutcome()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson(Issuer + "/"), contentType: WellKnownMediaTypes.Application.Json);

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        _ = Assert.IsInstanceOfType<AuthorizationServerMetadataIssuerMismatch>(resolution);
    }


    /// <summary>A resolved attempt reports the freshness a <c>max-age</c> response header implies (RFC 9111 §5.2).</summary>
    [TestMethod]
    public async Task ResolvedAttemptReportsMaxAgeFreshness()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson(Issuer), contentType: WellKnownMediaTypes.Application.Json,
            headers: Headers((WellKnownHttpHeaderNames.CacheControl, "max-age=300")));

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        AuthorizationServerMetadataResolved resolved =
            Assert.IsInstanceOfType<AuthorizationServerMetadataResolved>(resolution);
        Assert.IsTrue(resolved.Freshness.IsStorable);
        Assert.AreEqual(TimeSpan.FromSeconds(300), resolved.Freshness.FreshnessLifetime);
    }


    /// <summary>A failed attempt carries its status; only the resolved type exposes a cacheable document.</summary>
    [TestMethod]
    public async Task FailedAttemptCarriesStatus()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 500);

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        AuthorizationServerMetadataNotAnswered notAnswered =
            Assert.IsInstanceOfType<AuthorizationServerMetadataNotAnswered>(resolution);
        Assert.AreEqual(500, notAnswered.StatusCode);
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
            issuer, WellKnownPaths.OAuthAuthorizationServer, context, transport, AuthorizationServerMetadataJson.Parse,
            new AuthorizationServerMetadataResolverOptions(), TestContext.CancellationToken).ConfigureAwait(false);

        AuthorizationServerMetadataResolved resolved =
            Assert.IsInstanceOfType<AuthorizationServerMetadataResolved>(resolution);
        Assert.IsTrue(AuthorizationServerMetadataValidation.IsIssuerMatch(resolved.Metadata, issuer),
            "The real-wire document's issuer must match the identifier the metadata URL was derived from.");

        Uri expectedTokenEndpoint = TestHostShell.ComposeEndpointUri(
            hosted.HttpBaseAddress!, aligned.TenantId.Value, WellKnownEndpointNames.AuthCodeToken);
        Assert.AreEqual(expectedTokenEndpoint, resolved.Metadata.TokenEndpoint);
    }


    /// <summary>A fresh cache hit answers without dialing the transport again.</summary>
    [TestMethod]
    public async Task ReferenceCacheFreshHitDoesNotRedial()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson(Issuer), contentType: WellKnownMediaTypes.Application.Json,
            headers: Headers((WellKnownHttpHeaderNames.CacheControl, "max-age=300")));

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        AuthorizationServerMetadataResolutionCache cache = NewCache(transport, timeProvider);

        AuthorizationServerMetadataResolution first = await cache.ResolveAsync(new Uri(Issuer), NewContext(), TestContext.CancellationToken).ConfigureAwait(false);
        AuthorizationServerMetadataResolution second = await cache.ResolveAsync(new Uri(Issuer), NewContext(), TestContext.CancellationToken).ConfigureAwait(false);

        AuthorizationServerMetadataResolved firstResolved =
            Assert.IsInstanceOfType<AuthorizationServerMetadataResolved>(first);
        Assert.AreEqual(Issuer, firstResolved.PublishedIssuer);
        AuthorizationServerMetadataResolved secondResolved =
            Assert.IsInstanceOfType<AuthorizationServerMetadataResolved>(second);
        Assert.AreEqual(Issuer, secondResolved.PublishedIssuer);
        Assert.AreEqual(MetadataUrl, secondResolved.MetadataLocation.OriginalString);
        Assert.IsTrue(firstResolved.Freshness.IsStorable);
        Assert.IsFalse(secondResolved.Freshness.IsStorable, "A cache hit must not advertise a new response freshness lifetime.");
        Assert.HasCount(1, transport.Calls, "A fresh cache hit must not re-dial the transport.");
    }


    /// <summary>A stale cache entry re-fetches after the freshness lifetime elapses.</summary>
    [TestMethod]
    public async Task ReferenceCacheStaleEntryReFetches()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson(Issuer), contentType: WellKnownMediaTypes.Application.Json,
            headers: Headers((WellKnownHttpHeaderNames.CacheControl, "max-age=300")));
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson(Issuer), contentType: WellKnownMediaTypes.Application.Json,
            headers: Headers((WellKnownHttpHeaderNames.CacheControl, "max-age=300")));

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
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson(Issuer), contentType: WellKnownMediaTypes.Application.Json,
            headers: Headers((WellKnownHttpHeaderNames.CacheControl, "max-age=300")));
        transport.Enqueue(MetadataUrl, 500);

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        AuthorizationServerMetadataResolutionCache cache = NewCache(transport, timeProvider);

        AuthorizationServerMetadataResolution first = await cache.ResolveAsync(new Uri(Issuer), NewContext(), TestContext.CancellationToken).ConfigureAwait(false);
        AuthorizationServerMetadataResolved firstResolved =
            Assert.IsInstanceOfType<AuthorizationServerMetadataResolved>(first);
        Assert.AreEqual(Issuer, firstResolved.PublishedIssuer);

        timeProvider.Advance(TimeSpan.FromSeconds(301));

        AuthorizationServerMetadataResolution second = await cache.ResolveAsync(new Uri(Issuer), NewContext(), TestContext.CancellationToken).ConfigureAwait(false);

        AuthorizationServerMetadataNotAnswered notAnswered =
            Assert.IsInstanceOfType<AuthorizationServerMetadataNotAnswered>(second);
        Assert.AreEqual(500, notAnswered.StatusCode);
    }


    /// <summary>The resolved outcome preserves the published issuer and the document's location.</summary>
    [TestMethod]
    public async Task MatchingIssuerResolvesWithPublishedIssuerAndLocation()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson(Issuer), contentType: WellKnownMediaTypes.Application.Json);

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        AuthorizationServerMetadataResolved resolved =
            Assert.IsInstanceOfType<AuthorizationServerMetadataResolved>(resolution);
        Assert.AreEqual(Issuer, resolved.PublishedIssuer);
        Assert.AreEqual(Issuer, resolved.Metadata.Issuer.OriginalString);
        Assert.AreEqual(MetadataUrl, resolved.MetadataLocation.OriginalString);
    }


    /// <summary>A mismatch preserves both identifiers and where the server published its value.</summary>
    [TestMethod]
    public async Task DifferentIssuerReportsBothValuesAndLocation()
    {
        const string PublishedIssuer = "https://other.example.com";
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson(PublishedIssuer), contentType: WellKnownMediaTypes.Application.Json);

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        AuthorizationServerMetadataIssuerMismatch mismatch =
            Assert.IsInstanceOfType<AuthorizationServerMetadataIssuerMismatch>(resolution);
        Assert.AreEqual(Issuer, mismatch.RequestedIssuer.OriginalString);
        Assert.AreEqual(PublishedIssuer, mismatch.PublishedIssuer);
        Assert.AreEqual(MetadataUrl, mismatch.MetadataLocation.OriginalString);
    }


    /// <summary>
    /// A quoted, non-object body with an unescaped issuer fragment is invalid JSON. The former
    /// substring scanner accepted the embedded fragment without checking the enclosing document.
    /// </summary>
    [TestMethod]
    public async Task IssuerSubstringInsideMalformedStringIsUnreadable()
    {
        string body = "\"prefix " + ValidDocumentJson(Issuer) + " suffix\"";
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, body, contentType: WellKnownMediaTypes.Application.Json);

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        AuthorizationServerMetadataUnreadable unreadable =
            Assert.IsInstanceOfType<AuthorizationServerMetadataUnreadable>(resolution);
        Assert.AreEqual(AuthorizationServerMetadataUnreadableReason.InvalidJson, unreadable.Error.Reason);
    }


    /// <summary>A valid JSON array containing an issuer object is not a metadata object.</summary>
    [TestMethod]
    public async Task IssuerInsideArrayIsUnreadableAsNotObject()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, "[" + ValidDocumentJson(Issuer) + "]",
            contentType: WellKnownMediaTypes.Application.Json);

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        AuthorizationServerMetadataUnreadable unreadable =
            Assert.IsInstanceOfType<AuthorizationServerMetadataUnreadable>(resolution);
        Assert.AreEqual(AuthorizationServerMetadataUnreadableReason.NotObject, unreadable.Error.Reason);
    }


    /// <summary>A valid JSON string containing escaped issuer syntax is not a metadata object.</summary>
    [TestMethod]
    public async Task IssuerInsideJsonStringIsUnreadableAsNotObject()
    {
        const string Body = """
            "{\"issuer\":\"https://as.example.com\"}"
            """;
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, Body, contentType: WellKnownMediaTypes.Application.Json);

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        AuthorizationServerMetadataUnreadable unreadable =
            Assert.IsInstanceOfType<AuthorizationServerMetadataUnreadable>(resolution);
        Assert.AreEqual(AuthorizationServerMetadataUnreadableReason.NotObject, unreadable.Error.Reason);
    }


    /// <summary>JSON escapes are decoded before the ordinal issuer comparison and evidence capture.</summary>
    [TestMethod]
    public async Task EscapedIssuerResolvesToDecodedValue()
    {
        const string Body = """{"issuer":"https:\/\/as\u002eexample.com"}""";
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, Body, contentType: WellKnownMediaTypes.Application.Json);

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        AuthorizationServerMetadataResolved resolved =
            Assert.IsInstanceOfType<AuthorizationServerMetadataResolved>(resolution);
        Assert.AreEqual(Issuer, resolved.PublishedIssuer);
        Assert.AreEqual(Issuer, resolved.Metadata.Issuer.OriginalString);
        Assert.AreEqual(MetadataUrl, resolved.MetadataLocation.OriginalString);
    }


    /// <summary>A transport exception is returned as its concrete failure kind, without message parsing.</summary>
    [TestMethod]
    public async Task TransportFailureIsUnreachableWithFailureKind()
    {
        AuthorizationServerMetadataResolution resolution = await AuthorizationServerMetadataDocuments.ResolveAsync(
            new Uri(Issuer), WellKnownPaths.OAuthAuthorizationServer, NewContext(),
            static (_, _, _) => throw new IOException("Scripted transport failure."),
            AuthorizationServerMetadataJson.Parse, new AuthorizationServerMetadataResolverOptions(),
            TestContext.CancellationToken).ConfigureAwait(false);

        AuthorizationServerMetadataUnreachable unreachable =
            Assert.IsInstanceOfType<AuthorizationServerMetadataUnreachable>(resolution);
        Assert.AreEqual(typeof(IOException), unreachable.FailureKind);
    }


    /// <summary>Caller cancellation remains an exception rather than becoming an unreachable server.</summary>
    [TestMethod]
    public async Task TransportCancellationPropagates()
    {
        using CancellationTokenSource cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await cancellation.CancelAsync().ConfigureAwait(false);

        _ = await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () =>
            await AuthorizationServerMetadataDocuments.ResolveAsync(
                new Uri(Issuer), WellKnownPaths.OAuthAuthorizationServer, NewContext(),
                static (_, _, token) => throw new OperationCanceledException(token),
                AuthorizationServerMetadataJson.Parse, new AuthorizationServerMetadataResolverOptions(),
                cancellation.Token).ConfigureAwait(false)).ConfigureAwait(false);
    }


    /// <summary>A refused redirect preserves its status and original relative Location without following it.</summary>
    [TestMethod]
    public async Task RedirectRefusedReportsStatusAndLocation()
    {
        const string Location = "/moved-metadata";
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 302, headers: Headers((WellKnownHttpHeaderNames.Location, Location)));

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        AuthorizationServerMetadataRedirectRefused refused =
            Assert.IsInstanceOfType<AuthorizationServerMetadataRedirectRefused>(resolution);
        Assert.AreEqual(302, refused.StatusCode);
        Assert.AreEqual(Location, refused.Location);
        Assert.HasCount(1, transport.Calls);
    }


    /// <summary>A next-hop policy denial retains the redirect response that led to the blocked target.</summary>
    [TestMethod]
    public async Task RedirectToBlockedTargetRetainsRefusalEvidence()
    {
        const string Location = "https://127.0.0.1/metadata";
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 307, headers: Headers((WellKnownHttpHeaderNames.Location, Location)));
        ExchangeContext context = NewContext();
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault with
        {
            Redirects = RedirectMode.PolicyChecked,
            MaxRedirects = 1
        });

        AuthorizationServerMetadataResolution resolution = await AuthorizationServerMetadataDocuments.ResolveAsync(
            new Uri(Issuer), WellKnownPaths.OAuthAuthorizationServer, context, transport.Delegate,
            AuthorizationServerMetadataJson.Parse, new AuthorizationServerMetadataResolverOptions(),
            TestContext.CancellationToken).ConfigureAwait(false);

        AuthorizationServerMetadataRedirectRefused refused =
            Assert.IsInstanceOfType<AuthorizationServerMetadataRedirectRefused>(resolution);
        Assert.AreEqual(307, refused.StatusCode);
        Assert.AreEqual(Location, refused.Location);
        Assert.HasCount(1, transport.Calls);
    }


    /// <summary>Successful permitted redirects report the actual metadata location.</summary>
    [TestMethod]
    public async Task FollowedRedirectReportsFinalMetadataLocation()
    {
        const string Location = "https://as.example.com/moved-metadata";
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 302, headers: Headers((WellKnownHttpHeaderNames.Location, Location)));
        transport.Enqueue(Location, 200, ValidDocumentJson(Issuer), contentType: WellKnownMediaTypes.Application.Json);
        ExchangeContext context = NewContext();
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault with
        {
            Redirects = RedirectMode.SameOrigin,
            MaxRedirects = 1
        });

        AuthorizationServerMetadataResolution resolution = await AuthorizationServerMetadataDocuments.ResolveAsync(
            new Uri(Issuer), WellKnownPaths.OAuthAuthorizationServer, context, transport.Delegate,
            AuthorizationServerMetadataJson.Parse, new AuthorizationServerMetadataResolverOptions(),
            TestContext.CancellationToken).ConfigureAwait(false);

        AuthorizationServerMetadataResolved resolved =
            Assert.IsInstanceOfType<AuthorizationServerMetadataResolved>(resolution);
        Assert.AreEqual(Location, resolved.MetadataLocation.OriginalString);
        Assert.AreEqual(Issuer, resolved.PublishedIssuer);
        Assert.HasCount(2, transport.Calls);
    }


    /// <summary>The authoritative post-read size check reports both the cap and the observed length.</summary>
    [TestMethod]
    public async Task OversizedBodyReportsLimitAndLengthSeen()
    {
        string body = ValidDocumentJson(Issuer);
        long length = Encoding.UTF8.GetByteCount(body);
        AuthorizationServerMetadataResolverOptions options = new() { MaximumDocumentBytes = length - 1 };
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, body, contentType: WellKnownMediaTypes.Application.Json);

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport, options).ConfigureAwait(false);

        AuthorizationServerMetadataTooLarge tooLarge =
            Assert.IsInstanceOfType<AuthorizationServerMetadataTooLarge>(resolution);
        Assert.AreEqual(options.MaximumDocumentBytes, tooLarge.Limit);
        Assert.AreEqual(length, tooLarge.LengthSeen);
        Assert.AreEqual(options.MaximumDocumentBytes, transport.Calls[0].MaxResponseBytes);
    }


    /// <summary>Invalid UTF-8 in an otherwise ignored member must not be replaced and accepted.</summary>
    [TestMethod]
    public async Task InvalidUtf8IsUnreadable()
    {
        byte[] body = [.. Encoding.UTF8.GetBytes("{\"issuer\":\"" + Issuer + "\",\"extra\":\""), 0xFF, .. "\"}"u8];
        ScriptedTransport transport = new();
        transport.EnqueueRoute(MetadataUrl, 200, body,
            Headers((WellKnownHttpHeaderNames.ContentType, WellKnownMediaTypes.Application.Json)));

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        AuthorizationServerMetadataUnreadable unreadable =
            Assert.IsInstanceOfType<AuthorizationServerMetadataUnreadable>(resolution);
        Assert.AreEqual(AuthorizationServerMetadataUnreadableReason.InvalidUtf8, unreadable.Error.Reason);
    }


    /// <summary>Missing, mistyped, malformed and non-object bodies have distinct typed decoding reasons.</summary>
    [TestMethod]
    [DataRow("{}", AuthorizationServerMetadataUnreadableReason.MissingIssuer)]
    [DataRow("{\"issuer\":42}", AuthorizationServerMetadataUnreadableReason.IssuerNotString)]
    [DataRow("{\"issuer\":null}", AuthorizationServerMetadataUnreadableReason.IssuerNotString)]
    [DataRow("null", AuthorizationServerMetadataUnreadableReason.NotObject)]
    [DataRow("", AuthorizationServerMetadataUnreadableReason.InvalidJson)]
    public async Task UnreadableDocumentReportsTypedReason(string body, AuthorizationServerMetadataUnreadableReason expected)
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, body, contentType: WellKnownMediaTypes.Application.Json);

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        AuthorizationServerMetadataUnreadable unreadable =
            Assert.IsInstanceOfType<AuthorizationServerMetadataUnreadable>(resolution);
        Assert.AreEqual(expected, unreadable.Error.Reason);
    }


    /// <summary>The complete document is validated, even when a valid issuer occurs before trailing garbage.</summary>
    [TestMethod]
    public async Task TrailingGarbageIsUnreadable()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson(Issuer) + " trailing",
            contentType: WellKnownMediaTypes.Application.Json);

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        AuthorizationServerMetadataUnreadable unreadable =
            Assert.IsInstanceOfType<AuthorizationServerMetadataUnreadable>(resolution);
        Assert.AreEqual(AuthorizationServerMetadataUnreadableReason.InvalidJson, unreadable.Error.Reason);
    }


    /// <summary>Unpaired surrogate escapes fail even in unknown nested members or property names.</summary>
    [TestMethod]
    [DataRow("{\"issuer\":\"https://as.example.com/\\uD800\"}")]
    [DataRow("{\"issuer\":\"https://as.example.com\",\"extra\":[\"\\uDC00\"]}")]
    [DataRow("{\"issuer\":\"https://as.example.com\",\"\\uD800\":true}")]
    public async Task UnpairedSurrogateIsUnreadable(string body)
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, body, contentType: WellKnownMediaTypes.Application.Json);

        AuthorizationServerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        AuthorizationServerMetadataUnreadable unreadable =
            Assert.IsInstanceOfType<AuthorizationServerMetadataUnreadable>(resolution);
        Assert.AreEqual(AuthorizationServerMetadataUnreadableReason.UnpairedSurrogate, unreadable.Error.Reason);
    }


    /// <summary>Builds the reference application-layer cache under test, over the scripted transport and pinned clock.</summary>
    private static AuthorizationServerMetadataResolutionCache NewCache(ScriptedTransport transport, TimeProvider timeProvider) =>
        new(transport.Delegate, WellKnownPaths.OAuthAuthorizationServer, new AuthorizationServerMetadataResolverOptions(), timeProvider);


    /// <summary>Runs the attempt once directly against a scripted transport, with no cache in front.</summary>
    private async Task<AuthorizationServerMetadataResolution> ResolveAsync(
        string issuer, ScriptedTransport transport, AuthorizationServerMetadataResolverOptions? options = null) =>
        await AuthorizationServerMetadataDocuments.ResolveAsync(
            new Uri(issuer, UriKind.Absolute), WellKnownPaths.OAuthAuthorizationServer, NewContext(), transport.Delegate, AuthorizationServerMetadataJson.Parse,
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
        /// <summary>The scripted responses by URL.</summary>
        private Dictionary<string, List<ScriptedResponse>> Routes { get; } = new(StringComparer.Ordinal);
        /// <summary>The next response index for each URL.</summary>
        private Dictionary<string, int> CallIndex { get; } = new(StringComparer.Ordinal);


        /// <summary>The requests the resolver sent.</summary>
        public List<OutboundRequest> Calls { get; } = [];


        /// <summary>Adds a UTF-8 response to a URL's script.</summary>
        public void Enqueue(
            string url, int status, string? body = null, string? contentType = null,
            IReadOnlyDictionary<string, string>? headers = null)
        {
            Dictionary<string, string> merged = headers is null
                ? new(StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase);

            if(contentType is not null)
            {
                merged[WellKnownHttpHeaderNames.ContentType] = contentType;
            }

            byte[]? bodyBytes = body is null ? null : Encoding.UTF8.GetBytes(body);
            EnqueueRoute(url, status, bodyBytes, merged);
        }


        /// <summary>Adds an original-byte response to a URL's script.</summary>
        public void EnqueueRoute(string url, int status, byte[]? body, IReadOnlyDictionary<string, string> headers)
        {
            if(!Routes.TryGetValue(url, out List<ScriptedResponse>? list))
            {
                list = [];
                Routes[url] = list;
            }

            list.Add(new ScriptedResponse(status, body, headers));
        }


        /// <summary>The single-hop playback transport.</summary>
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

            HttpHeaderSet.Builder headerBuilder = new();
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


        /// <summary>A scripted HTTP response.</summary>
        /// <param name="Status">The response status.</param>
        /// <param name="Body">The original body bytes.</param>
        /// <param name="Headers">The response headers.</param>
        private sealed record ScriptedResponse(int Status, byte[]? Body, IReadOnlyDictionary<string, string> Headers);
    }
}
