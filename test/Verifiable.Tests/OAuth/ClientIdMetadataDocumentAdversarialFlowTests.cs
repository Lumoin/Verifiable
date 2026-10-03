using Microsoft.Extensions.Time.Testing;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.Outbound;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Server.Diagnostics;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Adversarial, SSRF, discrimination, display-seam, and logo-prefetch real-wire suite for CIMD:
/// every scenario crosses a real
/// <see cref="MinimalHttpHost"/> or <see cref="StaticContentHost"/> TLS loopback socket, mirroring
/// <see cref="ClientIdMetadataDocumentCrossWireFlowTests"/>'s topology. Caching behavior lives in
/// the sibling <see cref="ClientIdMetadataDocumentCachingFlowTests"/>.
/// </summary>
/// <remarks>
/// Covers draft-ietf-oauth-client-id-metadata-document-02 clauses 001-011 (wire), 008, 013-016,
/// 019-023, 028, 030, 033-040, 043-044, 051-061 per
/// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html">
/// draft-ietf-oauth-client-id-metadata-document-02</see>. Every host uses the single explicit
/// HTTPS <c>Listen</c> convention — no plaintext listener anywhere in this file — and every test
/// builds its own hosts, so the suite is parallel-safe. The pinned <see cref="FakeTimeProvider"/>
/// is the only clock consulted; production code never reads the wall clock here.
/// </remarks>
[TestClass]
internal sealed class ClientIdMetadataDocumentAdversarialFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");

    private const string SubjectId = "subject-cimd-adversarial-01";

    private static ImmutableHashSet<CapabilityIdentifier> AuthCodeCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization);

    /// <summary>
    /// The capabilities of a client served at UserInfo, a bearer resource that authenticates no client: the
    /// authorization code grant and UserInfo.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> UserInfoCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OidcUserInfo);

    /// <summary>
    /// The capabilities of a client served at three protected resources that authenticate a request by an access
    /// token: UserInfo, the OID4VCI Deferred Credential endpoint and the client configuration endpoint, beside the
    /// authorization code grant.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> ProtectedResourceCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OidcUserInfo,
            WellKnownCapabilityIdentifiers.Oid4VciDeferredCredentialEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDynamicClientRegistration);

    /// <summary>
    /// The capabilities of a client served at an application's device authorization endpoint
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8628#section-3.1">RFC 8628 Section 3.1</see>), which no builder of
    /// the library serves.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> DeviceAuthorizationCapabilities { get; } =
        ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthDeviceAuthorization);


    //(a) Fetch-contract adversarials.

    /// <summary>
    /// CIMD-033/035: a 404 status is treated as a discovery error, and the authorization server
    /// SHOULD abort the authorization request — proven here as a direct, non-redirecting 400
    /// answer from the PAR endpoint (materialization runs before any redirect is possible).
    /// </summary>
    [TestMethod]
    public async Task Fetch404AbortsAuthorizationDirectly()
    {
        RequestCounter counter = new();
        await using MinimalHttpHost documentHost = await MinimalHttpHost.StartAsync(
            (request, ct) =>
            {
                counter.Increment();

                return Task.FromResult(new MinimalHttpResponse { StatusCode = 404 });
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult result = await RunSingleAdversarialParAttemptAsync(
            documentHost, "/app", TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome,
            "CIMD-035: a fetch failure must abort the authorization request directly, never redirect.");
        AssertNoInternalDetailLeaked(result);
        Assert.AreEqual(1, counter.Count);
    }


    /// <summary>CIMD-033/035: a 500 status is likewise a discovery error that aborts the authorization request.</summary>
    [TestMethod]
    public async Task Fetch500AbortsAuthorizationDirectly()
    {
        await using MinimalHttpHost documentHost = await MinimalHttpHost.StartAsync(
            (request, ct) => Task.FromResult(new MinimalHttpResponse { StatusCode = 500 }),
            TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult result = await RunSingleAdversarialParAttemptAsync(
            documentHost, "/app", TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome,
            "CIMD-033: any non-200 status is an error response that must abort the authorization request.");
        AssertNoInternalDetailLeaked(result);
    }


    /// <summary>
    /// CIMD-034: the authorization server MUST NOT automatically follow an HTTP redirect when
    /// fetching the Client ID Metadata Document. The 302 answer aborts the authorization request,
    /// and the redirect target is never dialed at all — <see cref="OutboundFetch"/>'s
    /// <see cref="RedirectMode.None"/> default stops the loop before the second hop is even
    /// policy-evaluated.
    /// </summary>
    /// <remarks>
    /// Wires the resolver's transport manually with <see cref="SocketsHttpHandler.AllowAutoRedirect"/>
    /// explicitly <see langword="false"/> — <see cref="TestHostShell.WireCimdMaterializationAsync"/>'s
    /// pinned client leaves the framework default (<see langword="true"/>), which would let
    /// <see cref="HttpClient"/> itself silently follow the 302 before the guarded
    /// <see cref="OutboundFetch"/> chokepoint ever saw it, making this test's "never dialed"
    /// assertion pass or fail for the wrong reason.
    /// </remarks>
    [TestMethod]
    public async Task FetchRedirectAnswerAbortsAndRedirectTargetNeverDialed()
    {
        RequestCounter redirectTargetCounter = new();
        await using MinimalHttpHost redirectTarget = await MinimalHttpHost.StartAsync(
            (request, ct) =>
            {
                redirectTargetCounter.Increment();

                return Task.FromResult(new MinimalHttpResponse { StatusCode = 200 });
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        await using MinimalHttpHost documentHost = await MinimalHttpHost.StartAsync(
            (request, ct) => Task.FromResult(new MinimalHttpResponse
            {
                StatusCode = 302,
                Headers = new Dictionary<string, string>
                {
                    ["Location"] = new Uri(redirectTarget.BaseAddress, "/elsewhere").OriginalString
                }
            }),
            TestContext.CancellationToken).ConfigureAwait(false);

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));

        using SocketsHttpHandler noAutoRedirectHandler = LoopbackTls.CreatePinnedHandler(documentHost.Certificate);
        noAutoRedirectHandler.AllowAutoRedirect = false;
        using HttpClient documentHttpClient = new(noAutoRedirectHandler);
        OutboundTransportDelegate transport = GuardedHttpClientTransport.BuildSingleHopTransport(documentHttpClient);
        ResolveClientMetadataDelegate resolve = new ClientMetadataResolutionCache(
            transport, new ClientIdMetadataDocumentResolverOptions(), new JwksUriResolverOptions(), app.Time)
            .ResolveDocumentAsync;

        HostedAuthorizationServer host = app.Host("default");
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.MaterializeRegistrationAsync = ClientIdMetadataMaterialization.Build();

            candidateIntegration.ResolveClientMetadataAsync = (clientMetadataUri, context, cancellationToken) =>
            {
                context.SetOutboundFetchPolicy(TestHostShell.LoopbackOutboundFetchPolicy);

                return resolve(clientMetadataUri, context, cancellationToken);
            };
        }).ConfigureAwait(false);

        AuthCodeFlowEndpointResult result = await StartParAgainstStubAsync(
            app, new Uri(documentHost.BaseAddress, "/app"), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome,
            "CIMD-034: a redirect answer must abort the authorization request, never be followed.");
        Assert.AreEqual(0, redirectTargetCounter.Count,
            "CIMD-034: the redirect target must never be dialed — not even policy-evaluated.");
    }


    /// <summary>
    /// CIMD-059: a response larger than the configured maximum is treated as an error, even though
    /// the transport itself reported 200 — the guarded reader stops before the
    /// document is even parsed, so the body need not be well-formed JSON.
    /// </summary>
    [TestMethod]
    public async Task FetchOversizedBodyAborts()
    {
        string oversizedBody = new('x', 4096);
        await using MinimalHttpHost documentHost = await MinimalHttpHost.StartAsync(
            (request, ct) => Task.FromResult(new MinimalHttpResponse
            {
                StatusCode = 200,
                ContentType = "application/json",
                Body = oversizedBody
            }),
            TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult result = await RunSingleAdversarialParAttemptAsync(
            documentHost, "/app",
            options: new ClientIdMetadataDocumentResolverOptions { MaximumDocumentBytes = 64 },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome,
            "CIMD-059: a document exceeding the configured maximum size must abort the authorization request.");
    }


    /// <summary>CIMD-019 (negative side): a <c>text/html</c> content type is not JSON and must abort.</summary>
    [TestMethod]
    public async Task FetchTextHtmlContentTypeAborts()
    {
        await using MinimalHttpHost documentHost = await MinimalHttpHost.StartAsync(
            (request, ct) => Task.FromResult(new MinimalHttpResponse
            {
                StatusCode = 200,
                ContentType = "text/html",
                Body = "<html>not a Client ID Metadata Document</html>"
            }),
            TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult result = await RunSingleAdversarialParAttemptAsync(
            documentHost, "/app", TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome,
            "CIMD-019: a non-JSON content type must abort the authorization request.");
    }


    /// <summary>
    /// CIMD-018/032 (positive) and CIMD-019 (positive, the <c>+json</c> structured suffix branch):
    /// a plain <c>application/json</c> 200 response proceeds to a redirect, and so does an
    /// <c>application/oauth-client+json</c> response for a second, independent client.
    /// </summary>
    [TestMethod]
    public async Task FetchStructuredJsonContentTypeAndPlainJsonBothProceed()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);

        Uri plainDocumentUri = new(documentHost.BaseAddress, "/app-plain");
        documentHost.Publish("/app-plain",
            Encoding.UTF8.GetBytes(BuildDocumentJson(plainDocumentUri.OriginalString, [RedirectUri])),
            "application/json");

        Uri structuredDocumentUri = new(documentHost.BaseAddress, "/app-structured");
        documentHost.Publish("/app-structured",
            Encoding.UTF8.GetBytes(BuildDocumentJson(structuredDocumentUri.OriginalString, [RedirectUri])),
            "application/oauth-client+json");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);

        AuthCodeFlowEndpointResult plainResult = await StartParAgainstStubAsync(
            app, plainDocumentUri, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, plainResult.Outcome,
            $"CIMD-018/032: a plain application/json 200 response must proceed. ErrorDescription={plainResult.ErrorDescription}");

        AuthCodeFlowEndpointResult structuredResult = await StartParAgainstStubAsync(
            app, structuredDocumentUri, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, structuredResult.Outcome,
            $"CIMD-019: an application/<AS-defined>+json content type must be accepted. ErrorDescription={structuredResult.ErrorDescription}");
    }


    //(b) Document-validity adversarials — each aborts and is never cached.

    /// <summary>
    /// CIMD-013 (missing <c>client_id</c>), CIMD-021 (symmetric <c>token_endpoint_auth_method</c>),
    /// CIMD-022 (<c>client_secret</c> present), and CIMD-023 (private key material in <c>jwks</c>)
    /// each independently abort the authorization request, and CIMD-040 holds for every one of
    /// them: a second, fresh PAR attempt re-fetches rather than serving a cached invalid result.
    /// </summary>
    [TestMethod]
    public async Task DocumentValidityDefectsAbortAndAreNeverCached()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);

        Uri missingClientIdUri = new(documentHost.BaseAddress, "/missing-client-id");
        documentHost.Publish("/missing-client-id",
            Encoding.UTF8.GetBytes("""{"redirect_uris":["https://client.example.com/callback"]}"""),
            "application/json");

        Uri clientSecretUri = new(documentHost.BaseAddress, "/client-secret");
        documentHost.Publish("/client-secret",
            Encoding.UTF8.GetBytes(BuildDocumentJson(clientSecretUri.OriginalString, includeClientSecret: true)),
            "application/json");

        Uri symmetricAuthUri = new(documentHost.BaseAddress, "/symmetric-auth");
        documentHost.Publish("/symmetric-auth",
            Encoding.UTF8.GetBytes(BuildDocumentJson(
                symmetricAuthUri.OriginalString, tokenEndpointAuthMethod: WellKnownClientAuthenticationMethods.ClientSecretBasic)),
            "application/json");

        Uri privateJwksUri = new(documentHost.BaseAddress, "/private-jwks");
        documentHost.Publish("/private-jwks",
            Encoding.UTF8.GetBytes(BuildDocumentJson(privateJwksUri.OriginalString, jwksRawJson: PrivateEcJwkSetJson)),
            "application/json");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);

        await AssertAbortsAndNeverCachedAsync(
            app, documentHost, "/missing-client-id", missingClientIdUri,
            "CIMD-013: a document with no client_id property must abort and never be cached.",
            TestContext.CancellationToken).ConfigureAwait(false);

        await AssertAbortsAndNeverCachedAsync(
            app, documentHost, "/client-secret", clientSecretUri,
            "CIMD-022: a document carrying client_secret must abort and never be cached.",
            TestContext.CancellationToken).ConfigureAwait(false);

        await AssertAbortsAndNeverCachedAsync(
            app, documentHost, "/symmetric-auth", symmetricAuthUri,
            "CIMD-021: a symmetric token_endpoint_auth_method must abort and never be cached.",
            TestContext.CancellationToken).ConfigureAwait(false);

        await AssertAbortsAndNeverCachedAsync(
            app, documentHost, "/private-jwks", privateJwksUri,
            "CIMD-023: private key material in jwks must abort and never be cached.",
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// CIMD-008/014/015/016: the document's <c>client_id</c> MUST ordinal-equal the fetch URL. A
    /// generic mismatch aborts, and so does a scheme-case variant — RFC 3986 §3.1 treats the
    /// scheme as case-insensitive for URI equivalence, but CIMD-008/016 require literal ordinal
    /// comparison, so <c>HTTPS://…</c> does not match a fetch URL dialed as <c>https://…</c>.
    /// Neither result is cached (CIMD-040). The specification's own named example — an explicit
    /// <c>:443</c> default-port suffix — is proven at the resolver-unit level in
    /// <c>ClientIdMetadataDocumentsResolvingTests.DefaultPortSuffixIsNotEquivalentForClientIdMatch</c>,
    /// since a real loopback listener never binds the literal default port 443.
    /// </summary>
    [TestMethod]
    public async Task DocumentClientIdMismatchAndSchemeCaseVariantAbortAndAreNeverCached()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);

        Uri genericMismatchUri = new(documentHost.BaseAddress, "/generic-mismatch");
        documentHost.Publish("/generic-mismatch",
            Encoding.UTF8.GetBytes(BuildDocumentJson("https://someone-else.example.com/app")),
            "application/json");

        Uri caseVariantUri = new(documentHost.BaseAddress, "/case-variant");
        string caseVariantClientId = UppercaseScheme(caseVariantUri.OriginalString);
        documentHost.Publish("/case-variant",
            Encoding.UTF8.GetBytes(BuildDocumentJson(caseVariantClientId)),
            "application/json");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);

        await AssertAbortsAndNeverCachedAsync(
            app, documentHost, "/generic-mismatch", genericMismatchUri,
            "CIMD-008/014/015/016: a client_id naming a different URL entirely must abort and never be cached.",
            TestContext.CancellationToken).ConfigureAwait(false);

        await AssertAbortsAndNeverCachedAsync(
            app, documentHost, "/case-variant", caseVariantUri,
            "CIMD-008/016: a scheme-case variant is NOT equivalent under ordinal comparison and must abort.",
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    //(c) SSRF.

    /// <summary>
    /// CIMD-054/056: a Client Identifier URL resolving to a special-use (cloud metadata,
    /// link-local) address is denied before any network contact under the production
    /// <see cref="OutboundFetchPolicy.SecureDefault"/> — the transport spy records zero calls. The
    /// same PAR call's <c>Handle</c> span carries the policy-denial event, and the wire response
    /// never names the reason.
    /// </summary>
    [TestMethod]
    public async Task SpecialUseAddressDeniedBeforeNetworkContactUnderProductionDefault()
    {
        ConcurrentBag<Activity> captured = [];
        using ActivityListener listener = CreateListener(captured);
        ActivitySource.AddActivityListener(listener);

        TransportCallSpy spy = new();
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));

        Uri maliciousUri = new("https://169.254.169.254/app");
        ClientRecord stub = await app.RegisterCimdStubClientAsync(maliciousUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        HostedAuthorizationServer host = app.Host("default");
        AuthorizationServerIntegration oauth = host.Server.OAuth();
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.MaterializeRegistrationAsync = ClientIdMetadataMaterialization.Build();


            candidateIntegration.ResolveClientMetadataAsync = new ClientMetadataResolutionCache(
                spy.Delegate, new ClientIdMetadataDocumentResolverOptions(), new JwksUriResolverOptions(), app.Time)
                .ResolveDocumentAsync;
        }).ConfigureAwait(false);

        AuthCodeFlowEndpointResult result = await DriveParForStubAsync(
            app, stub, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome,
            "CIMD-054: a special-use-address client_id must be denied under production defaults.");
        Assert.AreEqual(0, spy.CallCount,
            "CIMD-054/056: the transport must never be dialed for a policy-denied target.");
        AssertNoInternalDetailLeaked(result);

        Activity[] handleActivities = captured
            .Where(a => string.Equals(a.OperationName, ServerActivityNames.Handle, StringComparison.Ordinal))
            .Where(a => a.Tags.Any(t =>
                string.Equals(t.Key, ServerTagNames.TenantHandle, StringComparison.Ordinal)
                && string.Equals(t.Value, stub.TenantHandle!.Value.Value, StringComparison.Ordinal)))
            .ToArray();
        Assert.IsGreaterThan(0, handleActivities.Length, "At least one Handle activity for this tenant must be captured.");
        Assert.Contains(
            a => a.Events.Any(e => string.Equals(e.Name, PolicyDeniedEventName, StringComparison.Ordinal)),
            handleActivities,
            "A policy-denial span event must be recorded on the request's Handle activity.");
    }


    /// <summary>
    /// CIMD-055/056: the development/testing loopback relaxation is an explicit, scoped opt-in —
    /// the SAME loopback document host is denied under production <see cref="OutboundFetchPolicy.SecureDefault"/>
    /// and succeeds only when the context explicitly carries <see cref="TestHostShell.LoopbackOutboundFetchPolicy"/>.
    /// </summary>
    [TestMethod]
    public async Task LoopbackRelaxationIsExplicitAndScoped()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/app");
        documentHost.Publish("/app",
            Encoding.UTF8.GetBytes(BuildDocumentJson(documentUri.OriginalString, [RedirectUri])),
            "application/json");

        //Production default: no relaxation applied anywhere.
        await using TestHostShell productionApp = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        HostedAuthorizationServer productionHost = productionApp.Host("default");
        using HttpClient productionHttpClient = LoopbackTls.CreatePinnedHttpClient(documentHost.Certificate);
        await TestHostShell.AlterAsync(productionHost.Server, candidateIntegration =>
        {
            candidateIntegration.MaterializeRegistrationAsync = ClientIdMetadataMaterialization.Build();

            candidateIntegration.ResolveClientMetadataAsync = new ClientMetadataResolutionCache(
                GuardedHttpClientTransport.BuildSingleHopTransport(productionHttpClient),
                new ClientIdMetadataDocumentResolverOptions(), new JwksUriResolverOptions(), productionApp.Time)
                .ResolveDocumentAsync;
        }).ConfigureAwait(false);

        AuthCodeFlowEndpointResult productionResult = await StartParAgainstStubAsync(
            productionApp, documentUri, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, productionResult.Outcome,
            "CIMD-056: production defaults must still deny a loopback target — the exception is never automatic.");

        //Explicit, scoped test-context relaxation against the SAME document host.
        await using TestHostShell relaxedApp = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await relaxedApp.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);

        AuthCodeFlowEndpointResult relaxedResult = await StartParAgainstStubAsync(
            relaxedApp, documentUri, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, relaxedResult.Outcome,
            $"CIMD-055: the explicit test-context relaxation must permit the loopback fetch. ErrorDescription={relaxedResult.ErrorDescription}");
    }


    /// <summary>CIMD-057: a listed host is blocked even under an otherwise-loopback-permissive policy.</summary>
    [TestMethod]
    public async Task HostDenyListBlocksListedHost()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/app");
        documentHost.Publish("/app",
            Encoding.UTF8.GetBytes(BuildDocumentJson(documentUri.OriginalString, [RedirectUri])),
            "application/json");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        HostedAuthorizationServer host = app.Host("default");
        using HttpClient httpClient = LoopbackTls.CreatePinnedHttpClient(documentHost.Certificate);
        OutboundTransportDelegate transport = GuardedHttpClientTransport.BuildSingleHopTransport(httpClient);
        ResolveClientMetadataDelegate resolve = new ClientMetadataResolutionCache(
            transport, new ClientIdMetadataDocumentResolverOptions(), new JwksUriResolverOptions(), app.Time)
            .ResolveDocumentAsync;

        OutboundFetchPolicy denyListPolicy = TestHostShell.LoopbackOutboundFetchPolicy with
        {
            HostDenyList = [documentUri.Host]
        };
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.MaterializeRegistrationAsync = ClientIdMetadataMaterialization.Build();

            candidateIntegration.ResolveClientMetadataAsync = (clientMetadataUri, context, cancellationToken) =>
            {
                context.SetOutboundFetchPolicy(denyListPolicy);

                return resolve(clientMetadataUri, context, cancellationToken);
            };
        }).ConfigureAwait(false);

        AuthCodeFlowEndpointResult result = await StartParAgainstStubAsync(
            app, documentUri, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome,
            "CIMD-057: a host on the deny list must be blocked even though loopback is otherwise permitted.");
    }


    /// <summary>CIMD-058: a <c>javascript:</c> scheme jwks_uri inside the document is rejected.</summary>
    [TestMethod]
    public async Task JavascriptSchemeJwksUriRejected()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/app");
        documentHost.Publish("/app",
            Encoding.UTF8.GetBytes(BuildDocumentJson(
                documentUri.OriginalString, [RedirectUri], jwksUriRaw: "javascript:alert(1)")),
            "application/json");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);

        AuthCodeFlowEndpointResult result = await StartParAgainstStubAsync(
            app, documentUri, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome,
            "CIMD-058: a javascript: scheme jwks_uri must reject the document.");
    }


    //(e) Discrimination.

    /// <summary>
    /// CIMD-043/044: a vanity <c>https://</c> client_id whose registration carries no
    /// <see cref="ClientRecord.ClientMetadataUri"/> is never fetched — the discrimination signal is
    /// the field, not the string shape. The flow proceeds entirely from the stored registration.
    /// </summary>
    [TestMethod]
    public async Task VanityHttpsClientIdWithNullMetadataUriGetsZeroFetches()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);

        const string vanityClientId = "https://vanity.example.com/my-app";
        using VerifierKeyMaterial material = await app.RegisterClientAsync(
            vanityClientId, new Uri(vanityClientId), AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        ClientRecord stub = material.Registration;
        Assert.IsNull(stub.ClientMetadataUri, "The vanity client must not carry a ClientMetadataUri.");

        (OAuthClient client, ClientRegistration registration, _) = await app.CreateOAuthClientAndRegistrationAsync(
            stub, RedirectUri.OriginalString, PolicyProfile.Rfc6749WithPkce, TestContext.CancellationToken)
            .ConfigureAwait(false);

        AuthCodeFlowEndpointResult result = await client.AuthCode.StartParAsync(
            registration, RedirectUri, OAuthFormEncodedFields.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, result.Outcome,
            $"CIMD-043/044: the vanity client must flow entirely from the stored registration. ErrorDescription={result.ErrorDescription}");
        Assert.AreEqual(0, documentHost.TotalRequests,
            "CIMD-043/044: a client with no ClientMetadataUri must never trigger a document fetch.");
    }


    /// <summary>
    /// An authorization request against a URL segment that names no registration at all (no CIMD
    /// stub, no pre-registered client) reaches the library's existing unknown-registration
    /// behavior — a direct 404 from <c>EndpointServer.DispatchAsync</c>'s tenant-resolution step,
    /// which runs before CIMD materialization is even reachable.
    /// </summary>
    [TestMethod]
    public async Task UnknownTenantSegmentFollowsExistingNotFoundBehavior()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterClientAsync(
            "opaque-client-1", new Uri("https://opaque.example.com"), AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = app.Host("default");

        Uri parEndpoint = TestHostShell.ComposeEndpointUri(
            hosted.HttpBaseAddress!, "never-registered-segment", WellKnownEndpointNames.AuthCodePar);

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, parEndpoint,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ResponseType] = "code",
                [OAuthRequestParameterNames.ClientId] = "https://unknown.example.com/app",
                [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
                [OAuthRequestParameterNames.CodeChallenge] = "adversarial-pkce-challenge-0123456789",
                [OAuthRequestParameterNames.CodeChallengeMethod] = "S256"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, (int)response.StatusCode,
            "An unregistered tenant segment follows the repo's existing unknown-registration behavior: a direct 404.");
    }


    //(f) Display / phishing seam.

    /// <summary>
    /// CIMD-051/053: in fetched mode, the evaluation seam observes the client_id host AND the
    /// fetched display fields (name, logo) — the application's phishing-mitigation SHOULDs are
    /// implementable from data the library actually surfaces.
    /// </summary>
    [TestMethod]
    public async Task FetchedModeEvaluationPopulatesHostAndDocumentFields()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/app");
        Uri logoUri = new("https://logo.example.com/mark.png");
        documentHost.Publish("/app",
            Encoding.UTF8.GetBytes(BuildDocumentJson(
                documentUri.OriginalString, [RedirectUri], clientName: "Adversarial Test Client", logoUri: logoUri.OriginalString)),
            "application/json");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);

        AuthorizationRequestEvaluation? captured = null;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync = (evaluation, registration, context, ct) =>
            {
                captured = evaluation;

                return ValueTask.FromResult(AuthorizationRequestDecision.Permit());
            };
        }).ConfigureAwait(false);

        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> flowStore) =
            await app.CreateOAuthClientAndRegistrationAsync(
                stub, RedirectUri.OriginalString, PolicyProfile.Rfc6749WithPkce, TestContext.CancellationToken)
                .ConfigureAwait(false);
        HostedAuthorizationServer hosted = app.Host("default");

        (string flowId, string location) = await DriveParAndAuthorizeAsync(
            app, hosted, client, registration, flowStore, stub.TenantId.Value, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(string.IsNullOrEmpty(flowId));
        Assert.IsFalse(string.IsNullOrEmpty(location));

        Assert.IsNotNull(captured, "The evaluation seam must have been invoked.");
        Assert.AreEqual(documentUri.Host, captured.ClientIdHost,
            "CIMD-053: the client_id hostname must be populated.");
        Assert.IsTrue(captured.HasFetchedClientMetadata,
            "CIMD-051: fetched mode must report that document-derived metadata is present.");
        Assert.AreEqual("Adversarial Test Client", captured.ClientName);
        Assert.AreEqual(logoUri, captured.LogoUri);
    }


    /// <summary>
    /// CIMD-028: the <c>software_statement</c> parameter defined in RFC 7591, when included as a
    /// property of the Client ID Metadata Document, is carried opaque through materialization onto
    /// the effective registration — observed here via the <see cref="ClientRecord"/> the evaluation
    /// seam receives, the materialized record itself rather than the display-only evaluation
    /// snapshot.
    /// </summary>
    [TestMethod]
    public async Task SoftwareStatementCarriedThroughToMaterializedRegistration()
    {
        const string softwareStatement = "eyJhbGciOiJub25lIn0.eyJzb2Z0d2FyZV9pZCI6InRlc3QifQ.";

        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/app");
        documentHost.Publish("/app",
            Encoding.UTF8.GetBytes(BuildDocumentJson(
                documentUri.OriginalString, [RedirectUri], softwareStatement: softwareStatement)),
            "application/json");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);

        ClientRecord? materialized = null;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync = (evaluation, registration, context, ct) =>
            {
                materialized = registration;

                return ValueTask.FromResult(AuthorizationRequestDecision.Permit());
            };
        }).ConfigureAwait(false);

        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> flowStore) =
            await app.CreateOAuthClientAndRegistrationAsync(
                stub, RedirectUri.OriginalString, PolicyProfile.Rfc6749WithPkce, TestContext.CancellationToken)
                .ConfigureAwait(false);
        HostedAuthorizationServer hosted = app.Host("default");

        _ = await DriveParAndAuthorizeAsync(
            app, hosted, client, registration, flowStore, stub.TenantId.Value, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(materialized, "The evaluation seam must have been invoked.");
        Assert.AreEqual(softwareStatement, materialized.SoftwareStatement,
            "CIMD-028: the document's software_statement must reach the materialized registration.");
    }


    /// <summary>
    /// CIMD-052/053: a pre-registered client whose document was never fetched at request time
    /// still surfaces the client_id host, so the application can fall back to §8.5 ¶2's "as much
    /// information as possible" using the hostname alone — <see cref="AuthorizationRequestEvaluation.HasFetchedClientMetadata"/>
    /// is <see langword="false"/>.
    /// </summary>
    [TestMethod]
    public async Task PreRegisteredNoFetchModeEvaluationPopulatesHostOnly()
    {
        const string clientId = "https://pre-registered.example.com/app";
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));

        //No WireCimdMaterialization call — this host never fetches CIMD documents at request time.
        //A vanity https:// client_id with a fully populated stored registration models §7.2's
        //pre-registration deployment pattern.
        using VerifierKeyMaterial material = await app.RegisterClientAsync(
            clientId, new Uri(clientId), AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        ClientRecord stub = material.Registration;

        AuthorizationRequestEvaluation? captured = null;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync = (evaluation, registration, context, ct) =>
            {
                captured = evaluation;

                return ValueTask.FromResult(AuthorizationRequestDecision.Permit());
            };
        }).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> flowStore) =
            await app.CreateOAuthClientAndRegistrationAsync(
                stub, RedirectUri.OriginalString, PolicyProfile.Rfc6749WithPkce, TestContext.CancellationToken)
                .ConfigureAwait(false);

        HostedAuthorizationServer hosted = app.Host("default");
        _ = await DriveParAndAuthorizeAsync(
            app, hosted, client, registration, flowStore, stub.TenantId.Value, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(captured, "The evaluation seam must have been invoked.");
        Assert.AreEqual(new Uri(clientId).Host, captured.ClientIdHost,
            "CIMD-053: the client_id hostname must be populated regardless of fetch mode.");
        Assert.IsFalse(captured.HasFetchedClientMetadata,
            "CIMD-052: a pre-registered, never-fetched client must report no document-derived metadata.");
    }


    //(g) Logo prefetch.

    /// <summary>
    /// CIMD-060: with <see cref="ClientIdMetadataDocumentResolverOptions.PrefetchLogo"/> enabled,
    /// the resolver dials the logo host exactly once and the bytes ride the resolution; a second
    /// resolve call within the document's cache lifetime (an explicit <c>Cache-Control: max-age</c>
    /// response) serves the cached resolution and does not re-dial the logo host.
    /// </summary>
    [TestMethod]
    public async Task LogoPrefetchDialsOnceBytesReachResolutionAndSkipsOnCachedSecondFlow()
    {
        const string logoPayload = "not-a-real-png-but-deterministic-bytes";
        RequestCounter logoCounter = new();
        await using MinimalHttpHost logoHost = await MinimalHttpHost.StartAsync(
            (request, ct) =>
            {
                logoCounter.Increment();

                return Task.FromResult(new MinimalHttpResponse
                {
                    StatusCode = 200,
                    ContentType = "image/png",
                    Body = logoPayload
                });
            },
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri logoUri = new(logoHost.BaseAddress, "/logo.png");

        //The handler closes over documentUri, assigned once BaseAddress is known below; the
        //closure only runs once an actual request arrives, after the assignment completes.
        Uri? documentUri = null;
        await using MinimalHttpHost documentHost = await MinimalHttpHost.StartAsync(
            (request, ct) => Task.FromResult(new MinimalHttpResponse
            {
                StatusCode = 200,
                ContentType = "application/json",
                Body = BuildDocumentJson(documentUri!.OriginalString, [RedirectUri], logoUri: logoUri.OriginalString),
                Headers = new Dictionary<string, string> { ["Cache-Control"] = "max-age=300" }
            }),
            TestContext.CancellationToken).ConfigureAwait(false);
        documentUri = new Uri(documentHost.BaseAddress, "/app");

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        using HttpClient httpClient = LoopbackTls.CreatePinnedHttpClient([documentHost.Certificate, logoHost.Certificate]);
        OutboundTransportDelegate transport = GuardedHttpClientTransport.BuildSingleHopTransport(httpClient);
        ResolveClientMetadataDelegate resolve = new ClientMetadataResolutionCache(
            transport, new ClientIdMetadataDocumentResolverOptions { PrefetchLogo = true }, new JwksUriResolverOptions(), timeProvider)
            .ResolveDocumentAsync;

        ExchangeContext context = [];
        context.SetOutboundFetchPolicy(TestHostShell.LoopbackOutboundFetchPolicy);

        ClientIdMetadataResolution first = await resolve(documentUri, context, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(first.IsResolved, $"Resolution must succeed. Defect={first.Defect}");
        Assert.IsNotNull(first.PrefetchedLogo, "CIMD-060: the prefetched logo bytes must ride the resolution.");
        Assert.AreEqual(logoPayload, Encoding.UTF8.GetString(first.PrefetchedLogo!.Value.Span));
        Assert.AreEqual(1, logoCounter.Count, "The logo host must be dialed exactly once.");

        ClientIdMetadataResolution second = await resolve(documentUri, context, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(second.IsResolved);
        Assert.AreEqual(1, logoCounter.Count,
            "CIMD-060: a second resolve within the document's cache lifetime must not re-dial the logo host.");
    }


    /// <summary>CIMD-060 (SHOULD-tier): a failed logo prefetch does not abort the authorization request.</summary>
    [TestMethod]
    public async Task LogoPrefetchFailureDoesNotAbortAuthorization()
    {
        await using MinimalHttpHost logoHost = await MinimalHttpHost.StartAsync(
            (request, ct) => Task.FromResult(new MinimalHttpResponse { StatusCode = 500 }),
            TestContext.CancellationToken).ConfigureAwait(false);

        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/app");
        Uri logoUri = new(logoHost.BaseAddress, "/logo.png");
        documentHost.Publish("/app",
            Encoding.UTF8.GetBytes(BuildDocumentJson(documentUri.OriginalString, [RedirectUri], logoUri: logoUri.OriginalString)),
            "application/json");

        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using TestHostShell app = new(timeProvider);
        HostedAuthorizationServer host = app.Host("default");

        using HttpClient httpClient = LoopbackTls.CreatePinnedHttpClient([documentHost.Certificate, logoHost.Certificate]);
        OutboundTransportDelegate transport = GuardedHttpClientTransport.BuildSingleHopTransport(httpClient);
        ResolveClientMetadataDelegate resolve = new ClientMetadataResolutionCache(
            transport, new ClientIdMetadataDocumentResolverOptions { PrefetchLogo = true }, new JwksUriResolverOptions(), timeProvider)
            .ResolveDocumentAsync;

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.MaterializeRegistrationAsync = ClientIdMetadataMaterialization.Build();

            candidateIntegration.ResolveClientMetadataAsync = (clientMetadataUri, context, cancellationToken) =>
            {
                context.SetOutboundFetchPolicy(TestHostShell.LoopbackOutboundFetchPolicy);

                return resolve(clientMetadataUri, context, cancellationToken);
            };
        }).ConfigureAwait(false);

        AuthCodeFlowEndpointResult result = await StartParAgainstStubAsync(
            app, documentUri, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, result.Outcome,
            $"CIMD-060: a failed logo prefetch must not abort the authorization request. ErrorDescription={result.ErrorDescription}");
    }


    //(h) CIMD-020 additional-validation hook.

    /// <summary>CIMD-020: an application-supplied restriction requiring private_key_jwt rejects a public-client document.</summary>
    [TestMethod]
    public async Task AdditionalDocumentValidationRejectsPublicClientDocument()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/app");
        documentHost.Publish("/app",
            Encoding.UTF8.GetBytes(BuildDocumentJson(documentUri.OriginalString, [RedirectUri])),
            "application/json");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate, RequirePrivateKeyJwtOptions).ConfigureAwait(false);

        AuthCodeFlowEndpointResult result = await StartParAgainstStubAsync(
            app, documentUri, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome,
            "CIMD-020: the additional restriction must reject a public-client document.");
    }


    /// <summary>CIMD-020: the same restriction accepts a conforming private_key_jwt document.</summary>
    [TestMethod]
    public async Task AdditionalDocumentValidationAcceptsConformingPrivateKeyJwtDocument()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/app");
        documentHost.Publish("/app",
            Encoding.UTF8.GetBytes(BuildDocumentJson(
                documentUri.OriginalString, [RedirectUri],
                tokenEndpointAuthMethod: WellKnownClientAuthenticationMethods.PrivateKeyJwt,
                jwksUriRaw: "https://client.example.com/jwks.json")),
            "application/json");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate, RequirePrivateKeyJwtOptions).ConfigureAwait(false);

        //RFC 9126 §2: the pushed request now authenticates the client too. This test's subject is
        //the document-validation restriction (CIMD-020), not assertion authentication, so the
        //declared method is advertised and unconditionally accepted here — isolating the restriction
        //under test from the separate private_key_jwt authentication proved elsewhere.
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ClientAuthenticationMethodsSupported = [ClientAuthenticationMethod.PrivateKeyJwt];
            candidateIntegration.ClientAssertionSigningAlgorithmsSupported = [WellKnownJwaValues.Es256];
            candidateIntegration.ValidateClientCredentialsAsync = static (reading, registration, context, ct) =>
                ValueTask.FromResult(true);
        }).ConfigureAwait(false);

        AuthCodeFlowEndpointResult result = await StartParAgainstStubAsync(
            app, documentUri, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, result.Outcome,
            $"CIMD-020: a conforming private_key_jwt document must be accepted. ErrorDescription={result.ErrorDescription}");
    }


    //(i) Advisory tier.

    /// <summary>
    /// CIMD-006: a client_id carrying a query component completes under the default (advisory,
    /// non-fatal) options, and aborts when the deployment opts into
    /// <see cref="ClientIdMetadataDocumentResolverOptions.TreatAdvisoriesAsErrors"/>.
    /// </summary>
    [TestMethod]
    public async Task QueryComponentAdvisoryCompletesByDefaultAbortsWhenTreatedAsError()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/app?tenant=adversarial");
        documentHost.Publish("/app",
            Encoding.UTF8.GetBytes(BuildDocumentJson(documentUri.OriginalString, [RedirectUri])),
            "application/json");

        ClientIdentifierUrlValidationResult validation = ClientIdentifierUrl.Validate(documentUri.OriginalString);
        Assert.IsTrue(validation.HasQueryComponent, "The candidate must carry the advisory this test exercises.");
        Assert.IsTrue(validation.IsValid, "CIMD-006 is advisory — it must not affect MUST-tier validity.");

        await using TestHostShell tolerantApp = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await tolerantApp.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        AuthCodeFlowEndpointResult tolerantResult = await StartParAgainstStubAsync(
            tolerantApp, documentUri, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, tolerantResult.Outcome,
            $"CIMD-006: a query component must be tolerated under default options. ErrorDescription={tolerantResult.ErrorDescription}");

        await using TestHostShell strictApp = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await strictApp.WireCimdMaterializationAsync(
            "default", documentHost.Certificate, new ClientIdMetadataDocumentResolverOptions { TreatAdvisoriesAsErrors = true }).ConfigureAwait(false);
        AuthCodeFlowEndpointResult strictResult = await StartParAgainstStubAsync(
            strictApp, documentUri, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, strictResult.Outcome,
            "CIMD-006: TreatAdvisoriesAsErrors must abort a query-bearing client_id.");
    }


    /// <summary>CIMD-011: a client_id whose path is exactly <c>/</c> completes by default and aborts when treated as an error.</summary>
    [TestMethod]
    public async Task RootPathAdvisoryCompletesByDefaultAbortsWhenTreatedAsError()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/");
        documentHost.Publish("/",
            Encoding.UTF8.GetBytes(BuildDocumentJson(documentUri.OriginalString, [RedirectUri])),
            "application/json");

        ClientIdentifierUrlValidationResult validation = ClientIdentifierUrl.Validate(documentUri.OriginalString);
        Assert.IsTrue(validation.IsRootPath, "The candidate must carry the advisory this test exercises.");
        Assert.IsTrue(validation.IsValid, "CIMD-011 is advisory — it must not affect MUST-tier validity.");

        await using TestHostShell tolerantApp = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await tolerantApp.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        AuthCodeFlowEndpointResult tolerantResult = await StartParAgainstStubAsync(
            tolerantApp, documentUri, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, tolerantResult.Outcome,
            $"CIMD-011: a root-path client_id must be tolerated under default options. ErrorDescription={tolerantResult.ErrorDescription}");

        await using TestHostShell strictApp = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await strictApp.WireCimdMaterializationAsync(
            "default", documentHost.Certificate, new ClientIdMetadataDocumentResolverOptions { TreatAdvisoriesAsErrors = true }).ConfigureAwait(false);
        AuthCodeFlowEndpointResult strictResult = await StartParAgainstStubAsync(
            strictApp, documentUri, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, strictResult.Outcome,
            "CIMD-011: TreatAdvisoriesAsErrors must abort a root-path client_id.");
    }


    //(j) Tamper / OTel.

    /// <summary>
    /// A wire <c>client_id</c> that does not ordinal-equal the matched registration's own
    /// <c>client_id</c> aborts the request, records a client-id-mismatch span event on the
    /// request's <c>Handle</c> activity, and the wire response never carries the mismatch detail —
    /// only the library's fixed description of a failed client authentication, the answer a pushed request gets
    /// under the token endpoint's rules (<see href="https://www.rfc-editor.org/rfc/rfc9126#section-2">RFC 9126
    /// Section 2</see>).
    /// </summary>
    [TestMethod]
    public async Task ClientIdMismatchEmitsSpanEventAndWireBodyOmitsInternalDetail()
    {
        ConcurrentBag<Activity> captured = [];
        using ActivityListener listener = CreateListener(captured);
        ActivitySource.AddActivityListener(listener);

        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/app");
        documentHost.Publish("/app",
            Encoding.UTF8.GetBytes(BuildDocumentJson(documentUri.OriginalString, [RedirectUri])),
            "application/json");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = app.Host("default");
        Uri parEndpoint = TestHostShell.ComposeEndpointUri(
            hosted.HttpBaseAddress!, stub.TenantId.Value, WellKnownEndpointNames.AuthCodePar);

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, parEndpoint,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ResponseType] = "code",
                [OAuthRequestParameterNames.ClientId] = "https://attacker-supplied.example.com/impersonation",
                [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
                [OAuthRequestParameterNames.CodeChallenge] = "adversarial-pkce-challenge-0123456789",
                [OAuthRequestParameterNames.CodeChallengeMethod] = "S256"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        string? description = doc.RootElement.TryGetProperty("error_description", out JsonElement el) ? el.GetString() : null;
        Assert.AreEqual("Client authentication failed.", description,
            "The wire body must carry only the library's fixed description, never the mismatched " +
            "client_id, the registration's real client_id, or any other internal diagnostic detail.");
        Assert.DoesNotContain("attacker-supplied", body);
        Assert.DoesNotContain(documentUri.OriginalString, body);

        Activity[] handleActivities = captured
            .Where(a => string.Equals(a.OperationName, ServerActivityNames.Handle, StringComparison.Ordinal))
            .Where(a => a.Tags.Any(t =>
                string.Equals(t.Key, ServerTagNames.TenantHandle, StringComparison.Ordinal)
                && string.Equals(t.Value, stub.TenantHandle!.Value.Value, StringComparison.Ordinal)))
            .ToArray();
        Assert.IsGreaterThan(0, handleActivities.Length, "At least one Handle activity for this tenant must be captured.");
        Assert.Contains(
            a => a.Events.Any(e => string.Equals(e.Name, ClientIdMismatchEventName, StringComparison.Ordinal)),
            handleActivities,
            "A client-id-mismatch span event must be recorded on the request's Handle activity.");
    }


    /// <summary>
    /// An application rule composed after <see cref="ClientIdMetadataMaterialization.Build"/>
    /// that refuses a document with no <c>client_name</c> through
    /// <see cref="ClientIdMetadataMaterialization.Refuse"/> answers a pushed authorization request
    /// with the library's own refusal of a pushed request, the token endpoint's client authentication failure
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9126#section-2">RFC 9126 Section 2</see>): 400
    /// <c>invalid_client</c> and the fixed description, at a server that advertises no <c>client_secret_basic</c>
    /// for a request that used no <c>Authorization</c> field. Other
    /// specifications "MAY place additional restrictions on the contents of the Client ID Metadata
    /// Document accepted by authorization servers implementing their specification"
    /// (<see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-4">
    /// draft-ietf-oauth-client-id-metadata-document-02 Section 4</see>). The document here was
    /// fetched, so the refusal is the application's rule under that sentence, and the shape of the
    /// refusal is the library's. Guards the shape a consumer rule gets from the library's public refusal.
    /// </summary>
    [TestMethod]
    public async Task AConsumerRuleRefusesInTheLibraryShapeAtThePushedRequestAsync()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/app");
        documentHost.Publish("/app",
            Encoding.UTF8.GetBytes(BuildDocumentJson(documentUri.OriginalString, [RedirectUri])),
            "application/json");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        await ComposeClientNameRuleAsync(app).ConfigureAwait(false);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        (int statusCode, string body) = await PostToCimdClientAsync(
            app, stub, WellKnownEndpointNames.AuthCodePar,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ResponseType] = "code",
                [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
                [OAuthRequestParameterNames.CodeChallenge] = "adversarial-pkce-challenge-0123456789",
                [OAuthRequestParameterNames.CodeChallengeMethod] = "S256"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(Bad("invalid_client", "Client authentication failed."), body);
    }


    /// <summary>
    /// The same application rule answers a token request with the library's own token-endpoint
    /// refusal: 400 <c>invalid_client</c> and the fixed description, the section's default status at a server
    /// that advertises no <c>client_secret_basic</c> for a request that used no <c>Authorization</c> field. RFC
    /// 6749 Section 5.2 defines
    /// <c>invalid_client</c> as "Client authentication failed (e.g., unknown client, no client
    /// authentication included, or unsupported authentication method)"
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>).
    /// Guards the shape a consumer rule gets from the library's public refusal.
    /// </summary>
    [TestMethod]
    public async Task AConsumerRuleRefusesInTheLibraryShapeAtTheTokenEndpointAsync()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/app");
        documentHost.Publish("/app",
            Encoding.UTF8.GetBytes(BuildDocumentJson(documentUri.OriginalString, [RedirectUri])),
            "application/json");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        await ComposeClientNameRuleAsync(app).ConfigureAwait(false);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        (int statusCode, string body) = await PostToCimdClientAsync(
            app, stub, WellKnownEndpointNames.AuthCodeToken, CodeRedemptionFields(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(Bad("invalid_client", "Client authentication failed."), body);
    }


    /// <summary>
    /// A token request whose <c>client_id</c> names a document that answers 404 is refused with
    /// the library's token-endpoint refusal, and the refusal carries the challenge the request's
    /// authentication asks for. RFC 6749 Section 5.2: "If the client attempted to authenticate via
    /// the "Authorization" request header field, the authorization server MUST respond with an HTTP
    /// 401 (Unauthorized) status code and include the "WWW-Authenticate" response header field
    /// matching the authentication scheme used by the client."
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>), and
    /// <see href="https://www.rfc-editor.org/rfc/rfc7617#section-2">RFC 7617 Section 2</see>: "The authentication
    /// parameter 'realm' is REQUIRED ([RFC7235], Section 2.2)."
    /// A request that carries <c>Authorization: Basic</c> is answered 401 with
    /// <c>WWW-Authenticate: Basic realm="&lt;issuer&gt;"</c>, the realm the issuer the registration is served under,
    /// and the fixed description; the same request without
    /// the header, at a server that advertises no <c>client_secret_basic</c>, is answered 400 with the same
    /// body and no challenge.
    /// </summary>
    /// <param name="isBasicAttempted">Whether the request carries <c>Authorization: Basic</c>.</param>
    /// <param name="expectedStatus">The status the response carries.</param>
    /// <param name="isChallenged">Whether the response carries the <c>Basic realm="&lt;issuer&gt;"</c> challenge; none otherwise.</param>
    [TestMethod]
    [DataRow(true, 401, true)]
    [DataRow(false, 400, false)]
    public async Task AFailedDocumentFetchAtTheTokenEndpointCarriesTheChallengeOfTheSchemeAttemptedAsync(
        bool isBasicAttempted,
        int expectedStatus,
        bool isChallenged)
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/absent");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        OutgoingHeaders? headers = isBasicAttempted
            ? OutgoingHeaders.Empty.WithClientSecretBasic(stub.ClientId, Encoding.UTF8.GetBytes("adversarial-secret-0123456789"))
            : null;

        (int statusCode, string body, string? challenge) = await PostToCimdClientWithHeadersAsync(
            app, stub, WellKnownEndpointNames.AuthCodeToken, CodeRedemptionFields(), headers,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedStatus, statusCode, body);
        Assert.AreEqual(Bad("invalid_client", "Client authentication failed."), body);
        Assert.AreEqual(isChallenged ? $"Basic realm=\"{stub.IssuerUri!.OriginalString}\"" : null, challenge);
    }


    /// <summary>
    /// A request to the token endpoint of a client allowed the authorization code grant, whose capability tags the
    /// authorization endpoint and the token endpoint both, that carries <c>grant_type=</c>, the parameter with an
    /// empty value, is read as if the parameter were omitted: it is no token request, so the abort for a document
    /// that answers 404 is the direct 400 <c>invalid_request</c> with the fixed description, where the same request
    /// with <c>grant_type=authorization_code</c> is refused as a token request, 400 <c>invalid_client</c>. RFC 6749
    /// Section 3.1: "Parameters sent without a value MUST be treated as if they were omitted from
    /// the request." (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749
    /// Section 3.1</see>).
    /// </summary>
    [TestMethod]
    public async Task AnEmptyGrantTypeAtTheTokenEndpointIsReadAsOmittedAsync()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/absent");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        Dictionary<string, string> emptyGrantType = CodeRedemptionFields();
        emptyGrantType[OAuthRequestParameterNames.GrantType] = string.Empty;

        (int statusCode, string body) = await PostToCimdClientAsync(
            app, stub, WellKnownEndpointNames.AuthCodeToken, emptyGrantType, TestContext.CancellationToken).ConfigureAwait(false);
        (int tokenRequestStatusCode, string tokenRequestBody) = await PostToCimdClientAsync(
            app, stub, WellKnownEndpointNames.AuthCodeToken, CodeRedemptionFields(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(Bad("invalid_request", "The request could not be processed."), body);
        Assert.AreEqual(400, tokenRequestStatusCode, tokenRequestBody);
        Assert.AreEqual(Bad("invalid_client", "Client authentication failed."), tokenRequestBody);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7617#section-2">RFC 7617 Section 2</see>: "The authentication
    /// parameter 'realm' is REQUIRED ([RFC7235], Section 2.2)." A token request whose <c>client_id</c> names a
    /// document that answers 404, sent over the wire with <c>Authorization: Basic</c>, at a server with no issuer
    /// resolver, for a registration whose issuer uses the <c>http</c> scheme, has no issuer the library resolves:
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414#section-2">RFC 8414 Section 2</see> defines it as "The
    /// authorization server's issuer identifier, which is a URL that uses the "https" scheme and has no query or
    /// fragment components." The refusal resolves the realm as the token endpoint resolves it, so it names no realm
    /// and is answered 400 <c>invalid_client</c> with the fixed description and no <c>WWW-Authenticate</c>. The 400
    /// is the library's named deviation from
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>: "If the client
    /// attempted to authenticate via the "Authorization" request header field, the authorization server MUST respond
    /// with an HTTP 401 (Unauthorized) status code and include the "WWW-Authenticate" response header field matching
    /// the authentication scheme used by the client." The reason: a challenge without a realm breaks RFC 7617
    /// Section 2, and a 401 without a challenge breaks
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.5.2">RFC 9110 Section 15.5.2</see>, "The server
    /// generating a 401 response MUST send a WWW-Authenticate header field (Section 11.6.1) containing at least one
    /// challenge applicable to the target resource."
    /// </summary>
    [TestMethod]
    public async Task AFailedDocumentFetchUnderAnIssuerOutsideTheIssuerShapeIsABadRequestWithoutAChallengeAsync()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/absent");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        ClientRecord registered = await app.RegisterCimdStubClientAsync(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        HostedAuthorizationServer hosted = app.Host("default");
        ClientRecord stub = registered with { IssuerUri = new Uri($"http://issuer.test/{registered.TenantId.Value}") };
        hosted.Registrations[stub.TenantId.Value] = stub;
        hosted.Registrations[stub.ClientId] = stub;

        (int statusCode, string body, string? challenge) = await PostToCimdClientWithHeadersAsync(
            app, stub, WellKnownEndpointNames.AuthCodeToken, CodeRedemptionFields(),
            OutgoingHeaders.Empty.WithClientSecretBasic(stub.ClientId, Encoding.UTF8.GetBytes("adversarial-secret-0123456789")),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(Bad("invalid_client", "Client authentication failed."), body);
        Assert.IsNull(challenge, "A refusal that names no realm carries no challenge.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7617#section-2">RFC 7617 Section 2</see>: "The authentication
    /// parameter 'realm' is REQUIRED ([RFC7235], Section 2.2)." A token request whose <c>client_id</c> names a
    /// document that answers 404, sent over the wire with <c>Authorization: Basic</c>, at a server whose issuer
    /// resolver answers no issuer while the application's policy step placed an issuer on the request's context
    /// before the resolver ran, has no issuer the token endpoint resolves: the refusal resolves the realm as the token
    /// endpoint resolves it, through the application's resolver, so it names no realm, not the issuer the context
    /// carries either, and is answered 400 <c>invalid_client</c> with the fixed description and no
    /// <c>WWW-Authenticate</c>. The 400 is the library's named deviation from
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>: "If the client
    /// attempted to authenticate via the "Authorization" request header field, the authorization server MUST respond
    /// with an HTTP 401 (Unauthorized) status code and include the "WWW-Authenticate" response header field matching
    /// the authentication scheme used by the client." The reason: the issuer the application's resolver declined is
    /// no issuer the token endpoint serves under, a challenge without a realm breaks RFC 7617 Section 2, and a 401
    /// without a challenge breaks
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.5.2">RFC 9110 Section 15.5.2</see>, "The server
    /// generating a 401 response MUST send a WWW-Authenticate header field (Section 11.6.1) containing at least one
    /// challenge applicable to the target resource."
    /// </summary>
    [TestMethod]
    public async Task AFailedDocumentFetchWhereTheIssuerResolverAnswersNoneIsABadRequestWithoutAChallengeAsync()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/absent");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        Uri presetIssuer = new("https://preset.issuer.test/");
        await TestHostShell.AlterAsync(app.Host("default").Server, candidate =>
        {
            ResolveServerPolicyDelegate resolvePolicy = candidate.ResolvePolicyAsync!;
            candidate.ResolvePolicyAsync = async (registration, context, cancellationToken) =>
            {
                await resolvePolicy(registration, context, cancellationToken).ConfigureAwait(false);
                context.SetIssuer(presetIssuer);
            };
            candidate.ResolveIssuerAsync = static (_, _, _) => ValueTask.FromResult<Uri?>(null);
        }).ConfigureAwait(false);

        (int statusCode, string body, string? challenge) = await PostToCimdClientWithHeadersAsync(
            app, stub, WellKnownEndpointNames.AuthCodeToken, CodeRedemptionFields(),
            OutgoingHeaders.Empty.WithClientSecretBasic(stub.ClientId, Encoding.UTF8.GetBytes("adversarial-secret-0123456789")),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(Bad("invalid_client", "Client authentication failed."), body);
        Assert.IsNull(challenge, "A refusal that names no realm carries no challenge.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 Section 3</see>: "If the protected
    /// resource request does not include authentication credentials or does not contain an access token that enables
    /// access to the protected resource, the resource server MUST include the HTTP "WWW-Authenticate" response header
    /// field; it MAY include it in response to other conditions as well." A UserInfo request of a client whose
    /// registration names a Client ID Metadata Document, sent over a raw TLS connection with one empty
    /// <c>Authorization</c> field line, authenticates no client, so the materialization leaves it to UserInfo, which
    /// reads it as a request without the authentication information it reads and answers 401 with an empty body and
    /// the one challenge naming the two schemes it accepts and no error,
    /// <c>Bearer scope="openid", DPoP algs="..."</c>:
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>, "If the request
    /// lacks any authentication information (e.g., the client was unaware that authentication is necessary or
    /// attempted using an unsupported authentication method), the resource server SHOULD NOT include an error code
    /// or other error information."
    /// </summary>
    [TestMethod]
    public async Task AnEmptyAuthorizationLineAtUserInfoIsChallengedWithoutAnErrorCodeAsync()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/absent");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, UserInfoCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        HttpResponseData response = await SendToCimdClientOverARawConnectionAsync(
            app, stub, WellKnownEndpointNames.UserInfo,
            [new(WellKnownHttpHeaderNames.Authorization, string.Empty)]).ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(
            $"Bearer scope=\"openid\", DPoP algs=\"{ResourceDpopProofs.AcceptedProofAlgorithms}\"",
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(string.Empty, response.Body, "No error code or other error information.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 Section 3</see>: "If the protected
    /// resource request does not include authentication credentials or does not contain an access token that enables
    /// access to the protected resource, the resource server MUST include the HTTP "WWW-Authenticate" response header
    /// field; it MAY include it in response to other conditions as well." A UserInfo request without an access token,
    /// sent over a raw TLS connection to a tenant whose registration names a Client ID Metadata Document and holds no
    /// <c>client_name</c>, arrives at the application's rule with the stored registration, since the request
    /// identifies and authenticates no OAuth client and the materialization fetches nothing for it. The rule refuses
    /// only a materialized registration, so the resource answers as it answers the same request without the rule: 401
    /// with an empty body and the one challenge naming the two schemes it accepts,
    /// <c>Bearer scope="openid", DPoP algs="..."</c>, where a rule that refused the stored registration would answer
    /// 400 without that challenge.
    /// </summary>
    [TestMethod]
    public async Task AProtectedResourceRequestUnderAnApplicationClientNameRuleKeepsTheResourcesChallengeAsync()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/absent");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        await ComposeClientNameRuleAsync(app).ConfigureAwait(false);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, UserInfoCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        HttpResponseData response = await SendToCimdClientOverARawConnectionAsync(
            app, stub, WellKnownEndpointNames.UserInfo,
            [new(WellKnownHttpHeaderNames.Authorization, string.Empty)]).ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(
            $"Bearer scope=\"openid\", DPoP algs=\"{ResourceDpopProofs.AcceptedProofAlgorithms}\"",
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(string.Empty, response.Body, "The resource's own answer carries no body.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>:
    /// "invalid_request The request is missing a required parameter, includes an unsupported parameter or
    /// parameter value, repeats the same parameter, uses more than one method for including an access
    /// token, or is otherwise malformed.  The resource server SHOULD respond with the HTTP 400 (Bad
    /// Request) status code." A UserInfo request of a client whose registration names a Client ID Metadata Document,
    /// sent over a raw TLS connection with two <c>Authorization: Bearer</c> field lines, authenticates no client, so
    /// the materialization leaves it to UserInfo, which refuses it 400 <c>invalid_request</c> with one
    /// <c>WWW-Authenticate</c> field holding the <c>Bearer</c> and the <c>DPoP</c> challenge,
    /// <c>Bearer realm="&lt;issuer&gt;", error="invalid_request", DPoP error="invalid_request", algs="..."</c>, as it
    /// refuses two lines of any client: <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449
    /// Section 7.2</see>, "Otherwise, both Bearer and DPoP challenges MAY be used to deliver error information
    /// (Figure 19)." Both lines name one scheme, where the section recommends "If the mechanism used to attempt
    /// authentication could be established unambiguously, then the corresponding challenge SHOULD be used to deliver
    /// error information (Figure 18)."; the both-challenges answer to two lines of one scheme is the library's named
    /// deviation, since the reading of a repeated field keeps no scheme.
    /// </summary>
    [TestMethod]
    public async Task TwoAuthorizationLinesAtUserInfoCarryBothChallengesAsync()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/absent");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, UserInfoCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        HttpResponseData response = await SendToCimdClientOverARawConnectionAsync(
            app, stub, WellKnownEndpointNames.UserInfo,
            [
                new(WellKnownHttpHeaderNames.Authorization, "Bearer first-access-token"),
                new(WellKnownHttpHeaderNames.Authorization, "Bearer second-access-token")
            ]).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual(
            $"Bearer realm=\"{stub.IssuerUri!.OriginalString}\", error=\"invalid_request\", "
            + $"DPoP error=\"invalid_request\", algs=\"{ResourceDpopProofs.AcceptedProofAlgorithms}\"",
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(Bad("invalid_request", "The Authorization header is not a single well-formed credential."), response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 Section 3</see>: "If the protected
    /// resource request does not include authentication credentials or does not contain an access token that enables
    /// access to the protected resource, the resource server MUST include the HTTP "WWW-Authenticate" response header
    /// field; it MAY include it in response to other conditions as well." A request without an access token, sent over a
    /// raw TLS connection to a protected resource of a tenant whose registration names a Client ID Metadata Document,
    /// that carries a <c>client_id</c> naming another client, or a <c>grant_type</c> beside an empty
    /// <c>Authorization</c> field line, identifies and authenticates no OAuth client there: the Client ID Metadata
    /// Document materialization fetches nothing for it, and the resource answers it 401 with its challenge exactly as
    /// it answers the same request of the same tenant once its registration names no document (status, every
    /// <c>WWW-Authenticate</c> value and body equal).
    /// </summary>
    /// <param name="resource">The protected resource the request is sent to.</param>
    /// <param name="request">The field the request carries.</param>
    [TestMethod]
    [DataRow("userinfo", "client_id", DisplayName = "UserInfo, a client_id naming another client")]
    [DataRow("userinfo", "grant_type", DisplayName = "UserInfo, a grant_type form field and an empty Authorization line")]
    [DataRow("deferred_credential", "client_id", DisplayName = "the Deferred Credential endpoint, a client_id naming another client")]
    [DataRow("deferred_credential", "grant_type", DisplayName = "the Deferred Credential endpoint, a grant_type and an empty Authorization line")]
    [DataRow("client_configuration", "client_id", DisplayName = "the client configuration endpoint, a client_id naming another client")]
    [DataRow("client_configuration", "grant_type", DisplayName = "the client configuration endpoint, a grant_type and an empty Authorization line")]
    public async Task AProtectedResourceRequestOfAMetadataDocumentTenantIsAnsweredAsWithoutADocumentAsync(string resource, string request)
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/absent");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        HostedAuthorizationServer hosted = app.Host("default");
        await TestHostShell.AlterAsync(hosted.Server, candidate =>
        {
            candidate.ResolveDeferredCredentialAsync = static (_, _, _, _, _) =>
                ValueTask.FromException<DeferredCredentialDecision>(
                    new InvalidOperationException("A request without an access token does not reach the deferred credential seam."));
        }).ConfigureAwait(false);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, ProtectedResourceCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        (string endpointName, string method) = resource switch
        {
            "userinfo" => (WellKnownEndpointNames.UserInfo, WellKnownHttpMethods.Post),
            "deferred_credential" => (WellKnownEndpointNames.Oid4VciDeferredCredential, WellKnownHttpMethods.Post),
            "client_configuration" => (WellKnownEndpointNames.RegistrationRegister, WellKnownHttpMethods.Get),

            _ => throw new ArgumentOutOfRangeException(nameof(resource), resource, "No such row.")
        };
        bool isFormBody = request == "grant_type" && resource == "userinfo";
        IReadOnlyList<KeyValuePair<string, string>> fieldLines = request switch
        {
            "client_id" => [],
            "grant_type" when isFormBody =>
            [
                new(WellKnownHttpHeaderNames.ContentType, "application/x-www-form-urlencoded"),
                new(WellKnownHttpHeaderNames.Authorization, string.Empty)
            ],
            "grant_type" => [new(WellKnownHttpHeaderNames.Authorization, string.Empty)],

            _ => throw new ArgumentOutOfRangeException(nameof(request), request, "No such row.")
        };
        string? query = request switch
        {
            "client_id" => $"client_id={Uri.EscapeDataString("https://other.example/app")}",
            _ when isFormBody => null,

            _ => "grant_type=authorization_code"
        };
        string? body = isFormBody ? "grant_type=authorization_code" : null;

        HttpResponseData atDocumentTenant = await SendToCimdClientOverARawConnectionAsync(
            app, stub, endpointName, fieldLines, method, query, body).ConfigureAwait(false);
        bool isDocumentFetched = documentHost.WasRequested("/absent");

        //The same tenant, its registration naming no metadata document.
        ClientRecord withoutDocument = hosted.Registrations[stub.TenantId.Value] with { ClientMetadataUri = null };
        hosted.Registrations[withoutDocument.TenantId.Value] = withoutDocument;
        hosted.Registrations[withoutDocument.ClientId] = withoutDocument;
        HttpResponseData atTenantWithoutDocument = await SendToCimdClientOverARawConnectionAsync(
            app, stub, endpointName, fieldLines, method, query, body).ConfigureAwait(false);

        Assert.AreEqual(atTenantWithoutDocument.StatusCode, atDocumentTenant.StatusCode, atDocumentTenant.Body);
        Assert.AreEqual(
            string.Join(" | ", atTenantWithoutDocument.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)),
            string.Join(" | ", atDocumentTenant.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(atTenantWithoutDocument.Body, atDocumentTenant.Body);
        Assert.AreEqual(401, atDocumentTenant.StatusCode, atDocumentTenant.Body);
        Assert.IsNotEmpty(atDocumentTenant.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate), "The 401 carries the resource's challenge.");
        Assert.IsFalse(isDocumentFetched, "A protected resource request fetches no document.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2">RFC 9126 Section 2</see>: "The rules for client
    /// authentication as defined in [RFC6749] for token endpoint requests, including the applicable authentication
    /// methods, apply for the PAR endpoint as well." A pushed authorization request of a client whose registration
    /// names a Client ID Metadata Document, sent over the wire with a <c>client_id</c> naming another client, and the
    /// same request with the client's own <c>client_id</c> whose document answers 404, are each refused in the shape
    /// of the token endpoint's client authentication failure, <c>invalid_client</c> with the fixed description, and the
    /// two answers are equal, so a caller cannot tell a mismatch from a failed fetch. With
    /// <c>Authorization: Basic</c> the answer is 401 with <c>Basic realm="&lt;issuer&gt;"</c>, as
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see> requires: "If the
    /// client attempted to authenticate via the "Authorization" request header field, the authorization server MUST
    /// respond with an HTTP 401 (Unauthorized) status code and include the "WWW-Authenticate" response header field
    /// matching the authentication scheme used by the client." Without an <c>Authorization</c> field, and with
    /// <c>client_secret_basic</c> not advertised, the answer is 400 with no challenge, as the token endpoint gives it.
    /// </summary>
    /// <param name="isBasicAttempted">Whether the request carries <c>Authorization: Basic</c>.</param>
    [TestMethod]
    [DataRow(true, DisplayName = "with Authorization: Basic")]
    [DataRow(false, DisplayName = "without an Authorization field")]
    public async Task APushedRequestNamingAnotherClientOrWhoseDocumentFailsIsAClientAuthenticationFailureAsync(bool isBasicAttempted)
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/absent");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        OutgoingHeaders? headers = isBasicAttempted
            ? OutgoingHeaders.Empty.WithClientSecretBasic(stub.ClientId, Encoding.UTF8.GetBytes("adversarial-secret-0123456789"))
            : null;

        (int mismatchStatus, string mismatchBody, string? mismatchChallenge) = await PostToCimdClientWithHeadersAsync(
            app, stub, WellKnownEndpointNames.AuthCodePar, PushedRequestFields(), headers, TestContext.CancellationToken,
            clientId: "https://other.example/app").ConfigureAwait(false);
        (int failedFetchStatus, string failedFetchBody, string? failedFetchChallenge) = await PostToCimdClientWithHeadersAsync(
            app, stub, WellKnownEndpointNames.AuthCodePar, PushedRequestFields(), headers, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(isBasicAttempted ? 401 : 400, mismatchStatus, mismatchBody);
        Assert.AreEqual(Bad("invalid_client", "Client authentication failed."), mismatchBody);
        Assert.AreEqual(isBasicAttempted ? $"Basic realm=\"{stub.IssuerUri!.OriginalString}\"" : null, mismatchChallenge);
        Assert.AreEqual(mismatchStatus, failedFetchStatus, failedFetchBody);
        Assert.AreEqual(mismatchBody, failedFetchBody);
        Assert.AreEqual(mismatchChallenge, failedFetchChallenge);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2">RFC 9126 Section 2</see>: "The rules for client
    /// authentication as defined in [RFC6749] for token endpoint requests, including the applicable authentication
    /// methods, apply for the PAR endpoint as well." A pushed authorization request of a client whose registration
    /// names a Client ID Metadata Document, sent over the wire without <c>client_id</c> (with
    /// <c>Authorization: Basic</c> and without it, and with a <c>grant_type</c> beside <c>Authorization: Basic</c>,
    /// which leaves a pushed request a pushed request), names no client to fetch a document for, and the pushed
    /// request endpoint answers it 400 <c>invalid_request</c> with "Missing client_id.". No document is fetched for
    /// any of them.
    /// </summary>
    /// <param name="request">The request sent.</param>
    /// <param name="expectedBody">The body the request is answered with.</param>
    [TestMethod]
    [DataRow("basic_without_client_id", "{\"error\":\"invalid_request\",\"error_description\":\"Missing client_id.\"}", DisplayName = "Authorization: Basic and no client_id")]
    [DataRow("basic_grant_type_without_client_id", "{\"error\":\"invalid_request\",\"error_description\":\"Missing client_id.\"}", DisplayName = "a grant_type, Authorization: Basic and no client_id")]
    [DataRow("without_client_id", "{\"error\":\"invalid_request\",\"error_description\":\"Missing client_id.\"}", DisplayName = "no credential and no client_id")]
    public async Task APushedRequestWithoutOneUsableClientIdFetchesNoDocumentAsync(string request, string expectedBody)
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/absent");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        string fields = $"response_type=code&redirect_uri={Uri.EscapeDataString(RedirectUri.OriginalString)}"
            + "&code_challenge=adversarial-pkce-challenge-0123456789&code_challenge_method=S256";
        string basic = $"Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Uri.EscapeDataString(stub.ClientId)}:adversarial-secret-0123456789"))}";
        (string Body, IReadOnlyList<KeyValuePair<string, string>> FieldLines) target = request switch
        {
            "basic_without_client_id" => (fields, [new(WellKnownHttpHeaderNames.ContentType, "application/x-www-form-urlencoded"), new(WellKnownHttpHeaderNames.Authorization, basic)]),
            "basic_grant_type_without_client_id" => (
                $"{fields}&grant_type=authorization_code",
                [new(WellKnownHttpHeaderNames.ContentType, "application/x-www-form-urlencoded"), new(WellKnownHttpHeaderNames.Authorization, basic)]),
            "without_client_id" => (fields, [new(WellKnownHttpHeaderNames.ContentType, "application/x-www-form-urlencoded")]),

            _ => throw new ArgumentOutOfRangeException(nameof(request), request, "No such row.")
        };

        HttpResponseData response = await SendToCimdClientOverARawConnectionAsync(
            app, stub, WellKnownEndpointNames.AuthCodePar, target.FieldLines, body: target.Body).ConfigureAwait(false);

        Assert.IsFalse(documentHost.WasRequested("/absent"), $"No document is fetched. {response.StatusCode} {response.Body}");
        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual(expectedBody, response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 Section 3.2</see>: "Request and
    /// response parameters MUST NOT be included more than once."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2">RFC 9126 Section 2</see>: "The rules for client
    /// authentication as defined in [RFC6749] for token endpoint requests, including the applicable authentication
    /// methods, apply for the PAR endpoint as well."
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>, <c>invalid_request</c>:
    /// "The request is missing a required parameter, includes an unsupported parameter value (other than grant type),
    /// repeats a parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the
    /// client, or is otherwise malformed." A pushed authorization request of a client whose registration names
    /// a Client ID Metadata Document, sent over the wire with its one <c>client_id</c> and <c>client_secret</c>
    /// repeated, is a malformed client authentication at an endpoint that authenticates as the token endpoint does: it
    /// is refused before any document is fetched, 400 <c>invalid_request</c> with the description of a repeated client
    /// authentication parameter.
    /// </summary>
    [TestMethod]
    public async Task APushedAuthorizationRequestRepeatingClientSecretIsAnInvalidRequestAsync()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/absent");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        string body = $"response_type=code&redirect_uri={Uri.EscapeDataString(RedirectUri.OriginalString)}"
            + "&code_challenge=adversarial-pkce-challenge-0123456789&code_challenge_method=S256"
            + $"&client_id={Uri.EscapeDataString(stub.ClientId)}&client_secret=first-secret&client_secret=second-secret";

        HttpResponseData response = await SendToCimdClientOverARawConnectionAsync(
            app, stub, WellKnownEndpointNames.AuthCodePar,
            [new(WellKnownHttpHeaderNames.ContentType, "application/x-www-form-urlencoded")], body: body).ConfigureAwait(false);

        Assert.IsFalse(documentHost.WasRequested("/absent"), $"No document is fetched. {response.StatusCode} {response.Body}");
        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual("{\"error\":\"invalid_request\",\"error_description\":\"The request repeats a client authentication parameter.\"}", response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>: "If the client
    /// attempted to authenticate via the "Authorization" request header field, the authorization server MUST respond
    /// with an HTTP 401 (Unauthorized) status code and include the "WWW-Authenticate" response header field matching
    /// the authentication scheme used by the client." A code redemption of a client whose registration names a Client
    /// ID Metadata Document, sent over the wire with a <c>client_id</c> naming another client, is refused before any
    /// fetch in the shape of the client authentication failure, <c>invalid_client</c> with the fixed description: 401
    /// with <c>Basic realm="&lt;issuer&gt;"</c> with <c>Authorization: Basic</c>, and 400 with no challenge without it
    /// at a server that advertises no <c>client_secret_basic</c>.
    /// </summary>
    /// <param name="isBasicAttempted">Whether the request carries <c>Authorization: Basic</c>.</param>
    [TestMethod]
    [DataRow(true, DisplayName = "with Authorization: Basic")]
    [DataRow(false, DisplayName = "without an Authorization field")]
    public async Task ATokenRequestNamingAnotherClientIsAClientAuthenticationFailureAsync(bool isBasicAttempted)
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/absent");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        OutgoingHeaders? headers = isBasicAttempted
            ? OutgoingHeaders.Empty.WithClientSecretBasic(stub.ClientId, Encoding.UTF8.GetBytes("adversarial-secret-0123456789"))
            : null;

        (int statusCode, string body, string? challenge) = await PostToCimdClientWithHeadersAsync(
            app, stub, WellKnownEndpointNames.AuthCodeToken, CodeRedemptionFields(), headers, TestContext.CancellationToken,
            clientId: "https://other.example/app").ConfigureAwait(false);

        Assert.IsFalse(documentHost.WasRequested("/absent"), "A client_id naming another client fetches no document.");
        Assert.AreEqual(isBasicAttempted ? 401 : 400, statusCode, body);
        Assert.AreEqual(Bad("invalid_client", "Client authentication failed."), body);
        Assert.AreEqual(isBasicAttempted ? $"Basic realm=\"{stub.IssuerUri!.OriginalString}\"" : null, challenge);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 Section 4.1.2.1</see>: "If the
    /// request fails due to a missing, invalid, or mismatching redirection URI, or if the client identifier is missing
    /// or invalid, the authorization server SHOULD inform the resource owner of the error and MUST NOT automatically
    /// redirect the user-agent to the invalid redirection URI." An authorization request of a client whose registration
    /// names a Client ID Metadata Document, sent over the wire with a <c>client_id</c> naming another client, carries
    /// an invalid client identifier: it is refused before any document is fetched with the direct 400
    /// <c>invalid_request</c> and the fixed description, no redirect being attempted.
    /// </summary>
    [TestMethod]
    public async Task AnAuthorizationRequestNamingAnotherClientIsAnsweredWithoutARedirectAsync()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/absent");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        HttpResponseData response = await SendToCimdClientOverARawConnectionAsync(
            app, stub, WellKnownEndpointNames.AuthCodeAuthorize, [], WellKnownHttpMethods.Get,
            AuthorizationRequestQuery(Uri.EscapeDataString("https://other.example/app"))).ConfigureAwait(false);

        Assert.IsFalse(documentHost.WasRequested("/absent"), $"A client_id naming another client fetches no document. {response.StatusCode} {response.Body}");
        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.IsEmpty(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.Location), "No redirect is attempted.");
        Assert.AreEqual("{\"error\":\"invalid_request\",\"error_description\":\"The request could not be processed.\"}", response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-4">RFC 9126 Section 4</see>: "The client uses the
    /// "request_uri" value returned by the authorization server to build an authorization request as defined in
    /// [RFC9101]." <see href="https://www.rfc-editor.org/rfc/rfc9101#section-5">RFC 9101 Section 5</see> names
    /// <c>client_id</c> "REQUIRED." in that authorization request: "The value MUST match the "request" or "request_uri"
    /// Request Object's (Section 2.1) "client_id"." The general form is
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749 Section 4.1.1</see>, <c>client_id</c>
    /// "REQUIRED.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">Section 4.1.2.1</see>: "If the request fails
    /// due to a missing, invalid, or mismatching redirection URI, or if the client identifier is missing or invalid, the
    /// authorization server SHOULD inform the resource owner of the error and MUST NOT automatically redirect the
    /// user-agent to the invalid redirection URI." An authorization request of a client whose registration names a
    /// Client ID Metadata Document, sent over the wire with <c>Authorization: Basic</c> and a <c>request_uri</c> but no
    /// <c>client_id</c>, names no client: no document is fetched, and the authorization endpoint answers the missing
    /// identifier itself, the direct 400 <c>invalid_request</c> with "Missing client_id.".
    /// </summary>
    [TestMethod]
    public async Task AnAuthorizationRequestWithoutClientIdIsAnsweredByTheAuthorizationEndpointAsync()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/absent");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        string basic = $"Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Uri.EscapeDataString(stub.ClientId)}:adversarial-secret-0123456789"))}";

        HttpResponseData response = await SendToCimdClientOverARawConnectionAsync(
            app, stub, WellKnownEndpointNames.AuthCodeAuthorize, [new(WellKnownHttpHeaderNames.Authorization, basic)], WellKnownHttpMethods.Get,
            $"request_uri={Uri.EscapeDataString("urn:ietf:params:oauth:request_uri:adversarial-0123456789")}").ConfigureAwait(false);

        Assert.IsFalse(documentHost.WasRequested("/absent"), $"A request that names no client fetches no document. {response.StatusCode} {response.Body}");
        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual("{\"error\":\"invalid_request\",\"error_description\":\"Missing client_id.\"}", response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>, <c>invalid_client</c>:
    /// "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported
    /// authentication method)." The library's rule: a request whose fields carry a <c>grant_type</c> with a value is
    /// authenticated as a request to the token endpoint is, whatever endpoint it reaches outside the protected
    /// resources, Global Token Revocation and the pushed authorization request, so the client's document is fetched for
    /// it. An authorization request of a client whose registration names a Client ID Metadata Document, sent over the
    /// wire with its own <c>client_id</c> and <c>grant_type=authorization_code</c>, has the document fetched, and the
    /// document's failure (404) is answered as the token endpoint answers a failed client authentication: 400
    /// <c>invalid_client</c> with the fixed description, without a challenge, since no <c>Authorization</c> field was
    /// attempted and no <c>client_secret_basic</c> is advertised.
    /// </summary>
    [TestMethod]
    public async Task AnAuthorizationRequestCarryingAGrantTypeIsAuthenticatedAsTheTokenEndpointAuthenticatesAsync()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/absent");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        HttpResponseData response = await SendToCimdClientOverARawConnectionAsync(
            app, stub, WellKnownEndpointNames.AuthCodeAuthorize, [], WellKnownHttpMethods.Get,
            $"{AuthorizationRequestQuery(Uri.EscapeDataString(stub.ClientId))}&grant_type=authorization_code").ConfigureAwait(false);

        Assert.IsTrue(documentHost.WasRequested("/absent"), $"The client's document is fetched. {response.StatusCode} {response.Body}");
        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.IsEmpty(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate), "No Authorization field was attempted.");
        Assert.AreEqual("{\"error\":\"invalid_client\",\"error_description\":\"Client authentication failed.\"}", response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 Section 3.1</see>: "The authorization
    /// server MUST ignore unrecognized request parameters." An authorization request of a client whose registration
    /// names a Client ID Metadata Document, sent over the wire with one <c>client_id</c> and a <c>client_secret</c>
    /// repeated beside it, names its client by that one <c>client_id</c>, the field the authorization endpoint
    /// identifies the client by: the client's document is fetched for it, and the answer (here the abort for a
    /// document that answers 404, the direct 400 <c>invalid_request</c> with the fixed description) equals the answer
    /// to the same request without the repeated field. The same section's "Request and response parameters MUST NOT be
    /// included more than once." does not make the request malformed here, since <c>client_secret</c> is no parameter
    /// of the authorization request
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749 Section 4.1.1</see>) and the
    /// endpoint ignores it.
    /// </summary>
    [TestMethod]
    public async Task ARepeatedClientSecretBesideOneClientIdAtTheAuthorizationEndpointIsJudgedByThatClientIdAsync()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/absent");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        string query = AuthorizationRequestQuery(Uri.EscapeDataString(stub.ClientId));

        HttpResponseData withRepeatedSecret = await SendToCimdClientOverARawConnectionAsync(
            app, stub, WellKnownEndpointNames.AuthCodeAuthorize, [], WellKnownHttpMethods.Get,
            $"{query}&client_secret=first-secret&client_secret=second-secret").ConfigureAwait(false);
        bool isDocumentFetched = documentHost.WasRequested("/absent");
        HttpResponseData withoutRepeatedSecret = await SendToCimdClientOverARawConnectionAsync(
            app, stub, WellKnownEndpointNames.AuthCodeAuthorize, [], WellKnownHttpMethods.Get, query).ConfigureAwait(false);

        Assert.IsTrue(isDocumentFetched, $"The client's document is fetched. {withRepeatedSecret.StatusCode} {withRepeatedSecret.Body}");
        Assert.AreEqual(withoutRepeatedSecret.StatusCode, withRepeatedSecret.StatusCode, withRepeatedSecret.Body);
        Assert.AreEqual(withoutRepeatedSecret.Body, withRepeatedSecret.Body);
        Assert.AreEqual(400, withRepeatedSecret.StatusCode, withRepeatedSecret.Body);
        Assert.AreEqual(Bad("invalid_request", "The request could not be processed."), withRepeatedSecret.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 Section 3.1</see>: "Request and
    /// response parameters MUST NOT be included more than once." An authorization request of a client whose
    /// registration names a Client ID Metadata Document, sent over the wire with two different non-empty
    /// <c>client_id</c> values, names no client: no document is fetched, and the authorization endpoint answers it
    /// as it answers a request that names no client, 400 <c>invalid_request</c> with "Missing client_id.".
    /// </summary>
    [TestMethod]
    public async Task TwoDifferentClientIdValuesAtTheAuthorizationEndpointNameNoClientAsync()
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/absent");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        string query = AuthorizationRequestQuery(Uri.EscapeDataString(stub.ClientId))
            + $"&client_id={Uri.EscapeDataString("https://other.example/app")}";

        HttpResponseData response = await SendToCimdClientOverARawConnectionAsync(
            app, stub, WellKnownEndpointNames.AuthCodeAuthorize, [], WellKnownHttpMethods.Get, query).ConfigureAwait(false);

        Assert.IsFalse(documentHost.WasRequested("/absent"), "A request that names no client fetches no document.");
        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual(Bad("invalid_request", "Missing client_id."), response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8628#section-3.1">RFC 8628 Section 3.1</see>: "The client
    /// authentication requirements of Section 3.2.1 of [RFC6749] apply to requests on this endpoint, which means that
    /// confidential clients (those that have established client credentials) authenticate in the same manner as when
    /// making requests to the token endpoint, and public clients provide the "client_id" parameter to identify
    /// themselves." A device authorization request of a client whose registration names a Client ID Metadata Document
    /// declaring <c>private_key_jwt</c>, sent over the wire without <c>client_id</c> to an application's device
    /// authorization endpoint (composed through the server's configuration with the library's public parts), with
    /// <c>Authorization: Basic</c> and with no credential at all, is judged against the client's document as a request
    /// to the token endpoint is: the document is fetched once, and the endpoint's handler sees the registration the document
    /// materialized, as does the client authentication seam it hands a presented credential to.
    /// </summary>
    /// <param name="isBasicAttempted">Whether the request carries <c>Authorization: Basic</c>.</param>
    /// <param name="expectedBody">The JSON body the endpoint's handler answers for the request, as a literal: whether
    /// it saw a materialized registration and whether the seam it handed the credential to accepted.</param>
    [TestMethod]
    [DataRow(true, "{\"client_metadata_materialized\":true,\"authenticated\":true}", DisplayName = "Authorization: Basic and no client_id")]
    [DataRow(false, "{\"client_metadata_materialized\":true,\"authenticated\":false}", DisplayName = "neither a credential nor a client_id")]
    public async Task ADeviceAuthorizationRequestWithoutClientIdIsJudgedAgainstTheClientsDocumentAsync(bool isBasicAttempted, string expectedBody)
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/app");
        documentHost.Publish("/app",
            Encoding.UTF8.GetBytes(BuildDocumentJson(
                documentUri.OriginalString, [RedirectUri],
                tokenEndpointAuthMethod: WellKnownClientAuthenticationMethods.PrivateKeyJwt,
                jwksUriRaw: "https://client.example.com/jwks.json")),
            "application/json");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        ConcurrentQueue<ClientRecord?> registrationsSeen = new();
        ConcurrentQueue<ClientRecord> seamRegistrations = new();
        await ComposeDeviceAuthorizationEndpointAsync(app, registrationsSeen, seamRegistrations).ConfigureAwait(false);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, DeviceAuthorizationCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        HttpResponseData response = await SendToCimdClientOverARawConnectionAsync(
            app, stub, SyntheticEndpointFamily.ClientAuthenticatingName, DeviceAuthorizationFieldLines(stub, isBasicAttempted),
            body: "scope=openid").ConfigureAwait(false);

        Assert.AreEqual(1, documentHost.TotalRequests, $"The client's document is fetched once. {response.StatusCode} {response.Body}");
        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual(expectedBody, response.Body);
        ClientRecord? seen = Assert.ContainsSingle(registrationsSeen);
        Assert.IsTrue(seen is { IsClientMetadataMaterialized: true }, "The handler sees the registration the document materialized.");
        Assert.AreEqual(ClientAuthenticationMethod.PrivateKeyJwt, seen.TokenEndpointAuthMethod);
        Assert.HasCount(isBasicAttempted ? 1 : 0, seamRegistrations);
        Assert.IsTrue(seamRegistrations.All(static registration => registration.IsClientMetadataMaterialized), "The seam is handed the materialized registration.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8628#section-3.1">RFC 8628 Section 3.1</see>: "The client
    /// authentication requirements of Section 3.2.1 of [RFC6749] apply to requests on this endpoint, which means that
    /// confidential clients (those that have established client credentials) authenticate in the same manner as when
    /// making requests to the token endpoint, and public clients provide the "client_id" parameter to identify
    /// themselves." <see href="https://www.rfc-editor.org/rfc/rfc8628#section-3.2">RFC 8628 Section 3.2</see>: "In the
    /// event of an error (such as an invalidly configured client), the authorization server responds in the same way as
    /// the token endpoint specified in Section 5.2 of [RFC6749]." A device authorization request with
    /// <c>Authorization: Basic</c> of a client whose registration names a Client ID Metadata Document, sent over the
    /// wire to an application's device authorization endpoint, whose document answers 404, or that carries a
    /// <c>client_id</c> naming another client, is refused before the endpoint's handler runs with the token endpoint's
    /// client authentication failure: 401, <c>Basic realm="&lt;issuer&gt;"</c> and <c>invalid_client</c> with the fixed
    /// description, the same bytes for both.
    /// </summary>
    /// <param name="isAnotherClientNamed">Whether the request carries a <c>client_id</c> naming another client.</param>
    [TestMethod]
    [DataRow(false, DisplayName = "a document that answers 404")]
    [DataRow(true, DisplayName = "a client_id naming another client")]
    public async Task ADeviceAuthorizationRequestWhoseClientIsNotAuthenticatedIsRefusedAsTheTokenEndpointRefusesItAsync(bool isAnotherClientNamed)
    {
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        Uri documentUri = new(documentHost.BaseAddress, "/absent");

        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        ConcurrentQueue<ClientRecord?> registrationsSeen = new();
        ConcurrentQueue<ClientRecord> seamRegistrations = new();
        await ComposeDeviceAuthorizationEndpointAsync(app, registrationsSeen, seamRegistrations).ConfigureAwait(false);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, DeviceAuthorizationCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        string body = isAnotherClientNamed
            ? $"scope=openid&client_id={Uri.EscapeDataString("https://other.example/app")}"
            : "scope=openid";

        HttpResponseData response = await SendToCimdClientOverARawConnectionAsync(
            app, stub, SyntheticEndpointFamily.ClientAuthenticatingName, DeviceAuthorizationFieldLines(stub, isBasicAttempted: true),
            body: body).ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(
            $"Basic realm=\"{stub.IssuerUri!.OriginalString}\"",
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual("{\"error\":\"invalid_client\",\"error_description\":\"Client authentication failed.\"}", response.Body);
        Assert.IsEmpty(registrationsSeen, "The endpoint's handler is not reached.");
        Assert.IsEmpty(seamRegistrations, "The client authentication seam is not reached.");
        Assert.AreEqual(isAnotherClientNamed ? 0 : 1, documentHost.TotalRequests, "A client_id naming another client fetches no document; the client's own is fetched once.");
    }


    /// <summary>
    /// Each fixed description the library answers a refusal with lies inside the character set
    /// of the <c>error_description</c> parameter: "Values for the "error_description" parameter
    /// MUST NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E."
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>).
    /// Guards the catalog values the library refuses a client's request with.
    /// </summary>
    /// <param name="description">A description the library answers a refusal with.</param>
    [TestMethod]
    [DynamicData(nameof(WellKnownDescriptions))]
    public void WellKnownOAuthErrorDescriptionsStayWithinTheRfc6749Charset(string description)
    {
        Assert.IsTrue(ErrorDescriptionCharset.IsConformant(description), description);
    }


    //Shared fixtures and helpers.

    /// <summary>The catalog descriptions, one case each.</summary>
    public static IEnumerable<object[]> WellKnownDescriptions { get; } =
    [
        [WellKnownOAuthErrorDescriptions.ClientAuthenticationFailed],
        [WellKnownOAuthErrorDescriptions.RequestNotProcessed],
        [WellKnownOAuthErrorDescriptions.RepeatedClientAuthenticationParameter],
        [WellKnownOAuthErrorDescriptions.MoreThanOneClientAuthenticationMethod],
        [WellKnownOAuthErrorDescriptions.MalformedAuthorizationField]
    ];


    /// <summary>
    /// The JSON body of an OAuth error response as the library writes it: the error code and its
    /// description, in that order, with no other member.
    /// </summary>
    /// <param name="error">The error code.</param>
    /// <param name="description">The error description.</param>
    private static string Bad(string error, string description) =>
        $"{{\"error\":\"{error}\",\"error_description\":\"{description}\"}}";


    /// <summary>
    /// Composes an application rule after the library's materialization on the <c>"default"</c>
    /// host: a materialized registration (<see cref="ClientRecord.IsClientMetadataMaterialized"/>) whose document
    /// carries no <c>client_name</c> is refused through <see cref="ClientIdMetadataMaterialization.Refuse"/>; every
    /// other outcome of the library's delegate stands. The rule tests that the registration is materialized because a
    /// protected resource request and a request that names no identifier arrive with the stored registration, which
    /// carries no <c>client_name</c> of a document, and their endpoints answer them with their own challenges.
    /// </summary>
    /// <param name="app">The fixture already wired with <see cref="TestHostShell.WireCimdMaterializationAsync"/>.</param>
    private static async Task ComposeClientNameRuleAsync(TestHostShell app)
    {
        HostedAuthorizationServer hosted = app.Host("default");
        await TestHostShell.AlterAsync(hosted.Server, candidate =>
        {
            MaterializeRegistrationDelegate library = candidate.MaterializeRegistrationAsync!;
            candidate.MaterializeRegistrationAsync = async (registration, context, cancellationToken) =>
            {
                RegistrationMaterialization materialization =
                    await library(registration, context, cancellationToken).ConfigureAwait(false);

                return materialization is { Failure: null, Registration: ClientRecord { IsClientMetadataMaterialized: true, ClientName: null } }
                    ? ClientIdMetadataMaterialization.Refuse(context)
                    : materialization;
            };
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// Posts <paramref name="fields"/> and the stub's <c>client_id</c> as a form to the named
    /// endpoint of the <c>"default"</c> host over its loopback HTTPS listener, and returns the
    /// status code and the response body.
    /// </summary>
    /// <param name="app">The fixture, wired and holding <paramref name="stub"/>.</param>
    /// <param name="stub">The CIMD client the request is made for.</param>
    /// <param name="endpointName">The endpoint the form is posted to.</param>
    /// <param name="fields">The form fields besides <c>client_id</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private static async Task<(int StatusCode, string Body)> PostToCimdClientAsync(
        TestHostShell app,
        ClientRecord stub,
        string endpointName,
        Dictionary<string, string> fields,
        CancellationToken cancellationToken)
    {
        (int statusCode, string body, _) = await PostToCimdClientWithHeadersAsync(
            app, stub, endpointName, fields, headers: null, cancellationToken).ConfigureAwait(false);

        return (statusCode, body);
    }


    /// <summary>
    /// Posts <paramref name="fields"/> and the stub's <c>client_id</c> as a form, with
    /// <paramref name="headers"/> when supplied, to the named endpoint of the <c>"default"</c>
    /// host over its loopback HTTPS listener, and returns the status code, the response body and
    /// the value of the <c>WWW-Authenticate</c> response header, or <see langword="null"/> when
    /// the response carries none.
    /// </summary>
    /// <param name="app">The fixture, wired and holding <paramref name="stub"/>.</param>
    /// <param name="stub">The CIMD client the request is made for.</param>
    /// <param name="endpointName">The endpoint the form is posted to.</param>
    /// <param name="fields">The form fields besides <c>client_id</c>.</param>
    /// <param name="headers">The request headers, or <see langword="null"/> for none.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="clientId">The <c>client_id</c> sent, or <see langword="null"/> for the stub's own.</param>
    private static async Task<(int StatusCode, string Body, string? Challenge)> PostToCimdClientWithHeadersAsync(
        TestHostShell app,
        ClientRecord stub,
        string endpointName,
        Dictionary<string, string> fields,
        OutgoingHeaders? headers,
        CancellationToken cancellationToken,
        string? clientId = null)
    {
        await app.StartHttpHostAsync(cancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = app.Host("default");
        Uri endpoint = TestHostShell.ComposeEndpointUri(hosted.HttpBaseAddress!, stub.TenantId.Value, endpointName);
        fields[OAuthRequestParameterNames.ClientId] = clientId ?? stub.ClientId;

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, endpoint, fields, headers, cancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        string? challenge = response.Headers.TryGetValues(WellKnownHttpHeaderNames.WwwAuthenticate, out IEnumerable<string>? values)
            ? string.Join(", ", values)
            : null;

        return ((int)response.StatusCode, body, challenge);
    }


    /// <summary>
    /// The form fields of a code redemption besides <c>client_id</c>: <c>grant_type</c>, a code no flow issued, the
    /// redirect URI and a PKCE verifier. The code is never looked up by the rows that send it, since the
    /// materialization refuses the request before the token endpoint runs.
    /// </summary>
    /// <returns>A fresh set of the fields, keyed by name.</returns>
    private static Dictionary<string, string> CodeRedemptionFields() => new()
    {
        [OAuthRequestParameterNames.GrantType] = "authorization_code",
        [OAuthRequestParameterNames.Code] = "adversarial-code-0123456789",
        [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
        [OAuthRequestParameterNames.CodeVerifier] = "adversarial-verifier-0123456789-0123456789-0123456789"
    };


    /// <summary>
    /// The form fields of a pushed authorization request besides <c>client_id</c>: <c>response_type</c>, the redirect
    /// URI and a PKCE challenge with its method.
    /// </summary>
    /// <returns>A fresh set of the fields, keyed by name.</returns>
    private static Dictionary<string, string> PushedRequestFields() => new()
    {
        [OAuthRequestParameterNames.ResponseType] = "code",
        [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
        [OAuthRequestParameterNames.CodeChallenge] = "adversarial-pkce-challenge-0123456789",
        [OAuthRequestParameterNames.CodeChallengeMethod] = "S256"
    };


    /// <summary>
    /// The query of an authorization request that completes a pushed request
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9126#section-4">RFC 9126 Section 4</see>):
    /// <paramref name="escapedClientId"/> as <c>client_id</c> and a <c>request_uri</c> no pushed request issued.
    /// </summary>
    /// <param name="escapedClientId">The <c>client_id</c> value, already escaped for a query.</param>
    /// <returns>The query without its <c>?</c>.</returns>
    private static string AuthorizationRequestQuery(string escapedClientId) =>
        $"client_id={escapedClientId}&request_uri={Uri.EscapeDataString("urn:ietf:params:oauth:request_uri:adversarial-0123456789")}";


    /// <summary>
    /// Sends <paramref name="method"/>, a POST unless named, with <paramref name="body"/>, empty unless given, to the
    /// named endpoint of <paramref name="stub"/>'s tenant on the <c>"default"</c> host's loopback listener, with
    /// <paramref name="query"/> as the target's query when given, starting the listener first, over a raw TLS
    /// connection through <see cref="RawHttpsRequest.SendAsync"/>, with <paramref name="fieldLines"/> each on its own
    /// field line, so a field sent on two lines or with an empty value reaches the wire as written. The name
    /// <see cref="SyntheticEndpointFamily.ClientAuthenticatingName"/> is sent to
    /// <see cref="SyntheticEndpointFamily.ComposeClientAuthenticatingPath"/> of the tenant.
    /// </summary>
    /// <param name="app">The fixture, wired and holding <paramref name="stub"/>.</param>
    /// <param name="stub">The client the request is made for.</param>
    /// <param name="endpointName">The endpoint the request is sent to.</param>
    /// <param name="fieldLines">The request's field lines, each sent as given.</param>
    /// <param name="method">The request method, or <see langword="null"/> for POST.</param>
    /// <param name="query">The target's query without its <c>?</c>, or <see langword="null"/> for none.</param>
    /// <param name="body">The body text, sent as UTF-8, or <see langword="null"/> for an empty body.</param>
    /// <returns>The status, every received field line and the body.</returns>
    private async Task<HttpResponseData> SendToCimdClientOverARawConnectionAsync(
        TestHostShell app,
        ClientRecord stub,
        string endpointName,
        IReadOnlyList<KeyValuePair<string, string>> fieldLines,
        string? method = null,
        string? query = null,
        string? body = null)
    {
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Uri baseAddress = app.Host("default").HttpBaseAddress!;
        Uri endpoint = string.Equals(endpointName, SyntheticEndpointFamily.ClientAuthenticatingName, StringComparison.Ordinal)
            ? new Uri(baseAddress, SyntheticEndpointFamily.ComposeClientAuthenticatingPath(stub.TenantId.Value))
            : TestHostShell.ComposeEndpointUri(baseAddress, stub.TenantId.Value, endpointName);
        if(query is not null)
        {
            endpoint = new UriBuilder(endpoint) { Query = query }.Uri;
        }

        ReadOnlyMemory<byte> bodyBytes = body is null ? ReadOnlyMemory<byte>.Empty : Encoding.UTF8.GetBytes(body);

        return await RawHttpsRequest.SendAsync(
            app, method ?? WellKnownHttpMethods.Post, endpoint, fieldLines, bodyBytes, TestContext.CancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Composes an application's device authorization endpoint into the <c>"default"</c> host's configuration after
    /// the library's builders, as an application composes its own endpoint builder: the client-authenticating builder of
    /// <see cref="SyntheticEndpointFamily"/> under <see cref="WellKnownCapabilityIdentifiers.OAuthDeviceAuthorization"/>,
    /// whose handler records the registration it sees in <paramref name="registrationsSeen"/>, with its address
    /// resolved, and a client authentication seam that records the registration it is handed in
    /// <paramref name="seamRegistrations"/> and accepts the credential.
    /// </summary>
    /// <param name="app">The fixture already wired with <see cref="TestHostShell.WireCimdMaterializationAsync"/>.</param>
    /// <param name="registrationsSeen">The registrations the endpoint's handler saw, in order.</param>
    /// <param name="seamRegistrations">The registrations the client authentication seam was handed, in order.</param>
    private async Task ComposeDeviceAuthorizationEndpointAsync(
        TestHostShell app,
        ConcurrentQueue<ClientRecord?> registrationsSeen,
        ConcurrentQueue<ClientRecord> seamRegistrations)
    {
        EndpointBuilderDelegate builder = SyntheticEndpointFamily.CreateClientAuthenticatingBuilder(
            WellKnownCapabilityIdentifiers.OAuthDeviceAuthorization, registrationsSeen);
        await app.Host("default").Server.RequestAlterationAsync(
            candidate =>
            {
                candidate.Configuration = SyntheticEndpointFamily.ComposeInto(candidate.Configuration, builder);
                AuthorizationServerIntegration integration = candidate.Family<AuthorizationServerIntegration>();
                SyntheticEndpointFamily.ResolveItsAddresses(integration);
                integration.ValidateClientCredentialsAsync = (_, registration, _, _) =>
                {
                    seamRegistrations.Enqueue(registration);

                    return ValueTask.FromResult(true);
                };
            },
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// The field lines of a device authorization request sent as a form: its content type, and, when
    /// <paramref name="isBasicAttempted"/>, <c>Authorization: Basic</c> naming <paramref name="stub"/>'s identifier
    /// with a secret.
    /// </summary>
    /// <param name="stub">The client the request is made for.</param>
    /// <param name="isBasicAttempted">Whether the request carries <c>Authorization: Basic</c>.</param>
    /// <returns>The field lines.</returns>
    private static IReadOnlyList<KeyValuePair<string, string>> DeviceAuthorizationFieldLines(ClientRecord stub, bool isBasicAttempted)
    {
        KeyValuePair<string, string> contentType = new(WellKnownHttpHeaderNames.ContentType, "application/x-www-form-urlencoded");
        string basic = $"Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Uri.EscapeDataString(stub.ClientId)}:adversarial-secret-0123456789"))}";

        return isBasicAttempted
            ? [contentType, new(WellKnownHttpHeaderNames.Authorization, basic)]
            : [contentType];
    }


    /// <summary>
    /// The span event name <see cref="ClientIdMetadataMaterialization"/> records for a wire
    /// <c>client_id</c> that does not match the registration.
    /// </summary>
    private static string ClientIdMismatchEventName { get; } = ClientIdMetadataMaterialization.ClientIdMismatchEventName;

    /// <summary>The span event name for a resolver-side policy denial (see <see cref="ClientIdMismatchEventName"/>).</summary>
    private static string PolicyDeniedEventName { get; } = ClientIdMetadataMaterialization.PolicyDeniedEventName;

    private static ClientIdMetadataDocumentResolverOptions RequirePrivateKeyJwtOptions { get; } = new()
    {
        AdditionalDocumentValidation = static (document, uri, context, ct) =>
            ValueTask.FromResult(document.TokenEndpointAuthMethod == ClientAuthenticationMethod.PrivateKeyJwt)
    };

    /// <summary>A hand-built JWKS carrying an EC key with a private <c>d</c> member (CIMD-023).</summary>
    private const string PrivateEcJwkSetJson =
        """{"keys":[{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","d":"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"}]}""";


    /// <summary>
    /// Registers a fresh CIMD stub for <c>documentUri</c> on a fresh <see cref="TestHostShell"/>
    /// already wired with <see cref="TestHostShell.WireCimdMaterializationAsync"/>, drives one PAR attempt, and
    /// returns the result — the one-shot shape most fetch-contract adversarials need.
    /// </summary>
    private static async Task<AuthCodeFlowEndpointResult> RunSingleAdversarialParAttemptAsync(
        MinimalHttpHost documentHost,
        string path,
        CancellationToken cancellationToken,
        ClientIdMetadataDocumentResolverOptions? options = null)
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        await app.WireCimdMaterializationAsync("default", documentHost.Certificate, options).ConfigureAwait(false);

        Uri documentUri = new(documentHost.BaseAddress, path);

        return await StartParAgainstStubAsync(app, documentUri, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Registers a CIMD stub for <paramref name="documentUri"/> on <paramref name="app"/> and drives one PAR attempt.</summary>
    private static async Task<AuthCodeFlowEndpointResult> StartParAgainstStubAsync(
        TestHostShell app, Uri documentUri, CancellationToken cancellationToken)
    {
        ClientRecord stub = await app.RegisterCimdStubClientAsync(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        return await DriveParForStubAsync(app, stub, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Drives one PAR attempt for an already-registered <paramref name="stub"/>.</summary>
    private static async Task<AuthCodeFlowEndpointResult> DriveParForStubAsync(
        TestHostShell app, ClientRecord stub, CancellationToken cancellationToken)
    {
        (OAuthClient client, ClientRegistration registration, _) = await app.CreateOAuthClientAndRegistrationAsync(
            stub, RedirectUri.OriginalString, PolicyProfile.Rfc6749WithPkce, cancellationToken).ConfigureAwait(false);

        return await client.AuthCode.StartParAsync(
            registration, RedirectUri, OAuthFormEncodedFields.Empty, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Runs <see cref="StartParAgainstStubAsync"/> twice against the same document path on
    /// <paramref name="app"/>, asserting the first attempt aborts and the second, independent
    /// attempt re-fetches (the document host's request count strictly increases) — CIMD-040's
    /// "never cache an invalid document" proven by the second attempt not being served from cache.
    /// </summary>
    private static async Task AssertAbortsAndNeverCachedAsync(
        TestHostShell app, StaticContentHost documentHost, string path, Uri documentUri, string message, CancellationToken cancellationToken)
    {
        AuthCodeFlowEndpointResult first = await StartParAgainstStubAsync(app, documentUri, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, first.Outcome, message);
        Assert.IsTrue(documentHost.WasRequested(path));
        int requestsAfterFirst = documentHost.TotalRequests;

        AuthCodeFlowEndpointResult second = await StartParAgainstStubAsync(app, documentUri, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, second.Outcome, message);
        Assert.IsGreaterThan(requestsAfterFirst, documentHost.TotalRequests,
            $"{message} A second attempt must re-fetch rather than serve a cached invalid result.");
    }


    /// <summary>
    /// Asserts that a pushed request's refusal <paramref name="result"/> carries the library's fixed answer to a
    /// failed client authentication, <c>invalid_client</c> with
    /// <see cref="WellKnownOAuthErrorDescriptions.ClientAuthenticationFailed"/>, the shape the token endpoint's rules
    /// give a pushed request (<see href="https://www.rfc-editor.org/rfc/rfc9126#section-2">RFC 9126 Section 2</see>),
    /// so no resolver <c>Defect</c> or <c>DenyReason</c> text ever reaches the wire.
    /// </summary>
    /// <param name="result">The pushed request's result.</param>
    private static void AssertNoInternalDetailLeaked(AuthCodeFlowEndpointResult result)
    {
        Assert.AreEqual(OAuthErrors.InvalidClient, result.ErrorCode);
        Assert.AreEqual("Client authentication failed.", result.ErrorDescription,
            "The wire response must carry only the fixed description, never internal diagnostics.");
    }


    /// <summary>
    /// Drives PAR (real-wire POST via the client wrapper) then the browser's authorize GET (a real
    /// wire GET with auto-redirect disabled and the test subject header standing in for an
    /// authenticated session). Returns the flow id and the raw redirect Location.
    /// </summary>
    private static async Task<(string FlowId, string Location)> DriveParAndAuthorizeAsync(
        TestHostShell app,
        HostedAuthorizationServer hosted,
        OAuthClient client,
        ClientRegistration registration,
        Dictionary<string, FlowState> clientFlowStore,
        string segment,
        CancellationToken cancellationToken)
    {
        AuthCodeFlowEndpointResult parResult = await client.AuthCode.StartParAsync(
            registration, RedirectUri, OAuthFormEncodedFields.Empty, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"PAR must redirect over the real wire. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");

        string flowId = clientFlowStore.Keys.Single();
        ParCompletedState parState = (ParCompletedState)clientFlowStore[flowId];

        Uri authorizeUrl = new(
            hosted.HttpBaseAddress!,
            $"{TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment)}" +
            $"?{OAuthRequestParameterNames.ClientId}={Uri.EscapeDataString(registration.ClientId.Value)}" +
            $"&{OAuthRequestParameterNames.RequestUri}={Uri.EscapeDataString(parState.Par.RequestUri.ToString())}");

        using SocketsHttpHandler noRedirectHandler = LoopbackTls.CreatePinnedHandler(app.ServerCertificate);
        noRedirectHandler.AllowAutoRedirect = false;
        using HttpClient browserClient = new(noRedirectHandler) { BaseAddress = hosted.HttpBaseAddress };
        using HttpRequestMessage authorizeRequest = new(HttpMethod.Get, authorizeUrl);
        authorizeRequest.Headers.Add(AuthorizationServerHttpApplication.TestSubjectHeaderName, SubjectId);

        using HttpResponseMessage authorizeResponse = await browserClient
            .SendAsync(authorizeRequest, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, (int)authorizeResponse.StatusCode,
            "The authorize endpoint must redirect.");

        return (flowId, authorizeResponse.Headers.Location!.ToString());
    }


    //Builds a conformant-shaped Client ID Metadata Document (§4). client_id is included unless the
    //caller wants to model CIMD-013's missing-property defect; every other member is included only
    //when supplied, so an omitted property stays genuinely absent from the wire JSON.
    private static string BuildDocumentJson(
        string clientId,
        IReadOnlyList<Uri>? redirectUris = null,
        string? tokenEndpointAuthMethod = null,
        bool includeClientSecret = false,
        string? jwksRawJson = null,
        string? jwksUriRaw = null,
        string? logoUri = null,
        string? clientName = null,
        string? softwareStatement = null)
    {
        List<string> members = [$"\"client_id\":\"{clientId}\""];

        if(redirectUris is { Count: > 0 })
        {
            string uris = string.Join(',', redirectUris.Select(static uri => $"\"{uri.OriginalString}\""));
            members.Add($"\"redirect_uris\":[{uris}]");
        }

        if(tokenEndpointAuthMethod is not null)
        {
            members.Add($"\"token_endpoint_auth_method\":\"{tokenEndpointAuthMethod}\"");
        }

        if(includeClientSecret)
        {
            members.Add("\"client_secret\":\"leaked-secret-value\"");
        }

        if(jwksRawJson is not null)
        {
            members.Add($"\"jwks\":{jwksRawJson}");
        }

        if(jwksUriRaw is not null)
        {
            members.Add($"\"jwks_uri\":\"{jwksUriRaw}\"");
        }

        if(logoUri is not null)
        {
            members.Add($"\"logo_uri\":\"{logoUri}\"");
        }

        if(clientName is not null)
        {
            members.Add($"\"client_name\":\"{clientName}\"");
        }

        if(softwareStatement is not null)
        {
            members.Add($"\"software_statement\":\"{softwareStatement}\"");
        }

        return "{" + string.Join(',', members) + "}";
    }


    //RFC 3986 §3.1: the scheme is case-insensitive for URI equivalence purposes, but CIMD-008/016
    //require literal ordinal comparison — this produces a client_id that URI-normalization would
    //consider the same origin as originalString but that ordinal comparison correctly rejects.
    private static string UppercaseScheme(string originalString) =>
        "HTTPS" + originalString[Uri.UriSchemeHttps.Length..];


    private static ActivityListener CreateListener(ConcurrentBag<Activity> captured) =>
        new()
        {
            ShouldListenTo = source =>
                string.Equals(source.Name, ServerActivitySource.SourceName, StringComparison.Ordinal),
            Sample = static (ref _) =>
                ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity => captured.Add(activity)
        };


    /// <summary>Thread-safe request counter a <see cref="MinimalHttpHandlerDelegate"/> closure increments.</summary>
    private sealed class RequestCounter
    {
        private int count;

        public int Count => Volatile.Read(ref count);

        public void Increment() => Interlocked.Increment(ref count);
    }


    /// <summary>
    /// A single-hop transport that counts every call and always answers with a bare 200 — used to
    /// prove a policy-denied resolve never dials the transport at all (<see cref="CallCount"/> stays
    /// 0); answering 200 rather than throwing means an accidental dial surfaces as a wrong
    /// resolution outcome rather than being swallowed by exception handling.
    /// </summary>
    private sealed class TransportCallSpy
    {
        private int callCount;

        public int CallCount => Volatile.Read(ref callCount);

        public OutboundTransportDelegate Delegate => (request, context, readResponse, cancellationToken) =>
        {
            _ = Interlocked.Increment(ref callCount);

            return ScriptedOutboundTransport.ReadAsync(readResponse, new OutboundResponse { StatusCode = 200 }, cancellationToken);
        };
    }
}
