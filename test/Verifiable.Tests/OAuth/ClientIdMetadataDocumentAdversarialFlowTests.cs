using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.WellKnown;
using Verifiable.Server;
using Verifiable.Server.Diagnostics;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Adversarial, SSRF, discrimination, display-seam, and logo-prefetch real-wire suite for CIMD
/// (slice E2, contract D12 second half): every scenario crosses a real
/// <see cref="MinimalHttpHost"/> or <see cref="StaticContentHost"/> TLS loopback socket, mirroring
/// <see cref="ClientIdMetadataDocumentCrossWireFlowTests"/>'s topology. Caching behavior lives in
/// the sibling <see cref="ClientIdMetadataDocumentCachingFlowTests"/>.
/// </summary>
/// <remarks>
/// Covers CIMD-02-clause-ledger rows 001-011 (wire), 008, 013-016, 019-023, 028, 030, 033-040,
/// 043-044, 051-061 per
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
    /// Wires the resolver's transport manually with <see cref="HttpClientHandler.AllowAutoRedirect"/>
    /// explicitly <see langword="false"/> — <see cref="TestHostShell.WireCimdMaterialization"/>'s
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

        using HttpClientHandler noAutoRedirectHandler = LoopbackTls.CreatePinnedHandler(documentHost.Certificate);
        noAutoRedirectHandler.AllowAutoRedirect = false;
        using HttpClient documentHttpClient = new(noAutoRedirectHandler);
        OutboundTransportDelegate transport = GuardedHttpClientTransport.BuildSingleHopTransport(documentHttpClient);
        ResolveClientMetadataDelegate resolve = ClientIdMetadataDocuments.BuildResolving(
            transport, new ClientIdMetadataDocumentResolverOptions(), app.Time);

        HostedAuthorizationServer host = app.Host("default");
        host.Server.OAuth().MaterializeRegistrationAsync = ClientIdMetadataMaterialization.Build();
        host.Server.OAuth().ResolveClientMetadataAsync = (clientMetadataUri, context, cancellationToken) =>
        {
            context.SetOutboundFetchPolicy(TestHostShell.LoopbackOutboundFetchPolicy);

            return resolve(clientMetadataUri, context, cancellationToken);
        };

        AuthCodeFlowEndpointResult result = await StartParAgainstStubAsync(
            app, new Uri(documentHost.BaseAddress, "/app"), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome,
            "CIMD-034: a redirect answer must abort the authorization request, never be followed.");
        Assert.AreEqual(0, redirectTargetCounter.Count,
            "CIMD-034: the redirect target must never be dialed — not even policy-evaluated.");
    }


    /// <summary>
    /// CIMD-059: a response larger than the configured maximum is treated as an error, even though
    /// the transport itself reported 200 — the resolver's post-read size check runs before the
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
        app.WireCimdMaterialization("default", documentHost.Certificate);

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
        app.WireCimdMaterialization("default", documentHost.Certificate);

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
        app.WireCimdMaterialization("default", documentHost.Certificate);

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
        ClientRecord stub = app.RegisterCimdStubClient(maliciousUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce);

        HostedAuthorizationServer host = app.Host("default");
        AuthorizationServerIntegration oauth = host.Server.OAuth();
        oauth.MaterializeRegistrationAsync = ClientIdMetadataMaterialization.Build();
        oauth.ResolveClientMetadataAsync = ClientIdMetadataDocuments.BuildResolving(
            spy.Delegate, new ClientIdMetadataDocumentResolverOptions(), app.Time);

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
                string.Equals(t.Key, ServerTagNames.TenantId, StringComparison.Ordinal)
                && string.Equals(t.Value, stub.TenantId.Value, StringComparison.Ordinal)))
            .ToArray();
        Assert.IsGreaterThan(0, handleActivities.Length, "At least one Handle activity for this tenant must be captured.");
        Assert.Contains(
            (Activity a) => a.Events.Any(e => string.Equals(e.Name, PolicyDeniedEventName, StringComparison.Ordinal)),
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
        productionHost.Server.OAuth().MaterializeRegistrationAsync = ClientIdMetadataMaterialization.Build();
        productionHost.Server.OAuth().ResolveClientMetadataAsync = ClientIdMetadataDocuments.BuildResolving(
            GuardedHttpClientTransport.BuildSingleHopTransport(productionHttpClient),
            new ClientIdMetadataDocumentResolverOptions(), productionApp.Time);

        AuthCodeFlowEndpointResult productionResult = await StartParAgainstStubAsync(
            productionApp, documentUri, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, productionResult.Outcome,
            "CIMD-056: production defaults must still deny a loopback target — the exception is never automatic.");

        //Explicit, scoped test-context relaxation against the SAME document host.
        await using TestHostShell relaxedApp = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        relaxedApp.WireCimdMaterialization("default", documentHost.Certificate);

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
        ResolveClientMetadataDelegate resolve = ClientIdMetadataDocuments.BuildResolving(
            transport, new ClientIdMetadataDocumentResolverOptions(), app.Time);

        OutboundFetchPolicy denyListPolicy = TestHostShell.LoopbackOutboundFetchPolicy with
        {
            HostDenyList = [documentUri.Host]
        };
        host.Server.OAuth().MaterializeRegistrationAsync = ClientIdMetadataMaterialization.Build();
        host.Server.OAuth().ResolveClientMetadataAsync = (clientMetadataUri, context, cancellationToken) =>
        {
            context.SetOutboundFetchPolicy(denyListPolicy);

            return resolve(clientMetadataUri, context, cancellationToken);
        };

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
        app.WireCimdMaterialization("default", documentHost.Certificate);

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
        app.WireCimdMaterialization("default", documentHost.Certificate);

        const string vanityClientId = "https://vanity.example.com/my-app";
        using VerifierKeyMaterial material = app.RegisterClient(
            vanityClientId, new Uri(vanityClientId), AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce);
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
        using VerifierKeyMaterial material = app.RegisterClient(
            "opaque-client-1", new Uri("https://opaque.example.com"), AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce);
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
        app.WireCimdMaterialization("default", documentHost.Certificate);

        AuthorizationRequestEvaluation? captured = null;
        app.Server.OAuth().EvaluateAuthorizationRequestAsync = (evaluation, registration, context, ct) =>
        {
            captured = evaluation;

            return ValueTask.FromResult(AuthorizationRequestDecision.Permit);
        };

        ClientRecord stub = app.RegisterCimdStubClient(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce);
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
        Assert.AreEqual(documentUri.Host, captured!.ClientIdHost,
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
        app.WireCimdMaterialization("default", documentHost.Certificate);

        ClientRecord? materialized = null;
        app.Server.OAuth().EvaluateAuthorizationRequestAsync = (evaluation, registration, context, ct) =>
        {
            materialized = registration;

            return ValueTask.FromResult(AuthorizationRequestDecision.Permit);
        };

        ClientRecord stub = app.RegisterCimdStubClient(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce);
        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> flowStore) =
            await app.CreateOAuthClientAndRegistrationAsync(
                stub, RedirectUri.OriginalString, PolicyProfile.Rfc6749WithPkce, TestContext.CancellationToken)
                .ConfigureAwait(false);
        HostedAuthorizationServer hosted = app.Host("default");

        await DriveParAndAuthorizeAsync(
            app, hosted, client, registration, flowStore, stub.TenantId.Value, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(materialized, "The evaluation seam must have been invoked.");
        Assert.AreEqual(softwareStatement, materialized!.SoftwareStatement,
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
        using VerifierKeyMaterial material = app.RegisterClient(
            clientId, new Uri(clientId), AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce);
        ClientRecord stub = material.Registration;

        AuthorizationRequestEvaluation? captured = null;
        app.Server.OAuth().EvaluateAuthorizationRequestAsync = (evaluation, registration, context, ct) =>
        {
            captured = evaluation;

            return ValueTask.FromResult(AuthorizationRequestDecision.Permit);
        };

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> flowStore) =
            await app.CreateOAuthClientAndRegistrationAsync(
                stub, RedirectUri.OriginalString, PolicyProfile.Rfc6749WithPkce, TestContext.CancellationToken)
                .ConfigureAwait(false);

        HostedAuthorizationServer hosted = app.Host("default");
        await DriveParAndAuthorizeAsync(
            app, hosted, client, registration, flowStore, stub.TenantId.Value, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(captured, "The evaluation seam must have been invoked.");
        Assert.AreEqual(new Uri(clientId).Host, captured!.ClientIdHost,
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
        ResolveClientMetadataDelegate resolve = ClientIdMetadataDocuments.BuildResolving(
            transport, new ClientIdMetadataDocumentResolverOptions { PrefetchLogo = true }, timeProvider);

        ExchangeContext context = new();
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
        ResolveClientMetadataDelegate resolve = ClientIdMetadataDocuments.BuildResolving(
            transport, new ClientIdMetadataDocumentResolverOptions { PrefetchLogo = true }, timeProvider);

        host.Server.OAuth().MaterializeRegistrationAsync = ClientIdMetadataMaterialization.Build();
        host.Server.OAuth().ResolveClientMetadataAsync = (clientMetadataUri, context, cancellationToken) =>
        {
            context.SetOutboundFetchPolicy(TestHostShell.LoopbackOutboundFetchPolicy);

            return resolve(clientMetadataUri, context, cancellationToken);
        };

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
        app.WireCimdMaterialization("default", documentHost.Certificate, RequirePrivateKeyJwtOptions);

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
        app.WireCimdMaterialization("default", documentHost.Certificate, RequirePrivateKeyJwtOptions);

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
        tolerantApp.WireCimdMaterialization("default", documentHost.Certificate);
        AuthCodeFlowEndpointResult tolerantResult = await StartParAgainstStubAsync(
            tolerantApp, documentUri, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, tolerantResult.Outcome,
            $"CIMD-006: a query component must be tolerated under default options. ErrorDescription={tolerantResult.ErrorDescription}");

        await using TestHostShell strictApp = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        strictApp.WireCimdMaterialization(
            "default", documentHost.Certificate, new ClientIdMetadataDocumentResolverOptions { TreatAdvisoriesAsErrors = true });
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
        tolerantApp.WireCimdMaterialization("default", documentHost.Certificate);
        AuthCodeFlowEndpointResult tolerantResult = await StartParAgainstStubAsync(
            tolerantApp, documentUri, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, tolerantResult.Outcome,
            $"CIMD-011: a root-path client_id must be tolerated under default options. ErrorDescription={tolerantResult.ErrorDescription}");

        await using TestHostShell strictApp = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        strictApp.WireCimdMaterialization(
            "default", documentHost.Certificate, new ClientIdMetadataDocumentResolverOptions { TreatAdvisoriesAsErrors = true });
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
    /// only the library's fixed, generic description.
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
        app.WireCimdMaterialization("default", documentHost.Certificate);
        ClientRecord stub = app.RegisterCimdStubClient(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce);

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
        Assert.AreEqual("The request could not be processed.", description,
            "The wire body must carry only the library's fixed generic description — never the mismatched " +
            "client_id, the registration's real client_id, or any other internal diagnostic detail.");
        Assert.DoesNotContain("attacker-supplied", body);
        Assert.DoesNotContain(documentUri.OriginalString, body);

        Activity[] handleActivities = captured
            .Where(a => string.Equals(a.OperationName, ServerActivityNames.Handle, StringComparison.Ordinal))
            .Where(a => a.Tags.Any(t =>
                string.Equals(t.Key, ServerTagNames.TenantId, StringComparison.Ordinal)
                && string.Equals(t.Value, stub.TenantId.Value, StringComparison.Ordinal)))
            .ToArray();
        Assert.IsGreaterThan(0, handleActivities.Length, "At least one Handle activity for this tenant must be captured.");
        Assert.Contains(
            (Activity a) => a.Events.Any(e => string.Equals(e.Name, ClientIdMismatchEventName, StringComparison.Ordinal)),
            handleActivities,
            "A client-id-mismatch span event must be recorded on the request's Handle activity.");
    }


    //Shared fixtures and helpers.

    /// <summary>
    /// The span event name <see cref="ClientIdMetadataMaterialization"/> records for a wire
    /// <c>client_id</c> that does not match the registration.
    /// </summary>
    private const string ClientIdMismatchEventName = ClientIdMetadataMaterialization.ClientIdMismatchEventName;

    /// <summary>The span event name for a resolver-side policy denial (see <see cref="ClientIdMismatchEventName"/>).</summary>
    private const string PolicyDeniedEventName = ClientIdMetadataMaterialization.PolicyDeniedEventName;

    private static readonly ClientIdMetadataDocumentResolverOptions RequirePrivateKeyJwtOptions = new()
    {
        AdditionalDocumentValidation = static (document, uri, context, ct) =>
            ValueTask.FromResult(document.TokenEndpointAuthMethod == ClientAuthenticationMethod.PrivateKeyJwt)
    };

    /// <summary>A hand-built JWKS carrying an EC key with a private <c>d</c> member (CIMD-023).</summary>
    private const string PrivateEcJwkSetJson =
        """{"keys":[{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","d":"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"}]}""";


    /// <summary>
    /// Registers a fresh CIMD stub for <paramref name="documentUri"/> on a fresh <see cref="TestHostShell"/>
    /// already wired with <see cref="TestHostShell.WireCimdMaterialization"/>, drives one PAR attempt, and
    /// returns the result — the one-shot shape most fetch-contract adversarials need.
    /// </summary>
    private static async Task<AuthCodeFlowEndpointResult> RunSingleAdversarialParAttemptAsync(
        MinimalHttpHost documentHost,
        string path,
        CancellationToken cancellationToken,
        ClientIdMetadataDocumentResolverOptions? options = null)
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        app.WireCimdMaterialization("default", documentHost.Certificate, options);

        Uri documentUri = new(documentHost.BaseAddress, path);

        return await StartParAgainstStubAsync(app, documentUri, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Registers a CIMD stub for <paramref name="documentUri"/> on <paramref name="app"/> and drives one PAR attempt.</summary>
    private static async Task<AuthCodeFlowEndpointResult> StartParAgainstStubAsync(
        TestHostShell app, Uri documentUri, CancellationToken cancellationToken)
    {
        ClientRecord stub = app.RegisterCimdStubClient(documentUri, AuthCodeCapabilities, PolicyProfile.Rfc6749WithPkce);

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
    /// Asserts <paramref name="result"/>'s <see cref="AuthCodeFlowEndpointResult.ErrorDescription"/>
    /// equals the library's fixed, generic materialization-failure description — proving no
    /// resolver <c>Defect</c> or <c>DenyReason</c> text ever reaches the wire.
    /// </summary>
    private static void AssertNoInternalDetailLeaked(AuthCodeFlowEndpointResult result)
    {
        Assert.AreEqual(OAuthErrors.InvalidRequest, result.ErrorCode);
        Assert.AreEqual("The request could not be processed.", result.ErrorDescription,
            "The wire response must carry only the fixed generic description, never internal diagnostics.");
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

        using HttpClientHandler noRedirectHandler = LoopbackTls.CreatePinnedHandler(app.ServerCertificate);
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
            Sample = static (ref ActivityCreationOptions<ActivityContext> _) =>
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

        public OutboundTransportDelegate Delegate => (request, context, cancellationToken) =>
        {
            Interlocked.Increment(ref callCount);

            return ValueTask.FromResult(new OutboundResponse { StatusCode = 200 });
        };
    }
}
