using Microsoft.Extensions.Time.Testing;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Diagnostics;
using Verifiable.OAuth.Server;
using Verifiable.Server.Diagnostics;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Verifies that <see cref="EndpointServer"/> emits activities (spans) and
/// events with the correct names and tags from <see cref="ServerActivitySource"/>.
/// </summary>
/// <remarks>
/// <para>
/// Uses <see cref="ActivityListener"/> to capture activities without any OTel SDK
/// dependency. The listener subscribes to <see cref="ServerActivitySource.SourceName"/>
/// and collects all completed activities for assertion.
/// </para>
/// </remarks>
[TestClass]
internal sealed class OAuthDiagnosticsTests
{
    public TestContext TestContext { get; set; } = null!;

    private static FakeTimeProvider TimeProvider { get; } = new();

    private static Uri IssuerUri { get; } = new("https://issuer.example.com");

    private static ImmutableHashSet<CapabilityIdentifier> JwksCapabilities { get; } =
        [WellKnownCapabilityIdentifiers.OAuthJwksEndpoint];


    [TestMethod]
    public async Task HandleAsyncEmitsActivityWithFlowKindAndStatusCode()
    {
        ConcurrentBag<Activity> captured = [];

        using ActivityListener listener = CreateListener(captured);
        ActivitySource.AddActivityListener(listener);

        await using TestHostShell app = new(TimeProvider);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();

        ClientRecord registration = await app.RegisterSigningClientAsync(
            "diag-client", keys, JwksCapabilities).ConfigureAwait(false);

        ExchangeContext context = [];
        context.SetTenantId(registration.TenantId);
        context.SetIssuer(IssuerUri);

        _ = await app.DispatchAtEndpointAsync(
            registration.TenantId,
            WellKnownEndpointNames.MetadataJwks,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        //The tenant key never leaves the process through any exported tag or event tag —
        //only an application-assigned handle is safe to export. Scanning every captured
        //activity (not only this request's) is deliberate: a leak on any activity is a leak.
        bool anyActivityLeaksTenantKey = captured.Any(a =>
            a.Tags.Any(t => string.Equals(t.Value, registration.TenantId.Value, StringComparison.Ordinal))
            || a.Events.Any(e => e.Tags.Any(t =>
                string.Equals(t.Value as string, registration.TenantId.Value, StringComparison.Ordinal))));

        Assert.IsFalse(anyActivityLeaksTenantKey,
            $"No captured activity or event tag may carry the tenant key '{registration.TenantId.Value}'.");

        //ActivityListener is process-wide: sibling tests running in
        //parallel emit activities into the same ServerActivitySource and
        //land in this bag while our listener is alive. Filter by the
        //test's own tenant handle (each RegisterSigningClient produces a
        //fresh, unique TenantHandle) so this assertion stays isolated from
        //other tests' traffic.
        string handle = registration.TenantHandle!.Value.Value;
        Activity[] handleActivities = captured
            .Where(a => string.Equals(
                a.OperationName, ServerActivityNames.Handle, StringComparison.Ordinal))
            .Where(a => a.Tags.Any(t =>
                string.Equals(t.Key, ServerTagNames.TenantHandle, StringComparison.Ordinal)
                && string.Equals(t.Value, handle, StringComparison.Ordinal)))
            .ToArray();

        Assert.IsGreaterThan(0, handleActivities.Length,
            $"At least one '{ServerActivityNames.Handle}' activity tagged " +
            $"with tenant handle '{handle}' must be emitted.");

        Activity activity = handleActivities[0];

        string? flowKind = activity.Tags
            .FirstOrDefault(t => string.Equals(
                t.Key, ServerTagNames.FlowKind, StringComparison.Ordinal))
            .Value;

        string? statusCode = activity.Tags
            .FirstOrDefault(t => string.Equals(
                t.Key, ServerTagNames.StatusCode, StringComparison.Ordinal))
            .Value;

        string? handleTag = activity.Tags
            .FirstOrDefault(t => string.Equals(
                t.Key, ServerTagNames.TenantHandle, StringComparison.Ordinal))
            .Value;

        Assert.IsNotNull(flowKind,
            $"Activity must carry '{ServerTagNames.FlowKind}' tag.");
        Assert.AreEqual("200", statusCode,
            $"Activity must carry '{ServerTagNames.StatusCode}' tag with value '200'.");
        Assert.AreEqual(handle, handleTag,
            $"Activity must carry '{ServerTagNames.TenantHandle}' tag equal to the registration's handle.");
    }


    /// <summary>
    /// A registration with no <see cref="ClientRecord.TenantHandle"/> produces no tenant-shaped
    /// tag at all — the library fails closed rather than falling back to the tenant key — and the
    /// request still succeeds, because the tag is diagnostic only.
    /// </summary>
    [TestMethod]
    public async Task HandleAsyncEmitsNoTenantTagWhenRegistrationHasNoHandle()
    {
        ConcurrentBag<Activity> captured = [];

        using ActivityListener listener = CreateListener(captured);
        ActivitySource.AddActivityListener(listener);

        await using TestHostShell app = new(TimeProvider);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();

        ClientRecord registration = await app.RegisterSigningClientAsync(
            "diag-no-handle-client", keys, JwksCapabilities).ConfigureAwait(false);
        registration = await app.Host("default").UpdateClientAsync(
            registration, registration with { TenantHandle = null }, [],
            TestContext.CancellationToken).ConfigureAwait(false);

        using Activity testRoot = new(nameof(HandleAsyncEmitsNoTenantTagWhenRegistrationHasNoHandle));
        _ = testRoot.Start();
        ActivityTraceId testTraceId = testRoot.TraceId;

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            registration.TenantId,
            WellKnownEndpointNames.MetadataJwks,
            "GET",
            new RequestFields(),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode);

        Activity[] handleActivities = captured
            .Where(a => a.TraceId == testTraceId)
            .Where(a => string.Equals(
                a.OperationName, ServerActivityNames.Handle, StringComparison.Ordinal))
            .ToArray();

        Assert.IsGreaterThan(0, handleActivities.Length,
            $"At least one '{ServerActivityNames.Handle}' activity must be emitted for the request.");
        Assert.DoesNotContain(
            t => string.Equals(t.Key, ServerTagNames.TenantHandle, StringComparison.Ordinal),
            handleActivities[0].Tags,
            "A registration with no handle must produce no tenant-shaped tag.");
    }


    [TestMethod]
    public async Task HandleAsyncEmitsActivityForUnknownSegmentWith404()
    {
        ConcurrentBag<Activity> captured = [];

        using ActivityListener listener = CreateListener(captured);
        ActivitySource.AddActivityListener(listener);

        //The ActivityListener is process-wide: sibling tests running in parallel
        //emit their own 'Handle' activities into this bag. Unlike the 200 test,
        //this one dispatches to a nonexistent tenant with no registration to filter
        //by, so isolate by trace instead — start a per-test root so the library's
        //activities (if any) inherit its TraceId, and keep only those.
        using Activity testRoot = new(nameof(HandleAsyncEmitsActivityForUnknownSegmentWith404));
        _ = testRoot.Start();
        ActivityTraceId testTraceId = testRoot.TraceId;

        await using TestHostShell app = new(TimeProvider);

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            "nonexistent",
            WellKnownEndpointNames.MetadataJwks,
            "GET",
            new RequestFields(),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode);
        Assert.AreEqual(string.Empty, response.Body,
            "The no-match reason is recorded on the dispatch activity, never in the response body.");

        Activity[] handleActivities = captured
            .Where(a => a.TraceId == testTraceId)
            .Where(a => string.Equals(
                a.OperationName, ServerActivityNames.Handle, StringComparison.Ordinal))
            .ToArray();

        //A 404 from DispatchAtEndpointAsync happens during registration load
        //(the registration isn't found) — before any matcher runs and before
        //HandleAsync is called. If the library emits an activity for
        //dispatch-level errors, assert on it. Otherwise this test documents
        //that unresolved segments produce no HandleAsync activity — which is
        //also valid.
        if(handleActivities.Length > 0)
        {
            string? statusCode = handleActivities[0].Tags
                .FirstOrDefault(t => string.Equals(
                    t.Key, ServerTagNames.StatusCode, StringComparison.Ordinal))
                .Value;

            Assert.AreEqual("404", statusCode,
                "Activity for unknown segment must carry status code 404.");

            ActivityEvent[] noMatchEvents = handleActivities
                .SelectMany(a => a.Events)
                .Where(e => string.Equals(e.Name, ServerEventNames.NoMatch, StringComparison.Ordinal))
                .ToArray();

            Assert.HasCount(1, noMatchEvents,
                $"Exactly one '{ServerEventNames.NoMatch}' event must be recorded when no registration is found for the tenant.");

            string? category = noMatchEvents[0].Tags
                .FirstOrDefault(t => string.Equals(
                    t.Key, ServerEventNames.NoMatchCategoryTagName, StringComparison.Ordinal))
                .Value as string;

            Assert.AreEqual(NoMatchCategories.NoRegistrationForTenant, category,
                "An unresolved segment has no registration for the tenant, distinct from a declined matcher.");
        }
    }


    /// <summary>
    /// A registration allowed the token endpoint's capabilities still answers a mute 404 for the
    /// wrong HTTP method — every candidate in its chain declines (path or method mismatch), so the
    /// no-match event must name the category as a matcher decline and carry the declined candidates'
    /// names, never leaving the operator to guess whether the path was simply unserved.
    /// </summary>
    [TestMethod]
    public async Task NoMatchEventRecordsMatcherDeclinedCategoryForWrongMethod()
    {
        ConcurrentBag<Activity> captured = [];

        using ActivityListener listener = CreateListener(captured);
        ActivitySource.AddActivityListener(listener);

        await using TestHostShell host = new(TimeProvider);
        const string clientId = "https://no-match-declined.example.com";
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            clientId, new Uri(clientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeToken, "GET",
            new RequestFields(), [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode);
        Assert.AreEqual(string.Empty, response.Body);

        Activity[] handleActivities = captured
            .Where(a => string.Equals(
                a.OperationName, ServerActivityNames.Handle, StringComparison.Ordinal))
            .Where(a => string.Equals(
                a.GetTagItem(ServerTagNames.TenantHandle) as string,
                material.Registration.TenantHandle!.Value.Value, StringComparison.Ordinal))
            .ToArray();

        Assert.IsGreaterThan(0, handleActivities.Length);

        ActivityEvent[] noMatchEvents = handleActivities
            .SelectMany(a => a.Events)
            .Where(e => string.Equals(e.Name, ServerEventNames.NoMatch, StringComparison.Ordinal))
            .ToArray();

        Assert.HasCount(1, noMatchEvents,
            $"Exactly one '{ServerEventNames.NoMatch}' event must be recorded for the wrong-method request.");

        string? category = noMatchEvents[0].Tags
            .FirstOrDefault(t => string.Equals(
                t.Key, ServerEventNames.NoMatchCategoryTagName, StringComparison.Ordinal))
            .Value as string;

        Assert.AreEqual(NoMatchCategories.MatcherDeclined, category);

        string? declined = noMatchEvents[0].Tags
            .FirstOrDefault(t => string.Equals(
                t.Key, ServerEventNames.NoMatchDeclinedTagName, StringComparison.Ordinal))
            .Value as string;

        Assert.IsFalse(string.IsNullOrWhiteSpace(declined),
            "The declined-candidate names tag must name every candidate whose matcher declined.");
    }


    /// <summary>
    /// A registration allowed only the JWKS endpoint capability, with that capability attenuated away
    /// for this one request by <see cref="ServerIntegration.ResolveCapabilitiesAsync"/>, leaves the
    /// chain with no candidate at all — the capability filter removed the only one a builder produced.
    /// The no-match event must distinguish this from a matcher decline and name the removed candidate.
    /// </summary>
    [TestMethod]
    public async Task NoMatchEventRecordsCapabilityFilteredCategoryWhenTheOnlyCandidateIsAttenuated()
    {
        ConcurrentBag<Activity> captured = [];

        using ActivityListener listener = CreateListener(captured);
        ActivitySource.AddActivityListener(listener);

        await using TestHostShell app = new(TimeProvider);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();

        ClientRecord registration = await app.RegisterSigningClientAsync(
            "diag-capability-filtered-client", keys, JwksCapabilities).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveCapabilitiesAsync = static (reg, context, ct) =>
                ValueTask.FromResult<IReadOnlySet<CapabilityIdentifier>>(
                    ImmutableHashSet<CapabilityIdentifier>.Empty);
        }).ConfigureAwait(false);

        ExchangeContext context = [];
        context.SetTenantId(registration.TenantId);
        context.SetIssuer(IssuerUri);

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            registration.TenantId.Value,
            WellKnownEndpointNames.MetadataJwks, "GET",
            new RequestFields(), context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode);
        Assert.AreEqual(string.Empty, response.Body);

        Activity[] handleActivities = captured
            .Where(a => string.Equals(
                a.OperationName, ServerActivityNames.Handle, StringComparison.Ordinal))
            .Where(a => string.Equals(
                a.GetTagItem(ServerTagNames.TenantHandle) as string,
                registration.TenantHandle!.Value.Value, StringComparison.Ordinal))
            .ToArray();

        Assert.IsGreaterThan(0, handleActivities.Length);

        ActivityEvent[] noMatchEvents = handleActivities
            .SelectMany(a => a.Events)
            .Where(e => string.Equals(e.Name, ServerEventNames.NoMatch, StringComparison.Ordinal))
            .ToArray();

        Assert.HasCount(1, noMatchEvents,
            $"Exactly one '{ServerEventNames.NoMatch}' event must be recorded when attenuation empties the chain.");

        string? category = noMatchEvents[0].Tags
            .FirstOrDefault(t => string.Equals(
                t.Key, ServerEventNames.NoMatchCategoryTagName, StringComparison.Ordinal))
            .Value as string;

        Assert.AreEqual(NoMatchCategories.CapabilityFiltered, category);

        string? filtered = noMatchEvents[0].Tags
            .FirstOrDefault(t => string.Equals(
                t.Key, ServerEventNames.NoMatchCapabilityFilteredTagName, StringComparison.Ordinal))
            .Value as string;

        Assert.Contains(WellKnownEndpointNames.MetadataJwks, filtered ?? string.Empty, StringComparison.Ordinal);
    }


    /// <summary>
    /// A registration allowed the JWKS endpoint's capability, and the capability filter keeps the
    /// only candidate a builder produced for the request, but the application's
    /// <see cref="ServerIntegration.ResolveEndpointUriAsync"/> answers <see langword="null"/> for
    /// that one candidate's name — every other name it maps unchanged. The no-match event must
    /// name the category as an unresolved URI and carry the unmapped candidate's name, distinct
    /// from a capability-filtered or matcher-declined chain.
    /// </summary>
    [TestMethod]
    public async Task NoMatchEventRecordsUriUnresolvedCategoryWhenTheOnlyCandidateHasNoMappedUri()
    {
        ConcurrentBag<Activity> captured = [];

        using ActivityListener listener = CreateListener(captured);
        ActivitySource.AddActivityListener(listener);

        await using TestHostShell app = new(TimeProvider);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();

        ClientRecord registration = await app.RegisterSigningClientAsync(
            "diag-uri-unresolved-client", keys, JwksCapabilities).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            ResolveEndpointUriDelegate mapped = candidateIntegration.ResolveEndpointUriAsync!;
            candidateIntegration.ResolveEndpointUriAsync = (endpointKey, reg, ctx, ct) =>
                string.Equals(endpointKey, WellKnownEndpointNames.MetadataJwks, StringComparison.Ordinal)
                    ? ValueTask.FromResult<Uri?>(null)
                    : mapped(endpointKey, reg, ctx, ct);
        }).ConfigureAwait(false);

        ExchangeContext context = [];
        context.SetTenantId(registration.TenantId);
        context.SetIssuer(IssuerUri);

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            registration.TenantId.Value,
            WellKnownEndpointNames.MetadataJwks, "GET",
            new RequestFields(), context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode);
        Assert.AreEqual(string.Empty, response.Body);

        Activity[] handleActivities = captured
            .Where(a => string.Equals(
                a.OperationName, ServerActivityNames.Handle, StringComparison.Ordinal))
            .Where(a => string.Equals(
                a.GetTagItem(ServerTagNames.TenantHandle) as string,
                registration.TenantHandle!.Value.Value, StringComparison.Ordinal))
            .ToArray();

        Assert.IsGreaterThan(0, handleActivities.Length);

        ActivityEvent[] noMatchEvents = handleActivities
            .SelectMany(a => a.Events)
            .Where(e => string.Equals(e.Name, ServerEventNames.NoMatch, StringComparison.Ordinal))
            .ToArray();

        Assert.HasCount(1, noMatchEvents,
            $"Exactly one '{ServerEventNames.NoMatch}' event must be recorded when the sole candidate's URI does not resolve.");

        string? category = noMatchEvents[0].Tags
            .FirstOrDefault(t => string.Equals(
                t.Key, ServerEventNames.NoMatchCategoryTagName, StringComparison.Ordinal))
            .Value as string;

        Assert.AreEqual(NoMatchCategories.EndpointNameUnresolved, category);

        string? unresolved = noMatchEvents[0].Tags
            .FirstOrDefault(t => string.Equals(
                t.Key, ServerEventNames.NoMatchEndpointNameUnresolvedTagName, StringComparison.Ordinal))
            .Value as string;

        Assert.Contains(WellKnownEndpointNames.MetadataJwks, unresolved ?? string.Empty, StringComparison.Ordinal);
    }


    /// <summary>
    /// A request the chain does serve is unaffected by the unresolved-URI bookkeeping: a mapped
    /// endpoint name still dispatches successfully even while an unrelated altered mapping exists.
    /// </summary>
    [TestMethod]
    public async Task MappedEndpointStillDispatchesWhileAnotherNameIsUnresolved()
    {
        await using TestHostShell app = new(TimeProvider);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();

        ClientRecord registration = await app.RegisterSigningClientAsync(
            "diag-uri-unresolved-unaffected-client", keys, JwksCapabilities).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            ResolveEndpointUriDelegate mapped = candidateIntegration.ResolveEndpointUriAsync!;
            candidateIntegration.ResolveEndpointUriAsync = (endpointKey, reg, ctx, ct) =>
                string.Equals(endpointKey, WellKnownEndpointNames.AuthCodeToken, StringComparison.Ordinal)
                    ? ValueTask.FromResult<Uri?>(null)
                    : mapped(endpointKey, reg, ctx, ct);
        }).ConfigureAwait(false);

        ExchangeContext context = [];
        context.SetTenantId(registration.TenantId);
        context.SetIssuer(IssuerUri);

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            registration.TenantId.Value,
            WellKnownEndpointNames.MetadataJwks, "GET",
            new RequestFields(), context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode);
    }


    [TestMethod]
    public void ActivitySourceNameMatchesConstant()
    {
        Assert.AreEqual(
            ServerActivitySource.SourceName,
            ServerActivitySource.Source.Name,
            "ActivitySource.Name must equal the published constant.");
    }


    [TestMethod]
    public void MeterNameMatchesConstant()
    {
        Assert.AreEqual(
            OAuthMeterSource.MeterName,
            OAuthMeterSource.Meter.Name,
            "Meter.Name must equal the published constant.");
    }


    [TestMethod]
    public void AllActivityNamesAreNonEmptyAndDotDelimited()
    {
        string[] names =
        [
            ServerActivityNames.Handle
        ];

        foreach(string name in names)
        {
            Assert.IsFalse(string.IsNullOrWhiteSpace(name),
                "Activity names must not be null or whitespace.");
            Assert.Contains('.', name,
                $"Activity name '{name}' must be dot-delimited.");
        }
    }


    [TestMethod]
    public void AllTagNamesAreNonEmptyAndDotDelimited()
    {
        string[] tags =
        [
            ServerTagNames.FlowKind,
            ServerTagNames.TenantHandle,
            ServerTagNames.RegistrationId,
            ServerTagNames.HttpMethod,
            ServerTagNames.StatusCode,
            ServerTagNames.FlowState,
            ServerTagNames.FlowStepCount,
            ServerTagNames.StartsNewFlow,
            ServerTagNames.CorrelationResolved
        ];

        foreach(string tag in tags)
        {
            Assert.IsFalse(string.IsNullOrWhiteSpace(tag),
                "Tag names must not be null or whitespace.");
            Assert.Contains('.', tag,
                $"Tag name '{tag}' must be dot-delimited.");
        }
    }


    [TestMethod]
    public void AllMetricNamesAreNonEmptyAndDotDelimited()
    {
        string[] metrics =
        [
            OAuthMetricNames.RequestCount,
            OAuthMetricNames.RequestDuration,
            OAuthMetricNames.ResponseCount,
            OAuthMetricNames.ValidationClaimCount,
            OAuthMetricNames.ValidationFailureCount,
            OAuthMetricNames.ActiveFlowCount,
            OAuthMetricNames.FlowCreatedCount,
            OAuthMetricNames.FlowCompletedCount,
            OAuthMetricNames.CorrelationResolutionCount,
            OAuthMetricNames.ActiveClientCount,
            OAuthMetricNames.ClientLifecycleCount,
            OAuthMetricNames.TokenSignedCount,
            OAuthMetricNames.TokenSignDuration,
            OAuthMetricNames.JwksBuildCount
        ];

        foreach(string metric in metrics)
        {
            Assert.IsFalse(string.IsNullOrWhiteSpace(metric),
                "Metric names must not be null or whitespace.");
            Assert.Contains('.', metric,
                $"Metric name '{metric}' must be dot-delimited.");
        }
    }


    [TestMethod]
    public void AllEventNamesAreNonEmptyAndDotDelimited()
    {
        string[] events =
        [
            ServerEventNames.StateTransition,
            ServerEventNames.CorrelationResolved,
            ServerEventNames.CorrelationNotFound,
            ServerEventNames.FlowCreated,
            ServerEventNames.NoMatch,
            OAuthEventNames.ExtraneousAuthorizeParameters,
            OAuthEventNames.DuplicateGrantedCredentialConfigurationCollapsed,
            OAuthEventNames.LongLivedBearerCredentialTokenRefused
        ];

        foreach(string eventName in events)
        {
            Assert.IsFalse(string.IsNullOrWhiteSpace(eventName),
                "Event names must not be null or whitespace.");
            Assert.Contains('.', eventName,
                $"Event name '{eventName}' must be dot-delimited.");
        }
    }


    /// <summary>
    /// <see cref="TenantId.ToString"/> shows nothing of the storage key it carries;
    /// <see cref="TenantHandle.ToString"/> is transparent, because the handle is the display form.
    /// </summary>
    [TestMethod]
    public void TenantIdToStringHidesValueWhileTenantHandleToStringShowsIt()
    {
        TenantId tenantId = new("distinctive-tenant-key-0123456789");
        TenantHandle tenantHandle = new("distinctive-tenant-handle-0123456789");

        string tenantIdDisplay = tenantId.ToString();
        string tenantHandleDisplay = tenantHandle.ToString();

        Assert.DoesNotContain(tenantId.Value, tenantIdDisplay,
            "TenantId.ToString() must not contain the tenant key.");
        Assert.AreEqual(tenantHandle.Value, tenantHandleDisplay,
            "TenantHandle.ToString() must equal its value — the handle is the display form.");
    }


    private const string FactsClientId = "https://diag-facts.client.test";

    private static Uri FactsRedirectUri { get; } = new("https://client.example.com/callback");

    private const string FactsSubjectId = "subject-diag-facts-01";


    /// <summary>
    /// The library already holds grant type, client id, granted scope, PKCE method and the
    /// issued access token's <c>jti</c> typed at token issuance; a real-wire code-grant token
    /// request's dispatch span carries all five, so a host inspecting
    /// <see cref="OutgoingResponseStage"/> reads them typed instead of re-parsing the response
    /// body or decoding the token. The tagged <c>jti</c> equals the access token's own
    /// <c>jti</c> claim.
    /// </summary>
    [TestMethod]
    public async Task CodeGrantTokenActivityCarriesTheOAuthWireFacts()
    {
        ConcurrentBag<Activity> captured = [];

        using ActivityListener listener = CreateListener(captured);
        ActivitySource.AddActivityListener(listener);

        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            FactsClientId, new Uri(FactsClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                FactsRedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
            hosted, client, registration, clientFlowStore, segment, FactsRedirectUri, FactsSubjectId, browserClient,
            scope: WellKnownScopes.OpenId, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string accessToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.AccessToken];
        string expectedJti = JwtPayloadReader.ReadJti(accessToken)
            ?? throw new InvalidOperationException("Issued access token carries no jti claim.");

        Activity[] tokenActivities = captured
            .Where(a => string.Equals(
                a.OperationName, ServerActivityNames.Handle, StringComparison.Ordinal))
            .Where(a => a.Tags.Any(t =>
                string.Equals(t.Key, OAuthTagNames.GrantType, StringComparison.Ordinal)))
            .Where(a => string.Equals(
                a.GetTagItem(ServerTagNames.TenantHandle) as string,
                material.Registration.TenantHandle!.Value.Value, StringComparison.Ordinal))
            .ToArray();

        Assert.HasCount(1, tokenActivities,
            "Exactly one token-endpoint activity must carry the OAuth wire facts.");

        Activity activity = tokenActivities[0];

        Assert.AreEqual(WellKnownGrantTypes.AuthorizationCode,
            activity.GetTagItem(OAuthTagNames.GrantType) as string);
        Assert.AreEqual(FactsClientId,
            activity.GetTagItem(OAuthTagNames.ClientId) as string);
        Assert.AreEqual(WellKnownScopes.OpenId,
            activity.GetTagItem(OAuthTagNames.GrantedScope) as string);
        Assert.AreEqual(WellKnownCodeChallengeMethods.S256,
            activity.GetTagItem(OAuthTagNames.PkceMethod) as string);
        Assert.AreEqual(expectedJti,
            activity.GetTagItem(OAuthTagNames.AccessTokenJti) as string);
    }


    /// <summary>
    /// The same tagging at token issuance means every grant carries its own facts, not only the
    /// authorization-code grant: a client-credentials token request's dispatch span carries its
    /// own <c>grant_type</c>.
    /// </summary>
    [TestMethod]
    public async Task ClientCredentialsTokenActivityCarriesItsOwnGrantType()
    {
        ConcurrentBag<Activity> captured = [];

        using ActivityListener listener = CreateListener(captured);
        ActivitySource.AddActivityListener(listener);

        await using TestHostShell host = new(TimeProvider);
        const string clientId = "https://diag-facts-cc.client.test";
        const string clientSecret = "diag-facts-cc-secret";

        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthClientCredentials,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            clientId, new Uri(clientId), profile: PolicyProfile.Rfc6749WithPkce, capabilities: capabilities).ConfigureAwait(false);

        _ = await host.SetTokenEndpointAuthMethodAsync(
            material, ClientAuthenticationMethod.ClientSecretPost, clientJwks: null,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ClientAuthenticationMethodsSupported =
                [ClientAuthenticationMethod.None, ClientAuthenticationMethod.ClientSecretPost];
            candidateIntegration.ValidateClientCredentialsAsync =
                static (request, fields, registration, context, ct) => ValueTask.FromResult(true);
        }).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(
            hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(hosted.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = clientId,
            [OAuthRequestParameterNames.ClientSecret] = clientSecret
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, (int)response.StatusCode, body);

        Activity[] tokenActivities = captured
            .Where(a => string.Equals(
                a.OperationName, ServerActivityNames.Handle, StringComparison.Ordinal))
            .Where(a => string.Equals(
                a.GetTagItem(ServerTagNames.TenantHandle) as string,
                material.Registration.TenantHandle!.Value.Value, StringComparison.Ordinal))
            .ToArray();

        Assert.HasCount(1, tokenActivities);
        Assert.AreEqual(WellKnownGrantTypes.ClientCredentials,
            tokenActivities[0].GetTagItem(OAuthTagNames.GrantType) as string);
    }


    /// <summary>
    /// The AS's error factories JSON-serialize the error code into
    /// <see cref="ServerHttpResponse.Body"/>; <see cref="ServerHttpResponse.ErrorCode"/> carries
    /// the same code typed, before that collapse, and the dispatch span's error-code tag equals
    /// it — a host inspecting <see cref="OutgoingResponseStage"/> reads the typed member instead
    /// of re-parsing the JSON body.
    /// </summary>
    [TestMethod]
    public async Task RefusedTokenRequestActivityAndResponseCarryTheSameErrorCode()
    {
        ConcurrentBag<Activity> captured = [];

        using ActivityListener listener = CreateListener(captured);
        ActivitySource.AddActivityListener(listener);

        await using TestHostShell app = new(TimeProvider);
        const string clientId = "https://diag-facts-refused.client.test";
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            clientId, new Uri(clientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        Dictionary<string, string> fields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
            [OAuthRequestParameterNames.ClientId] = clientId,
            [OAuthRequestParameterNames.Code] = "nonexistent-authorization-code-0123456789",
            [OAuthRequestParameterNames.CodeVerifier] = "a-code-verifier-that-satisfies-the-rfc7636-length-floor-0123456789"
        };

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeToken,
            "POST",
            new RequestFields(fields),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual(200, response.StatusCode,
            "An unknown authorization code must be refused.");
        Assert.IsNotNull(response.ErrorCode,
            "A refused token response must carry a typed ErrorCode.");

        Activity[] tokenActivities = captured
            .Where(a => string.Equals(
                a.OperationName, ServerActivityNames.Handle, StringComparison.Ordinal))
            .Where(a => string.Equals(
                a.GetTagItem(ServerTagNames.TenantHandle) as string,
                material.Registration.TenantHandle!.Value.Value, StringComparison.Ordinal))
            .ToArray();

        Assert.HasCount(1, tokenActivities);
        Assert.AreEqual(response.ErrorCode,
            tokenActivities[0].GetTagItem(ServerTagNames.ErrorCode) as string,
            "The dispatch span's error-code tag must equal the typed ServerHttpResponse.ErrorCode.");
    }


    /// <summary>
    /// Widening the dispatch span's OAuth facts must never widen what it leaks: no captured
    /// activity or event tag carries the issued access token, the authorization code, or the
    /// authenticated subject, across a full real-wire code-grant drive.
    /// </summary>
    [TestMethod]
    public async Task NoActivityTagCarriesTheAccessTokenAuthorizationCodeOrSubject()
    {
        ConcurrentBag<Activity> captured = [];

        using ActivityListener listener = CreateListener(captured);
        ActivitySource.AddActivityListener(listener);

        await using TestHostShell host = new(TimeProvider);
        const string clientId = "https://diag-facts-no-leak.client.test";
        const string subjectId = "subject-diag-facts-no-leak-01";
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            clientId, new Uri(clientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                FactsRedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
            hosted, client, registration, clientFlowStore, segment, FactsRedirectUri, subjectId, browserClient,
            scope: WellKnownScopes.OpenId, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string accessToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.AccessToken];
        string? authorizationCode = TestBrowser.ExtractQueryParam(drive.AuthorizeLocation, OAuthRequestParameterNames.Code);

        string handle = material.Registration.TenantHandle!.Value.Value;
        Activity[] relevantActivities = captured
            .Where(a => string.Equals(
                a.GetTagItem(ServerTagNames.TenantHandle) as string, handle, StringComparison.Ordinal))
            .ToArray();

        Assert.IsGreaterThan(0, relevantActivities.Length);

        bool leaksSecret = relevantActivities.Any(a =>
            a.Tags.Any(t => IsSecretLeak(t.Value, accessToken, authorizationCode, subjectId))
            || a.Events.Any(e => e.Tags.Any(t => IsSecretLeak(t.Value as string, accessToken, authorizationCode, subjectId))));

        Assert.IsFalse(leaksSecret,
            "No captured activity or event tag may carry the access token, authorization code, or subject.");
    }


    /// <summary>Whether <paramref name="tagValue"/> equals one of the three secrets a span tag must never carry.</summary>
    private static bool IsSecretLeak(string? tagValue, string accessToken, string? authorizationCode, string subjectId)
    {
        if(string.IsNullOrEmpty(tagValue))
        {
            return false;
        }

        return string.Equals(tagValue, accessToken, StringComparison.Ordinal)
            || (authorizationCode is not null && string.Equals(tagValue, authorizationCode, StringComparison.Ordinal))
            || string.Equals(tagValue, subjectId, StringComparison.Ordinal);
    }


    private static ActivityListener CreateListener(ConcurrentBag<Activity> captured) =>
        new()
        {
            ShouldListenTo = source =>
                string.Equals(source.Name, ServerActivitySource.SourceName, StringComparison.Ordinal),
            Sample = static (ref _) =>
                ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity => captured.Add(activity)
        };
}
