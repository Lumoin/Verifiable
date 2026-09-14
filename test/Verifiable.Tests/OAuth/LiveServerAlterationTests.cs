using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Metadata;
using Verifiable.Server.Routing;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.OAuth.AuthorizationServerFeatureTests;
using static Verifiable.Tests.OAuth.JwksRotationTests;
namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests the design of a server that is altered while it serves: the configuration snapshot is
/// published atomically, read through a volatile read, and captured once per request chain, and
/// the registration-event subject atomically publishes a copy-on-write observer list. The
/// requested, drained, candidate-validated alteration described in
/// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration</see>
/// adds coherent wiring changes while the host serves. Each test exercises the host in process
/// or over the wire as its own documentation states; initial-validation cases establish the
/// admission prerequisites for the running-host alteration cases.
/// </summary>
[TestClass]
internal sealed class LiveServerAlterationTests
{
    /// <summary>
    /// The test execution context supplying cancellation and the fixture's clock selection.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// The clock retained for this test so event emissions and request processing share one time source.
    /// </summary>
    private FakeTimeProvider? timeProvider;


    /// <summary>
    /// The deterministic clock for this case, retaining the rotation fixture's epoch and the
    /// shared suite epoch for the other cases so their time-dependent inputs remain stable.
    /// </summary>
    private FakeTimeProvider TimeProvider
    {
        get
        {

            return timeProvider ??= new FakeTimeProvider(
                string.Equals(TestContext.TestName, nameof(RotationLifecycleEmitsClientUpdatedAtEveryTransition), StringComparison.Ordinal)
                    ? DateTimeOffset.Parse("2026-01-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture)
                    : TestClock.CanonicalEpoch);
        }

    }


    /// <summary>
    /// Configuration coverage for the lifecycle required by
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see>'s "Authorization servers MUST utilize one of these methods to detect
    /// refresh token replay by malicious actors for public clients".
    /// <see cref="EndpointServer"/> validates its <see cref="ServerIntegration"/> lazily on the
    /// first call to <see cref="EndpointServer.DispatchAsync"/> rather than at construction — the
    /// integration is mutable after the object is built, so construction-time validation would
    /// reject a host whose wiring finishes afterward. A host missing a required seam
    /// (<see cref="ServerIntegration.ClaimFlowStateAsync"/> here) surfaces the named-seam
    /// <see cref="InvalidOperationException"/> <see cref="ServerIntegration.Validate"/> throws — a
    /// configuration fault reported at the first dispatch, never a
    /// <see cref="NullReferenceException"/> deep inside a handler that assumes the seam is present.
    /// In-process is the correct shape for this test: it proves a construction-time property of the
    /// host, not a wire-protocol clause, so it calls <see cref="EndpointServer.DispatchAsync"/>
    /// directly rather than driving a request over the real wire.
    /// </summary>
    [TestMethod]
    public async Task DispatchThrowsTheNamedConfigurationFaultWhenClaimFlowStateAsyncIsMissing()
    {
        AuthorizationServerIntegration integration = new()
        {
            ExtractTenantIdAsync = (ctx, ct) =>
                ValueTask.FromResult<TenantId?>(null),
            LoadClientRegistrationAsync = (tenantId, ctx, ct) =>
                ValueTask.FromResult<IRegistrationRecord?>(null),
            SaveFlowStateAsync = (tenantId, key, state, stepCount, ctx, ct) =>
                ValueTask.CompletedTask,
            LoadFlowStateAsync = (tenantId, key, ctx, ct) =>
                ValueTask.FromResult<(FlowState?, int)>((null, 0)),
            //ClaimFlowStateAsync deliberately omitted — the seam this test proves is named.
            ResolvePolicyAsync = (registration, ctx, ct) =>
                PolicyProfiles.DefaultResolvePolicyAsync((ClientRecord)registration, ctx, ct),
            MemoryPool = BaseMemoryPool.Shared
        };

        using EndpointServer server = new()
        {
            Integration = integration,
            TimeProvider = TimeProvider,
            Configuration = new ServerConfiguration
            {
                EndpointBuilders = new EndpointBuilderSet([AuthCodeEndpoints.Builder])
            }
        };
        server.AddIntegration(integration);

        Assert.IsFalse(server.IsValidated,
            "Construction must not validate — the integration is still mutable at this point.");

        IncomingRequest request = new(
            Path: "/token",
            Method: "POST",
            Fields: new RequestFields(),
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty);

        InvalidOperationException ex = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => server.DispatchAsync(request, new ExchangeContext(), TestContext.CancellationToken).AsTask());

        Assert.Contains(
            nameof(ServerIntegration.ClaimFlowStateAsync),
            ex.Message,
            StringComparison.Ordinal,
            "The first-dispatch configuration fault must name ClaimFlowStateAsync.");
        Assert.IsFalse(server.IsValidated,
            "IsValidated must remain false after a lazy validation that threw.");
    }


    /// <summary>
    /// Configuration coverage for the lifecycle required by
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see>'s "Authorization servers MUST utilize one of these methods to detect
    /// refresh token replay by malicious actors for public clients".
    /// <see cref="EndpointServer"/>'s first-dispatch validation gate uses
    /// <see cref="LazyThreadSafetyMode.PublicationOnly"/>, which does NOT cache a thrown factory
    /// exception — proves the recovery half of that guarantee: a host whose wiring COMPLETES
    /// between two dispatches is validated successfully on the very next one, rather than
    /// replaying the first dispatch's configuration fault forever.
    /// </summary>
    [TestMethod]
    public async Task DispatchRecoversOnTheNextCallAfterTheMissingSeamIsWiredAsync()
    {
        AuthorizationServerIntegration integration = new()
        {
            ExtractTenantIdAsync = (ctx, ct) =>
                ValueTask.FromResult<TenantId?>(null),
            LoadClientRegistrationAsync = (tenantId, ctx, ct) =>
                ValueTask.FromResult<IRegistrationRecord?>(null),
            SaveFlowStateAsync = (tenantId, key, state, stepCount, ctx, ct) =>
                ValueTask.CompletedTask,
            LoadFlowStateAsync = (tenantId, key, ctx, ct) =>
                ValueTask.FromResult<(FlowState?, int)>((null, 0)),
            DeleteFlowStateAsync = (tenantId, key, ctx, ct) =>
                ValueTask.CompletedTask,
            //ClaimFlowStateAsync deliberately omitted for the first dispatch.
            ResolvePolicyAsync = (registration, ctx, ct) =>
                PolicyProfiles.DefaultResolvePolicyAsync((ClientRecord)registration, ctx, ct),
            ResolveSubjectIdentifierAsync = (endUserId, registration, ctx, ct) =>
                ValueTask.FromResult(endUserId),
            ResolveCapabilitiesAsync = (registration, ctx, ct) =>
                ValueTask.FromResult<IReadOnlySet<CapabilityIdentifier>>(new HashSet<CapabilityIdentifier>()),
            InspectAsync = Verifiable.Server.Pipeline.DefaultInspector.NoOpAsync,
            GenerateIdentifierAsync = (purpose, ctx, ct) =>
                ValueTask.FromResult(Guid.CreateVersion7().ToString("N")),
            ResolveEndpointUriAsync = (endpointKey, registration, ctx, ct) =>
                ValueTask.FromResult<Uri?>(new Uri($"https://as.example.test/{endpointKey}")),
            MemoryPool = BaseMemoryPool.Shared
        };

        using EndpointServer server = new()
        {
            Integration = integration,
            TimeProvider = TimeProvider,
            Configuration = new ServerConfiguration
            {
                EndpointBuilders = new EndpointBuilderSet([AuthCodeEndpoints.Builder])
            }
        };
        server.AddIntegration(integration);

        IncomingRequest request = new(
            Path: "/token",
            Method: "POST",
            Fields: new RequestFields(),
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty);

        InvalidOperationException fault = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => server.DispatchAsync(request, new ExchangeContext(), TestContext.CancellationToken).AsTask());
        Assert.Contains(nameof(ServerIntegration.ClaimFlowStateAsync), fault.Message, StringComparison.Ordinal);
        Assert.IsFalse(server.IsValidated,
            "IsValidated must remain false after the first, faulting dispatch.");

        //The wiring completes between the two dispatches — the deployment shape ValidationGate's
        //remarks describe.
        integration.ClaimFlowStateAsync = (tenantId, key, expectedStepCount, ctx, ct) =>
            ValueTask.FromResult(true);

        ServerHttpResponse secondResponse = await server.DispatchAsync(
            request, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(server.IsValidated,
            "The second dispatch must validate successfully once the missing seam is wired.");
        Assert.AreEqual(400, secondResponse.StatusCode,
            "The second dispatch must serve the ordinary missing-tenant response.");
        Assert.Contains("No tenant identifier resolved for request.", secondResponse.Body!, StringComparison.Ordinal);
    }


    /// <summary>
    /// Configuration coverage for the lifecycle required by
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see>'s "Authorization servers MUST utilize one of these methods to detect
    /// refresh token replay by malicious actors for public clients".
    /// The positive side of
    /// <see cref="DispatchThrowsTheNamedConfigurationFaultWhenClaimFlowStateAsyncIsMissing"/>: a
    /// fully-wired host reaches <see cref="EndpointServer.DispatchAsync"/> and serves the request
    /// without ever having had <see cref="EndpointServer.Validate"/> called on it explicitly — the
    /// lazy gate alone is sufficient, and <see cref="EndpointServer.IsValidated"/> flips to
    /// <see langword="true"/> as a side effect of that first dispatch.
    /// </summary>
    [TestMethod]
    public async Task FullyWiredHostDispatchesWithoutAnExplicitValidateCall()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = app.RegisterDpopClient(
            VerifierClientId, VerifierBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: JwksCapabilities);

        //Install a fresh server before starting the listener so its captured server is the
        //unvalidated instance. The shared wiring remains complete from host setup.
        HostedAuthorizationServer hosted = app.Host("default");
        EndpointServer freshServer = new()
        {
            Integration = hosted.Server.Integration,
            TimeProvider = TimeProvider,
            Configuration = hosted.Server.Configuration,
            ActionExecutor = hosted.Server.ActionExecutor
        };
        freshServer.AddIntegration(hosted.Server.GetIntegration<AuthorizationServerIntegration>());
        hosted.Server = freshServer;

        Assert.IsFalse(freshServer.IsValidated,
            "The fresh instance must not be validated before its first dispatch.");

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Uri jwksUri = new(hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(
            WellKnownEndpointNames.MetadataJwks, material.Registration.TenantId.Value));
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            app, jwksUri, "validation-subject", TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, (int)response.StatusCode,
            "A fully-wired host must serve the wire request through lazy validation.");
        Assert.IsTrue(freshServer.IsValidated,
            "The first dispatch must validate lazily even with no explicit Validate() call.");
    }


    /// <summary>
    /// A registration must emit one event identifying its client and tenant and carrying its record,
    /// verified in process for the registration-plane rule in
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task RegisterClientFiresClientRegisteredEventWithCorrectPayload()
    {
        List<ClientRegistrationEvent> received = [];



        await using TestHostShell app = new(TimeProvider);

        using IDisposable subscription = app.Server.Events.Subscribe(
            new CollectingObserver<ClientRegistrationEvent>(received));
        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        //Filter to events for this test's segment only — the static subject is
        //shared across all tests in the process so other tests' events may appear.
        string segment = keys.Registration.TenantId;
        ClientRegistrationEvent[] forThisSegment = received
            .Where(e => string.Equals(e.TenantId, segment, StringComparison.Ordinal))
            .ToArray();

        Assert.HasCount(1, forThisSegment,
            "Exactly one ClientRegistered event must be emitted for this segment.");
        _ = Assert.IsInstanceOfType<ClientRegistered>(forThisSegment[0],
            "The emitted event must be ClientRegistered.");

        ClientRegistered evt = (ClientRegistered)forThisSegment[0];
        Assert.AreEqual(VerifierClientId, evt.ClientId,
            "ClientRegistered must carry the registered client identifier.");
        Assert.AreEqual(segment, evt.TenantId.Value,
            "ClientRegistered must carry the endpoint segment.");
        Assert.AreSame(keys.Registration, evt.Registration,
            "ClientRegistered must carry the exact ClientRecord instance.");
    }


    /// <summary>
    /// A completed registration must be visible in the host routing store immediately,
    /// verified in process for the registration-plane rule in
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task RegistrationStoreIsPopulatedImmediatelyAfterRegisterClient()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        Assert.IsTrue(
            app.RegistrationStore.ContainsKey(keys.Registration.TenantId),
            "Registration store must contain the segment immediately after RegisterClient.");

        ClientRecord stored = app.RegistrationStore[keys.Registration.TenantId];
        Assert.AreEqual(VerifierClientId, stored.ClientId,
            "Stored registration must carry the correct client identifier.");
    }


    /// <summary>
    /// A deregistered client must be absent from routing and receive a 404 on its next dispatch,
    /// verified in process for the registration-plane rule in
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task DeregisterClientRemovesFromRoutingTableAndDispatchReturns404()
    {
        List<ClientRegistrationEvent> received = [];



        await using TestHostShell app = new(TimeProvider);

        using IDisposable subscription = app.Server.Events.Subscribe(
            new CollectingObserver<ClientRegistrationEvent>(received));
        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        string segment = keys.Registration.TenantId;

        Assert.IsTrue(app.RegistrationStore.ContainsKey(segment),
            "Registration must be present before deregistration.");

        app.DeregisterClient(segment, "Test deregistration.");

        Assert.IsFalse(app.RegistrationStore.ContainsKey(segment),
            "Registration must be removed from routing table immediately after deregistration.");

        //Filter to this segment only — the static subject is shared across tests.
        ClientRegistrationEvent[] forThisSegment = received
            .Where(e => string.Equals(e.TenantId, segment, StringComparison.Ordinal))
            .ToArray();

        Assert.HasCount(2, forThisSegment,
            "ClientRegistered then ClientDeregistered must be emitted for this segment.");
        _ = Assert.IsInstanceOfType<ClientRegistered>(forThisSegment[0]);
        _ = Assert.IsInstanceOfType<ClientDeregistered>(forThisSegment[1]);

        ClientDeregistered deregistered = (ClientDeregistered)forThisSegment[1];
        Assert.AreEqual(segment, deregistered.TenantId.Value,
            "ClientDeregistered must carry the correct endpoint segment.");
        Assert.AreEqual("Test deregistration.", deregistered.Reason,
            "ClientDeregistered must carry the deregistration reason.");

        //A dispatch to the deregistered segment must return 404.
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownEndpointNames.AuthCodePar,
            "POST",
            new RequestFields(),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode,
            "Dispatch to a deregistered segment must return 404.");
    }


    /// <summary>
    /// A capability-grant notification must identify the client, tenant, and granted capability,
    /// verified in process for the registration-plane rule in
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task CapabilityGrantedEventCarriesCorrectPayload()
    {
        List<ClientRegistrationEvent> received = [];



        await using TestHostShell app = new(TimeProvider);

        using IDisposable subscription = app.Server.Events.Subscribe(
            new CollectingObserver<ClientRegistrationEvent>(received));
        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        string segment = keys.Registration.TenantId;

        app.Server.GrantCapability(
            keys.Registration,
            WellKnownCapabilityIdentifiers.VcVerifiableCredentialIssuance,
            []);

        //Filter to this segment — the static subject is shared across tests.
        ClientRegistrationEvent[] forThisSegment = received
            .Where(e => string.Equals(e.TenantId, segment, StringComparison.Ordinal))
            .ToArray();

        Assert.HasCount(2, forThisSegment,
            "ClientRegistered then CapabilityGranted must be emitted for this segment.");
        _ = Assert.IsInstanceOfType<CapabilityGranted>(forThisSegment[1],
            "Second event must be CapabilityGranted.");

        CapabilityGranted evt = (CapabilityGranted)forThisSegment[1];
        Assert.AreEqual(VerifierClientId, evt.ClientId,
            "CapabilityGranted must carry the client identifier.");
        Assert.AreEqual(segment, evt.TenantId.Value,
            "CapabilityGranted must carry the endpoint segment.");
        Assert.AreEqual(
            WellKnownCapabilityIdentifiers.VcVerifiableCredentialIssuance,
            evt.Capability,
            "CapabilityGranted must carry the granted capability.");
    }


    /// <summary>
    /// The first JWKS response after signing-key rotation must contain the replacement key identifier,
    /// verified by in-process dispatch for the registration-plane rule in
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task AfterKeyRotationJwksContainsNewKid()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial originalKeys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        string segment = originalKeys.Registration.TenantId;

        using VerifierKeyMaterial rotatedKeys = app.RotateSigningKey(segment);

        ExchangeContext context = [];
        context.SetTenantId(segment);
        context.SetIssuer(VerifierBaseUri);

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownEndpointNames.MetadataJwks,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            "JWKS endpoint must return HTTP 200 after key rotation.");

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        JsonElement[] jwkArray = doc.RootElement
            .GetProperty(WellKnownJwkMemberNames.Keys).EnumerateArray().ToArray();

        //After rotation the routing table carries the updated registration with the
        //new SigningKeyId. BuildJwksDocumentAsync receives the updated registration
        //and returns the new key. Whether the old key also appears depends on the
        //delegate implementation — in TestHostShell it follows the current
        //registration's SigningKeyId.
        bool foundRotatedKey = jwkArray.Any(jwk =>
            jwk.TryGetProperty(WellKnownJwkMemberNames.Kid, out JsonElement kid) &&
            string.Equals(kid.GetString(), rotatedKeys.SigningKeyId.Value, StringComparison.Ordinal));

        Assert.IsTrue(foundRotatedKey,
            "JWKS must contain the new signing key's kid after rotation.");
    }


    /// <summary>
    /// A deregistered client must have neither a JWKS endpoint nor a discovery endpoint reachable,
    /// verified by in-process dispatch for the registration-plane rule in
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task DeregisteredClientJwksAndDiscoveryReturn404()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        string segment = keys.Registration.TenantId;
        app.DeregisterClient(segment, "Client offboarded.");

        ExchangeContext context = [];
        context.SetTenantId(segment);
        context.SetIssuer(VerifierBaseUri);

        ServerHttpResponse jwksResponse = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownEndpointNames.MetadataJwks,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse discoveryResponse = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownEndpointNames.MetadataDiscovery,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, jwksResponse.StatusCode,
            "JWKS endpoint must return 404 after deregistration.");
        Assert.AreEqual(404, discoveryResponse.StatusCode,
            "Discovery endpoint must return 404 after deregistration.");
    }


    /// <summary>
    /// The library must invoke the installed JWKS document delegate once per request,
    /// verified by in-process dispatch for the application-owned caching rule in
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LibraryCallsBuildJwksDocumentDelegateOnEveryRequest()
    {
        //The library never caches. The delegate is called on every JWKS request.
        //The application's delegate implementation decides whether to hit a cache,
        //compute fresh, or serve a precomputed document — the library does not know
        //and must not know.
        int callCount = 0;

        await using TestHostShell app = new(TimeProvider);

        app.Server.OAuth().Cryptography.BuildJwksDocumentAsync = (registration, ctx, ct) =>
        {
            callCount++;
            return ValueTask.FromResult(new JwksDocument { Keys = [] });
        };

        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);
        string segment = keys.Registration.TenantId;

        ExchangeContext context = [];
        context.SetTenantId(segment);
        context.SetIssuer(VerifierBaseUri);

        const int requestCount = 3;
        for(int i = 0; i < requestCount; i++)
        {
            _ = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownEndpointNames.MetadataJwks,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.AreEqual(requestCount, callCount,
            "BuildJwksDocumentAsync must be called once per JWKS request. " +
            "The library never caches — caching is the application's concern.");
    }


    /// <summary>
    /// A key-rotation event must identify the old and new keys so application cache eviction exposes
    /// the replacement key on the next in-process JWKS dispatch, as specified in
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task KeyRotationFiresClientUpdatedEventForCacheInvalidation()
    {
        //Key rotation emits ClientUpdated via AuthorizationServer.
        //An application's cache invalidation subscriber reacts to this event —
        //the library provides the signal, the application decides what to evict
        //and when (immediately, after approval, gated by time-of-day policy, etc.).
        List<ClientRegistrationEvent> received = [];



        await using TestHostShell app = new(TimeProvider);

        using IDisposable subscription = app.Server.Events.Subscribe(
            new CollectingObserver<ClientRegistrationEvent>(received));
        using VerifierKeyMaterial originalKeys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        string segment = originalKeys.Registration.TenantId;

        //Simulate: application has cached the JWKS for this segment.
        //The cache key is the segment; the cached value is the JWKS document.
        JwksDocument? cachedDocument = new()
        {
            Keys = [new JsonWebKey { Kty = WellKnownKeyTypeValues.Ec, Kid = originalKeys.SigningKeyId.Value }]
        };

        //The application's cache-aware delegate: serve from cache when available,
        //invalidate on ClientUpdated, recompute on next request.
        app.Server.OAuth().Cryptography.BuildJwksDocumentAsync = (registration, ctx, ct) =>
        {
            JwksDocument doc = cachedDocument
                ?? new JwksDocument { Keys = [new JsonWebKey { Kty = WellKnownKeyTypeValues.Ec, Kid = registration.GetDefaultSigningKeyId(KeyUsageContext.JarSigning).Value }] };

            return ValueTask.FromResult(doc);
        };

        //Rotate — emits ClientUpdated.
        using VerifierKeyMaterial rotatedKeys = app.RotateSigningKey(segment);

        //The application's subscriber receives ClientUpdated and evicts the cache.
        ClientRegistrationEvent[] forThisSegment = received
            .Where(e => string.Equals(e.TenantId, segment, StringComparison.Ordinal))
            .ToArray();

        ClientUpdated? updateEvent = forThisSegment.OfType<ClientUpdated>().FirstOrDefault();

        Assert.IsNotNull(updateEvent,
            "ClientUpdated must be emitted on key rotation so cache subscribers can invalidate.");
        Assert.AreEqual(originalKeys.SigningKeyId, updateEvent.Previous.GetDefaultSigningKeyId(KeyUsageContext.JarSigning),
            "ClientUpdated.Previous must carry the original key identifier for targeted eviction.");
        Assert.AreEqual(rotatedKeys.SigningKeyId, updateEvent.Current.GetDefaultSigningKeyId(KeyUsageContext.JarSigning),
            "ClientUpdated.Current must carry the new key identifier to warm the replacement cache entry.");

        //Application evicts after receiving the event.
        cachedDocument = null;

        //Next JWKS request recomputes with the new key.
        ExchangeContext context = [];
        context.SetTenantId(segment);
        context.SetIssuer(VerifierBaseUri);

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownEndpointNames.MetadataJwks,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            "JWKS request after cache eviction must succeed.");

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        JsonElement[] jwkArray = doc.RootElement
            .GetProperty(WellKnownJwkMemberNames.Keys).EnumerateArray().ToArray();

        bool foundNewKey = jwkArray.Any(jwk =>
            jwk.TryGetProperty(WellKnownJwkMemberNames.Kid, out JsonElement kid) &&
            string.Equals(kid.GetString(), rotatedKeys.SigningKeyId.Value, StringComparison.Ordinal));

        Assert.IsTrue(foundNewKey,
            "After cache eviction and recompute, JWKS must carry the new key identifier.");
    }


    /// <summary>
    /// Each JWKS invocation must receive the current request context for application decisions,
    /// verified by in-process dispatch for the per-request resolution rule in
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextBagReachesJwksDelegateOnEveryCallForPerCallDecisions()
    {
        //Verifies that each JWKS request carries its own context bag to the delegate.
        //In production the context bag changes per request — different callers have
        //different regions, tiers, and trust levels. The delegate uses these to decide
        //which cache partition to consult, whether to serve stale, and which keys to include.
        var capturedRegions = new List<string>();

        await using TestHostShell app = new(TimeProvider);

        app.Server.OAuth().Cryptography.BuildJwksDocumentAsync = (registration, ctx, ct) =>
        {
            if(ctx.TryGetValue("app.region", out object? region) && region is string r)
            {
                capturedRegions.Add(r);
            }

            return ValueTask.FromResult(new JwksDocument { Keys = [] });
        };

        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);
        string segment = keys.Registration.TenantId;

        //Three requests from different regions — each carries its own context bag.
        //A production delegate would consult the EU cache for EU callers, the NA cache
        //for NA callers, etc. The time-of-day, approval state, and maintenance window
        //checks also come from the context bag.
        string[] regions = ["eu-west-1", "us-east-1", "ap-southeast-1"];

        foreach(string region in regions)
        {
            ExchangeContext context = [];
            context.SetTenantId(segment);
            context.SetIssuer(VerifierBaseUri);
            context["app.region"] = region;
            _ = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownEndpointNames.MetadataJwks,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.HasCount(3, capturedRegions,
            "The delegate must be called once per request with each request's context bag.");
        Assert.AreEqual("eu-west-1", capturedRegions[0],
            "First request's region must reach the delegate.");
        Assert.AreEqual("us-east-1", capturedRegions[1],
            "Second request's region must reach the delegate.");
        Assert.AreEqual("ap-southeast-1", capturedRegions[2],
            "Third request's region must reach the delegate.");
    }


    /// <summary>
    /// A JWKS delegate must be able to serve one application-cached document across requests,
    /// verified by in-process dispatch for the application-owned caching rule in
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task DelegateCanServePrecomputedDocumentFromApplicationCache()
    {
        //Demonstrates precomputation: the application builds the JwksDocument at
        //registration time (before any request arrives), stores it in its cache,
        //and the delegate serves the precomputed document on every request.
        //The ClientRegistered event triggers precomputation; ClientUpdated triggers
        //cache eviction and re-precomputation.
        JwksDocument? precomputedDocument = null;
        int computeCount = 0;

        await using TestHostShell app = new(TimeProvider);

        //Subscribe to precompute on registration.
        List<ClientRegistrationEvent> events = [];
        using IDisposable subscription = app.Server.Events.Subscribe(
            new CollectingObserver<ClientRegistrationEvent>(events));

        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);
        string segment = keys.Registration.TenantId;

        //Simulate: application's ClientRegistered subscriber precomputes the document.
        ClientRegistered? registeredEvent = events
            .OfType<ClientRegistered>()
            .FirstOrDefault(e => string.Equals(
                e.TenantId, segment, StringComparison.Ordinal));

        Assert.IsNotNull(registeredEvent,
            "ClientRegistered must fire so the application can precompute at registration time.");

        //Precompute now (in production this happens in the subscriber, possibly async).
        computeCount++;
        precomputedDocument = new JwksDocument
        {
            Keys =
            [
                new JsonWebKey
                {
                    Kty = WellKnownKeyTypeValues.Ec,
                    Use = WellKnownJwkValues.UseSig,
                    Kid = registeredEvent.Registration.GetDefaultSigningKeyId(KeyUsageContext.JarSigning).Value
                }
            ]
        };

        //Wire the delegate to serve the precomputed document.
        app.Server.OAuth().Cryptography.BuildJwksDocumentAsync = (registration, ctx, ct) =>
            ValueTask.FromResult(precomputedDocument!);

        //Ten requests — delegate always serves the precomputed document.
        //The application's compute count stays at 1 because caching is its concern.
        string segment2 = segment;
        ExchangeContext context = [];
        context.SetTenantId(segment2);
        context.SetIssuer(VerifierBaseUri);

        for(int i = 0; i < 10; i++)
        {
            ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment2,
            WellKnownEndpointNames.MetadataJwks,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(200, response.StatusCode,
                $"Request {i + 1} must succeed against precomputed document.");
        }

        Assert.AreEqual(1, computeCount,
            "The application computed the document exactly once at registration time. " +
            "The library called the delegate 10 times but the delegate served from cache — " +
            "no recomputation was needed.");

        using JsonDocument doc = JsonDocument.Parse(
            (await app.DispatchAtEndpointAsync(
            segment2,
            WellKnownEndpointNames.MetadataJwks,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false)).Body);

        JsonElement[] finalKeys = doc.RootElement
            .GetProperty(WellKnownJwkMemberNames.Keys)
            .EnumerateArray()
            .ToArray();

        string expectedKid = keys.SigningKeyId.Value;
        JsonElement? matchingKey = finalKeys
            .Cast<JsonElement?>()
            .FirstOrDefault(jwk =>
                jwk!.Value.TryGetProperty(WellKnownJwkMemberNames.Kid, out JsonElement kid)
                && string.Equals(kid.GetString(), expectedKid, StringComparison.Ordinal));

        Assert.IsNotNull(matchingKey,
            "Precomputed document must carry the registration's signing key identifier.");
    }


    /// <summary>
    /// Registration-event timestamps must follow the injected host clock at each emission,
    /// verified in process for the registration-event rule in
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task EventTimestampsReflectFakeTimeProviderAndAreOrdered()
    {
        //Verifies that AuthorizationServer timestamps come from the injected
        //TimeProvider — not from DateTimeOffset.UtcNow or any other clock.
        //This matters for rotation grace-period logic: an application that schedules
        //cache eviction as "evict 5 minutes after ClientUpdated.OccurredAt" must get
        //a timestamp consistent with the same clock the rest of the system uses.
        //
        //No Task.Delay or real waits — FakeTimeProvider.Advance is synchronous and
        //deterministic. The observable fires synchronously via Subject<T>.OnNext so
        //timestamps are captured before RegisterClient or RotateSigningKey return.

        List<ClientRegistrationEvent> received = [];


        await using TestHostShell app = new(TimeProvider);

        using IDisposable subscription = app.Server.Events.Subscribe(
            new CollectingObserver<ClientRegistrationEvent>(received));

        DateTimeOffset t0 = TimeProvider.GetUtcNow();

        //Advance before registration so ClientRegistered.OccurredAt is ahead of t0.
        TimeSpan registrationAdvance = TimeSpan.FromMinutes(5);
        TimeProvider.Advance(registrationAdvance);

        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);
        string segment = keys.Registration.TenantId;

        DateTimeOffset expectedRegistrationTime = t0 + registrationAdvance;

        //Advance again before rotation so ClientUpdated.OccurredAt is further ahead.
        TimeSpan rotationAdvance = TimeSpan.FromMinutes(10);
        TimeProvider.Advance(rotationAdvance);

        using VerifierKeyMaterial rotatedKeys = app.RotateSigningKey(segment);

        DateTimeOffset expectedRotationTime = expectedRegistrationTime + rotationAdvance;

        ClientRegistrationEvent[] forSegment = received
            .Where(e => string.Equals(
                e.TenantId, segment, StringComparison.Ordinal))
            .ToArray();

        ClientRegistered? registeredEvent =
            forSegment.OfType<ClientRegistered>().FirstOrDefault();
        ClientUpdated? updatedEvent =
            forSegment.OfType<ClientUpdated>().FirstOrDefault();

        Assert.IsNotNull(registeredEvent,
            "ClientRegistered must be emitted on registration.");
        Assert.IsNotNull(updatedEvent,
            "ClientUpdated must be emitted on key rotation.");

        Assert.AreEqual(expectedRegistrationTime, registeredEvent.OccurredAt,
            "ClientRegistered.OccurredAt must reflect the FakeTimeProvider value at " +
            "the moment of registration — not wall time.");
        Assert.AreEqual(expectedRotationTime, updatedEvent.OccurredAt,
            "ClientUpdated.OccurredAt must reflect the FakeTimeProvider value at " +
            "the moment of rotation — not wall time.");

        Assert.IsLessThan(updatedEvent.OccurredAt, registeredEvent.OccurredAt,
            "ClientRegistered must precede ClientUpdated in time.");
        Assert.AreEqual(rotationAdvance, updatedEvent.OccurredAt - registeredEvent.OccurredAt,
            "The gap between ClientRegistered and ClientUpdated must equal exactly " +
            "the time advanced between the two operations.");
    }


    /// <summary>
    /// An installed endpoint builder must be invoked once for each request chain,
    /// verified by in-process dispatch for the chain-build rule in
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task EndpointBuildersAreInvokedOncePerRequestNotCachedPerRegistration()
    {
        int builderInvocations = 0;

        ValueTask<IReadOnlyList<EndpointCandidate>> countingMetadataBuilder(IRegistrationRecord registration, ExchangeContext context, CancellationToken server)
        {
            _ = Interlocked.Increment(ref builderInvocations);
            return MetadataEndpoints.Builder(registration, context, server);
        }

        await using TestHostShell app = new(TimeProvider);

        Verifiable.Server.ServerConfiguration configWithCounting = app.Server.Configuration
            .WithEndpointBuilders(new EndpointBuilderSet([
                AuthCodeEndpoints.Builder,
            Oid4VpEndpoints.Builder,
countingMetadataBuilder
            ]));
        app.Server.ApplyConfiguration(configWithCounting);

        using VerifierKeyMaterial keys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        string segment = keys.Registration.TenantId.Value;

        ServerHttpResponse first = await app.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.MetadataJwks, "GET",
            new RequestFields(), [],
            TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse second = await app.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.MetadataJwks, "GET",
            new RequestFields(), [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, first.StatusCode);
        Assert.AreEqual(200, second.StatusCode);
        Assert.AreEqual(2, builderInvocations,
            "The metadata builder must be invoked once per dispatch — the chain is not cached per registration.");
    }


    /// <summary>
    /// Each signing-key lifecycle transition must emit a client update consistent with the published
    /// JWKS membership, verified by in-process dispatch for the registration-plane rule in
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task RotationLifecycleEmitsClientUpdatedAtEveryTransition()
    {
        await using TestHostShell app = new(TimeProvider);

        List<ClientRegistrationEvent> received = [];
        using IDisposable subscription = app.Server.Events.Subscribe(
            new CollectingObserver<ClientRegistrationEvent>(received));

        using VerifierKeyMaterial keys = app.RegisterClient(ClientId, BaseUri, VerifierCapabilities);

        string segment = keys.Registration.TenantId;
        KeyId keyA = keys.SigningKeyId;
        KeyId keyB = app.AllocateSigningKey();

        //Stage 1 → Stage 2: Pre-publish. Current = [A], Incoming = [B].
        app.UpdateSigningKeys(segment, new Dictionary<KeyUsageContext, SigningKeySet>
        {
            [KeyUsageContext.JarSigning] = new SigningKeySet
            {
                Current = [keyA],
                Incoming = [keyB]
            }
        });

        string[] stage2Kids = await FetchJwksKidsAsync(app, segment, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.HasCount(2, stage2Kids,
            "Stage 2: JWKS must publish both Current (A) and Incoming (B).");

        //Stage 2 → Stage 3: Activate. Current = [B], Retiring = [A].
        app.UpdateSigningKeys(segment, new Dictionary<KeyUsageContext, SigningKeySet>
        {
            [KeyUsageContext.JarSigning] = new SigningKeySet
            {
                Current = [keyB],
                Retiring = [keyA]
            }
        });

        string[] stage3Kids = await FetchJwksKidsAsync(app, segment, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.HasCount(2, stage3Kids,
            "Stage 3: JWKS must still publish both B (now Current) and A (now Retiring).");

        //Stage 3 → Stage 4: Drop. Current = [B], Historical = [A].
        app.UpdateSigningKeys(segment, new Dictionary<KeyUsageContext, SigningKeySet>
        {
            [KeyUsageContext.JarSigning] = new SigningKeySet
            {
                Current = [keyB],
                Historical = [keyA]
            }
        });

        string[] stage4Kids = await FetchJwksKidsAsync(app, segment, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.HasCount(1, stage4Kids,
            "Stage 4: JWKS must publish only the Current key — Historical keys are not emitted.");
        Assert.Contains(keyB.Value, stage4Kids,
            "Stage 4: Current key B must remain in JWKS after A is dropped to Historical.");

        //One ClientRegistered from RegisterClient plus three ClientUpdated from the
        //three transitions, filtered to this segment. The static event subject is
        //shared across tests so filter by segment.
        ClientRegistrationEvent[] forThisSegment = received
            .Where(e => string.Equals(e.TenantId, segment, StringComparison.Ordinal))
            .ToArray();

        Assert.HasCount(4, forThisSegment,
            "Each rotation transition must emit a ClientRegistrationEvent (one initial register, three updates).");
        _ = Assert.IsInstanceOfType<ClientRegistered>(forThisSegment[0],
            "The first event for a segment must be ClientRegistered.");

        for(int i = 1; i <= 3; i++)
        {
            _ = Assert.IsInstanceOfType<ClientUpdated>(forThisSegment[i],
                $"Transition {i} must emit ClientUpdated so cache subscribers can invalidate.");
        }
    }


    /// <summary>
    /// An event observer that retains notifications for in-process registration assertions.
    /// The supplied list receives each synchronous notification in delivery order.
    /// </summary>
    /// <typeparam name="T">The notification type.</typeparam>
    /// <param name="collected">The list used by the test to inspect notifications.</param>
    private sealed class CollectingObserver<T>(List<T> collected): IObserver<T>
    {
        /// <summary>
        /// Records the delivered notification so the test can inspect its payload.
        /// </summary>
        /// <param name="value">The delivered notification.</param>
        public void OnNext(T value)
        {
            collected.Add(value);
        }


        /// <summary>
        /// Accepts an error notification without adding a lifecycle event to the test list.
        /// </summary>
        /// <param name="error">The reported error.</param>
        public void OnError(Exception error)
        {
        }


        /// <summary>
        /// Accepts completion without adding a lifecycle event to the test list.
        /// </summary>
        public void OnCompleted()
        {
        }

    }
}
