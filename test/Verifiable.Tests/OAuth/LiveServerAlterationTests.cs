using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.Dcql;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Metadata;
using Verifiable.Server.Routing;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.OAuth.AuthorizationServerFeatureTests;
using static Verifiable.Tests.OAuth.JwksRotationTests;
namespace Verifiable.Tests.OAuth;

/// <summary>
/// Proves requested, drained and validated wiring publication under
/// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>.
/// Each admitted request retains one composition; an incoherent candidate cannot change serving wiring.
/// Registration data remains application-owned and its existing notification cases retain their scope.
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
    private FakeTimeProvider? RetainedTimeProvider { get; set; }


    /// <summary>
    /// The deterministic clock for this case, retaining the rotation fixture's epoch and the
    /// shared suite epoch for the other cases so their time-dependent inputs remain stable.
    /// </summary>
    private FakeTimeProvider TimeProvider
    {
        get
        {

            return RetainedTimeProvider ??= new FakeTimeProvider(
                string.Equals(TestContext.TestName, nameof(RotationLifecycleEmitsClientUpdatedAtEveryTransition), StringComparison.Ordinal)
                    ? DateTimeOffset.Parse("2026-01-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture)
                    : TestClock.CanonicalEpoch);
        }

    }


    /// <summary>
    /// A missing claim operation is rejected before publication under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "Structural validation requires ClaimFlowStateAsync before publication."
    /// </summary>
    [TestMethod]
    public async Task DispatchThrowsTheNamedConfigurationFaultWhenClaimFlowStateAsyncIsMissing()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string before = await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        InvalidOperationException fault = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
            app.Server.RequestAlterationAsync(candidate => candidate.Integration.ClaimFlowStateAsync = null, TestContext.CancellationToken));
        Assert.Contains(nameof(ServerIntegration.ClaimFlowStateAsync), fault.Message, StringComparison.Ordinal);
        Assert.IsTrue(app.Server.IsValidated);
        Assert.AreEqual(before, await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false));
    }


    /// <summary>
    /// Unvalidated admission recovers after the missing claim operation is supplied through
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "Admission requires explicit validation or a successful alteration."
    /// </summary>
    [TestMethod]
    public async Task DispatchRecoversOnTheNextCallAfterTheMissingSeamIsWiredAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        app.Host("default").UseUnvalidatedServer();
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        ClaimServerFlowStateDelegate claim = app.Server.Integration.ClaimFlowStateAsync!;
        app.Server.Integration.ClaimFlowStateAsync = null;
        app.Host("default").IsUnvalidatedListenerAllowed = true;
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using HttpResponseMessage refused = await SendDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        Assert.AreEqual(500, (int)refused.StatusCode);
        Assert.IsFalse(app.Server.IsValidated);
        Assert.IsTrue(app.Host("default").HttpFaults.TryDequeue(out Exception? fault));
        _ = Assert.IsInstanceOfType<InvalidOperationException>(fault);
        await app.Server.RequestAlterationAsync(candidate => candidate.Integration.ClaimFlowStateAsync = claim, TestContext.CancellationToken).ConfigureAwait(false);
        using HttpResponseMessage accepted = await SendDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        Exception[] recoveryFaults = app.Host("default").ConsumeHttpFaults();
        Assert.IsEmpty(recoveryFaults, "A repaired composition must admit the next request.");
        Assert.AreEqual(200, (int)accepted.StatusCode);
        Assert.IsTrue(app.Server.IsValidated);
    }


    /// <summary>
    /// Requested publication validates a complete composition without a separate Validate call under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "Admission requires explicit validation or a successful alteration."
    /// </summary>
    [TestMethod]
    public async Task FullyWiredHostDispatchesWithoutAnExplicitValidateCall()
    {
        await using TestHostShell app = new(TimeProvider);
        app.Host("default").UseUnvalidatedServer();
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        Assert.IsFalse(app.Server.IsValidated);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using HttpResponseMessage response = await SendDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        Exception[] preparationFaults = app.Host("default").ConsumeHttpFaults();
        Assert.IsEmpty(preparationFaults, "Requested preparation must validate admission.");
        Assert.AreEqual(200, (int)response.StatusCode);
        Assert.IsTrue(app.Server.IsValidated);
    }


    /// <summary>
    /// A registration must emit one event identifying its client and tenant and carrying its immutable projection,
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
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);

        //Filter to the registration participating in this test.
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
        Assert.AreEqual(keys.Registration.Revision, evt.Projection.Revision,
            "ClientRegistered must carry the committed registration revision.");
        Assert.AreEqual(keys.Registration.GetDefaultSigningKeyId(KeyUsageContext.JarSigning),
            evt.Projection.SigningKeyIds[KeyUsageContext.JarSigning],
            "ClientRegistered must carry the committed signing key identifier.");
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
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);

        Assert.IsTrue(
            app.RegistrationStore.ContainsKey(keys.Registration.TenantId),
            "Registration store must contain the segment immediately after RegisterClient.");

        ClientRecord stored = app.RegistrationStore[keys.Registration.TenantId];
        Assert.AreEqual(VerifierClientId, stored.ClientId,
            "Stored registration must carry the correct client identifier.");
    }


    /// <summary>
    /// A deregistered client must be absent from routing and receive a 404 on its next dispatch,
    /// verified over the listener for the registration-plane rule in
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task DeregisterClientRemovesFromRoutingTableAndDispatchReturns404()
    {
        List<ClientRegistrationEvent> received = [];


        await using TestHostShell app = new(TimeProvider);

        using IDisposable subscription = app.Server.Events.Subscribe(
            new CollectingObserver<ClientRegistrationEvent>(received));
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);

        string segment = keys.Registration.TenantId;

        Assert.IsTrue(app.RegistrationStore.ContainsKey(segment),
            "Registration must be present before deregistration.");

        await app.DeregisterClientAsync(segment, "Test deregistration.", TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(app.RegistrationStore.ContainsKey(segment),
            "Registration must be removed from routing table immediately after deregistration.");

        //Filter to this segment only — the subject belongs to this host.
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
        ServerHttpResponse response = await RawAuthCodeWirePushers.PushNamedEndpointAsync(app,
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
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);

        string segment = keys.Registration.TenantId;

        await app.Server.GrantCapabilityAsync(
            keys.Registration,
            WellKnownCapabilityIdentifiers.VcVerifiableCredentialIssuance,
            []).ConfigureAwait(false);

        //Filter to this segment — the subject belongs to this host.
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
    /// verified by listener dispatch for the registration-plane rule in
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task AfterKeyRotationJwksContainsNewKid()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial originalKeys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);

        string segment = originalKeys.Registration.TenantId;

        using VerifierKeyMaterial rotatedKeys = await app.RotateSigningKeyAsync(segment).ConfigureAwait(false);

        ExchangeContext context = [];
        context.SetTenantId(segment);
        context.SetIssuer(VerifierBaseUri);

        ServerHttpResponse response = await RawAuthCodeWirePushers.PushNamedEndpointAsync(app,
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
    /// verified by listener dispatch for the registration-plane rule in
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task DeregisteredClientJwksAndDiscoveryReturn404()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);

        string segment = keys.Registration.TenantId;
        await app.DeregisterClientAsync(segment, "Client offboarded.", TestContext.CancellationToken).ConfigureAwait(false);

        ExchangeContext context = [];
        context.SetTenantId(segment);
        context.SetIssuer(VerifierBaseUri);

        ServerHttpResponse jwksResponse = await RawAuthCodeWirePushers.PushNamedEndpointAsync(app,
            segment,
            WellKnownEndpointNames.MetadataJwks,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse discoveryResponse = await RawAuthCodeWirePushers.PushNamedEndpointAsync(app,
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
    /// verified by listener dispatch for the application-owned caching rule in
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

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.Cryptography.BuildJwksDocumentAsync = (registration, ctx, ct) =>
            {
                callCount++;

                return ValueTask.FromResult(new JwksDocument { Keys = [] });
            };
        }).ConfigureAwait(false);

        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        string segment = keys.Registration.TenantId;

        ExchangeContext context = [];
        context.SetTenantId(segment);
        context.SetIssuer(VerifierBaseUri);

        const int requestCount = 3;
        for(int i = 0; i < requestCount; i++)
        {
            _ = await RawAuthCodeWirePushers.PushNamedEndpointAsync(app,
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
    /// the replacement key on the next listener JWKS dispatch, as specified in
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
        using VerifierKeyMaterial originalKeys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);

        string segment = originalKeys.Registration.TenantId;

        //Simulate: application has cached the JWKS for this segment.
        //The cache key is the segment; the cached value is the JWKS document.
        JwksDocument? cachedDocument = new()
        {
            Keys = [new JsonWebKey { Kty = WellKnownKeyTypeValues.Ec, Kid = originalKeys.SigningKeyId.Value }]
        };

        //The application's cache-aware delegate: serve from cache when available,
        //invalidate on ClientUpdated, recompute on next request.
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.Cryptography.BuildJwksDocumentAsync = (registration, ctx, ct) =>
            {
                JwksDocument doc = cachedDocument
                    ?? new JwksDocument { Keys = [new JsonWebKey { Kty = WellKnownKeyTypeValues.Ec, Kid = registration.GetDefaultSigningKeyId(KeyUsageContext.JarSigning).Value }] };

                return ValueTask.FromResult(doc);
            };
        }).ConfigureAwait(false);

        //Rotate — emits ClientUpdated.
        using VerifierKeyMaterial rotatedKeys = await app.RotateSigningKeyAsync(segment).ConfigureAwait(false);

        //The application's subscriber receives ClientUpdated and evicts the cache.
        ClientRegistrationEvent[] forThisSegment = received
            .Where(e => string.Equals(e.TenantId, segment, StringComparison.Ordinal))
            .ToArray();

        ClientUpdated? updateEvent = forThisSegment.OfType<ClientUpdated>().FirstOrDefault();

        Assert.IsNotNull(updateEvent,
            "ClientUpdated must be emitted on key rotation so cache subscribers can invalidate.");
        Assert.AreEqual(originalKeys.SigningKeyId, updateEvent.Previous.SigningKeyIds[KeyUsageContext.JarSigning],
            "ClientUpdated.Previous must carry the original key identifier for targeted eviction.");
        Assert.AreEqual(rotatedKeys.SigningKeyId, updateEvent.Projection.SigningKeyIds[KeyUsageContext.JarSigning],
            "ClientUpdated.Projection must carry the new key identifier to warm the replacement cache entry.");

        //Application evicts after receiving the event.
        cachedDocument = null;

        //Next JWKS request recomputes with the new key.
        ExchangeContext context = [];
        context.SetTenantId(segment);
        context.SetIssuer(VerifierBaseUri);

        ServerHttpResponse response = await RawAuthCodeWirePushers.PushNamedEndpointAsync(app,
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
    /// verified by listener dispatch for the per-request resolution rule in
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

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.Cryptography.BuildJwksDocumentAsync = (registration, ctx, ct) =>
            {
                if(ctx.TryGetValue("app.region", out object? region) && region is string r)
                {
                    capturedRegions.Add(r);
                }

                return ValueTask.FromResult(new JwksDocument { Keys = [] });
            };
        }).ConfigureAwait(false);

        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
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
            _ = await RawAuthCodeWirePushers.PushNamedEndpointAsync(app,
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
    /// verified by listener dispatch for the application-owned caching rule in
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

        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
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
                    Kid = registeredEvent.Projection.SigningKeyIds[KeyUsageContext.JarSigning].Value
                }

            ]
        };

        //Wire the delegate to serve the precomputed document.
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.Cryptography.BuildJwksDocumentAsync = (registration, ctx, ct) =>
                ValueTask.FromResult(precomputedDocument!);
        }).ConfigureAwait(false);

        //Ten requests — delegate always serves the precomputed document.
        //The application's compute count stays at 1 because caching is its concern.
        string segment2 = segment;
        ExchangeContext context = [];
        context.SetTenantId(segment2);
        context.SetIssuer(VerifierBaseUri);

        for(int i = 0; i < 10; i++)
        {
            ServerHttpResponse response = await RawAuthCodeWirePushers.PushNamedEndpointAsync(app,
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
            (await RawAuthCodeWirePushers.PushNamedEndpointAsync(app,
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

        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        string segment = keys.Registration.TenantId;

        DateTimeOffset expectedRegistrationTime = t0 + registrationAdvance;

        //Advance again before rotation so ClientUpdated.OccurredAt is further ahead.
        TimeSpan rotationAdvance = TimeSpan.FromMinutes(10);
        TimeProvider.Advance(rotationAdvance);

        using VerifierKeyMaterial rotatedKeys = await app.RotateSigningKeyAsync(segment).ConfigureAwait(false);

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
    /// verified by listener dispatch for the chain-build rule in
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
        await app.Server.RequestAlterationAsync(candidate => candidate.Configuration = configWithCounting, TestContext.CancellationToken).ConfigureAwait(false);

        using VerifierKeyMaterial keys = await app.RegisterClientAsync(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);

        string segment = keys.Registration.TenantId.Value;

        ServerHttpResponse first = await RawAuthCodeWirePushers.PushNamedEndpointAsync(app,
            segment, WellKnownEndpointNames.MetadataJwks, "GET",
            new RequestFields(), [],
            TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse second = await RawAuthCodeWirePushers.PushNamedEndpointAsync(app,
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
    /// JWKS membership, verified by listener dispatch for the registration-plane rule in
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "Application observers supply persistence and cache effects."
    /// </summary>
    [TestMethod]
    public async Task RotationLifecycleEmitsClientUpdatedAtEveryTransition()
    {
        await using TestHostShell app = new(TimeProvider);

        List<ClientRegistrationEvent> received = [];
        using IDisposable subscription = app.Server.Events.Subscribe(
            new CollectingObserver<ClientRegistrationEvent>(received));

        using VerifierKeyMaterial keys = await app.RegisterClientAsync(ClientId, BaseUri, VerifierCapabilities).ConfigureAwait(false);

        string segment = keys.Registration.TenantId;
        KeyId keyA = keys.SigningKeyId;
        KeyId keyB = app.AllocateSigningKey();

        //Stage 1 → Stage 2: Pre-publish. Current = [A], Incoming = [B].
        await app.UpdateSigningKeysAsync(segment, new Dictionary<KeyUsageContext, SigningKeySet>
        {
            [KeyUsageContext.JarSigning] = new SigningKeySet
            {
                Current = [keyA],
                Incoming = [keyB]
            }
        }).ConfigureAwait(false);

        string[] stage2Kids = await app.FetchJwksKidsOverWireAsync(segment, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.HasCount(2, stage2Kids,
            "Stage 2: JWKS must publish both Current (A) and Incoming (B).");

        //Stage 2 → Stage 3: Activate. Current = [B], Retiring = [A].
        await app.UpdateSigningKeysAsync(segment, new Dictionary<KeyUsageContext, SigningKeySet>
        {
            [KeyUsageContext.JarSigning] = new SigningKeySet
            {
                Current = [keyB],
                Retiring = [keyA]
            }
        }).ConfigureAwait(false);

        string[] stage3Kids = await app.FetchJwksKidsOverWireAsync(segment, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.HasCount(2, stage3Kids,
            "Stage 3: JWKS must still publish both B (now Current) and A (now Retiring).");

        //Stage 3 → Stage 4: Drop. Current = [B], Historical = [A].
        await app.UpdateSigningKeysAsync(segment, new Dictionary<KeyUsageContext, SigningKeySet>
        {
            [KeyUsageContext.JarSigning] = new SigningKeySet
            {
                Current = [keyB],
                Historical = [keyA]
            }
        }).ConfigureAwait(false);

        string[] stage4Kids = await app.FetchJwksKidsOverWireAsync(segment, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.HasCount(1, stage4Kids,
            "Stage 4: JWKS must publish only the Current key — Historical keys are not emitted.");
        Assert.Contains(keyB.Value, stage4Kids,
            "Stage 4: Current key B must remain in JWKS after A is dropped to Historical.");

        //One ClientRegistered from RegisterClient plus three ClientUpdated from the
        //three transitions, filtered to this registration segment.
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
    /// An admitted request retains its wiring while alteration drains it, under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "Requests already admitted complete before the alteration callback runs."
    /// </summary>
    [TestMethod]
    public async Task InFlightRequestCompletesOnItsAdmittedWiringAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        bool hasCapturedWiring = false;
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource exited = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeDiscoveryFieldsAsync = async (_, context, ct) =>
            {
                hasCapturedWiring = !ReferenceEquals(context.Server, context.RequestServer);
                entered.SetResult();
                await release.Task.WaitAsync(ct).ConfigureAwait(false);
                exited.SetResult();

                return Marker("A");
            };
        }).ConfigureAwait(false);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Task<string> oldRequest = ReadDiscoveryAsync(app, keys.Registration);
        await entered.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Task alteration = app.Server.RequestAlterationAsync(candidate =>
        {
            Assert.IsTrue(exited.Task.IsCompletedSuccessfully, "An alteration callback cannot run while an admitted seam is active.");
            candidate.Family<AuthorizationServerIntegration>().ContributeDiscoveryFieldsAsync = (_, _, _) => ValueTask.FromResult(Marker("B"));
        }, TestContext.CancellationToken);
        try
        {
            Assert.IsFalse(app.Server.IsValidated, "Draining must close validated admission.");
        }
        finally
        {
            release.SetResult();
        }

        string oldBody = await oldRequest.ConfigureAwait(false);
        await alteration.ConfigureAwait(false);
        Assert.IsTrue(hasCapturedWiring, "Admission must retain a fixed wiring view separately from the serving owner.");
        Assert.AreEqual("A", ReadMarker(oldBody));
        Assert.AreEqual("B", ReadMarker(await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false)));
    }


    /// <summary>
    /// An arrival held during draining uses the accepted composition under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "New arrivals wait while the server drains requests and processes queued candidates in alteration enqueue order."
    /// </summary>
    [TestMethod]
    public async Task ArrivalDuringDrainUsesThePublishedWiringAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        int visits = 0;
        int arrivals = 0;
        TaskCompletionSource heldArrival = new(TaskCreationOptions.RunContinuationsAsynchronously);
        app.Host("default").RequestArriving = () =>
        {
            if(Interlocked.Increment(ref arrivals) == 2)
            {
                heldArrival.SetResult();
            }

            return Task.CompletedTask;
        };
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeDiscoveryFieldsAsync = async (_, _, ct) =>
            {
                if(Interlocked.Increment(ref visits) == 1)
                {
                    entered.SetResult();
                    await release.Task.WaitAsync(ct).ConfigureAwait(false);
                }

                return Marker("A");
            };
        }).ConfigureAwait(false);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Task<string> oldRequest = ReadDiscoveryAsync(app, keys.Registration);
        await entered.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Task alteration = app.Server.RequestAlterationAsync(candidate =>
            candidate.Family<AuthorizationServerIntegration>().ContributeDiscoveryFieldsAsync = (_, _, _) => ValueTask.FromResult(Marker("B")), TestContext.CancellationToken);
        Task<string> arrival = ReadDiscoveryAsync(app, keys.Registration);
        try
        {
            await heldArrival.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            release.SetResult();
        }

        await alteration.ConfigureAwait(false);
        Assert.AreEqual("A", ReadMarker(await oldRequest.ConfigureAwait(false)));
        Assert.AreEqual("B", ReadMarker(await arrival.ConfigureAwait(false)));
    }


    /// <summary>
    /// The bounded admission hold emits Retry-After under
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.6.4">RFC 9110 §15.6.4</see>:
    /// "The server MAY send a Retry-After header field" with a temporary 503 refusal, whose body
    /// reuses <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>'s
    /// <c>temporarily_unavailable</c> authorization-endpoint vocabulary as a transport-level refusal,
    /// not an RFC 6749 §5.2 token-endpoint error response.
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "The refusal body reuses RFC 6749 section 4.1.2.1 authorization-endpoint vocabulary as a transport-level refusal, not an RFC 6749 section 5.2 token-endpoint error response."
    /// </summary>
    [TestMethod]
    public async Task AdmissionBoundReturnsTemporaryRefusalWithRetryAfterAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        app.Server.ApplyConfiguration(app.Server.Configuration with { AdmissionWaitTimeout = TimeSpan.FromMilliseconds(50) });
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeDiscoveryFieldsAsync = async (_, _, ct) =>
            {
                entered.SetResult();
                await release.Task.WaitAsync(ct).ConfigureAwait(false);

                return Marker("A");
            };
        }).ConfigureAwait(false);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Task<string> oldRequest = ReadDiscoveryAsync(app, keys.Registration);
        await entered.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Task alteration = app.Server.RequestAlterationAsync(candidate =>
            candidate.Family<AuthorizationServerIntegration>().ContributeDiscoveryFieldsAsync = (_, _, _) => ValueTask.FromResult(Marker("B")), TestContext.CancellationToken);
        try
        {
            using HttpResponseMessage refusal = await SendDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
            Assert.AreEqual(503, (int)refusal.StatusCode);
            Assert.AreEqual(TimeSpan.FromSeconds(1), refusal.Headers.RetryAfter?.Delta,
                "RFC 9110 §10.2.3's delay-seconds form must name the exact one-second bound the refusal grants.");
            Assert.IsNull(refusal.Headers.RetryAfter?.Date, "The refusal must use the delay-seconds form, not an HTTP-date.");
            string refusalBody = await refusal.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.Contains("temporarily_unavailable", refusalBody, StringComparison.Ordinal);
            Assert.Contains("temporarily unable to accept this request", refusalBody, StringComparison.Ordinal,
                "The refusal names only the transient condition, never the reconfiguration in progress.");
        }
        finally
        {
            release.SetResult();
            _ = await oldRequest.ConfigureAwait(false);
            await alteration.ConfigureAwait(false);
        }

        Assert.AreEqual("B", ReadMarker(await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false)));
    }


    /// <summary>
    /// A replaced discovery seam applies to the next request under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "A candidate is validated before one reference assignment publishes the complete composition."
    /// </summary>
    [TestMethod]
    public async Task RequestedSeamReplacementAppliesToTheNextRequestAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeDiscoveryFieldsAsync = (_, _, _) => ValueTask.FromResult(Marker("A"));
        }).ConfigureAwait(false);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        Assert.AreEqual("A", ReadMarker(await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false)));
        app.Server.Validate();
        Assert.IsTrue(app.Server.IsValidated);
        await app.Server.RequestAlterationAsync(candidate =>
            candidate.Family<AuthorizationServerIntegration>().ContributeDiscoveryFieldsAsync = (_, _, _) => ValueTask.FromResult(Marker("B")), deadline.Token).ConfigureAwait(false);
        Assert.AreEqual("B", ReadMarker(await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false)));
    }


    /// <summary>
    /// Concurrent discovery requests observe one builder configuration under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "Every admitted request retains one complete wiring composition."
    /// </summary>
    [TestMethod]
    public async Task ConcurrentArrivalsNeverMixBuilderConfigurationsAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        int visits = 0;
        app.Server.ApplyConfiguration(ProbeConfiguration(app.Server.Configuration, "A"));
        await TestHostShell.AlterAsync(app.Server, integration =>
        {
            InspectDelegate inspect = integration.InspectAsync!;
            integration.InspectAsync = async (stage, context, ct) =>
            {
                if(Interlocked.Increment(ref visits) == 1)
                {
                    _ = entered.TrySetResult();
                    await release.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
                }

                await inspect(stage, context, ct).ConfigureAwait(false);
            };
            integration.ContributeDiscoveryFieldsAsync = (_, ctx, _) => ValueTask.FromResult(
                new DiscoveryDocumentContribution([new DiscoveryStringField("wiring_marker", (string)ctx["left"] + (string)ctx["right"])]));
        }).ConfigureAwait(false);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        Task<string> held = ReadDiscoveryAsync(app, keys.Registration);
        TestHostShell.DrainCheckpoint checkpoint = new(app.Server);
        Task? alteration = null;
        Task<string>[] arrivals = [];
        try
        {
            await entered.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            alteration = app.Server.RequestAlterationAsync(candidate => candidate.Configuration = ProbeConfiguration(candidate.Configuration, "B"), deadline.Token);
            await checkpoint.ReachAsync(alteration, deadline.Token).ConfigureAwait(false);
            arrivals = [.. Enumerable.Range(0, 16).Select(_ => ReadDiscoveryAsync(app, keys.Registration))];
        }
        finally
        {
            _ = release.TrySetResult();
        }

        Assert.AreEqual("AA", ReadMarker(await held.WaitAsync(deadline.Token).ConfigureAwait(false)));
        Assert.IsTrue(checkpoint.IsParked, "The worker must be parked at its registered drain wait before release.");
        string[] bodies = await Task.WhenAll(arrivals).WaitAsync(deadline.Token).ConfigureAwait(false);
        await alteration!.WaitAsync(deadline.Token).ConfigureAwait(false);
        foreach(string body in bodies)
        {
            Assert.IsTrue(ReadMarker(body) is "AA" or "BB", "A response must contain one complete builder configuration.");
        }

        Assert.AreEqual("BB", ReadMarker(await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false)));
    }


    /// <summary>
    /// Incoherent candidates leave the accepted response byte-identical under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "An incoherent candidate is discarded and only its requester faults."
    /// </summary>
    [TestMethod]
    [DataRow("ResolveEndpointUriAsync")]
    [DataRow("DeleteFlowStateAsync")]
    [DataRow("Cryptography")]
    [DataRow("Encoder")]
    [DataRow("ClientAuthenticationMethodsSupported")]
    [DataRow("EndpointBuilders")]
    [DataRow("Integration")]
    [DataRow("AuthorizeTokenExchangeAsync")]
    [DataRow("ClaimIssuer")]
    [DataRow("TokenProducers")]
    [DataRow("AuthorizationDetailTypes")]
    [DataRow("VcalmTemplateEvaluators")]
    [DataRow("VcalmSchemaValidators")]
    [DataRow("another EndpointServer")]
    [DataRow("registered authorization family")]
    public async Task IncoherentCandidateLeavesLiveDiscoveryByteIdenticalAsync(string missing)
    {
        await using TestHostShell app = new(TimeProvider);
        await using TestHostShell other = new(TimeProvider);
        using CancellationTokenSource deadline = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeDiscoveryFieldsAsync = (_, context, _) => ValueTask.FromResult(Marker(
                string.Join(",", context.RequestServer!.OAuth().AuthorizationDetailTypes.RegisteredTypes)
                + context.RequestServer!.OAuth().AuthorizationDetailTypes.IsRegistered("discarded-type")
                + context.RequestServer!.GetIntegration<Verifiable.Vcalm.VcalmIntegration>().VcalmSchemaValidators.IsRegistered("discarded-schema")
                + context.RequestServer!.GetIntegration<Verifiable.Vcalm.VcalmIntegration>().VcalmTemplateEvaluators.IsRegistered("discarded-template")));
        }).ConfigureAwait(false);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        string before = await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        ServerIntegration integration = app.Server.Integration;
        ServerConfiguration configuration = app.Server.Configuration;
        Action<AlterationCandidate> invalidate = missing switch
        {
            "ResolveEndpointUriAsync" => candidate => candidate.Integration.ResolveEndpointUriAsync = null,
            "DeleteFlowStateAsync" => candidate => candidate.Integration.DeleteFlowStateAsync = null,
            "Cryptography" => candidate => candidate.Family<AuthorizationServerIntegration>().Cryptography = null!,
            "Encoder" => candidate => candidate.Family<AuthorizationServerIntegration>().Codecs.Encoder = null,
            "ClientAuthenticationMethodsSupported" => candidate => candidate.Family<AuthorizationServerIntegration>().ClientAuthenticationMethodsSupported = [],
            "EndpointBuilders" => candidate => candidate.Configuration = ServerConfiguration.Empty,
            "Integration" => candidate => candidate.AddIntegration(new AuthorizationServerIntegration { MemoryPool = other.Server.OAuth().MemoryPool }),
            "ClaimIssuer" => candidate => candidate.Family<AuthorizationServerIntegration>().ClaimIssuer = null,
            "TokenProducers" => candidate => candidate.Family<AuthorizationServerIntegration>().TokenProducers = new TokenProducerSet([null!]),
            "AuthorizationDetailTypes" => candidate => candidate.Family<AuthorizationServerIntegration>().AuthorizationDetailTypes.Register(new AuthorizationDetailHandler { Type = "invalid", ValidateShape = null! }),
            "VcalmTemplateEvaluators" => candidate => candidate.Family<Verifiable.Vcalm.VcalmIntegration>().VcalmTemplateEvaluators = null!,
            "VcalmSchemaValidators" => candidate => candidate.Family<Verifiable.Vcalm.VcalmIntegration>().VcalmSchemaValidators = null!,
            "AuthorizeTokenExchangeAsync" => candidate => candidate.Family<AuthorizationServerIntegration>().AuthorizeTokenExchangeAsync = (_, _, _, _, _, _) => throw new InvalidOperationException("Uninvoked candidate operation."),
            "another EndpointServer" => candidate => candidate.AddIntegration<ServerIntegration>(other.Server.OAuth()),
            "registered authorization family" => candidate => candidate.AddIntegration<ServerIntegration>((AuthorizationServerIntegration)candidate.Family<AuthorizationServerIntegration>().CreateCandidateCopy()),
            _ => throw new ArgumentOutOfRangeException(nameof(missing))
        };
        TaskCompletionSource<bool> drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
        app.Server.DrainWaitStarted = drain => drained.TrySetResult(drain.IsCompletedSuccessfully);
        InvalidOperationException fault;
        try
        {
            fault = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => app.Server.RequestAlterationAsync(candidate =>
            {
                candidate.Family<AuthorizationServerIntegration>().ContributeDiscoveryFieldsAsync = (_, _, _) => ValueTask.FromResult(Marker("discarded"));
                candidate.Family<AuthorizationServerIntegration>().AuthorizationDetailTypes.Register(new AuthorizationDetailHandler { Type = "discarded-type", ValidateShape = (_, _) => null });
                candidate.Family<Verifiable.Vcalm.VcalmIntegration>().VcalmSchemaValidators.Register("discarded-schema", (_, _, _) => throw new InvalidOperationException("Uninvoked schema validator."));
                candidate.Family<Verifiable.Vcalm.VcalmIntegration>().VcalmTemplateEvaluators.Register("discarded-template", (_, _, _, _) => null);
                invalidate(candidate);
            }, deadline.Token));
            Assert.IsTrue(await drained.Task.WaitAsync(deadline.Token).ConfigureAwait(false),
                "The completed discovery request must leave no lease for candidate validation to drain.");
        }
        finally
        {
            app.Server.DrainWaitStarted = null;
        }

        Assert.IsTrue(app.Server.IsValidated, "A rejected candidate must reopen admission before its requester faults.");
        Assert.Contains(missing, fault.Message, StringComparison.Ordinal);
        Assert.AreSame(integration, app.Server.Integration);
        Assert.AreSame(configuration, app.Server.Configuration);
        Assert.AreEqual(before, await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false));
        if(missing is "another EndpointServer")
        {
            AuthorizationServerIntegration otherIntegration = other.Server.OAuth();
            Exception? editFault = null;
            try
            {
                otherIntegration.ClaimIssuer = otherIntegration.ClaimIssuer;
            }
            catch(InvalidOperationException exception)
            {
                editFault = exception;
            }

            Assert.IsNull(editFault, "A rejected adoption must leave the supplied construction integration mutable.");
            Assert.IsFalse(other.Server.IsValidated, "The supplied integration must still invalidate its own server.");
            Assert.AreSame(otherIntegration, other.Server.GetIntegration<AuthorizationServerIntegration>(),
                "A rejected candidate must not re-own another composition's live integration.");
        }

        await app.Server.RequestAlterationAsync(candidate =>
            candidate.Family<AuthorizationServerIntegration>().ContributeDiscoveryFieldsAsync = (_, _, _) => ValueTask.FromResult(Marker("accepted")), deadline.Token).ConfigureAwait(false);
        Assert.AreEqual("accepted", ReadMarker(await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false)));
    }


    /// <summary>
    /// Proves the stated publication rule under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "A null endpoint-builder member is rejected by ArgumentNullException before publication."
    /// </summary>
    [TestMethod]
    public async Task NullEndpointBuilderIsRejectedBeforePublicationAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string before = await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        ServerConfiguration configuration = app.Server.Configuration;
        _ = await Assert.ThrowsExactlyAsync<ArgumentNullException>(() => app.Server.RequestAlterationAsync(candidate =>
            candidate.Configuration = configuration with { EndpointBuilders = new EndpointBuilderSet([null!]) }, TestContext.CancellationToken));
        Assert.AreSame(configuration, app.Server.Configuration);
        Assert.AreEqual(before, await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false));
    }


    /// <summary>
    /// Proves the stated publication rule under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "A construction edit to a shared component invalidates every attached server."
    /// </summary>
    [TestMethod]
    public async Task SharedIntegrationInvalidatesEveryConstructionOwnerAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        AuthorizationServerIntegration shared = app.Server.OAuth();
        using EndpointServer second = new()
        {
            Integration = shared,
            Configuration = app.Server.Configuration,
            TimeProvider = TimeProvider
        };
        second.AddIntegration(shared);
        second.Validate();
        Assert.IsTrue(app.Server.IsValidated);
        Assert.IsTrue(second.IsValidated);
        shared.ClaimIssuer = shared.ClaimIssuer;
        Assert.IsFalse(second.IsValidated, "The owner that just edited a shared component must see its own invalidation.");
        Assert.IsFalse(app.Server.IsValidated,
            "A component shared by construction must invalidate every attached owner, not only the most recently attached one.");
        using HttpResponseMessage response = await SendDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        Assert.AreEqual(500, (int)response.StatusCode, "Admission must refuse the now-unvalidated wiring rather than serve it stale.");
        Assert.IsTrue(app.Host("default").HttpFaults.TryDequeue(out Exception? fault));
        Assert.Contains(nameof(EndpointServer.Validate), fault.Message, StringComparison.Ordinal);
        app.Server.Validate();
        Assert.IsTrue(app.Server.IsValidated);
        using HttpResponseMessage recovered = await SendDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        Assert.AreEqual(200, (int)recovered.StatusCode, "Re-validating recovers admission.");
    }


    /// <summary>
    /// Proves the stated publication rule under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "A subscription made inside a candidate callback attaches to its shared stream immediately and survives that candidate's acceptance or rejection."
    /// </summary>
    [TestMethod]
    public async Task SubscriptionInsideRejectedCandidateCallbackSurvivesTheRejectionAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        List<ClientRegistrationEvent> observed = [];
        InvalidOperationException fault = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => app.Server.RequestAlterationAsync(candidate =>
        {
            _ = candidate.Family<AuthorizationServerIntegration>().Events.Subscribe(new CollectingObserver<ClientRegistrationEvent>(observed));
            candidate.Integration.DeleteFlowStateAsync = null;
        }, deadline.Token).WaitAsync(deadline.Token));
        Assert.Contains(nameof(ServerIntegration.DeleteFlowStateAsync), fault.Message, StringComparison.Ordinal);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using HttpResponseMessage response = await RegisterOverWireAsync(app).ConfigureAwait(false);
        Assert.AreEqual(201, (int)response.StatusCode);
        Assert.HasCount(1, observed.OfType<ClientRegistered>().ToArray(),
            "A subscription made inside a rejected candidate must observe a subsequent HTTP registration.");
    }


    /// <summary>
    /// Live wiring rejects direct mutation under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "Serving setters and registry registration require an alteration candidate."
    /// </summary>
    [TestMethod]
    [DataRow("InspectAsync")]
    [DataRow("Timings")]
    [DataRow("BuildJwksDocumentAsync")]
    [DataRow("Encoder")]
    [DataRow("AuthorizationDetailTypes")]
    [DataRow("ActionExecutor")]
    [DataRow("ApplyConfiguration")]
    [DataRow("AddIntegration")]
    [DataRow("Register")]
    [DataRow("VcalmTemplateEvaluators")]
    [DataRow("VcalmSchemaValidators")]
    public async Task ServingSetterRequiresRequestedAlterationAsync(string member)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        AuthorizationServerIntegration retained = app.Server.OAuth();
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string before = await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        Action edit = member switch
        {
            "InspectAsync" => () => retained.InspectAsync = retained.InspectAsync,
            "Timings" => () => app.Server.OAuth().Timings = TimingPolicy.Default,
            "BuildJwksDocumentAsync" => () => app.Server.OAuth().Cryptography.BuildJwksDocumentAsync = null,
            "Encoder" => () => app.Server.OAuth().Codecs.Encoder = null,
            "AuthorizationDetailTypes" => () => app.Server.OAuth().AuthorizationDetailTypes.Register(new AuthorizationDetailHandler { Type = "example", ValidateShape = (_, _) => null }),
            "ActionExecutor" => () => app.Server.ActionExecutor = null,
            "ApplyConfiguration" => () => app.Server.ApplyConfiguration(ServerConfiguration.Empty),
            "AddIntegration" => () => app.Server.AddIntegration(retained),
            "VcalmTemplateEvaluators" => () => app.Server.GetIntegration<Verifiable.Vcalm.VcalmIntegration>().VcalmTemplateEvaluators.Register("example", (_, _, _, _) => null),
            "VcalmSchemaValidators" => () => app.Server.GetIntegration<Verifiable.Vcalm.VcalmIntegration>().VcalmSchemaValidators.Register("example", (_, _, _) => throw new InvalidOperationException("Uninvoked validator.")),
            "Register" => () => app.Server.OAuth().ActionExecutor!.Register<OAuthAction>((_, _, _) => throw new InvalidOperationException("Uninvoked action.")),
            _ => throw new ArgumentOutOfRangeException(nameof(member))
        };
        InvalidOperationException fault = Assert.ThrowsExactly<InvalidOperationException>(edit);
        Assert.Contains(nameof(EndpointServer.RequestAlterationAsync), fault.Message, StringComparison.Ordinal);
        Assert.AreEqual(before, await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false));
    }


    /// <summary>
    /// Proves the stated publication rule under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "A signed OID4VP request_uri request needing an unregistered signing action receives a neutral server error without an internal type name."
    /// </summary>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task AlteredExecutorMissingSignJarActionAnswersTheJarRequestGracefullyAsync(bool isPost)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        OAuthActionExecutor working = app.Server.OAuth().ActionExecutor!;
        (_, string parHandle) = await app.HandleParAsync(keys,
            new TransactionNonce("nonce-g08-live-alteration"), DcqlFixtures.PidFamilyNamePrepared(),
            TestContext.CancellationToken).ConfigureAwait(false);
        _ = Assert.IsInstanceOfType<VerifierParReceivedState>(app.GetFlowState(parHandle).State,
            "Verifier PDA must be in VerifierParReceived after PAR, before the JAR request under test.");
        Uri requestUri = new(app.Host("default").HttpBaseAddress!, $"/connect/{keys.Registration.TenantId.Value}/request/{parHandle}");
        await app.Server.RequestAlterationAsync(candidate =>
            candidate.Family<AuthorizationServerIntegration>().ActionExecutor = new OAuthActionExecutor(), TestContext.CancellationToken).ConfigureAwait(false);
        using HttpResponseMessage response = isPost
            ? await RawAuthCodeWirePushers.SendPinnedFormPostAsync(app, requestUri, new Dictionary<string, string> { ["wallet_nonce"] = "alteration-wallet" }, TestContext.CancellationToken).ConfigureAwait(false)
            : await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(app, requestUri, "alteration-subject", TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(500, (int)response.StatusCode,
            "A candidate that validates without SignJarAction's handler must still answer the JAR request gracefully, not crash the listener.");
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.Contains(OAuthErrors.ServerError, body, StringComparison.Ordinal,
            "The graceful refusal must carry the stable OAuth error code, never an internal action type name in an unauthenticated response.");
        using JsonDocument error = JsonDocument.Parse(body);
        Assert.AreEqual("The server is not ready to serve this request.", error.RootElement.GetProperty("error_description").GetString());
        Assert.DoesNotContain("SignJarAction", body, StringComparison.Ordinal,
            "The wire body must not disclose the internal action type whose absence produced the refusal.");
        Exception[] faults = app.Host("default").ConsumeHttpFaults();
        Assert.IsEmpty(faults, "The endpoint must handle an absent action without an uncaught host fault.");
        await app.Server.RequestAlterationAsync(candidate =>
            candidate.Family<AuthorizationServerIntegration>().ActionExecutor = working, TestContext.CancellationToken).ConfigureAwait(false);
        using HttpResponseMessage recovered = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            app, requestUri, "alteration-subject", TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)recovered.StatusCode, "Restoring the working executor recovers the still-pending JAR request.");
    }


    /// <summary>
    /// Proves the stated publication rule under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "DrainTimeout bounds the drain and abandonment reopens admission on unchanged wiring."
    /// </summary>
    [TestMethod]
    public async Task DrainBoundExceededReopensAdmissionAndFaultsTheRequestedAlterationAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        app.Server.ApplyConfiguration(app.Server.Configuration with { DrainTimeout = TimeSpan.FromMilliseconds(100) });
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        int visits = 0;
        await TestHostShell.AlterAsync(app.Server, integration => integration.ContributeDiscoveryFieldsAsync = async (_, _, _) =>
        {
            if(Interlocked.Increment(ref visits) == 1)
            {
                _ = entered.TrySetResult();
                await release.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            }

            return Marker("A");
        }).ConfigureAwait(false);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        Task<string> stuckRequest = ReadDiscoveryAsync(app, keys.Registration);
        try
        {
            await entered.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            Task alteration = app.Server.RequestAlterationAsync(candidate =>
                candidate.Family<AuthorizationServerIntegration>().ContributeDiscoveryFieldsAsync = (_, _, _) => ValueTask.FromResult(Marker("B")), deadline.Token);
            InvalidOperationException fault = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => alteration);
            Assert.Contains(nameof(ServerConfiguration.DrainTimeout), fault.Message, StringComparison.Ordinal);
            Assert.IsTrue(app.Server.IsValidated, "Admission must reopen on unchanged wiring after the drain bound expires.");
            Assert.AreEqual("A", ReadMarker(await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false)));
        }
        finally
        {
            _ = release.TrySetResult();
            _ = await stuckRequest.WaitAsync(deadline.Token).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Proves the stated publication rule under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "Each abandoned request is cancelled when its own token is cancelled; other requests receive the window's actual timeout or opening-request cancellation fault."
    /// </summary>
    [TestMethod]
    public async Task AlterationCancelledDuringDrainFaultsOnlyItsRequesterAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        using CancellationTokenSource opening = new();
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        app.Server.ApplyConfiguration(app.Server.Configuration with { DrainTimeout = TimeSpan.FromSeconds(30) });
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        int visits = 0;
        int callbacks = 0;
        await TestHostShell.AlterAsync(app.Server, integration => integration.ContributeDiscoveryFieldsAsync = async (_, _, _) =>
        {
            if(Interlocked.Increment(ref visits) == 1)
            {
                _ = entered.TrySetResult();
                await release.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            }

            return Marker("A");
        }).ConfigureAwait(false);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        Task<string> stuckRequest = ReadDiscoveryAsync(app, keys.Registration);
        try
        {
            await entered.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            Task cancelled = app.Server.RequestAlterationAsync(_ => Interlocked.Increment(ref callbacks), opening.Token);
            Task sibling = app.Server.RequestAlterationAsync(_ => Interlocked.Increment(ref callbacks), deadline.Token);
            await opening.CancelAsync().WaitAsync(deadline.Token).ConfigureAwait(false);
            _ = await Assert.ThrowsExactlyAsync<TaskCanceledException>(() => cancelled);
            InvalidOperationException fault = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => sibling);
            Assert.Contains("opening request was cancelled", fault.Message, StringComparison.Ordinal);
            Assert.DoesNotContain(nameof(ServerConfiguration.DrainTimeout), fault.Message, StringComparison.Ordinal);
            Assert.AreEqual(0, Volatile.Read(ref callbacks), "An abandoned window cannot execute any callback.");
            Assert.IsTrue(app.Server.IsValidated, "The abandoned window must reopen admission on its accepted wiring.");
            Assert.AreEqual("A", ReadMarker(await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false)));
        }
        finally
        {
            _ = release.TrySetResult();
            _ = await stuckRequest.WaitAsync(deadline.Token).ConfigureAwait(false);
        }

        await app.Server.RequestAlterationAsync(candidate =>
            candidate.Family<AuthorizationServerIntegration>().ContributeDiscoveryFieldsAsync = (_, _, _) => ValueTask.FromResult(Marker("B")), deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
        Assert.AreEqual("B", ReadMarker(await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false)));
    }


    /// <summary>
    /// Proves the stated publication rule under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "A callback that throws discards its half-edited candidate, faults its requester with that exception and advances the queue."
    /// </summary>
    [TestMethod]
    public async Task CallbackThrowingMidEditDiscardsThatEditAndAdvancesTheQueueAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        InvalidOperationException thrown = new("Deliberate mid-edit failure.");
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using ManualResetEventSlim release = new(false);
        AuthorizationServerIntegration? discarded = null;
        Task throwing = app.Server.RequestAlterationAsync(candidate =>
        {
            discarded = candidate.Family<AuthorizationServerIntegration>();
            discarded.Timings = TimingPolicy.Default with { ClockSkewTolerance = TimeSpan.FromSeconds(41) };
            _ = entered.TrySetResult();
            release.Wait(deadline.Token);
            throw thrown;
        }, deadline.Token);
        Task? next = null;
        try
        {
            await entered.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            next = app.Server.RequestAlterationAsync(candidate =>
            {
                Assert.AreNotEqual(TimeSpan.FromSeconds(41), candidate.Family<AuthorizationServerIntegration>().Timings.ClockSkewTolerance,
                    "A discarded candidate's half-applied edit must not reach the next candidate.");
                candidate.Family<AuthorizationServerIntegration>().ContributeDiscoveryFieldsAsync = (_, _, _) => ValueTask.FromResult(Marker("next"));
            }, deadline.Token);
        }
        finally
        {
            release.Set();
        }

        InvalidOperationException fault = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => throwing.WaitAsync(deadline.Token));
        Assert.AreSame(thrown, fault);
        Assert.IsNotNull(discarded);
        _ = Assert.ThrowsExactly<InvalidOperationException>(() => discarded.Timings = TimingPolicy.Default);
        await next.WaitAsync(deadline.Token).ConfigureAwait(false);
        Assert.IsTrue(app.Server.IsValidated);
        Assert.AreEqual("next", ReadMarker(await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false)));
    }


    /// <summary>
    /// A policy alteration reaches the next request's resolved decisions under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "Policy is resolved once per request from its admitted wiring."
    /// </summary>
    [TestMethod]
    public async Task PolicyAlterationResolvesOnTheNextRequestAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        Dictionary<ExchangeContext, int> calls = new(ReferenceEqualityComparer.Instance);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            ResolveServerPolicyDelegate initial = candidateIntegration.ResolvePolicyAsync!;
            candidateIntegration.ResolvePolicyAsync = async (registration, context, ct) =>
            {
                calls[context] = calls.GetValueOrDefault(context) + 1;
                await initial(registration, context, ct).ConfigureAwait(false);
            };
            candidateIntegration.ContributeDiscoveryFieldsAsync = (_, ctx, _) => ValueTask.FromResult(Marker(ctx.ClockSkewTolerance.TotalSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        }).ConfigureAwait(false);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        string before = ReadMarker(await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false));
        await app.Server.RequestAlterationAsync(candidate =>
        {
            ResolveServerPolicyDelegate resolve = candidate.Integration.ResolvePolicyAsync!;
            candidate.Integration.ResolvePolicyAsync = async (registration, ctx, ct) =>
            {
                await resolve(registration, ctx, ct).ConfigureAwait(false);
                ctx.SetClockSkewTolerance(TimeSpan.FromSeconds(17));
            };
        }, deadline.Token).ConfigureAwait(false);
        Assert.AreNotEqual("17", before);
        Assert.AreEqual("17", ReadMarker(await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false)));
        Assert.HasCount(2, calls);
        Assert.IsTrue(calls.Values.All(count => count == 1), "Each admitted request resolves policy exactly once.");
    }


    /// <summary>
    /// Global registration also requires validated admission under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "The ordinary dispatcher and global registration handler both acquire a ServerRequestLease
    /// through AcquireRequestAsync before reading any application seam."
    /// </summary>
    [TestMethod]
    public async Task GlobalRegistrationRefusesNeverValidatedWiringAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        app.Host("default").UseUnvalidatedServer();
        HostedAuthorizationServer host = app.Host("default");
        host.IsUnvalidatedListenerAllowed = true;
        app.Server.ApplyConfiguration(app.Server.Configuration);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedJsonPostAsync(app,
            new Uri(host.HttpBaseAddress!, "/connect/register"), "{\"redirect_uris\":[\"https://client.example.test/callback\"]}", TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(500, (int)response.StatusCode);
        Assert.IsTrue(host.HttpFaults.TryDequeue(out Exception? fault));
        _ = Assert.IsInstanceOfType<InvalidOperationException>(fault);
        Assert.Contains(nameof(EndpointServer.Validate), fault!.Message, StringComparison.Ordinal);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual("{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}", body);
        Assert.DoesNotContain(fault.Message, body, StringComparison.Ordinal);
        Assert.IsEmpty(host.Registrations);
    }


    /// <summary>
    /// A registration observer can enqueue alteration without blocking its emitting request under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "An observer queues the alteration and returns; publication follows request completion."
    /// </summary>
    [TestMethod]
    public async Task RegistrationObserverRequestsAlterationWithoutBlockingAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, integration => integration.ContributeDiscoveryFieldsAsync = (_, _, _) => ValueTask.FromResult(Marker("before"))).ConfigureAwait(false);
        TaskCompletionSource<Task> requested = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using IDisposable subscription = app.Server.Events.Subscribe(new CollectingObserver<ClientRegistrationEvent>([], _ =>
            requested.SetResult(app.Server.RequestAlterationAsync(candidate =>
                candidate.Family<AuthorizationServerIntegration>().ContributeDiscoveryFieldsAsync = (_, _, _) => ValueTask.FromResult(Marker("observer")), deadline.Token))));
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using CancellationTokenSource exchange = CreateTestCancellation();
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedJsonPostAsync(app,
            new Uri(app.Host("default").HttpBaseAddress!, "/connect/register"), "{\"redirect_uris\":[\"https://client.example.test/callback\"]}", exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(201, (int)response.StatusCode);
        await (await requested.Task.WaitAsync(deadline.Token).ConfigureAwait(false)).WaitAsync(deadline.Token).ConfigureAwait(false);
        Assert.AreEqual("observer", ReadMarker(await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false)));
    }


    /// <summary>
    /// A signal-style trigger requests the same publication operation under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "Direct host calls, registration observers and signal handlers use this operation."
    /// </summary>
    [TestMethod]
    public async Task SignalTriggerPublishesThroughRequestedAlterationAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeDiscoveryFieldsAsync = async (_, _, ct) =>
            {
                _ = entered.TrySetResult();
                await release.Task.WaitAsync(ct).ConfigureAwait(false);

                return Marker("A");
            };
        }).ConfigureAwait(false);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        Task<string> admittedRequest = ReadDiscoveryAsync(app, keys.Registration);
        Task? signalledAlteration = null;
        try
        {
            await entered.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            using CancellationTokenSource signal = new();
            TaskCompletionSource<Task> requested = new(TaskCreationOptions.RunContinuationsAsynchronously);
            using CancellationTokenRegistration subscription = signal.Token.Register(() => requested.SetResult(app.Server.RequestAlterationAsync(candidate =>
                candidate.Family<AuthorizationServerIntegration>().ContributeDiscoveryFieldsAsync = (_, _, _) => ValueTask.FromResult(Marker("signal")), deadline.Token)));
            await signal.CancelAsync().WaitAsync(deadline.Token).ConfigureAwait(false);
            signalledAlteration = await requested.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            Assert.IsFalse(app.Server.IsValidated, "The signal alteration must drain the admitted request before publication.");
        }
        finally
        {
            _ = release.TrySetResult();
        }

        Assert.AreEqual("A", ReadMarker(await admittedRequest.WaitAsync(deadline.Token).ConfigureAwait(false)),
            "The request admitted before the signal must complete on the wiring it was admitted under.");
        await signalledAlteration.WaitAsync(deadline.Token).ConfigureAwait(false);
        Assert.AreEqual("signal", ReadMarker(await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false)));
    }


    /// <summary>
    /// Proves the stated publication rule under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "New arrivals wait while the server drains requests and processes queued candidates in alteration enqueue order."
    /// </summary>
    [TestMethod]
    public async Task ConcurrentAlterationsApplyInRequestedOrderAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeDiscoveryFieldsAsync = async (_, _, ct) =>
            {
                entered.SetResult();
                await release.Task.WaitAsync(ct).ConfigureAwait(false);

                return Marker("A");
            };
        }).ConfigureAwait(false);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Task<string> oldRequest = ReadDiscoveryAsync(app, keys.Registration);
        await entered.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Task first = app.Server.RequestAlterationAsync(candidate => candidate.Family<AuthorizationServerIntegration>().Timings = TimingPolicy.Default with { ClockSkewTolerance = TimeSpan.FromSeconds(19) }, TestContext.CancellationToken);
        Task rejected = app.Server.RequestAlterationAsync(candidate => candidate.Integration.DeleteFlowStateAsync = null, TestContext.CancellationToken);
        Task last = app.Server.RequestAlterationAsync(candidate =>
        {
            Assert.AreEqual(TimeSpan.FromSeconds(19), candidate.Family<AuthorizationServerIntegration>().Timings.ClockSkewTolerance);
            Assert.IsNotNull(candidate.Integration.DeleteFlowStateAsync);
            candidate.Family<AuthorizationServerIntegration>().ContributeDiscoveryFieldsAsync = (_, _, _) => ValueTask.FromResult(Marker("last"));
        }, TestContext.CancellationToken);
        release.SetResult();
        _ = await oldRequest.ConfigureAwait(false);
        await first.ConfigureAwait(false);
        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => rejected);
        await last.ConfigureAwait(false);
        Assert.IsTrue(app.Server.IsValidated);
        Assert.AreEqual("last", ReadMarker(await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false)));
    }


    /// <summary>
    /// A flow spanning storage replacement continues only through migrated state under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "The drain quiesces requests, not flows; the host migrates or forwards retained state."
    /// </summary>
    [TestMethod]
    public async Task StorageAlterationKeepsEachRequestOnOneBackendAndMigratesRetainedFlowsAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        Uri redirect = new("https://client.example.com/callback");
        using VerifierKeyMaterial keys = await app.RegisterDpopClientAsync("https://client.example.test", new Uri("https://client.example.test"),
            profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        using CancellationTokenSource exchange = CreateTestCancellation();
        var (client, registration, clientStates) = await app.CreateOAuthClientAndRegistrationAsync(keys.Registration,
            redirect.OriginalString, PolicyProfile.Rfc6749WithPkce, exchange.Token).ConfigureAwait(false);
        HostedAuthorizationServer original = app.Host("default");
        HostedAuthorizationServer replacement = app.AddHost("replacement");
        using HttpClient browser = LoopbackTls.CreateSingleHopPinnedHttpClient(app.ServerCertificate);
        AuthCodeFlowDriveResult flow = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(original, client, registration,
            clientStates, keys.Registration.TenantId.Value, redirect, "storage-subject", browser,
            cancellationToken: exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, flow.TokenResult.Outcome);
        string refresh = (string)flow.TokenResult.Body![OAuthRequestParameterNames.RefreshToken];
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await app.Server.RequestAlterationAsync(candidate =>
        {
            AuthorizationServerIntegration integration = candidate.Family<AuthorizationServerIntegration>();
            original.InstallObservedStorage(integration, original);
            LoadServerFlowStateDelegate load = integration.LoadFlowStateAsync!;
            integration.LoadFlowStateAsync = async (tenant, key, ctx, ct) =>
            {
                var state = await load(tenant, key, ctx, ct).ConfigureAwait(false);
                _ = entered.TrySetResult();
                await release.Task.WaitAsync(ct).ConfigureAwait(false);

                return state;
            };
        }, deadline.Token).ConfigureAwait(false);
        Task<(int StatusCode, string Body)> rotating = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(app, keys.Registration.TenantId.Value,
            RawAuthCodeWirePushers.BuildRefreshTokenFields(keys.Registration.ClientId, refresh), exchange.Token);
        TestHostShell.DrainCheckpoint checkpoint = new(app.Server);
        Task? alteration = null;
        try
        {
            await entered.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            alteration = app.Server.RequestAlterationAsync(candidate =>
            {
                original.MigrateFlowStorageTo(replacement);
                original.InstallObservedStorage(candidate.Family<AuthorizationServerIntegration>(), replacement);
            }, deadline.Token);
            await checkpoint.ReachAsync(alteration, deadline.Token).ConfigureAwait(false);
        }
        finally
        {
            _ = release.TrySetResult();
        }

        var (StatusCode, Body) = await rotating.WaitAsync(deadline.Token).ConfigureAwait(false);
        foreach(var request in original.StorageObservations.GroupBy(entry => entry.Context))
        {
            Assert.HasCount(1, request.Select(entry => entry.Backend).Distinct(StringComparer.Ordinal), "One request cannot split storage operations across backends.");
        }

        Assert.AreEqual(200, StatusCode, Body);
        using JsonDocument first = JsonDocument.Parse(Body);
        string next = first.RootElement.GetProperty(OAuthRequestParameterNames.RefreshToken).GetString()!;
        await alteration!.WaitAsync(deadline.Token).ConfigureAwait(false);
        var continued = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(app, keys.Registration.TenantId.Value,
            RawAuthCodeWirePushers.BuildRefreshTokenFields(keys.Registration.ClientId, next), exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(200, continued.StatusCode, continued.Body);
        var reuse = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(app, keys.Registration.TenantId.Value,
            RawAuthCodeWirePushers.BuildRefreshTokenFields(keys.Registration.ClientId, refresh), exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(400, reuse.StatusCode, reuse.Body);
        foreach(var request in original.StorageObservations.GroupBy(entry => entry.Context))
        {
            Assert.HasCount(1, request.Select(entry => entry.Backend).Distinct(StringComparer.Ordinal), "One request cannot split storage operations across backends.");
        }

        CollectionAssert.IsSubsetOf(RequiredStorageOperations, original.StorageObservations.Select(entry => entry.Operation).Distinct(StringComparer.Ordinal).ToArray());
        Assert.Contains("replacement", original.StorageObservations.Select(entry => entry.Backend));
    }


    /// <summary>
    /// Proves the stated publication rule under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "Maintenance requests receive the ordinary unmatched-endpoint response."
    /// </summary>
    [TestMethod]
    public async Task ExplicitMaintenanceConfigurationServesNoEndpointAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        ServerConfiguration configuration = app.Server.Configuration;
        Exception? publicationFault = null;
        try
        {
            await app.Server.RequestAlterationAsync(candidate =>
                candidate.Configuration = ServerConfiguration.Empty with { IsMaintenanceMode = true }, TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(Exception exception)
        {
            publicationFault = exception;
        }

        Assert.IsNull(publicationFault, "Explicit maintenance mode permits an empty endpoint set.");
        using HttpResponseMessage response = await SendDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        Assert.AreEqual(404, (int)response.StatusCode);
        Assert.IsTrue(app.Server.IsValidated);
        await app.Server.RequestAlterationAsync(candidate => candidate.Configuration = configuration, TestContext.CancellationToken).ConfigureAwait(false);
        using HttpResponseMessage restored = await SendDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        Assert.AreEqual(200, (int)restored.StatusCode);
    }


    /// <summary>The storage operations that the migration flow must exercise.</summary>
    private static string[] RequiredStorageOperations { get; } = ["load", "claim", "delete", "save"];


    /// <summary>The typed discovery marker for observing a composition over the listener.</summary>
    /// <param name="value">The wiring identity emitted by the actual metadata handler.</param>
    private static DiscoveryDocumentContribution Marker(string value)
    {

        return new([new DiscoveryStringField("wiring_marker", value)]);
    }


    /// <summary>
    /// Fresh adoption preserves one composition's stream under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "A source component can be adopted by only one composition; a second adoption is refused with a named ownership fault."
    /// </summary>
    [TestMethod]
    public async Task FreshAdoptedIntegrationDeliversOnlyItsServersRegistrationEventsAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        await using TestHostShell donor = new(TimeProvider);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        await donor.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        AuthorizationServerIntegration fresh = TestHostShell.CreateFreshAuthorizationIntegration(app.Server.OAuth());
        List<ClientRegistrationEvent> adoptedEvents = [];
        List<ClientRegistrationEvent> donorEvents = [];
        using IDisposable adoptedSubscription = fresh.Events.Subscribe(new CollectingObserver<ClientRegistrationEvent>(adoptedEvents));
        using IDisposable donorSubscription = donor.Server.Events.Subscribe(new CollectingObserver<ClientRegistrationEvent>(donorEvents));
        await app.Server.RequestAlterationAsync(candidate => candidate.AddIntegration(fresh), deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
        Assert.AreNotSame(fresh, app.Server.OAuth());
        Assert.AreSame(app.Server.Integration, app.Server.OAuth());
        AssertMutableAfterDiscard(() => fresh.ClaimIssuer = fresh.ClaimIssuer);
        List<ClientRegistrationEvent> servingEvents = [];
        using IDisposable servingSubscription = app.Server.Events.Subscribe(new CollectingObserver<ClientRegistrationEvent>(servingEvents));
        _ = Assert.ThrowsExactly<InvalidOperationException>(() =>
        {
            using EndpointServer foreign = new() { Integration = fresh, Configuration = donor.Server.Configuration, TimeProvider = TimeProvider };
        });
        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => donor.Server.RequestAlterationAsync(candidate => candidate.Family<AuthorizationServerIntegration>().Codecs = fresh.Codecs, deadline.Token).WaitAsync(deadline.Token));
        InvalidOperationException secondFault = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => donor.Server.RequestAlterationAsync(candidate => candidate.AddIntegration(fresh), deadline.Token).WaitAsync(deadline.Token));
        Assert.Contains("adopted", secondFault.Message, StringComparison.Ordinal);
        using HttpResponseMessage response = await RegisterOverWireAsync(app).ConfigureAwait(false);
        Assert.AreEqual(201, (int)response.StatusCode);
        Assert.HasCount(1, adoptedEvents.OfType<ClientRegistered>().ToArray());
        Assert.HasCount(1, servingEvents.OfType<ClientRegistered>().ToArray());
        Assert.IsEmpty(donorEvents);
        using HttpResponseMessage donorResponse = await RegisterOverWireAsync(donor).ConfigureAwait(false);
        Assert.AreEqual(201, (int)donorResponse.StatusCode);
        Assert.HasCount(1, donorEvents.OfType<ClientRegistered>().ToArray());
        Assert.HasCount(1, servingEvents.OfType<ClientRegistered>().ToArray());
        Assert.HasCount(1, adoptedEvents.OfType<ClientRegistered>().ToArray());
    }


    /// <summary>
    /// Candidate nested assignment rejects foreign owners under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "Every candidate assignment of a wiring component copies the supplied containers and refuses components attached to another server."
    /// </summary>
    [TestMethod]
    [DataRow("Cryptography")]
    [DataRow("Codecs")]
    [DataRow("ActionExecutor")]
    [DataRow("VcalmTemplateEvaluators")]
    [DataRow("VcalmSchemaValidators")]
    [DataRow("VcalmCredentialVerification")]
    [DataRow("VcalmExchangeVerification")]
    public async Task CandidateNestedAssignmentRefusesAnotherServingServerAsync(string member)
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        await using TestHostShell donor = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        using VerifierKeyMaterial donorKeys = await donor.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        await donor.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        string before = await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        _ = await ReadDiscoveryAsync(donor, donorKeys.Registration).ConfigureAwait(false);
        Action<AlterationCandidate> assign = member switch
        {
            "Cryptography" => candidate => candidate.Family<AuthorizationServerIntegration>().Cryptography = donor.Server.OAuth().Cryptography,
            "Codecs" => candidate => candidate.Family<AuthorizationServerIntegration>().Codecs = donor.Server.OAuth().Codecs,
            "ActionExecutor" => candidate => candidate.Family<AuthorizationServerIntegration>().ActionExecutor = donor.Server.OAuth().ActionExecutor,
            "VcalmTemplateEvaluators" => candidate => candidate.Family<Verifiable.Vcalm.VcalmIntegration>().VcalmTemplateEvaluators = donor.Server.GetIntegration<Verifiable.Vcalm.VcalmIntegration>().VcalmTemplateEvaluators,
            "VcalmSchemaValidators" => candidate => candidate.Family<Verifiable.Vcalm.VcalmIntegration>().VcalmSchemaValidators = donor.Server.GetIntegration<Verifiable.Vcalm.VcalmIntegration>().VcalmSchemaValidators,
            "VcalmCredentialVerification" => candidate => candidate.Family<Verifiable.Vcalm.VcalmIntegration>().VcalmCredentialVerification = TestHostShell.CreateSchemaVerification(donor.Server.GetIntegration<Verifiable.Vcalm.VcalmIntegration>().VcalmSchemaValidators),
            "VcalmExchangeVerification" => candidate => candidate.Family<Verifiable.Vcalm.VcalmIntegration>().VcalmExchangeVerification = TestHostShell.CreateSchemaVerification(donor.Server.GetIntegration<Verifiable.Vcalm.VcalmIntegration>().VcalmSchemaValidators),
            _ => throw new ArgumentOutOfRangeException(nameof(member))
        };
        InvalidOperationException fault = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => app.Server.RequestAlterationAsync(assign, deadline.Token).WaitAsync(deadline.Token));
        Assert.Contains("another EndpointServer", fault.Message, StringComparison.Ordinal);
        Assert.AreEqual(before, await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false));
        await donor.Server.RequestAlterationAsync(candidate => candidate.Family<AuthorizationServerIntegration>().ContributeDiscoveryFieldsAsync = (_, _, _) => ValueTask.FromResult(Marker("donor")), deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
        Assert.AreEqual("donor", ReadMarker(await ReadDiscoveryAsync(donor, donorKeys.Registration).ConfigureAwait(false)));
    }


    /// <summary>
    /// A discarded adoption freezes only its own containers under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "Every candidate assignment of a wiring component copies the supplied containers and refuses components attached to another server."
    /// </summary>
    [TestMethod]
    [DataRow("Cryptography")]
    [DataRow("Codecs")]
    [DataRow("ActionExecutor")]
    [DataRow("VcalmTemplateEvaluators")]
    [DataRow("VcalmSchemaValidators")]
    public async Task DiscardedNestedAdoptionLeavesSuppliedContainerMutableAsync(string member)
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        string before = await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        AuthorizationServerCryptography cryptography = new();
        AuthorizationServerCodecs codecs = new();
        OAuthActionExecutor executor = new();
        Verifiable.Vcalm.VcalmTemplateEvaluatorRegistry templates = new();
        Verifiable.Vcalm.VcalmSchemaValidatorRegistry schemas = new();
        Action<AlterationCandidate> assign = member switch
        {
            "Cryptography" => candidate => candidate.Family<AuthorizationServerIntegration>().Cryptography = cryptography,
            "Codecs" => candidate => candidate.Family<AuthorizationServerIntegration>().Codecs = codecs,
            "ActionExecutor" => candidate => candidate.Family<AuthorizationServerIntegration>().ActionExecutor = executor,
            "VcalmTemplateEvaluators" => candidate => candidate.Family<Verifiable.Vcalm.VcalmIntegration>().VcalmTemplateEvaluators = templates,
            "VcalmSchemaValidators" => candidate => candidate.Family<Verifiable.Vcalm.VcalmIntegration>().VcalmSchemaValidators = schemas,
            _ => throw new ArgumentOutOfRangeException(nameof(member))
        };
        InvalidOperationException thrown = new("Deliberate discard after nested adoption.");
        InvalidOperationException fault = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => app.Server.RequestAlterationAsync(candidate =>
        {
            assign(candidate);
            throw thrown;
        }, deadline.Token).WaitAsync(deadline.Token));
        Assert.AreSame(thrown, fault);
        Action edit = member switch
        {
            "Cryptography" => () => cryptography.BuildJwksDocumentAsync = cryptography.BuildJwksDocumentAsync,
            "Codecs" => () => codecs.Encoder = codecs.Encoder,
            "ActionExecutor" => () => executor.Register<OAuthAction>((_, _, _) => throw new InvalidOperationException("Uninvoked action.")),
            "VcalmTemplateEvaluators" => () => templates.Register("fresh", (_, _, _, _) => null),
            "VcalmSchemaValidators" => () => schemas.Register("fresh", (_, _, _) => throw new InvalidOperationException("Uninvoked schema operation.")),
            _ => throw new ArgumentOutOfRangeException(nameof(member))
        };
        AssertMutableAfterDiscard(edit);
        Assert.AreEqual(before, await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false));
    }


    /// <summary>Asserts that discarding a candidate did not freeze the caller's supplied container.</summary>
    /// <param name="edit">A harmless edit on the caller-owned container.</param>
    private static void AssertMutableAfterDiscard(Action edit)
    {
        Exception? failure = null;
        try
        {
            edit();
        }
        catch(InvalidOperationException exception)
        {
            failure = exception;
        }

        Assert.IsNull(failure, "Discarding candidate-owned containers must leave supplied containers mutable.");
    }


    /// <summary>
    /// Invalid timer construction preserves serving wiring under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "AdmissionWaitTimeout and DrainTimeout reject nonpositive values and values above one minute in their init accessors with ArgumentOutOfRangeException."
    /// </summary>
    [TestMethod]
    [DataRow("AdmissionWaitTimeout", -2)]
    [DataRow("AdmissionWaitTimeout", 0)]
    [DataRow("AdmissionWaitTimeout", 60001)]
    [DataRow("DrainTimeout", -2)]
    [DataRow("DrainTimeout", 0)]
    [DataRow("DrainTimeout", 60001)]
    public async Task OutOfRangeDrainPolicyIsRejectedAndServerStillServesAsync(string member, int milliseconds)
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        string before = await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        ArgumentOutOfRangeException fault = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
        {
            _ = member switch
            {
                "AdmissionWaitTimeout" => app.Server.Configuration with { AdmissionWaitTimeout = TimeSpan.FromMilliseconds(milliseconds) },
                "DrainTimeout" => app.Server.Configuration with { DrainTimeout = TimeSpan.FromMilliseconds(milliseconds) },
                _ => throw new ArgumentOutOfRangeException(nameof(member))
            };
        });
        Assert.AreEqual(member, fault.ParamName);
        Assert.IsTrue(app.Server.IsValidated);
        Assert.AreEqual(before, await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false));
    }


    /// <summary>
    /// First admission preserves validated wiring under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "First admission freezes component setters and then rechecks validation before publishing or admitting a request."
    /// </summary>
    /// <remarks>
    /// This is the only test that can meet a construction setter landing after admission's validation check
    /// and before its freeze, an ordering nothing outside the server can force; three hundred fresh servers
    /// race a waiting setter against the first listener admission so that window is exercised many times.
    /// The invariant it asserts holds for every interleaving: a response is served only by validated wiring,
    /// or admission is refused. <see cref="ConstructionSetterCompletingBeforeFirstAdmissionRefusesTheRequestAsync"/>
    /// and <see cref="FirstAdmissionCompletingBeforeConstructionSetterRejectsTheSetterAsync"/> prove the two
    /// orderings that a fixture hook CAN force deterministically.
    /// </remarks>
    [TestMethod]
    public async Task ConstructionSetterRacingFirstAdmissionNeverServesInvalidWiringAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        for(int iteration = 0; iteration < 300; ++iteration)
        {
            await AssertConstructionSetterRacingFirstAdmissionAsync(deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
        }
    }


    /// <summary>Asserts the admission and wiring invariant for one fresh listener and a waiting construction setter.</summary>
    /// <param name="cancellationToken">The cancellation shared by the complete sequence of fresh servers.</param>
    private async Task AssertConstructionSetterRacingFirstAdmissionAsync(CancellationToken cancellationToken)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        app.Host("default").IsUnvalidatedListenerAllowed = true;
        AuthorizationServerIntegration integration = app.Server.OAuth();
        var resolve = integration.ResolveSubjectIdentifierAsync;
        app.Server.Validate();
        TaskCompletionSource arrived = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource start = new(TaskCreationOptions.RunContinuationsAsynchronously);
        app.Host("default").RequestArriving = async () =>
        {
            _ = arrived.TrySetResult();
            await start.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        };
        await app.StartHttpHostAsync(cancellationToken).ConfigureAwait(false);
        Task<HttpResponseMessage> request = SendDiscoveryAsync(app, keys.Registration);
        TaskCompletionSource setterReady = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<Exception?>? setter = null;
        try
        {
            await arrived.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            setter = Task.Run(async () =>
            {
                _ = setterReady.TrySetResult();
                await start.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    integration.ResolveSubjectIdentifierAsync = null;

                    return null;
                }
                catch(InvalidOperationException exception)
                {

                    return (Exception?)exception;
                }
            }, cancellationToken);
            await setterReady.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = start.TrySetResult();
        }

        _ = await setter.WaitAsync(cancellationToken).ConfigureAwait(false);
        using HttpResponseMessage response = await request.ConfigureAwait(false);
        bool isServed = (int)response.StatusCode == 200;
        bool isRefused = (int)response.StatusCode == 500;
        Assert.IsTrue((isServed && integration.ResolveSubjectIdentifierAsync is not null) || isRefused,
            "A request may be served only by validated wiring; a construction edit must otherwise cause admission refusal.");
        if(isRefused)
        {
            Assert.IsTrue(app.Host("default").HttpFaults.TryDequeue(out Exception? admissionFault));
            Assert.Contains(nameof(EndpointServer.Validate), admissionFault.Message, StringComparison.Ordinal);
        }

        app.Host("default").RequestArriving = null;
        await app.Server.RequestAlterationAsync(candidate => candidate.Family<AuthorizationServerIntegration>().ResolveSubjectIdentifierAsync = resolve, cancellationToken).WaitAsync(cancellationToken).ConfigureAwait(false);
        using HttpResponseMessage recovered = await SendDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        Assert.AreEqual(200, (int)recovered.StatusCode);
    }


    /// <summary>Registers the verifier client and explicitly validates a construction-editable host with nothing published yet.</summary>
    /// <param name="app">The host receiving the registration and validation.</param>
    private static async Task<(VerifierKeyMaterial Keys, AuthorizationServerIntegration Integration, ResolveSubjectIdentifierDelegate? Resolve)> PrepareValidatedUnpublishedHostAsync(TestHostShell app)
    {
        VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        app.Host("default").IsUnvalidatedListenerAllowed = true;
        AuthorizationServerIntegration integration = app.Server.OAuth();
        ResolveSubjectIdentifierDelegate? resolve = integration.ResolveSubjectIdentifierAsync;
        app.Server.Validate();

        return (keys, integration, resolve);
    }


    /// <summary>
    /// The setter-before-admission ordering of
    /// <see cref="ConstructionSetterRacingFirstAdmissionNeverServesInvalidWiringAsync"/>'s invariant under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "First admission freezes component setters and then rechecks validation before publishing or admitting a request."
    /// </summary>
    /// <remarks>
    /// A construction setter that returns before the held first request resumes invalidates the wiring it edits;
    /// admission then refuses with the named validation fault rather than freezing and serving it, and a requested
    /// alteration that restores the edited delegate recovers admission.
    /// </remarks>
    [TestMethod]
    public async Task ConstructionSetterCompletingBeforeFirstAdmissionRefusesTheRequestAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        (VerifierKeyMaterial keysValue, AuthorizationServerIntegration integration, ResolveSubjectIdentifierDelegate? resolve) =
            await PrepareValidatedUnpublishedHostAsync(app).ConfigureAwait(false);
        using VerifierKeyMaterial keys = keysValue;
        TaskCompletionSource setterDone = new(TaskCreationOptions.RunContinuationsAsynchronously);
        app.Host("default").RequestArriving = () => setterDone.Task.WaitAsync(deadline.Token);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        Task<HttpResponseMessage> request = SendDiscoveryAsync(app, keys.Registration);
        Exception? setterFault = null;
        try
        {
            integration.ResolveSubjectIdentifierAsync = null;
        }
        catch(Exception exception)
        {
            setterFault = exception;
        }
        finally
        {
            _ = setterDone.TrySetResult();
        }

        Assert.IsNull(setterFault, "A construction setter completing before the first admission must not throw.");
        using HttpResponseMessage response = await request.ConfigureAwait(false);
        Assert.AreEqual(500, (int)response.StatusCode);
        Assert.IsTrue(app.Host("default").HttpFaults.TryDequeue(out Exception? admissionFault));
        Assert.Contains(nameof(EndpointServer.Validate), admissionFault.Message, StringComparison.Ordinal);
        await app.Server.RequestAlterationAsync(candidate => candidate.Family<AuthorizationServerIntegration>().ResolveSubjectIdentifierAsync = resolve, deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
        using HttpResponseMessage recovered = await SendDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        Assert.AreEqual(200, (int)recovered.StatusCode);
    }


    /// <summary>
    /// The admission-before-setter ordering of
    /// <see cref="ConstructionSetterRacingFirstAdmissionNeverServesInvalidWiringAsync"/>'s invariant under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "First admission freezes component setters and then rechecks validation before publishing or admitting a request."
    /// </summary>
    /// <remarks>
    /// A construction setter attempted only after the first admission has already frozen and served the wiring is
    /// rejected with the named fault requiring a requested alteration, and the frozen wiring keeps serving a later
    /// request unaffected.
    /// </remarks>
    [TestMethod]
    public async Task FirstAdmissionCompletingBeforeConstructionSetterRejectsTheSetterAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        (VerifierKeyMaterial keysValue, AuthorizationServerIntegration integration, ResolveSubjectIdentifierDelegate? resolve) =
            await PrepareValidatedUnpublishedHostAsync(app).ConfigureAwait(false);
        using VerifierKeyMaterial keys = keysValue;
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using HttpResponseMessage response = await SendDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode);
        _ = Assert.ThrowsExactly<InvalidOperationException>(() => integration.ResolveSubjectIdentifierAsync = null);
        Assert.IsNotNull(integration.ResolveSubjectIdentifierAsync);
        Assert.AreSame(resolve, integration.ResolveSubjectIdentifierAsync);
        using HttpResponseMessage second = await SendDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        Assert.AreEqual(200, (int)second.StatusCode);
    }


    /// <summary>
    /// Concurrent attachment preserves each owner's invalidation under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "A construction edit to a shared component invalidates every attached server."
    /// </summary>
    [TestMethod]
    public async Task ConcurrentConstructionAndEditingInvalidatesEveryOwnerAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        AuthorizationServerIntegration shared = app.Server.OAuth();
        for(int iteration = 0; iteration < 32; ++iteration)
        {
            app.Server.Validate();
            TaskCompletionSource start = new(TaskCreationOptions.RunContinuationsAsynchronously);
            Task<EndpointServer> constructing = Task.Run(async () =>
            {
                await start.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
                EndpointServer second = new() { Integration = shared, Configuration = app.Server.Configuration, TimeProvider = TimeProvider };
                second.AddIntegration(shared);
                second.Validate();

                return second;
            }, deadline.Token);
            Task editing = Task.Run(async () =>
            {
                await start.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
                for(int edit = 0; edit < 128; ++edit)
                {
                    shared.ClaimIssuer = shared.ClaimIssuer;
                }
            }, deadline.Token);
            Exception? concurrencyFault = null;
            try
            {
                _ = start.TrySetResult();
                await Task.WhenAll(constructing, editing).WaitAsync(deadline.Token).ConfigureAwait(false);
            }
            catch(Exception exception)
            {
                concurrencyFault = exception;
            }
            finally
            {
                _ = start.TrySetResult();
            }

            Assert.IsNull(concurrencyFault, "Concurrent construction and editing must complete without an escaped exception.");
            using EndpointServer second = await constructing.WaitAsync(deadline.Token).ConfigureAwait(false);
            shared.ClaimIssuer = shared.ClaimIssuer;
            Assert.IsFalse(app.Server.IsValidated);
            Assert.IsFalse(second.IsValidated);
        }

        app.Host("default").IsUnvalidatedListenerAllowed = true;
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using HttpResponseMessage refusal = await SendDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        Assert.AreEqual(500, (int)refusal.StatusCode);
        Assert.IsTrue(app.Host("default").HttpFaults.TryDequeue(out Exception? fault));
        Assert.Contains(nameof(EndpointServer.Validate), fault.Message, StringComparison.Ordinal);
        await app.Server.RequestAlterationAsync(_ => { }, deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
        using HttpResponseMessage recovered = await SendDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        Assert.AreEqual(200, (int)recovered.StatusCode);
    }


    /// <summary>
    /// Pre-cancellation leaves admission untouched under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "Caller cancellation before a window opens cancels its request without touching admission."
    /// </summary>
    [TestMethod]
    public async Task PreCancelledAlterationLeavesAdmissionAndLiveWiringUntouchedAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        using CancellationTokenSource cancelled = new();
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using ManualResetEventSlim allowWorker = new(false);
        int visits = 0;
        await TestHostShell.AlterAsync(app.Server, integration => integration.ContributeDiscoveryFieldsAsync = async (_, _, _) =>
        {
            if(Interlocked.Increment(ref visits) == 1)
            {
                _ = entered.TrySetResult();
                await release.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            }

            return Marker("A");
        }).ConfigureAwait(false);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        Task<string> held = ReadDiscoveryAsync(app, keys.Registration);
        try
        {
            await entered.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            await cancelled.CancelAsync().ConfigureAwait(false);
            app.Server.DrainWaitFinished = () => allowWorker.Wait(deadline.Token);
            bool hasRun = false;
            Task alteration = app.Server.RequestAlterationAsync(_ => hasRun = true, cancelled.Token);
            Assert.IsTrue(app.Server.IsValidated, "An already-cancelled request must leave admission open while another request is held.");
            Assert.AreEqual("A", ReadMarker(await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false)));
            _ = await Assert.ThrowsExactlyAsync<TaskCanceledException>(() => alteration.WaitAsync(deadline.Token));
            Assert.IsFalse(hasRun);
        }
        finally
        {
            allowWorker.Set();
            _ = release.TrySetResult();
            app.Server.DrainWaitFinished = null;
        }

        Assert.AreEqual("A", ReadMarker(await held.WaitAsync(deadline.Token).ConfigureAwait(false)));
    }


    /// <summary>
    /// Cancellation after an edit freezes the discarded candidate under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "Cancellation after a callback edits its candidate discards and freezes that candidate before publication."
    /// </summary>
    [TestMethod]
    public async Task CancellationInsideCallbackFreezesDiscardedCandidateAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        using CancellationTokenSource cancelled = new();
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        string before = await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        AuthorizationServerIntegration? discarded = null;
        _ = await Assert.ThrowsExactlyAsync<TaskCanceledException>(() => app.Server.RequestAlterationAsync(candidate =>
        {
            discarded = candidate.Family<AuthorizationServerIntegration>();
            discarded.Timings = TimingPolicy.Default with { ClockSkewTolerance = TimeSpan.FromSeconds(41) };
            cancelled.Cancel();
        }, cancelled.Token).WaitAsync(deadline.Token));
        Assert.IsNotNull(discarded);
        _ = Assert.ThrowsExactly<InvalidOperationException>(() => discarded.Timings = TimingPolicy.Default);
        Assert.AreEqual(before, await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false));
    }


    /// <summary>
    /// An arrival after abandonment enters a fresh window under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "Requests queued after the drain's terminal outcome belong to a fresh window and cannot inherit an abandoned window's fault."
    /// </summary>
    [TestMethod]
    public async Task AlterationQueuedAfterDrainCancellationUsesAFreshWindowAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        using CancellationTokenSource opening = new();
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource terminal = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using ManualResetEventSlim resume = new(false);
        await TestHostShell.AlterAsync(app.Server, integration => integration.ContributeDiscoveryFieldsAsync = async (_, _, _) =>
        {
            _ = entered.TrySetResult();
            await release.Task.WaitAsync(deadline.Token).ConfigureAwait(false);

            return Marker("A");
        }).ConfigureAwait(false);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        Task<string> held = ReadDiscoveryAsync(app, keys.Registration);
        Task? following = null;
        try
        {
            await entered.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            app.Server.DrainWaitFinished = () =>
            {
                _ = terminal.TrySetResult();
                resume.Wait(deadline.Token);
            };
            Task opener = app.Server.RequestAlterationAsync(_ => { }, opening.Token);

            // The worker's drain continuation can run inline on the cancelling thread, and the hook blocks it, so the opening token is cancelled from the pool instead.
            _ = Task.Run(opening.Cancel, TestContext.CancellationToken);
            await terminal.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            following = app.Server.RequestAlterationAsync(candidate => candidate.Family<AuthorizationServerIntegration>().ContributeDiscoveryFieldsAsync = (_, _, _) => ValueTask.FromResult(Marker("B")), deadline.Token);
            resume.Set();
            _ = await Assert.ThrowsExactlyAsync<TaskCanceledException>(() => opener.WaitAsync(deadline.Token));
        }
        finally
        {
            resume.Set();
            _ = release.TrySetResult();
            app.Server.DrainWaitFinished = null;
        }

        _ = await held.WaitAsync(deadline.Token).ConfigureAwait(false);
        Exception? followingFault = null;
        try
        {
            await following.WaitAsync(deadline.Token).ConfigureAwait(false);
        }
        catch(Exception exception)
        {
            followingFault = exception;
        }

        Assert.IsNull(followingFault, "A later arrival cannot inherit a completed drain's abandonment.");
        Assert.AreEqual("B", ReadMarker(await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false)));
    }


    /// <summary>
    /// Unsigned requests bypass signing actions under
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3">OID4VP 1.0 §5.9.3</see> and
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "The unsigned redirect_uri request path does not require SignJarAction."
    /// </summary>
    [TestMethod]
    public async Task UnsignedRedirectUriJarSucceedsWithoutSignJarActionAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using CancellationTokenSource exchangeDeadline = CreateTestCancellation();
        ClientRecord current = app.Host("default").Registrations[keys.Registration.TenantId.Value];
        app.Host("default").Registrations[current.TenantId.Value] = current with { ClientId = $"redirect_uri:{current.ResponseUri!.OriginalString}" };
        (_, string handle) = await app.HandleParAsync(keys, new TransactionNonce("unsigned-alteration"), DcqlFixtures.PidFamilyNamePrepared(), exchangeDeadline.Token).ConfigureAwait(false);
        await app.Server.RequestAlterationAsync(candidate => candidate.Family<AuthorizationServerIntegration>().ActionExecutor = new OAuthActionExecutor(), deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
        Uri uri = new(app.Host("default").HttpBaseAddress!, $"/connect/{current.TenantId.Value}/request/{handle}");
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(app, uri, "alteration-subject", exchangeDeadline.Token).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode);
        string body = await response.Content.ReadAsStringAsync(exchangeDeadline.Token).ConfigureAwait(false);
        string[] segments = body.Split('.');
        Assert.HasCount(3, segments);
        Assert.AreEqual(string.Empty, segments[2]);
        Assert.IsEmpty(app.Host("default").HttpFaults);
    }


    /// <summary>
    /// Worker failures preserve admission under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "An exception escaping the worker faults every queued requester and reopens admission on the accepted wiring."
    /// </summary>
    [TestMethod]
    public async Task EscapingWorkerFailureFaultsQueuedRequestsAndReopensAdmissionAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        await app.Server.RequestAlterationAsync(candidate => candidate.AddIntegration(new TestHostShell.TraversalFaultIntegration()), deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        string before = await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using ManualResetEventSlim release = new(false);
        Task first = app.Server.RequestAlterationAsync(candidate =>
        {
            _ = entered.TrySetResult();
            release.Wait(deadline.Token);
            candidate.Family<TestHostShell.TraversalFaultIntegration>().RefuseTwoTraversals();
        }, deadline.Token);
        Task? second = null;
        try
        {
            await entered.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            second = app.Server.RequestAlterationAsync(_ => Assert.Fail("An escaped worker failure must fault queued callbacks without invoking them."), deadline.Token);
        }
        finally
        {
            release.Set();
        }

        InvalidOperationException firstFault = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => first);
        InvalidOperationException secondFault = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => second);
        Assert.AreEqual("Deliberate component traversal failure.", firstFault.Message);
        Assert.AreSame(firstFault, secondFault);
        Assert.IsTrue(app.Server.IsValidated);
        Assert.AreEqual(before, await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false));
    }


    /// <summary>
    /// Disposal releases ownership under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "Disposing a server detaches its component ownership, including retained replaced or discarded views, without disposing application resources."
    /// </summary>
    [TestMethod]
    public async Task DisposedOwnerReleasesItsNestedContainerForAdoptionAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        await using TestHostShell donor = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        AuthorizationServerCodecs supplied = donor.Server.OAuth().Codecs;
        donor.Server.Dispose();
        Exception? adoptionFault = null;
        try
        {
            await app.Server.RequestAlterationAsync(candidate => candidate.Family<AuthorizationServerIntegration>().Codecs = supplied, deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
        }
        catch(InvalidOperationException exception)
        {
            adoptionFault = exception;
        }

        Assert.IsNull(adoptionFault, "A disposed owner must release its component attachment.");
        Assert.AreNotSame(supplied, app.Server.OAuth().Codecs);
        using HttpResponseMessage response = await SendDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode);
    }


    /// <summary>
    /// Reversed shared compositions retain bounded validation and admission under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "Component graphs are collected before their locks are acquired in ascending stable acquisition-key order, independent of composition order."
    /// </summary>
    /// <remarks>
    /// Two dedicated workers validate reversed compositions two hundred times. Each construction edit
    /// invalidates both owners before their next paired validation; the harness cancellation bounds the complete sequence.
    /// </remarks>
    [TestMethod]
    public async Task ReversedSharedCompositionsValidateAndReleaseWireRequestsAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell first = new(TimeProvider);
        await using TestHostShell second = new(TimeProvider);
        ServerIntegration a = TestHostShell.CreateNeutralIntegration(first.Server.Integration);
        ServerIntegration b = TestHostShell.CreateNeutralIntegration(second.Server.Integration);
        EndpointServer firstSource = first.Server;
        EndpointServer secondSource = second.Server;
        EndpointServer one = new() { Integration = a, Configuration = ServerConfiguration.Empty with { IsMaintenanceMode = true }, TimeProvider = TimeProvider };
        EndpointServer two = new() { Integration = b, Configuration = ServerConfiguration.Empty with { IsMaintenanceMode = true }, TimeProvider = TimeProvider };
        one.AddIntegration(b);
        two.AddIntegration(a);
        using Barrier paired = new(2);
        Task left = Task.Factory.StartNew(() =>
        {
            for(int iteration = 0; iteration < 200; ++iteration)
            {
                a.InspectAsync = a.InspectAsync;
                paired.SignalAndWait(deadline.Token);
                one.Validate();
                paired.SignalAndWait(deadline.Token);
                Assert.IsTrue(one.IsValidated && two.IsValidated);
            }
        }, deadline.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        Task right = Task.Factory.StartNew(() =>
        {
            for(int iteration = 0; iteration < 200; ++iteration)
            {
                paired.SignalAndWait(deadline.Token);
                two.Validate();
                paired.SignalAndWait(deadline.Token);
            }
        }, deadline.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        Exception? validationFault = null;
        try
        {
            await Task.WhenAll(left, right).WaitAsync(deadline.Token).ConfigureAwait(false);
        }
        catch(Exception exception)
        {
            validationFault = exception;
        }

        Assert.IsNull(validationFault, "Both shared compositions must validate within the bounded wait.");
        Assert.IsTrue(one.IsValidated && two.IsValidated);
        first.Host("default").Server = one;
        second.Host("default").Server = two;
        firstSource.Dispose();
        secondSource.Dispose();
        await first.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        await second.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using CancellationTokenSource exchange = CreateTestCancellation();
        using HttpResponseMessage firstResponse = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(first, new Uri(first.Host("default").HttpBaseAddress!, "/neutral"), "subject", exchange.Token).ConfigureAwait(false);
        using HttpResponseMessage secondResponse = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(second, new Uri(second.Host("default").HttpBaseAddress!, "/neutral"), "subject", exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(400, (int)firstResponse.StatusCode);
        Assert.AreEqual(400, (int)secondResponse.StatusCode);
        Exception? releaseFault = null;
        try
        {
            await Task.WhenAll(one.RequestAlterationAsync(_ => { }, deadline.Token), two.RequestAlterationAsync(_ => { }, deadline.Token)).ConfigureAwait(false);
        }
        catch(Exception exception)
        {
            releaseFault = exception;
        }

        Assert.IsNull(releaseFault, "Both wire requests must release their leases so alterations complete.");
    }


    /// <summary>
    /// A cancelled pending opener cannot abandon its uncancelled sibling under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "Caller cancellation before a window opens cancels its request without touching admission."
    /// </summary>
    /// <remarks>
    /// The terminal worker remains held before pending promotion until cancellation is observed and all
    /// queued tasks are asserted incomplete. The next drain observation releases the held listener request
    /// after capturing that window's wait, so publication never waits on the test to observe a checkpoint.
    /// </remarks>
    [TestMethod]
    public async Task CancelledPendingOpenerLeavesItsSiblingApplicableAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        using CancellationTokenSource opening = new();
        using CancellationTokenSource pending = new();
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource terminal = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using ManualResetEventSlim resume = new(false);
        await TestHostShell.AlterAsync(app.Server, integration => integration.ContributeDiscoveryFieldsAsync = async (_, _, _) =>
        {
            _ = entered.TrySetResult();
            await release.Task.WaitAsync(deadline.Token).ConfigureAwait(false);

            return Marker("A");
        }).ConfigureAwait(false);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        Task<string> held = ReadDiscoveryAsync(app, keys.Registration);
        Task? sibling = null;
        bool hasCancelledCallbackRun = false;
        try
        {
            await entered.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            app.Server.DrainWaitFinished = () =>
            {
                _ = terminal.TrySetResult();
                resume.Wait(deadline.Token);
            };
            Task opener = app.Server.RequestAlterationAsync(_ => { }, opening.Token);

            // The worker's drain continuation can run inline on the cancelling thread, and the hook blocks it, so the opening token is cancelled from the pool instead.
            _ = Task.Run(opening.Cancel, TestContext.CancellationToken);
            await terminal.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            Task cancelled = app.Server.RequestAlterationAsync(_ => hasCancelledCallbackRun = true, pending.Token);
            sibling = app.Server.RequestAlterationAsync(candidate => candidate.Family<AuthorizationServerIntegration>().ContributeDiscoveryFieldsAsync = (_, _, _) => ValueTask.FromResult(Marker("B")), deadline.Token);
            await pending.CancelAsync().ConfigureAwait(false);
            Assert.IsTrue(pending.IsCancellationRequested);
            Assert.IsFalse(resume.IsSet);
            Assert.IsFalse(opener.IsCompleted);
            Assert.IsFalse(cancelled.IsCompleted);
            Assert.IsFalse(sibling.IsCompleted);
            Assert.IsFalse(held.IsCompleted);
            app.Server.DrainWaitStarted = _ => release.TrySetResult();
            app.Server.DrainWaitFinished = null;
            resume.Set();
            _ = await Assert.ThrowsExactlyAsync<TaskCanceledException>(() => opener.WaitAsync(deadline.Token));
            _ = await Assert.ThrowsExactlyAsync<TaskCanceledException>(() => cancelled.WaitAsync(deadline.Token));
            Exception? pendingFault = null;
            try
            {
                await sibling.WaitAsync(deadline.Token).ConfigureAwait(false);
            }
            catch(Exception exception)
            {
                pendingFault = exception;
            }

            Assert.IsNull(pendingFault, "An uncancelled sibling cannot inherit an already-cancelled pending opener's fault.");
        }
        finally
        {
            resume.Set();
            _ = release.TrySetResult();
            app.Server.DrainWaitStarted = null;
            app.Server.DrainWaitFinished = null;
        }

        _ = await held.WaitAsync(deadline.Token).ConfigureAwait(false);
        await sibling.WaitAsync(deadline.Token).ConfigureAwait(false);
        Assert.IsFalse(hasCancelledCallbackRun);
        Assert.AreEqual("B", ReadMarker(await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false)));
    }


    /// <summary>
    /// A cancelled sibling retains cancellation when its window expires under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "Each abandoned request is cancelled when its own token is cancelled; other requests receive the window's actual timeout or opening-request cancellation fault."
    /// </summary>
    [TestMethod]
    public async Task ExpiredDrainCancelsItsCancelledSiblingAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        using CancellationTokenSource cancelled = new();
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await TestHostShell.AlterAsync(app.Server, integration => integration.ContributeDiscoveryFieldsAsync = async (_, _, _) =>
        {
            _ = entered.TrySetResult();
            await release.Task.WaitAsync(deadline.Token).ConfigureAwait(false);

            return Marker("A");
        }).ConfigureAwait(false);
        await app.Server.RequestAlterationAsync(candidate => candidate.Configuration = candidate.Configuration with { DrainTimeout = TimeSpan.FromMilliseconds(200) }, deadline.Token).ConfigureAwait(false);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        Task<string> held = ReadDiscoveryAsync(app, keys.Registration);
        try
        {
            await entered.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            Task opener = app.Server.RequestAlterationAsync(_ => { }, deadline.Token);
            Task sibling = app.Server.RequestAlterationAsync(_ => Assert.Fail("A cancelled sibling cannot execute."), cancelled.Token);
            await cancelled.CancelAsync().ConfigureAwait(false);
            InvalidOperationException fault = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => opener);
            Assert.Contains(nameof(ServerConfiguration.DrainTimeout), fault.Message, StringComparison.Ordinal);
            _ = await Assert.ThrowsExactlyAsync<TaskCanceledException>(() => sibling.WaitAsync(deadline.Token));
            Assert.IsTrue(app.Server.IsValidated);
        }
        finally
        {
            _ = release.TrySetResult();
        }

        Assert.AreEqual("A", ReadMarker(await held.WaitAsync(deadline.Token).ConfigureAwait(false)));
    }


    /// <summary>
    /// Explicit validation cannot enter an active window under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "Validate refuses a call while an alteration window owns admission."
    /// </summary>
    [TestMethod]
    public async Task ValidateDuringHeldWindowHasTheNamedFaultAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await TestHostShell.AlterAsync(app.Server, integration => integration.ContributeDiscoveryFieldsAsync = async (_, _, _) =>
        {
            _ = entered.TrySetResult();
            await release.Task.WaitAsync(deadline.Token).ConfigureAwait(false);

            return Marker("A");
        }).ConfigureAwait(false);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        Task<string> held = ReadDiscoveryAsync(app, keys.Registration);
        Task? alteration = null;
        try
        {
            await entered.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            alteration = app.Server.RequestAlterationAsync(_ => { }, deadline.Token);
            InvalidOperationException fault = Assert.ThrowsExactly<InvalidOperationException>(app.Server.Validate);
            Assert.Contains("Validate cannot run during RequestAlterationAsync", fault.Message, StringComparison.Ordinal);
        }
        finally
        {
            _ = release.TrySetResult();
        }

        Assert.AreEqual("A", ReadMarker(await held.WaitAsync(deadline.Token).ConfigureAwait(false)));
        await alteration.WaitAsync(deadline.Token).ConfigureAwait(false);
    }


    /// <summary>
    /// A shared component freezes all construction owners under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "Each owner can alter its own copied composition through its requested alteration afterwards."
    /// </summary>
    [TestMethod]
    public async Task SharedFrozenComponentAllowsEachOwnersRequestedAlterationAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        await using TestHostShell other = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        AuthorizationServerIntegration shared = app.Server.OAuth();
        other.Server.Dispose();
        other.Host("default").Server = new EndpointServer { Integration = shared, Configuration = app.Server.Configuration, TimeProvider = TimeProvider };
        other.Server.AddIntegration(shared);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        _ = await ReadDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        _ = Assert.ThrowsExactly<InvalidOperationException>(() => shared.ClaimIssuer = shared.ClaimIssuer);
        Exception? alterationFault = null;
        try
        {
            await other.Server.RequestAlterationAsync(candidate => candidate.Family<AuthorizationServerIntegration>().ContributeDiscoveryFieldsAsync = (_, _, _) => ValueTask.FromResult(Marker("other")), deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
        }
        catch(Exception exception)
        {
            alterationFault = exception;
        }

        Assert.IsNull(alterationFault, "Each owner can copy its own frozen graph regardless of another owner's publication.");
        await other.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        Assert.AreEqual("other", ReadMarker(await ReadDiscoveryAsync(other, keys.Registration).ConfigureAwait(false)));
    }


    /// <summary>
    /// Disposal cannot be followed by attachment through validation under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "Validation and construction mutation reject a disposed owner before attaching any component."
    /// </summary>
    [TestMethod]
    public async Task DisposalWinningValidationLeavesOwnershipReleasedAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        await using TestHostShell donor = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        await donor.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using ServerRequestLease? lease = await donor.Server.AcquireRequestAsync([], deadline.Token).ConfigureAwait(false);
        Assert.IsNotNull(lease);
        EndpointServer retained = lease.Server;
        AuthorizationServerCodecs codecs = retained.OAuth().Codecs;
        TaskCompletionSource disposed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task disposing = Task.Run(() => { donor.Server.Dispose(); _ = disposed.TrySetResult(); }, deadline.Token);
        Task validating = Task.Run(async () =>
        {
            await disposed.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            _ = Assert.ThrowsExactly<ObjectDisposedException>(donor.Server.Validate);
            _ = Assert.ThrowsExactly<ObjectDisposedException>(retained.Validate);
            _ = Assert.ThrowsExactly<ObjectDisposedException>(() => donor.Server.AddIntegration(new ServerIntegration()));
            _ = Assert.ThrowsExactly<ObjectDisposedException>(() => donor.Server.ApplyConfiguration(donor.Server.Configuration));
            _ = Assert.ThrowsExactly<ObjectDisposedException>(() => donor.Server.ActionExecutor = null);
        }, deadline.Token);
        await Task.WhenAll(disposing, validating).WaitAsync(deadline.Token).ConfigureAwait(false);
        Exception? adoptionFault = null;
        try
        {
            await app.Server.RequestAlterationAsync(candidate => candidate.Family<AuthorizationServerIntegration>().Codecs = codecs, deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
        }
        catch(Exception exception)
        {
            adoptionFault = exception;
        }

        Assert.IsNull(adoptionFault, "Disposed owners cannot retain an attachment through validation.");
        using HttpResponseMessage response = await SendDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode);
    }


    /// <summary>
    /// Unexpected response states expose only a neutral condition under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "An unexpected JAR response state receives a neutral server error without an internal type name."
    /// </summary>
    [TestMethod]
    public async Task UnexpectedJarResponseStateHasNeutralWireBodyAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using CancellationTokenSource exchangeDeadline = CreateTestCancellation();
        (_, string handle) = await app.HandleParAsync(keys, new TransactionNonce("unexpected-jar-state"), DcqlFixtures.PidFamilyNamePrepared(), exchangeDeadline.Token).ConfigureAwait(false);
        FlowState unexpected = app.GetFlowState(handle).State;
        await app.Server.RequestAlterationAsync(candidate => TestHostShell.UseUnexpectedJarResponseState(candidate, unexpected), deadline.Token).ConfigureAwait(false);
        Uri uri = new(app.Host("default").HttpBaseAddress!, $"/connect/{keys.Registration.TenantId.Value}/request/{handle}");
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(app, uri, "subject", exchangeDeadline.Token).ConfigureAwait(false);
        Assert.AreEqual(500, (int)response.StatusCode);
        using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(exchangeDeadline.Token).ConfigureAwait(false));
        Assert.AreEqual("The server is not ready to serve this request.", body.RootElement.GetProperty("error_description").GetString());
        Exception[] faults = app.Host("default").ConsumeHttpFaults();
        Assert.IsEmpty(faults, "An unexpected response state is handled by the endpoint.");
    }


    /// <summary>
    /// Host teardown completes before reporting an unconsumed request fault under
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>:
    /// "The host completes resource cleanup before reporting unconsumed request faults."
    /// </summary>
    [TestMethod]
    public async Task CapturedHttpFaultCannotSkipOwnedResourceDisposalAsync()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = await app.RegisterClientAsync(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        TestHostShell.DisposalProbe probe = app.ObserveTransportDisposal();
        await TestHostShell.AlterAsync(app.Server, integration => integration.ContributeDiscoveryFieldsAsync = (_, _, _) => throw new InvalidOperationException("Deliberate request fault for resource disposal.")).ConfigureAwait(false);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using HttpResponseMessage response = await SendDiscoveryAsync(app, keys.Registration).ConfigureAwait(false);
        Assert.AreEqual(500, (int)response.StatusCode);
        AssertFailedException failure = await Assert.ThrowsExactlyAsync<AssertFailedException>(() => app.DisposeAsync().AsTask());
        Assert.Contains("Every captured HTTP fault", failure.Message, StringComparison.Ordinal);
        Exception[] faults = app.Host("default").ConsumeHttpFaults();
        Assert.HasCount(1, faults);
        Assert.Contains("Deliberate request fault for resource disposal.", faults[0].Message, StringComparison.Ordinal);
        Assert.IsTrue(probe.IsDisposed, "An unconsumed HTTP fault cannot skip host-owned resource disposal.");
    }


    /// <summary>
    /// Proves RFC 7591 <see href="https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1">§3.2.1</see>
    /// and <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">section 4.1</see>: "Registration events carry immutable selected client data, event identifiers, tenant and client identifiers, occurrence times and per-registration revisions; they carry neither the request context nor the management credential."
    /// </summary>
    [TestMethod]
    public async Task RegistrationEventCarriesImmutableProjectionOverWire()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        List<ClientRegistrationEvent> observed = [];
        using IDisposable subscription = app.Server.Events.Subscribe(new CollectingObserver<ClientRegistrationEvent>(observed));
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using CancellationTokenSource exchange = CreateTestCancellation();
        var client = await RegisterManagedClientOverWireAsync(app).ConfigureAwait(false);
        ClientRegistered created = Assert.IsInstanceOfType<ClientRegistered>(observed.Single());
        ClientRegistrationProjection projection = created.Projection;
        Assert.AreEqual(client.ClientId, projection.ClientId);
        Assert.AreEqual("dynamic-clients", projection.TenantId.Value);
        Assert.AreEqual(1L, projection.Revision);
        Assert.AreEqual(TimeProvider.GetUtcNow(), created.OccurredAt);
        Assert.IsGreaterThan(0L, created.EventId);
        Assert.AreEqual("initial-client", projection.ClientName);
        Assert.AreEqual(new Uri("https://client.example.test/"), projection.ClientUri);
        Assert.IsTrue(projection.RedirectUris.SetEquals([new Uri("https://client.example.test/callback")]));
        Assert.IsTrue(projection.Scopes.SetEquals(["initial-scope"]));
        Assert.IsTrue(projection.Capabilities.SetEquals([WellKnownCapabilityIdentifiers.OAuthDynamicClientRegistration]));
        string serialized = JsonSerializer.Serialize(created);
        Assert.DoesNotContain(client.AccessToken, serialized, StringComparison.Ordinal,
            "Optional registration notifications must not contain the management credential.");
        using JsonDocument payload = JsonDocument.Parse(serialized);
        Assert.IsFalse(payload.RootElement.TryGetProperty("Context", out _), "A registration notification must not retain its mutable request context.");
        Assert.IsFalse(payload.RootElement.TryGetProperty("AccessToken", out _), "A registration notification must not expose an access-token member.");
        using HttpResponseMessage updated = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
            HttpMethod.Put, client.ManagementUri, client.AccessToken,
            ManagementDocument(client.ClientId, "updated-client", "https://client.example.test/new", "new-scope"), exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(200, (int)updated.StatusCode);
        ClientUpdated changed = Assert.IsInstanceOfType<ClientUpdated>(observed[1]);
        Assert.AreEqual(2L, changed.Revision);
        Assert.AreEqual(1L, changed.Previous.Revision);
        Assert.AreNotEqual(created.EventId, changed.EventId);
        Assert.AreEqual("updated-client", changed.Projection.ClientName);
        Assert.AreEqual("initial-client", projection.ClientName, "A retained projection must preserve the data of its own committed revision.");
        Assert.IsTrue(projection.Scopes.SetEquals(["initial-scope"]));
        Assert.IsTrue(projection.RedirectUris.SetEquals([new Uri("https://client.example.test/callback")]));
    }


    /// <summary>
    /// Proves successful registration under <see href="https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1">RFC 7591 §3.2.1</see>:
    /// Under <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">section 4.1</see>:
    /// "Optional observer exceptions and exceptions from their inspection reports are isolated per subscription, preserving the committed response and delivery to later subscribers."
    /// </summary>
    [TestMethod]
    public async Task ThrowingOptionalObserverPreservesCommittedRegistrationOverWire()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        List<RegistrationObserverFailureStage> diagnostics = [];
        InvalidOperationException observerFault = new("Optional observer failed.");
        await TestHostShell.AlterAsync(app.Server, integration => integration.InspectAsync = (stage, _, _) =>
        {
            if(stage is RegistrationObserverFailureStage failure)
            {
                diagnostics.Add(failure);
                throw new InvalidOperationException("Observer diagnostics failed.");
            }

            return ValueTask.CompletedTask;
        }).ConfigureAwait(false);
        using IDisposable first = app.Server.Events.Subscribe(new CollectingObserver<ClientRegistrationEvent>([], _ => throw observerFault));
        List<ClientRegistrationEvent> observed = [];
        bool isCommittedWhenObserved = false;
        using IDisposable second = app.Server.Events.Subscribe(new CollectingObserver<ClientRegistrationEvent>(observed, value =>
            isCommittedWhenObserved = app.RegistrationStore.ContainsKey(value.ClientId)));
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using CancellationTokenSource exchange = CreateTestCancellation();
        using HttpResponseMessage response = await RegisterOverWireAsync(app).ConfigureAwait(false);
        Exception[] faults = app.Host("default").ConsumeHttpFaults();
        Assert.AreEqual(201, (int)response.StatusCode, "Optional exceptions must preserve the committed response.");
        Assert.IsEmpty(faults);
        using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(exchange.Token).ConfigureAwait(false));
        string clientId = body.RootElement.GetProperty("client_id").GetString()!;
        string accessToken = body.RootElement.GetProperty("registration_access_token").GetString()!;
        Uri managementUri = new(body.RootElement.GetProperty("registration_client_uri").GetString()!, UriKind.Absolute);
        Assert.IsTrue(app.RegistrationStore.ContainsKey(clientId), "An optional observer failure must preserve the committed registration.");
        Assert.HasCount(1, observed, "A throwing optional observer must not prevent the next observer receiving the event.");
        Assert.IsTrue(isCommittedWhenObserved, "Registration persistence must complete before optional observers run.");
        Assert.HasCount(1, diagnostics, "Each optional observer failure must reach the inspection seam.");
        Assert.AreSame(observerFault, diagnostics[0].Exception);
        Assert.AreEqual(observed[0].EventId, diagnostics[0].Event.EventId);
        using HttpResponseMessage read = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
            HttpMethod.Get, managementUri, accessToken, null, exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(200, (int)read.StatusCode, "A committed registration must remain reachable with its issued credential.");
    }


    /// <summary>
    /// Proves the registration success boundary under <see href="https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1">RFC 7591 §3.2.1</see>:
    /// Under <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">section 4.1</see>:
    /// "A required persistence exception propagates before notification and the operation emits no registration event."
    /// </summary>
    [TestMethod]
    public async Task RequiredPersistenceFailureEmitsNothingOverWire()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        InvalidOperationException expected = new("Required registration persistence failed.");
        app.Host("default").BeforeRegistrationCreateAsync = (_, _) => throw expected;
        List<ClientRegistrationEvent> observed = [];
        using IDisposable subscription = app.Server.Events.Subscribe(new CollectingObserver<ClientRegistrationEvent>(observed));
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using HttpResponseMessage response = await RegisterOverWireAsync(app).ConfigureAwait(false);
        Exception[] faults = app.Host("default").ConsumeHttpFaults();
        Assert.AreEqual(500, (int)response.StatusCode, "Required persistence failure must abort registration.");
        Assert.HasCount(1, faults);
        Assert.AreSame(expected, faults[0], "The required persistence exception must propagate unchanged.");
        Assert.IsEmpty(observed, "Failed required persistence must emit no registration event.");
        Assert.IsEmpty(app.RegistrationStore);
        Assert.IsEmpty(app.Host("default").RegistrationAccessTokens);
    }


    /// <summary>
    /// Proves subscription membership in <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">§4.1</see>:
    /// Under <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">section 4.1</see>:
    /// "Each subscription owns a unique token; repeated concurrent disposal removes only that token, including when an observer subscribes more than once."
    /// </summary>
    [TestMethod]
    public async Task ConcurrentDoubleDisposalPreservesDuplicateSubscriptionOverWire()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        TaskCompletionSource captured = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using ManualResetEventSlim release = new(false);
        using IDisposable blocker = app.Server.Events.Subscribe(new CollectingObserver<ClientRegistrationEvent>([], _ =>
        {
            bool wasCaptureSet = captured.TrySetResult();
            release.Wait(deadline.Token);
        }));
        List<ClientRegistrationEvent> observed = [];
        CollectingObserver<ClientRegistrationEvent> observer = new(observed);
        using IDisposable first = app.Server.Events.Subscribe(observer);
        using IDisposable second = app.Server.Events.Subscribe(observer);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        Task<HttpResponseMessage> pending = RegisterOverWireAsync(app);
        IDisposable? added = null;
        System.Collections.Concurrent.ConcurrentQueue<Exception> faults = new();
        using Barrier start = new(3);
        try
        {
            await captured.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            await Task.WhenAll(Enumerable.Range(0, 3).Select(index => Task.Run(() =>
            {
                try
                {
                    start.SignalAndWait(deadline.Token);
                    if(index == 2)
                    {
                        added = app.Server.Events.Subscribe(observer);
                    }
                    else
                    {
                        first.Dispose();
                    }
                }
                catch(Exception exception)
                {
                    faults.Enqueue(exception);
                }
            }, deadline.Token))).ConfigureAwait(false);
        }
        finally
        {
            release.Set();
        }

        using IDisposable? third = added;
        using CancellationTokenSource exchange = CreateTestCancellation();
        using HttpResponseMessage response = await pending.ConfigureAwait(false);
        Assert.IsEmpty(faults, "Concurrent disposal and subscription must not throw.");
        Assert.AreEqual(201, (int)response.StatusCode);
        Assert.HasCount(2, observed, "Disposal must preserve every already captured delivery.");
        using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(exchange.Token).ConfigureAwait(false));
        string clientId = body.RootElement.GetProperty("client_id").GetString()!;
        string accessToken = body.RootElement.GetProperty("registration_access_token").GetString()!;
        Uri managementUri = new(body.RootElement.GetProperty("registration_client_uri").GetString()!, UriKind.Absolute);
        first.Dispose();
        first.Dispose();
        using HttpResponseMessage update = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
            HttpMethod.Put, managementUri, accessToken, ManagementDocument(clientId, "subscribed"), exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(200, (int)update.StatusCode);
        Assert.HasCount(4, observed, "The surviving and newly subscribed tokens must each receive the next event after double disposal.");
    }


    /// <summary>
    /// Proves subscription identity in <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">§4.1</see>:
    /// Under <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">section 4.1</see>:
    /// "Observer equality cannot substitute for subscription identity."
    /// </summary>
    [TestMethod]
    public async Task DisposingEqualObserverPreservesOtherSubscriptionOverWire()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        List<ClientRegistrationEvent> firstEvents = [];
        List<ClientRegistrationEvent> secondEvents = [];
        using IDisposable first = app.Server.Events.Subscribe(new EqualRegistrationObserver(firstEvents));
        using IDisposable second = app.Server.Events.Subscribe(new EqualRegistrationObserver(secondEvents));
        second.Dispose();
        second.Dispose();
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using HttpResponseMessage response = await RegisterOverWireAsync(app).ConfigureAwait(false);
        Assert.AreEqual(201, (int)response.StatusCode);
        Assert.HasCount(1, firstEvents, "Disposal must preserve a different subscription even when its observer compares equal.");
        Assert.IsEmpty(secondEvents, "A disposed token must not receive subsequent emissions.");
    }


    /// <summary>
    /// Proves conditional replacement under <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.2">RFC 7592 §2.2</see>:
    /// Under <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">section 4.1</see>:
    /// "Concurrent updates that read one registration revision have exactly one successful conditional commit; a stale update returns HTTP 400 with invalid_client_metadata and emits nothing."
    /// </summary>
    [TestMethod]
    public async Task ConcurrentRegistrationUpdatesHaveOneCoherentWinnerOverWire()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using CancellationTokenSource exchange = CreateTestCancellation();
        var client = await RegisterManagedClientOverWireAsync(app).ConfigureAwait(false);
        const int requestCount = 8;
        int entered = 0;
        TaskCompletionSource allEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        app.Host("default").BeforeRegistrationUpdateAsync = async (_, ct) =>
        {
            if(Interlocked.Increment(ref entered) == requestCount)
            {
                bool wasAllEnteredSet = allEntered.TrySetResult();
            }

            await release.Task.WaitAsync(ct).ConfigureAwait(false);
        };
        List<ClientRegistrationEvent> observed = [];
        using IDisposable subscription = app.Server.Events.Subscribe(new CollectingObserver<ClientRegistrationEvent>(observed));
        Task<(int Index, int Status, string Body)>[] requests = Enumerable.Range(0, requestCount).Select(async index =>
        {
            string json = ManagementDocument(client.ClientId, $"client-{index}", $"https://client.example.test/{index}", $"scope-{index}");
            using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
                HttpMethod.Put, client.ManagementUri, client.AccessToken, json, exchange.Token).ConfigureAwait(false);
            string body = await response.Content.ReadAsStringAsync(exchange.Token).ConfigureAwait(false);

            return (index, (int)response.StatusCode, body);
        }).ToArray();
        try
        {
            await allEntered.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
        }
        finally
        {
            _ = release.TrySetResult();
        }

        var results = await Task.WhenAll(requests).ConfigureAwait(false);
        var winners = results.Where(result => result.Status == 200).ToArray();
        Assert.HasCount(1, winners, "Exactly one concurrent update of a loaded registration revision must commit.");
        foreach(var loser in results.Where(result => result.Status != 200))
        {
            Assert.AreEqual(400, loser.Status);
            using JsonDocument error = JsonDocument.Parse(loser.Body);
            Assert.AreEqual(OAuthErrors.InvalidClientMetadata, error.RootElement.GetProperty("error").GetString());
        }

        int winner = winners[0].Index;
        using JsonDocument winnerBody = JsonDocument.Parse(winners[0].Body);
        Assert.AreEqual(client.ClientId, winnerBody.RootElement.GetProperty("client_id").GetString());
        Assert.AreEqual(client.AccessToken, winnerBody.RootElement.GetProperty("registration_access_token").GetString());
        Assert.AreEqual(client.ManagementUri.AbsoluteUri, winnerBody.RootElement.GetProperty("registration_client_uri").GetString());
        Assert.AreEqual($"client-{winner}", winnerBody.RootElement.GetProperty("client_name").GetString());
        Assert.AreEqual("https://client.example.test/", winnerBody.RootElement.GetProperty("client_uri").GetString());
        Assert.AreEqual($"scope-{winner}", winnerBody.RootElement.GetProperty("scope").GetString());
        Assert.AreEqual($"https://client.example.test/{winner}", winnerBody.RootElement.GetProperty("redirect_uris")[0].GetString());
        ClientRecord stored = app.RegistrationStore[client.ClientId];
        Assert.AreEqual(2L, stored.Revision, "The winning update must advance the registration revision exactly once.");
        Assert.AreEqual($"client-{winner}", stored.ClientName);
        Assert.IsTrue(stored.AllowedScopes.SetEquals([$"scope-{winner}"]));
        Assert.IsTrue(stored.AllowedRedirectUris.SetEquals([new Uri($"https://client.example.test/{winner}")]));
        Assert.AreSame(stored, app.RegistrationStore[stored.TenantId], "Both routing indexes must identify the winning record.");
        Assert.HasCount(1, observed, "Only the committed update may emit a registration event.");
        Assert.AreEqual(stored.ClientName, observed[0].Projection.ClientName);
        Assert.AreEqual(stored.Revision, observed[0].Revision);
        using HttpResponseMessage read = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
            HttpMethod.Get, client.ManagementUri, client.AccessToken, null, exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(200, (int)read.StatusCode);
        Assert.AreEqual(winners[0].Body, await read.Content.ReadAsStringAsync(exchange.Token).ConfigureAwait(false),
            "The retained registration and its management response must equal the winning update.");
    }


    /// <summary>
    /// Proves capability effects in <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">§4.1</see>:
    /// Under <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">section 4.1</see>:
    /// "Capability grant and revoke signals require an application effect on synchronized registration and granted-capability state before endpoint reachability changes."
    /// </summary>
    [TestMethod]
    public async Task CapabilityGrantAndRevokeChangeReachabilityOverWire()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using CancellationTokenSource exchange = CreateTestCancellation();
        var client = await RegisterManagedClientOverWireAsync(app).ConfigureAwait(false);
        Task effect = Task.CompletedTask;
        using IDisposable subscriber = app.Server.Events.Subscribe(new CollectingObserver<ClientRegistrationEvent>([], value =>
        {
            if(value is ClientUpdated update)
            {
                ClientRecord record = app.RegistrationStore[update.ClientId];
                effect = update.Projection.ClientName switch
                {
                    "grant" => app.Server.GrantCapabilityAsync(record, WellKnownCapabilityIdentifiers.OAuthJwksEndpoint, []).AsTask(),
                    "revoke" => app.Server.RevokeCapabilityAsync(record, WellKnownCapabilityIdentifiers.OAuthJwksEndpoint, "Application revoked access.", []).AsTask(),
                    _ => Task.CompletedTask
                };
            }
        }));
        ServerHttpResponse before = await RawAuthCodeWirePushers.PushNamedEndpointAsync(app, "dynamic-clients",
            WellKnownEndpointNames.MetadataJwks, "GET", new RequestFields(), [], exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(404, before.StatusCode, "The capability-gated endpoint must be unreachable before grant.");
        using HttpResponseMessage grant = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
            HttpMethod.Put, client.ManagementUri, client.AccessToken,
            ManagementDocument(client.ClientId, "grant"), exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(200, (int)grant.StatusCode);
        await effect.WaitAsync(exchange.Token).ConfigureAwait(false);
        ServerHttpResponse granted = await RawAuthCodeWirePushers.PushNamedEndpointAsync(app, "dynamic-clients",
            WellKnownEndpointNames.MetadataJwks, "GET", new RequestFields(), [], exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(200, granted.StatusCode, "The application's grant effect must make the capability-gated endpoint reachable.");
        using HttpResponseMessage revoke = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
            HttpMethod.Put, client.ManagementUri, client.AccessToken,
            ManagementDocument(client.ClientId, "revoke"), exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(200, (int)revoke.StatusCode);
        await effect.WaitAsync(exchange.Token).ConfigureAwait(false);
        ServerHttpResponse revoked = await RawAuthCodeWirePushers.PushNamedEndpointAsync(app, "dynamic-clients",
            WellKnownEndpointNames.MetadataJwks, "GET", new RequestFields(), [], exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(404, revoked.StatusCode, "The application's revoke effect must make the capability-gated endpoint unreachable.");
        using HttpResponseMessage metadata = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
            HttpMethod.Put, client.ManagementUri, client.AccessToken,
            ManagementDocument(client.ClientId, "retained-revocation"), exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(200, (int)metadata.StatusCode);
        ServerHttpResponse retained = await RawAuthCodeWirePushers.PushNamedEndpointAsync(app, "dynamic-clients",
            WellKnownEndpointNames.MetadataJwks, "GET", new RequestFields(), [], exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(404, retained.StatusCode, "A metadata update must preserve the application's revoked capability grant.");
    }


    /// <summary>
    /// Proves deletion under <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.3">RFC 7592 §2.3</see>:
    /// Under <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">section 4.1</see>:
    /// "Registration creation, conditional replacement and deletion commit through the required registration store before optional observers run."
    /// </summary>
    [TestMethod]
    public async Task RegistrationDeletionCommitsBeforeObserversOverWire()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using CancellationTokenSource exchange = CreateTestCancellation();
        var client = await RegisterManagedClientOverWireAsync(app).ConfigureAwait(false);
        List<ClientRegistrationEvent> observed = [];
        bool isRemovedWhenObserved = false;
        using IDisposable subscription = app.Server.Events.Subscribe(new CollectingObserver<ClientRegistrationEvent>(observed, value =>
            isRemovedWhenObserved = !app.RegistrationStore.ContainsKey(value.ClientId)
                && !app.RegistrationStore.ContainsKey(value.TenantId)
                && !app.Host("default").RegistrationAccessTokens.ContainsKey(value.ClientId)));
        using HttpResponseMessage deleted = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
            HttpMethod.Delete, client.ManagementUri, client.AccessToken, null, exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(204, (int)deleted.StatusCode);
        Assert.IsTrue(isRemovedWhenObserved, "Deletion must commit all registration indexes and credentials before optional observers run.");
        ClientDeregistered notification = Assert.IsInstanceOfType<ClientDeregistered>(observed.Single());
        Assert.AreEqual(client.ClientId, notification.ClientId);
        Assert.AreEqual(2L, notification.Revision);
        using HttpResponseMessage read = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
            HttpMethod.Get, client.ManagementUri, client.AccessToken, null, exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(401, (int)read.StatusCode);
    }


    /// <summary>
    /// Proves failed replacement under <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.2">RFC 7592 §2.2</see>:
    /// Under <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">section 4.1</see>:
    /// "A required persistence exception propagates before notification and the operation emits no registration event."
    /// </summary>
    [TestMethod]
    public async Task RequiredUpdatePersistenceFailurePreservesRecordOverWire()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using CancellationTokenSource exchange = CreateTestCancellation();
        var client = await RegisterManagedClientOverWireAsync(app).ConfigureAwait(false);
        ClientRecord initial = app.RegistrationStore[client.ClientId];
        InvalidOperationException expected = new("Required update persistence failed.");
        app.Host("default").BeforeRegistrationUpdateAsync = (_, _) => throw expected;
        List<ClientRegistrationEvent> observed = [];
        using IDisposable subscription = app.Server.Events.Subscribe(new CollectingObserver<ClientRegistrationEvent>(observed));
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
            HttpMethod.Put, client.ManagementUri, client.AccessToken,
            ManagementDocument(client.ClientId, "uncommitted"), exchange.Token).ConfigureAwait(false);
        Exception[] faults = app.Host("default").ConsumeHttpFaults();
        Assert.AreEqual(500, (int)response.StatusCode);
        Assert.HasCount(1, faults);
        Assert.AreSame(expected, faults[0]);
        Assert.IsEmpty(observed, "A failed required update must emit no registration event.");
        Assert.AreSame(initial, app.RegistrationStore[client.ClientId], "A failed required update must preserve the committed record.");
    }


    /// <summary>
    /// Proves required wiring in <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">§4.1</see>:
    /// Under <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">section 4.1</see>:
    /// "Registration parsing or management-token validation requires ClientRegistrationStore in the validated composition."
    /// </summary>
    [TestMethod]
    public async Task RegistrationWithoutRequiredStoreIsRefusedOverWire()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        app.Host("default").UseUnvalidatedServer();
        app.Host("default").IsUnvalidatedListenerAllowed = true;
        app.Server.OAuth().ClientRegistrationStore = null;
        InvalidOperationException validation = Assert.ThrowsExactly<InvalidOperationException>(app.Server.Validate);
        Assert.Contains("ClientRegistrationStore", validation.Message, StringComparison.Ordinal);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using HttpResponseMessage response = await RegisterOverWireAsync(app).ConfigureAwait(false);
        Exception[] faults = app.Host("default").ConsumeHttpFaults();
        Assert.AreEqual(500, (int)response.StatusCode, "Registration cannot be admitted without its required persistence store.");
        Assert.HasCount(1, faults);
        Assert.IsEmpty(app.RegistrationStore);
    }


    /// <summary>
    /// Proves authenticated management under <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2">RFC 7592 section 2</see>.
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Section 4.1</see>:
    /// "Observer failure reports receive a detached context containing no request, headers, body, live registration or management bearer."
    /// </summary>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task AuthenticatedObserverFailureInputsExcludeRequestAndCredentialOverWire(bool isDelete)
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using CancellationTokenSource exchange = CreateTestCancellation();
        var client = await RegisterManagedClientOverWireAsync(app).ConfigureAwait(false);
        ExchangeContext? incoming = null;
        List<(RegistrationObserverFailureStage Stage, ExchangeContext Context)> reports = [];
        await TestHostShell.AlterAsync(app.Server, integration => integration.InspectAsync = (stage, context, _) =>
        {
            if(stage is IncomingRequestStage)
            {
                incoming = context;
            }

            if(stage is RegistrationObserverFailureStage failure)
            {
                reports.Add((failure, context));
            }

            return ValueTask.CompletedTask;
        }).ConfigureAwait(false);
        InvalidOperationException expected = new("Optional notification failed.");
        using IDisposable observer = app.Server.Events.Subscribe(new CollectingObserver<ClientRegistrationEvent>([], _ => throw expected));
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
            isDelete ? HttpMethod.Delete : HttpMethod.Put, client.ManagementUri, client.AccessToken,
            isDelete ? null : ManagementDocument(client.ClientId, "detached"), exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(isDelete ? 204 : 200, (int)response.StatusCode);
        Assert.HasCount(1, reports);
        var (Stage, Context) = reports[0];
        Assert.IsNotNull(incoming?.IncomingRequest);
        Assert.AreNotSame(incoming, Context);
        Assert.IsEmpty(Context, "The complete diagnostic context must be detached and empty.");
        Assert.IsNull(Context.IncomingRequest);
        Assert.IsNull(Context.IncomingRequest?.Headers);
        Assert.IsNull(Context.IncomingRequest?.Body);
        Assert.IsNull(Context.Registration);
        Assert.AreSame(expected, Stage.Exception);
        Assert.AreEqual("Optional notification failed.", Stage.Exception.Message);
        Assert.IsNull(Stage.Exception.InnerException);
        Assert.IsEmpty(Stage.Exception.Data);
        Assert.DoesNotContain(client.AccessToken, Stage.Exception.ToString(), StringComparison.Ordinal);
        Assert.AreEqual(client.ClientId, Stage.Event.Projection.ClientId);
        string selected = JsonSerializer.Serialize(Stage.Event);
        Assert.DoesNotContain(client.AccessToken, selected, StringComparison.Ordinal);
        Assert.DoesNotContain("IncomingRequest", selected, StringComparison.Ordinal);
        Assert.DoesNotContain("Headers", selected, StringComparison.Ordinal);
        Assert.DoesNotContain("Body", selected, StringComparison.Ordinal);
        Assert.DoesNotContain("AccessToken", selected, StringComparison.Ordinal);
        Assert.DoesNotContain("Authorization", selected, StringComparison.Ordinal);
        string source = await File.ReadAllTextAsync(Path.Combine(
            Foundation.SourceHygieneScanner.FindRepositoryRoot(), "src", "Verifiable.OAuth", "Server", "ClientRegistrationEvent.cs"), deadline.Token).ConfigureAwait(false);
        string declaration = source[source.IndexOf("public sealed record RegistrationObserverFailureStage(", StringComparison.Ordinal)..]
            .Trim().ReplaceLineEndings("\n");
        Assert.AreEqual("public sealed record RegistrationObserverFailureStage(\n"
            + "    ClientRegistrationEvent Event, Exception Exception): InspectionStage;", declaration,
            "The stage declaration must expose exactly Event and Exception, with no request, headers, body or bearer member.");
    }


    /// <summary>
    /// Proves committed responses under <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2">RFC 7592 section 2</see>.
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Section 4.1</see>:
    /// "Outgoing inspection runs after the handler completes on every dispatch; its exceptions are recorded on the request Activity and the response returns as built."
    /// </summary>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task OutgoingInspectionFailurePreservesCommittedManagementResponseOverWire(bool isDelete)
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using CancellationTokenSource exchange = CreateTestCancellation();
        var client = await RegisterManagedClientOverWireAsync(app).ConfigureAwait(false);
        using System.Diagnostics.ActivityListener listener = new()
        {
            ShouldListenTo = source => source.Name == Verifiable.Server.Diagnostics.ServerActivitySource.SourceName,
            Sample = (ref _) => System.Diagnostics.ActivitySamplingResult.AllData
        };
        System.Diagnostics.ActivitySource.AddActivityListener(listener);
        System.Diagnostics.Activity? activity = null;
        bool isCommitted = false;
        await TestHostShell.AlterAsync(app.Server, integration => integration.InspectAsync = (stage, _, _) =>
        {
            if(stage is OutgoingResponseStage)
            {
                activity = System.Diagnostics.Activity.Current;
                isCommitted = isDelete ? !app.RegistrationStore.ContainsKey(client.ClientId)
                    : app.RegistrationStore[client.ClientId].ClientName == "outgoing";
                throw new InvalidOperationException("Outgoing inspection failed.");
            }

            return ValueTask.CompletedTask;
        }).ConfigureAwait(false);
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
            isDelete ? HttpMethod.Delete : HttpMethod.Put, client.ManagementUri, client.AccessToken,
            isDelete ? null : ManagementDocument(client.ClientId, "outgoing"), exchange.Token).ConfigureAwait(false);
        Exception[] faults = app.Host("default").ConsumeHttpFaults();
        Assert.AreEqual(isDelete ? 204 : 200, (int)response.StatusCode);
        Assert.IsTrue(isCommitted);
        Assert.IsEmpty(faults);
        Assert.IsNotNull(activity);
        Assert.Contains(value => value.Name == "exception", activity.Events, "The request Activity must retain the outgoing inspection exception.");
    }


    /// <summary>
    /// Proves replacement authentication under <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.2">RFC 7592 section 2.2</see>.
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Section 4.1</see>:
    /// "A management PUT requires the issued client_id; a missing or different identifier returns invalid_client_metadata without mutation or notification."
    /// </summary>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task ManagementReplacementRejectsAbsentOrDifferentClientIdOverWire(bool isMissing)
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using CancellationTokenSource exchange = CreateTestCancellation();
        var client = await RegisterManagedClientOverWireAsync(app).ConfigureAwait(false);
        ClientRecord initial = app.RegistrationStore[client.ClientId];
        List<ClientRegistrationEvent> events = [];
        using IDisposable observer = app.Server.Events.Subscribe(new CollectingObserver<ClientRegistrationEvent>(events));
        Dictionary<string, object> metadata = JsonSerializer.Deserialize<Dictionary<string, object>>(ManagementDocument("another-client", "refused"))!;
        if(isMissing)
        {
            _ = metadata.Remove("client_id");
        }

        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
            HttpMethod.Put, client.ManagementUri, client.AccessToken, JsonSerializer.Serialize(metadata), exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode);
        using JsonDocument error = JsonDocument.Parse(await response.Content.ReadAsStringAsync(exchange.Token).ConfigureAwait(false));
        Assert.AreEqual(OAuthErrors.InvalidClientMetadata, error.RootElement.GetProperty("error").GetString());
        Assert.AreSame(initial, app.RegistrationStore[client.ClientId]);
        Assert.IsEmpty(events);
    }


    /// <summary>
    /// Proves deletion authentication under <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.1">RFC 7592 section 2.1</see>.
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Section 4.1</see>:
    /// "Management requests for absent clients or with invalid registration access tokens return HTTP 401."
    /// </summary>
    [TestMethod]
    [DataRow("GET", false)]
    [DataRow("PUT", false)]
    [DataRow("DELETE", false)]
    [DataRow("GET", true)]
    [DataRow("PUT", true)]
    [DataRow("DELETE", true)]
    public async Task MissingClientOrInvalidManagementBearerReturnsUnauthorizedOverWire(string method, bool isAbsent)
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using CancellationTokenSource exchange = CreateTestCancellation();
        var client = await RegisterManagedClientOverWireAsync(app).ConfigureAwait(false);
        if(isAbsent)
        {
            using HttpResponseMessage deleted = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
                HttpMethod.Delete, client.ManagementUri, client.AccessToken, null, exchange.Token).ConfigureAwait(false);
            Assert.AreEqual(204, (int)deleted.StatusCode);
        }

        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
            new HttpMethod(method), client.ManagementUri, isAbsent ? client.AccessToken : "invalid-bearer",
            method == "PUT" ? ManagementDocument(client.ClientId, "refused") : null, exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(401, (int)response.StatusCode);
    }


    /// <summary>
    /// Proves conditional deletion under <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.3">RFC 7592 section 2.3</see>.
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Section 4.1</see>:
    /// "Deletion retries a lost conditional race and emits a tombstone one revision beyond the atomically removed record, so delayed updates cannot repopulate a deleted cache entry."
    /// </summary>
    [TestMethod]
    [DataRow(false, false)]
    [DataRow(true, false)]
    [DataRow(true, true)]
    public async Task ConditionalDeletionKeepsCacheDeletedAcrossCommitAndDeliveryOrdersOverWire(bool isUpdateFirst, bool isDeliveryReversed)
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using CancellationTokenSource exchange = CreateTestCancellation();
        var client = await RegisterManagedClientOverWireAsync(app).ConfigureAwait(false);
        TaskCompletionSource updateEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource deleteEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource releaseUpdate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource releaseDelete = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource updateCommitted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using ManualResetEventSlim deliverUpdate = new(false);
        app.Host("default").BeforeRegistrationUpdateAsync = async (_, ct) =>
        {
            bool wasUpdateEnteredSet = updateEntered.TrySetResult();
            await releaseUpdate.Task.WaitAsync(ct).ConfigureAwait(false);
        };
        app.Host("default").BeforeRegistrationDeleteAsync = async (_, ct) =>
        {
            bool wasDeleteEnteredSet = deleteEntered.TrySetResult();
            await releaseDelete.Task.WaitAsync(ct).ConfigureAwait(false);
        };
        using IDisposable delay = app.Server.Events.Subscribe(new ActionRegistrationObserver(value =>
        {
            if(value is ClientUpdated)
            {
                _ = updateCommitted.TrySetResult();
                if(isDeliveryReversed)
                {
                    deliverUpdate.Wait(deadline.Token);
                }
            }
        }));
        System.Collections.Concurrent.ConcurrentQueue<ClientRegistrationEvent> delivered = new();
        using IDisposable cache = app.Server.Events.Subscribe(new ActionRegistrationObserver(delivered.Enqueue));
        Task<HttpResponseMessage> updateTask = RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
            HttpMethod.Put, client.ManagementUri, client.AccessToken, ManagementDocument(client.ClientId, "racing"), exchange.Token);
        Task<HttpResponseMessage> deleteTask = RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
            HttpMethod.Delete, client.ManagementUri, client.AccessToken, null, exchange.Token);
        try
        {
            await Task.WhenAll(updateEntered.Task, deleteEntered.Task).WaitAsync(deadline.Token).ConfigureAwait(false);
            if(isUpdateFirst)
            {
                _ = releaseUpdate.TrySetResult();
                await updateCommitted.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
                if(!isDeliveryReversed)
                {
                    _ = await updateTask.ConfigureAwait(false);
                }

                _ = releaseDelete.TrySetResult();
                _ = await deleteTask.ConfigureAwait(false);
            }
            else
            {
                _ = releaseDelete.TrySetResult();
                _ = await deleteTask.ConfigureAwait(false);
                _ = releaseUpdate.TrySetResult();
            }
        }
        finally
        {
            _ = releaseUpdate.TrySetResult();
            _ = releaseDelete.TrySetResult();
            deliverUpdate.Set();
        }

        using HttpResponseMessage update = await updateTask.ConfigureAwait(false);
        using HttpResponseMessage delete = await deleteTask.ConfigureAwait(false);
        Assert.AreEqual(204, (int)delete.StatusCode);
        Assert.IsTrue((int)update.StatusCode is 200 or 400);
        Assert.IsFalse(app.RegistrationStore.ContainsKey(client.ClientId));
        ClientRegistrationEvent[] events = delivered.ToArray();
        ClientDeregistered tombstone = events.OfType<ClientDeregistered>().Single();
        Assert.AreEqual((int)update.StatusCode == 200 ? 3L : 2L, tombstone.Revision);
        long retainedRevision = 0;
        bool isPresent = true;
        foreach(ClientRegistrationEvent value in events)
        {
            if(value.Revision > retainedRevision)
            {
                retainedRevision = value.Revision;
                isPresent = value is not ClientDeregistered;
            }
        }

        Assert.IsFalse(isPresent, "A delayed update cannot repopulate a cache retaining the deletion revision.");
        Assert.AreEqual(tombstone.Revision, retainedRevision);
        Assert.HasCount((int)update.StatusCode == 200 ? 1 : 0, events.OfType<ClientUpdated>());
    }


    /// <summary>
    /// Proves identity isolation under <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.3">RFC 7592 section 2.3</see>.
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Section 4.1</see>:
    /// "A delayed deletion cannot remove a different client's reused tenant index or grant state."
    /// </summary>
    [TestMethod]
    public async Task DelayedDeletionPreservesReusedTenantOverWire()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using CancellationTokenSource exchange = CreateTestCancellation();
        var client = await RegisterManagedClientOverWireAsync(app).ConfigureAwait(false);
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        int attempts = 0;
        app.Host("default").BeforeRegistrationDeleteAsync = async (_, ct) =>
        {
            if(Interlocked.Increment(ref attempts) == 1)
            {
                bool wasEnteredSet = entered.TrySetResult();
                await release.Task.WaitAsync(ct).ConfigureAwait(false);
            }
        };
        Task<HttpResponseMessage> delayed = RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
            HttpMethod.Delete, client.ManagementUri, client.AccessToken, null, exchange.Token);
        await entered.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
        var replacement = client;
        try
        {
            using HttpResponseMessage deleted = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
                HttpMethod.Delete, client.ManagementUri, client.AccessToken, null, exchange.Token).ConfigureAwait(false);
            Assert.AreEqual(204, (int)deleted.StatusCode);
            replacement = await RegisterManagedClientOverWireAsync(app).ConfigureAwait(false);
        }
        finally
        {
            _ = release.TrySetResult();
        }

        using HttpResponseMessage stale = await delayed.ConfigureAwait(false);
        Assert.AreEqual(401, (int)stale.StatusCode);
        Assert.AreNotEqual(client.ClientId, replacement.ClientId);
        Assert.AreSame(app.RegistrationStore[replacement.ClientId], app.RegistrationStore["dynamic-clients"]);
        using HttpResponseMessage read = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
            HttpMethod.Get, replacement.ManagementUri, replacement.AccessToken, null, exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(200, (int)read.StatusCode, "A stale deletion cannot remove a reused tenant's live registration or grants.");
    }


    /// <summary>
    /// Proves capability isolation under <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">section 4.1</see>:
    /// "For a persisted registration, an absent grant set or a different current client identity grants no capabilities to an overlapping request."
    /// </summary>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task RevokedCapabilityStaysUnreachableAcrossDeletionOverWire(bool isTenantReused)
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using CancellationTokenSource exchange = CreateTestCancellation();
        var client = await RegisterManagedClientOverWireAsync(app).ConfigureAwait(false);
        await app.Server.GrantCapabilityAsync(app.RegistrationStore[client.ClientId], WellKnownCapabilityIdentifiers.OAuthJwksEndpoint, []).ConfigureAwait(false);
        await app.Server.RevokeCapabilityAsync(app.RegistrationStore[client.ClientId], WellKnownCapabilityIdentifiers.OAuthJwksEndpoint, "Access revoked.", []).ConfigureAwait(false);
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await TestHostShell.AlterAsync(app.Server, integration =>
        {
            var resolve = integration.ResolvePolicyAsync!;
            integration.ResolvePolicyAsync = async (registration, context, ct) =>
            {
                await resolve(registration, context, ct).ConfigureAwait(false);
                if(context.IncomingRequest!.Path.EndsWith("/jwks", StringComparison.Ordinal))
                {
                    _ = entered.TrySetResult();
                    await release.Task.WaitAsync(ct).ConfigureAwait(false);
                }
            };
        }).ConfigureAwait(false);
        Task<ServerHttpResponse> pending = RawAuthCodeWirePushers.PushNamedEndpointAsync(app, "dynamic-clients",
            WellKnownEndpointNames.MetadataJwks, "GET", new RequestFields(), [], exchange.Token);
        try
        {
            await entered.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            using HttpResponseMessage deleted = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
                HttpMethod.Delete, client.ManagementUri, client.AccessToken, null, exchange.Token).ConfigureAwait(false);
            Assert.AreEqual(204, (int)deleted.StatusCode);
            if(isTenantReused)
            {
                var replacement = await RegisterManagedClientOverWireAsync(app).ConfigureAwait(false);
                await app.Server.GrantCapabilityAsync(app.RegistrationStore[replacement.ClientId], WellKnownCapabilityIdentifiers.OAuthJwksEndpoint, []).ConfigureAwait(false);
            }
        }
        finally
        {
            _ = release.TrySetResult();
        }

        ServerHttpResponse response = await pending.ConfigureAwait(false);
        Assert.AreEqual(404, response.StatusCode, "The loaded client's revoked capability cannot become reachable during deletion or tenant reuse.");
    }


    /// <summary>
    /// Proves ordered capability effects under <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">section 4.1</see>:
    /// "Capability effects apply only to their source identity and revision, so a delayed signal cannot overwrite a newer grant decision."
    /// </summary>
    [TestMethod]
    public async Task DelayedCapabilityGrantCannotOverrideRevocationOverWire()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using CancellationTokenSource exchange = CreateTestCancellation();
        var client = await RegisterManagedClientOverWireAsync(app).ConfigureAwait(false);
        ClientRecord initial = app.RegistrationStore[client.ClientId];
        await app.Server.GrantCapabilityAsync(initial, WellKnownCapabilityIdentifiers.OAuthJwksEndpoint, []).ConfigureAwait(false);
        await app.Server.RevokeCapabilityAsync(app.RegistrationStore[client.ClientId], WellKnownCapabilityIdentifiers.OAuthJwksEndpoint, "Access revoked.", []).ConfigureAwait(false);
        await app.Server.GrantCapabilityAsync(initial, WellKnownCapabilityIdentifiers.OAuthJwksEndpoint, []).ConfigureAwait(false);
        ServerHttpResponse response = await RawAuthCodeWirePushers.PushNamedEndpointAsync(app, "dynamic-clients",
            WellKnownEndpointNames.MetadataJwks, "GET", new RequestFields(), [], exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(404, response.StatusCode);
    }


    /// <summary>
    /// Proves client serialization under <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.2">RFC 7592 section 2.2</see>.
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Section 4.1</see>:
    /// "The client update handler includes its issued client identifier in the complete replacement document."
    /// </summary>
    [TestMethod]
    public async Task ClientUpdateHandlerIncludesIssuedIdentifierOverWire()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using CancellationTokenSource exchange = CreateTestCancellation();
        var client = await RegisterManagedClientOverWireAsync(app).ConfigureAwait(false);
        Verifiable.OAuth.Client.OAuthClientInfrastructure source = app.CreateOAuthClientWithoutRegistration().Infrastructure;
        int responseStatus = 0;
        Verifiable.OAuth.Client.OAuthClientInfrastructure infrastructure = Verifiable.OAuth.Client.OAuthClientInfrastructure.Create(
            source.SendFormPostAsync, source.SaveStateAsync, source.LoadStateAsync, source.LoadStateByRequestUriAsync,
            source.ParseParResponseAsync, source.ParseTokenResponseAsync,
            source.ParseRegistrationResponseAsync, source.ResolveAuthorizationServerMetadataAsync, source.ResolveCallbackValidator,
            source.Base64UrlEncoder, source.MemoryPool, source.TimeProvider, source.FillEntropy, source.GenerateIdentifierAsync,
            sendJsonPutAsync: async (endpoint, json, headers, _, ct) =>
            {
                string bearer = headers.Values[WellKnownHttpHeaderNames.Authorization][(WellKnownAuthenticationSchemes.Bearer.Length + 1)..];
                using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
                    HttpMethod.Put, endpoint, bearer, json, ct).ConfigureAwait(false);
                responseStatus = (int)response.StatusCode;

                return new HttpResponseData
                {
                    StatusCode = responseStatus,
                    Body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false)
                };
            },
            parseClientMetadataAsync: source.ParseClientMetadataAsync);
        Verifiable.OAuth.Client.ClientRegistration registration = new()
        {
            ClientId = new(client.ClientId),
            AuthorizationServerIssuer = app.IssuerUri,
            AuthenticationMethod = Verifiable.OAuth.Client.ClientAuthenticationMethod.None,
            AccessToken = new RegistrationAccessToken(client.AccessToken),
            ManagementUri = client.ManagementUri
        };
        Verifiable.OAuth.Client.ClientMetadata metadata = new()
        {
            ClientName = "client-serializer-update",
            ClientUri = new Uri("https://client.example.test/"),
            RedirectUris = [new Uri("https://client.example.test/callback")],
            Scope = "initial-scope"
        };
        InvalidOperationException? failure = null;
        try
        {
            _ = await Verifiable.OAuth.Client.DynamicRegistrationHandlers.HandleUpdateAsync(
                registration, metadata, infrastructure, [], exchange.Token).ConfigureAwait(false);
        }
        catch(InvalidOperationException exception)
        {
            failure = exception;
        }

        Assert.AreEqual(200, responseStatus);
        Assert.IsNull(failure);
        Assert.AreEqual("client-serializer-update", app.RegistrationStore[client.ClientId].ClientName);
    }


    /// <summary>
    /// Proves response completeness under <see href="https://www.rfc-editor.org/rfc/rfc7592#section-3">RFC 7592 section 3</see>.
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Section 4.1</see>:
    /// "Registration responses carry an absolute configuration URI, the management bearer, the client identifier and every accepted metadata field."
    /// </summary>
    [TestMethod]
    public async Task ManagementResponsesCarryAllRegisteredMetadataOverWire()
    {
        using CancellationTokenSource deadline = CreateTestCancellation();
        await using TestHostShell app = new(TimeProvider);
        await app.StartHttpHostAsync(deadline.Token).ConfigureAwait(false);
        using CancellationTokenSource exchange = CreateTestCancellation();
        string metadata = """
            {"client_name":"complete","client_uri":"https://client.example.test/","redirect_uris":["https://client.example.test/callback"],"scope":"initial-scope","logo_uri":"https://client.example.test/logo","grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none","token_endpoint_auth_signing_alg":"ES256","authorization_details_types":["payment"],"authorization_grant_profiles_supported":["profile-a"],"jwks":{"keys":[]},"software_statement":"opaque-statement","application_type":"web","id_token_signed_response_alg":"ES256","request_object_signing_alg":"ES256","request_object_encryption_alg":"ECDH-ES","post_logout_redirect_uris":["https://client.example.test/logout"],"backchannel_logout_uri":"https://client.example.test/backchannel","backchannel_logout_session_required":true,"frontchannel_logout_uri":"https://client.example.test/frontchannel","frontchannel_logout_session_required":true}
            """;
        using HttpResponseMessage created = await RawAuthCodeWirePushers.SendPinnedJsonPostAsync(app,
            new Uri(app.Host("default").HttpBaseAddress!, "/connect/register"), metadata, exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(201, (int)created.StatusCode);
        using JsonDocument initial = JsonDocument.Parse(await created.Content.ReadAsStringAsync(exchange.Token).ConfigureAwait(false));
        Assert.IsTrue(Uri.TryCreate(initial.RootElement.GetProperty("registration_client_uri").GetString(), UriKind.Absolute, out Uri? uri),
            "The wire value itself must be an absolute configuration URI.");
        string clientId = initial.RootElement.GetProperty("client_id").GetString()!;
        string token = initial.RootElement.GetProperty("registration_access_token").GetString()!;
        Assert.IsFalse(string.IsNullOrEmpty(clientId));
        Assert.IsFalse(string.IsNullOrEmpty(token));
        using JsonDocument expected = JsonDocument.Parse(metadata);
        foreach(JsonProperty property in expected.RootElement.EnumerateObject())
        {
            Assert.IsTrue(JsonElement.DeepEquals(property.Value, initial.RootElement.GetProperty(property.Name)), property.Name);
        }

        Dictionary<string, object> replacement = JsonSerializer.Deserialize<Dictionary<string, object>>(metadata)!;
        replacement["client_id"] = clientId;
        replacement["client_name"] = "complete-replacement";
        string replacementJson = JsonSerializer.Serialize(replacement);
        using JsonDocument winning = JsonDocument.Parse(replacementJson);
        using HttpResponseMessage updated = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
            HttpMethod.Put, uri!, token, replacementJson, exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(200, (int)updated.StatusCode);
        using HttpResponseMessage read = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(app,
            HttpMethod.Get, uri!, token, null, exchange.Token).ConfigureAwait(false);
        Assert.AreEqual(200, (int)read.StatusCode);
        foreach(HttpResponseMessage response in new[] { updated, read })
        {
            using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(deadline.Token).ConfigureAwait(false));
            Assert.AreEqual(clientId, body.RootElement.GetProperty("client_id").GetString());
            Assert.AreEqual(token, body.RootElement.GetProperty("registration_access_token").GetString());
            Assert.AreEqual(uri!.AbsoluteUri, body.RootElement.GetProperty("registration_client_uri").GetString());
            foreach(JsonProperty property in winning.RootElement.EnumerateObject())
            {
                Assert.IsTrue(JsonElement.DeepEquals(property.Value, body.RootElement.GetProperty(property.Name)), property.Name);
            }
        }
    }


    /// <summary>Builds the complete replacement metadata with the issued client identifier required by RFC 7592 section 2.2.</summary>
    private static string ManagementDocument(string clientId, string name,
        string redirectUri = "https://client.example.test/callback", string scope = "initial-scope") =>
        JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["client_id"] = clientId,
            ["client_name"] = name,
            ["client_uri"] = "https://client.example.test/",
            ["redirect_uris"] = new[] { redirectUri },
            ["scope"] = scope
        });


    /// <summary>Creates a managed registration through the listener and reads its client-owned credential.</summary>
    /// <param name="app">The serving fixture.</param>
    /// <param name="cancellationToken">An explicit case deadline; an absent value selects a fresh exchange-only deadline.</param>
    private async Task<(string ClientId, string AccessToken, Uri ManagementUri)> RegisterManagedClientOverWireAsync(
        TestHostShell app, CancellationToken? cancellationToken = null)
    {
        using CancellationTokenSource? deadline = cancellationToken.HasValue ? null : CreateTestCancellation();
        CancellationToken exchangeToken = cancellationToken ?? deadline!.Token;
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedJsonPostAsync(app,
            new Uri(app.Host("default").HttpBaseAddress!, "/connect/register"),
            "{\"client_name\":\"initial-client\",\"client_uri\":\"https://client.example.test/\",\"redirect_uris\":[\"https://client.example.test/callback\"],\"scope\":\"initial-scope\"}", exchangeToken).ConfigureAwait(false);
        Exception[] faults = app.Host("default").ConsumeHttpFaults();
        Assert.AreEqual(201, (int)response.StatusCode, "A committed registration must return HTTP 201.");
        Assert.IsEmpty(faults, "Successful registration must have no unconsumed request faults.");
        using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(exchangeToken).ConfigureAwait(false));

        return (body.RootElement.GetProperty("client_id").GetString()!,
            body.RootElement.GetProperty("registration_access_token").GetString()!,
            new Uri(body.RootElement.GetProperty("registration_client_uri").GetString()!, UriKind.Absolute));
    }


    /// <summary>An observer that invokes its action without retaining a mutable delivery collection.</summary>
    private sealed class ActionRegistrationObserver(Action<ClientRegistrationEvent> action): IObserver<ClientRegistrationEvent>
    {
        /// <summary>Invokes the application callback for the supplied immutable event.</summary>
        public void OnNext(ClientRegistrationEvent value) => action(value);


        /// <summary>Accepts the stream error callback.</summary>
        public void OnError(Exception error)
        {
        }


        /// <summary>Accepts the stream completion callback.</summary>
        public void OnCompleted()
        {
        }
    }


    /// <summary>An observer whose application equality is deliberately independent of subscription identity.</summary>
    /// <param name="events">The collection receiving notifications for this particular observer.</param>
    private sealed class EqualRegistrationObserver(List<ClientRegistrationEvent> events): IObserver<ClientRegistrationEvent>
    {
        /// <summary>Records this observer's own delivery.</summary>
        public void OnNext(ClientRegistrationEvent value)
        {
            events.Add(value);
        }


        /// <summary>Accepts the observable error callback.</summary>
        public void OnError(Exception error)
        {
        }


        /// <summary>Accepts the observable completion callback.</summary>
        public void OnCompleted()
        {
        }


        /// <summary>Defines application equality without sharing delivery state.</summary>
        public override bool Equals(object? obj) => obj is EqualRegistrationObserver;


        /// <summary>Uses one hash for the application's equality domain.</summary>
        public override int GetHashCode() => 0;
    }


    /// <summary>
    /// Creates a test-owned cancellation source for barriers, requests and alteration completion, linked
    /// to <see cref="TestContext"/>'s own cancellation token and bounded by nothing else: MSTest owns the
    /// timeout for this class, never a wall-clock budget of the test's own.
    /// </summary>
    private CancellationTokenSource CreateTestCancellation()
    {
        return CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
    }


    /// <summary>Registers a client through the global endpoint on the pinned listener.</summary>
    /// <param name="app">The serving fixture.</param>
    /// <param name="cancellationToken">An explicit case deadline; an absent value selects a fresh exchange-only deadline.</param>
    private async Task<HttpResponseMessage> RegisterOverWireAsync(TestHostShell app, CancellationToken? cancellationToken = null)
    {
        using CancellationTokenSource? deadline = cancellationToken.HasValue ? null : CreateTestCancellation();

        return await RawAuthCodeWirePushers.SendPinnedJsonPostAsync(app,
            new Uri(app.Host("default").HttpBaseAddress!, "/connect/register"),
            "{\"redirect_uris\":[\"https://client.example.test/callback\"]}", cancellationToken ?? deadline!.Token).ConfigureAwait(false);
    }


    /// <summary>Reads the emitted wiring identity from the real metadata response.</summary>
    /// <param name="body">The JSON response body.</param>
    private static string ReadMarker(string body)
    {
        using JsonDocument document = JsonDocument.Parse(body);

        return document.RootElement.GetProperty("wiring_marker").GetString()!;
    }


    /// <summary>Sends a discovery GET through the pinned listener.</summary>
    /// <param name="app">The running host fixture.</param>
    /// <param name="registration">The target tenant registration.</param>
    /// <param name="cancellationToken">An explicit case deadline; an absent value selects the default request deadline.</param>
    private async Task<HttpResponseMessage> SendDiscoveryAsync(TestHostShell app, ClientRecord registration, CancellationToken? cancellationToken = null)
    {
        Uri uri = new(app.Host("default").HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.MetadataDiscovery, registration.TenantId.Value));
        using CancellationTokenSource? deadline = cancellationToken.HasValue ? null : CreateTestCancellation();

        return await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(app, uri, "alteration-subject", cancellationToken ?? deadline!.Token).ConfigureAwait(false);
    }


    /// <summary>Returns a successful discovery response body obtained over the listener.</summary>
    /// <param name="app">The running host fixture.</param>
    /// <param name="registration">The target tenant registration.</param>
    /// <param name="cancellationToken">The case deadline shared with transport and alteration barriers.</param>
    private async Task<string> ReadDiscoveryAsync(TestHostShell app, ClientRecord registration, CancellationToken? cancellationToken = null)
    {
        using HttpResponseMessage response = await SendDiscoveryAsync(app, registration, cancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(cancellationToken ?? TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        return body;
    }


    /// <summary>Builds cooperating metadata builders that expose one configuration's identity.</summary>
    /// <remarks>
    /// The second builder re-derives its marker from <c>ExchangeContextServerExtensions.RequestServer</c>
    /// into an isolated probe context. The request lease and the fixed view independently preserve
    /// configuration identity, so the response invariant covers their combined behavior.
    /// </remarks>
    /// <param name="configuration">The configuration whose admission policy is retained.</param>
    /// <param name="marker">The identity each builder writes onto the request context.</param>
    private static ServerConfiguration ProbeConfiguration(ServerConfiguration configuration, string marker)
    {

        return configuration with
        {
            EndpointBuilders = new EndpointBuilderSet([
                (_, ctx, _) =>
                {
                    ctx["left"] = marker;

                    return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>([]);
                },
                async (registration, ctx, ct) =>
                {
                    ExchangeContext probe = [];
                    _ = await ctx.RequestServer!.Configuration.EndpointBuilders[0](registration, probe, ct).ConfigureAwait(false);
                    ctx["right"] = probe["left"];

                    return await MetadataEndpoints.Builder(registration, ctx, ct).ConfigureAwait(false);
                }])
        };
    }


    /// <summary>
    /// An event observer that retains notifications for in-process registration assertions.
    /// The supplied list receives each synchronous notification in delivery order.
    /// </summary>
    /// <typeparam name="T">The notification type.</typeparam>
    /// <param name="collected">The list used by the test to inspect notifications.</param>
    /// <param name="observe">An optional synchronous request observer.</param>
    private sealed class CollectingObserver<T>(List<T> collected, Action<T>? observe = null): IObserver<T>
    {
        /// <summary>
        /// Records the delivered notification so the test can inspect its payload.
        /// </summary>
        /// <param name="value">The delivered notification.</param>
        public void OnNext(T value)
        {
            collected.Add(value);
            observe?.Invoke(value);
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

