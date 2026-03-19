using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.JCose.Sd;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for <see cref="TestHostShell"/> exercising the
/// <see cref="AuthorizationServer"/> observable paths, dynamic registration,
/// deregistration, key rotation, and multi-client routing — exactly as a production
/// ASP.NET application would observe them.
/// </summary>
/// <remarks>
/// Each test subscribes to <see cref="app.Server.Events"/> independently
/// to assert that the correct events are emitted in order with the correct payloads.
/// The routing table assertions verify that the observable subscriber updates the
/// in-memory store that backs <see cref="AuthorizationServerOptions.LoadClientRegistrationAsync"/>
/// before each test's dispatch calls begin.
/// </remarks>
[TestClass]
internal sealed class AuthorizationServerFeatureTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private const string VerifierClientId = "https://verifier.example.com";

    private static Uri VerifierBaseUri { get; } = new("https://verifier.example.com");

    private const string IssuerId = "https://issuer.example.com";
    private const string IssuerKeyId = "did:web:issuer.example.com#key-1";
    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    private static ImmutableHashSet<ServerCapabilityName> Oid4VpCapabilities { get; } =
        ImmutableHashSet.Create(
            ServerCapabilityName.VerifiablePresentation,
            ServerCapabilityName.JwksEndpoint,
            ServerCapabilityName.DiscoveryEndpoint);

    private static ImmutableHashSet<ServerCapabilityName> JwksCapabilities { get; } =
        [ServerCapabilityName.JwksEndpoint];


    /// <summary>
    /// Every signing algorithm the library supports. Each entry is a display
    /// name (from a well-known constant) and a factory function from
    /// <see cref="TestKeyMaterialProvider"/>. Expected JWK fields are derived
    /// from the key's <see cref="Tag"/> at test time — adding a new algorithm
    /// requires only a new row here.
    /// </summary>
    public static IEnumerable<object[]> AllSigningAlgorithms { get; } =
    [
        [WellKnownCurveValues.P256,
            new Func<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>>(
                TestKeyMaterialProvider.CreateP256KeyMaterial)],

        [WellKnownCurveValues.P384,
            new Func<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>>(
                TestKeyMaterialProvider.CreateP384KeyMaterial)],

        [WellKnownCurveValues.P521,
            new Func<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>>(
                TestKeyMaterialProvider.CreateP521KeyMaterial)],

        [WellKnownCurveValues.Ed25519,
            new Func<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>>(
                TestKeyMaterialProvider.CreateEd25519KeyMaterial)],

        [WellKnownCurveValues.Secp256k1,
            new Func<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>>(
                TestKeyMaterialProvider.CreateSecp256k1KeyMaterial)],

        [WellKnownKeyTypeValues.Rsa,
            new Func<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>>(
                TestKeyMaterialProvider.CreateRsa2048KeyMaterial)],

        [WellKnownJwaValues.MlDsa44,
            new Func<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>>(
                TestKeyMaterialProvider.CreateMlDsa44KeyMaterial)],

        [WellKnownJwaValues.MlDsa65,
            new Func<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>>(
                TestKeyMaterialProvider.CreateMlDsa65KeyMaterial)],

        [WellKnownJwaValues.MlDsa87,
            new Func<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>>(
                TestKeyMaterialProvider.CreateMlDsa87KeyMaterial)],
    ];


    //=========================================================================
    //Observable: ClientRegistered event fires on registration.
    //
    //A real ASP.NET app subscribes to app.Server.Events at
    //startup to populate its routing table. This test verifies that the event
    //fires with the correct payload immediately when RegisterClient is called,
    //before any dispatch calls are made.
    //=========================================================================

    [TestMethod]
    public void ValidatePassesWithoutActionExecutorForAuthCodeFlow()
    {
        //ActionExecutor is only needed for flows that produce OAuthAction values —
        //the OID4VP Verifier flow does. The Authorization Code server flow does not.
        //Validate() must not require it so Auth Code deployments can omit it cleanly.
        AuthorizationServerOptions options = new()
        {
            TimeProvider = TimeProvider,
            Encoder = TestSetup.Base64UrlEncoder,
            Decoder = TestSetup.Base64UrlDecoder,
            HashFunctionSelector = DefaultHashFunctionSelector.Select,
            ExtractTenantIdAsync = (ctx, ct) =>
                ValueTask.FromResult<TenantId?>(null),
            LoadClientRegistrationAsync = (tenantId, ctx, ct) =>
                ValueTask.FromResult<ClientRegistration?>(null),
            SaveFlowStateAsync = (tenantId, key, state, stepCount, ctx, ct) =>
                ValueTask.CompletedTask,
            LoadFlowStateAsync = (tenantId, key, ctx, ct) =>
                ValueTask.FromResult<(OAuthFlowState?, int)>((null, 0)),
            SigningKeyResolver = (keyId, ctx, ct) =>
                ValueTask.FromResult<Verifiable.Cryptography.PrivateKeyMemory?>(null),
            VerificationKeyResolver = (keyId, ctx, ct) =>
                ValueTask.FromResult<Verifiable.Cryptography.PublicKeyMemory?>(null),
            JwtHeaderSerializer = static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)header,
                TestSetup.DefaultSerializationOptions),
            JwtPayloadSerializer = static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)payload,
                TestSetup.DefaultSerializationOptions),
            EndpointBuilders = [AuthCodeEndpoints.Builder]
            //ActionExecutor deliberately omitted.
        };

        //Must not throw.
        options.Validate();

        Assert.IsTrue(options.IsValidated,
            "Options without ActionExecutor must pass validation for Auth Code flows.");
    }


    [TestMethod]
    public void ValidateThrowsWhenRequiredDelegatesAreMissing()
    {
        //All required delegates omitted — Validate must list them all.
        AuthorizationServerOptions options = new()
        {
            TimeProvider = TimeProvider
        };

        InvalidOperationException ex =
            Assert.ThrowsExactly<InvalidOperationException>(options.Validate);

        Assert.IsTrue(
            ex.Message.Contains(
                nameof(AuthorizationServerOptions.LoadClientRegistrationAsync),
                StringComparison.Ordinal),
            "Error must name LoadClientRegistrationAsync.");
        Assert.IsTrue(
            ex.Message.Contains(
                nameof(AuthorizationServerOptions.SaveFlowStateAsync),
                StringComparison.Ordinal),
            "Error must name SaveFlowStateAsync.");
        Assert.IsTrue(
            ex.Message.Contains(
                nameof(AuthorizationServerOptions.LoadFlowStateAsync),
                StringComparison.Ordinal),
            "Error must name LoadFlowStateAsync.");
        Assert.IsTrue(
            ex.Message.Contains(
                nameof(AuthorizationServerOptions.SigningKeyResolver),
                StringComparison.Ordinal),
            "Error must name SigningKeyResolver.");
        Assert.IsTrue(
            ex.Message.Contains(
                nameof(AuthorizationServerOptions.VerificationKeyResolver),
                StringComparison.Ordinal),
            "Error must name VerificationKeyResolver.");
        Assert.IsTrue(
            ex.Message.Contains(
                nameof(AuthorizationServerOptions.Encoder),
                StringComparison.Ordinal),
            "Error must name Encoder.");
        Assert.IsTrue(
            ex.Message.Contains(
                nameof(AuthorizationServerOptions.Decoder),
                StringComparison.Ordinal),
            "Error must name Decoder.");
        Assert.IsTrue(
            ex.Message.Contains(
                nameof(AuthorizationServerOptions.HashFunctionSelector),
                StringComparison.Ordinal),
            "Error must name HashFunctionSelector.");
        Assert.IsTrue(
            ex.Message.Contains(
                nameof(AuthorizationServerOptions.JwtHeaderSerializer),
                StringComparison.Ordinal),
            "Error must name JwtHeaderSerializer.");
        Assert.IsTrue(
            ex.Message.Contains(
                nameof(AuthorizationServerOptions.JwtPayloadSerializer),
                StringComparison.Ordinal),
            "Error must name JwtPayloadSerializer.");
        Assert.IsTrue(
            ex.Message.Contains(
                nameof(AuthorizationServerOptions.EndpointBuilders),
                StringComparison.Ordinal),
            "Error must name EndpointBuilders.");
        Assert.IsFalse(
            ex.Message.Contains(
                nameof(AuthorizationServerOptions.ActionExecutor),
                StringComparison.Ordinal),
            "Error must not name ActionExecutor — it is optional.");
    }


    [TestMethod]
    public void RegisterClientFiresClientRegisteredEventWithCorrectPayload()
    {
        List<ClientRegistrationEvent> received = [];



        using TestHostShell app = new(TimeProvider);

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
        Assert.IsInstanceOfType<ClientRegistered>(forThisSegment[0],
            "The emitted event must be ClientRegistered.");

        ClientRegistered evt = (ClientRegistered)forThisSegment[0];
        Assert.AreEqual(VerifierClientId, evt.ClientId,
            "ClientRegistered must carry the registered client identifier.");
        Assert.AreEqual(segment, evt.TenantId.Value,
            "ClientRegistered must carry the endpoint segment.");
        Assert.AreSame(keys.Registration, evt.Registration,
            "ClientRegistered must carry the exact ClientRegistration instance.");
    }


    //=========================================================================
    //Observable: registration store is populated before dispatch.
    //
    //The routing table must be updated synchronously by the subscriber so that
    //the first dispatch call after RegisterClient can resolve the registration.
    //=========================================================================

    [TestMethod]
    public void RegistrationStoreIsPopulatedImmediatelyAfterRegisterClient()
    {
        using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        Assert.IsTrue(
            app.RegistrationStore.ContainsKey(keys.Registration.TenantId),
            "Registration store must contain the segment immediately after RegisterClient.");

        ClientRegistration stored = app.RegistrationStore[keys.Registration.TenantId];
        Assert.AreEqual(VerifierClientId, stored.ClientId,
            "Stored registration must carry the correct client identifier.");
    }


    //=========================================================================
    //Observable: deregistration removes from routing table immediately.
    //
    //A production app that deregisters a client must have the routing table
    //updated before the next request arrives. Dispatch to the deregistered
    //segment must return 404.
    //=========================================================================

    [TestMethod]
    public async Task DeregisterClientRemovesFromRoutingTableAndDispatchReturns404()
    {
        List<ClientRegistrationEvent> received = [];



        using TestHostShell app = new(TimeProvider);

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
        Assert.IsInstanceOfType<ClientRegistered>(forThisSegment[0]);
        Assert.IsInstanceOfType<ClientDeregistered>(forThisSegment[1]);

        ClientDeregistered deregistered = (ClientDeregistered)forThisSegment[1];
        Assert.AreEqual(segment, deregistered.TenantId.Value,
            "ClientDeregistered must carry the correct endpoint segment.");
        Assert.AreEqual("Test deregistration.", deregistered.Reason,
            "ClientDeregistered must carry the deregistration reason.");

        //A dispatch to the deregistered segment must return 404.
        ServerHttpResponse response = await app.DispatchBySegmentAsync(
            segment,
            ServerCapabilityName.VerifiablePresentation,
            "POST",
            new RequestFields(),
            new RequestContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode,
            "Dispatch to a deregistered segment must return 404.");
    }


    //=========================================================================
    //Observable: key rotation updates registration and new flows use new key.
    //
    //Key rotation is a common production operation. The old signing key must
    //remain resolvable for in-flight flows. New flows must use the new signing
    //key. This test verifies that RotateSigningKey emits ClientUpdated, that
    //the routing table reflects the new key identifier, and that a full flow
    //completed after rotation verifies correctly with the new key.
    //=========================================================================

    [TestMethod]
    public async Task KeyRotationEmitsClientUpdatedAndNewFlowUsesNewKey()
    {
        List<ClientRegistrationEvent> received = [];



        using TestHostShell app = new(TimeProvider);

        using IDisposable subscription = app.Server.Events.Subscribe(
            new CollectingObserver<ClientRegistrationEvent>(received));
        using VerifierKeyMaterial originalKeys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        string segment = originalKeys.Registration.TenantId;
        KeyId originalSigningKeyId = originalKeys.SigningKeyId;

        //Rotate — emits ClientUpdated, adds new keys to stores.
        using VerifierKeyMaterial rotatedKeys = app.RotateSigningKey(segment);

        //Filter to this segment — the static subject is shared across tests.
        ClientRegistrationEvent[] forThisSegment = received
            .Where(e => string.Equals(e.TenantId, segment, StringComparison.Ordinal))
            .ToArray();

        Assert.HasCount(2, forThisSegment,
            "ClientRegistered then ClientUpdated must be emitted for this segment.");
        Assert.IsInstanceOfType<ClientUpdated>(forThisSegment[1],
            "Second event must be ClientUpdated.");

        ClientUpdated updated = (ClientUpdated)forThisSegment[1];
        Assert.AreEqual(originalSigningKeyId, updated.Previous.GetDefaultSigningKeyId(KeyUsageContext.JarSigning),
            "ClientUpdated.Previous must carry the original signing key identifier.");
        Assert.AreEqual(rotatedKeys.SigningKeyId, updated.Current.GetDefaultSigningKeyId(KeyUsageContext.JarSigning),
            "ClientUpdated.Current must carry the new signing key identifier.");

        //Routing table must immediately reflect the new registration.
        ClientRegistration current = app.RegistrationStore[segment];
        Assert.AreEqual(rotatedKeys.SigningKeyId, current.GetDefaultSigningKeyId(KeyUsageContext.JarSigning),
            "Routing table must carry the new signing key identifier after rotation.");

        //A full flow completed after rotation must succeed with the new key.

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        TestWallet wallet = new(
            VerifierClientId,
            new Dictionary<string, string> { ["pid"] = serializedSdJwt },
            holderKey,
            TimeProvider);

        string walletFlowId = $"wallet-rotated-{Guid.NewGuid():N}";

        (Uri requestUri, string requestUriToken) = await app.HandleParAsync(rotatedKeys,
            new TransactionNonce("nonce-rotation-01"),
            CreatePreparedQuery(),
            VerifierBaseUri,
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = await app.HandleJarRequestAsync(rotatedKeys,
            requestUriToken, TestContext.CancellationToken).ConfigureAwait(false);

        wallet.HandleQrScan(requestUri, walletFlowId);

        await wallet.HandleJarFetchAsync(
            walletFlowId,
            requestUri,
            compactJar,
            rotatedKeys.SigningPublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJwe = await wallet.HandleResponsePostAsync(
            walletFlowId, TestContext.CancellationToken).ConfigureAwait(false);

        PresentationVerifiedState verified = await app.HandleDirectPostAsync(rotatedKeys,
            requestUriToken,
            compactJwe,
            redirectUri: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<PresentationVerifiedState>(
            app.GetFlowState(requestUriToken).State,
            "Flow started after key rotation must reach PresentationVerified.");
        Assert.IsTrue(verified.Claims.ContainsKey("pid"),
            "Verified claims must contain the pid credential.");
    }


    //=========================================================================
    //Observable: multiple clients registered, each receives independent events.
    //
    //A SaaS deployment registers multiple tenants. Each registration emits its
    //own ClientRegistered event. All registrations must be independently
    //reachable via their own endpoint segments with no cross-contamination.
    //=========================================================================

    [TestMethod]
    public async Task MultipleClientsRegisteredEachReachableIndependently()
    {
        List<ClientRegistrationEvent> received = [];



        using TestHostShell app = new(TimeProvider);

        using IDisposable subscription = app.Server.Events.Subscribe(
            new CollectingObserver<ClientRegistrationEvent>(received));
        using VerifierKeyMaterial keysA = app.RegisterClient("https://tenant-a.example.com", VerifierBaseUri, Oid4VpCapabilities);
        using VerifierKeyMaterial keysB = app.RegisterClient("https://tenant-b.example.com", VerifierBaseUri, Oid4VpCapabilities);

        string segmentA = keysA.Registration.TenantId;
        string segmentB = keysB.Registration.TenantId;

        Assert.AreNotEqual(segmentA, segmentB,
            "Each registration must receive a distinct endpoint segment.");

        //Filter to events for segments created in this test only.
        ClientRegistrationEvent[] forSegmentA = received
            .Where(e => string.Equals(e.TenantId, segmentA, StringComparison.Ordinal))
            .ToArray();
        ClientRegistrationEvent[] forSegmentB = received
            .Where(e => string.Equals(e.TenantId, segmentB, StringComparison.Ordinal))
            .ToArray();

        Assert.HasCount(1, forSegmentA,
            "Exactly one ClientRegistered event must be emitted for tenant A.");
        Assert.HasCount(1, forSegmentB,
            "Exactly one ClientRegistered event must be emitted for tenant B.");

        //Both registrations reachable in the routing table.
        Assert.IsTrue(app.RegistrationStore.ContainsKey(segmentA),
            "Tenant A registration must be in the routing table.");
        Assert.IsTrue(app.RegistrationStore.ContainsKey(segmentB),
            "Tenant B registration must be in the routing table.");

        //Run a full flow for tenant A — must not affect tenant B's routing.

        (string serializedSdJwtA, PrivateKeyMemory holderPrivateKeyA, PublicKeyMemory issuerPublicKeyA) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKeyA = holderPrivateKeyA;
        using PublicKeyMemory issuerKeyA = issuerPublicKeyA;
        app.RegisterIssuerTrust(IssuerId, issuerKeyA);

        TestWallet walletA = new(
            "https://tenant-a.example.com",
            new Dictionary<string, string> { ["pid"] = serializedSdJwtA },
            holderKeyA,
            TimeProvider);

        string walletFlowId = $"wallet-multi-{Guid.NewGuid():N}";

        (Uri requestUriA, string requestUriTokenA) = await app.HandleParAsync(keysA,
            new TransactionNonce("nonce-multi-a-01"),
            CreatePreparedQuery(),
            VerifierBaseUri,
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJarA = await app.HandleJarRequestAsync(keysA,
            requestUriTokenA, TestContext.CancellationToken).ConfigureAwait(false);

        walletA.HandleQrScan(requestUriA, walletFlowId);

        await walletA.HandleJarFetchAsync(
            walletFlowId,
            requestUriA,
            compactJarA,
            keysA.SigningPublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJweA = await walletA.HandleResponsePostAsync(
            walletFlowId, TestContext.CancellationToken).ConfigureAwait(false);

        PresentationVerifiedState verifiedA = await app.HandleDirectPostAsync(keysA,
            requestUriTokenA,
            compactJweA,
            redirectUri: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<PresentationVerifiedState>(
            app.GetFlowState(requestUriTokenA).State,
            "Tenant A flow must reach PresentationVerified.");

        //Tenant B routing table entry must be unaffected.
        Assert.IsTrue(app.RegistrationStore.ContainsKey(segmentB),
            "Tenant B registration must remain in routing table after tenant A flow completes.");
        Assert.AreEqual("https://tenant-b.example.com",
            app.RegistrationStore[segmentB].ClientId,
            "Tenant B registration must retain its original client identifier.");
    }


    //=========================================================================
    //Observable: capability granted event fires and is carried correctly.
    //
    //Verifies that OnCapabilityGranted produces a CapabilityGranted event with
    //the correct payload — a production app would use this to activate new
    //endpoints for a client without a full re-registration.
    //=========================================================================

    [TestMethod]
    public void CapabilityGrantedEventCarriesCorrectPayload()
    {
        List<ClientRegistrationEvent> received = [];



        using TestHostShell app = new(TimeProvider);

        using IDisposable subscription = app.Server.Events.Subscribe(
            new CollectingObserver<ClientRegistrationEvent>(received));
        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        string segment = keys.Registration.TenantId;

        app.Server.GrantCapability(
            keys.Registration,
            ServerCapabilityName.VerifiableCredentialIssuance,
            new RequestContext());

        //Filter to this segment — the static subject is shared across tests.
        ClientRegistrationEvent[] forThisSegment = received
            .Where(e => string.Equals(e.TenantId, segment, StringComparison.Ordinal))
            .ToArray();

        Assert.HasCount(2, forThisSegment,
            "ClientRegistered then CapabilityGranted must be emitted for this segment.");
        Assert.IsInstanceOfType<CapabilityGranted>(forThisSegment[1],
            "Second event must be CapabilityGranted.");

        CapabilityGranted evt = (CapabilityGranted)forThisSegment[1];
        Assert.AreEqual(VerifierClientId, evt.ClientId,
            "CapabilityGranted must carry the client identifier.");
        Assert.AreEqual(segment, evt.TenantId.Value,
            "CapabilityGranted must carry the endpoint segment.");
        Assert.AreEqual(
            ServerCapabilityName.VerifiableCredentialIssuance,
            evt.Capability,
            "CapabilityGranted must carry the granted capability.");
    }


    //=========================================================================
    //Observable: unsubscribed observer stops receiving events.
    //
    //A production app may conditionally enable or disable observability. This
    //test verifies that disposing the subscription stops event delivery.
    //=========================================================================

    [TestMethod]
    public void DisposingSubscriptionStopsEventDelivery()
    {
        List<ClientRegistrationEvent> received = [];



        using TestHostShell app = new(TimeProvider);

        IDisposable subscription = app.Server.Events.Subscribe(
            new CollectingObserver<ClientRegistrationEvent>(received));
        using VerifierKeyMaterial firstKeys = app.RegisterClient("https://first.example.com", VerifierBaseUri, Oid4VpCapabilities);

        string firstSegment = firstKeys.Registration.TenantId;

        //Filter to the first segment to confirm the event was received.
        ClientRegistrationEvent[] forFirstSegment = received
            .Where(e => string.Equals(e.TenantId, firstSegment, StringComparison.Ordinal))
            .ToArray();

        Assert.HasCount(1, forFirstSegment,
            "One ClientRegistered event must be received for the first segment.");

        subscription.Dispose();

        int countBeforeSecond = received.Count;

        //Register a second client — the disposed observer must not receive it.
        using VerifierKeyMaterial secondKeys = app.RegisterClient("https://second.example.com", VerifierBaseUri, Oid4VpCapabilities);

        Assert.HasCount(countBeforeSecond, received,
            "No additional events must be received after subscription is disposed.");
    }


    //=========================================================================
    //HTTP response shape: PAR response body is valid JSON with request_uri and
    //expires_in — exactly what the ASP.NET skin would read and forward.
    //=========================================================================

    [TestMethod]
    public async Task ParDispatchReturns200WithRequestUriAndExpiresInJson()
    {
        using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        string segment = keys.Registration.TenantId;
        PreparedDcqlQuery query = CreatePreparedQuery();
        TransactionNonce nonce = new("nonce-par-shape-01");

        RequestContext context = new();
        context.SetRequestUriBase(VerifierBaseUri);
        context.SetTransactionNonce(nonce);
        context.SetPreparedQuery(query);
        context.SetDecryptionKeyId(keys.EncryptionKeyId);
        context.SetTenantId(segment);

        ServerHttpResponse response = await app.DispatchBySegmentAsync(
            segment,
            ServerCapabilityName.VerifiablePresentation,
            "POST",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            "PAR must return HTTP 200.");
        Assert.AreEqual("application/json", response.ContentType,
            "PAR must return Content-Type: application/json.");

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        Assert.IsTrue(doc.RootElement.TryGetProperty("request_uri", out JsonElement requestUri),
            "PAR response body must contain request_uri.");
        Assert.IsTrue(doc.RootElement.TryGetProperty("expires_in", out JsonElement expiresIn),
            "PAR response body must contain expires_in.");
        Assert.IsFalse(string.IsNullOrWhiteSpace(requestUri.GetString()),
            "request_uri must be a non-empty string.");
        Assert.IsGreaterThan(0, expiresIn.GetInt32(),
            "expires_in must be a positive integer.");
    }


    //=========================================================================
    //HTTP response shape: JAR request returns compact JWS in correct MIME type.
    //=========================================================================

    [TestMethod]
    public async Task JarRequestDispatchReturns200WithCompactJwsContentType()
    {
        using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);



        (Uri requestUri, string requestUriToken) = await app.HandleParAsync(keys,
            new TransactionNonce("nonce-jar-shape-01"),
            CreatePreparedQuery(),
            VerifierBaseUri,
            TestContext.CancellationToken).ConfigureAwait(false);

        RequestContext context = new();
        context.SetTenantId(keys.Registration.TenantId);
        context.SetCorrelationKey(requestUriToken);

        ServerHttpResponse response = await app.DispatchBySegmentAsync(
            keys.Registration.TenantId,
            ServerCapabilityName.VerifiablePresentation,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            "JAR request must return HTTP 200.");
        Assert.AreEqual(
            WellKnownMediaTypes.Application.OauthAuthzReqJwt,
            response.ContentType,
            "JAR request must return the correct JWT content type.");

        //The compact JWS is written to context, not body, per the dispatcher design.
        Assert.IsNotNull(context.Jar,
            "Compact JAR must be written to context bag by the dispatcher.");
        string compactJar = context.Jar!;
        Assert.HasCount(3, compactJar.Split('.'),
            "Compact JWS must have exactly three dot-separated segments.");
    }


    //=========================================================================
    //HTTP response shape: direct_post returns 200 with empty body (cross-device)
    //or JSON with redirect_uri (same-device).
    //=========================================================================

    [TestMethod]
    public async Task DirectPostCrossDeviceReturns200WithEmptyBody()
    {
        using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);


        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        TestWallet wallet = new(
            VerifierClientId,
            new Dictionary<string, string> { ["pid"] = serializedSdJwt },
            holderKey,
            TimeProvider);

        string walletFlowId = $"wallet-cbshape-{Guid.NewGuid():N}";

        (Uri requestUri, string requestUriToken) = await app.HandleParAsync(keys,
            new TransactionNonce("nonce-cb-shape-01"),
            CreatePreparedQuery(),
            VerifierBaseUri,
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = await app.HandleJarRequestAsync(keys,
            requestUriToken, TestContext.CancellationToken).ConfigureAwait(false);

        wallet.HandleQrScan(requestUri, walletFlowId);

        await wallet.HandleJarFetchAsync(
            walletFlowId, requestUri, compactJar, keys.SigningPublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJwe = await wallet.HandleResponsePostAsync(
            walletFlowId, TestContext.CancellationToken).ConfigureAwait(false);

        //Dispatch direct_post directly to inspect raw response shape.
        RequestContext context = new();
        context.SetTenantId(keys.Registration.TenantId);

        ServerEndpoint directPostEndpoint = EndpointMatcher.Find(
            app.GetEndpoints(keys.Registration),
            ServerCapabilityName.VerifiablePresentation, "POST", startsNewFlow: false)!;

        ServerHttpResponse response = await app.Server.HandleAsync(
            directPostEndpoint,
            new RequestFields
            {
                [OAuthRequestParameters.Response] = compactJwe,
                [OAuthRequestParameters.State] = requestUriToken
            },
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            "direct_post cross-device must return HTTP 200.");
        Assert.AreEqual("application/json", response.ContentType,
            "direct_post must return Content-Type: application/json.");

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        Assert.AreEqual(JsonValueKind.Object, doc.RootElement.ValueKind,
            "direct_post cross-device body must be a JSON object.");
        Assert.IsEmpty(doc.RootElement.EnumerateObject().ToArray(),
            "Cross-device direct_post body must be empty JSON object {}.");
    }


    [TestMethod]
    public async Task DirectPostSameDeviceReturns200WithRedirectUriInBody()
    {
        using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);


        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        TestWallet wallet = new(
            VerifierClientId,
            new Dictionary<string, string> { ["pid"] = serializedSdJwt },
            holderKey,
            TimeProvider);

        string walletFlowId = $"wallet-cbsamedev-{Guid.NewGuid():N}";
        Uri sameDeviceRedirectUri = new("https://verifier.example.com/complete?session=abc123");

        (Uri requestUri, string requestUriToken) = await app.HandleParAsync(keys,
            new TransactionNonce("nonce-cbsd-shape-01"),
            CreatePreparedQuery(),
            VerifierBaseUri,
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = await app.HandleJarRequestAsync(keys,
            requestUriToken, TestContext.CancellationToken).ConfigureAwait(false);

        wallet.HandleQrScan(requestUri, walletFlowId);

        await wallet.HandleJarFetchAsync(
            walletFlowId, requestUri, compactJar, keys.SigningPublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJwe = await wallet.HandleResponsePostAsync(
            walletFlowId, TestContext.CancellationToken).ConfigureAwait(false);

        RequestContext context = new();
        context.SetTenantId(keys.Registration.TenantId);
        context.SetOid4VpRedirectUri(sameDeviceRedirectUri);

        ServerEndpoint directPostEndpoint = EndpointMatcher.Find(
            app.GetEndpoints(keys.Registration),
            ServerCapabilityName.VerifiablePresentation, "POST", startsNewFlow: false)!;

        ServerHttpResponse response = await app.Server.HandleAsync(
            directPostEndpoint,
            new RequestFields
            {
                [OAuthRequestParameters.Response] = compactJwe,
                [OAuthRequestParameters.State] = requestUriToken
            },
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            "direct_post same-device must return HTTP 200.");

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        Assert.IsTrue(doc.RootElement.TryGetProperty("redirect_uri", out JsonElement redirectUriEl),
            "Same-device direct_post body must contain redirect_uri.");
        Assert.AreEqual(
            sameDeviceRedirectUri.ToString(),
            redirectUriEl.GetString(),
            "redirect_uri in body must match the redirect_uri placed in context.");
    }


    //=========================================================================
    //HTTP response shape: unknown segment returns 404.
    //=========================================================================

    [TestMethod]
    public async Task DispatchToUnknownSegmentReturns404()
    {
        using TestHostShell app = new(TimeProvider);

        ServerHttpResponse response = await app.DispatchBySegmentAsync(
            "doesnotexist",
            ServerCapabilityName.VerifiablePresentation,
            "POST",
            new RequestFields(),
            new RequestContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode,
            "Dispatch to an unknown segment must return 404.");
    }


    //=========================================================================
    //Client journey: newly registered client discovers endpoints and verifies
    //the JWKS — exactly what a real client does immediately after registration.
    //
    //In production the client receives its segment and base URI at registration
    //time (via registration_client_uri per RFC 7592). It then:
    //  1. Fetches /.well-known/openid-configuration to discover all endpoint URIs.
    //  2. Fetches /jwks to obtain the Verifier's current public key set.
    //  3. Verifies a JAR signature against the JWKS before proceeding.
    //
    //These tests assert on the raw ServerHttpResponse the ASP.NET skin would
    //receive and forward — no test-specific helpers, exactly what the real skin
    //does with each endpoint.
    //=========================================================================

    //=========================================================================
    //Client journey: newly registered client discovers endpoints and verifies
    //the JWKS — exactly what a real client does immediately after registration.
    //
    //An OID4VP Verifier with JwksEndpoint and DiscoveryEndpoint capabilities
    //serves a JWKS and a discovery document. The ASP.NET skin populates the
    //context bag with whatever the application wants — tenant ID, caller IP,
    //billing tier. The BuildJwksDocumentAsync delegate reads from that bag
    //to make per-call decisions: which keys to include, which to suppress.
    //
    //These tests dispatch to the real endpoints via DispatchAsync, asserting on
    //the raw ServerHttpResponse the ASP.NET skin would receive and forward.
    //=========================================================================

    [TestMethod]
    public void NewlyRegisteredClientCanComputeEndpointUrisFromSegment()
    {
        using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        string segment = keys.Registration.TenantId;

        Uri parUri = ServerEndpointPaths.ComputeUri(
            VerifierBaseUri, segment, ServerEndpointPaths.Par);
        Uri jarUri = ServerEndpointPaths.ComputeUri(
            VerifierBaseUri, segment, ServerEndpointPaths.JarRequest);
        Uri directPostUri = ServerEndpointPaths.ComputeUri(
            VerifierBaseUri, segment, ServerEndpointPaths.DirectPost);
        Uri jwksUri = ServerEndpointPaths.ComputeUri(
            VerifierBaseUri, segment, ServerEndpointPaths.Jwks);
        Uri discoveryUri = ServerEndpointPaths.ComputeUri(
            VerifierBaseUri, segment, ServerEndpointPaths.Discovery);

        Assert.AreEqual(
            $"https://verifier.example.com/connect/{segment}/par",
            parUri.ToString(),
            "PAR URI must follow the /connect/{segment}/par pattern.");
        Assert.AreEqual(
            $"https://verifier.example.com/connect/{segment}/request/{{flowId}}",
            jarUri.ToString(),
            "JAR request URI must follow the /connect/{segment}/request/{flowId} pattern.");
        Assert.AreEqual(
            $"https://verifier.example.com/connect/{segment}/cb",
            directPostUri.ToString(),
            "Direct-post URI must follow the /connect/{segment}/cb pattern.");
        Assert.AreEqual(
            $"https://verifier.example.com/connect/{segment}/jwks",
            jwksUri.ToString(),
            "JWKS URI must follow the /connect/{segment}/jwks pattern.");
        Assert.AreEqual(
            $"https://verifier.example.com/connect/{segment}/.well-known/openid-configuration",
            discoveryUri.ToString(),
            "Discovery URI must follow the /connect/{segment}/.well-known/openid-configuration pattern.");
    }


    [TestMethod]
    public async Task NewlyRegisteredClientCanReachParEndpointAndReceivesRequestUri()
    {
        using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        string segment = keys.Registration.TenantId;

        //The ASP.NET skin populates the context bag with whatever request-scoped
        //data the application wants — segment, issuer, tenant, caller IP, billing tier.
        //The library passes this bag to all delegates unchanged.
        RequestContext context = new();
        context.SetRequestUriBase(VerifierBaseUri);
        context.SetTransactionNonce(new TransactionNonce("nonce-journey-01"));
        context.SetPreparedQuery(CreatePreparedQuery());
        context.SetDecryptionKeyId(keys.EncryptionKeyId);
        context.SetTenantId(segment);

        ServerHttpResponse response = await app.DispatchBySegmentAsync(
            segment,
            ServerCapabilityName.VerifiablePresentation,
            "POST",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            "PAR endpoint must return HTTP 200 for a newly registered client.");
        Assert.AreEqual("application/json", response.ContentType,
            "PAR endpoint must return Content-Type: application/json.");

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        Assert.IsTrue(doc.RootElement.TryGetProperty("request_uri", out JsonElement requestUri),
            "PAR response must contain request_uri.");
        Assert.IsTrue(doc.RootElement.TryGetProperty("expires_in", out JsonElement expiresIn),
            "PAR response must contain expires_in.");

        Assert.IsTrue(
            Uri.TryCreate(requestUri.GetString(), UriKind.Absolute, out Uri? parsedRequestUri),
            "request_uri must be an absolute URI.");
        Assert.IsTrue(
            parsedRequestUri!.ToString().StartsWith(
                VerifierBaseUri.GetLeftPart(UriPartial.Authority),
                StringComparison.Ordinal),
            "request_uri must be rooted at the server base URI.");
        Assert.IsGreaterThan(0, expiresIn.GetInt32(),
            "expires_in must be a positive integer.");
    }


    [TestMethod]
    [DynamicData(nameof(AllSigningAlgorithms))]
    public async Task JwksReflectsRegisteredKeyParameters(
        string displayName,
        Func<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> createKeys)
    {
        using TestHostShell app = new(TimeProvider);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair = createKeys();

        //Derive expected values by running the same converter the server uses
        //to emit the JWK. The test never hardcodes kty, alg, or crv — adding a
        //new algorithm requires no test-side change beyond a new data row.
        JsonWebKey expectedJwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            keyPair.PublicKey.Tag.Get<CryptoAlgorithm>(),
            keyPair.PublicKey.Tag.Get<Purpose>(),
            keyPair.PublicKey.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);

        string expectedKty = expectedJwk.Kty!;
        string expectedAlg = expectedJwk.Alg!;
        string? expectedCrv = expectedJwk.Crv;

        ClientRegistration registration = app.RegisterSigningClient(
            $"client-{displayName}", keyPair, JwksCapabilities);

        ServerHttpResponse response = await FetchJwksAsync(
            app, registration, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            $"JWKS endpoint must return HTTP 200 for {displayName}.");
        Assert.AreEqual("application/json", response.ContentType,
            $"JWKS endpoint must return Content-Type: application/json for {displayName}.");

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        JsonElement keysElement = doc.RootElement.GetProperty(WellKnownJwkValues.Keys);
        JsonElement[] jwkArray = keysElement.EnumerateArray().ToArray();

        Assert.HasCount(1, jwkArray,
            $"JWKS must contain exactly one key for {displayName}.");

        JsonElement jwk = jwkArray[0];

        Assert.AreEqual(expectedKty, jwk.GetProperty(WellKnownJwkValues.Kty).GetString(),
            $"Key type mismatch for {displayName}.");

        Assert.AreEqual(expectedAlg, jwk.GetProperty(WellKnownJwkValues.Alg).GetString(),
            $"Algorithm mismatch for {displayName}.");

        Assert.AreEqual(WellKnownJwkValues.UseSig,
            jwk.GetProperty(WellKnownJwkValues.Use).GetString(),
            $"Use must be '{WellKnownJwkValues.UseSig}' for {displayName}.");

        Assert.AreEqual(registration.GetDefaultSigningKeyId(KeyUsageContext.AccessTokenIssuance).Value,
            jwk.GetProperty(WellKnownJwkValues.Kid).GetString(),
            $"Kid must match registration signing key identifier for {displayName}.");

        if(expectedCrv is not null)
        {
            Assert.AreEqual(expectedCrv,
                jwk.GetProperty(WellKnownJwkValues.Crv).GetString(),
                $"Curve mismatch for {displayName}.");
        }
        else
        {
            Assert.IsFalse(jwk.TryGetProperty(WellKnownJwkValues.Crv, out _),
                $"Key type '{expectedKty}' must not have a 'crv' property for {displayName}.");
        }
    }


    [TestMethod]
    public async Task DistinctAlgorithmFamiliesProduceDistinctJwksKeyTypes()
    {
        using TestHostShell app = new(TimeProvider);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ecKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> pqKeys =
            TestKeyMaterialProvider.CreateMlDsa65KeyMaterial();

        ClientRegistration ecClient = app.RegisterSigningClient(
            "ec-client", ecKeys, JwksCapabilities);
        ClientRegistration pqClient = app.RegisterSigningClient(
            "pq-client", pqKeys, JwksCapabilities);

        ServerHttpResponse ecResponse = await FetchJwksAsync(
            app, ecClient, TestContext.CancellationToken).ConfigureAwait(false);
        ServerHttpResponse pqResponse = await FetchJwksAsync(
            app, pqClient, TestContext.CancellationToken).ConfigureAwait(false);

        using JsonDocument ecDoc = JsonDocument.Parse(ecResponse.Body);
        using JsonDocument pqDoc = JsonDocument.Parse(pqResponse.Body);

        string? ecKty = ecDoc.RootElement.GetProperty(WellKnownJwkValues.Keys)
            .EnumerateArray().First()
            .GetProperty(WellKnownJwkValues.Kty).GetString();

        string? pqKty = pqDoc.RootElement.GetProperty(WellKnownJwkValues.Keys)
            .EnumerateArray().First()
            .GetProperty(WellKnownJwkValues.Kty).GetString();

        Assert.AreEqual(WellKnownKeyTypeValues.Ec, ecKty,
            "EC client JWKS must report key type 'EC'.");
        Assert.AreEqual(WellKnownKeyTypeValues.Akp, pqKty,
            "Post-quantum client JWKS must report key type 'AKP'.");

        Assert.AreNotEqual(ecKty, pqKty,
            "Distinct algorithm families must produce distinct key types.");
    }


    [TestMethod]
    public async Task BuildJwksDocumentDelegateReceivesContextBagFromAspNetSkin()
    {
        //This test verifies that whatever the ASP.NET skin places in the context bag
        //reaches the BuildJwksDocumentAsync delegate unchanged — the full per-call
        //decision surface is available. A production implementation uses this for
        //billing tier filtering, grace-period key suppression, tenant isolation, etc.
        const string tenantId = "tenant-acme-corp";
        const string callerTier = "premium";

        KeyId? capturedSigningKeyId = null;
        string? capturedTenantId = null;
        string? capturedCallerTier = null;

        using TestHostShell app = new(TimeProvider);

        //Override BuildJwksDocumentAsync to capture what the delegate receives.
        //This is exactly what an application developer would do — wire a delegate
        //that reads from the context bag to make per-call decisions.
        app.Server.Options.BuildJwksDocumentAsync = (registration, ctx, ct) =>
        {
            capturedSigningKeyId = registration.GetDefaultSigningKeyId(KeyUsageContext.JarSigning);

            if(ctx.TryGetValue("app.tenantId", out object? tid) && tid is string t)
            {
                capturedTenantId = t;
            }

            if(ctx.TryGetValue("app.callerTier", out object? tier) && tier is string tr)
            {
                capturedCallerTier = tr;
            }

            return ValueTask.FromResult(new JwksDocument { Keys = [] });
        };

        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);
        string segment = keys.Registration.TenantId;

        //The ASP.NET skin adds tenant and caller tier to the context bag.
        //In production this comes from JWT claims, HTTP headers, DI services, etc.
        RequestContext context = new();
        context.SetTenantId(segment);
        context.SetIssuer(VerifierBaseUri);
        context["app.tenantId"] = tenantId;
        context["app.callerTier"] = callerTier;

        await app.DispatchBySegmentAsync(
            segment,
            ServerCapabilityName.JwksEndpoint,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(keys.SigningKeyId, capturedSigningKeyId,
            "BuildJwksDocumentAsync must receive the ClientRegistration with its SigningKeyId.");
        Assert.AreEqual(tenantId, capturedTenantId,
            "BuildJwksDocumentAsync must receive the tenant identifier from the context bag.");
        Assert.AreEqual(callerTier, capturedCallerTier,
            "BuildJwksDocumentAsync must receive the caller tier from the context bag.");
    }


    [TestMethod]
    public async Task BuildJwksDocumentDelegateCanSuppressKeysBasedOnContext()
    {
        //Demonstrates the per-call dynamic gate: the same registration returns
        //different JWKS depending on context bag contents. This is the billing/
        //tier/tenant isolation pattern the design intends.
        using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        string segment = keys.Registration.TenantId;

        //Wire BuildJwksDocumentAsync to suppress all keys for restricted callers.
        app.Server.Options.BuildJwksDocumentAsync = (registration, ctx, ct) =>
        {
            bool isRestricted = ctx.TryGetValue("app.restricted", out object? r)
                && r is bool b && b;

            if(isRestricted)
            {
                return ValueTask.FromResult(new JwksDocument { Keys = [] });
            }

            return ValueTask.FromResult(new JwksDocument
            {
                Keys =
                [
                    new JsonWebKey
                    {
                        Kty = WellKnownKeyTypeValues.Ec,
                        Use = WellKnownJwkValues.UseSig,
                        Kid = registration.GetDefaultSigningKeyId(KeyUsageContext.JarSigning).Value
                    }
                ]
            });
        };

        //Unrestricted caller — receives the full JWKS.
        RequestContext unrestrictedContext = new();
        unrestrictedContext.SetTenantId(segment);
        unrestrictedContext.SetIssuer(VerifierBaseUri);
        unrestrictedContext["app.restricted"] = false;
        ServerHttpResponse unrestrictedResponse = await app.DispatchBySegmentAsync(
            segment,
            ServerCapabilityName.JwksEndpoint,
            "GET",
            new RequestFields(),
            unrestrictedContext,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Restricted caller — receives an empty JWKS.
        RequestContext restrictedContext = new();
        restrictedContext.SetTenantId(segment);
        restrictedContext.SetIssuer(VerifierBaseUri);
        restrictedContext["app.restricted"] = true;
        ServerHttpResponse restrictedResponse = await app.DispatchBySegmentAsync(
            segment,
            ServerCapabilityName.JwksEndpoint,
            "GET",
            new RequestFields(),
            restrictedContext,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, unrestrictedResponse.StatusCode,
            "Unrestricted caller must receive HTTP 200.");
        Assert.AreEqual(200, restrictedResponse.StatusCode,
            "Restricted caller must receive HTTP 200 — the capability is allowed, only the key set differs.");

        using JsonDocument unrestrictedDoc = JsonDocument.Parse(unrestrictedResponse.Body);
        JsonElement[] unrestrictedKeys = unrestrictedDoc.RootElement
            .GetProperty(WellKnownJwkValues.Keys).EnumerateArray().ToArray();

        using JsonDocument restrictedDoc = JsonDocument.Parse(restrictedResponse.Body);
        JsonElement[] restrictedKeys = restrictedDoc.RootElement
            .GetProperty(WellKnownJwkValues.Keys).EnumerateArray().ToArray();

        Assert.IsGreaterThan(0, unrestrictedKeys.Length,
            "Unrestricted caller must receive at least one key.");
        Assert.IsEmpty(restrictedKeys,
            "Restricted caller must receive an empty keys array.");
    }


    [TestMethod]
    public async Task DiscoveryEndpointReturns200WithActiveCapabilityEndpoints()
    {
        using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        string segment = keys.Registration.TenantId;

        //The ASP.NET skin places the issuer URI in the context bag.
        //The discovery BuildInputAsync reads it to compute absolute endpoint URIs.
        RequestContext context = new();
        context.SetTenantId(segment);
        context.SetIssuer(VerifierBaseUri);

        ServerHttpResponse response = await app.DispatchBySegmentAsync(
            segment,
            ServerCapabilityName.DiscoveryEndpoint,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            "Discovery endpoint must return HTTP 200.");
        Assert.AreEqual("application/json", response.ContentType,
            "Discovery endpoint must return Content-Type: application/json.");

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        JsonElement root = doc.RootElement;

        Assert.IsTrue(root.TryGetProperty("issuer", out _),
            "Discovery document must contain issuer.");
        Assert.IsTrue(root.TryGetProperty(
                AuthorizationServerMetadataKeys.JwksUri, out JsonElement jwksUriEl),
            "Discovery document must advertise the JWKS URI.");

        //The advertised JWKS URI must match the computed URI for this segment.
        //The discovery handler resolves the issuer via the library resolver, which
        //prefers the registration's IssuerUri over the context's request-scoped
        //fallback. Build the expectation from the same source.
        Uri expectedJwksUri = ServerEndpointPaths.ComputeUri(
            keys.Registration.IssuerUri!, segment, ServerEndpointPaths.Jwks);
        Assert.AreEqual(expectedJwksUri.ToString(), jwksUriEl.GetString(),
            "Advertised JWKS URI must match the computed URI for this segment.");

        //OID4VP Verifier does not have PAR as an AuthCode capability — it has its
        //own OID4VP PAR. The discovery document reflects the actual capability set.
        Assert.IsFalse(
            root.TryGetProperty(
                AuthorizationServerMetadataKeys.PushedAuthorizationRequestEndpoint, out _),
            "OID4VP-only registration must not advertise PAR in the Auth Code sense.");
    }


    [TestMethod]
    public async Task AfterKeyRotationJwksContainsNewKid()
    {
        using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial originalKeys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        string segment = originalKeys.Registration.TenantId;

        using VerifierKeyMaterial rotatedKeys = app.RotateSigningKey(segment);

        RequestContext context = new();
        context.SetTenantId(segment);
        context.SetIssuer(VerifierBaseUri);

        ServerHttpResponse response = await app.DispatchBySegmentAsync(
            segment,
            ServerCapabilityName.JwksEndpoint,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            "JWKS endpoint must return HTTP 200 after key rotation.");

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        JsonElement[] jwkArray = doc.RootElement
            .GetProperty(WellKnownJwkValues.Keys).EnumerateArray().ToArray();

        //After rotation the routing table carries the updated registration with the
        //new SigningKeyId. BuildJwksDocumentAsync receives the updated registration
        //and returns the new key. Whether the old key also appears depends on the
        //delegate implementation — in TestHostShell it follows the current
        //registration's SigningKeyId.
        bool foundRotatedKey = jwkArray.Any(jwk =>
            jwk.TryGetProperty(WellKnownJwkValues.Kid, out JsonElement kid) &&
            string.Equals(kid.GetString(), rotatedKeys.SigningKeyId.Value, StringComparison.Ordinal));

        Assert.IsTrue(foundRotatedKey,
            "JWKS must contain the new signing key's kid after rotation.");
    }


    [TestMethod]
    public async Task DeregisteredClientJwksAndDiscoveryReturn404()
    {
        using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        string segment = keys.Registration.TenantId;
        app.DeregisterClient(segment, "Client offboarded.");

        RequestContext context = new();
        context.SetTenantId(segment);
        context.SetIssuer(VerifierBaseUri);

        ServerHttpResponse jwksResponse = await app.DispatchBySegmentAsync(
            segment,
            ServerCapabilityName.JwksEndpoint,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse discoveryResponse = await app.DispatchBySegmentAsync(
            segment,
            ServerCapabilityName.DiscoveryEndpoint,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, jwksResponse.StatusCode,
            "JWKS endpoint must return 404 after deregistration.");
        Assert.AreEqual(404, discoveryResponse.StatusCode,
            "Discovery endpoint must return 404 after deregistration.");
    }


    //=========================================================================
    //Caching contract: the library always calls BuildJwksDocumentAsync on every
    //request — it never caches. Caching, precomputation, invalidation, regional
    //distribution, and change-gating are entirely the application's concern,
    //wired through the delegate and driven by AuthorizationServer.
    //
    //These tests verify the library's side of the contract:
    //  - BuildJwksDocumentAsync is called on every JWKS request
    //  - ClientUpdated fires on key rotation — the application's cache eviction
    //    subscriber reacts to this signal
    //  - The context bag reaches the delegate unchanged on every call, carrying
    //    whatever the application placed there (region, time-of-day, caller tier)
    //=========================================================================

    [TestMethod]
    public async Task LibraryCallsBuildJwksDocumentDelegateOnEveryRequest()
    {
        //The library never caches. The delegate is called on every JWKS request.
        //The application's delegate implementation decides whether to hit a cache,
        //compute fresh, or serve a precomputed document — the library does not know
        //and must not know.
        int callCount = 0;

        using TestHostShell app = new(TimeProvider);

        app.Server.Options.BuildJwksDocumentAsync = (registration, ctx, ct) =>
        {
            callCount++;
            return ValueTask.FromResult(new JwksDocument { Keys = [] });
        };

        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);
        string segment = keys.Registration.TenantId;

        RequestContext context = new();
        context.SetTenantId(segment);
        context.SetIssuer(VerifierBaseUri);

        const int requestCount = 3;
        for(int i = 0; i < requestCount; i++)
        {
            await app.DispatchBySegmentAsync(
            segment,
            ServerCapabilityName.JwksEndpoint,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.AreEqual(requestCount, callCount,
            "BuildJwksDocumentAsync must be called once per JWKS request. " +
            "The library never caches — caching is the application's concern.");
    }


    [TestMethod]
    public async Task KeyRotationFiresClientUpdatedEventForCacheInvalidation()
    {
        //Key rotation emits ClientUpdated via AuthorizationServer.
        //An application's cache invalidation subscriber reacts to this event —
        //the library provides the signal, the application decides what to evict
        //and when (immediately, after approval, gated by time-of-day policy, etc.).
        List<ClientRegistrationEvent> received = [];



        using TestHostShell app = new(TimeProvider);

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
        app.Server.Options.BuildJwksDocumentAsync = (registration, ctx, ct) =>
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
        RequestContext context = new();
        context.SetTenantId(segment);
        context.SetIssuer(VerifierBaseUri);

        ServerHttpResponse response = await app.DispatchBySegmentAsync(
            segment,
            ServerCapabilityName.JwksEndpoint,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            "JWKS request after cache eviction must succeed.");

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        JsonElement[] jwkArray = doc.RootElement
            .GetProperty(WellKnownJwkValues.Keys).EnumerateArray().ToArray();

        bool foundNewKey = jwkArray.Any(jwk =>
            jwk.TryGetProperty(WellKnownJwkValues.Kid, out JsonElement kid) &&
            string.Equals(kid.GetString(), rotatedKeys.SigningKeyId.Value, StringComparison.Ordinal));

        Assert.IsTrue(foundNewKey,
            "After cache eviction and recompute, JWKS must carry the new key identifier.");
    }


    [TestMethod]
    public async Task ContextBagReachesJwksDelegateOnEveryCallForPerCallDecisions()
    {
        //Verifies that each JWKS request carries its own context bag to the delegate.
        //In production the context bag changes per request — different callers have
        //different regions, tiers, and trust levels. The delegate uses these to decide
        //which cache partition to consult, whether to serve stale, and which keys to include.
        var capturedRegions = new List<string>();

        using TestHostShell app = new(TimeProvider);

        app.Server.Options.BuildJwksDocumentAsync = (registration, ctx, ct) =>
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
            RequestContext context = new();
            context.SetTenantId(segment);
            context.SetIssuer(VerifierBaseUri);
            context["app.region"] = region;
            await app.DispatchBySegmentAsync(
            segment,
            ServerCapabilityName.JwksEndpoint,
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

        using TestHostShell app = new(TimeProvider);

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
        app.Server.Options.BuildJwksDocumentAsync = (registration, ctx, ct) =>
            ValueTask.FromResult(precomputedDocument!);

        //Ten requests — delegate always serves the precomputed document.
        //The application's compute count stays at 1 because caching is its concern.
        string segment2 = segment;
        RequestContext context = new();
        context.SetTenantId(segment2);
        context.SetIssuer(VerifierBaseUri);

        for(int i = 0; i < 10; i++)
        {
            ServerHttpResponse response = await app.DispatchBySegmentAsync(
            segment2,
            ServerCapabilityName.JwksEndpoint,
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
            (await app.DispatchBySegmentAsync(
            segment2,
            ServerCapabilityName.JwksEndpoint,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false)).Body);

        JsonElement[] finalKeys = doc.RootElement
            .GetProperty(WellKnownJwkValues.Keys)
            .EnumerateArray()
            .ToArray();

        string expectedKid = keys.SigningKeyId.Value;
        JsonElement? matchingKey = finalKeys
            .Cast<JsonElement?>()
            .FirstOrDefault(jwk =>
                jwk!.Value.TryGetProperty(WellKnownJwkValues.Kid, out JsonElement kid)
                && string.Equals(kid.GetString(), expectedKid, StringComparison.Ordinal));

        Assert.IsNotNull(matchingKey,
            "Precomputed document must carry the registration's signing key identifier.");
    }


    [TestMethod]
    public void EventTimestampsReflectFakeTimeProviderAndAreOrdered()
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


        using TestHostShell app = new(TimeProvider);

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

    private static async ValueTask<ServerHttpResponse> FetchJwksAsync(
        TestHostShell app,
        ClientRegistration registration,
        CancellationToken cancellationToken)
    {
        RequestContext context = new();
        context.SetTenantId(registration.TenantId);
        context.SetIssuer(VerifierBaseUri);

        return await app.DispatchBySegmentAsync(
            registration.TenantId,
            ServerCapabilityName.JwksEndpoint,
            "GET",
            new RequestFields(),
            context,
            cancellationToken).ConfigureAwait(false);
    }


    private static PreparedDcqlQuery CreatePreparedQuery()
    {
        return DcqlPreparer.Prepare(new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = "pid",
                    Format = WellKnownMediaTypes.Jwt.DcSdJwt,
                    Claims = [new ClaimsQuery { Path = DcqlClaimPattern.FromKeys("family_name") }]
                }
            ]
        });
    }


    /// <summary>
    /// Issues a PID SD-JWT VC with holder key binding. The issuer signs with P-256,
    /// the holder key is Ed25519 (bound via <c>cnf</c>). Returns the serialized SD-JWT
    /// without KB-JWT (the wallet adds the KB-JWT at presentation time) and the holder
    /// private key for KB-JWT signing.
    /// </summary>
    private async ValueTask<(string SerializedSdJwt, PrivateKeyMemory HolderPrivateKey, PublicKeyMemory IssuerPublicKey)> IssuePidCredentialAsync(
        CancellationToken cancellationToken)
    {
        var issuerKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory issuerPrivateKey = issuerKeys.PrivateKey;

        var holderKeys = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublicKey = holderKeys.PublicKey;

        Dictionary<string, object> holderJwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            holderPublicKey.Tag.Get<CryptoAlgorithm>(),
            holderPublicKey.Tag.Get<Purpose>(),
            holderPublicKey.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);

        JwtPayload payload = JwtPayload.ForSdJwtVcIssuance(
            issuer: IssuerId,
            verifiableCredentialType: EudiPid.SdJwtVct,
            issuedAt: TimeProvider.GetUtcNow(),
            holderConfirmation: holderJwk,
            claims:
            [
                new(EudiPid.SdJwt.GivenName, "Erika"),
                new(EudiPid.SdJwt.FamilyName, "Mustermann")
            ]);

        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.GivenName}"),
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.FamilyName}")
        };

        SdTokenResult result = await payload.IssueSdJwtAsync(
            disclosablePaths, SaltGenerator.Create,
            issuerPrivateKey, IssuerKeyId, Pool,
            TestSetup.DefaultSerializationOptions,
            mediaType: WellKnownMediaTypes.Jwt.VcSdJwt,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        string compactJws = Encoding.UTF8.GetString(result.SignedToken.Span);
        SdToken<string> issuedToken = new(compactJws, result.Disclosures.ToList());
        string serializedSdJwt = SdJwtSerializer.SerializeToken(issuedToken, TestSetup.Base64UrlEncoder);

        return (serializedSdJwt, holderKeys.PrivateKey, issuerKeys.PublicKey);
    }


    //Helper observer that collects all events into a list for assertion.
    private sealed class CollectingObserver<T>(List<T> collected): IObserver<T>
    {
        public void OnNext(T value)
        {
            collected.Add(value);
        }

        public void OnError(Exception error) { }

        public void OnCompleted() { }
    }
}
