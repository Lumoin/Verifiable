using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.Server.Metadata;
using Verifiable.Server.Routing;
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

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private const string VerifierClientId = "https://verifier.example.com";

    private static Uri VerifierBaseUri { get; } = new("https://verifier.example.com");

    private const string IssuerId = "https://issuer.example.com";
    private const string IssuerKeyId = "did:web:issuer.example.com#key-1";
    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private static ImmutableHashSet<CapabilityIdentifier> Oid4VpCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);

    private static ImmutableHashSet<CapabilityIdentifier> JwksCapabilities { get; } =
        [WellKnownCapabilityIdentifiers.OAuthJwksEndpoint];


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


    //Observable: ClientRegistered event fires on registration.
    //
    //A real ASP.NET app subscribes to app.Server.Events at
    //startup to populate its routing table. This test verifies that the event
    //fires with the correct payload immediately when RegisterClient is called,
    //before any dispatch calls are made.

    [TestMethod]
    public void PolicyProfileEqualityIsByCode()
    {
        //Round 4.8 — built-in values are equal to themselves, distinct from
        //each other; the dynamic-enum pattern's contract. The self-comparison
        //is against an independently retrieved copy (via the Profiles registry)
        //rather than the same expression twice, so the check exercises the
        //Code == other.Code comparison instead of a compile-time tautology.
        PolicyProfile fapi20FromRegistry = PolicyProfile.Profiles.First(profile => profile.Code == PolicyProfile.Fapi20.Code);

        Assert.AreEqual(PolicyProfile.Fapi20, fapi20FromRegistry,
            "Strict equals Strict.");
        Assert.AreNotEqual(PolicyProfile.Fapi20, PolicyProfile.Haip10,
            "Strict and Haip have different codes; they must not be equal.");
        Assert.AreNotEqual(PolicyProfile.Haip10, PolicyProfile.Rfc6749WithPkce,
            "Haip and Rfc6749 have different codes; they must not be equal.");
        Assert.AreEqual(PolicyProfile.Fapi20.GetHashCode(),
            PolicyProfile.Fapi20.Code,
            "GetHashCode returns Code per the dynamic-enum pattern.");
    }


    [TestMethod]
    public void PolicyProfileCreateRejectsDuplicateCode()
    {
        //Code 0 is registered as Strict — Create(0) must throw.
        Assert.ThrowsExactly<ArgumentException>(
            () => PolicyProfile.Create(0));
    }


    [TestMethod]
    public void PolicyProfileNamesReturnsExpectedNames()
    {
        Assert.AreEqual(nameof(PolicyProfile.Fapi20),
            PolicyProfileNames.GetName(PolicyProfile.Fapi20));
        Assert.AreEqual(nameof(PolicyProfile.Haip10),
            PolicyProfileNames.GetName(PolicyProfile.Haip10));
        Assert.AreEqual(nameof(PolicyProfile.Rfc6749WithPkce),
            PolicyProfileNames.GetName(PolicyProfile.Rfc6749WithPkce));
        Assert.AreEqual(nameof(PolicyProfile.Oid4VpVerifier),
            PolicyProfileNames.GetName(PolicyProfile.Oid4VpVerifier));

        //Application-defined codes return a generic Custom (code) form. Use
        //a code in the application-reserved range so the test does not
        //collide with any future built-in.
        Assert.AreEqual("Custom (9999)", PolicyProfileNames.GetName(9999));
    }


    [TestMethod]
    public async Task DefaultResolvePolicyAsyncDispatchesCorrectProfile()
    {
        //Three registrations, one per built-in profile, produce the expected
        //policy values. Round 4.8 — confirms the dispatch via PolicyProfile
        //code equality replaces the earlier string-equality approach.
        ClientRecord strict = MakeMinimalRegistration(PolicyProfile.Fapi20);
        ClientRecord haip = MakeMinimalRegistration(PolicyProfile.Haip10);
        ClientRecord rfc = MakeMinimalRegistration(PolicyProfile.Rfc6749WithPkce);

        ExchangeContext strictContext = new();
        ExchangeContext haipContext = new();
        ExchangeContext rfcContext = new();

        await PolicyProfiles.DefaultResolvePolicyAsync(
            strict, strictContext, TestContext.CancellationToken).ConfigureAwait(false);
        await PolicyProfiles.DefaultResolvePolicyAsync(
            haip, haipContext, TestContext.CancellationToken).ConfigureAwait(false);
        await PolicyProfiles.DefaultResolvePolicyAsync(
            rfc, rfcContext, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(PkceMethodSet.S256Only, strictContext.AllowedPkceMethods,
            "Strict permits only S256.");
        Assert.AreEqual(PkceMethodSet.S256Only, haipContext.AllowedPkceMethods,
            "Haip is Strict + tightenings — also S256-only.");
        Assert.AreEqual(PkceMethodSet.S256AndPlain, rfcContext.AllowedPkceMethods,
            "Rfc6749 baseline permits both S256 and plain.");

        Assert.IsTrue(strictContext.EmitIssOnRedirect,
            "Strict emits iss on redirect (RFC 9207 / FAPI 2.0).");
        Assert.IsFalse(rfcContext.EmitIssOnRedirect,
            "Rfc6749 baseline does not emit iss on redirect.");
    }


    [TestMethod]
    public async Task Oid4VpVerifierProfileSetsPresentationAxesNotTokenEndpointDefault()
    {
        //The dedicated OID4VP verifier profile sets only the two KB-JWT timing
        //axes the verification pipeline consumes (ApplyOid4VpVerifier has exactly
        //those two setters). The clean behavioural discriminator versus Fapi20 is
        //KbJwtMaxAgeWindow: Fapi20 never sets it (null → the ValidationContext
        //field default applies), whereas the verifier profile sets it to 60s.
        ClientRecord verifier = MakeMinimalRegistration(PolicyProfile.Oid4VpVerifier);
        ClientRecord fapi = MakeMinimalRegistration(PolicyProfile.Fapi20);

        ExchangeContext verifierContext = new();
        ExchangeContext fapiContext = new();

        await PolicyProfiles.DefaultResolvePolicyAsync(
            verifier, verifierContext, TestContext.CancellationToken).ConfigureAwait(false);
        await PolicyProfiles.DefaultResolvePolicyAsync(
            fapi, fapiContext, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TimeSpan.FromSeconds(60), verifierContext.ClockSkewToleranceOverride,
            "The verifier profile sets the clock-skew tolerance the KB-JWT iat checks read.");
        Assert.AreEqual(TimeSpan.FromSeconds(60), verifierContext.KbJwtMaxAgeWindow,
            "The verifier profile sets the KB-JWT iat max-age window (RFC 9901 leaves the number to policy; 60s aligns with HAIP §3).");

        Assert.IsNull(fapiContext.KbJwtMaxAgeWindow,
            "Fapi20 does not set the KB-JWT max-age window — proving the verifier profile is genuinely distinct, not Fapi20-with-extras.");
    }


    [TestMethod]
    public async Task Oid4VpVerifierProfileDerivesTimingFromServerTimings()
    {
        //Single source of truth: when a server is on the context, the verifier
        //profile derives BOTH presentation timing axes from server.Timings, not
        //from literals. Distinct non-default values (7s / 13s) prove the
        //derivation — a default-60s server could not catch a regression to a
        //hardcoded 60. The no-server fallback path is covered separately by
        //Oid4VpVerifierProfileSetsPresentationAxesNotTokenEndpointDefault.
        var customTimings = new TimingPolicy
        {
            ClockSkewTolerance = TimeSpan.FromSeconds(7),
            KbJwtIatMaxAge = TimeSpan.FromSeconds(13)
        };

        HostedAuthorizationServer host = HostedAuthorizationServer.Build(
            name: "timing-derivation",
            timeProvider: TimeProvider,
            subjectClaims: new Dictionary<string, Verifiable.OAuth.Oidc.OidcClaims>(),
            resolveIssuerKey: (string _) => null,
            vpValidator: new Verifiable.Core.Assessment.ClaimIssuer<Verifiable.OAuth.Validation.ValidationContext>(
                "vp-timing-derivation",
                Verifiable.OAuth.Validation.ValidationProfiles.Haip10SdJwtRules(),
                TimeProvider),
            timings: customTimings);

        ExchangeContext context = new();
        context.SetServer(host.Server);

        await PolicyProfiles.DefaultResolvePolicyAsync(
            MakeMinimalRegistration(PolicyProfile.Oid4VpVerifier), context, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(TimeSpan.FromSeconds(7), context.ClockSkewToleranceOverride,
            "The verifier profile must derive clock-skew from server.Timings.ClockSkewTolerance, not a literal.");
        Assert.AreEqual(TimeSpan.FromSeconds(13), context.KbJwtMaxAgeWindow,
            "The verifier profile must derive the KB-JWT max-age window from server.Timings.KbJwtIatMaxAge.");
    }


    [TestMethod]
    public async Task DefaultResolvePolicyAsyncFallsBackToStrictForCustomCode()
    {
        //An application-defined profile that the library's default does not
        //recognise falls through to the strict baseline as a fail-safe. Use
        //a high code so the test does not collide with built-ins or other
        //test-side registrations.
        PolicyProfile custom = PolicyProfile.Create(9001);
        ClientRecord registration = MakeMinimalRegistration(custom);
        ExchangeContext context = new();

        await PolicyProfiles.DefaultResolvePolicyAsync(
            registration, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(PkceMethodSet.S256Only, context.AllowedPkceMethods,
            "Custom code with no application resolver falls back to Strict.");
        Assert.IsTrue(context.EmitIssOnRedirect,
            "Strict baseline emits iss on the redirect.");
    }


    [TestMethod]
    public void IntegrationValidateThrowsWhenLoadRegistrationAsyncIsMissing()
    {
        //AuthorizationServerIntegration.Validate names every missing required
        //delegate in one error so misconfiguration is fixable in a single
        //startup pass. Constructing a fully-populated group with exactly one
        //required slot null isolates the message to that slot's name. The
        //registration loader is the host-generic LoadRegistrationAsync seam;
        //LoadClientRegistrationAsync is the OAuth-facing alias that forwards to it.
        AuthorizationServerIntegration integration = new()
        {
            ExtractTenantIdAsync = (ctx, ct) =>
                ValueTask.FromResult<TenantId?>(null),
            //LoadClientRegistrationAsync (LoadRegistrationAsync) deliberately omitted.
            SaveFlowStateAsync = (tenantId, key, state, stepCount, ctx, ct) =>
                ValueTask.CompletedTask,
            LoadFlowStateAsync = (tenantId, key, ctx, ct) =>
                ValueTask.FromResult<(FlowState?, int)>((null, 0)),
            ResolvePolicyAsync = (registration, ctx, ct) =>
                PolicyProfiles.DefaultResolvePolicyAsync((ClientRecord)registration, ctx, ct)
        };

        InvalidOperationException ex =
            Assert.ThrowsExactly<InvalidOperationException>(integration.Validate);

        Assert.Contains(
            nameof(ServerIntegration.LoadRegistrationAsync),
            ex.Message,
            StringComparison.Ordinal,
            "Error must name LoadRegistrationAsync.");
        Assert.IsFalse(integration.IsValidated,
            "IsValidated must remain false after a Validate() that threw.");
    }


    [TestMethod]
    public void IntegrationValidateThrowsWhenResolvePolicyAsyncIsMissing()
    {
        //ResolvePolicyAsync is required so every dispatch resolves policy
        //before matchers run. Misconfiguration detected at startup, not at
        //first request.
        AuthorizationServerIntegration integration = new()
        {
            ExtractTenantIdAsync = (ctx, ct) =>
                ValueTask.FromResult<TenantId?>(null),
            LoadClientRegistrationAsync = (tenantId, ctx, ct) =>
                ValueTask.FromResult<IRegistrationRecord?>(null),
            SaveFlowStateAsync = (tenantId, key, state, stepCount, ctx, ct) =>
                ValueTask.CompletedTask,
            LoadFlowStateAsync = (tenantId, key, ctx, ct) =>
                ValueTask.FromResult<(FlowState?, int)>((null, 0))
            //ResolvePolicyAsync deliberately omitted.
        };

        InvalidOperationException ex =
            Assert.ThrowsExactly<InvalidOperationException>(integration.Validate);

        Assert.Contains(
            nameof(AuthorizationServerIntegration.ResolvePolicyAsync),
            ex.Message,
            StringComparison.Ordinal,
            "Error must name ResolvePolicyAsync.");
    }


    [TestMethod]
    public void CryptographyValidateThrowsWhenVerificationKeyResolverIsMissing()
    {
        //AuthorizationServerCryptography requires both SigningKeyResolver and
        //VerificationKeyResolver. Nulling one and populating the other proves
        //Validate names the missing slot rather than the populated one.
        AuthorizationServerCryptography cryptography = new()
        {
            SigningKeyResolver = (keyId, tenantId, ctx, ct) =>
                ValueTask.FromResult<Verifiable.Cryptography.PrivateKeyMemory?>(null)
            //VerificationKeyResolver deliberately omitted.
        };

        InvalidOperationException ex =
            Assert.ThrowsExactly<InvalidOperationException>(cryptography.Validate);

        Assert.Contains(
            nameof(AuthorizationServerCryptography.VerificationKeyResolver),
            ex.Message,
            StringComparison.Ordinal,
            "Error must name VerificationKeyResolver.");
        Assert.IsFalse(cryptography.IsValidated,
            "IsValidated must remain false after a Validate() that threw.");
    }


    [TestMethod]
    public void CodecsValidateThrowsWhenJwtHeaderDeserializerIsMissing()
    {
        //AuthorizationServerCodecs requires both serializer and deserializer
        //pairs alongside the encoder/decoder/digest slots. Nulling exactly one
        //(JwtHeaderDeserializer) confirms Validate isolates that slot.
        AuthorizationServerCodecs codecs = new()
        {
            Encoder = TestSetup.Base64UrlEncoder,
            Decoder = TestSetup.Base64UrlDecoder,
            ComputeDigest = MicrosoftEntropyFunctions.ComputeDigestAsync,
            JwtHeaderSerializer = static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)header,
                TestSetup.DefaultSerializationOptions),
            JwtPayloadSerializer = static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)payload,
                TestSetup.DefaultSerializationOptions),
            //JwtHeaderDeserializer deliberately omitted.
            JwtPayloadDeserializer = static bytes =>
                JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                    bytes, TestSetup.DefaultSerializationOptions)
                ?? throw new FormatException("Payload JSON parsed to null.")
        };

        InvalidOperationException ex =
            Assert.ThrowsExactly<InvalidOperationException>(codecs.Validate);

        Assert.Contains(
            nameof(AuthorizationServerCodecs.JwtHeaderDeserializer),
            ex.Message,
            StringComparison.Ordinal,
            "Error must name JwtHeaderDeserializer.");
        Assert.IsFalse(codecs.IsValidated,
            "IsValidated must remain false after a Validate() that threw.");
    }


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
        Assert.IsInstanceOfType<ClientRegistered>(forThisSegment[0],
            "The emitted event must be ClientRegistered.");

        ClientRegistered evt = (ClientRegistered)forThisSegment[0];
        Assert.AreEqual(VerifierClientId, evt.ClientId,
            "ClientRegistered must carry the registered client identifier.");
        Assert.AreEqual(segment, evt.TenantId.Value,
            "ClientRegistered must carry the endpoint segment.");
        Assert.AreSame(keys.Registration, evt.Registration,
            "ClientRegistered must carry the exact ClientRecord instance.");
    }


    //Observable: registration store is populated before dispatch.
    //
    //The routing table must be updated synchronously by the subscriber so that
    //the first dispatch call after RegisterClient can resolve the registration.

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


    //Observable: deregistration removes from routing table immediately.
    //
    //A production app that deregisters a client must have the routing table
    //updated before the next request arrives. Dispatch to the deregistered
    //segment must return 404.

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
        Assert.IsInstanceOfType<ClientRegistered>(forThisSegment[0]);
        Assert.IsInstanceOfType<ClientDeregistered>(forThisSegment[1]);

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
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode,
            "Dispatch to a deregistered segment must return 404.");
    }


    //Observable: key rotation updates registration and new flows use new key.
    //
    //Key rotation is a common production operation. The old signing key must
    //remain resolvable for in-flight flows. New flows must use the new signing
    //key. This test verifies that RotateSigningKey emits ClientUpdated, that
    //the routing table reflects the new key identifier, and that a full flow
    //completed after rotation verifies correctly with the new key.

    [TestMethod]
    public async Task KeyRotationEmitsClientUpdatedAndNewFlowUsesNewKey()
    {
        List<ClientRegistrationEvent> received = [];



        await using TestHostShell app = new(TimeProvider);

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
        ClientRecord current = app.RegistrationStore[segment];
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

        (Uri requestUri, string parHandle) = await app.HandleParAsync(rotatedKeys,
            new TransactionNonce("nonce-rotation-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = await app.HandleJarRequestAsync(rotatedKeys,
            parHandle, TestContext.CancellationToken).ConfigureAwait(false);

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
            parHandle,
            compactJwe,
            redirectUri: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<PresentationVerifiedState>(
            app.GetFlowState(parHandle).State,
            "Flow started after key rotation must reach PresentationVerified.");
        Assert.IsTrue(verified.Claims.ContainsKey("pid"),
            "Verified claims must contain the pid credential.");
    }


    //Observable: multiple clients registered, each receives independent events.
    //
    //A SaaS deployment registers multiple tenants. Each registration emits its
    //own ClientRegistered event. All registrations must be independently
    //reachable via their own endpoint segments with no cross-contamination.

    [TestMethod]
    public async Task MultipleClientsRegisteredEachReachableIndependently()
    {
        List<ClientRegistrationEvent> received = [];



        await using TestHostShell app = new(TimeProvider);

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

        (Uri requestUriA, string parHandleA) = await app.HandleParAsync(keysA,
            new TransactionNonce("nonce-multi-a-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJarA = await app.HandleJarRequestAsync(keysA,
            parHandleA, TestContext.CancellationToken).ConfigureAwait(false);

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
            parHandleA,
            compactJweA,
            redirectUri: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<PresentationVerifiedState>(
            app.GetFlowState(parHandleA).State,
            "Tenant A flow must reach PresentationVerified.");

        //Tenant B routing table entry must be unaffected.
        Assert.IsTrue(app.RegistrationStore.ContainsKey(segmentB),
            "Tenant B registration must remain in routing table after tenant A flow completes.");
        Assert.AreEqual("https://tenant-b.example.com",
            app.RegistrationStore[segmentB].ClientId,
            "Tenant B registration must retain its original client identifier.");
    }


    //Observable: capability granted event fires and is carried correctly.
    //
    //Verifies that OnCapabilityGranted produces a CapabilityGranted event with
    //the correct payload — a production app would use this to activate new
    //endpoints for a client without a full re-registration.

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
            new ExchangeContext());

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
            WellKnownCapabilityIdentifiers.VcVerifiableCredentialIssuance,
            evt.Capability,
            "CapabilityGranted must carry the granted capability.");
    }


    //Observable: unsubscribed observer stops receiving events.
    //
    //A production app may conditionally enable or disable observability. This
    //test verifies that disposing the subscription stops event delivery.

    [TestMethod]
    public async Task DisposingSubscriptionStopsEventDelivery()
    {
        List<ClientRegistrationEvent> received = [];



        await using TestHostShell app = new(TimeProvider);

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


    //HTTP response shape: PAR response body is valid JSON with request_uri and
    //expires_in — exactly what the ASP.NET skin would read and forward.

    [TestMethod]
    public async Task ParDispatchReturns201WithRequestUriAndExpiresInJson()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        string segment = keys.Registration.TenantId;
        PreparedDcqlQuery query = CreatePreparedQuery();
        TransactionNonce nonce = new("nonce-par-shape-01");

        ExchangeContext context = new();
        context.SetTransactionNonce(nonce);
        context.SetPreparedQuery(query);
        context.SetDecryptionKeyId(keys.EncryptionKeyId);
        context.SetTenantId(segment);

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownEndpointNames.AuthCodePar,
            "POST",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode,
            "PAR must return HTTP 201.");
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


    //HTTP response shape: JAR request returns compact JWS in correct MIME type.

    [TestMethod]
    public async Task JarRequestDispatchReturns200WithCompactJwsContentType()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);



        (Uri requestUri, string parHandle) = await app.HandleParAsync(keys,
            new TransactionNonce("nonce-jar-shape-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        ExchangeContext context = new();
        context.SetTenantId(keys.Registration.TenantId);
        context.SetCorrelationKey(parHandle);

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            keys.Registration.TenantId,
            WellKnownEndpointNames.Oid4VpJarRequest,
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


    //HTTP response shape: direct_post returns 200 with empty body (cross-device)
    //or JSON with redirect_uri (same-device).

    [TestMethod]
    public async Task DirectPostCrossDeviceReturns200WithEmptyBody()
    {
        await using TestHostShell app = new(TimeProvider);
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

        (Uri requestUri, string parHandle) = await app.HandleParAsync(keys,
            new TransactionNonce("nonce-cb-shape-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = await app.HandleJarRequestAsync(keys,
            parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        wallet.HandleQrScan(requestUri, walletFlowId);

        await wallet.HandleJarFetchAsync(
            walletFlowId, requestUri, compactJar, keys.SigningPublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJwe = await wallet.HandleResponsePostAsync(
            walletFlowId, TestContext.CancellationToken).ConfigureAwait(false);

        //Dispatch direct_post directly to inspect raw response shape.
        ExchangeContext context = new();
        context.SetTenantId(keys.Registration.TenantId);

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            keys.Registration.TenantId,
            WellKnownEndpointNames.Oid4VpDirectPost,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.Response] = compactJwe,
                [OAuthRequestParameterNames.State] = parHandle
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
        await using TestHostShell app = new(TimeProvider);
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

        (Uri requestUri, string parHandle) = await app.HandleParAsync(keys,
            new TransactionNonce("nonce-cbsd-shape-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = await app.HandleJarRequestAsync(keys,
            parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        wallet.HandleQrScan(requestUri, walletFlowId);

        await wallet.HandleJarFetchAsync(
            walletFlowId, requestUri, compactJar, keys.SigningPublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJwe = await wallet.HandleResponsePostAsync(
            walletFlowId, TestContext.CancellationToken).ConfigureAwait(false);

        ExchangeContext context = new();
        context.SetTenantId(keys.Registration.TenantId);
        context.SetOid4VpRedirectUri(sameDeviceRedirectUri);

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            keys.Registration.TenantId,
            WellKnownEndpointNames.Oid4VpDirectPost,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.Response] = compactJwe,
                [OAuthRequestParameterNames.State] = parHandle
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


    //HTTP response shape: unknown segment returns 404.

    [TestMethod]
    public async Task DispatchToUnknownSegmentReturns404()
    {
        await using TestHostShell app = new(TimeProvider);

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            "doesnotexist",
            WellKnownEndpointNames.AuthCodePar,
            "POST",
            new RequestFields(),
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode,
            "Dispatch to an unknown segment must return 404.");
    }


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

    [TestMethod]
    public async Task NewlyRegisteredClientCanComputeEndpointUrisFromSegment()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        string segment = keys.Registration.TenantId;

        //Phase 9h chunk 12 — URL shape is the application's choice (the
        //ResolveEndpointUriAsync lambda), no longer the library's baked-in
        //path template. This test now verifies the fixture's lambda produces
        //the expected /connect/{segment}/<suffix> shape for each endpoint
        //role, which is the same contract any production application
        //provides through its own ResolveEndpointUriAsync wiring.
        Uri parUri = TestHostShell.ComposeEndpointUri(
            VerifierBaseUri, segment, WellKnownEndpointNames.AuthCodePar);
        Uri jarUri = TestHostShell.ComposeEndpointUri(
            VerifierBaseUri, segment, WellKnownEndpointNames.Oid4VpJarRequest);
        Uri directPostUri = TestHostShell.ComposeEndpointUri(
            VerifierBaseUri, segment, WellKnownEndpointNames.Oid4VpDirectPost);
        Uri jwksUri = TestHostShell.ComposeEndpointUri(
            VerifierBaseUri, segment, WellKnownEndpointNames.MetadataJwks);
        Uri discoveryUri = TestHostShell.ComposeEndpointUri(
            VerifierBaseUri, segment, WellKnownEndpointNames.MetadataDiscovery);

        Assert.AreEqual(
            $"https://verifier.example.com/connect/{segment}/par",
            parUri.ToString(),
            "PAR URI must follow the fixture's /connect/{segment}/par pattern.");
        Assert.AreEqual(
            $"https://verifier.example.com/connect/{segment}/jar",
            jarUri.ToString(),
            "JAR request URI must follow the fixture's /connect/{segment}/jar pattern. "
            + "The library no longer bakes a per-flow {flowId} into the path; the "
            + "request_uri the wallet receives carries the per-flow handle, not the URL.");
        Assert.AreEqual(
            $"https://verifier.example.com/connect/{segment}/cb",
            directPostUri.ToString(),
            "Direct-post URI must follow the fixture's /connect/{segment}/cb pattern.");
        Assert.AreEqual(
            $"https://verifier.example.com/connect/{segment}/jwks",
            jwksUri.ToString(),
            "JWKS URI must follow the fixture's /connect/{segment}/jwks pattern.");
        Assert.AreEqual(
            $"https://verifier.example.com/connect/{segment}/.well-known/openid-configuration",
            discoveryUri.ToString(),
            "Discovery URI must follow the fixture's /connect/{segment}/.well-known/openid-configuration pattern.");
    }


    [TestMethod]
    public async Task NewlyRegisteredClientCanReachParEndpointAndReceivesRequestUri()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        string segment = keys.Registration.TenantId;

        //The ASP.NET skin populates the context bag with whatever request-scoped
        //data the application wants — segment, issuer, tenant, caller IP, billing tier.
        //The library passes this bag to all delegates unchanged.
        ExchangeContext context = new();
        context.SetTransactionNonce(new TransactionNonce("nonce-journey-01"));
        context.SetPreparedQuery(CreatePreparedQuery());
        context.SetDecryptionKeyId(keys.EncryptionKeyId);
        context.SetTenantId(segment);

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownEndpointNames.AuthCodePar,
            "POST",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode,
            "PAR endpoint must return HTTP 201 for a newly registered client.");
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
        //The request_uri is served by the Authorization Server and rooted at the
        //AS issuer URI per OID4VP 1.0 §5.2 / RFC 9126 §2.2 — not at the Verifier's
        //external base URI. The TestHostShell resolver derives the URL from
        //registration.IssuerUri (https://issuer.test/{segment}), and incorporates
        //the per-flow handle the library placed on context.
        Assert.IsTrue(
            parsedRequestUri!.ToString().StartsWith(
                keys.Registration.IssuerUri!.GetLeftPart(UriPartial.Authority),
                StringComparison.Ordinal),
            "request_uri must be rooted at the Authorization Server issuer authority.");
        Assert.IsGreaterThan(0, expiresIn.GetInt32(),
            "expires_in must be a positive integer.");
    }


    [TestMethod]
    [DynamicData(nameof(AllSigningAlgorithms))]
    public async Task JwksReflectsRegisteredKeyParameters(
        string displayName,
        Func<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> createKeys)
    {
        await using TestHostShell app = new(TimeProvider);
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

        ClientRecord registration = app.RegisterSigningClient(
            $"client-{displayName}", keyPair, JwksCapabilities);

        ServerHttpResponse response = await FetchJwksAsync(
            app, registration, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            $"JWKS endpoint must return HTTP 200 for {displayName}.");
        Assert.AreEqual("application/json", response.ContentType,
            $"JWKS endpoint must return Content-Type: application/json for {displayName}.");

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        JsonElement keysElement = doc.RootElement.GetProperty(WellKnownJwkMemberNames.Keys);
        JsonElement[] jwkArray = keysElement.EnumerateArray().ToArray();

        Assert.HasCount(1, jwkArray,
            $"JWKS must contain exactly one key for {displayName}.");

        JsonElement jwk = jwkArray[0];

        Assert.AreEqual(expectedKty, jwk.GetProperty(WellKnownJwkMemberNames.Kty).GetString(),
            $"Key type mismatch for {displayName}.");

        Assert.AreEqual(expectedAlg, jwk.GetProperty(WellKnownJwkMemberNames.Alg).GetString(),
            $"Algorithm mismatch for {displayName}.");

        Assert.AreEqual(WellKnownJwkValues.UseSig,
            jwk.GetProperty(WellKnownJwkMemberNames.Use).GetString(),
            $"Use must be '{WellKnownJwkValues.UseSig}' for {displayName}.");

        Assert.AreEqual(registration.GetDefaultSigningKeyId(KeyUsageContext.AccessTokenIssuance).Value,
            jwk.GetProperty(WellKnownJwkMemberNames.Kid).GetString(),
            $"Kid must match registration signing key identifier for {displayName}.");

        if(expectedCrv is not null)
        {
            Assert.AreEqual(expectedCrv,
                jwk.GetProperty(WellKnownJwkMemberNames.Crv).GetString(),
                $"Curve mismatch for {displayName}.");
        }
        else
        {
            Assert.IsFalse(jwk.TryGetProperty(WellKnownJwkMemberNames.Crv, out _),
                $"Key type '{expectedKty}' must not have a 'crv' property for {displayName}.");
        }
    }


    [TestMethod]
    public async Task DistinctAlgorithmFamiliesProduceDistinctJwksKeyTypes()
    {
        await using TestHostShell app = new(TimeProvider);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ecKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> pqKeys =
            TestKeyMaterialProvider.CreateMlDsa65KeyMaterial();

        ClientRecord ecClient = app.RegisterSigningClient(
            "ec-client", ecKeys, JwksCapabilities);
        ClientRecord pqClient = app.RegisterSigningClient(
            "pq-client", pqKeys, JwksCapabilities);

        ServerHttpResponse ecResponse = await FetchJwksAsync(
            app, ecClient, TestContext.CancellationToken).ConfigureAwait(false);
        ServerHttpResponse pqResponse = await FetchJwksAsync(
            app, pqClient, TestContext.CancellationToken).ConfigureAwait(false);

        using JsonDocument ecDoc = JsonDocument.Parse(ecResponse.Body);
        using JsonDocument pqDoc = JsonDocument.Parse(pqResponse.Body);

        string? ecKty = ecDoc.RootElement.GetProperty(WellKnownJwkMemberNames.Keys)
            .EnumerateArray().First()
            .GetProperty(WellKnownJwkMemberNames.Kty).GetString();

        string? pqKty = pqDoc.RootElement.GetProperty(WellKnownJwkMemberNames.Keys)
            .EnumerateArray().First()
            .GetProperty(WellKnownJwkMemberNames.Kty).GetString();

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

        await using TestHostShell app = new(TimeProvider);

        //Override BuildJwksDocumentAsync to capture what the delegate receives.
        //This is exactly what an application developer would do — wire a delegate
        //that reads from the context bag to make per-call decisions.
        app.Server.OAuth().Cryptography.BuildJwksDocumentAsync = (registration, ctx, ct) =>
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
        ExchangeContext context = new();
        context.SetTenantId(segment);
        context.SetIssuer(VerifierBaseUri);
        context["app.tenantId"] = tenantId;
        context["app.callerTier"] = callerTier;

        await app.DispatchAtEndpointAsync(
            segment,
            WellKnownEndpointNames.MetadataJwks,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(keys.SigningKeyId, capturedSigningKeyId,
            "BuildJwksDocumentAsync must receive the ClientRecord with its SigningKeyId.");
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
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        string segment = keys.Registration.TenantId;

        //Wire BuildJwksDocumentAsync to suppress all keys for restricted callers.
        app.Server.OAuth().Cryptography.BuildJwksDocumentAsync = (registration, ctx, ct) =>
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
        ExchangeContext unrestrictedContext = new();
        unrestrictedContext.SetTenantId(segment);
        unrestrictedContext.SetIssuer(VerifierBaseUri);
        unrestrictedContext["app.restricted"] = false;
        ServerHttpResponse unrestrictedResponse = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownEndpointNames.MetadataJwks,
            "GET",
            new RequestFields(),
            unrestrictedContext,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Restricted caller — receives an empty JWKS.
        ExchangeContext restrictedContext = new();
        restrictedContext.SetTenantId(segment);
        restrictedContext.SetIssuer(VerifierBaseUri);
        restrictedContext["app.restricted"] = true;
        ServerHttpResponse restrictedResponse = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownEndpointNames.MetadataJwks,
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
            .GetProperty(WellKnownJwkMemberNames.Keys).EnumerateArray().ToArray();

        using JsonDocument restrictedDoc = JsonDocument.Parse(restrictedResponse.Body);
        JsonElement[] restrictedKeys = restrictedDoc.RootElement
            .GetProperty(WellKnownJwkMemberNames.Keys).EnumerateArray().ToArray();

        Assert.IsGreaterThan(0, unrestrictedKeys.Length,
            "Unrestricted caller must receive at least one key.");
        Assert.IsEmpty(restrictedKeys,
            "Restricted caller must receive an empty keys array.");
    }


    [TestMethod]
    public async Task DiscoveryEndpointReturns200WithActiveCapabilityEndpoints()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        string segment = keys.Registration.TenantId;

        //The ASP.NET skin places the issuer URI in the context bag.
        //The discovery BuildInputAsync reads it to compute absolute endpoint URIs.
        ExchangeContext context = new();
        context.SetTenantId(segment);
        context.SetIssuer(VerifierBaseUri);

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownEndpointNames.MetadataDiscovery,
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
                AuthorizationServerMetadataParameterNames.JwksUri, out JsonElement jwksUriEl),
            "Discovery document must advertise the JWKS URI.");

        //The advertised JWKS URI must match the computed URI for this segment.
        //The discovery handler resolves the issuer via the library resolver, which
        //prefers the registration's IssuerUri over the context's request-scoped
        //fallback. Build the expectation from the same source.
        Uri expectedJwksUri = TestHostShell.ComposeEndpointUri(
            keys.Registration.IssuerUri!, segment, WellKnownEndpointNames.MetadataJwks);
        Assert.AreEqual(expectedJwksUri.ToString(), jwksUriEl.GetString(),
            "Advertised JWKS URI must match the computed URI for this segment.");

        //OID4VP Verifier does not have PAR as an AuthCode capability — it has its
        //own OID4VP PAR. The discovery document reflects the actual capability set.
        Assert.IsFalse(
            root.TryGetProperty(
                AuthorizationServerMetadataParameterNames.PushedAuthorizationRequestEndpoint, out _),
            "OID4VP-only registration must not advertise PAR in the Auth Code sense.");
    }


    [TestMethod]
    public async Task DiscoveryEmissionDropsFieldsForCapabilitiesAttenuatedByResolveCapabilitiesAsync()
    {
        await using TestHostShell app = new(TimeProvider);

        //Veto JwksEndpoint via the per-request capability resolver — the
        //chain build drops the JWKS endpoint candidate; discovery emission
        //walks the chain, so jwks_uri must be absent from the document.
        //The library default keeps every other capability the registration
        //allows, so the issuer and any other advertised endpoint (e.g.
        //pushed_authorization_request_endpoint if it were in the set)
        //still emit.
        app.Server.OAuth().ResolveCapabilitiesAsync = (registration, ctx, ct) =>
        {
            HashSet<CapabilityIdentifier> attenuated =
                [.. registration.AllowedCapabilities.Where(c => c != WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)];
            return ValueTask.FromResult<IReadOnlySet<CapabilityIdentifier>>(attenuated);
        };

        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);
        string segment = keys.Registration.TenantId;

        ExchangeContext context = new();
        context.SetTenantId(segment);
        context.SetIssuer(VerifierBaseUri);

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownEndpointNames.MetadataDiscovery,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            "Discovery endpoint must still return 200 — only JWKS was vetoed.");

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        JsonElement root = doc.RootElement;

        Assert.IsTrue(root.TryGetProperty("issuer", out _),
            "Issuer is request-scoped, not capability-derived — must still emit.");
        Assert.IsFalse(
            root.TryGetProperty(AuthorizationServerMetadataParameterNames.JwksUri, out _),
            "jwks_uri must be absent from discovery when ResolveCapabilitiesAsync "
            + "attenuated JwksEndpoint out of the active set. The chain-walk "
            + "emission reads endpoint.DiscoveryMetadataKey for every chain "
            + "entry; an absent endpoint produces no entry to emit.");
    }


    [TestMethod]
    public async Task AfterKeyRotationJwksContainsNewKid()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial originalKeys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        string segment = originalKeys.Registration.TenantId;

        using VerifierKeyMaterial rotatedKeys = app.RotateSigningKey(segment);

        ExchangeContext context = new();
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


    [TestMethod]
    public async Task DeregisteredClientJwksAndDiscoveryReturn404()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        string segment = keys.Registration.TenantId;
        app.DeregisterClient(segment, "Client offboarded.");

        ExchangeContext context = new();
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

        ExchangeContext context = new();
        context.SetTenantId(segment);
        context.SetIssuer(VerifierBaseUri);

        const int requestCount = 3;
        for(int i = 0; i < requestCount; i++)
        {
            await app.DispatchAtEndpointAsync(
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
        ExchangeContext context = new();
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
            ExchangeContext context = new();
            context.SetTenantId(segment);
            context.SetIssuer(VerifierBaseUri);
            context["app.region"] = region;
            await app.DispatchAtEndpointAsync(
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
        ExchangeContext context = new();
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

    [TestMethod]
    public async Task EndpointBuildersAreInvokedOncePerRequestNotCachedPerRegistration()
    {
        int builderInvocations = 0;

        EndpointBuilderDelegate countingMetadataBuilder = (registration, context, server) =>
        {
            Interlocked.Increment(ref builderInvocations);
            return MetadataEndpoints.Builder(registration, context, server);
        };

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
            new RequestFields(), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse second = await app.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.MetadataJwks, "GET",
            new RequestFields(), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, first.StatusCode);
        Assert.AreEqual(200, second.StatusCode);
        Assert.AreEqual(2, builderInvocations,
            "The metadata builder must be invoked once per dispatch — the chain is not cached per registration.");
    }


    [TestMethod]
    public async Task CapabilityAttenuationByResolveCapabilitiesAsyncRemovesEndpointFromChain()
    {
        await using TestHostShell app = new(TimeProvider);

        using VerifierKeyMaterial keys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        // Phase 9h chunk 8 — the per-request capability gate moved into
        // EndpointChain.BuildForRequestAsync. Attenuating the capability set
        // at chain-build time drops candidates whose capability isn't in the
        // active set; the dispatcher never sees the endpoint, so the chain
        // walk finds no match and the response is 404 (not 403 as under the
        // old post-match capability-check model).
        app.Server.OAuth().ResolveCapabilitiesAsync = static (registration, context, ct) =>
        {
            HashSet<CapabilityIdentifier> attenuated =
                [.. registration.AllowedCapabilities.Where(c => c != WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)];
            return ValueTask.FromResult<IReadOnlySet<CapabilityIdentifier>>(attenuated);
        };

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            keys.Registration.TenantId.Value,
            WellKnownEndpointNames.MetadataJwks, "GET",
            new RequestFields(), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode);
    }


    [TestMethod]
    public async Task StatelessEndpointDispatchDoesNotPersistFlowState()
    {
        await using TestHostShell app = new(TimeProvider);

        using VerifierKeyMaterial keys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        int flowsBefore = app.FlowStore.Count;

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            keys.Registration.TenantId.Value,
            WellKnownEndpointNames.MetadataJwks, "GET",
            new RequestFields(), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode);
        Assert.HasCount(flowsBefore, app.FlowStore, "Stateless dispatch must not persist any flow state.");
    }


    [TestMethod]
    public async Task ContinuingFlowDispatchedAfterExpiresAtReturns400Expired()
    {
        await using TestHostShell app = new(TimeProvider);

        using VerifierKeyMaterial keys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (Uri _, string parHandle) = await app.HandleParAsync(
            keys,
            new TransactionNonce("nonce-ttl-contract-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        (FlowState State, int _) entry = app.GetFlowState(parHandle);
        Assert.IsNotNull(entry.State);

        // Advance past the flow's ExpiresAt by one second so the dispatcher's TTL
        // check fails on the resume attempt.
        TimeSpan beyondExpiry = entry.State.ExpiresAt - TimeProvider.GetUtcNow() + TimeSpan.FromSeconds(1);
        TimeProvider.Advance(beyondExpiry);

        ExchangeContext context = new();
        context.SetCorrelationKey(parHandle);

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            keys.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VpJarRequest, "GET",
            new RequestFields(), context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
    }


    [TestMethod]
    public async Task PostDispatchContextCarriesMatchedEndpointCapability()
    {
        await using TestHostShell app = new(TimeProvider);

        using VerifierKeyMaterial keys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        ExchangeContext context = new();

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            keys.Registration.TenantId.Value,
            WellKnownEndpointNames.MetadataJwks, "GET",
            new RequestFields(), context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode);
        Assert.AreEqual(WellKnownCapabilityIdentifiers.OAuthJwksEndpoint, context.Capability);
    }


    [TestMethod]
    public async Task ContinuingFlowResolvesExternalHandleToInternalFlowIdBeforeLoadingState()
    {
        await using TestHostShell app = new(TimeProvider);

        using VerifierKeyMaterial keys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (Uri _, string parHandle) = await app.HandleParAsync(
            keys,
            new TransactionNonce("nonce-handle-resolution-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        string? capturedLoadFlowId = null;
        LoadServerFlowStateDelegate originalLoad = app.Server.OAuth().LoadFlowStateAsync!;
        app.Server.OAuth().LoadFlowStateAsync = async (tenantId, flowId, ctx, ct) =>
        {
            capturedLoadFlowId = flowId;
            return await originalLoad(tenantId, flowId, ctx, ct).ConfigureAwait(false);
        };

        ExchangeContext context = new();
        context.SetCorrelationKey(parHandle);

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            keys.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VpJarRequest, "GET",
            new RequestFields(), context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode);
        Assert.IsNotNull(capturedLoadFlowId);
        Assert.AreNotEqual(parHandle, capturedLoadFlowId,
            "LoadFlowStateAsync must receive the resolved internal flowId, not the external request_uri handle.");
    }


    [TestMethod]
    public async Task DispatchPlacesMatchPayloadOnContextBeforeHandlerFires()
    {
        await using TestHostShell app = new(TimeProvider);

        using VerifierKeyMaterial keys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        MatchPayload? capturedAtMatchedStage = null;

        // Phase 9h chunk 8 — the InspectAsync(MatchedStage) hook fires after
        // the dispatcher placed the match payload on the context and before
        // the matched endpoint's handler runs. Capturing context.MatchPayload
        // here proves the payload is visible to anything that fires
        // post-match-pre-handler.
        app.Server.OAuth().InspectAsync = (stage, context, ct) =>
        {
            if(stage is MatchedStage)
            {
                capturedAtMatchedStage = context.MatchPayload;
            }

            return ValueTask.CompletedTask;
        };

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            keys.Registration.TenantId.Value,
            WellKnownEndpointNames.MetadataJwks, "GET",
            new RequestFields(), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode);
        Assert.IsNotNull(capturedAtMatchedStage);
    }


    [TestMethod]
    public async Task SameRequestContextInstanceReachesEveryIntegrationDelegate()
    {
        await using TestHostShell app = new(TimeProvider);

        using VerifierKeyMaterial keys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        List<ExchangeContext> captured = [];

        LoadRegistrationDelegate originalLoadReg = app.Server.OAuth().LoadClientRegistrationAsync!;
        app.Server.OAuth().LoadClientRegistrationAsync = async (tenantId, ctx, ct) =>
        {
            captured.Add(ctx);
            return await originalLoadReg(tenantId, ctx, ct).ConfigureAwait(false);
        };

        InspectDelegate originalInspect = app.Server.OAuth().InspectAsync!;
        app.Server.OAuth().InspectAsync = (stage, ctx, ct) =>
        {
            captured.Add(ctx);
            return originalInspect(stage, ctx, ct);
        };

        ExchangeContext outerContext = new();

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            keys.Registration.TenantId.Value,
            WellKnownEndpointNames.MetadataJwks, "GET",
            new RequestFields(), outerContext,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode);
        Assert.IsGreaterThan(0, captured.Count);
        foreach(ExchangeContext ctx in captured)
        {
            Assert.AreSame(outerContext, ctx);
        }
    }


    [TestMethod]
    public async Task SaveFlowStateAsyncReceivesResolvedTenantId()
    {
        await using TestHostShell app = new(TimeProvider);

        using VerifierKeyMaterial keys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        TenantId? capturedTenantId = null;
        SaveServerFlowStateDelegate originalSave = app.Server.OAuth().SaveFlowStateAsync!;
        app.Server.OAuth().SaveFlowStateAsync = async (tenantId, key, state, stepCount, ctx, ct) =>
        {
            capturedTenantId = tenantId;
            await originalSave(tenantId, key, state, stepCount, ctx, ct).ConfigureAwait(false);
        };

        await app.HandleParAsync(
            keys,
            new TransactionNonce("nonce-save-tenant-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(capturedTenantId);
        Assert.AreEqual(keys.Registration.TenantId, capturedTenantId.Value);
    }


    [TestMethod]
    public async Task LoadFlowStateAsyncReceivesResolvedTenantId()
    {
        await using TestHostShell app = new(TimeProvider);

        using VerifierKeyMaterial keys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (Uri _, string parHandle) = await app.HandleParAsync(
            keys,
            new TransactionNonce("nonce-load-tenant-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        TenantId? capturedTenantId = null;
        LoadServerFlowStateDelegate originalLoad = app.Server.OAuth().LoadFlowStateAsync!;
        app.Server.OAuth().LoadFlowStateAsync = async (tenantId, flowId, ctx, ct) =>
        {
            capturedTenantId = tenantId;
            return await originalLoad(tenantId, flowId, ctx, ct).ConfigureAwait(false);
        };

        ExchangeContext context = new();
        context.SetCorrelationKey(parHandle);

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            keys.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VpJarRequest, "GET",
            new RequestFields(), context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode);
        Assert.IsNotNull(capturedTenantId);
        Assert.AreEqual(keys.Registration.TenantId, capturedTenantId.Value);
    }

    private static async ValueTask<ServerHttpResponse> FetchJwksAsync(
        TestHostShell app,
        ClientRecord registration,
        CancellationToken cancellationToken)
    {
        ExchangeContext context = new();
        context.SetTenantId(registration.TenantId);
        context.SetIssuer(VerifierBaseUri);

        return await app.DispatchAtEndpointAsync(
            registration.TenantId,
            WellKnownEndpointNames.MetadataJwks,
            "GET",
            new RequestFields(),
            context,
            cancellationToken).ConfigureAwait(false);
    }


    private static PreparedDcqlQuery CreatePreparedQuery() =>
        DcqlFixtures.PidFamilyNamePrepared();


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
            c => JsonSerializerExtensions.SerializeToUtf8Bytes(c, TestSetup.DefaultSerializationOptions),
            SdJwtIssuance.IssueVerboseAsync,
            disclosablePaths, TestSalts.DefaultGenerator(),
            issuerPrivateKey, IssuerKeyId, Pool,
            mediaType: WellKnownMediaTypes.Jwt.VcSdJwt,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        string compactJws = Encoding.UTF8.GetString(result.SignedToken.Span);
        using SdToken<string> issuedToken = new(compactJws, result.Disclosures.ToList());
        string serializedSdJwt = SdJwtSerializer.SerializeToken(issuedToken, TestSetup.Base64UrlEncoder);

        return (serializedSdJwt, holderKeys.PrivateKey, issuerKeys.PublicKey);
    }


    [TestMethod]
    public async Task DefaultResolverReturnsNullWhenScopeToAudienceUnset()
    {
        //Body D — closes audit Finding 2. Registration with no ScopeToAudience
        //map produces null audience from the default resolver.
        ClientRecord registration = MakeRegistrationForAud(scopeToAudience: null);
        IssuanceContext context = MakeIssuanceContext(registration, "openid profile");

        IReadOnlyList<string>? audiences = await Rfc9068AccessTokenProducer
            .DefaultResolveAccessTokenAudienceAsync(
                registration, context, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.IsNull(audiences,
            "Default resolver returns null when ScopeToAudience is unset.");
    }


    [TestMethod]
    public async Task DefaultResolverMapsSingleScopeToAudiences()
    {
        //One scope mapping → list with the mapped audience.
        Dictionary<string, IReadOnlyList<string>> map = new(StringComparer.Ordinal)
        {
            ["read"] = new[] { "https://api.example.com/orders" }
        };
        ClientRecord registration = MakeRegistrationForAud(scopeToAudience: map);
        IssuanceContext context = MakeIssuanceContext(registration, "read");

        IReadOnlyList<string>? audiences = await Rfc9068AccessTokenProducer
            .DefaultResolveAccessTokenAudienceAsync(
                registration, context, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.IsNotNull(audiences);
        Assert.HasCount(1, audiences);
        Assert.AreEqual("https://api.example.com/orders", audiences[0]);
    }


    [TestMethod]
    public async Task DefaultResolverDedupesAcrossScopes()
    {
        //Two scopes mapping to overlapping audiences — the union is deduped via
        //ordinal-equal string comparison.
        Dictionary<string, IReadOnlyList<string>> map = new(StringComparer.Ordinal)
        {
            ["read"] = new[] { "https://api.example.com/orders", "https://api.example.com/billing" },
            ["write"] = new[] { "https://api.example.com/orders" }
        };
        ClientRecord registration = MakeRegistrationForAud(scopeToAudience: map);
        IssuanceContext context = MakeIssuanceContext(registration, "read write");

        IReadOnlyList<string>? audiences = await Rfc9068AccessTokenProducer
            .DefaultResolveAccessTokenAudienceAsync(
                registration, context, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.IsNotNull(audiences);
        Assert.HasCount(2, audiences);
        Assert.Contains("https://api.example.com/orders", audiences);
        Assert.Contains("https://api.example.com/billing", audiences);
    }


    [TestMethod]
    public void JwtPayloadEmitsAudPerRfc7519()
    {
        //RFC 7519 §4.1.3 — single-element list emits as JSON string;
        //multi-element list emits as JSON array; null/empty omits the claim.
        DateTimeOffset now = TimeProvider.GetUtcNow();

        JwtPayload single = JwtPayload.ForAccessToken(
            subject: "alice", jti: "j1", scope: "read",
            issuedAt: now, expiresAt: now.AddHours(1),
            issuer: "https://issuer", audience: SingleAudience, clientId: "c1");
        Assert.IsTrue(single.TryGetValue(WellKnownJwtClaimNames.Aud, out object? singleAud));
        Assert.IsInstanceOfType<string>(singleAud);
        Assert.AreEqual("https://api1", (string)singleAud!);

        JwtPayload multi = JwtPayload.ForAccessToken(
            subject: "alice", jti: "j2", scope: "read",
            issuedAt: now, expiresAt: now.AddHours(1),
            issuer: "https://issuer",
            audience: MultiAudience, clientId: "c1");
        Assert.IsTrue(multi.TryGetValue(WellKnownJwtClaimNames.Aud, out object? multiAud));
        Assert.IsInstanceOfType<IReadOnlyList<string>>(multiAud);

        JwtPayload absent = JwtPayload.ForAccessToken(
            subject: "alice", jti: "j3", scope: "read",
            issuedAt: now, expiresAt: now.AddHours(1),
            issuer: "https://issuer", audience: null, clientId: "c1");
        Assert.IsFalse(absent.ContainsKey(WellKnownJwtClaimNames.Aud),
            "Null audience must omit the aud claim entirely.");

        JwtPayload empty = JwtPayload.ForAccessToken(
            subject: "alice", jti: "j4", scope: "read",
            issuedAt: now, expiresAt: now.AddHours(1),
            issuer: "https://issuer",
            audience: Array.Empty<string>(), clientId: "c1");
        Assert.IsFalse(empty.ContainsKey(WellKnownJwtClaimNames.Aud),
            "Empty audience list must omit the aud claim entirely.");
    }


    private static readonly string[] SingleAudience = ["https://api1"];
    private static readonly string[] MultiAudience = ["https://api1", "https://api2"];


    [TestMethod]
    public async Task DefaultResolverSurfacesCancellation()
    {
        //Body D — cancellation propagates through the default resolver.
        Dictionary<string, IReadOnlyList<string>> map = new(StringComparer.Ordinal)
        {
            ["read"] = new[] { "https://api" }
        };
        ClientRecord registration = MakeRegistrationForAud(scopeToAudience: map);
        IssuanceContext context = MakeIssuanceContext(registration, "read");

        using CancellationTokenSource cts = new();
        await cts.CancelAsync();

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () =>
            await Rfc9068AccessTokenProducer.DefaultResolveAccessTokenAudienceAsync(
                registration, context, cts.Token));
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


    //Constructs the minimum-fields ClientRecord the policy resolver
    //needs. Tests in this class consume only the Profile axis.
    private static ClientRecord MakeMinimalRegistration(PolicyProfile profile) =>
        new()
        {
            ClientId = "policy-test-client",
            TenantId = "policy-test",
            AllowedCapabilities = ImmutableHashSet<CapabilityIdentifier>.Empty,
            AllowedRedirectUris = ImmutableHashSet<Uri>.Empty,
            AllowedScopes = ImmutableHashSet<string>.Empty,
            SigningKeys = ImmutableDictionary<KeyUsageContext, SigningKeySet>.Empty,
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty,
            Profile = profile
        };


    //Constructs the registration shape the Body D audience-resolver tests need:
    //the ScopeToAudience field is the only axis under test; everything else is
    //placeholder.
    private static ClientRecord MakeRegistrationForAud(
        IReadOnlyDictionary<string, IReadOnlyList<string>>? scopeToAudience) =>
        new()
        {
            ClientId = "aud-test-client",
            TenantId = "aud-test",
            AllowedCapabilities = ImmutableHashSet<CapabilityIdentifier>.Empty,
            AllowedRedirectUris = ImmutableHashSet<Uri>.Empty,
            AllowedScopes = ImmutableHashSet<string>.Empty,
            SigningKeys = ImmutableDictionary<KeyUsageContext, SigningKeySet>.Empty,
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty,
            ScopeToAudience = scopeToAudience
        };


    //Builds the IssuanceContext the resolver consumes. Subject and ClientId are
    //placeholder; only Scope is varied per test. GrantType is fixed at
    //authorization_code — audience resolution does not vary by grant.
    private static IssuanceContext MakeIssuanceContext(
        ClientRecord registration, string scope) =>
        new()
        {
            Registration = registration,
            Context = new ExchangeContext(),
            IssuerUri = new Uri("https://issuer.example.com"),
            Subject = "alice",
            Scope = scope,
            ClientId = registration.ClientId,
            GrantType = WellKnownGrantTypes.AuthorizationCode,
            IssuedAt = DateTimeOffset.UnixEpoch
        };
}
