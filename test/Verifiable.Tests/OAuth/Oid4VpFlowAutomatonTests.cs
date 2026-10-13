using Microsoft.Extensions.Time.Testing;
using System.Text;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Core.Dcql;
using Verifiable.Cryptography;
using Verifiable.Foundation.Automata;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;


/// <summary>
/// Structural tests for the OID4VP flow pushdown automaton produced by
/// <see cref="Oid4VpFlowAutomaton.Create"/>. Each test exercises state machine
/// behaviour in isolation from the party-boundary wire format.
/// </summary>
[TestClass]
internal sealed class Oid4VpFlowAutomatonTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static JwtPayloadSerializer PayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);

    private const string VerifierClientId = "https://verifier.example.com";
    private const string ResponseUriString = "https://verifier.example.com/cb";

    /// <summary>
    /// In-memory key store keyed by <see cref="KeyId"/>. Each test instance has its
    /// own store so tests are isolated.
    /// </summary>
    private Dictionary<KeyId, PrivateKeyMemory> KeyStore { get; } = [];


    [TestMethod]
    public async Task InitiateTransitionsToPkceGenerated()
    {
        PushdownAutomaton<FlowState, FlowInput, Oid4VpStackSymbol> pda = CreatePda();

        bool stepped = await pda.StepAsync(
            CreateInitiate("flow-1"),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(stepped, "Initiate must produce a transition.");
        _ = Assert.IsInstanceOfType<PkceGeneratedState>(pda.CurrentState);
        Assert.AreEqual("flow-1", pda.CurrentState.FlowId);
        Assert.AreEqual("https://as.example.com", pda.CurrentState.ExpectedIssuer);
    }


    [TestMethod]
    public async Task ParBodyComposedTransitionsFromPkceGeneratedToParRequestReady()
    {
        PushdownAutomaton<FlowState, FlowInput, Oid4VpStackSymbol> pda = CreatePda();
        _ = await pda.StepAsync(
            CreateInitiate("flow-2"), TestContext.CancellationToken).ConfigureAwait(false);

        bool stepped = await pda.StepAsync(
            new ParBodyComposed("client_id=test&code_challenge=abc", TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(stepped);
        _ = Assert.IsInstanceOfType<ParRequestReadyState>(pda.CurrentState);
    }


    [TestMethod]
    public async Task ParSucceededTransitionsToParCompletedWithCorrectExpiry()
    {
        PushdownAutomaton<FlowState, FlowInput, Oid4VpStackSymbol> pda = CreatePda();
        _ = await pda.StepAsync(
            CreateInitiate("flow-3"), TestContext.CancellationToken).ConfigureAwait(false);
        _ = await pda.StepAsync(
            new ParBodyComposed("body", TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        DateTimeOffset receivedAt = TimeProvider.GetUtcNow();
        KeyId keyId = StoreDecryptionKey();

        bool stepped = await pda.StepAsync(
            new ParSucceeded(
                new ParResponse(new Uri("urn:ietf:params:oauth:request_uri:abc"), 60),
                new TransactionNonce("nonce-xyz"),
                CreatePreparedQuery(),
                keyId,
                receivedAt),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(stepped);
        Verifiable.OAuth.Oid4Vp.States.ParCompletedState parCompleted =
            Assert.IsInstanceOfType<Verifiable.OAuth.Oid4Vp.States.ParCompletedState>(pda.CurrentState);
        Assert.AreEqual("flow-3", parCompleted.FlowId);
        Assert.AreEqual(receivedAt.AddSeconds(60), parCompleted.ExpiresAt,
            "ExpiresAt must be derived from the PAR expires_in value.");
    }


    [TestMethod]
    public async Task FailInputTransitionsToFlowFailedFromAnyNonTerminalState()
    {
        PushdownAutomaton<FlowState, FlowInput, Oid4VpStackSymbol> pda = CreatePda();
        _ = await pda.StepAsync(
            CreateInitiate("flow-4"), TestContext.CancellationToken).ConfigureAwait(false);

        DateTimeOffset failedAt = TimeProvider.GetUtcNow();
        bool stepped = await pda.StepAsync(
            new Fail("PAR endpoint unreachable.", failedAt),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(stepped);
        FlowFailed failed = Assert.IsInstanceOfType<FlowFailed>(pda.CurrentState);
        Assert.AreEqual("PAR endpoint unreachable.", failed.Reason);
        Assert.AreEqual(failedAt, failed.FailedAt);
    }


    [TestMethod]
    public async Task PdaHaltsAfterFlowFailed()
    {
        PushdownAutomaton<FlowState, FlowInput, Oid4VpStackSymbol> pda = CreatePda();
        _ = await pda.StepAsync(
            CreateInitiate("flow-5"), TestContext.CancellationToken).ConfigureAwait(false);
        _ = await pda.StepAsync(
            new Fail("First failure.", TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        bool stepped = await pda.StepAsync(
            new Fail("Second failure — must not apply.", TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(stepped, "No transition is defined from FlowFailed.");
        Assert.IsTrue(pda.IsHalted);
    }


    [TestMethod]
    public async Task UndefinedInputOnWrongStateHaltsPda()
    {
        PushdownAutomaton<FlowState, FlowInput, Oid4VpStackSymbol> pda = CreatePda();
        _ = await pda.StepAsync(
            CreateInitiate("flow-6"), TestContext.CancellationToken).ConfigureAwait(false);

        bool stepped = await pda.StepAsync(
            new JarFetched(TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(stepped, "JarFetched from PkceGenerated is undefined — PDA must halt.");
        Assert.IsTrue(pda.IsHalted);
    }


    [TestMethod]
    public async Task TraceObserverReceivesOneEntryPerStep()
    {
        PushdownAutomaton<FlowState, FlowInput, Oid4VpStackSymbol> pda = CreatePda();
        string pdaRunId = pda.RunId;
        var observer = new TestObserver<TraceEntry<FlowState, FlowInput>>();
        using IDisposable subscription = pda.Subscribe(observer);

        _ = await pda.StepAsync(
            CreateInitiate("flow-7"), TestContext.CancellationToken).ConfigureAwait(false);
        _ = await pda.StepAsync(
            new ParBodyComposed("body", TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        KeyId keyId = StoreDecryptionKey();
        _ = await pda.StepAsync(
            new ParSucceeded(
                new ParResponse(new Uri("urn:ietf:params:oauth:request_uri:test"), 60),
                new TransactionNonce("nonce"),
                CreatePreparedQuery(),
                keyId,
                TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(3, observer.Received,
            "Three transitions must produce exactly three trace entries.");

        foreach(TraceEntry<FlowState, FlowInput> entry in observer.Received)
        {
            Assert.AreEqual(pdaRunId, entry.RunId,
                "Each trace entry must carry the PDA run identifier.");
            Assert.AreEqual(TraceOutcome.Transitioned, entry.Outcome);
            Assert.IsNotNull(entry.Label, "Every transition must carry a label.");
        }
    }


    [TestMethod]
    public async Task StackDepthRemainsOneOnLinearFlow()
    {
        PushdownAutomaton<FlowState, FlowInput, Oid4VpStackSymbol> pda = CreatePda();
        _ = await pda.StepAsync(
            CreateInitiate("flow-8"), TestContext.CancellationToken).ConfigureAwait(false);
        _ = await pda.StepAsync(
            new ParBodyComposed("body", TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, pda.StackDepth,
            "Stack must contain only the sentinel on the linear path.");
    }


    [TestMethod]
    public async Task StepCountMatchesNumberOfSuccessfulTransitions()
    {
        PushdownAutomaton<FlowState, FlowInput, Oid4VpStackSymbol> pda = CreatePda();
        _ = await pda.StepAsync(
            CreateInitiate("flow-9"), TestContext.CancellationToken).ConfigureAwait(false);
        _ = await pda.StepAsync(
            new ParBodyComposed("body", TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(2, pda.StepCount);
    }


    [TestMethod]
    public void AcceptPredicateReturnsTrueOnlyForPresentationVerified()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();

        Assert.IsTrue(
            IsAcceptState(new PresentationVerifiedState
            {
                FlowId = "flow-10",
                ExpectedIssuer = "https://as.example.com",
                EnteredAt = now,
                ExpiresAt = now.AddMinutes(5),
                Kind = FlowKind.Oid4VpVerifier,
                VerifiedAt = now,
                Credentials = new Dictionary<CredentialQueryId, VpCredentialClaims>()
            }),
            "PresentationVerified must satisfy the accept predicate.");

        Assert.IsFalse(
            IsAcceptState(new FlowFailed
            {
                FlowId = "flow-10",
                ExpectedIssuer = "https://as.example.com",
                EnteredAt = now,
                ExpiresAt = now.AddMinutes(5),
                Kind = FlowKind.Oid4VpVerifier,
                Reason = "Failure.",
                FailedAt = now
            }),
            "FlowFailed must not satisfy the accept predicate.");
    }


    [TestMethod]
    public async Task JarSignedTransitionsParCompletedToJarReady()
    {
        PushdownAutomaton<FlowState, FlowInput, Oid4VpStackSymbol> pda = CreatePda();
        await RunToParCompleted(pda, "flow-11", TestContext.CancellationToken).ConfigureAwait(false);

        await RunToJarReadyFromParCompleted(pda, TestContext.CancellationToken).ConfigureAwait(false);

        _ = Assert.IsInstanceOfType<JarReadyState>(pda.CurrentState);
    }


    [TestMethod]
    public async Task JarFetchedTransitionsJarReadyToJarServed()
    {
        PushdownAutomaton<FlowState, FlowInput, Oid4VpStackSymbol> pda = CreatePda();
        await RunToJarReady(pda, "flow-12", TestContext.CancellationToken).ConfigureAwait(false);

        bool stepped = await pda.StepAsync(
            new JarFetched(TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(stepped, "JarFetched must transition JarReady to JarServed.");
        _ = Assert.IsInstanceOfType<JarServedState>(pda.CurrentState);
    }


    [TestMethod]
    public async Task FullFlowStepCountMatchesAllTransitions()
    {
        PushdownAutomaton<FlowState, FlowInput, Oid4VpStackSymbol> pda = CreatePda();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> exchangeKeys =
            TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory encryptionPublicKey = exchangeKeys.PublicKey;
        KeyId keyId = StoreDecryptionKey(exchangeKeys.PrivateKey);

        await RunToParCompletedWithKey(
            pda, "flow-16", keyId, TestContext.CancellationToken).ConfigureAwait(false);
        await RunToJarReadyFromParCompleted(pda, TestContext.CancellationToken).ConfigureAwait(false);
        _ = await pda.StepAsync(
            new JarFetched(TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        //Encrypt a minimal payload to the verifier's public key so ResponsePosted can be stepped.
        byte[] minimalPayload = Encoding.UTF8.GetBytes(/*lang=json,strict*/ "{\"vp_token\":\"test\"}");
        string compactJwe = await EncryptPayloadAsync(
            encryptionPublicKey, minimalPayload, TestContext.CancellationToken).ConfigureAwait(false);

        _ = await pda.StepAsync(
            new ResponsePosted(compactJwe, TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        _ = await pda.StepAsync(
            new VerificationSucceeded(
                new Dictionary<CredentialQueryId, VpCredentialClaims>(),
                TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        //Initiate, ParBodyComposed, ParSucceeded, JarSigned, JarFetched,
        //ResponsePosted, VerificationSucceeded = 7 transitions.
        Assert.AreEqual(7, pda.StepCount,
            "Full PAR+JAR+direct_post.jwt flow must produce exactly seven transitions.");
    }


    private PushdownAutomaton<FlowState, FlowInput, Oid4VpStackSymbol> CreatePda() =>
        Oid4VpFlowAutomaton.Create(Guid.NewGuid().ToString(), TimeProvider);


    private Initiate CreateInitiate(string flowId) =>
        new(
            Pkce: PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool),
            RedirectUri: new Uri("https://client.example.com/callback"),
            Scopes: ["openid"],
            FlowId: flowId,
            ExpectedIssuer: "https://as.example.com",
            InitiatedAt: TimeProvider.GetUtcNow(),
            InitialExpiresAt: TimeProvider.GetUtcNow().AddMinutes(5));


    private async System.Threading.Tasks.ValueTask RunToParCompleted(
        PushdownAutomaton<FlowState, FlowInput, Oid4VpStackSymbol> pda,
        string flowId,
        CancellationToken cancellationToken)
    {
        KeyId keyId = StoreDecryptionKey();
        await RunToParCompletedWithKey(pda, flowId, keyId, cancellationToken)
            .ConfigureAwait(false);
    }


    private async System.Threading.Tasks.ValueTask RunToParCompletedWithKey(
        PushdownAutomaton<FlowState, FlowInput, Oid4VpStackSymbol> pda,
        string flowId,
        KeyId keyId,
        CancellationToken cancellationToken)
    {
        _ = await pda.StepAsync(CreateInitiate(flowId), cancellationToken).ConfigureAwait(false);
        _ = await pda.StepAsync(
            new ParBodyComposed("client_id=test", TimeProvider.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);
        _ = await pda.StepAsync(
            new ParSucceeded(
                new ParResponse(new Uri("urn:ietf:params:oauth:request_uri:test"), 60),
                new TransactionNonce("nonce-abc"),
                CreatePreparedQuery(),
                keyId,
                TimeProvider.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);
    }


    private async System.Threading.Tasks.ValueTask RunToJarReady(
        PushdownAutomaton<FlowState, FlowInput, Oid4VpStackSymbol> pda,
        string flowId,
        CancellationToken cancellationToken)
    {
        await RunToParCompleted(pda, flowId, cancellationToken).ConfigureAwait(false);
        await RunToJarReadyFromParCompleted(pda, cancellationToken).ConfigureAwait(false);
    }


    private async System.Threading.Tasks.ValueTask RunToJarReadyFromParCompleted(
        PushdownAutomaton<FlowState, FlowInput, Oid4VpStackSymbol> pda,
        CancellationToken cancellationToken)
    {
        Verifiable.OAuth.Oid4Vp.States.ParCompletedState state =
            Assert.IsInstanceOfType<Verifiable.OAuth.Oid4Vp.States.ParCompletedState>(pda.CurrentState);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signingKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory signingPublicKey = signingKeys.PublicKey;
        using PrivateKeyMemory signingPrivateKey = signingKeys.PrivateKey;

        //The client metadata carries an empty JWKS for structural tests — encryption
        //key extraction is exercised separately in the party-boundary tests.
        VerifierClientMetadata clientMetadata =
            HaipProfile.CreateVerifierClientMetadata(VerifierClientId, BuildEmptyJwksJson());

        //The convenience overload that derived BuildJarAsync inputs from a
        //ParCompletedState was removed: the client-side ParCompletedState carries
        //no state value and JAR timing claims are policy-driven. Compose the
        //inputs explicitly here.
        DateTimeOffset now = TimeProvider.GetUtcNow();
        (JarSigned input, _) = await HaipProfile.BuildJarAsync(
            now: now,
            requestObjectLifetime: TimingPolicy.Default.Oid4VpRequestObjectLifetime,
            state: $"state-{state.FlowId}",
            nonce: state.Nonce,
            dcqlQuery: state.Query,
            clientId: VerifierClientId,
            responseUri: new Uri(ResponseUriString),
            clientMetadata: clientMetadata,
            signingKey: signingPrivateKey,
            headerSerializer: HeaderSerializer,
            payloadSerializer: PayloadSerializer,
            dcqlQuerySerializer: q => JsonSerializer.Serialize(q, TestSetup.DefaultSerializationOptions),
            clientMetadataSerializer: m => JsonSerializer.Serialize(m, TestSetup.DefaultSerializationOptions),
            encoder: TestSetup.Base64UrlEncoder,
            pool: Pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        _ = await pda.StepAsync(input, cancellationToken).ConfigureAwait(false);
    }


    private KeyId StoreDecryptionKey(PrivateKeyMemory? existing = null)
    {
        KeyId id = new($"urn:uuid:{Guid.NewGuid()}");
        PrivateKeyMemory key = existing
            ?? TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial().PrivateKey;
        KeyStore[id] = key;
        return id;
    }


    private static async Task<string> EncryptPayloadAsync(
        PublicKeyMemory encryptionPublicKey,
        byte[] payloadBytes,
        CancellationToken cancellationToken)
    {
        UnencryptedJwe unencrypted = UnencryptedJwe.ForEcdhEs(
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            payloadBytes.AsMemory());

        using JweMessage message = await unencrypted.EncryptAsync(
            encryptionPublicKey,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            Pool,
            cancellationToken).ConfigureAwait(false);

        return message.ToCompactJwe(TestSetup.Base64UrlEncoder);
    }


    private static bool IsAcceptState(FlowState state) => state is PresentationVerifiedState;


    private static string BuildEmptyJwksJson() =>
        /*lang=json,strict*/ "{\"keys\":[]}";


    private static PreparedDcqlQuery CreatePreparedQuery() =>
        DcqlFixtures.PidFamilyNamePrepared();


    /// <summary>
    /// The library's rule for the caller's own argument: the library writes a request object's <c>iat</c> and
    /// <c>exp</c> as whole-second NumericDates, so a request object lifetime under one second would make <c>exp</c>
    /// equal <c>iat</c>, and <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4">RFC 7519 Section
    /// 4.1.4</see> names <c>exp</c> the time "on or after which the JWT MUST NOT be accepted for processing".
    /// <see cref="HaipProfile.BuildJarAsync"/> and <see cref="HaipProfile.BuildUnsignedJarAsync"/> refuse a lifetime of
    /// 500 milliseconds with <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
    /// <param name="builder">The builder the row calls: <see cref="SignedBuilder"/> or <see cref="UnsignedBuilder"/>.</param>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    [DataRow(SignedBuilder)]
    [DataRow(UnsignedBuilder)]
    public async Task ARequestObjectBuilderRefusesASubSecondLifetimeAsync(string builder)
    {
        _ = await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(
            () => BuildRequestObjectWithAsync(builder, TimeSpan.FromMilliseconds(500))).ConfigureAwait(false);
    }


    /// <summary>
    /// The library's rule for the caller's own argument: the library writes a request object's <c>iat</c> and
    /// <c>exp</c> as whole-second NumericDates, so one second is the shortest lifetime a request object is issued with:
    /// <see cref="HaipProfile.BuildJarAsync"/> and <see cref="HaipProfile.BuildUnsignedJarAsync"/> stamp an <c>exp</c>
    /// one second after the <c>iat</c>.
    /// </summary>
    /// <param name="builder">The builder the row calls: <see cref="SignedBuilder"/> or <see cref="UnsignedBuilder"/>.</param>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    [DataRow(SignedBuilder)]
    [DataRow(UnsignedBuilder)]
    public async Task ARequestObjectBuilderStampsALifetimeOfOneSecondAsync(string builder)
    {
        string compactJar = await BuildRequestObjectWithAsync(builder, TimeSpan.FromSeconds(1)).ConfigureAwait(false);

        using JsonDocument payload = JwtPayloadReader.ParsePayloadJson(compactJar);
        Assert.AreEqual(
            1L,
            payload.RootElement.GetProperty(WellKnownJwtClaimNames.Exp).GetInt64()
                - payload.RootElement.GetProperty(WellKnownJwtClaimNames.Iat).GetInt64());
    }


    /// <summary>
    /// The library's rule for the caller's own argument: the library writes a request object's <c>iat</c> and
    /// <c>exp</c> as whole-second NumericDates, so it issues a request object for the whole seconds of its lifetime.
    /// <see cref="HaipProfile.BuildJarAsync"/> and <see cref="HaipProfile.BuildUnsignedJarAsync"/> under a lifetime of
    /// 90.7 seconds, the request object issued half a second past a whole second, stamp an <c>exp</c> 90 seconds after
    /// the <c>iat</c>.
    /// </summary>
    /// <param name="builder">The builder the row calls: <see cref="SignedBuilder"/> or <see cref="UnsignedBuilder"/>.</param>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    [DataRow(SignedBuilder)]
    [DataRow(UnsignedBuilder)]
    public async Task ARequestObjectBuilderStampsTheWholeSecondsOfAFractionalLifetimeAsync(string builder)
    {
        TimeProvider.Advance(TimeSpan.FromTicks(TimeSpan.TicksPerSecond / 2));

        string compactJar = await BuildRequestObjectWithAsync(builder, TimeSpan.FromTicks(907_000_000L)).ConfigureAwait(false);

        using JsonDocument payload = JwtPayloadReader.ParsePayloadJson(compactJar);
        Assert.AreEqual(
            90L,
            payload.RootElement.GetProperty(WellKnownJwtClaimNames.Exp).GetInt64()
                - payload.RootElement.GetProperty(WellKnownJwtClaimNames.Iat).GetInt64(),
            compactJar);
    }


    /// <summary>
    /// The row value naming <see cref="HaipProfile.BuildJarAsync"/>. A constant because <see cref="DataRowAttribute"/>
    /// takes compile-time constants only.
    /// </summary>
    private const string SignedBuilder = "signed";


    /// <summary>
    /// The row value naming <see cref="HaipProfile.BuildUnsignedJarAsync"/>. A constant because
    /// <see cref="DataRowAttribute"/> takes compile-time constants only.
    /// </summary>
    private const string UnsignedBuilder = "unsigned";


    /// <summary>
    /// Builds a request object for the verifier fixture with <paramref name="requestObjectLifetime"/> through the
    /// builder <paramref name="builder"/> names.
    /// </summary>
    /// <param name="builder"><see cref="SignedBuilder"/> or <see cref="UnsignedBuilder"/>.</param>
    /// <param name="requestObjectLifetime">The lifetime passed to the builder.</param>
    /// <returns>The compact request object.</returns>
    private Task<string> BuildRequestObjectWithAsync(string builder, TimeSpan requestObjectLifetime) => builder switch
    {
        SignedBuilder => BuildSignedRequestObjectAsync(requestObjectLifetime),
        UnsignedBuilder => BuildUnsignedRequestObjectAsync(requestObjectLifetime),
        _ => throw new ArgumentOutOfRangeException(nameof(builder), builder, "Unknown builder.")
    };


    /// <summary>
    /// Builds a signed request object for the verifier fixture with <paramref name="requestObjectLifetime"/> through
    /// <see cref="HaipProfile.BuildJarAsync"/>, signed with fresh P-256 material.
    /// </summary>
    /// <param name="requestObjectLifetime">The lifetime passed to the builder.</param>
    /// <returns>The compact request object.</returns>
    private async Task<string> BuildSignedRequestObjectAsync(TimeSpan requestObjectLifetime)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signingKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory signingPublicKey = signingKeys.PublicKey;
        using PrivateKeyMemory signingPrivateKey = signingKeys.PrivateKey;

        (_, string compactJar) = await HaipProfile.BuildJarAsync(
            now: TimeProvider.GetUtcNow(),
            requestObjectLifetime: requestObjectLifetime,
            state: "state-request-object-lifetime",
            nonce: new TransactionNonce("nonce-request-object-lifetime"),
            dcqlQuery: CreatePreparedQuery(),
            clientId: VerifierClientId,
            responseUri: new Uri(ResponseUriString),
            clientMetadata: HaipProfile.CreateVerifierClientMetadata(VerifierClientId, BuildEmptyJwksJson()),
            signingKey: signingPrivateKey,
            headerSerializer: HeaderSerializer,
            payloadSerializer: PayloadSerializer,
            dcqlQuerySerializer: q => JsonSerializer.Serialize(q, TestSetup.DefaultSerializationOptions),
            clientMetadataSerializer: m => JsonSerializer.Serialize(m, TestSetup.DefaultSerializationOptions),
            encoder: TestSetup.Base64UrlEncoder,
            pool: Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return compactJar;
    }


    /// <summary>
    /// Builds an unsigned request object for the verifier fixture with <paramref name="requestObjectLifetime"/> through
    /// <see cref="HaipProfile.BuildUnsignedJarAsync"/>.
    /// </summary>
    /// <param name="requestObjectLifetime">The lifetime passed to the builder.</param>
    /// <returns>The compact request object.</returns>
    private async Task<string> BuildUnsignedRequestObjectAsync(TimeSpan requestObjectLifetime)
    {
        return await HaipProfile.BuildUnsignedJarAsync(
            now: TimeProvider.GetUtcNow(),
            requestObjectLifetime: requestObjectLifetime,
            state: "state-request-object-lifetime",
            nonce: new TransactionNonce("nonce-request-object-lifetime"),
            dcqlQuery: CreatePreparedQuery(),
            clientId: VerifierClientId,
            responseUri: new Uri(ResponseUriString),
            clientMetadata: HaipProfile.CreateVerifierClientMetadata(VerifierClientId, BuildEmptyJwksJson()),
            headerSerializer: HeaderSerializer,
            payloadSerializer: PayloadSerializer,
            dcqlQuerySerializer: q => JsonSerializer.Serialize(q, TestSetup.DefaultSerializationOptions),
            clientMetadataSerializer: m => JsonSerializer.Serialize(m, TestSetup.DefaultSerializationOptions),
            encoder: TestSetup.Base64UrlEncoder,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }
}
