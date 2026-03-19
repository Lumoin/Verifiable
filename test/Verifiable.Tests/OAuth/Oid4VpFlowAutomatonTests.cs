using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Text;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Core.Automata;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Oid4Vp;
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

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer PayloadSerializer =
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
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda = CreatePda();

        bool stepped = await pda.StepAsync(
            CreateInitiate("flow-1"),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(stepped, "Initiate must produce a transition.");
        Assert.IsInstanceOfType<PkceGeneratedState>(pda.CurrentState);
        Assert.AreEqual("flow-1", pda.CurrentState.FlowId);
        Assert.AreEqual("https://as.example.com", pda.CurrentState.ExpectedIssuer);
    }


    [TestMethod]
    public async Task ParBodyComposedTransitionsFromPkceGeneratedToParRequestReady()
    {
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda = CreatePda();
        await pda.StepAsync(
            CreateInitiate("flow-2"), TestContext.CancellationToken).ConfigureAwait(false);

        bool stepped = await pda.StepAsync(
            new ParBodyComposed("client_id=test&code_challenge=abc", TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(stepped);
        Assert.IsInstanceOfType<ParRequestReadyState>(pda.CurrentState);
    }


    [TestMethod]
    public async Task ParSucceededTransitionsToParCompletedWithCorrectExpiry()
    {
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda = CreatePda();
        await pda.StepAsync(
            CreateInitiate("flow-3"), TestContext.CancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
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
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda = CreatePda();
        await pda.StepAsync(
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
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda = CreatePda();
        await pda.StepAsync(
            CreateInitiate("flow-5"), TestContext.CancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
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
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda = CreatePda();
        await pda.StepAsync(
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
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda = CreatePda();
        string pdaRunId = pda.RunId;
        var observer = new TestObserver<TraceEntry<OAuthFlowState, OAuthFlowInput>>();
        using IDisposable subscription = pda.Subscribe(observer);

        await pda.StepAsync(
            CreateInitiate("flow-7"), TestContext.CancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new ParBodyComposed("body", TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        KeyId keyId = StoreDecryptionKey();
        await pda.StepAsync(
            new ParSucceeded(
                new ParResponse(new Uri("urn:ietf:params:oauth:request_uri:test"), 60),
                new TransactionNonce("nonce"),
                CreatePreparedQuery(),
                keyId,
                TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(3, observer.Received,
            "Three transitions must produce exactly three trace entries.");

        foreach(TraceEntry<OAuthFlowState, OAuthFlowInput> entry in observer.Received)
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
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda = CreatePda();
        await pda.StepAsync(
            CreateInitiate("flow-8"), TestContext.CancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new ParBodyComposed("body", TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, pda.StackDepth,
            "Stack must contain only the sentinel on the linear path.");
    }


    [TestMethod]
    public async Task StepCountMatchesNumberOfSuccessfulTransitions()
    {
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda = CreatePda();
        await pda.StepAsync(
            CreateInitiate("flow-9"), TestContext.CancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new ParBodyComposed("body", TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(2, pda.StepCount);
    }


    [TestMethod]
    public async Task AcceptPredicateReturnsTrueOnlyForPresentationVerified()
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
                Claims = new Dictionary<string, IReadOnlyDictionary<string, string>>()
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
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda = CreatePda();
        await RunToParCompleted(pda, "flow-11", TestContext.CancellationToken).ConfigureAwait(false);

        await RunToJarReadyFromParCompleted(pda, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<JarReadyState>(pda.CurrentState);
    }


    [TestMethod]
    public async Task JarFetchedTransitionsJarReadyToJarServed()
    {
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda = CreatePda();
        await RunToJarReady(pda, "flow-12", TestContext.CancellationToken).ConfigureAwait(false);

        bool stepped = await pda.StepAsync(
            new JarFetched(TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(stepped, "JarFetched must transition JarReady to JarServed.");
        Assert.IsInstanceOfType<JarServedState>(pda.CurrentState);
    }


    [TestMethod]
    public async Task FullFlowStepCountMatchesAllTransitions()
    {
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda = CreatePda();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> exchangeKeys =
            TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory encryptionPublicKey = exchangeKeys.PublicKey;
        KeyId keyId = StoreDecryptionKey(exchangeKeys.PrivateKey);

        await RunToParCompletedWithKey(
            pda, "flow-16", keyId, TestContext.CancellationToken).ConfigureAwait(false);
        await RunToJarReadyFromParCompleted(pda, TestContext.CancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new JarFetched(TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        //Encrypt a minimal payload to the verifier's public key so ResponsePosted can be stepped.
        byte[] minimalPayload = Encoding.UTF8.GetBytes(/*lang=json,strict*/ "{\"vp_token\":\"test\"}");
        string compactJwe = await EncryptPayloadAsync(
            encryptionPublicKey, minimalPayload, TestContext.CancellationToken).ConfigureAwait(false);

        await pda.StepAsync(
            new ResponsePosted(compactJwe, TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        await pda.StepAsync(
            new VerificationSucceeded(
                new Dictionary<string, IReadOnlyDictionary<string, string>>(),
                TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        //Initiate, ParBodyComposed, ParSucceeded, JarSigned, JarFetched,
        //ResponsePosted, VerificationSucceeded = 7 transitions.
        Assert.AreEqual(7, pda.StepCount,
            "Full PAR+JAR+direct_post.jwt flow must produce exactly seven transitions.");
    }


    private PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> CreatePda() =>
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
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda,
        string flowId,
        CancellationToken cancellationToken)
    {
        KeyId keyId = StoreDecryptionKey();
        await RunToParCompletedWithKey(pda, flowId, keyId, cancellationToken)
            .ConfigureAwait(false);
    }


    private async System.Threading.Tasks.ValueTask RunToParCompletedWithKey(
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda,
        string flowId,
        KeyId keyId,
        CancellationToken cancellationToken)
    {
        await pda.StepAsync(CreateInitiate(flowId), cancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new ParBodyComposed("client_id=test", TimeProvider.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new ParSucceeded(
                new ParResponse(new Uri("urn:ietf:params:oauth:request_uri:test"), 60),
                new TransactionNonce("nonce-abc"),
                CreatePreparedQuery(),
                keyId,
                TimeProvider.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);
    }


    private async System.Threading.Tasks.ValueTask RunToJarReady(
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda,
        string flowId,
        CancellationToken cancellationToken)
    {
        await RunToParCompleted(pda, flowId, cancellationToken).ConfigureAwait(false);
        await RunToJarReadyFromParCompleted(pda, cancellationToken).ConfigureAwait(false);
    }


    private static async System.Threading.Tasks.ValueTask RunToJarReadyFromParCompleted(
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda,
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

        (JarSigned input, _) = await HaipProfile.BuildJarAsync(
            state: state,
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

        await pda.StepAsync(input, cancellationToken).ConfigureAwait(false);
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


    private static bool IsAcceptState(OAuthFlowState state) => state is PresentationVerifiedState;


    private static string BuildEmptyJwksJson() =>
        /*lang=json,strict*/ "{\"keys\":[]}";


    private static PreparedDcqlQuery CreatePreparedQuery() =>
        DcqlPreparer.Prepare(new DcqlQuery
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
