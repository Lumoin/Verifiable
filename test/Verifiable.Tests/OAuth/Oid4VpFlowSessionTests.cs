using Microsoft.Extensions.Time.Testing;
using System.Buffers;
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
using Verifiable.OAuth.Oid4Vp.Session;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;


/// <summary>
/// Tests for <see cref="Oid4VpFlowSession"/> modelling each step as a separate
/// controller action that loads a (state, stepCount) snapshot, steps once, and
/// persists the result.
/// </summary>
/// <remarks>
/// <para>
/// The <c>state</c> and <c>stepCount</c> variables play the role of durable storage.
/// The <see cref="KeyStore"/> dictionary plays the role of the application's secret
/// store — key material is placed there before being referenced by a
/// <see cref="KeyId"/>, and retrieved through a resolver delegate at the step that
/// needs it. This is the pattern an ASP.NET application would follow with a real KMS
/// or database-backed secret store.
/// </para>
/// </remarks>
[TestClass]
internal sealed class Oid4VpFlowSessionTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    /// <summary>
    /// In-memory secret store keyed by <see cref="KeyId"/>. Each test instance has its
    /// own store so tests are isolated.
    /// </summary>
    private Dictionary<KeyId, PrivateKeyMemory> KeyStore { get; } = [];


    /// <summary>
    /// The PAR controller drives Initiate → PkceGenerated → ParRequestReady →
    /// ParCompleted in three sequential steps. The key is stored before the step and
    /// identified by a UUID. No key material touches the state records.
    /// </summary>
    [TestMethod]
    public async Task ParControllerStepsToParCompleted()
    {
        OAuthFlowState state = CreateUninitializedState();
        int stepCount = 0;

        //Step 1 — Initiate.
        (state, stepCount) = await StepAsync(
            state, stepCount, CreateInitiate("session-par-1")).ConfigureAwait(false);

        Assert.IsInstanceOfType<PkceGeneratedState>(state);

        //Step 2 — PAR body composed.
        (state, stepCount) = await StepAsync(
            state, stepCount,
            new ParBodyComposed("client_id=test", TimeProvider.GetUtcNow())).ConfigureAwait(false);

        Assert.IsInstanceOfType<ParRequestReadyState>(state);

        //Step 3 — PAR succeeded. Store the key before referencing it by ID.
        KeyId keyId = StoreDecryptionKey();
        DateTimeOffset parReceivedAt = TimeProvider.GetUtcNow();

        Oid4VpStepResult result = await Oid4VpFlowSession.StepAsync(
            state, stepCount,
            new ParSucceeded(
                new ParResponse(new Uri("urn:ietf:params:oauth:request_uri:session-par-1"), 90),
                new TransactionNonce("nonce-session-par-1"),
                CreatePreparedQuery(),
                keyId,
                parReceivedAt),
            resolveDecryptionKey: null,
            TimeProvider,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(Oid4VpStepOutcome.Transitioned, result.Outcome);
        Assert.AreEqual(3, result.StepCount,
            "Three transitions to ParCompleted must yield StepCount=3.");
        Verifiable.OAuth.Oid4Vp.States.ParCompletedState parCompleted =
            Assert.IsInstanceOfType<Verifiable.OAuth.Oid4Vp.States.ParCompletedState>(result.State);
        Assert.AreEqual(keyId, parCompleted.DecryptionKeyId,
            "DecryptionKeyId must be carried forward into the state unchanged.");
        Assert.AreEqual(parReceivedAt.AddSeconds(90), parCompleted.ExpiresAt,
            "ExpiresAt must be derived from the PAR expires_in value.");
    }


    /// <summary>
    /// The full flow reaches PresentationVerified. The resolver delegate is supplied
    /// only at the step that needs key material. At no other step does the library
    /// touch or hold key material.
    /// </summary>
    [TestMethod]
    public async Task ResponseEndpointStepsToAcceptedState()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> exchangeKeys =
            TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory encryptionPublicKey = exchangeKeys.PublicKey;

        //Store the private key in the key store and record its ID.
        KeyId keyId = StoreDecryptionKey(exchangeKeys.PrivateKey);

        (OAuthFlowState state, int stepCount) = await DriveToParCompleted(
            "session-response-1", keyId).ConfigureAwait(false);

        using SignedJar jar = await CreateMinimalSignedJarAsync(
            state.FlowId, TestContext.CancellationToken).ConfigureAwait(false);
        (state, stepCount) = await StepAsync(state, stepCount, new JarSigned(jar)).ConfigureAwait(false);
        (state, stepCount) = await StepAsync(
            state, stepCount, new JarFetched(TimeProvider.GetUtcNow())).ConfigureAwait(false);

        string compactJwe = await EncryptMinimalPayloadAsync(
            encryptionPublicKey, TestContext.CancellationToken).ConfigureAwait(false);

        (state, stepCount) = await StepAsync(
            state, stepCount, new ResponsePosted(compactJwe, TimeProvider.GetUtcNow())).ConfigureAwait(false);

        Assert.IsInstanceOfType<ResponseReceivedState>(state);
        ResponseReceivedState received = (ResponseReceivedState)state;
        Assert.AreEqual(keyId, received.DecryptionKeyId,
            "DecryptionKeyId must be present in ResponseReceived.");

        //VerificationSucceeded step — the resolver is supplied here and only here.
        Oid4VpStepResult result = await Oid4VpFlowSession.StepAsync(
            state, stepCount,
            new VerificationSucceeded(
                new Dictionary<string, IReadOnlyDictionary<string, string>>
                {
                    ["pid"] = new Dictionary<string, string>
                    {
                        ["family_name"] = "Mustermann",
                        ["given_name"] = "Erika"
                    }
                },
                TimeProvider.GetUtcNow()),
            resolveDecryptionKey: ResolveKeyAsync,
            TimeProvider,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(Oid4VpStepOutcome.Transitioned, result.Outcome);
        Assert.IsTrue(result.Accepted, "Flow must be accepted after VerificationSucceeded.");
        PresentationVerifiedState verified =
            Assert.IsInstanceOfType<PresentationVerifiedState>(result.State);
        Assert.IsTrue(verified.Claims.ContainsKey("pid"),
            "Verified claims must carry the pid credential.");
    }


    /// <summary>
    /// An undefined input returns Outcome=Halted. State and StepCount are unchanged.
    /// TraceEntry carries the Halted outcome and a non-empty run identifier.
    /// </summary>
    [TestMethod]
    public async Task UndefinedInputReturnsHaltedWithUnchangedStateAndStepCount()
    {
        KeyId keyId = StoreDecryptionKey();
        (OAuthFlowState state, int stepCount) = await DriveToParCompleted(
            "session-halt-1", keyId).ConfigureAwait(false);

        Oid4VpStepResult result = await Oid4VpFlowSession.StepAsync(
            state, stepCount,
            new JarFetched(TimeProvider.GetUtcNow()),
            resolveDecryptionKey: null,
            TimeProvider,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(Oid4VpStepOutcome.Halted, result.Outcome);
        Assert.AreSame(state, result.State,
            "State must be the same instance when halted.");
        Assert.AreEqual(stepCount, result.StepCount,
            "StepCount must be unchanged when halted.");
        Assert.AreEqual(TraceOutcome.Halted, result.TraceEntry.Outcome);
        Assert.IsFalse(string.IsNullOrWhiteSpace(result.TraceEntry.RunId),
            "TraceEntry must carry a non-empty run identifier.");
    }


    /// <summary>
    /// A Fail input transitions to FlowFailed. A subsequent step on FlowFailed halts.
    /// StepCount increments after the Fail transition and is unchanged after the halt.
    /// </summary>
    [TestMethod]
    public async Task FailInputTransitionsToFlowFailedAndSubsequentStepHalts()
    {
        KeyId keyId = StoreDecryptionKey();
        (OAuthFlowState state, int stepCount) = await DriveToParCompleted(
            "session-fail-1", keyId).ConfigureAwait(false);

        Oid4VpStepResult failed = await Oid4VpFlowSession.StepAsync(
            state, stepCount,
            new Fail("PAR expired before JAR could be signed.", TimeProvider.GetUtcNow()),
            resolveDecryptionKey: null,
            TimeProvider,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(Oid4VpStepOutcome.Transitioned, failed.Outcome);
        FlowFailed flowFailed = Assert.IsInstanceOfType<FlowFailed>(failed.State);
        Assert.AreEqual("PAR expired before JAR could be signed.", flowFailed.Reason);
        Assert.AreEqual(stepCount + 1, failed.StepCount);
        Assert.AreEqual(TraceOutcome.Transitioned, failed.TraceEntry.Outcome);

        Oid4VpStepResult afterFail = await Oid4VpFlowSession.StepAsync(
            failed.State, failed.StepCount,
            new JarFetched(TimeProvider.GetUtcNow()),
            resolveDecryptionKey: null,
            TimeProvider,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(Oid4VpStepOutcome.Halted, afterFail.Outcome);
        Assert.AreEqual(failed.StepCount, afterFail.StepCount,
            "StepCount must be unchanged when halted from FlowFailed.");
    }


    /// <summary>
    /// StepCount in the result reflects the snapshot position. Rehydrating at step N
    /// and stepping once produces StepCount=N+1. TraceEntry.Step equals the snapshot
    /// StepCount before the step.
    /// </summary>
    [TestMethod]
    public async Task StepCountReflectsSnapshotPosition()
    {
        KeyId keyId = StoreDecryptionKey();
        (OAuthFlowState parState, int parStepCount) = await DriveToParCompleted(
            "session-stepcount-1", keyId).ConfigureAwait(false);

        Assert.AreEqual(3, parStepCount,
            "Three transitions to ParCompleted must yield StepCount=3.");

        using SignedJar jar = await CreateMinimalSignedJarAsync(
            parState.FlowId, TestContext.CancellationToken).ConfigureAwait(false);

        Oid4VpStepResult result = await Oid4VpFlowSession.StepAsync(
            parState, parStepCount,
            new JarSigned(jar),
            resolveDecryptionKey: null,
            TimeProvider,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(4, result.StepCount,
            "One more transition from step 3 must yield StepCount=4.");
        Assert.AreEqual(parStepCount, result.TraceEntry.Step,
            "TraceEntry.Step must equal the snapshot StepCount before the step.");
    }


    private async ValueTask<(OAuthFlowState, int)> DriveToParCompleted(
        string flowId,
        KeyId keyId)
    {
        OAuthFlowState state = CreateUninitializedState();
        int stepCount = 0;

        (state, stepCount) = await StepAsync(state, stepCount, CreateInitiate(flowId)).ConfigureAwait(false);
        (state, stepCount) = await StepAsync(
            state, stepCount,
            new ParBodyComposed("client_id=test", TimeProvider.GetUtcNow())).ConfigureAwait(false);
        (state, stepCount) = await StepAsync(
            state, stepCount,
            new ParSucceeded(
                new ParResponse(new Uri($"urn:ietf:params:oauth:request_uri:{flowId}"), 60),
                new TransactionNonce($"nonce-{flowId}"),
                CreatePreparedQuery(),
                keyId,
                TimeProvider.GetUtcNow())).ConfigureAwait(false);

        return (state, stepCount);
    }


    private async ValueTask<(OAuthFlowState, int)> StepAsync(
        OAuthFlowState state,
        int stepCount,
        OAuthFlowInput input)
    {
        Oid4VpStepResult result = await Oid4VpFlowSession.StepAsync(
            state, stepCount, input,
            resolveDecryptionKey: null,
            TimeProvider,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(Oid4VpStepOutcome.Transitioned, result.Outcome,
            $"Expected Transitioned for {input.GetType().Name} but got {result.Outcome}.");

        return (result.State, result.StepCount);
    }


    private KeyId StoreDecryptionKey(PrivateKeyMemory? existing = null)
    {
        KeyId id = new($"urn:uuid:{Guid.NewGuid()}");
        PrivateKeyMemory key = existing
            ?? TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial().PrivateKey;
        KeyStore[id] = key;
        return id;
    }


    private ValueTask<PrivateKeyMemory> ResolveKeyAsync(
        KeyId keyId,
        CancellationToken cancellationToken)
    {
        if(!KeyStore.TryGetValue(keyId, out PrivateKeyMemory? key))
        {
            throw new KeyNotFoundException(
                $"No key found for identifier '{keyId}'. " +
                $"Ensure the key was stored before the flow was initiated.");
        }

        return ValueTask.FromResult(key);
    }


    private FlowFailed CreateUninitializedState()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        return new FlowFailed
        {
            FlowId = string.Empty,
            ExpectedIssuer = string.Empty,
            EnteredAt = now,
            ExpiresAt = DateTimeOffset.MaxValue,
            Kind = FlowKind.Oid4VpVerifier,
            Reason = "Flow not yet initiated.",
            FailedAt = now
        };
    }


    private Initiate CreateInitiate(string flowId) =>
        new(
            Pkce: PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool),
            RedirectUri: new Uri("https://client.example.com/callback"),
            Scopes: ["openid"],
            FlowId: flowId,
            ExpectedIssuer: "https://as.example.com",
            InitiatedAt: TimeProvider.GetUtcNow(),
            InitialExpiresAt: TimeProvider.GetUtcNow().AddMinutes(5));


    private static async Task<SignedJar> CreateMinimalSignedJarAsync(
        string flowId,
        CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signingKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory signingPublicKey = signingKeys.PublicKey;
        using PrivateKeyMemory signingPrivateKey = signingKeys.PrivateKey;

        JwtHeaderSerializer headerSerializer =
            static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)header,
                TestSetup.DefaultSerializationOptions);

        JwtPayloadSerializer payloadSerializer =
            static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)payload,
                TestSetup.DefaultSerializationOptions);

        var header = new JwtHeader
        {
            [WellKnownJwkValues.Alg] = WellKnownJwaValues.Es256,
            [WellKnownJwkValues.Typ] = WellKnownMediaTypes.Jwt.OauthAuthzReqJwt
        };

        var payload = new JwtPayload
        {
            [WellKnownJwtClaims.Nonce] = "nonce-abc",
            [OAuthRequestParameters.ResponseType] = AuthorizationRequestParameters.ResponseTypeVpToken,
            [OAuthRequestParameters.ResponseMode] = WellKnownResponseModes.DirectPostJwt,
            [WellKnownJwtClaims.ClientId] = "https://verifier.example.com",
            [OAuthRequestParameters.State] = flowId
        };

        UnsignedJwt unsignedJar = new(header, payload);
        JwsMessage signed = await unsignedJar.SignAsync(
            signingPrivateKey,
            headerSerializer,
            payloadSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            cancellationToken).ConfigureAwait(false);

        return new SignedJar(signed);
    }


    private static async Task<string> EncryptMinimalPayloadAsync(
        PublicKeyMemory encryptionPublicKey,
        CancellationToken cancellationToken)
    {
        JwtHeaderSerializer headerSerializer =
            static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)header,
                TestSetup.DefaultSerializationOptions);

        byte[] payload = System.Text.Encoding.UTF8.GetBytes(
            /*lang=json,strict*/ "{\"vp_token\":\"test\"}");

        UnencryptedJwe unencrypted = UnencryptedJwe.ForEcdhEs(
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            payload.AsMemory());

        using JweMessage message = await unencrypted.EncryptAsync(
            encryptionPublicKey,
            headerSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            Pool,
            cancellationToken).ConfigureAwait(false);

        return message.ToCompactJwe(TestSetup.Base64UrlEncoder);
    }


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
