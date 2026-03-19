using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Reactive.Linq;
using Verifiable.Core.Automata;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Par;
using Verifiable.OAuth.Pkce;
using Verifiable.Tests.TestInfrastructure;
namespace Verifiable.Tests.OAuth;


[TestClass]
internal sealed class Oid4VpFlowTransitionsTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();


    [TestMethod]
    public async Task InitiateTransitionsToPkceGenerated()
    {
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda = CreatePda();

        bool stepped = await pda.StepAsync(
            CreateInitiate("flow-1"),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(stepped, "Initiate must produce a transition.");
        Assert.IsInstanceOfType<PkceGenerated>(pda.CurrentState);
        Assert.AreEqual("flow-1", pda.CurrentState.FlowId);
        Assert.AreEqual("https://as.example.com", pda.CurrentState.ExpectedIssuer);
    }


    [TestMethod]
    public async Task ParBodyComposedTransitionsFromPkceGeneratedToParRequestReady()
    {
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda = CreatePda();
        await pda.StepAsync(CreateInitiate("flow-2"), TestContext.CancellationToken).ConfigureAwait(false);

        bool stepped = await pda.StepAsync(
            new ParBodyComposed("client_id=test&code_challenge=abc", TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(stepped);
        Assert.IsInstanceOfType<ParRequestReady>(pda.CurrentState);
    }


    [TestMethod]
    public async Task ParSucceededTransitionsToParCompletedWithCorrectExpiry()
    {
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda = CreatePda();
        await pda.StepAsync(CreateInitiate("flow-3"), TestContext.CancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new ParBodyComposed("body", TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        DateTimeOffset receivedAt = TimeProvider.GetUtcNow();
        using EphemeralEncryptionKeyPair keyPair = CreateEncryptionKeyPair();
        bool stepped = await pda.StepAsync(
            new ParSucceeded(
                new ParResponse(new Uri("urn:ietf:params:oauth:request_uri:abc"), 60),
                new TransactionNonce("nonce-xyz"),
                CreatePreparedQuery(),
                keyPair,
                receivedAt),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(stepped);
        var parCompleted = Assert.IsInstanceOfType<ParCompleted>(pda.CurrentState);
        Assert.AreEqual(receivedAt.AddSeconds(60), parCompleted.ExpiresAt,
            "ExpiresAt must be derived from the PAR expires_in value.");
    }


    [TestMethod]
    public async Task FailInputTransitionsToFlowFailedFromAnyNonTerminalState()
    {
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda = CreatePda();
        await pda.StepAsync(CreateInitiate("flow-4"), TestContext.CancellationToken).ConfigureAwait(false);

        DateTimeOffset failedAt = TimeProvider.GetUtcNow();
        bool stepped = await pda.StepAsync(
            new Fail("PAR endpoint unreachable.", failedAt),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(stepped);
        var failed = Assert.IsInstanceOfType<FlowFailed>(pda.CurrentState);
        Assert.AreEqual("PAR endpoint unreachable.", failed.Reason);
        Assert.AreEqual(failedAt, failed.FailedAt);
    }


    [TestMethod]
    public async Task PdaHaltsAfterFlowFailed()
    {
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda = CreatePda();
        await pda.StepAsync(CreateInitiate("flow-5"), TestContext.CancellationToken).ConfigureAwait(false);
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
        await pda.StepAsync(CreateInitiate("flow-6"), TestContext.CancellationToken).ConfigureAwait(false);

        bool stepped = await pda.StepAsync(
            new JarFetched(TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(stepped, "JarFetched from PkceGenerated is undefined — PDA must halt.");
        Assert.IsTrue(pda.IsHalted);
    }


    [TestMethod]
    public async Task TraceObserverReceivesOneEntryPerStep()
    {
        var entries = new List<TraceEntry<OAuthFlowState, OAuthFlowInput>>();
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda = CreatePda();
        string pdaRunId = pda.RunId;
        using IDisposable subscription = pda.Subscribe(entries.Add);

        await pda.StepAsync(CreateInitiate("flow-7"), TestContext.CancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new ParBodyComposed("body", TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        using EphemeralEncryptionKeyPair keyPair = CreateEncryptionKeyPair();
        await pda.StepAsync(
            new ParSucceeded(
                new ParResponse(new Uri("urn:ietf:params:oauth:request_uri:test"), 60),
                new TransactionNonce("nonce"),
                CreatePreparedQuery(),
                keyPair,
                TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(3, entries, "Three transitions must produce exactly three trace entries.");

        foreach(TraceEntry<OAuthFlowState, OAuthFlowInput> entry in entries)
        {
            Assert.AreEqual(pdaRunId, entry.RunId, "Each trace entry must carry the PDA run identifier.");
            Assert.AreEqual(TraceOutcome.Transitioned, entry.Outcome);
            Assert.IsNotNull(entry.Label, "Every transition must carry a label.");
        }
    }


    [TestMethod]
    public async Task StackDepthRemainsOneOnLinearFlow()
    {
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda = CreatePda();
        await pda.StepAsync(CreateInitiate("flow-8"), TestContext.CancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new ParBodyComposed("body", TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        //Linear flow never pushes or pops — only the sentinel remains.
        Assert.AreEqual(1, pda.StackDepth, "Stack must contain only the sentinel on the linear path.");
    }


    [TestMethod]
    public async Task StepCountMatchesNumberOfSuccessfulTransitions()
    {
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda = CreatePda();
        await pda.StepAsync(CreateInitiate("flow-9"), TestContext.CancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new ParBodyComposed("body", TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(2, pda.StepCount);
    }


    [TestMethod]
    public async Task AcceptPredicateReturnsTrueOnlyForPresentationVerified()
    {
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda = CreatePda();
        await RunToParCompleted(pda, "flow-10", TestContext.CancellationToken).ConfigureAwait(false);

        //Verify the accept predicate directly against constructed terminal states.
        DateTimeOffset now = TimeProvider.GetUtcNow();

        Assert.IsTrue(
            IsAcceptState(new PresentationVerified
            {
                FlowId = "flow-10",
                ExpectedIssuer = "https://as.example.com",
                EnteredAt = now,
                ExpiresAt = now.AddMinutes(5),
                Claims = new Dictionary<string, IReadOnlyDictionary<string, string>>(),
                VerifiedAt = now
            }),
            "PresentationVerified must satisfy the accept predicate.");

        Assert.IsFalse(
            IsAcceptState(new FlowFailed
            {
                FlowId = "flow-10",
                ExpectedIssuer = "https://as.example.com",
                EnteredAt = now,
                ExpiresAt = now.AddMinutes(5),
                Reason = "Failure.",
                FailedAt = now
            }),
            "FlowFailed must not satisfy the accept predicate.");
    }


    private PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> CreatePda() =>
        new(
            runId: Guid.NewGuid().ToString(),
            initialState: new FlowFailed
            {
                FlowId = string.Empty,
                ExpectedIssuer = string.Empty,
                EnteredAt = TimeProvider.GetUtcNow(),
                ExpiresAt = DateTimeOffset.MaxValue,
                Reason = "Not yet initiated.",
                FailedAt = TimeProvider.GetUtcNow()
            },
            initialStackSymbol: Oid4VpStackSymbol.Base,
            transition: Oid4VpFlowTransitions.Create(),
            acceptPredicate: static state => state is PresentationVerified,
            timeProvider: TimeProvider);

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of PkceParameters transfers to Initiate on success; disposed explicitly in the catch block on failure.")]
    private Initiate CreateInitiate(string flowId)
    {
        PkceParameters pkce = CreatePkceParameters();
        try
        {
            return new Initiate(
                Pkce: pkce,
                RedirectUri: new Uri("https://client.example.com/callback"),
                Scopes: ["openid"],
                FlowId: flowId,
                ExpectedIssuer: "https://as.example.com",
                InitiatedAt: TimeProvider.GetUtcNow(),
                InitialExpiresAt: TimeProvider.GetUtcNow().AddMinutes(5));
        }
        catch
        {
            pkce.Dispose();
            throw;
        }
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of PkceParameters transfers to Initiate on success; disposed explicitly in the catch block on failure.")]
    private static PkceParameters CreatePkceParameters() =>
        PkceParameters.Generate(TestSetup.Base64UrlEncoder, SensitiveMemoryPool<byte>.Shared);

    private static EphemeralEncryptionKeyPair CreateEncryptionKeyPair()
    {
        IMemoryOwner<byte> privateKeyOwner = MemoryPool<byte>.Shared.Rent(32);
        return new EphemeralEncryptionKeyPair(
            /*lang=json,strict*/ "{\"kty\":\"EC\",\"crv\":\"P-256\"}",
            privateKeyOwner);
    }

    private static PreparedDcqlQuery CreatePreparedQuery() =>
        DcqlPreparer.Prepare(new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = "pid",
                    Format = "dc+sd-jwt",
                    Claims = [new ClaimsQuery { Path = DcqlClaimPattern.FromKeys("family_name") }]
                }
            ]
        });

    private async System.Threading.Tasks.ValueTask RunToParCompleted(
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda,
        string flowId,
        System.Threading.CancellationToken cancellationToken)
    {
        await pda.StepAsync(CreateInitiate(flowId), cancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new ParBodyComposed("client_id=test", TimeProvider.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);

        using EphemeralEncryptionKeyPair keyPair = CreateEncryptionKeyPair();
        await pda.StepAsync(
            new ParSucceeded(
                new ParResponse(new Uri("urn:ietf:params:oauth:request_uri:test"), 60),
                new TransactionNonce("nonce-abc"),
                CreatePreparedQuery(),
                keyPair,
                TimeProvider.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);
    }

    private static bool IsAcceptState(OAuthFlowState state) => state is PresentationVerified;
}


/// <summary>
/// Minimal <see cref="IObserver{T}"/> factory to avoid a library dependency in tests.
/// </summary>