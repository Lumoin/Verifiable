using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Automata;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Pkce;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;


[TestClass]
internal sealed class AuthCodeFlowTransitionsTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();


    [TestMethod]
    public async Task InitiateTransitionsToPkceGenerated()
    {
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, AuthCodeStackSymbol> pda = CreatePda();

        bool stepped = await pda.StepAsync(
            CreateInitiate("flow-1"),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(stepped, "Initiate must produce a transition.");
        Assert.IsInstanceOfType<PkceGeneratedState>(pda.CurrentState);
        Assert.AreEqual("flow-1", pda.CurrentState.FlowId);
        Assert.AreEqual("https://as.example.com", pda.CurrentState.ExpectedIssuer);
    }


    [TestMethod]
    public async Task ParBodyComposedTransitionsToParRequestReady()
    {
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, AuthCodeStackSymbol> pda = CreatePda();
        await pda.StepAsync(CreateInitiate("flow-2"), TestContext.CancellationToken).ConfigureAwait(false);

        bool stepped = await pda.StepAsync(
            new ParBodyComposed("client_id=test&code_challenge=abc", TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(stepped);
        Assert.IsInstanceOfType<ParRequestReadyState>(pda.CurrentState);
    }


    [TestMethod]
    public async Task ParSucceededTransitionsToParCompletedWithCorrectExpiry()
    {
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, AuthCodeStackSymbol> pda = CreatePda();
        await pda.StepAsync(CreateInitiate("flow-3"), TestContext.CancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new ParBodyComposed("body", TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        DateTimeOffset receivedAt = TimeProvider.GetUtcNow();
        bool stepped = await pda.StepAsync(
            new ParSucceeded(
                new ParResponse(new Uri("urn:ietf:params:oauth:request_uri:abc"), 90),
                receivedAt),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(stepped);
        var parCompleted = Assert.IsInstanceOfType<ParCompletedState>(pda.CurrentState);
        Assert.AreEqual(receivedAt.AddSeconds(90), parCompleted.ExpiresAt,
            "ExpiresAt must be derived from the PAR expires_in value.");
    }


    [TestMethod]
    public async Task CodeReceivedTransitionsToAuthorizationCodeReceived()
    {
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, AuthCodeStackSymbol> pda = CreatePda();
        await RunToParCompleted(pda, "flow-4", TestContext.CancellationToken).ConfigureAwait(false);

        bool stepped = await pda.StepAsync(
            new CodeReceived(
                Code: "auth-code-xyz",
                State: "state-abc",
                IssuerId: "https://as.example.com",
                ReceivedAt: TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(stepped);
        var codeState = Assert.IsInstanceOfType<AuthorizationCodeReceivedState>(pda.CurrentState);
        Assert.AreEqual("auth-code-xyz", codeState.Code);
        Assert.AreEqual("https://as.example.com", codeState.IssuerId);
    }


    [TestMethod]
    public async Task TokenExchangeSucceededTransitionsToTokenReceived()
    {
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, AuthCodeStackSymbol> pda = CreatePda();
        await RunToParCompleted(pda, "flow-5", TestContext.CancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new CodeReceived("code", "state", "https://as.example.com", TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        bool stepped = await pda.StepAsync(
            new TokenExchangeSucceeded(
                AccessToken: "at.opaque.abc",
                TokenType: "Bearer",
                ExpiresIn: 3600,
                RefreshToken: null,
                Scope: null,
                ReceivedAt: TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(stepped);
        var tokenState = Assert.IsInstanceOfType<TokenReceivedState>(pda.CurrentState);
        Assert.AreEqual("at.opaque.abc", tokenState.AccessToken);
        Assert.AreEqual("Bearer", tokenState.TokenType);
        Assert.AreEqual(3600, tokenState.ExpiresIn);
    }


    [TestMethod]
    public async Task FullHappyPathReachesTokenReceived()
    {
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, AuthCodeStackSymbol> pda = CreatePda();

        await pda.StepAsync(CreateInitiate("flow-6"), TestContext.CancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new ParBodyComposed("client_id=test", TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new ParSucceeded(
                new ParResponse(new Uri("urn:ietf:params:oauth:request_uri:test"), 60),
                TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new CodeReceived("code", "state", "https://as.example.com", TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new TokenExchangeSucceeded("at.abc", "Bearer", 3600, null, null, TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<TokenReceivedState>(pda.CurrentState);
        Assert.IsTrue(pda.IsAccepted, "TokenReceived is an accept state.");
        Assert.AreEqual(5, pda.StepCount, "Happy path must traverse exactly five transitions.");
    }


    [TestMethod]
    public async Task FailInputTransitionsToFlowFailedFromAnyNonTerminalState()
    {
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, AuthCodeStackSymbol> pda = CreatePda();
        await pda.StepAsync(CreateInitiate("flow-7"), TestContext.CancellationToken).ConfigureAwait(false);

        DateTimeOffset failedAt = TimeProvider.GetUtcNow();
        bool stepped = await pda.StepAsync(
            new Fail("Token endpoint unreachable.", failedAt),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(stepped);
        var failed = Assert.IsInstanceOfType<FlowFailed>(pda.CurrentState);
        Assert.AreEqual("Token endpoint unreachable.", failed.Reason);
        Assert.AreEqual(failedAt, failed.FailedAt);
    }


    [TestMethod]
    public async Task PdaHaltsAfterTokenReceived()
    {
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, AuthCodeStackSymbol> pda = CreatePda();
        await pda.StepAsync(CreateInitiate("flow-8"), TestContext.CancellationToken).ConfigureAwait(false);
        await RunToTokenReceived(pda, TestContext.CancellationToken).ConfigureAwait(false);

        bool stepped = await pda.StepAsync(
            new Fail("Should not transition.", TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(stepped, "No transition is defined from TokenReceived.");
        Assert.IsTrue(pda.IsHalted);
    }


    [TestMethod]
    public async Task StackDepthRemainsOneOnLinearFlow()
    {
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, AuthCodeStackSymbol> pda = CreatePda();
        await pda.StepAsync(CreateInitiate("flow-9"), TestContext.CancellationToken).ConfigureAwait(false);
        await RunToTokenReceived(pda, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, pda.StackDepth, "Stack must contain only the sentinel on the linear path.");
    }


    [TestMethod]
    public async Task UndefinedInputOnWrongStateHaltsPda()
    {
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, AuthCodeStackSymbol> pda = CreatePda();
        await pda.StepAsync(CreateInitiate("flow-10"), TestContext.CancellationToken).ConfigureAwait(false);

        bool stepped = await pda.StepAsync(
            new CodeReceived("code", "state", "https://as.example.com", TimeProvider.GetUtcNow()),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(stepped, "CodeReceived from PkceGenerated is undefined — PDA must halt.");
        Assert.IsTrue(pda.IsHalted);
    }


    private PushdownAutomaton<OAuthFlowState, OAuthFlowInput, AuthCodeStackSymbol> CreatePda() =>
        AuthCodeFlowAutomaton.Create(Guid.NewGuid().ToString(), TimeProvider);

    private Initiate CreateInitiate(string flowId)
    {
        PkceParameters pkce = CreatePkceParameters();
        return new Initiate(
            Pkce: pkce,
            RedirectUri: new Uri("https://client.example.com/callback"),
            Scopes: ["openid"],
            FlowId: flowId,
            ExpectedIssuer: "https://as.example.com",
            InitiatedAt: TimeProvider.GetUtcNow(),
            InitialExpiresAt: TimeProvider.GetUtcNow().AddMinutes(5));
    }

    private static PkceParameters CreatePkceParameters() =>
        PkceGeneration.Generate(TestSetup.Base64UrlEncoder, SensitiveMemoryPool<byte>.Shared);

    private async System.Threading.Tasks.ValueTask RunToParCompleted(
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, AuthCodeStackSymbol> pda,
        string flowId,
        System.Threading.CancellationToken cancellationToken)
    {
        await pda.StepAsync(CreateInitiate(flowId), cancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new ParBodyComposed("client_id=test", TimeProvider.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new ParSucceeded(
                new ParResponse(new Uri("urn:ietf:params:oauth:request_uri:test"), 60),
                TimeProvider.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);
    }

    private async System.Threading.Tasks.ValueTask RunToTokenReceived(
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, AuthCodeStackSymbol> pda,
        System.Threading.CancellationToken cancellationToken)
    {
        await pda.StepAsync(
            new ParBodyComposed("client_id=test", TimeProvider.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new ParSucceeded(
                new ParResponse(new Uri("urn:ietf:params:oauth:request_uri:test"), 60),
                TimeProvider.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new CodeReceived("code", "state", "https://as.example.com", TimeProvider.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new TokenExchangeSucceeded("at.abc", "Bearer", 3600, null, null, TimeProvider.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);
    }
}
