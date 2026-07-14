using Microsoft.Extensions.Time.Testing;
using Verifiable.OAuth.Siop;
using Verifiable.OAuth.Siop.Server;
using Verifiable.OAuth.Siop.Server.States;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Structural tests for the server-side SIOPv2 Relying Party flow PDA (no crypto): the
/// request-preparation → verified happy path and the fail path. These pin the transition shape
/// the dispatched endpoints drive.
/// </summary>
[TestClass]
internal sealed class SiopVerifierFlowAutomatonTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);


    [TestMethod]
    public async Task PreparationReceiptAndVerificationReachesTerminalSuccess()
    {
        var pda = SiopVerifierFlowAutomaton.Create("siop-run-1", TimeProvider);

        await pda.StepAsync(Prepared(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsInstanceOfType<SiopRequestPreparedState>(pda.CurrentState);

        await pda.StepAsync(
            new SiopResponsePosted { IdToken = "header.body.sig", ReceivedAt = TimeProvider.GetUtcNow() },
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsInstanceOfType<SiopResponseReceivedState>(pda.CurrentState);
        Assert.IsInstanceOfType<ValidateSelfIssuedIdToken>(pda.CurrentState.NextAction,
            "The received-but-unverified state must declare the validation action the executor runs.");

        //The executor would produce this input; the PDA transition itself is pure.
        await pda.StepAsync(
            new SelfIssuedAuthenticationVerified
            {
                Subject = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:abc",
                SubjectSyntaxType = SiopSubjectSyntaxType.JwkThumbprint,
                Nonce = "n-1",
                VerifiedAt = TimeProvider.GetUtcNow()
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(pda.CurrentState);
        Assert.IsTrue(pda.IsAccepted, "The verified state is the PDA's accept state.");
    }


    [TestMethod]
    public async Task FailFromReceivedReachesTerminalFailure()
    {
        var pda = SiopVerifierFlowAutomaton.Create("siop-run-2", TimeProvider);

        await pda.StepAsync(Prepared(), TestContext.CancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new SiopResponsePosted { IdToken = "header.body.sig", ReceivedAt = TimeProvider.GetUtcNow() },
            TestContext.CancellationToken).ConfigureAwait(false);
        await pda.StepAsync(
            new SiopFlowFailed { Reason = "id_token validation failed.", FailedAt = TimeProvider.GetUtcNow() },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<SiopVerifierFlowFailedState>(pda.CurrentState);
        Assert.IsFalse(pda.IsAccepted);
    }


    private SiopRequestPrepared Prepared() =>
        new()
        {
            FlowId = "flow-1",
            ClientId = "https://verifier.example.com",
            Nonce = "n-1",
            AllowedAlgorithms = ["ES256"],
            RequestHandle = "handle-1",
            PreparedAt = TimeProvider.GetUtcNow(),
            ExpiresAt = TimeProvider.GetUtcNow().AddMinutes(5)
        };
}
