using Verifiable.Foundation.Automata;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Server;
using Verifiable.Server;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The <see cref="Oid4VpVerifierFlowTransitions"/> transition function exercised directly (no PDA, no
/// endpoint), pinning that a <see cref="VerifierWalletErrorReceivedState"/> is terminal for every input the
/// same way <see cref="Verifiable.OAuth.Oid4Vp.States.PresentationVerifiedState"/> and
/// <see cref="VerifierFlowFailedState"/> already are.
/// </summary>
/// <remarks>
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
/// Presentations 1.0, Section 8.2</see>: "If the Response URI has successfully processed the Authorization
/// Response or Authorization Error Response, it MUST respond with an HTTP status code of 200 with Content-Type
/// of application/json and a JSON object in the response body." A Wallet's Authorization Error Response, once
/// recorded, has already been successfully processed — a later <see cref="Fail"/> or
/// <see cref="VerifierPresentationRefused"/> input reaching the flow must not rewrite that recorded outcome
/// into a failure.
/// </remarks>
[TestClass]
internal sealed class Oid4VpVerifierFlowTransitionsTests
{
    public TestContext TestContext { get; set; } = null!;

    private static TransitionDelegate<FlowState, FlowInput, Oid4VpVerifierStackSymbol> Transition { get; } =
        Oid4VpVerifierFlowTransitions.Create();

    private static VerifierWalletErrorReceivedState CreateWalletErrorReceivedState() =>
        new()
        {
            FlowId = "flow-wallet-error",
            ExpectedIssuer = "https://verifier.example.com",
            EnteredAt = DateTimeOffset.UnixEpoch,
            ExpiresAt = DateTimeOffset.UnixEpoch.AddMinutes(10),
            Kind = FlowKind.Oid4VpVerifierServer,
            Error = OAuthErrors.AccessDenied,
            ReceivedAt = DateTimeOffset.UnixEpoch
        };


    /// <summary>
    /// A <see cref="Fail"/> arriving after a Wallet Authorization Error Response was already recorded produces
    /// no transition — the recorded §8.2 outcome is not rewritten into a failure.
    /// </summary>
    [TestMethod]
    public async Task FailAfterWalletErrorReceivedProducesNoTransition()
    {
        TransitionResult<FlowState, Oid4VpVerifierStackSymbol>? result = await Transition(
            CreateWalletErrorReceivedState(),
            new Fail("Reason: unrelated later fault.", DateTimeOffset.UnixEpoch.AddSeconds(1)),
            Oid4VpVerifierStackSymbol.Base,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(result, "A Fail input must not transition a terminal VerifierWalletErrorReceivedState.");
    }


    /// <summary>
    /// A <see cref="VerifierPresentationRefused"/> arriving after a Wallet Authorization Error Response was
    /// already recorded produces no transition — the recorded §8.2 outcome is not rewritten into a refusal.
    /// </summary>
    [TestMethod]
    public async Task PresentationRefusedAfterWalletErrorReceivedProducesNoTransition()
    {
        TransitionResult<FlowState, Oid4VpVerifierStackSymbol>? result = await Transition(
            CreateWalletErrorReceivedState(),
            new VerifierPresentationRefused(
                VerifierFlowRefusal.For(VerifierFlowRefusalKind.Unverifiable),
                "Reason: unrelated later refusal.",
                DateTimeOffset.UnixEpoch.AddSeconds(1)),
            Oid4VpVerifierStackSymbol.Base,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(result, "A VerifierPresentationRefused input must not transition a terminal VerifierWalletErrorReceivedState.");
    }
}
