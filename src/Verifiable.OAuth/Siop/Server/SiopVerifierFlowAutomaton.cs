using System.Diagnostics;
using Verifiable.Core.Automata;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Siop.Server.States;

namespace Verifiable.OAuth.Siop.Server;

/// <summary>
/// Factory for the server-side SIOPv2 Relying Party flow pushdown automaton. The PDA models the
/// RP's two HTTP boundaries — request preparation and Self-Issued ID Token response receipt — one
/// <c>StepAsync</c> per boundary.
/// </summary>
[DebuggerDisplay("SiopVerifierFlowAutomaton")]
public static class SiopVerifierFlowAutomaton
{
    /// <summary>Creates a new SIOP RP flow PDA ready to accept its first <see cref="SiopRequestPrepared"/> input.</summary>
    /// <param name="runId">A unique identifier for this PDA instance, used for tracing.</param>
    /// <param name="timeProvider">The time provider used to stamp the initial state.</param>
    public static PushdownAutomaton<OAuthFlowState, OAuthFlowInput, SiopVerifierStackSymbol> Create(
        string runId,
        TimeProvider timeProvider)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);
        ArgumentNullException.ThrowIfNull(timeProvider);

        DateTimeOffset now = timeProvider.GetUtcNow();

        return new PushdownAutomaton<OAuthFlowState, OAuthFlowInput, SiopVerifierStackSymbol>(
            runId: runId,
            initialState: new SiopVerifierFlowFailedState
            {
                FlowId = string.Empty,
                ExpectedIssuer = string.Empty,
                EnteredAt = now,
                ExpiresAt = DateTimeOffset.MaxValue,
                Kind = FlowKind.SiopVerifierServer,
                Reason = "Flow not yet initiated.",
                FailedAt = now
            },
            initialStackSymbol: SiopVerifierStackSymbol.Base,
            transition: SiopVerifierFlowTransitions.Create(),
            acceptPredicate: static state => state is SelfIssuedAuthenticationVerifiedState,
            timeProvider: timeProvider);
    }


    /// <summary>Restores a SIOP RP flow PDA from a persisted state snapshot.</summary>
    /// <param name="state">The persisted flow state loaded from the store.</param>
    /// <param name="stepCount">The step count at the time the state was persisted.</param>
    /// <param name="timeProvider">The time provider used for expiry checks.</param>
    public static PushdownAutomaton<OAuthFlowState, OAuthFlowInput, SiopVerifierStackSymbol> CreateFromSnapshot(
        OAuthFlowState state,
        int stepCount,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(timeProvider);

        return new PushdownAutomaton<OAuthFlowState, OAuthFlowInput, SiopVerifierStackSymbol>(
            runId: Guid.CreateVersion7(timeProvider.GetUtcNow()).ToString("N"),
            savedState: state,
            savedStack: [SiopVerifierStackSymbol.Base],
            savedStepCount: stepCount,
            transition: SiopVerifierFlowTransitions.Create(),
            acceptPredicate: static s => s is SelfIssuedAuthenticationVerifiedState,
            timeProvider: timeProvider);
    }
}
