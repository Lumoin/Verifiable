using System.Diagnostics;
using Verifiable.Core.Automata;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// Factory for the server-side OID4VP Verifier flow pushdown automaton.
/// </summary>
/// <remarks>
/// The PDA produced by <see cref="Create"/> models the Verifier's HTTP endpoints:
/// receiving a PAR request, signing and serving the JAR, and receiving the encrypted
/// Authorization Response. Each call to <c>StepAsync</c> corresponds to one HTTP
/// endpoint handling.
/// </remarks>
[DebuggerDisplay("Oid4VpVerifierFlowAutomaton")]
public static class Oid4VpVerifierFlowAutomaton
{
    /// <summary>
    /// Creates a new server-side OID4VP Verifier flow PDA ready to accept its first
    /// <see cref="ParSucceeded"/> input.
    /// </summary>
    /// <param name="runId">A unique identifier for this PDA instance, used for tracing.</param>
    /// <param name="timeProvider">The time provider used to stamp the initial state.</param>
    public static PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpVerifierStackSymbol> Create(
        string runId,
        TimeProvider timeProvider)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);
        ArgumentNullException.ThrowIfNull(timeProvider);

        DateTimeOffset now = timeProvider.GetUtcNow();

        return new PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpVerifierStackSymbol>(
            runId: runId,
            initialState: new VerifierFlowFailedState
            {
                FlowId = string.Empty,
                ExpectedIssuer = string.Empty,
                EnteredAt = now,
                ExpiresAt = DateTimeOffset.MaxValue,
                Kind = FlowKind.Oid4VpVerifierServer,
                Reason = "Flow not yet initiated.",
                FailedAt = now
            },
            initialStackSymbol: Oid4VpVerifierStackSymbol.Base,
            transition: Oid4VpVerifierFlowTransitions.Create(),
            acceptPredicate: static state => state is PresentationVerifiedState,
            timeProvider: timeProvider);
    }


    /// <summary>
    /// Restores a server-side OID4VP Verifier flow PDA from a persisted state snapshot.
    /// </summary>
    /// <param name="state">The persisted flow state loaded from the store.</param>
    /// <param name="stepCount">The step count at the time the state was persisted.</param>
    /// <param name="timeProvider">The time provider used for expiry checks.</param>
    public static PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpVerifierStackSymbol> CreateFromSnapshot(
        OAuthFlowState state,
        int stepCount,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(timeProvider);

        return new PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpVerifierStackSymbol>(
            runId: Guid.NewGuid().ToString(),
            savedState: state,
            savedStack: [Oid4VpVerifierStackSymbol.Base],
            savedStepCount: stepCount,
            transition: Oid4VpVerifierFlowTransitions.Create(),
            acceptPredicate: static s => s is PresentationVerifiedState,
            timeProvider: timeProvider);
    }
}
