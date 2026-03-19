using System.Diagnostics;
using Verifiable.Core.Automata;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// Factory for the client-side Authorization Code flow pushdown automaton.
/// </summary>
/// <remarks>
/// <para>
/// The PDA produced by <see cref="Create"/> models the client's steps from PKCE
/// generation through token receipt. Each call to <c>StepAsync</c> corresponds to
/// one protocol step, and the resulting state snapshot can be persisted between
/// HTTP round-trips.
/// </para>
/// <para>
/// The accept predicate matches <see cref="TokenReceivedState"/> — the client has
/// successfully completed the Authorization Code exchange.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthCodeFlowAutomaton")]
public static class AuthCodeFlowAutomaton
{
    /// <summary>
    /// Creates a new client-side Authorization Code flow PDA ready to accept its
    /// first <see cref="Initiate"/> input.
    /// </summary>
    /// <param name="runId">
    /// A unique identifier for this PDA instance, used for tracing and correlation.
    /// </param>
    /// <param name="timeProvider">
    /// The time provider used to stamp the initial state. Supply a
    /// <c>FakeTimeProvider</c> in tests and <see cref="TimeProvider.System"/> in
    /// production.
    /// </param>
    /// <returns>
    /// A <see cref="PushdownAutomaton{TState,TInput,TStackSymbol}"/> wired with
    /// <see cref="AuthCodeFlowTransitions.Create"/> and accept predicate
    /// <c>state is TokenReceived</c>. The initial state is a sentinel
    /// <see cref="FlowFailed"/> with an empty <c>FlowId</c> — it is superseded
    /// immediately by the first <see cref="Initiate"/> transition.
    /// </returns>
    public static PushdownAutomaton<OAuthFlowState, OAuthFlowInput, AuthCodeStackSymbol> Create(
        string runId,
        TimeProvider timeProvider)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);
        ArgumentNullException.ThrowIfNull(timeProvider);

        DateTimeOffset now = timeProvider.GetUtcNow();

        return new PushdownAutomaton<OAuthFlowState, OAuthFlowInput, AuthCodeStackSymbol>(
            runId: runId,
            initialState: new FlowFailed
            {
                FlowId = string.Empty,
                ExpectedIssuer = string.Empty,
                EnteredAt = now,
                ExpiresAt = DateTimeOffset.MaxValue,
                Kind = FlowKind.AuthCodeClient,
                Reason = "Flow not yet initiated.",
                FailedAt = now
            },
            initialStackSymbol: AuthCodeStackSymbol.Base,
            transition: AuthCodeFlowTransitions.Create(),
            acceptPredicate: static state => state is TokenReceivedState,
            timeProvider: timeProvider);
    }


    /// <summary>
    /// Restores a client-side Authorization Code flow PDA from a previously
    /// persisted state snapshot.
    /// </summary>
    /// <param name="state">The persisted flow state.</param>
    /// <param name="stepCount">The step count at the time of persistence.</param>
    /// <param name="timeProvider">The time provider used for expiry checks.</param>
    /// <returns>
    /// A <see cref="PushdownAutomaton{TState,TInput,TStackSymbol}"/> restored to
    /// <paramref name="state"/> and <paramref name="stepCount"/>, ready to accept
    /// the next input.
    /// </returns>
    public static PushdownAutomaton<OAuthFlowState, OAuthFlowInput, AuthCodeStackSymbol> CreateFromSnapshot(
        OAuthFlowState state,
        int stepCount,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(timeProvider);

        return new PushdownAutomaton<OAuthFlowState, OAuthFlowInput, AuthCodeStackSymbol>(
            runId: Guid.NewGuid().ToString(),
            savedState: state,
            savedStack: [AuthCodeStackSymbol.Base],
            savedStepCount: stepCount,
            transition: AuthCodeFlowTransitions.Create(),
            acceptPredicate: static s => s is TokenReceivedState,
            timeProvider: timeProvider);
    }
}
