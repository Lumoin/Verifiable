using System.Diagnostics;
using Verifiable.Core.Automata;
using Verifiable.OAuth.AuthCode.Server.States;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.AuthCode.Server;

/// <summary>
/// Factory for the server-side Authorization Code flow pushdown automaton.
/// </summary>
/// <remarks>
/// <para>
/// Each inbound client session gets its own
/// <see cref="PushdownAutomaton{TState,TInput,TStackSymbol}"/> instance.
/// The HTTP handler rehydrates the PDA from stored state at the start of each
/// request boundary, steps it once with the result of effectful work, and
/// persists the new state — the same pattern used by the OID4VP verifier PDA.
/// </para>
/// <para>
/// The store key is the <c>flowId</c> generated at PAR time. Subsequent endpoints
/// resolve the <c>flowId</c> from the request: the authorize endpoint maps
/// <c>request_uri → flowId</c>, the token endpoint maps <c>code → flowId</c>.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthCodeServerFlowAutomaton")]
public static class AuthCodeServerFlowAutomaton
{
    /// <summary>
    /// Creates a new server-side Authorization Code flow automaton ready to accept
    /// its first <see cref="ServerParValidated"/> input.
    /// </summary>
    /// <param name="runId">
    /// A unique identifier for this automaton instance, used for tracing.
    /// </param>
    /// <param name="timeProvider">
    /// The time provider used to stamp the initial state. Supply a
    /// <c>FakeTimeProvider</c> in tests and <see cref="TimeProvider.System"/> in production.
    /// </param>
    public static PushdownAutomaton<OAuthFlowState, OAuthFlowInput, AuthCodeServerStackSymbol> Create(
        string runId,
        TimeProvider timeProvider)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);
        ArgumentNullException.ThrowIfNull(timeProvider);

        DateTimeOffset now = timeProvider.GetUtcNow();

        return new PushdownAutomaton<OAuthFlowState, OAuthFlowInput, AuthCodeServerStackSymbol>(
            runId: runId,
            initialState: new ServerFlowFailedState
            {
                FlowId = string.Empty,
                ExpectedIssuer = string.Empty,
                EnteredAt = now,
                ExpiresAt = DateTimeOffset.MaxValue,
                Kind = FlowKind.AuthCodeServer,
                ErrorCode = "server_error",
                Reason = "Flow not yet initiated.",
                FailedAt = now
            },
            initialStackSymbol: AuthCodeServerStackSymbol.Base,
            transition: AuthCodeServerFlowTransitions.Create(),
            acceptPredicate: static state => state is ServerTokenIssuedState,
            timeProvider: timeProvider);
    }


    /// <summary>
    /// Restores a server-side Authorization Code flow automaton from a previously
    /// persisted state snapshot.
    /// </summary>
    /// <param name="state">The persisted server flow state loaded from the store.</param>
    /// <param name="stepCount">The step count at the time the state was persisted.</param>
    /// <param name="timeProvider">The time provider used for expiry checks.</param>
    public static PushdownAutomaton<OAuthFlowState, OAuthFlowInput, AuthCodeServerStackSymbol> CreateFromSnapshot(
        OAuthFlowState state,
        int stepCount,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(timeProvider);

        return new PushdownAutomaton<OAuthFlowState, OAuthFlowInput, AuthCodeServerStackSymbol>(
            runId: Guid.NewGuid().ToString(),
            savedState: state,
            savedStack: [AuthCodeServerStackSymbol.Base],
            savedStepCount: stepCount,
            transition: AuthCodeServerFlowTransitions.Create(),
            acceptPredicate: static s => s is ServerTokenIssuedState,
            timeProvider: timeProvider);
    }
}
