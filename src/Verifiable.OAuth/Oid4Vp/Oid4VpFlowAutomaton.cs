using Verifiable.Core.Automata;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Factory for the OID4VP authorization flow pushdown automaton.
/// </summary>
/// <remarks>
/// <para>
/// Combines the transition function from <see cref="Oid4VpFlowTransitions"/> with the
/// required initial state, stack symbol, accept predicate, and time provider into a
/// ready-to-use <see cref="PushdownAutomaton{TState,TInput,TStackSymbol}"/>. Application
/// code calls <see cref="Create"/> once per authorization session and drives the returned
/// automaton by calling <c>StepAsync</c> with typed input records.
/// </para>
/// <para>
/// The automaton is not thread-safe. Each authorization session must use its own instance.
/// </para>
/// </remarks>
public static class Oid4VpFlowAutomaton
{
    /// <summary>
    /// Creates a new OID4VP flow automaton ready to accept its first <c>Initiate</c> input.
    /// </summary>
    /// <param name="runId">
    /// A unique identifier for this automaton instance, used for tracing and logging.
    /// Callers typically supply a new <see cref="Guid"/> formatted as a string.
    /// </param>
    /// <param name="timeProvider">
    /// The time provider used to stamp the initial state. Supply a
    /// <c>FakeTimeProvider</c> in tests and <see cref="TimeProvider.System"/> in production.
    /// </param>
    /// <returns>
    /// A <see cref="PushdownAutomaton{TState,TInput,TStackSymbol}"/> wired with the OID4VP
    /// transition function and accept predicate. The initial state is
    /// <see cref="FlowFailed"/> with an explanatory reason — this state is superseded
    /// immediately by the first <c>Initiate</c> transition.
    /// </returns>
    public static PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> Create(
        string runId,
        TimeProvider timeProvider)
    {
        ArgumentException.ThrowIfNullOrEmpty(runId);
        ArgumentNullException.ThrowIfNull(timeProvider);

        DateTimeOffset now = timeProvider.GetUtcNow();

        return new PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol>(
            runId: runId,
            initialState: new FlowFailed
            {
                FlowId = string.Empty,
                ExpectedIssuer = string.Empty,
                EnteredAt = now,
                ExpiresAt = DateTimeOffset.MaxValue,
                Kind = FlowKind.Oid4VpVerifier,
                Reason = "Flow not yet initiated.",
                FailedAt = now
            },
            initialStackSymbol: Oid4VpStackSymbol.Base,
            transition: Oid4VpFlowTransitions.Create(),
            acceptPredicate: static state => state is PresentationVerifiedState,
            timeProvider: timeProvider);
    }


    /// <summary>
    /// Restores an OID4VP flow automaton from a previously persisted state snapshot.
    /// </summary>
    /// <param name="state">The persisted flow state, typically loaded from a database.</param>
    /// <param name="stepCount">The step count at the time the state was persisted.</param>
    /// <param name="timeProvider">The time provider used for expiry checks.</param>
    /// <returns>
    /// A <see cref="PushdownAutomaton{TState,TInput,TStackSymbol}"/> restored to
    /// <paramref name="state"/> and <paramref name="stepCount"/>, ready to accept the
    /// next input for this flow.
    /// </returns>
    public static PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> CreateFromSnapshot(
        OAuthFlowState state,
        int stepCount,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(timeProvider);

        return new PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol>(
            runId: Guid.NewGuid().ToString(),
            savedState: state,
            savedStack: [Oid4VpStackSymbol.Base],
            savedStepCount: stepCount,
            transition: Oid4VpFlowTransitions.Create(),
            acceptPredicate: static s => s is PresentationVerifiedState,
            timeProvider: timeProvider);
    }
}
