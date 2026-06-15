using System.Diagnostics;
using Verifiable.Foundation.Automata;
using Verifiable.Server;

namespace Verifiable.Vcalm.Exchange;

/// <summary>
/// Factory for the W3C VCALM 1.0 §3.6 exchange-instance flow pushdown automaton. The PDA models the
/// exchange lifecycle (§3.6.6 <c>pending → active → (complete | invalid)</c>): one
/// <c>StepAsync</c> per §3.6.5 vcapi message that advances the exchange.
/// </summary>
[DebuggerDisplay("VcalmExchangeFlowAutomaton")]
public static class VcalmExchangeFlowAutomaton
{
    /// <summary>Creates a new exchange flow PDA ready to accept its first <see cref="VcalmExchangeCreated"/> input.</summary>
    /// <param name="runId">A unique identifier for this PDA instance, used for tracing.</param>
    /// <param name="timeProvider">The time provider used to stamp the initial sentinel state.</param>
    public static PushdownAutomaton<FlowState, FlowInput, VcalmExchangeStackSymbol> Create(
        string runId,
        TimeProvider timeProvider)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);
        ArgumentNullException.ThrowIfNull(timeProvider);

        DateTimeOffset now = timeProvider.GetUtcNow();

        return new PushdownAutomaton<FlowState, FlowInput, VcalmExchangeStackSymbol>(
            runId: runId,
            initialState: new VcalmExchangeInvalidState
            {
                FlowId = string.Empty,
                ExpectedIssuer = string.Empty,
                EnteredAt = now,
                ExpiresAt = DateTimeOffset.MaxValue,
                Kind = VcalmExchangeFlowKind.Instance,
                ExchangeId = string.Empty,
                ErrorType = string.Empty,
                ErrorTitle = "Exchange not yet initiated.",
                ErrorDetail = "Exchange not yet initiated.",
                FailedAt = now
            },
            initialStackSymbol: VcalmExchangeStackSymbol.Base,
            transition: VcalmExchangeFlowTransitions.Create(),
            acceptPredicate: static state => state is VcalmExchangeCompleteState,
            timeProvider: timeProvider);
    }


    /// <summary>Restores an exchange flow PDA from a persisted state snapshot.</summary>
    /// <param name="state">The persisted flow state loaded from the store.</param>
    /// <param name="stepCount">The step count at the time the state was persisted.</param>
    /// <param name="timeProvider">The time provider used for expiry checks.</param>
    public static PushdownAutomaton<FlowState, FlowInput, VcalmExchangeStackSymbol> CreateFromSnapshot(
        FlowState state,
        int stepCount,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(timeProvider);

        return new PushdownAutomaton<FlowState, FlowInput, VcalmExchangeStackSymbol>(
            runId: Guid.CreateVersion7(timeProvider.GetUtcNow()).ToString("N"),
            savedState: state,
            savedStack: [VcalmExchangeStackSymbol.Base],
            savedStepCount: stepCount,
            transition: VcalmExchangeFlowTransitions.Create(),
            acceptPredicate: static s => s is VcalmExchangeCompleteState,
            timeProvider: timeProvider);
    }
}
