using System.Diagnostics;
using Verifiable.Server;

namespace Verifiable.Vcalm.Exchange;

/// <summary>
/// The W3C VCALM 1.0 §3.6 exchange-instance flow. Models the exchange lifecycle (§3.6.6
/// <c>pending → active → (complete | invalid)</c>) the §3.6.5 vcapi participation drives. Accessed via
/// <c>FlowKind.VcalmExchange</c>.
/// </summary>
/// <remarks>
/// <see cref="RequiresActionExecutor"/> is <see langword="false"/>: the holder
/// <c>verifiablePresentation</c> verification is run in the participate endpoint's
/// <c>BuildInputAsync</c> (composing the §3.3.2 verify path) BEFORE the PDA is stepped, so the
/// verified / rejected verdict reaches the PURE transition as an input. The exchange flow therefore
/// needs no family action executor — keeping the engine usable on a host that wires no executor (the
/// VCALM family has none of its own; only the OAuth family ships one).
/// </remarks>
[DebuggerDisplay("VcalmExchangeFlowKind")]
public sealed class VcalmExchangeFlowKind: StatefulFlowKind
{
    /// <summary>The singleton instance.</summary>
    public static VcalmExchangeFlowKind Instance { get; } = new();


    private VcalmExchangeFlowKind() { }


    /// <inheritdoc/>
    public override string Name => "vcalm_exchange";


    /// <inheritdoc/>
    public override ValueTask<(FlowState State, int StepCount)> CreateAsync(
        string runId,
        TimeProvider timeProvider)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);
        ArgumentNullException.ThrowIfNull(timeProvider);

        var pda = VcalmExchangeFlowAutomaton.Create(runId, timeProvider);

        return ValueTask.FromResult<(FlowState, int)>((pda.CurrentState, pda.StepCount));
    }


    /// <inheritdoc/>
    public override async ValueTask<(FlowState State, int StepCount)> StepAsync(
        FlowState state,
        int stepCount,
        FlowInput input,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(timeProvider);

        var pda = VcalmExchangeFlowAutomaton.CreateFromSnapshot(state, stepCount, timeProvider);

        await pda.StepAsync(input, cancellationToken).ConfigureAwait(false);

        return (pda.CurrentState, pda.StepCount);
    }
}
