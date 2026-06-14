using System.Collections.Immutable;
using System.Diagnostics;

namespace Verifiable.Vcalm.Exchange;

/// <summary>
/// The W3C VCALM 1.0 §3.6 exchange immediately after creation (§3.6.3): the exchange instance exists
/// but no vcapi message has yet been exchanged. The §3.6.6 state is <c>pending</c> with
/// <c>sequence</c> 0. This is also the PDA's initial state, set by the create endpoint.
/// </summary>
/// <remarks>
/// §3.6.6: the exchange status is "set to 'pending' on creation". The first §3.6.5 vcapi POST advances
/// it: when the engine has a presentation to request it transitions to
/// <see cref="VcalmExchangeActiveState"/> (issuing a §3.4 verifiable presentation request bound to a
/// fresh challenge / domain); when the engine has nothing to request nor offer it transitions
/// straight to <see cref="VcalmExchangeCompleteState"/>.
/// </remarks>
[DebuggerDisplay("VcalmExchangePendingState FlowId={FlowId} ExchangeId={ExchangeId}")]
public sealed record VcalmExchangePendingState: FlowState
{
    /// <summary>The §3.6 <c>{localExchangeId}</c> the exchange is addressed by.</summary>
    public required string ExchangeId { get; init; }

    /// <summary>The §3.6.3 <c>expires</c> the exchange was created with, verbatim, or <see langword="null"/> when unbounded.</summary>
    public string? Expires { get; init; }

    /// <summary>The verbatim §3.6.3 <c>variables</c> JSON the creator supplied, or <see langword="null"/> when none.</summary>
    public string? VariablesJson { get; init; }

    /// <summary>
    /// The §3.6.6 <c>variables.results</c> accumulated so far — empty on a freshly-created exchange (no
    /// step has recorded a result yet). Present for symmetry with the active / complete / invalid states
    /// so the engine carries the same accumulation across every transition.
    /// </summary>
    public ImmutableDictionary<string, string> StepResults { get; init; } =
        ImmutableDictionary<string, string>.Empty;
}
