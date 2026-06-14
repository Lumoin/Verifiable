using System.Collections.Immutable;
using System.Diagnostics;

namespace Verifiable.Vcalm.Exchange;

/// <summary>
/// Terminal failure of the W3C VCALM 1.0 §3.6 exchange: a presented vcapi message was unacceptable —
/// for example a <c>verifiablePresentation</c> that failed verification against the bound challenge /
/// domain — so the exchange cannot continue. The §3.6.6 state is <c>invalid</c> and the §3.6.6
/// <c>lastError</c> carries the §3.8 ProblemDetail. Also serves, with an empty
/// <see cref="FlowState.FlowId"/>, as the PDA's pre-initiation sentinel before the create input.
/// </summary>
/// <remarks>
/// §3.6: "When a workflow service determines that a particular message is not acceptable, it raises an
/// error by responding with a 4xx HTTP status message and a JSON object that expresses information
/// about the error." The participate endpoint maps this terminal state to a 4xx + ProblemDetails; the
/// state retains the §3.6.6 reporting fields so a later get-state read surfaces the same error.
/// </remarks>
[DebuggerDisplay("VcalmExchangeInvalidState FlowId={FlowId} ExchangeId={ExchangeId} Reason={ErrorTitle,nq}")]
public sealed record VcalmExchangeInvalidState: FlowState
{
    /// <summary>The §3.6 <c>{localExchangeId}</c> the exchange is addressed by, or empty for the pre-initiation sentinel.</summary>
    public required string ExchangeId { get; init; }

    /// <summary>The §3.6.3 <c>expires</c> the exchange was created with, verbatim, or <see langword="null"/> when unbounded.</summary>
    public string? Expires { get; init; }

    /// <summary>The verbatim §3.6.3 <c>variables</c> JSON the creator supplied, or <see langword="null"/> when none.</summary>
    public string? VariablesJson { get; init; }

    /// <summary>The §3.6.6 <c>step</c> the failing message was presented at, or <see langword="null"/>.</summary>
    public string? StepName { get; init; }

    /// <summary>The §3.8 / §3.6.6 <c>lastError.type</c> URL identifying the problem.</summary>
    public required string ErrorType { get; init; }

    /// <summary>The §3.8 / §3.6.6 <c>lastError.title</c> short human-readable string.</summary>
    public required string ErrorTitle { get; init; }

    /// <summary>The §3.8 / §3.6.6 <c>lastError.detail</c> longer human-readable string.</summary>
    public required string ErrorDetail { get; init; }

    /// <summary>
    /// The §3.6.6 <c>variables.results</c> accumulated before the exchange failed — per step name, the
    /// verbatim JSON of a result the engine recorded at a prior step. A multi-step exchange that fails
    /// at a later step still surfaces the earlier steps' outputs in the §3.6.6 view.
    /// </summary>
    public ImmutableDictionary<string, string> StepResults { get; init; } =
        ImmutableDictionary<string, string>.Empty;

    /// <summary>When the exchange failed.</summary>
    public required DateTimeOffset FailedAt { get; init; }
}
