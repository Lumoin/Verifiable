using System.Diagnostics;

namespace Verifiable.OAuth;

/// <summary>
/// Terminal failure state applicable to any OAuth/OpenID flow.
/// No further transitions are defined from this state; the PDA halts when it enters here.
/// </summary>
/// <remarks>
/// The complete transition history is available through the
/// <see cref="Verifiable.Core.Automata.TraceEntry{TState,TInput}"/> stream emitted during the run.
/// That stream is the audit trail; state records do not embed history links.
/// </remarks>
[DebuggerDisplay("FlowFailed FlowId={FlowId} Reason={Reason}")]
public sealed record FlowFailed: OAuthFlowState
{
    /// <summary>
    /// Human-readable reason for the failure, suitable for server-side logging.
    /// Must not be forwarded to clients or included in any protocol response.
    /// </summary>
    public required string Reason { get; init; }

    /// <summary>The UTC instant at which the failure was recorded.</summary>
    public required DateTimeOffset FailedAt { get; init; }
}
