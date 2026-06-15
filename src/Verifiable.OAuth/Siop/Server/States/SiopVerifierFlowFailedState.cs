using System.Diagnostics;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Siop.Server.States;

/// <summary>
/// Terminal failure of the SIOPv2 RP flow. Also serves, with an empty <see cref="FlowState.FlowId"/>,
/// as the PDA's pre-initiation sentinel before the first request-preparation input.
/// </summary>
[DebuggerDisplay("SiopVerifierFlowFailedState FlowId={FlowId} Reason={Reason,nq}")]
public sealed record SiopVerifierFlowFailedState: FlowState
{
    /// <summary>Why the flow failed.</summary>
    public required string Reason { get; init; }

    /// <summary>When the flow failed.</summary>
    public required DateTimeOffset FailedAt { get; init; }
}
