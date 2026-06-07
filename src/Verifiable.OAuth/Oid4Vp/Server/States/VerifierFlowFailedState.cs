using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp.Server.States;

/// <summary>
/// The Verifier flow has failed. Terminal failure state.
/// </summary>
/// <remarks>
/// Produced by any non-terminal state when a <see cref="Verifiable.OAuth.Fail"/> input
/// is received. The PDA halts here.
/// </remarks>
[DebuggerDisplay("VerifierFlowFailed FlowId={FlowId} Reason={Reason}")]
public sealed record VerifierFlowFailedState: OAuthFlowState
{
    /// <summary>A human-readable description of the failure reason.</summary>
    public required string Reason { get; init; }

    /// <summary>The UTC instant at which the failure was recorded.</summary>
    public required DateTimeOffset FailedAt { get; init; }
}
