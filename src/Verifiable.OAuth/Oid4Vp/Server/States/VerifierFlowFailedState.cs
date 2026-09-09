using System.Diagnostics;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Oid4Vp.Server.States;

/// <summary>
/// The Verifier flow has failed. Terminal failure state.
/// </summary>
/// <remarks>
/// Produced by any non-terminal state when a <see cref="Verifiable.OAuth.Fail"/> input
/// is received. The PDA halts here.
/// </remarks>
[DebuggerDisplay("VerifierFlowFailed FlowId={FlowId} Reason={Reason}")]
public sealed record VerifierFlowFailedState: FlowState
{
    /// <summary>A human-readable description of the failure reason.</summary>
    public required string Reason { get; init; }

    /// <summary>
    /// The typed, client-facing refusal when this failure is a refused presentation — the
    /// <c>direct_post</c> endpoint answers it as an RFC 6749 §4.1.2.1 error (HTTP 400). <see langword="null"/>
    /// when the failure is a genuine Verifier-side fault carrying no client-safe classification, which the
    /// endpoint answers as HTTP 500.
    /// </summary>
    public VerifierFlowRefusal? Refusal { get; init; }

    /// <summary>
    /// The credential-status policy's typed verdict when <see cref="Refusal"/>'s
    /// <see cref="VerifierFlowRefusal.Kind"/> is <see cref="VerifierFlowRefusalKind.PolicyRefused"/> — which
    /// credential queries were refused, their raw status values, and each one's disposition. Never on the
    /// wire; a relying party inspects this from the failed state for its own logging or UI.
    /// <see langword="null"/> for every other refusal kind or when the failure carries no refusal at all.
    /// </summary>
    public Verifiable.Core.StatusList.CredentialStatusRefusal? CredentialStatusRefusal { get; init; }

    /// <summary>The UTC instant at which the failure was recorded.</summary>
    public required DateTimeOffset FailedAt { get; init; }
}
