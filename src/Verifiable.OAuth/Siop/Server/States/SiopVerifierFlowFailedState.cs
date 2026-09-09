using System.Diagnostics;
using Verifiable.Core.StatusList;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Siop.Server.States;

/// <summary>
/// Terminal failure of the SIOPv2 RP flow. Also serves, with an empty <see cref="FlowState.FlowId"/>,
/// as the PDA's pre-initiation sentinel before the first request-preparation input.
/// </summary>
[DebuggerDisplay("SiopVerifierFlowFailedState FlowId={FlowId} Reason={Reason,nq}")]
public sealed record SiopVerifierFlowFailedState: FlowState
{
    /// <summary>Why the flow failed. Server-side logging only; never forwarded to the Wallet.</summary>
    public required string Reason { get; init; }

    /// <summary>When the flow failed.</summary>
    public required DateTimeOffset FailedAt { get; init; }

    /// <summary>
    /// The wire-safe refusal the SIOP response endpoint answers with, carried through from
    /// <see cref="SiopFlowFailed.Refusal"/>. <see langword="null"/> for an unclassified failure, which
    /// answers a genuine-fault 500 instead of a 400.
    /// </summary>
    public VerifierFlowRefusal? Refusal { get; init; }

    /// <summary>
    /// The credential-status policy's typed refusal detail, carried through from
    /// <see cref="SiopFlowFailed.CredentialStatusRefusal"/>. <see langword="null"/> unless
    /// <see cref="Refusal"/> carries <see cref="VerifierFlowRefusalKind.PolicyRefused"/>.
    /// </summary>
    public CredentialStatusRefusal? CredentialStatusRefusal { get; init; }
}
