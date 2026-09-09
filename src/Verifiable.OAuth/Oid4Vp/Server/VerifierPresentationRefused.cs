using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// Signals that the Verifier refused the presented VP token. Accepted from any non-terminal Verifier state and
/// transitions to <see cref="VerifierFlowFailedState"/>, carrying the typed, client-facing
/// <see cref="VerifierFlowRefusal"/> the <c>direct_post</c> endpoint answers per RFC 6749 §4.1.2.1. Distinct from
/// <see cref="Fail"/>, whose reason is server-side log detail that must never reach the wire.
/// </summary>
/// <param name="Refusal">The typed refusal answered to the Wallet, selecting the RFC 6749 §4.1.2.1 error code.</param>
/// <param name="LogReason">A human-readable reason for server-side logging only; never forwarded to clients.</param>
/// <param name="FailedAt">The UTC instant the refusal was recorded.</param>
public sealed record VerifierPresentationRefused(VerifierFlowRefusal Refusal, string LogReason, DateTimeOffset FailedAt): FlowInput
{
    /// <summary>
    /// The credential-status policy's typed verdict when <see cref="Refusal"/> is
    /// <see cref="VerifierFlowRefusalKind.PolicyRefused"/> — carried onto
    /// <see cref="VerifierFlowFailedState.CredentialStatusRefusal"/> by the transition. <see langword="null"/>
    /// for every other refusal kind.
    /// </summary>
    public Verifiable.Core.StatusList.CredentialStatusRefusal? CredentialStatusRefusal { get; init; }
}
