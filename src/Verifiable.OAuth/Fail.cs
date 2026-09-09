using System.Diagnostics;

namespace Verifiable.OAuth;

/// <summary>
/// Signals a failure at any stage of an OAuth/OpenID flow. Accepted from any
/// non-terminal state and transitions to <see cref="FlowFailed"/>.
/// </summary>
/// <param name="Reason">
/// Human-readable failure reason for server-side logging only.
/// Must not be forwarded to clients or included in any protocol response.
/// </param>
/// <param name="FailedAt">The UTC instant the failure was recorded.</param>
/// <remarks>
/// On the OID4VP verifier flow, a refused (rather than faulted) presentation uses
/// <c>VerifierPresentationRefused</c> instead, whose <c>Refusal</c> is a typed
/// <c>Verifiable.OAuth.Server.VerifierFlowRefusal</c> the <c>direct_post</c> endpoint answers on the wire.
/// This type's <see cref="Reason"/> is server-side log detail and never reaches a protocol response; the
/// client-facing refusal is <c>VerifierPresentationRefused</c> / <c>Verifiable.OAuth.Server.VerifierFlowRefusal</c>.
/// </remarks>
[DebuggerDisplay("Fail Reason={Reason}")]
public sealed record Fail(string Reason, DateTimeOffset FailedAt): FlowInput;
