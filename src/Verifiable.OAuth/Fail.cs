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
[DebuggerDisplay("Fail Reason={Reason}")]
public sealed record Fail(string Reason, DateTimeOffset FailedAt): OAuthFlowInput;
