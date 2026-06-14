using System.Diagnostics;
using Verifiable.Server;

namespace Verifiable.OAuth.AuthZen;

/// <summary>
/// The Decision entity of an OpenID AuthZEN Authorization API 1.0 Access
/// Evaluation response — the Policy Decision Point's boolean
/// <see cref="Decision"/> plus an optional <see cref="Context"/> conveying
/// additional enforcement information (obligations, reasons, advice).
/// </summary>
/// <remarks>
/// The Policy Decision Point produces this via the
/// <see cref="Server.EvaluateAccessDelegate"/> seam; the library serialises
/// it to the <c>{ "decision": &lt;bool&gt; }</c> wire body by hand through
/// <see cref="JsonAppender"/>.
/// </remarks>
[DebuggerDisplay("AccessEvaluationDecision Decision={Decision}")]
public sealed record AccessEvaluationDecision
{
    /// <summary>
    /// The decision — <see langword="true"/> permits the access,
    /// <see langword="false"/> denies it. Required.
    /// </summary>
    public required bool Decision { get; init; }

    /// <summary>
    /// Optional additional enforcement information (obligations, reasons,
    /// advice) the Policy Enforcement Point may act on. Emitted as the
    /// response <c>context</c> object when present.
    /// </summary>
    public IReadOnlyDictionary<string, object>? Context { get; init; }


    /// <summary>A bare permit decision with no context.</summary>
    public static AccessEvaluationDecision Permit { get; } = new() { Decision = true };

    /// <summary>A bare deny decision with no context.</summary>
    public static AccessEvaluationDecision Deny { get; } = new() { Decision = false };
}
