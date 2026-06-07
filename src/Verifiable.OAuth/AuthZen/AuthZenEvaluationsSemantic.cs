namespace Verifiable.OAuth.AuthZen;

/// <summary>
/// The batch evaluation semantic of an OpenID AuthZEN Authorization API 1.0
/// Access Evaluations API request — how the Policy Decision Point processes
/// the <c>evaluations</c> array, per
/// <see href="https://openid.net/specs/authorization-api-1_0.html">AuthZEN
/// Authorization API 1.0 §6 (Access Evaluations API)</see>.
/// </summary>
/// <remarks>
/// The wire form lives in <c>options.evaluations_semantic</c>; the string
/// values are in <see cref="AuthZenEvaluationsSemanticValues"/>. The default —
/// applied when <c>options</c> or <c>evaluations_semantic</c> is absent — is
/// <see cref="ExecuteAll"/>, the enum's zero value.
/// </remarks>
public enum AuthZenEvaluationsSemantic
{
    /// <summary>
    /// <c>execute_all</c> (the default): every request in the
    /// <c>evaluations</c> array is evaluated and a decision returned in the
    /// same array order.
    /// </summary>
    ExecuteAll = 0,

    /// <summary>
    /// <c>deny_on_first_deny</c>: evaluation stops at the first deny; the
    /// response array contains only the items evaluated up to and including
    /// that deny.
    /// </summary>
    DenyOnFirstDeny,

    /// <summary>
    /// <c>permit_on_first_permit</c>: evaluation stops at the first permit; the
    /// response array contains only the items evaluated up to and including
    /// that permit.
    /// </summary>
    PermitOnFirstPermit
}
