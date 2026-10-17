using System.Diagnostics;

namespace Verifiable.OAuth.ProtectedResource;

/// <summary>
/// The kind of a <see cref="DpopResourceDecision"/>: whether the protected resource grants access to the presentation
/// it judged, refuses it, or cannot decide. <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449
/// Section 7.1</see>: "The resource server MUST NOT grant access to the resource unless all checks are successful."
/// </summary>
public enum DpopResourceDecisionKind
{
    /// <summary>Every check succeeded and the resource may grant access to the presentation.</summary>
    Permit,

    /// <summary>A check refused the presentation; the decision carries the refusal to send.</summary>
    Deny,

    /// <summary>
    /// The resource cannot decide, a fault of its own wiring rather than of the presentation (a check is not wired, the
    /// <c>jti</c> store is unavailable, a validator answered success without what it promises); access is not granted
    /// and the decision carries the <c>server_error</c> answer to send.
    /// </summary>
    IndeterminateDeny
}


/// <summary>
/// The outcome of <see cref="DpopResourceAccess.DecideAsync"/>: the protected resource's decision on one presentation
/// of an access token under the <c>DPoP</c> or the <c>Bearer</c> scheme, by the checks of
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "a resource server
/// MUST check that a DPoP proof was also received in the DPoP header field of the HTTP request, check the DPoP proof
/// according to the rules in Section 4.3, and check that the public key of the DPoP proof matches the public key to
/// which the access token is bound per Section 6."
/// </summary>
/// <remarks>
/// Only the library mints a decision, so a permit is never a value an application composes for itself. A permit
/// carries the thumbprint the token's binding was confirmed against and nothing of the token's claims, which stay with
/// the caller's own validation. A denial carries the exact answer to send: its status, its body and its
/// <c>WWW-Authenticate</c>, <c>DPoP-Nonce</c> and <c>Access-Control-Expose-Headers</c> fields.
/// </remarks>
[DebuggerDisplay("DpopResourceDecision {Kind}")]
public sealed record DpopResourceDecision
{
    /// <summary>The kind of the decision.</summary>
    public DpopResourceDecisionKind Kind { get; }

    /// <summary>Whether the resource may grant access to the presentation: <see cref="Kind"/> is <see cref="DpopResourceDecisionKind.Permit"/>.</summary>
    public bool IsPermitted => Kind is DpopResourceDecisionKind.Permit;

    /// <summary>
    /// The base64url JWK SHA-256 Thumbprint of the DPoP proof's public key, which matched the token's
    /// <c>cnf.jkt</c> binding (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">RFC 9449 Section
    /// 6.1</see>), on a permit of a DPoP-bound access token; <see langword="null"/> on a permit of an unbound token
    /// presented under the <c>Bearer</c> scheme and on every refusal.
    /// </summary>
    public string? ProofThumbprint { get; }

    /// <summary>
    /// The answer to send on <see cref="DpopResourceDecisionKind.Deny"/> and
    /// <see cref="DpopResourceDecisionKind.IndeterminateDeny"/>; <see langword="null"/> on a permit.
    /// </summary>
    public ServerHttpResponse? Response { get; }

    /// <summary>
    /// The name of the check that refused the presentation, one of the closed list of <see cref="DpopResourceCheckNames"/>
    /// recorded as <see cref="Diagnostics.OAuthTagNames.DpopResourceCheck"/>, on
    /// <see cref="DpopResourceDecisionKind.Deny"/> and <see cref="DpopResourceDecisionKind.IndeterminateDeny"/>;
    /// <see langword="null"/> on a permit. A member of the record's value equality: two decisions refused by different
    /// checks are two decisions.
    /// </summary>
    internal string? Check { get; }


    /// <summary>Creates a decision; only the factories below call it.</summary>
    /// <param name="kind">The kind of the decision.</param>
    /// <param name="proofThumbprint">The thumbprint of a permit of a bound token, or <see langword="null"/>.</param>
    /// <param name="response">The answer of a refusal, or <see langword="null"/> for a permit.</param>
    /// <param name="check">The name of the refusing check, or <see langword="null"/> for a permit.</param>
    private DpopResourceDecision(DpopResourceDecisionKind kind, string? proofThumbprint, ServerHttpResponse? response, string? check)
    {
        Kind = kind;
        ProofThumbprint = proofThumbprint;
        Response = response;
        Check = check;
    }


    /// <summary>The permit of a presentation every check accepted.</summary>
    /// <param name="proofThumbprint">
    /// The thumbprint of the proof the token's binding was confirmed against, or <see langword="null"/> for an unbound
    /// token presented under the <c>Bearer</c> scheme.
    /// </param>
    /// <returns>The permit.</returns>
    internal static DpopResourceDecision Permit(string? proofThumbprint) =>
        new(DpopResourceDecisionKind.Permit, proofThumbprint, null, null);


    /// <summary>The refusal of a presentation a check refused.</summary>
    /// <param name="response">The answer to send.</param>
    /// <param name="check">The name of the refusing check, from <see cref="DpopResourceCheckNames"/>.</param>
    /// <returns>The refusal.</returns>
    internal static DpopResourceDecision Deny(ServerHttpResponse response, string check) =>
        new(DpopResourceDecisionKind.Deny, null, response, check);


    /// <summary>The refusal of a presentation the resource cannot decide on.</summary>
    /// <param name="response">The <c>server_error</c> answer to send.</param>
    /// <param name="check">The name of the refusing check, from <see cref="DpopResourceCheckNames"/>.</param>
    /// <returns>The refusal.</returns>
    internal static DpopResourceDecision IndeterminateDeny(ServerHttpResponse response, string check) =>
        new(DpopResourceDecisionKind.IndeterminateDeny, null, response, check);
}
