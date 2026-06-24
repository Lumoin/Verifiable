using System.Diagnostics;

namespace Verifiable.OAuth.TokenExchange;

/// <summary>
/// The validated claims of a Token Exchange <c>subject_token</c> the application's trust authority
/// has accepted, per
/// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 §2.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// Returned by the application's <see cref="Server.ValidateTokenExchangeTokenDelegate"/> after it has
/// run "the appropriate validation procedures for the indicated token type" (RFC 8693 §2.1) — the
/// signature, the issuer, the timing window, and whatever else the deployment's trust model demands.
/// The library never validates the token itself: which issuers and keys to accept, and any remote
/// key fetch, are the application's concern.
/// </para>
/// <para>
/// A <see langword="null"/> return from the validating delegate means the token is invalid,
/// untrusted, or expired and the request MUST be rejected; a non-null instance means the token is
/// good and carries the claims the authorization step and the issued token are shaped from.
/// </para>
/// </remarks>
[DebuggerDisplay("ValidatedSecurityToken Subject={Subject}, Issuer={Issuer}")]
public sealed record ValidatedSecurityToken
{
    /// <summary>
    /// The subject (<c>sub</c>) of the <c>subject_token</c> — the party on behalf of whom the
    /// request is being made (RFC 8693 §2.1). With impersonation semantics this becomes the subject
    /// of the issued token per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#appendix-A.1.4">RFC 8693 Appendix A.1.4</see>.
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// The issuer (<c>iss</c>) of the <c>subject_token</c>, when the application surfaces it.
    /// </summary>
    public string? Issuer { get; init; }

    /// <summary>
    /// The audience(s) (<c>aud</c>) of the <c>subject_token</c>, when the application surfaces them.
    /// MAY be empty.
    /// </summary>
    public IReadOnlyList<string> Audience { get; init; } = [];

    /// <summary>
    /// The scope associated with the <c>subject_token</c> (the space-delimited <c>scope</c> claim),
    /// when present.
    /// </summary>
    public string? Scope { get; init; }

    /// <summary>
    /// The expiry (<c>exp</c>) of the <c>subject_token</c>, when the application surfaces it. The
    /// issued token's lifetime MAY be influenced by this value per RFC 8693 §2.1.
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>
    /// The <c>act</c> (actor) claim already present on this token, when the application surfaces it
    /// — present when the token is itself a delegated (composite) token. A subsequent exchange nests
    /// this prior <c>act</c> under the new actor to preserve the delegation chain per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> (the
    /// outermost <c>act</c> is the current actor; nested <c>act</c> claims are prior actors). The
    /// value is the nested JSON object exactly as it appears in the token — a
    /// <see cref="IReadOnlyDictionary{TKey, TValue}"/> mirroring the structured-claim shape, with
    /// nested <c>act</c> objects themselves dictionaries. <see langword="null"/> when the token
    /// carries no <c>act</c> claim.
    /// </summary>
    public IReadOnlyDictionary<string, object>? Act { get; init; }

    /// <summary>
    /// The <c>sub</c> of this token's <c>may_act</c> (authorized actor) claim, when present — the
    /// party the subject has authorized to act on its behalf per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC 8693 §4.4</see>. When the
    /// application surfaces it, a delegation exchange MUST reject an <c>actor_token</c> whose subject
    /// is not this value: the subject named whom it permits to act for it, and a different actor is
    /// unauthorized. <see langword="null"/> when the token carries no <c>may_act</c> constraint (the
    /// application applies whatever broader policy its deployment demands).
    /// </summary>
    public string? MayActSubject { get; init; }

    /// <summary>
    /// The <c>iss</c> member of this token's <c>may_act</c> claim, when present — per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC 8693 §4.4</see> "the
    /// combination of the two claims <c>iss</c> and <c>sub</c> are sometimes necessary to uniquely
    /// identify an authorized actor." The validation seam surfaces it from the subject token alongside
    /// <see cref="MayActSubject"/>. When non-null, a delegation exchange MUST reject an
    /// <c>actor_token</c> whose issuer is not this value: the authorized actor is identified by the
    /// issuer/subject combination, so a matching subject under a different issuer is a different —
    /// unauthorized — party. <see langword="null"/> when the <c>may_act</c> claim names no issuer (the
    /// subject constrains the actor by <c>sub</c> alone, or carries no <c>may_act</c> constraint at all).
    /// </summary>
    public string? MayActIssuer { get; init; }
}
