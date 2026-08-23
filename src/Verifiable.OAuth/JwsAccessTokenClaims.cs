using System.Diagnostics;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth;

/// <summary>
/// Typed view of the claims extracted from a successfully-validated
/// JWS-signed access token per RFC 7519 and RFC 9068. Returned in
/// <see cref="JwsAccessTokenValidationResult.Claims"/> on success; the
/// resource server reads these instead of re-parsing the JWT payload
/// directly.
/// </summary>
/// <remarks>
/// <para>
/// Absent optional claims are surfaced as <see langword="null"/>. The
/// validator populates <see cref="Confirmation"/> from the <c>cnf</c>
/// claim per RFC 7800 §3 / RFC 9449 §6.1; consumers compare its
/// <see cref="ConfirmationMethod.JwkThumbprint"/> against the proof
/// thumbprint returned by
/// <see cref="Verifiable.OAuth.Dpop.DpopProofValidator.ValidateAsync"/>
/// to enforce DPoP binding.
/// </para>
/// <para>
/// When the token records a delegation, <see cref="Act"/> carries the
/// RFC 8693 §4.1 actor. The access-control surface of this record is
/// bounded by that section's consumer MUST: "For the purpose of applying
/// access control policy, the consumer of a token MUST only consider the
/// token's top-level claims and the party identified as the current actor
/// by the 'act' claim. Prior actors identified by any nested 'act' claims
/// are informational only and are not to be considered in access control
/// decisions." A decision is therefore made from the members of this
/// record plus <see cref="CurrentActor.Subject"/>/
/// <see cref="CurrentActor.Issuer"/>;
/// <see cref="CurrentActor.DelegationHistory"/> is history for audit and
/// diagnostics, never an authorization input.
/// </para>
/// </remarks>
[DebuggerDisplay("JwsAccessTokenClaims Sub={Subject,nq} Iss={Issuer,nq}")]
public sealed record JwsAccessTokenClaims
{
    /// <summary>RFC 7519 §4.1.2 <c>sub</c> — the subject identifier.</summary>
    public required string Subject { get; init; }

    /// <summary>RFC 7519 §4.1.1 <c>iss</c> — the issuer identifier. Compared by ordinal equality.</summary>
    public required string Issuer { get; init; }

    /// <summary>
    /// RFC 7519 §4.1.3 <c>aud</c> — the audience values. RFC 9068 §4 permits
    /// either a single string or array; the validator normalises both shapes
    /// into this list.
    /// </summary>
    public required IReadOnlyList<string> Audience { get; init; }

    /// <summary>RFC 7519 §4.1.6 <c>iat</c> — issuance instant.</summary>
    public required DateTimeOffset IssuedAt { get; init; }

    /// <summary>RFC 7519 §4.1.4 <c>exp</c> — expiry instant.</summary>
    public required DateTimeOffset Expiration { get; init; }

    /// <summary>RFC 7519 §4.1.5 <c>nbf</c> — not-before instant. <see langword="null"/> when absent.</summary>
    public DateTimeOffset? NotBefore { get; init; }

    /// <summary>RFC 9068 §2.2 <c>client_id</c> — the client identifier.</summary>
    public string? ClientId { get; init; }

    /// <summary>
    /// OIDC Core §2 <c>azp</c> — the authorized party the token was issued to. <see langword="null"/>
    /// when absent. When present it must equal the recipient's own client identifier (OIDC §3.1.3.7);
    /// the validator enforces that when the caller supplies an expected authorized party.
    /// </summary>
    public string? AuthorizedParty { get; init; }

    /// <summary>RFC 9068 §2.2 <c>scope</c> — space-separated granted scopes.</summary>
    public string? Scope { get; init; }

    /// <summary>RFC 7519 §4.1.7 <c>jti</c> — the token's unique identifier.</summary>
    public string? JwtId { get; init; }

    /// <summary>
    /// RFC 7800 §3 <c>cnf</c> — the confirmation method binding the token to
    /// a proof of possession key. <see langword="null"/> when the token is
    /// not sender-constrained.
    /// </summary>
    public ConfirmationMethod? Confirmation { get; init; }

    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> <c>act</c> —
    /// the current actor: the party to whom <see cref="Subject"/> delegated authority, together with
    /// the prior actors of the delegation chain as read-only history. <see langword="null"/> when the
    /// token records no delegation, which per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-1.1">RFC 8693 §1.1</see> means the
    /// subject is acting directly or the token is an impersonation token in which the actor is
    /// deliberately indistinguishable from the subject. Only <see cref="CurrentActor.Subject"/> and
    /// <see cref="CurrentActor.Issuer"/> may take part in an access-control decision; see that type's
    /// remarks for the §4.1 consumer MUST that scopes them.
    /// </summary>
    public CurrentActor? Act { get; init; }

    /// <summary>
    /// The <c>sub</c> member of the token's <c>may_act</c> (authorized actor) claim, when present —
    /// the party the token's subject has authorized to become the actor and act on its behalf per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC 8693 §4.4</see>. A resource
    /// server that itself exchanges this token onward reads it to know whom the subject permits to
    /// act for it; it says nothing about who is acting now (that is <see cref="Act"/>).
    /// <see langword="null"/> when the token carries no <c>may_act</c> constraint.
    /// </summary>
    public string? MayActSubject { get; init; }

    /// <summary>
    /// The <c>iss</c> member of the token's <c>may_act</c> claim, when present — per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC 8693 §4.4</see> "the
    /// combination of the two claims <c>iss</c> and <c>sub</c> are sometimes necessary to uniquely
    /// identify an authorized actor", so a matching <see cref="MayActSubject"/> under a different
    /// issuer is a different — unauthorized — party. <see langword="null"/> when the <c>may_act</c>
    /// claim names no issuer, or when the token carries no <c>may_act</c> constraint at all.
    /// </summary>
    public string? MayActIssuer { get; init; }
}
