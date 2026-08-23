namespace Verifiable.OAuth.IdJag;

/// <summary>
/// The reason an Identity Assertion JWT Authorization Grant (ID-JAG) assertion failed the
/// <see cref="IdJagAssertionValidation"/> claim rules of
/// draft-ietf-oauth-identity-assertion-authz-grant-04 (21 May 2026) §4.4.1 (and the §9.3 same-trust-domain rule).
/// Every value maps a Resource Authorization Server to the <c>invalid_grant</c> rejection the
/// processing rules mandate.
/// </summary>
public enum IdJagValidationFailureReason
{
    /// <summary>The JWT <c>typ</c> header is not <c>oauth-id-jag+jwt</c> (§4.4.1 / RFC 8725 §3.11).</summary>
    InvalidType,

    /// <summary>The <c>iss</c> claim is absent.</summary>
    MissingIssuer,

    /// <summary>
    /// The <c>iss</c> claim equals the Resource Authorization Server's own issuer identifier — the
    /// grant was issued in the same trust domain, which §9.3 forbids redeeming for an access token.
    /// </summary>
    SameTrustDomain,

    /// <summary>The <c>aud</c> claim is absent.</summary>
    MissingAudience,

    /// <summary>
    /// The <c>aud</c> claim does not name the Resource Authorization Server's issuer identifier, or is
    /// an array that does not contain exactly one element equal to it (§4.4.1 — audience injection).
    /// </summary>
    AudienceMismatch,

    /// <summary>The <c>client_id</c> claim is absent.</summary>
    MissingClientId,

    /// <summary>The <c>client_id</c> claim does not match the authenticated client (§4.4.1 client continuity).</summary>
    ClientMismatch,

    /// <summary>The <c>sub</c> claim is absent (RFC 7521 §5.2 / RFC 7523 §3 rule 2).</summary>
    MissingSubject,

    /// <summary>
    /// The <c>cnf</c> claim is present but carries no usable <c>jkt</c> thumbprint (§9.8.1). A grant
    /// asserting a confirmation the Resource Authorization Server cannot honor is rejected rather than
    /// silently downgraded to an unbound Bearer token.
    /// </summary>
    MalformedConfirmation,

    /// <summary>
    /// The <c>act</c> claim is present but is not an
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> actor object —
    /// not a JSON object, naming no <c>sub</c>, nesting a prior actor that is itself not an actor
    /// object, or nesting deeper than a delegation chain can reach. A grant asserting a delegation the
    /// Resource Authorization Server cannot read is rejected rather than redeemed as if no delegation
    /// had occurred, which would silently drop the acting party from the issued access token.
    /// </summary>
    MalformedActor,

    /// <summary>
    /// The <c>may_act</c> claim is present but is not an
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC 8693 §4.4</see>
    /// authorized-actor object — not a JSON object, or naming neither a <c>sub</c> nor an <c>iss</c> to
    /// identify the party eligible to act. A grant whose actor constraint cannot be read is rejected
    /// rather than redeemed unconstrained, which would let a malformed claim bypass the constraint
    /// entirely.
    /// </summary>
    MalformedAuthorizedActor,

    /// <summary>The <c>exp</c> claim is absent (RFC 7521 §5.2).</summary>
    MissingExpiration,

    /// <summary>The grant has expired (<c>exp</c> at or before now, within skew).</summary>
    Expired,

    /// <summary>The grant is not yet valid (<c>nbf</c> after now, beyond skew).</summary>
    NotYetValid,

    /// <summary>
    /// The temporal claims are internally inconsistent — <c>exp</c> at or before <c>iat</c> or
    /// <c>nbf</c> (the validity window never opens, independent of the current clock), or an
    /// <c>exp</c>/<c>iat</c>/<c>nbf</c> claim that is present but not a numeric timestamp.
    /// </summary>
    InconsistentTemporalClaims
}
