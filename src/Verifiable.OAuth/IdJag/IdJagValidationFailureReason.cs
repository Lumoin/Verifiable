namespace Verifiable.OAuth.IdJag;

/// <summary>
/// The reason an Identity Assertion JWT Authorization Grant (ID-JAG) assertion failed the
/// <see cref="IdJagAssertionValidation"/> claim rules of
/// draft-ietf-oauth-identity-assertion-authz-grant §4.4.1 (and the §9.3 same-trust-domain rule).
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
