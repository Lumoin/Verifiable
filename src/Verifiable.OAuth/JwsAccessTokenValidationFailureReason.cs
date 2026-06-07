namespace Verifiable.OAuth;

/// <summary>
/// The discrete reasons a JWS-signed access token can be rejected per
/// RFC 7519 (JWT), RFC 9068 (JWT Profile for OAuth Access Tokens), and
/// RFC 8725 (JWT BCP). The set is closed; new reasons land as additional
/// cases.
/// </summary>
public enum JwsAccessTokenValidationFailureReason
{
    /// <summary>The token string is not parseable as a three-part compact JWS.</summary>
    Malformed,

    /// <summary>The header is missing required members or carries unrecognised shapes.</summary>
    InvalidHeader,

    /// <summary>
    /// The token's <c>alg</c> is missing, is <c>none</c>, or is not in the
    /// caller's accepted set per RFC 8725 §3.1.
    /// </summary>
    AlgorithmNotAllowed,

    /// <summary>The header's <c>kid</c> could not be resolved to a verification key.</summary>
    UnknownKid,

    /// <summary>The signature does not verify against the resolved key.</summary>
    SignatureFailed,

    /// <summary>The payload is missing a required claim (<c>iss</c>, <c>aud</c>, <c>exp</c>, <c>iat</c>, <c>sub</c>).</summary>
    MissingRequiredClaim,

    /// <summary>The <c>iss</c> claim does not equal the expected issuer (ordinal string match).</summary>
    IssuerMismatch,

    /// <summary>The <c>aud</c> claim does not contain the expected audience.</summary>
    AudienceMismatch,

    /// <summary>The <c>exp</c> claim is at or before the current instant.</summary>
    Expired,

    /// <summary>The <c>nbf</c> claim is in the future.</summary>
    NotYetValid,

    /// <summary>The <c>iat</c> claim is in the future beyond the caller's skew tolerance.</summary>
    IssuedInFuture,

    /// <summary>
    /// The temporal claims are mutually inconsistent regardless of the current clock — <c>exp</c> is at
    /// or before <c>iat</c> (non-positive lifetime), or <c>exp</c> is at or before <c>nbf</c> (the
    /// validity window never opens). A structurally nonsensical token.
    /// </summary>
    InconsistentTemporalClaims,

    /// <summary>
    /// The token has multiple audiences but no <c>azp</c> (authorized party) claim, so the recipient
    /// cannot confirm the token was issued for it — OIDC Core §3.1.3.7. Reported only when the caller
    /// supplied an expected authorized party.
    /// </summary>
    AuthorizedPartyMissing,

    /// <summary>
    /// The <c>azp</c> (authorized party) claim is present but does not equal the caller's expected
    /// authorized party (its own client_id) — OIDC Core §3.1.3.7.
    /// </summary>
    AuthorizedPartyMismatch,
}
