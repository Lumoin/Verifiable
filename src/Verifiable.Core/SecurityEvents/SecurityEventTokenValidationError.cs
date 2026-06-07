namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The reason a Security Event Token failed verification. Verification reports
/// failure as a typed value (alongside a <see langword="null"/> on success)
/// rather than throwing, mirroring the claims-JWT validator family so a receiver
/// can branch on the cause.
/// </summary>
public enum SecurityEventTokenValidationError
{
    /// <summary>The compact serialization was not three parts, or a segment did not decode.</summary>
    Malformed,

    /// <summary>
    /// The protected header lacked the explicit <c>typ</c> of <c>secevent+jwt</c>
    /// required by RFC 8417 §2.3 / SSF §4.1.1.
    /// </summary>
    ExplicitTypeMissing,

    /// <summary>The signature did not verify against the supplied key.</summary>
    SignatureInvalid,

    /// <summary>The <c>iss</c> claim did not match the expected issuer.</summary>
    IssuerMismatch,

    /// <summary>The <c>aud</c> claim did not include the expected audience.</summary>
    AudienceMismatch,

    /// <summary>The <c>iat</c> claim was absent or unparseable.</summary>
    MissingIssuedAt,

    /// <summary>The <c>jti</c> claim was absent (a SET MUST carry one — RFC 8417 §2.2).</summary>
    MissingJwtId,

    /// <summary>The <c>jti</c> was already seen — the SET is a replay.</summary>
    Replayed,

    /// <summary>The <c>events</c> claim was absent or empty (a SET MUST carry at least one event).</summary>
    NoEvents
}
