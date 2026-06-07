namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The reasons a presented DPoP nonce can be rejected by
/// <see cref="ValidateDpopNonceDelegate"/>.
/// </summary>
public enum DpopNonceValidationFailureReason
{
    /// <summary>The nonce string is not parseable in the expected format.</summary>
    Malformed,

    /// <summary>The kid embedded in the nonce is not known to the resolver.</summary>
    UnknownKid,

    /// <summary>
    /// The audience hash inside the nonce does not match the expected
    /// audience URI.
    /// </summary>
    AudienceMismatch,

    /// <summary>
    /// The HMAC tag does not match the recomputed value — the nonce was
    /// tampered with or signed by a different key.
    /// </summary>
    HmacMismatch,

    /// <summary>
    /// The nonce's issuedAt is outside the validity window.
    /// </summary>
    Expired
}
