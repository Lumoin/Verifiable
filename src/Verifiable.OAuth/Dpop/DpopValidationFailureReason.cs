namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The discrete reasons a DPoP proof can be rejected, per RFC 9449
/// §4.3 and §11. The set is closed; new reasons land as additional cases.
/// </summary>
public enum DpopValidationFailureReason
{
    /// <summary>The proof string is not parseable as a compact JWS.</summary>
    Malformed,

    /// <summary>The <c>typ</c> header is missing or not <c>dpop+jwt</c>.</summary>
    InvalidTyp,

    /// <summary>The <c>alg</c> header is missing or not an acceptable algorithm.</summary>
    InvalidAlg,

    /// <summary>The <c>jwk</c> header is missing or malformed.</summary>
    InvalidJwk,

    /// <summary>The proof's signature does not verify against the embedded JWK.</summary>
    SignatureFailed,

    /// <summary>The <c>htm</c> claim does not match the request method.</summary>
    HtmMismatch,

    /// <summary>The <c>htu</c> claim does not match the normalised request URI.</summary>
    HtuMismatch,

    /// <summary>The <c>iat</c> claim is outside the receiver's skew tolerance.</summary>
    IatOutOfWindow,

    /// <summary>The <c>nonce</c> claim is missing when a nonce was required.</summary>
    NonceMissing,

    /// <summary>The <c>nonce</c> claim does not match the receiver's expectation.</summary>
    NonceMismatch,

    /// <summary>The <c>ath</c> claim does not match the presented access token.</summary>
    AthMismatch,
}
