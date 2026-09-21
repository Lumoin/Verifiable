namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The discrete reasons a DPoP proof can be rejected, per RFC 9449
/// §4.3 and §11. The set is closed; new reasons land as additional cases.
/// </summary>
public enum DpopProofValidationFailureReason
{
    /// <summary>The proof string is not parseable as a compact JWS.</summary>
    Malformed,

    /// <summary>
    /// The <c>typ</c> header is missing or does not name the <c>dpop+jwt</c> media type; the long
    /// form <c>application/dpop+jwt</c> and any casing of either spelling name that same media type
    /// per <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9">RFC 7515 §4.1.9</see>.
    /// </summary>
    InvalidTyp,

    /// <summary>The <c>alg</c> header is missing or not an acceptable algorithm.</summary>
    InvalidAlg,

    /// <summary>The <c>jwk</c> header is missing or malformed.</summary>
    InvalidJwk,

    /// <summary>
    /// The <c>jwk</c> header carries private or symmetric key material (RFC 7518
    /// <c>d</c>/<c>p</c>/<c>q</c>/<c>dp</c>/<c>dq</c>/<c>qi</c>/<c>oth</c>/<c>k</c>).
    /// A DPoP proof's JWK MUST be a public key per RFC 9449 §4.2.
    /// </summary>
    JwkContainsPrivateKey,

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
