namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The discrete reasons a DPoP proof can be rejected, per RFC 9449
/// §4.3 and §11. The set is closed; new reasons land as additional cases.
/// </summary>
public enum DpopProofValidationFailureReason
{
    /// <summary>
    /// The proof is not a well-formed DPoP proof (RFC 9449 section 4.3 check 2): no compact JWS of three parts, a part that is
    /// no one JSON object or that repeats a member name, or a member of the header, the claims set or the embedded key the
    /// reading refuses by its own rule - absent where it is required, of another kind than it is defined as, or established to
    /// contradict another member. A member whose relation to another the reading does not establish is
    /// <see cref="UnsupportedOrUnestablished"/>, never this.
    /// </summary>
    Malformed,

    /// <summary>
    /// The <c>typ</c> header is missing or does not name the <c>dpop+jwt</c> media type; the long
    /// form <c>application/dpop+jwt</c> and any casing of either spelling name that same media type
    /// per <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9">RFC 7515 §4.1.9</see>.
    /// </summary>
    InvalidTyp,

    /// <summary>
    /// The <c>alg</c> header is missing, not an acceptable algorithm, or not an algorithm of the key the
    /// <c>jwk</c> header carries, so it does not accurately represent the algorithm the signature is
    /// validated under (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 §5.2</see>
    /// step 8: "which MUST be accurately represented by the value of the "alg" (algorithm) Header
    /// Parameter").
    /// </summary>
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

    /// <summary>
    /// The embedded key carries a member whose relation to the key or to another member the validation does not establish: a
    /// <c>use</c> or a <c>key_ops</c> operation outside the registered vocabulary beside the other (RFC 7517 section 4.3), or an
    /// <c>x5c</c> whose first certificate's key is of a type, curve or algorithm the certificate judgement compares none of
    /// (section 4.7). The proof is not established to be malformed or inconsistent; it is refused because a judgement its
    /// acceptance rests on is not made. The part refusal the result carries names the member and its detailed defect.
    /// </summary>
    UnsupportedOrUnestablished,
}
