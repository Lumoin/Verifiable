namespace Verifiable.OAuth.Dpop;

/// <summary>
/// Well-known constants used in DPoP per
/// <see href="https://www.rfc-editor.org/rfc/rfc9449">RFC 9449</see>.
/// </summary>
public static class WellKnownDpopValues
{
    /// <summary>
    /// The required value of the <c>typ</c> JWS header parameter on DPoP
    /// proofs, per RFC 9449 §4.2.
    /// </summary>
    public static readonly string ProofTypeHeader = "dpop+jwt";

    /// <summary>
    /// The error code returned by an AS or RS that requires a fresh
    /// nonce-bearing proof, per RFC 9449 §8 and §9.
    /// </summary>
    public static readonly string UseDpopNonceError = "use_dpop_nonce";

    /// <summary>
    /// The error code returned when a proof is structurally invalid,
    /// missing required claims, or fails signature/binding verification.
    /// </summary>
    public static readonly string InvalidDpopProofError = "invalid_dpop_proof";

    /// <summary>
    /// The error code returned when an access token presented with DPoP
    /// scheme cannot be bound to the supplied proof.
    /// </summary>
    public static readonly string InvalidTokenError = "invalid_token";

    /// <summary>
    /// Default replay-protection window for the <c>(jti, iat)</c> cache.
    /// RFC 9449 §11.1 recommends a small window; 5 minutes matches typical
    /// deployments.
    /// </summary>
    public static readonly TimeSpan DefaultReplayWindow = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Maximum tolerated skew between the proof's <c>iat</c> claim and the
    /// receiver's current time, in either direction.
    /// </summary>
    public static readonly TimeSpan DefaultIatSkew = TimeSpan.FromSeconds(30);

    /// <summary>
    /// The <c>htm</c> claim name per RFC 9449 §4.2 — the HTTP method the
    /// proof authorises.
    /// </summary>
    public static readonly string ClaimHtm = "htm";

    /// <summary>
    /// The <c>htu</c> claim name per RFC 9449 §4.2 — the HTTP URI the
    /// proof authorises (origin + path; no query, no fragment).
    /// </summary>
    public static readonly string ClaimHtu = "htu";

    /// <summary>
    /// The <c>nonce</c> claim name per RFC 9449 §8.1 — the server-issued
    /// nonce being echoed.
    /// </summary>
    public static readonly string ClaimNonce = "nonce";

    /// <summary>
    /// The <c>ath</c> claim name per RFC 9449 §4.3 — base64url SHA-256 of
    /// the access token presented alongside the proof.
    /// </summary>
    public static readonly string ClaimAth = "ath";

    /// <summary>
    /// The <c>jkt</c> member name within an RFC 7800 <c>cnf</c> claim per
    /// RFC 9449 §6.1 — the base64url-encoded RFC 7638 JWK thumbprint of
    /// the public key the access token is sender-constrained to.
    /// </summary>
    public static readonly string ConfirmationJwkThumbprint = "jkt";

    /// <summary>
    /// The length in bytes of the issuedAt field inside a binary-packed nonce.
    /// Encoded as Unix seconds in an int64 big-endian.
    /// </summary>
    public static readonly int NonceIssuedAtByteLength = 8;

    /// <summary>
    /// The length in bytes of the audience hash inside a binary-packed nonce.
    /// Computed as the first half of SHA-256 of the audience URI's
    /// <see cref="Uri.OriginalString"/>.
    /// </summary>
    public static readonly int NonceAudienceHashByteLength = 16;

    /// <summary>
    /// The length in bytes of the random field inside a binary-packed nonce.
    /// 128 bits is sufficient for collision resistance under agent-ready
    /// issuance volumes.
    /// </summary>
    public static readonly int NonceRandomByteLength = 16;

    /// <summary>
    /// The length in bytes of the HMAC-SHA-256 tag at the end of a binary-packed
    /// nonce. Matches the natural HMAC-SHA-256 output length.
    /// </summary>
    public static readonly int NonceHmacTagByteLength = 32;

    /// <summary>
    /// Default validity window for issued nonces. Validation accepts nonces
    /// whose <c>issuedAt</c> falls inside <c>now ± DefaultNonceValidityWindow</c>.
    /// 5 minutes matches the replay-window default.
    /// </summary>
    public static readonly TimeSpan DefaultNonceValidityWindow = TimeSpan.FromMinutes(5);
}
