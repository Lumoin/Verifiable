using Verifiable.Cryptography.Text;
using Verifiable.JCose;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// DPoP-domain VALUES — the configuration defaults and the JWS-header
/// <c>typ</c> value that DPoP proofs carry per
/// <see href="https://www.rfc-editor.org/rfc/rfc9449">RFC 9449</see>.
/// </summary>
/// <remarks>
/// <para>
/// Names that previously lived here moved to their semantic homes after
/// the JCose constants split:
/// </para>
/// <list type="bullet">
///   <item><description>The <c>htm</c>, <c>htu</c>, <c>nonce</c>, <c>ath</c>, <c>jkt</c>
///         JWT/cnf member names live in <see cref="JCose.WellKnownJwtClaimNames"/>.</description></item>
///   <item><description>The <c>use_dpop_nonce</c> and <c>invalid_dpop_proof</c> OAuth
///         error code values live in <see cref="OAuthErrors"/>.</description></item>
///   <item><description>The <c>invalid_token</c> error code value lives in
///         <see cref="OAuthErrors.InvalidToken"/>; it predates this class and
///         is not DPoP-specific.</description></item>
/// </list>
/// <para>
/// What remains here is genuinely DPoP-specific: the JWS <c>typ</c> header
/// VALUE that distinguishes a DPoP proof from any other JWS, plus the
/// binary nonce wire-format byte-length constants and the timing-window
/// defaults the library applies when the application doesn't override.
/// </para>
/// </remarks>
public static class WellKnownDpopValues
{
    /// <summary>The UTF-8 source literal of <see cref="ProofTypeHeader"/>.</summary>
    public static ReadOnlySpan<byte> ProofTypeHeaderUtf8 => "dpop+jwt"u8;

    /// <summary>
    /// The required VALUE of the <c>typ</c> JWS header parameter on DPoP
    /// proofs, per RFC 9449 §4.2. Distinguishes a DPoP proof JWS from
    /// other JWS shapes during structural parse.
    /// </summary>
    public static readonly string ProofTypeHeader = Utf8Constants.ToInternedString(ProofTypeHeaderUtf8);

    /// <summary>
    /// The asymmetric JWS signature algorithms a DPoP proof may use, per RFC 9449 §4.2 —
    /// ECDSA, RSA-SHA2 PKCS#1, RSA-PSS, and EdDSA (symmetric and <c>none</c> excluded).
    /// This is the set <see cref="DpopProofValidator"/> accepts and the value an
    /// authorization server advertises as <c>dpop_signing_alg_values_supported</c>
    /// (RFC 9449 §5.1). Kept in sync with <c>DpopProofValidator.IsDpopProofAlg</c>.
    /// </summary>
    public static readonly IReadOnlyList<string> SupportedSigningAlgorithms =
    [
        WellKnownJwaValues.Es256,
        WellKnownJwaValues.Es384,
        WellKnownJwaValues.Es512,
        WellKnownJwaValues.Rs256,
        WellKnownJwaValues.Rs384,
        WellKnownJwaValues.Rs512,
        WellKnownJwaValues.Ps256,
        WellKnownJwaValues.Ps384,
        WellKnownJwaValues.Ps512,
        WellKnownJwaValues.EdDsa
    ];

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
