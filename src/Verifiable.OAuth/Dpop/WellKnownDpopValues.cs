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
    public static ReadOnlySpan<byte> ProofTypeHeaderUtf8 => WellKnownMediaTypes.Jwt.DpopJwtUtf8;

    /// <summary>
    /// The required VALUE of the <c>typ</c> JWS header parameter on DPoP proofs, per RFC 9449
    /// §4.2. An alias of <see cref="WellKnownMediaTypes.Jwt.DpopJwt"/> — the one home of the
    /// literal — kept here so callers already using this DPoP-domain class find the wire's
    /// <c>typ</c> value beside the other DPoP constants.
    /// </summary>
    public static string ProofTypeHeader { get; } = WellKnownMediaTypes.Jwt.DpopJwt;

    /// <summary>
    /// The default policy of the DPoP proof algorithm slot: the JWS <c>alg</c> values the library's authorization
    /// server accepts for a DPoP proof, and publishes as <c>dpop_signing_alg_values_supported</c>, when the host names
    /// no list of its own (<see cref="Server.AuthorizationServerCryptography.ResolveSupportedSigningAlgorithmsAsync"/>
    /// for <see cref="Verifiable.Cryptography.Context.KeyUsageContext.DpopProof"/>, defaulting through
    /// <see cref="Server.Metadata.DefaultSupportedSigningAlgorithms.ResolveAsync"/>), and the <c>algs</c> the library's
    /// protected resources name in a <c>DPoP</c> challenge. In this order: the ECDSA identifiers <c>ES256</c>,
    /// <c>ES384</c>, <c>ES512</c> and <c>ES256K</c>, the RSA PKCS#1 v1.5 identifiers <c>RS256</c>, <c>RS384</c> and
    /// <c>RS512</c>, the RSA-PSS identifiers <c>PS256</c>, <c>PS384</c> and <c>PS512</c>, <c>EdDSA</c>, and the
    /// fully-specified <c>Ed25519</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5.1">RFC 9449 Section 5.1</see>:
    /// "dpop_signing_alg_values_supported: A JSON array containing a list of the JWS alg values (from the
    /// [IANA.JOSE.ALGS] registry) supported by the authorization server for DPoP proof JWTs." The list is the acceptance
    /// policy the library's servers apply and publish. Each is an identifier a DPoP proof may be signed under
    /// (<see cref="WellKnownJwaValues.IsAsymmetricSignatureAlgorithm(string)"/>,
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>) and one the library's
    /// validator binds to the family of a proof's public key: <c>ES256K</c>, registered by
    /// <see href="https://www.rfc-editor.org/rfc/rfc8812#section-4.3">RFC 8812 Section 4.3</see> ("Algorithm Name:
    /// ES256K Algorithm Description: ECDSA using secp256k1 curve and SHA-256"), to a secp256k1 public key, and
    /// <c>Ed25519</c>, registered by <see href="https://www.rfc-editor.org/rfc/rfc9864#section-4.1.1">RFC 9864 Section
    /// 4.1.1</see> ("Algorithm Name: Ed25519 Algorithm Description: EdDSA using the Ed25519 parameter set in Section 5.1
    /// of [RFC8032]"), to an Ed25519 public key, as <c>EdDSA</c> is. The Brainpool ECDSA and the ML-DSA identifiers a
    /// proof may also be signed under are left out, since the validator binds no public key family to them.
    /// </para>
    /// <para>
    /// The list names what the library's servers accept and publish; it verifies nothing. A host verifies a proof's
    /// signature through the providers it registered in the cryptographic function registry, the overload of
    /// <see cref="DpopProofValidator"/> without a <see cref="Verifiable.Cryptography.VerificationDelegate"/> (which
    /// <see cref="DefaultDpopProofValidation"/> runs when the host assigns no proof validator), where the tag of the
    /// proof's public key selects the provider; or through the primitive it bound, the overload that takes a
    /// <see cref="Verifiable.Cryptography.VerificationDelegate"/>. Either way the host's registry or its delegate must
    /// serve every family the host accepts: a proof under an accepted identifier of a family it does not serve is
    /// refused <see cref="DpopProofValidationFailureReason.SignatureFailed"/>. An RSA public key reconstructed from a
    /// proof's <c>jwk</c> is tagged by the proof's <c>alg</c>: under <c>RS256</c> with its size tag, which the registry
    /// serves as RSASSA-PKCS1-v1_5 with SHA-256, and under each other RSA identifier with the tag of the scheme it names,
    /// so the registry serves the scheme the proof names. A host whose registry serves fewer RSA schemes narrows its
    /// list to them.
    /// </para>
    /// <para>
    /// <c>EdDSA</c> is Deprecated in JOSE by <see href="https://www.rfc-editor.org/rfc/rfc9864#section-4.1.2">RFC 9864
    /// Section 4.1.2</see> ("IANA has updated the status to "Deprecated" for the following registration. Algorithm Name:
    /// EdDSA ... JOSE Implementation Requirements: Deprecated"), Section 4.4 defining the term: "There is a preferred
    /// mechanism to achieve functionality similar to that referenced by the identifier; this replacement functionality
    /// SHOULD be utilized in new deployments in preference to the deprecated identifier". It is kept beside its
    /// replacement <c>Ed25519</c> for interoperability with clients that sign under it.
    /// </para>
    /// <para>
    /// A host narrows or widens what its authorization server accepts by answering its own list from the slot; the list
    /// it answers is both what its metadata publishes and what its token endpoint and pushed authorization request
    /// accept (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 5: "is
    /// supported by the application, and is acceptable per local policy").
    /// </para>
    /// </remarks>
    public static IReadOnlyList<string> SupportedSigningAlgorithms { get; } =
    [
        WellKnownJwaValues.Es256,
        WellKnownJwaValues.Es384,
        WellKnownJwaValues.Es512,
        WellKnownJwaValues.Es256K,
        WellKnownJwaValues.Rs256,
        WellKnownJwaValues.Rs384,
        WellKnownJwaValues.Rs512,
        WellKnownJwaValues.Ps256,
        WellKnownJwaValues.Ps384,
        WellKnownJwaValues.Ps512,
        WellKnownJwaValues.EdDsa,
        WellKnownJwaValues.Ed25519
    ];

    /// <summary>
    /// The value of the <c>Access-Control-Expose-Headers</c> field (<see cref="WellKnownHttpHeaderNames.AccessControlExposeHeaders"/>)
    /// the library writes on every response that carries a <c>DPoP-Nonce</c> field or a <c>DPoP</c> challenge,
    /// <c>WWW-Authenticate, DPoP-Nonce</c>: the two field names, joined by <c>, </c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "In order for the
    /// application to obtain and use the WWW-Authenticate HTTP response header value, the server needs to make it
    /// available to the application by including WWW-Authenticate in the Access-Control-Expose-Headers response header
    /// list value." and <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">Section 8</see>: "In order for the
    /// application to obtain and use the DPoP-Nonce HTTP response header value, the server needs to make it available
    /// to the application by including DPoP-Nonce in the Access-Control-Expose-Headers response header list value."
    /// The field is written whether or not the request names an <c>Origin</c>: the library reads no <c>Origin</c>, and
    /// the CORS policy, <c>Access-Control-Allow-Origin</c> among it, is the host's, so the field has effect only where
    /// the host's CORS layer admits the origin.
    /// </summary>
    internal static string ExposedDpopResponseFields { get; } =
        $"{WellKnownHttpHeaderNames.WwwAuthenticate}, {WellKnownHttpHeaderNames.DPoPNonce}";

    /// <summary>
    /// Default replay-protection window for the <c>(jti, iat)</c> cache.
    /// RFC 9449 §11.1 recommends a small window; 5 minutes matches typical
    /// deployments.
    /// </summary>
    public static TimeSpan DefaultReplayWindow { get; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Maximum tolerated skew between the proof's <c>iat</c> claim and the
    /// receiver's current time, in either direction.
    /// </summary>
    public static TimeSpan DefaultIatSkew { get; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// The length in bytes of the issuedAt field inside a binary-packed nonce.
    /// Encoded as Unix seconds in an int64 big-endian.
    /// </summary>
    public static int NonceIssuedAtByteLength { get; } = 8;

    /// <summary>
    /// The length in bytes of the audience hash inside a binary-packed nonce.
    /// Computed as the first half of SHA-256 of the audience URI's
    /// <see cref="Uri.OriginalString"/>.
    /// </summary>
    public static int NonceAudienceHashByteLength { get; } = 16;

    /// <summary>
    /// The length in bytes of the random field inside a binary-packed nonce.
    /// 128 bits is sufficient for collision resistance under agent-ready
    /// issuance volumes.
    /// </summary>
    public static int NonceRandomByteLength { get; } = 16;

    /// <summary>
    /// The length in bytes of the HMAC-SHA-256 tag at the end of a binary-packed
    /// nonce. Matches the natural HMAC-SHA-256 output length.
    /// </summary>
    public static int NonceHmacTagByteLength { get; } = 32;

    /// <summary>
    /// Default validity window for issued nonces. Validation accepts nonces
    /// whose <c>issuedAt</c> falls inside <c>now ± DefaultNonceValidityWindow</c>.
    /// 5 minutes matches the replay-window default.
    /// </summary>
    public static TimeSpan DefaultNonceValidityWindow { get; } = TimeSpan.FromMinutes(5);
}
