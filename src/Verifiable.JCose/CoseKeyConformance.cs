namespace Verifiable.JCose;

/// <summary>
/// Pure, format-agnostic consistency checks and per-key-type parameter tables for a COSE_Key
/// (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-7">RFC 9052 §7</see>) that is used as a
/// WebAuthn credential public key.
/// </summary>
/// <remarks>
/// <para>
/// This type holds only the MECHANISM — registry tables and predicates — with no knowledge of the wire
/// format or of when the checks are applied. The WebAuthn-specific POLICY (which of these predicates a
/// credential public key must satisfy, and what happens when one fails) is enforced at the parse boundary
/// in <c>Verifiable.Fido2.AuthenticatorDataReader</c>.
/// </para>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier">W3C Web Authentication Level 3,
/// section 5.8.5: Cryptographic Algorithm Identifier</see> and
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">section 6.5.1: Attested
/// Credential Data</see>.
/// </para>
/// </remarks>
public static class CoseKeyConformance
{
    /// <summary>The EC2 required-and-allowed label set for a WebAuthn credential public key: <c>kty</c>, <c>alg</c>, <c>crv</c>, <c>x</c>, <c>y</c>.</summary>
    private static IReadOnlyList<int> Ec2Labels { get; } = [CoseKeyParameters.Kty, CoseKeyParameters.Alg, CoseKeyParameters.Crv, CoseKeyParameters.X, CoseKeyParameters.Y];

    /// <summary>The OKP required-and-allowed label set for a WebAuthn credential public key: <c>kty</c>, <c>alg</c>, <c>crv</c>, <c>x</c>.</summary>
    private static IReadOnlyList<int> OkpLabels { get; } = [CoseKeyParameters.Kty, CoseKeyParameters.Alg, CoseKeyParameters.Crv, CoseKeyParameters.X];

    /// <summary>The RSA required-and-allowed label set for a WebAuthn credential public key: <c>kty</c>, <c>alg</c>, <c>n</c>, <c>e</c>.</summary>
    private static IReadOnlyList<int> RsaLabels { get; } = [CoseKeyParameters.Kty, CoseKeyParameters.Alg, CoseKeyParameters.RsaN, CoseKeyParameters.RsaE];


    /// <summary>
    /// Determines whether <paramref name="algorithm"/>, <paramref name="keyType"/> and
    /// <paramref name="curve"/> are mutually consistent per the WebAuthn credential public key
    /// algorithm/curve pinning clauses.
    /// </summary>
    /// <param name="algorithm">The COSE algorithm identifier (<c>alg</c>).</param>
    /// <param name="keyType">The COSE key type (<c>kty</c>).</param>
    /// <param name="curve">The COSE curve identifier (<c>crv</c>), or <see langword="null"/> when absent.</param>
    /// <returns>
    /// <see langword="true"/> when <paramref name="algorithm"/> does not pin a curve (the RSA family) or is
    /// not one of the algorithms this table recognises, or when it does pin one and
    /// <paramref name="keyType"/>/<paramref name="curve"/> match the pinned pair; <see langword="false"/>
    /// otherwise.
    /// </returns>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier">W3C Web Authentication Level 3,
    /// section 5.8.5: Cryptographic Algorithm Identifier</see> pins <see cref="WellKnownCoseAlgorithms.Es256"/>
    /// (-7) to <see cref="CoseKeyCurves.P256"/> (1), <see cref="WellKnownCoseAlgorithms.Es384"/> (-35) to
    /// <see cref="CoseKeyCurves.P384"/> (2), <see cref="WellKnownCoseAlgorithms.Es512"/> (-36) to
    /// <see cref="CoseKeyCurves.P521"/> (3), and <see cref="WellKnownCoseAlgorithms.EdDsa"/> (-8) to
    /// <see cref="CoseKeyCurves.Ed25519"/> (6). The <see href="https://www.rfc-editor.org/rfc/rfc9864">RFC
    /// 9864</see> fully-specified ECDSA family pins the same curve as its legacy ES* counterpart —
    /// <see cref="WellKnownCoseAlgorithms.Esp256"/>, <see cref="WellKnownCoseAlgorithms.Esp384"/>, and
    /// <see cref="WellKnownCoseAlgorithms.Esp512"/> — since RFC 9864 only adds an explicit hash binding to
    /// the same signature scheme. <see cref="WellKnownCoseAlgorithms.Es256K"/> (-47) pins
    /// <see cref="CoseKeyCurves.Secp256k1"/> (8) per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8812#section-3">RFC 8812 §3</see>. All EC2/OKP pinned
    /// algorithms also require <paramref name="keyType"/> to match the key type their curve belongs to.
    /// Algorithms that leave curve choice unconstrained (the RSA family) or that this table does not
    /// recognise return <see langword="true"/> — an allowlist elsewhere already rejects unknown algorithms;
    /// this predicate only answers consistency for algorithms it is asked about.
    /// </remarks>
    public static bool IsAlgorithmCurveConsistent(int algorithm, int keyType, int? curve) => algorithm switch
    {
        WellKnownCoseAlgorithms.Es256 or WellKnownCoseAlgorithms.Esp256 => keyType == CoseKeyTypes.Ec2 && curve == CoseKeyCurves.P256,
        WellKnownCoseAlgorithms.Es384 or WellKnownCoseAlgorithms.Esp384 => keyType == CoseKeyTypes.Ec2 && curve == CoseKeyCurves.P384,
        WellKnownCoseAlgorithms.Es512 or WellKnownCoseAlgorithms.Esp512 => keyType == CoseKeyTypes.Ec2 && curve == CoseKeyCurves.P521,
        WellKnownCoseAlgorithms.Es256K => keyType == CoseKeyTypes.Ec2 && curve == CoseKeyCurves.Secp256k1,
        WellKnownCoseAlgorithms.EdDsa => keyType == CoseKeyTypes.Okp && curve == CoseKeyCurves.Ed25519,
        _ => true
    };


    /// <summary>
    /// Determines whether <paramref name="key"/> encodes its EC2 <c>y</c> coordinate in compressed
    /// (sign-bit) form rather than as an uncompressed coordinate.
    /// </summary>
    /// <param name="key">The COSE_Key to inspect.</param>
    /// <returns>
    /// <see langword="true"/> when <see cref="CoseKey.EncodedYCompressionSign"/> is not
    /// <see langword="null"/>; otherwise <see langword="false"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="key"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier">W3C Web Authentication Level 3,
    /// section 5.8.5: Cryptographic Algorithm Identifier</see> requires ES256, ES384, ES512 and their RFC
    /// 9864 fully-specified ESP* counterparts to use the uncompressed point form; EdDSA keys always use a
    /// compressed form in COSE and are exempt from this prohibition.
    /// </remarks>
    public static bool UsesCompressedPointEncoding(CoseKey key)
    {
        ArgumentNullException.ThrowIfNull(key);

        return key.EncodedYCompressionSign is not null;
    }


    /// <summary>
    /// Gets the exact set of top-level COSE_Key parameter labels a WebAuthn credential public key of
    /// <paramref name="keyType"/> MUST carry.
    /// </summary>
    /// <param name="keyType">The COSE key type (<c>kty</c>).</param>
    /// <returns>The required label set, expressed via the <see cref="CoseKeyParameters"/> label constants.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="keyType"/> is not EC2 (2), OKP (1), or RSA (3) — the only key types the WebAuthn
    /// credential public key clause set defines a parameter shape for.
    /// </exception>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">W3C Web Authentication
    /// Level 3, section 6.5.1: Attested Credential Data</see>: "The COSE_Key-encoded credential public key
    /// MUST contain the 'alg' parameter" together with "MUST also contain any additional REQUIRED
    /// parameters stipulated by the relevant key type specification" — <c>x</c>/<c>y</c> for EC2 and
    /// <c>x</c> for OKP per <see href="https://www.rfc-editor.org/rfc/rfc9053#section-7.1">RFC 9053
    /// §7.1</see>, <c>n</c>/<c>e</c> for RSA per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>.
    /// </remarks>
    public static IReadOnlyList<int> RequiredParameterLabels(int keyType) => ResolveLabels(keyType);


    /// <summary>
    /// Gets the exact set of top-level COSE_Key parameter labels a WebAuthn credential public key of
    /// <paramref name="keyType"/> is permitted to carry.
    /// </summary>
    /// <param name="keyType">The COSE key type (<c>kty</c>).</param>
    /// <returns>The allowed label set, expressed via the <see cref="CoseKeyParameters"/> label constants.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="keyType"/> is not EC2 (2), OKP (1), or RSA (3) — the only key types the WebAuthn
    /// credential public key clause set defines a parameter shape for.
    /// </exception>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">W3C Web Authentication
    /// Level 3, section 6.5.1: Attested Credential Data</see>: "MUST NOT contain any other OPTIONAL
    /// parameters". For the three key types this clause set covers, the allowed set coincides with the
    /// required set returned by <see cref="RequiredParameterLabels(int)"/> — every REQUIRED parameter is
    /// mandatory and no additional COSE_Key common parameter (e.g. <c>kid</c>, label 2) is admitted.
    /// </remarks>
    public static IReadOnlyList<int> AllowedParameterLabels(int keyType) => ResolveLabels(keyType);


    /// <summary>
    /// Resolves the shared required-and-allowed label table for <paramref name="keyType"/> — the single
    /// backing lookup for both <see cref="RequiredParameterLabels(int)"/> and
    /// <see cref="AllowedParameterLabels(int)"/>, which return the same set for every key type this clause
    /// set covers.
    /// </summary>
    /// <param name="keyType">The COSE key type (<c>kty</c>).</param>
    /// <returns>The label set for <paramref name="keyType"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="keyType"/> is not EC2 (2), OKP (1), or RSA (3).
    /// </exception>
    private static IReadOnlyList<int> ResolveLabels(int keyType) => keyType switch
    {
        CoseKeyTypes.Ec2 => Ec2Labels,
        CoseKeyTypes.Okp => OkpLabels,
        CoseKeyTypes.Rsa => RsaLabels,
        _ => throw new ArgumentOutOfRangeException(
            nameof(keyType),
            keyType,
            "The WebAuthn credential public key clause set (section 6.5.1) defines a parameter shape only for EC2 (2), OKP (1), and RSA (3) key types.")
    };
}
