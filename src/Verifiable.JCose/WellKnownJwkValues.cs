using Verifiable.Cryptography.Text;


namespace Verifiable.JCose
{
    /// <summary>
    /// Well-known JWK member VALUES — the strings that appear AS values inside
    /// JWK / JOSE JSON members. Distinct from
    /// <see cref="WellKnownJwkMemberNames"/> (the names of JWK members),
    /// <see cref="WellKnownJoseHeaderNames"/> (the names of JOSE header
    /// parameters), and <see cref="WellKnownJwtClaimNames"/> (the names of JWT
    /// payload claims). Per RFC 7517 parameter values are case-sensitive.
    /// </summary>
    /// <remarks>
    /// <para>
    /// More-specific value families live in dedicated classes:
    /// <see cref="WellKnownKeyTypeValues"/> for <c>kty</c> values
    /// (<c>EC</c>, <c>RSA</c>, <c>oct</c>, <c>OKP</c>);
    /// <see cref="WellKnownCurveValues"/> for <c>crv</c> values
    /// (<c>P-256</c>, <c>Ed25519</c>, etc.);
    /// <see cref="WellKnownJwaValues"/> for <c>alg</c> values
    /// (<c>ES256</c>, <c>RS256</c>, etc.). This class holds the small set of
    /// generic values not covered by those.
    /// </para>
    /// </remarks>
    public static class WellKnownJwkValues
    {
        //Values of the "use" (Public Key Use) parameter — RFC 7517 §4.2.

        /// <summary>The UTF-8 source literal of <see cref="UseSig"/>.</summary>
        public static ReadOnlySpan<byte> UseSigUtf8 => "sig"u8;

        /// <summary>
        /// The <c>sig</c> value for the <see cref="WellKnownJwkMemberNames.Use"/> parameter,
        /// indicating the key is used for computing digital signatures or MACs per
        /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.2">RFC 7517 §4.2</see>.
        /// </summary>
        public static readonly string UseSig = Utf8Constants.ToInternedString(UseSigUtf8);

        /// <summary>The UTF-8 source literal of <see cref="UseEnc"/>.</summary>
        public static ReadOnlySpan<byte> UseEncUtf8 => "enc"u8;

        /// <summary>
        /// The <c>enc</c> value for the <see cref="WellKnownJwkMemberNames.Use"/> parameter,
        /// indicating the key is used for encryption per
        /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.2">RFC 7517 §4.2</see>.
        /// </summary>
        /// <remarks>
        /// Distinct from <see cref="WellKnownJoseHeaderNames.Enc"/> which is the
        /// JWE header parameter NAME (also the string <c>"enc"</c>) per RFC 7516 §4.1.2.
        /// Same string, different semantic context.
        /// </remarks>
        public static readonly string UseEnc = Utf8Constants.ToInternedString(UseEncUtf8);


        //Values of the "typ" (Type) header parameter — RFC 7519 §5.1.

        /// <summary>The UTF-8 source literal of <see cref="TypeJwt"/>.</summary>
        public static ReadOnlySpan<byte> TypeJwtUtf8 => "JWT"u8;

        /// <summary>
        /// The <c>JWT</c> value for the <see cref="WellKnownJoseHeaderNames.Typ"/> parameter
        /// per <see href="https://www.rfc-editor.org/rfc/rfc7519#section-5.1">RFC 7519 §5.1</see>.
        /// Spelled uppercase for compatibility with legacy implementations.
        /// </summary>
        public static readonly string TypeJwt = Utf8Constants.ToInternedString(TypeJwtUtf8);


        /// <summary>Whether <paramref name="value"/> is <see cref="UseSig"/>.</summary>
        public static bool IsUseSig(string value) => Equals(value, UseSig);

        /// <summary>Whether <paramref name="value"/> is <see cref="UseEnc"/>.</summary>
        public static bool IsUseEnc(string value) => Equals(value, UseEnc);

        /// <summary>Whether <paramref name="value"/> is <see cref="TypeJwt"/>.</summary>
        public static bool IsTypeJwt(string value) => Equals(value, TypeJwt);


        /// <summary>
        /// Returns the interned constant for a known JWK / JOSE value, or the
        /// original string if unrecognized.
        /// </summary>
        public static string GetCanonicalizedValue(string value) => value switch
        {
            _ when IsUseSig(value) => UseSig,
            _ when IsUseEnc(value) => UseEnc,
            _ when IsTypeJwt(value) => TypeJwt,
            _ => value
        };


        /// <summary>
        /// Compares two well-known values for equality. Comparison is case-sensitive
        /// per RFC 7517.
        /// </summary>
        public static bool Equals(string valueA, string valueB) =>
            object.ReferenceEquals(valueA, valueB) || StringComparer.Ordinal.Equals(valueA, valueB);
    }
}
