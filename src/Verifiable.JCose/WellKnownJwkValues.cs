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
        public static string UseSig { get; } = Utf8Constants.ToInternedString(UseSigUtf8);

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
        public static string UseEnc { get; } = Utf8Constants.ToInternedString(UseEncUtf8);


        //Values of the "key_ops" (Key Operations) parameter — RFC 7517 §4.3.

        /// <summary>The UTF-8 source literal of <see cref="KeyOpsSign"/>.</summary>
        public static ReadOnlySpan<byte> KeyOpsSignUtf8 => "sign"u8;

        /// <summary>
        /// The <c>sign</c> value of the <see cref="WellKnownJwkMemberNames.KeyOps"/> parameter, "compute digital signature or MAC" per
        /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.3">RFC 7517 §4.3</see>.
        /// </summary>
        public static string KeyOpsSign { get; } = Utf8Constants.ToInternedString(KeyOpsSignUtf8);

        /// <summary>The UTF-8 source literal of <see cref="KeyOpsVerify"/>.</summary>
        public static ReadOnlySpan<byte> KeyOpsVerifyUtf8 => "verify"u8;

        /// <summary>
        /// The <c>verify</c> value of the <see cref="WellKnownJwkMemberNames.KeyOps"/> parameter, "verify digital signature or MAC" per
        /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.3">RFC 7517 §4.3</see>.
        /// </summary>
        public static string KeyOpsVerify { get; } = Utf8Constants.ToInternedString(KeyOpsVerifyUtf8);

        /// <summary>The UTF-8 source literal of <see cref="KeyOpsEncrypt"/>.</summary>
        public static ReadOnlySpan<byte> KeyOpsEncryptUtf8 => "encrypt"u8;

        /// <summary>
        /// The <c>encrypt</c> value of the <see cref="WellKnownJwkMemberNames.KeyOps"/> parameter, "encrypt content" per
        /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.3">RFC 7517 §4.3</see>.
        /// </summary>
        public static string KeyOpsEncrypt { get; } = Utf8Constants.ToInternedString(KeyOpsEncryptUtf8);

        /// <summary>The UTF-8 source literal of <see cref="KeyOpsDecrypt"/>.</summary>
        public static ReadOnlySpan<byte> KeyOpsDecryptUtf8 => "decrypt"u8;

        /// <summary>
        /// The <c>decrypt</c> value of the <see cref="WellKnownJwkMemberNames.KeyOps"/> parameter, "decrypt content and validate decryption, if applicable" per
        /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.3">RFC 7517 §4.3</see>.
        /// </summary>
        public static string KeyOpsDecrypt { get; } = Utf8Constants.ToInternedString(KeyOpsDecryptUtf8);

        /// <summary>The UTF-8 source literal of <see cref="KeyOpsWrapKey"/>.</summary>
        public static ReadOnlySpan<byte> KeyOpsWrapKeyUtf8 => "wrapKey"u8;

        /// <summary>
        /// The <c>wrapKey</c> value of the <see cref="WellKnownJwkMemberNames.KeyOps"/> parameter, "encrypt key" per
        /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.3">RFC 7517 §4.3</see>.
        /// </summary>
        public static string KeyOpsWrapKey { get; } = Utf8Constants.ToInternedString(KeyOpsWrapKeyUtf8);

        /// <summary>The UTF-8 source literal of <see cref="KeyOpsUnwrapKey"/>.</summary>
        public static ReadOnlySpan<byte> KeyOpsUnwrapKeyUtf8 => "unwrapKey"u8;

        /// <summary>
        /// The <c>unwrapKey</c> value of the <see cref="WellKnownJwkMemberNames.KeyOps"/> parameter, "decrypt key and validate decryption, if applicable" per
        /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.3">RFC 7517 §4.3</see>.
        /// </summary>
        public static string KeyOpsUnwrapKey { get; } = Utf8Constants.ToInternedString(KeyOpsUnwrapKeyUtf8);

        /// <summary>The UTF-8 source literal of <see cref="KeyOpsDeriveKey"/>.</summary>
        public static ReadOnlySpan<byte> KeyOpsDeriveKeyUtf8 => "deriveKey"u8;

        /// <summary>
        /// The <c>deriveKey</c> value of the <see cref="WellKnownJwkMemberNames.KeyOps"/> parameter, "derive key" per
        /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.3">RFC 7517 §4.3</see>.
        /// </summary>
        public static string KeyOpsDeriveKey { get; } = Utf8Constants.ToInternedString(KeyOpsDeriveKeyUtf8);

        /// <summary>The UTF-8 source literal of <see cref="KeyOpsDeriveBits"/>.</summary>
        public static ReadOnlySpan<byte> KeyOpsDeriveBitsUtf8 => "deriveBits"u8;

        /// <summary>
        /// The <c>deriveBits</c> value of the <see cref="WellKnownJwkMemberNames.KeyOps"/> parameter, "derive bits not to be used as a key" per
        /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.3">RFC 7517 §4.3</see>.
        /// </summary>
        public static string KeyOpsDeriveBits { get; } = Utf8Constants.ToInternedString(KeyOpsDeriveBitsUtf8);


        //Values of the "typ" (Type) header parameter — RFC 7519 §5.1.

        /// <summary>The UTF-8 source literal of <see cref="TypeJwt"/>.</summary>
        public static ReadOnlySpan<byte> TypeJwtUtf8 => "JWT"u8;

        /// <summary>
        /// The <c>JWT</c> value for the <see cref="WellKnownJoseHeaderNames.Typ"/> parameter
        /// per <see href="https://www.rfc-editor.org/rfc/rfc7519#section-5.1">RFC 7519 §5.1</see>.
        /// Spelled uppercase for compatibility with legacy implementations.
        /// </summary>
        public static string TypeJwt { get; } = Utf8Constants.ToInternedString(TypeJwtUtf8);


        /// <summary>Whether <paramref name="value"/> is <see cref="UseSig"/>.</summary>
        public static bool IsUseSig(string value) => Equals(value, UseSig);

        /// <summary>Whether <paramref name="value"/> is <see cref="UseEnc"/>.</summary>
        public static bool IsUseEnc(string value) => Equals(value, UseEnc);

        /// <summary>Whether <paramref name="value"/> is <see cref="KeyOpsSign"/>.</summary>
        public static bool IsKeyOpsSign(string value) => Equals(value, KeyOpsSign);

        /// <summary>Whether <paramref name="value"/> is <see cref="KeyOpsVerify"/>.</summary>
        public static bool IsKeyOpsVerify(string value) => Equals(value, KeyOpsVerify);

        /// <summary>Whether <paramref name="value"/> is <see cref="KeyOpsEncrypt"/>.</summary>
        public static bool IsKeyOpsEncrypt(string value) => Equals(value, KeyOpsEncrypt);

        /// <summary>Whether <paramref name="value"/> is <see cref="KeyOpsDecrypt"/>.</summary>
        public static bool IsKeyOpsDecrypt(string value) => Equals(value, KeyOpsDecrypt);

        /// <summary>Whether <paramref name="value"/> is <see cref="KeyOpsWrapKey"/>.</summary>
        public static bool IsKeyOpsWrapKey(string value) => Equals(value, KeyOpsWrapKey);

        /// <summary>Whether <paramref name="value"/> is <see cref="KeyOpsUnwrapKey"/>.</summary>
        public static bool IsKeyOpsUnwrapKey(string value) => Equals(value, KeyOpsUnwrapKey);

        /// <summary>Whether <paramref name="value"/> is <see cref="KeyOpsDeriveKey"/>.</summary>
        public static bool IsKeyOpsDeriveKey(string value) => Equals(value, KeyOpsDeriveKey);

        /// <summary>Whether <paramref name="value"/> is <see cref="KeyOpsDeriveBits"/>.</summary>
        public static bool IsKeyOpsDeriveBits(string value) => Equals(value, KeyOpsDeriveBits);

        /// <summary>
        /// Whether <paramref name="value"/> is <see cref="TypeJwt"/>, comparing as the RFC 7515
        /// §4.1.9 media type a <c>typ</c> header names — case insensitively, with the implicit
        /// <c>application/</c> prefix — rather than through this class's own RFC 7517 ordinal
        /// <see cref="Equals(string, string)"/>, which is right for a <c>use</c> value (RFC 7517
        /// parameter values are case-sensitive) but wrong for a <c>typ</c> value.
        /// </summary>
        /// <param name="value">The JWT <c>typ</c> header value.</param>
        /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="TypeJwt"/>; otherwise, <see langword="false"/>.</returns>
        /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9">RFC 7515 §4.1.9</see>.</remarks>
        public static bool IsTypeJwt(string value) => WellKnownMediaTypes.Jwt.Equals(value, TypeJwt);


        /// <summary>
        /// Returns the interned constant for a known JWK / JOSE value, or the
        /// original string if unrecognized.
        /// </summary>
        public static string GetCanonicalizedValue(string value) => value switch
        {
            _ when IsUseSig(value) => UseSig,
            _ when IsUseEnc(value) => UseEnc,
            _ when IsKeyOpsSign(value) => KeyOpsSign,
            _ when IsKeyOpsVerify(value) => KeyOpsVerify,
            _ when IsKeyOpsEncrypt(value) => KeyOpsEncrypt,
            _ when IsKeyOpsDecrypt(value) => KeyOpsDecrypt,
            _ when IsKeyOpsWrapKey(value) => KeyOpsWrapKey,
            _ when IsKeyOpsUnwrapKey(value) => KeyOpsUnwrapKey,
            _ when IsKeyOpsDeriveKey(value) => KeyOpsDeriveKey,
            _ when IsKeyOpsDeriveBits(value) => KeyOpsDeriveBits,
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
