using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.WellKnown;

/// <summary>
/// The <c>response_type</c> wire values per RFC 6749 §3.1.1, OIDC Core 1.0 §3, and OID4VP (the IANA
/// OAuth Parameters registry). Multi-token values are space-separated in canonical OIDC Core order. The
/// companion <see cref="Client.ResponseTypeNames"/> maps typed <see cref="Client.ResponseType"/> values
/// to and from these. Comparison is ordinal.
/// </summary>
public static class WellKnownResponseTypes
{
    /// <summary>The UTF-8 source literal of <see cref="Code"/>.</summary>
    public static ReadOnlySpan<byte> CodeUtf8 => "code"u8;

    /// <summary>The <c>code</c> response type (RFC 6749 §4.1.1).</summary>
    public static readonly string Code = Utf8Constants.ToInternedString(CodeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Token"/>.</summary>
    public static ReadOnlySpan<byte> TokenUtf8 => "token"u8;

    /// <summary>The <c>token</c> response type (RFC 6749 §4.2.1).</summary>
    public static readonly string Token = Utf8Constants.ToInternedString(TokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IdToken"/>.</summary>
    public static ReadOnlySpan<byte> IdTokenUtf8 => "id_token"u8;

    /// <summary>The <c>id_token</c> response type (OIDC Core 1.0 §3.2.2.1).</summary>
    public static readonly string IdToken = Utf8Constants.ToInternedString(IdTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CodeIdToken"/>.</summary>
    public static ReadOnlySpan<byte> CodeIdTokenUtf8 => "code id_token"u8;

    /// <summary>The <c>code id_token</c> hybrid response type (OIDC Core 1.0 §3.3).</summary>
    public static readonly string CodeIdToken = Utf8Constants.ToInternedString(CodeIdTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CodeToken"/>.</summary>
    public static ReadOnlySpan<byte> CodeTokenUtf8 => "code token"u8;

    /// <summary>The <c>code token</c> hybrid response type (OIDC Core 1.0 §3.3).</summary>
    public static readonly string CodeToken = Utf8Constants.ToInternedString(CodeTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IdTokenToken"/>.</summary>
    public static ReadOnlySpan<byte> IdTokenTokenUtf8 => "id_token token"u8;

    /// <summary>The <c>id_token token</c> implicit response type (OIDC Core 1.0 §3.2).</summary>
    public static readonly string IdTokenToken = Utf8Constants.ToInternedString(IdTokenTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CodeIdTokenToken"/>.</summary>
    public static ReadOnlySpan<byte> CodeIdTokenTokenUtf8 => "code id_token token"u8;

    /// <summary>The <c>code id_token token</c> hybrid response type (OIDC Core 1.0 §3.3).</summary>
    public static readonly string CodeIdTokenToken = Utf8Constants.ToInternedString(CodeIdTokenTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="None"/>.</summary>
    public static ReadOnlySpan<byte> NoneUtf8 => "none"u8;

    /// <summary>The <c>none</c> response type (OAuth 2.0 Multiple Response Type Encoding Practices).</summary>
    public static readonly string None = Utf8Constants.ToInternedString(NoneUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VpToken"/>.</summary>
    public static ReadOnlySpan<byte> VpTokenUtf8 => "vp_token"u8;

    /// <summary>The <c>vp_token</c> response type (OpenID for Verifiable Presentations).</summary>
    public static readonly string VpToken = Utf8Constants.ToInternedString(VpTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CodeVpToken"/>.</summary>
    public static ReadOnlySpan<byte> CodeVpTokenUtf8 => "code vp_token"u8;

    /// <summary>The <c>code vp_token</c> response type (OpenID for Verifiable Presentations).</summary>
    public static readonly string CodeVpToken = Utf8Constants.ToInternedString(CodeVpTokenUtf8);


    /// <summary>Whether <paramref name="value"/> is <see cref="Code"/>.</summary>
    public static bool IsCode(string value) => string.Equals(value, Code, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="Token"/>.</summary>
    public static bool IsToken(string value) => string.Equals(value, Token, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="IdToken"/>.</summary>
    public static bool IsIdToken(string value) => string.Equals(value, IdToken, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="CodeIdToken"/>.</summary>
    public static bool IsCodeIdToken(string value) => string.Equals(value, CodeIdToken, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="CodeToken"/>.</summary>
    public static bool IsCodeToken(string value) => string.Equals(value, CodeToken, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="IdTokenToken"/>.</summary>
    public static bool IsIdTokenToken(string value) => string.Equals(value, IdTokenToken, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="CodeIdTokenToken"/>.</summary>
    public static bool IsCodeIdTokenToken(string value) => string.Equals(value, CodeIdTokenToken, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="None"/>.</summary>
    public static bool IsNone(string value) => string.Equals(value, None, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="VpToken"/>.</summary>
    public static bool IsVpToken(string value) => string.Equals(value, VpToken, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="CodeVpToken"/>.</summary>
    public static bool IsCodeVpToken(string value) => string.Equals(value, CodeVpToken, StringComparison.Ordinal);
}
