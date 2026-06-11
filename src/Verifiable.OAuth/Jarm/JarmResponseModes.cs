using System.Diagnostics;
using System.Text;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Jarm;

/// <summary>
/// The <c>response_mode</c> values defined by JWT Secured Authorization Response Mode
/// for OAuth 2.0 per
/// <see href="https://openid.net/specs/oauth-v2-jarm-final.html#section-2.3">JARM §2.3</see>.
/// </summary>
/// <remarks>
/// These are the generic OAuth JARM modes; the OID4VP-specific response modes
/// (<c>direct_post</c>, <c>dc_api</c>, …) live in
/// <see cref="Oid4Vp.WellKnownResponseModes"/>.
/// </remarks>
[DebuggerDisplay("JarmResponseModes")]
public static class JarmResponseModes
{
    /// <summary>The UTF-8 source literal of <see cref="QueryJwt"/>.</summary>
    public static ReadOnlySpan<byte> QueryJwtUtf8 => "query.jwt"u8;

    /// <summary>
    /// The <c>query.jwt</c> response mode — the response JWT rides the <c>response</c>
    /// parameter in the query component of the redirect URI (§2.3.1). MUST NOT be used
    /// with response types containing <c>token</c> or <c>id_token</c> unless the
    /// response JWT is encrypted.
    /// </summary>
    public static readonly string QueryJwt = Utf8Constants.ToInternedString(QueryJwtUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FragmentJwt"/>.</summary>
    public static ReadOnlySpan<byte> FragmentJwtUtf8 => "fragment.jwt"u8;

    /// <summary>
    /// The <c>fragment.jwt</c> response mode — the response JWT rides the
    /// <c>response</c> parameter in the fragment component of the redirect URI (§2.3.2).
    /// </summary>
    public static readonly string FragmentJwt = Utf8Constants.ToInternedString(FragmentJwtUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FormPostJwt"/>.</summary>
    public static ReadOnlySpan<byte> FormPostJwtUtf8 => "form_post.jwt"u8;

    /// <summary>
    /// The <c>form_post.jwt</c> response mode — the response JWT is auto-submitted from
    /// the User Agent as an HTML form value POSTed to the redirect URI (§2.3.3).
    /// </summary>
    public static readonly string FormPostJwt = Utf8Constants.ToInternedString(FormPostJwtUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Jwt"/>.</summary>
    public static ReadOnlySpan<byte> JwtUtf8 => "jwt"u8;

    /// <summary>
    /// The <c>jwt</c> response mode — a shortcut for the default redirect encoding of
    /// the requested response type (§2.3.4): <see cref="QueryJwt"/> for <c>code</c>,
    /// <see cref="FragmentJwt"/> for <c>token</c> and the OIDC response types except
    /// <c>none</c>.
    /// </summary>
    public static readonly string Jwt = Utf8Constants.ToInternedString(JwtUtf8);


    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>query.jwt</c>.</summary>
    public static bool IsQueryJwt(string value) =>
        string.Equals(value, QueryJwt, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>fragment.jwt</c>.</summary>
    public static bool IsFragmentJwt(string value) =>
        string.Equals(value, FragmentJwt, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>form_post.jwt</c>.</summary>
    public static bool IsFormPostJwt(string value) =>
        string.Equals(value, FormPostJwt, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>jwt</c>.</summary>
    public static bool IsJwt(string value) =>
        string.Equals(value, Jwt, StringComparison.Ordinal);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="value"/> is any of the four
    /// JARM response modes — i.e. the Authorization Request asks for a JWT-secured
    /// authorization response.
    /// </summary>
    public static bool IsJwtSecuredResponseMode(string value) =>
        IsQueryJwt(value) || IsFragmentJwt(value) || IsFormPostJwt(value) || IsJwt(value);


    /// <summary>
    /// Returns the canonical form of a well-known JARM response mode, or the original
    /// value when not recognized. Comparison is case-sensitive.
    /// </summary>
    public static string GetCanonicalizedValue(string value) => value switch
    {
        _ when IsQueryJwt(value) => QueryJwt,
        _ when IsFragmentJwt(value) => FragmentJwt,
        _ when IsFormPostJwt(value) => FormPostJwt,
        _ when IsJwt(value) => Jwt,
        _ => value
    };
}
