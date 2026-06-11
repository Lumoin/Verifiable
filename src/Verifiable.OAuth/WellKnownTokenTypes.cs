using Verifiable.Cryptography.Text;


namespace Verifiable.OAuth;

/// <summary>
/// Well-known token type names used as response field keys in token endpoint
/// responses and as keys in <see cref="ClientRecord.TokenLifetimes"/>.
/// </summary>
/// <remarks>
/// <para>
/// These constants are the canonical names for tokens emitted by the
/// Authorization Server and appear in the JSON body of the token endpoint
/// response, in the <see cref="TokenProducer.ResponseField"/> property of each
/// producer, and as keys in the registration's per-token-type lifetime map.
/// </para>
/// <para>
/// Values follow the OAuth 2.0 token response field names per
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>
/// and the OpenID Connect Core ID Token response field per
/// <see href="https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse">OIDC Core §3.1.3.3</see>.
/// </para>
/// </remarks>
public static class WellKnownTokenTypes
{
    /// <summary>The UTF-8 source literal of <see cref="AccessToken"/>.</summary>
    public static ReadOnlySpan<byte> AccessTokenUtf8 => "access_token"u8;

    /// <summary>
    /// The OAuth 2.0 access token response field name (<c>access_token</c>) per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>.
    /// </summary>
    public static readonly string AccessToken = Utf8Constants.ToInternedString(AccessTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IdToken"/>.</summary>
    public static ReadOnlySpan<byte> IdTokenUtf8 => "id_token"u8;

    /// <summary>
    /// The OpenID Connect ID Token response field name (<c>id_token</c>) per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse">OIDC Core §3.1.3.3</see>.
    /// </summary>
    public static readonly string IdToken = Utf8Constants.ToInternedString(IdTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RefreshToken"/>.</summary>
    public static ReadOnlySpan<byte> RefreshTokenUtf8 => "refresh_token"u8;

    /// <summary>
    /// The OAuth 2.0 refresh token response field name (<c>refresh_token</c>) per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>.
    /// </summary>
    public static readonly string RefreshToken = Utf8Constants.ToInternedString(RefreshTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="LogoutToken"/>.</summary>
    public static ReadOnlySpan<byte> LogoutTokenUtf8 => "logout_token"u8;

    /// <summary>
    /// The OpenID Connect Back-Channel Logout token type name (<c>logout_token</c>) per
    /// <see href="https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken">OIDC Back-Channel Logout §2.4</see>.
    /// </summary>
    public static readonly string LogoutToken = Utf8Constants.ToInternedString(LogoutTokenUtf8);


    /// <summary>
    /// Whether <paramref name="tokenType"/> is <see cref="AccessToken"/>.
    /// </summary>
    public static bool IsAccessToken(string tokenType) => Equals(tokenType, AccessToken);

    /// <summary>
    /// Whether <paramref name="tokenType"/> is <see cref="IdToken"/>.
    /// </summary>
    public static bool IsIdToken(string tokenType) => Equals(tokenType, IdToken);

    /// <summary>
    /// Whether <paramref name="tokenType"/> is <see cref="RefreshToken"/>.
    /// </summary>
    public static bool IsRefreshToken(string tokenType) => Equals(tokenType, RefreshToken);

    /// <summary>
    /// Whether <paramref name="tokenType"/> is <see cref="LogoutToken"/>.
    /// </summary>
    public static bool IsLogoutToken(string tokenType) => Equals(tokenType, LogoutToken);


    /// <summary>
    /// Returns the interned constant for a known token type name, or the original
    /// string if unrecognized. Enables reference-equality fast paths downstream.
    /// </summary>
    /// <param name="tokenType">The token type name to canonicalize.</param>
    /// <returns>The canonical constant, or <paramref name="tokenType"/> unchanged.</returns>
    public static string GetCanonicalizedValue(string tokenType) => tokenType switch
    {
        _ when IsAccessToken(tokenType) => AccessToken,
        _ when IsIdToken(tokenType) => IdToken,
        _ when IsRefreshToken(tokenType) => RefreshToken,
        _ when IsLogoutToken(tokenType) => LogoutToken,
        _ => tokenType
    };


    /// <summary>
    /// Compares two token type names for equality. Comparison is ordinal.
    /// </summary>
    public static bool Equals(string tokenTypeA, string tokenTypeB) =>
        object.ReferenceEquals(tokenTypeA, tokenTypeB) || StringComparer.Ordinal.Equals(tokenTypeA, tokenTypeB);
}
