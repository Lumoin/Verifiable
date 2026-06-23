using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.WellKnown;

/// <summary>
/// The <c>grant_type</c> wire values per RFC 6749 and its extensions (the IANA OAuth Parameters
/// registry). The companion <see cref="Client.GrantTypeNames"/> maps typed <see cref="Client.GrantType"/>
/// values to and from these. Comparison is ordinal.
/// </summary>
public static class WellKnownGrantTypes
{
    /// <summary>The UTF-8 source literal of <see cref="AuthorizationCode"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationCodeUtf8 => "authorization_code"u8;

    /// <summary>The <c>authorization_code</c> grant type (RFC 6749 §4.1.3).</summary>
    public static readonly string AuthorizationCode = Utf8Constants.ToInternedString(AuthorizationCodeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RefreshToken"/>.</summary>
    public static ReadOnlySpan<byte> RefreshTokenUtf8 => "refresh_token"u8;

    /// <summary>The <c>refresh_token</c> grant type (RFC 6749 §6).</summary>
    public static readonly string RefreshToken = Utf8Constants.ToInternedString(RefreshTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClientCredentials"/>.</summary>
    public static ReadOnlySpan<byte> ClientCredentialsUtf8 => "client_credentials"u8;

    /// <summary>The <c>client_credentials</c> grant type (RFC 6749 §4.4.2).</summary>
    public static readonly string ClientCredentials = Utf8Constants.ToInternedString(ClientCredentialsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Password"/>.</summary>
    public static ReadOnlySpan<byte> PasswordUtf8 => "password"u8;

    /// <summary>The <c>password</c> grant type (RFC 6749 §4.3.2; deprecated by RFC 9700).</summary>
    public static readonly string Password = Utf8Constants.ToInternedString(PasswordUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DeviceCode"/>.</summary>
    public static ReadOnlySpan<byte> DeviceCodeUtf8 => "urn:ietf:params:oauth:grant-type:device_code"u8;

    /// <summary>The device authorization grant type (RFC 8628 §3.4).</summary>
    public static readonly string DeviceCode = Utf8Constants.ToInternedString(DeviceCodeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TokenExchange"/>.</summary>
    public static ReadOnlySpan<byte> TokenExchangeUtf8 => "urn:ietf:params:oauth:grant-type:token-exchange"u8;

    /// <summary>The token exchange grant type (RFC 8693 §2.1).</summary>
    public static readonly string TokenExchange = Utf8Constants.ToInternedString(TokenExchangeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="JwtBearer"/>.</summary>
    public static ReadOnlySpan<byte> JwtBearerUtf8 => "urn:ietf:params:oauth:grant-type:jwt-bearer"u8;

    /// <summary>The JWT bearer authorization grant type (RFC 7523 §2.1).</summary>
    public static readonly string JwtBearer = Utf8Constants.ToInternedString(JwtBearerUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Saml2Bearer"/>.</summary>
    public static ReadOnlySpan<byte> Saml2BearerUtf8 => "urn:ietf:params:oauth:grant-type:saml2-bearer"u8;

    /// <summary>The SAML 2.0 bearer assertion grant type (RFC 7522 §2.1).</summary>
    public static readonly string Saml2Bearer = Utf8Constants.ToInternedString(Saml2BearerUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Ciba"/>.</summary>
    public static ReadOnlySpan<byte> CibaUtf8 => "urn:openid:params:grant-type:ciba"u8;

    /// <summary>The Client-Initiated Backchannel Authentication grant type (OpenID CIBA Core §7.1).</summary>
    public static readonly string Ciba = Utf8Constants.ToInternedString(CibaUtf8);

    /// <summary>The UTF-8 source literal of <see cref="PreAuthorizedCode"/>.</summary>
    public static ReadOnlySpan<byte> PreAuthorizedCodeUtf8 => "urn:ietf:params:oauth:grant-type:pre-authorized_code"u8;

    /// <summary>The Pre-Authorized Code grant type (OID4VCI 1.0 §6.1).</summary>
    public static readonly string PreAuthorizedCode = Utf8Constants.ToInternedString(PreAuthorizedCodeUtf8);


    /// <summary>Whether <paramref name="value"/> is <see cref="AuthorizationCode"/>.</summary>
    public static bool IsAuthorizationCode(string value) => string.Equals(value, AuthorizationCode, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="RefreshToken"/>.</summary>
    public static bool IsRefreshToken(string value) => string.Equals(value, RefreshToken, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="ClientCredentials"/>.</summary>
    public static bool IsClientCredentials(string value) => string.Equals(value, ClientCredentials, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="Password"/>.</summary>
    public static bool IsPassword(string value) => string.Equals(value, Password, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="DeviceCode"/>.</summary>
    public static bool IsDeviceCode(string value) => string.Equals(value, DeviceCode, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="TokenExchange"/>.</summary>
    public static bool IsTokenExchange(string value) => string.Equals(value, TokenExchange, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="JwtBearer"/>.</summary>
    public static bool IsJwtBearer(string value) => string.Equals(value, JwtBearer, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="Saml2Bearer"/>.</summary>
    public static bool IsSaml2Bearer(string value) => string.Equals(value, Saml2Bearer, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="Ciba"/>.</summary>
    public static bool IsCiba(string value) => string.Equals(value, Ciba, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="PreAuthorizedCode"/>.</summary>
    public static bool IsPreAuthorizedCode(string value) => string.Equals(value, PreAuthorizedCode, StringComparison.Ordinal);
}
