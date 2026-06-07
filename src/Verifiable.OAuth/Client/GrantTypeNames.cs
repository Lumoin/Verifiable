namespace Verifiable.OAuth.Client;

/// <summary>
/// Provides wire-format strings and reverse-lookup parsing for
/// <see cref="GrantType"/> values.
/// </summary>
/// <remarks>
/// <para>
/// Wire-format strings are case-sensitive per
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.5">RFC 6749 §4.5</see>
/// and the grant-type extension URIs registered in the IANA OAuth Parameters
/// registry. <see cref="TryParse"/> compares with
/// <see cref="StringComparison.Ordinal"/>.
/// </para>
/// <para>
/// Application-defined codes return a generic <c>custom-{code}</c> form when
/// looked up by code, since the library does not own their wire string.
/// Applications that ship custom grant types must keep their own
/// code-to-wire-string mapping if they need string emission.
/// </para>
/// </remarks>
public static class GrantTypeNames
{
    /// <summary>Gets the wire-format string for the specified grant type.</summary>
    public static string GetName(GrantType grantType) => GetName(grantType.Code);


    /// <summary>Gets the wire-format string for the specified grant type code.</summary>
    public static string GetName(int code) => code switch
    {
        var c when c == GrantType.AuthorizationCode.Code => "authorization_code",
        var c when c == GrantType.RefreshToken.Code => "refresh_token",
        var c when c == GrantType.ClientCredentials.Code => "client_credentials",
        var c when c == GrantType.Password.Code => "password",
        var c when c == GrantType.DeviceCode.Code => "urn:ietf:params:oauth:grant-type:device_code",
        var c when c == GrantType.TokenExchange.Code => "urn:ietf:params:oauth:grant-type:token-exchange",
        var c when c == GrantType.JwtBearer.Code => "urn:ietf:params:oauth:grant-type:jwt-bearer",
        var c when c == GrantType.Saml2Bearer.Code => "urn:ietf:params:oauth:grant-type:saml2-bearer",
        var c when c == GrantType.Ciba.Code => "urn:openid:params:grant-type:ciba",
        var c when c == GrantType.PreAuthorizedCode.Code => "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        _ => $"custom-{code}"
    };


    /// <summary>
    /// Attempts to parse a wire-format grant type string into a typed
    /// <see cref="GrantType"/>. Returns <see langword="false"/> when the value
    /// does not match any library-defined grant type.
    /// </summary>
    public static bool TryParse(string wireValue, out GrantType grantType)
    {
        ArgumentNullException.ThrowIfNull(wireValue);

        if(string.Equals(wireValue, "authorization_code", StringComparison.Ordinal))
        {
            grantType = GrantType.AuthorizationCode;
            return true;
        }
        if(string.Equals(wireValue, "refresh_token", StringComparison.Ordinal))
        {
            grantType = GrantType.RefreshToken;
            return true;
        }
        if(string.Equals(wireValue, "client_credentials", StringComparison.Ordinal))
        {
            grantType = GrantType.ClientCredentials;
            return true;
        }
        if(string.Equals(wireValue, "password", StringComparison.Ordinal))
        {
            grantType = GrantType.Password;
            return true;
        }
        if(string.Equals(wireValue, "urn:ietf:params:oauth:grant-type:device_code", StringComparison.Ordinal))
        {
            grantType = GrantType.DeviceCode;
            return true;
        }
        if(string.Equals(wireValue, "urn:ietf:params:oauth:grant-type:token-exchange", StringComparison.Ordinal))
        {
            grantType = GrantType.TokenExchange;
            return true;
        }
        if(string.Equals(wireValue, "urn:ietf:params:oauth:grant-type:jwt-bearer", StringComparison.Ordinal))
        {
            grantType = GrantType.JwtBearer;
            return true;
        }
        if(string.Equals(wireValue, "urn:ietf:params:oauth:grant-type:saml2-bearer", StringComparison.Ordinal))
        {
            grantType = GrantType.Saml2Bearer;
            return true;
        }
        if(string.Equals(wireValue, "urn:openid:params:grant-type:ciba", StringComparison.Ordinal))
        {
            grantType = GrantType.Ciba;
            return true;
        }
        if(string.Equals(wireValue, "urn:ietf:params:oauth:grant-type:pre-authorized_code", StringComparison.Ordinal))
        {
            grantType = GrantType.PreAuthorizedCode;
            return true;
        }

        grantType = default;
        return false;
    }
}
