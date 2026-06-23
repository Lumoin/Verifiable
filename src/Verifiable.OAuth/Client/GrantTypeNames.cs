namespace Verifiable.OAuth.Client;

/// <summary>
/// Provides wire-format strings and reverse-lookup parsing for <see cref="GrantType"/> values.
/// </summary>
/// <remarks>
/// Wire-format strings are the values in <see cref="WellKnownGrantTypes"/> (RFC 6749 and its extensions,
/// the IANA OAuth Parameters registry), compared with <see cref="StringComparison.Ordinal"/>.
/// Application-defined codes return a generic <c>custom-{code}</c> form when looked up by code, since the
/// library does not own their wire string; such applications keep their own code-to-wire-string mapping.
/// </remarks>
public static class GrantTypeNames
{
    /// <summary>Gets the wire-format string for the specified grant type.</summary>
    public static string GetName(GrantType grantType) => GetName(grantType.Code);


    /// <summary>Gets the wire-format string for the specified grant type code.</summary>
    public static string GetName(int code) => code switch
    {
        var c when c == GrantType.AuthorizationCode.Code => WellKnownGrantTypes.AuthorizationCode,
        var c when c == GrantType.RefreshToken.Code => WellKnownGrantTypes.RefreshToken,
        var c when c == GrantType.ClientCredentials.Code => WellKnownGrantTypes.ClientCredentials,
        var c when c == GrantType.Password.Code => WellKnownGrantTypes.Password,
        var c when c == GrantType.DeviceCode.Code => WellKnownGrantTypes.DeviceCode,
        var c when c == GrantType.TokenExchange.Code => WellKnownGrantTypes.TokenExchange,
        var c when c == GrantType.JwtBearer.Code => WellKnownGrantTypes.JwtBearer,
        var c when c == GrantType.Saml2Bearer.Code => WellKnownGrantTypes.Saml2Bearer,
        var c when c == GrantType.Ciba.Code => WellKnownGrantTypes.Ciba,
        var c when c == GrantType.PreAuthorizedCode.Code => WellKnownGrantTypes.PreAuthorizedCode,
        _ => $"custom-{code}"
    };


    /// <summary>
    /// Attempts to parse a wire-format grant type string into a typed <see cref="GrantType"/>. Returns
    /// <see langword="false"/> when the value does not match any library-defined grant type.
    /// </summary>
    public static bool TryParse(string wireValue, out GrantType grantType)
    {
        ArgumentNullException.ThrowIfNull(wireValue);

        GrantType? parsed = wireValue switch
        {
            _ when WellKnownGrantTypes.IsAuthorizationCode(wireValue) => GrantType.AuthorizationCode,
            _ when WellKnownGrantTypes.IsRefreshToken(wireValue) => GrantType.RefreshToken,
            _ when WellKnownGrantTypes.IsClientCredentials(wireValue) => GrantType.ClientCredentials,
            _ when WellKnownGrantTypes.IsPassword(wireValue) => GrantType.Password,
            _ when WellKnownGrantTypes.IsDeviceCode(wireValue) => GrantType.DeviceCode,
            _ when WellKnownGrantTypes.IsTokenExchange(wireValue) => GrantType.TokenExchange,
            _ when WellKnownGrantTypes.IsJwtBearer(wireValue) => GrantType.JwtBearer,
            _ when WellKnownGrantTypes.IsSaml2Bearer(wireValue) => GrantType.Saml2Bearer,
            _ when WellKnownGrantTypes.IsCiba(wireValue) => GrantType.Ciba,
            _ when WellKnownGrantTypes.IsPreAuthorizedCode(wireValue) => GrantType.PreAuthorizedCode,
            _ => null
        };

        grantType = parsed ?? default;

        return parsed is not null;
    }
}
