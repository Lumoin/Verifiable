namespace Verifiable.OAuth.Client;

/// <summary>
/// Provides wire-format strings and reverse-lookup parsing for <see cref="TokenType"/> values per
/// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-3">RFC 8693 §3</see>.
/// </summary>
/// <remarks>
/// <para>
/// Wire-format strings are the token-type URIs in <see cref="WellKnownTokenTypeIdentifiers"/> (the IANA
/// OAuth URI registry). <see cref="TryParse"/> compares with <see cref="StringComparison.Ordinal"/>.
/// </para>
/// <para>
/// Application-defined codes return a generic <c>custom-{code}</c> form when looked up by code,
/// since the library does not own their wire string. Applications that ship custom token types must
/// keep their own code-to-wire-string mapping if they need string emission.
/// </para>
/// </remarks>
public static class TokenTypeNames
{
    /// <summary>Gets the wire-format string for the specified token type.</summary>
    public static string GetName(TokenType tokenType) => GetName(tokenType.Code);


    /// <summary>Gets the wire-format string for the specified token type code.</summary>
    public static string GetName(int code) => code switch
    {
        var c when c == TokenType.AccessToken.Code => WellKnownTokenTypeIdentifiers.AccessToken,
        var c when c == TokenType.RefreshToken.Code => WellKnownTokenTypeIdentifiers.RefreshToken,
        var c when c == TokenType.IdToken.Code => WellKnownTokenTypeIdentifiers.IdToken,
        var c when c == TokenType.Saml1.Code => WellKnownTokenTypeIdentifiers.Saml1,
        var c when c == TokenType.Saml2.Code => WellKnownTokenTypeIdentifiers.Saml2,
        var c when c == TokenType.Jwt.Code => WellKnownTokenTypeIdentifiers.Jwt,
        var c when c == TokenType.IdJag.Code => WellKnownTokenTypeIdentifiers.IdJag,
        _ => $"custom-{code}"
    };


    /// <summary>
    /// Attempts to parse a wire-format token type URI into a typed <see cref="TokenType"/>. Returns
    /// <see langword="false"/> when the value does not match any library-defined token type.
    /// </summary>
    public static bool TryParse(string wireValue, out TokenType tokenType)
    {
        ArgumentNullException.ThrowIfNull(wireValue);

        TokenType? parsed = wireValue switch
        {
            _ when WellKnownTokenTypeIdentifiers.IsAccessToken(wireValue) => TokenType.AccessToken,
            _ when WellKnownTokenTypeIdentifiers.IsRefreshToken(wireValue) => TokenType.RefreshToken,
            _ when WellKnownTokenTypeIdentifiers.IsIdToken(wireValue) => TokenType.IdToken,
            _ when WellKnownTokenTypeIdentifiers.IsSaml1(wireValue) => TokenType.Saml1,
            _ when WellKnownTokenTypeIdentifiers.IsSaml2(wireValue) => TokenType.Saml2,
            _ when WellKnownTokenTypeIdentifiers.IsJwt(wireValue) => TokenType.Jwt,
            _ when WellKnownTokenTypeIdentifiers.IsIdJag(wireValue) => TokenType.IdJag,
            _ => null
        };

        tokenType = parsed ?? default;

        return parsed is not null;
    }
}
