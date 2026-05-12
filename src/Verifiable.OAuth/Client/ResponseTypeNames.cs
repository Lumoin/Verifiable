namespace Verifiable.OAuth.Client;

/// <summary>
/// Provides wire-format strings and reverse-lookup parsing for
/// <see cref="ResponseType"/> values.
/// </summary>
/// <remarks>
/// <para>
/// Wire-format strings are case-sensitive per
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.1">RFC 6749 §3.1.1</see>
/// and the response-type strings registered in the IANA OAuth Parameters
/// registry. <see cref="TryParse"/> compares with
/// <see cref="StringComparison.Ordinal"/>.
/// </para>
/// <para>
/// Multi-token response types (<c>code id_token</c>, <c>id_token token</c>,
/// and so on) are space-separated in canonical OIDC Core 1.0 §3 order. RFC
/// 6749 §3.1.1 lets the authorization server treat the value as a set, but
/// emission uses the canonical order so that exact-match equality holds
/// against published <c>response_types_supported</c> entries.
/// </para>
/// </remarks>
public static class ResponseTypeNames
{
    /// <summary>Gets the wire-format string for the specified response type.</summary>
    public static string GetName(ResponseType responseType) => GetName(responseType.Code);


    /// <summary>Gets the wire-format string for the specified response type code.</summary>
    public static string GetName(int code) => code switch
    {
        var c when c == ResponseType.AuthorizationCode.Code => "code",
        var c when c == ResponseType.Token.Code => "token",
        var c when c == ResponseType.IdToken.Code => "id_token",
        var c when c == ResponseType.CodeIdToken.Code => "code id_token",
        var c when c == ResponseType.CodeToken.Code => "code token",
        var c when c == ResponseType.IdTokenToken.Code => "id_token token",
        var c when c == ResponseType.CodeIdTokenToken.Code => "code id_token token",
        var c when c == ResponseType.None.Code => "none",
        var c when c == ResponseType.VpToken.Code => "vp_token",
        var c when c == ResponseType.CodeVpToken.Code => "code vp_token",
        _ => $"custom-{code}"
    };


    /// <summary>
    /// Attempts to parse a wire-format response type string into a typed
    /// <see cref="ResponseType"/>. Returns <see langword="false"/> when the value
    /// does not match any library-defined response type.
    /// </summary>
    public static bool TryParse(string wireValue, out ResponseType responseType)
    {
        ArgumentNullException.ThrowIfNull(wireValue);

        if(string.Equals(wireValue, "code", StringComparison.Ordinal))
        {
            responseType = ResponseType.AuthorizationCode;
            return true;
        }
        if(string.Equals(wireValue, "token", StringComparison.Ordinal))
        {
            responseType = ResponseType.Token;
            return true;
        }
        if(string.Equals(wireValue, "id_token", StringComparison.Ordinal))
        {
            responseType = ResponseType.IdToken;
            return true;
        }
        if(string.Equals(wireValue, "code id_token", StringComparison.Ordinal))
        {
            responseType = ResponseType.CodeIdToken;
            return true;
        }
        if(string.Equals(wireValue, "code token", StringComparison.Ordinal))
        {
            responseType = ResponseType.CodeToken;
            return true;
        }
        if(string.Equals(wireValue, "id_token token", StringComparison.Ordinal))
        {
            responseType = ResponseType.IdTokenToken;
            return true;
        }
        if(string.Equals(wireValue, "code id_token token", StringComparison.Ordinal))
        {
            responseType = ResponseType.CodeIdTokenToken;
            return true;
        }
        if(string.Equals(wireValue, "none", StringComparison.Ordinal))
        {
            responseType = ResponseType.None;
            return true;
        }
        if(string.Equals(wireValue, "vp_token", StringComparison.Ordinal))
        {
            responseType = ResponseType.VpToken;
            return true;
        }
        if(string.Equals(wireValue, "code vp_token", StringComparison.Ordinal))
        {
            responseType = ResponseType.CodeVpToken;
            return true;
        }

        responseType = default;
        return false;
    }
}
