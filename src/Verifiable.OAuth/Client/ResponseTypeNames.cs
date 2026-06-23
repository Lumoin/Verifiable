namespace Verifiable.OAuth.Client;

/// <summary>
/// Provides wire-format strings and reverse-lookup parsing for <see cref="ResponseType"/> values.
/// </summary>
/// <remarks>
/// Wire-format strings are the values in <see cref="WellKnownResponseTypes"/> (RFC 6749 §3.1.1, OIDC
/// Core 1.0 §3, OID4VP), compared with <see cref="StringComparison.Ordinal"/>. Multi-token response
/// types are space-separated in canonical OIDC Core 1.0 §3 order so exact-match equality holds against
/// published <c>response_types_supported</c> entries.
/// </remarks>
public static class ResponseTypeNames
{
    /// <summary>Gets the wire-format string for the specified response type.</summary>
    public static string GetName(ResponseType responseType) => GetName(responseType.Code);


    /// <summary>Gets the wire-format string for the specified response type code.</summary>
    public static string GetName(int code) => code switch
    {
        var c when c == ResponseType.AuthorizationCode.Code => WellKnownResponseTypes.Code,
        var c when c == ResponseType.Token.Code => WellKnownResponseTypes.Token,
        var c when c == ResponseType.IdToken.Code => WellKnownResponseTypes.IdToken,
        var c when c == ResponseType.CodeIdToken.Code => WellKnownResponseTypes.CodeIdToken,
        var c when c == ResponseType.CodeToken.Code => WellKnownResponseTypes.CodeToken,
        var c when c == ResponseType.IdTokenToken.Code => WellKnownResponseTypes.IdTokenToken,
        var c when c == ResponseType.CodeIdTokenToken.Code => WellKnownResponseTypes.CodeIdTokenToken,
        var c when c == ResponseType.None.Code => WellKnownResponseTypes.None,
        var c when c == ResponseType.VpToken.Code => WellKnownResponseTypes.VpToken,
        var c when c == ResponseType.CodeVpToken.Code => WellKnownResponseTypes.CodeVpToken,
        _ => $"custom-{code}"
    };


    /// <summary>
    /// Attempts to parse a wire-format response type string into a typed <see cref="ResponseType"/>.
    /// Returns <see langword="false"/> when the value does not match any library-defined response type.
    /// </summary>
    public static bool TryParse(string wireValue, out ResponseType responseType)
    {
        ArgumentNullException.ThrowIfNull(wireValue);

        ResponseType? parsed = wireValue switch
        {
            _ when WellKnownResponseTypes.IsCode(wireValue) => ResponseType.AuthorizationCode,
            _ when WellKnownResponseTypes.IsToken(wireValue) => ResponseType.Token,
            _ when WellKnownResponseTypes.IsIdToken(wireValue) => ResponseType.IdToken,
            _ when WellKnownResponseTypes.IsCodeIdToken(wireValue) => ResponseType.CodeIdToken,
            _ when WellKnownResponseTypes.IsCodeToken(wireValue) => ResponseType.CodeToken,
            _ when WellKnownResponseTypes.IsIdTokenToken(wireValue) => ResponseType.IdTokenToken,
            _ when WellKnownResponseTypes.IsCodeIdTokenToken(wireValue) => ResponseType.CodeIdTokenToken,
            _ when WellKnownResponseTypes.IsNone(wireValue) => ResponseType.None,
            _ when WellKnownResponseTypes.IsVpToken(wireValue) => ResponseType.VpToken,
            _ when WellKnownResponseTypes.IsCodeVpToken(wireValue) => ResponseType.CodeVpToken,
            _ => null
        };

        responseType = parsed ?? default;

        return parsed is not null;
    }
}
