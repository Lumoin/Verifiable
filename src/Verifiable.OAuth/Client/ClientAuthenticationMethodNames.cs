namespace Verifiable.OAuth.Client;

/// <summary>
/// Provides wire-format strings and reverse-lookup parsing for <see cref="ClientAuthenticationMethod"/>
/// values.
/// </summary>
/// <remarks>
/// Wire-format strings are the values in <see cref="WellKnownClientAuthenticationMethods"/> (the IANA
/// OAuth Token Endpoint Authentication Methods registry), compared with <see cref="StringComparison.Ordinal"/>.
/// </remarks>
public static class ClientAuthenticationMethodNames
{
    /// <summary>Gets the wire-format string for the specified authentication method.</summary>
    public static string GetName(ClientAuthenticationMethod method) => GetName(method.Code);


    /// <summary>Gets the wire-format string for the specified authentication method code.</summary>
    public static string GetName(int code) => code switch
    {
        var c when c == ClientAuthenticationMethod.None.Code => WellKnownClientAuthenticationMethods.None,
        var c when c == ClientAuthenticationMethod.ClientSecretBasic.Code => WellKnownClientAuthenticationMethods.ClientSecretBasic,
        var c when c == ClientAuthenticationMethod.ClientSecretPost.Code => WellKnownClientAuthenticationMethods.ClientSecretPost,
        var c when c == ClientAuthenticationMethod.ClientSecretJwt.Code => WellKnownClientAuthenticationMethods.ClientSecretJwt,
        var c when c == ClientAuthenticationMethod.PrivateKeyJwt.Code => WellKnownClientAuthenticationMethods.PrivateKeyJwt,
        var c when c == ClientAuthenticationMethod.TlsClientAuth.Code => WellKnownClientAuthenticationMethods.TlsClientAuth,
        var c when c == ClientAuthenticationMethod.SelfSignedTlsClientAuth.Code => WellKnownClientAuthenticationMethods.SelfSignedTlsClientAuth,
        var c when c == ClientAuthenticationMethod.AttestJwtClientAuth.Code => WellKnownClientAuthenticationMethods.AttestJwtClientAuth,
        var c when c == ClientAuthenticationMethod.SpiffeJwt.Code => WellKnownClientAuthenticationMethods.SpiffeJwt,
        _ => $"custom-{code}"
    };


    /// <summary>
    /// Attempts to parse a wire-format authentication method string into a typed
    /// <see cref="ClientAuthenticationMethod"/>. Returns <see langword="false"/> when the value does not
    /// match any library-defined method.
    /// </summary>
    public static bool TryParse(string wireValue, out ClientAuthenticationMethod method)
    {
        ArgumentNullException.ThrowIfNull(wireValue);

        ClientAuthenticationMethod? parsed = wireValue switch
        {
            _ when WellKnownClientAuthenticationMethods.IsNone(wireValue) => ClientAuthenticationMethod.None,
            _ when WellKnownClientAuthenticationMethods.IsClientSecretBasic(wireValue) => ClientAuthenticationMethod.ClientSecretBasic,
            _ when WellKnownClientAuthenticationMethods.IsClientSecretPost(wireValue) => ClientAuthenticationMethod.ClientSecretPost,
            _ when WellKnownClientAuthenticationMethods.IsClientSecretJwt(wireValue) => ClientAuthenticationMethod.ClientSecretJwt,
            _ when WellKnownClientAuthenticationMethods.IsPrivateKeyJwt(wireValue) => ClientAuthenticationMethod.PrivateKeyJwt,
            _ when WellKnownClientAuthenticationMethods.IsTlsClientAuth(wireValue) => ClientAuthenticationMethod.TlsClientAuth,
            _ when WellKnownClientAuthenticationMethods.IsSelfSignedTlsClientAuth(wireValue) => ClientAuthenticationMethod.SelfSignedTlsClientAuth,
            _ when WellKnownClientAuthenticationMethods.IsAttestJwtClientAuth(wireValue) => ClientAuthenticationMethod.AttestJwtClientAuth,
            _ when WellKnownClientAuthenticationMethods.IsSpiffeJwt(wireValue) => ClientAuthenticationMethod.SpiffeJwt,
            _ => null
        };

        method = parsed ?? default;

        return parsed is not null;
    }
}
