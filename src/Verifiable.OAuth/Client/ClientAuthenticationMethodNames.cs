namespace Verifiable.OAuth.Client;

/// <summary>
/// Provides wire-format strings and reverse-lookup parsing for
/// <see cref="ClientAuthenticationMethod"/> values.
/// </summary>
/// <remarks>
/// Wire-format strings are the values registered in the IANA OAuth Token
/// Endpoint Authentication Methods registry, compared with
/// <see cref="StringComparison.Ordinal"/>.
/// </remarks>
public static class ClientAuthenticationMethodNames
{
    /// <summary>Gets the wire-format string for the specified authentication method.</summary>
    public static string GetName(ClientAuthenticationMethod method) => GetName(method.Code);


    /// <summary>Gets the wire-format string for the specified authentication method code.</summary>
    public static string GetName(int code) => code switch
    {
        var c when c == ClientAuthenticationMethod.None.Code => "none",
        var c when c == ClientAuthenticationMethod.ClientSecretBasic.Code => "client_secret_basic",
        var c when c == ClientAuthenticationMethod.ClientSecretPost.Code => "client_secret_post",
        var c when c == ClientAuthenticationMethod.ClientSecretJwt.Code => "client_secret_jwt",
        var c when c == ClientAuthenticationMethod.PrivateKeyJwt.Code => "private_key_jwt",
        var c when c == ClientAuthenticationMethod.TlsClientAuth.Code => "tls_client_auth",
        var c when c == ClientAuthenticationMethod.SelfSignedTlsClientAuth.Code => "self_signed_tls_client_auth",
        var c when c == ClientAuthenticationMethod.AttestJwtClientAuth.Code => "attest_jwt_client_auth",
        var c when c == ClientAuthenticationMethod.SpiffeJwt.Code => "spiffe_jwt",
        _ => $"custom-{code}"
    };


    /// <summary>
    /// Attempts to parse a wire-format authentication method string into a
    /// typed <see cref="ClientAuthenticationMethod"/>. Returns <see langword="false"/>
    /// when the value does not match any library-defined method.
    /// </summary>
    public static bool TryParse(string wireValue, out ClientAuthenticationMethod method)
    {
        ArgumentNullException.ThrowIfNull(wireValue);

        if(string.Equals(wireValue, "none", StringComparison.Ordinal))
        {
            method = ClientAuthenticationMethod.None;
            return true;
        }
        if(string.Equals(wireValue, "client_secret_basic", StringComparison.Ordinal))
        {
            method = ClientAuthenticationMethod.ClientSecretBasic;
            return true;
        }
        if(string.Equals(wireValue, "client_secret_post", StringComparison.Ordinal))
        {
            method = ClientAuthenticationMethod.ClientSecretPost;
            return true;
        }
        if(string.Equals(wireValue, "client_secret_jwt", StringComparison.Ordinal))
        {
            method = ClientAuthenticationMethod.ClientSecretJwt;
            return true;
        }
        if(string.Equals(wireValue, "private_key_jwt", StringComparison.Ordinal))
        {
            method = ClientAuthenticationMethod.PrivateKeyJwt;
            return true;
        }
        if(string.Equals(wireValue, "tls_client_auth", StringComparison.Ordinal))
        {
            method = ClientAuthenticationMethod.TlsClientAuth;
            return true;
        }
        if(string.Equals(wireValue, "self_signed_tls_client_auth", StringComparison.Ordinal))
        {
            method = ClientAuthenticationMethod.SelfSignedTlsClientAuth;
            return true;
        }
        if(string.Equals(wireValue, "attest_jwt_client_auth", StringComparison.Ordinal))
        {
            method = ClientAuthenticationMethod.AttestJwtClientAuth;
            return true;
        }
        if(string.Equals(wireValue, "spiffe_jwt", StringComparison.Ordinal))
        {
            method = ClientAuthenticationMethod.SpiffeJwt;
            return true;
        }

        method = default;
        return false;
    }
}
