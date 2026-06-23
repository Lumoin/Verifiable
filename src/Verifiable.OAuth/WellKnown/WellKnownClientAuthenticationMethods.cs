using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.WellKnown;

/// <summary>
/// The <c>token_endpoint_auth_method</c> wire values registered in the IANA OAuth Token Endpoint
/// Authentication Methods registry. The companion <see cref="Client.ClientAuthenticationMethodNames"/>
/// maps typed <see cref="Client.ClientAuthenticationMethod"/> values to and from these. Comparison is ordinal.
/// </summary>
public static class WellKnownClientAuthenticationMethods
{
    /// <summary>The UTF-8 source literal of <see cref="None"/>.</summary>
    public static ReadOnlySpan<byte> NoneUtf8 => "none"u8;

    /// <summary>The <c>none</c> method — a public client with no authentication (RFC 6749 §2.1).</summary>
    public static readonly string None = Utf8Constants.ToInternedString(NoneUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClientSecretBasic"/>.</summary>
    public static ReadOnlySpan<byte> ClientSecretBasicUtf8 => "client_secret_basic"u8;

    /// <summary>The <c>client_secret_basic</c> method (RFC 6749 §2.3.1).</summary>
    public static readonly string ClientSecretBasic = Utf8Constants.ToInternedString(ClientSecretBasicUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClientSecretPost"/>.</summary>
    public static ReadOnlySpan<byte> ClientSecretPostUtf8 => "client_secret_post"u8;

    /// <summary>The <c>client_secret_post</c> method (RFC 6749 §2.3.1).</summary>
    public static readonly string ClientSecretPost = Utf8Constants.ToInternedString(ClientSecretPostUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClientSecretJwt"/>.</summary>
    public static ReadOnlySpan<byte> ClientSecretJwtUtf8 => "client_secret_jwt"u8;

    /// <summary>The <c>client_secret_jwt</c> method (OIDC Core 1.0 §9 / RFC 7523 §2.2).</summary>
    public static readonly string ClientSecretJwt = Utf8Constants.ToInternedString(ClientSecretJwtUtf8);

    /// <summary>The UTF-8 source literal of <see cref="PrivateKeyJwt"/>.</summary>
    public static ReadOnlySpan<byte> PrivateKeyJwtUtf8 => "private_key_jwt"u8;

    /// <summary>The <c>private_key_jwt</c> method (OIDC Core 1.0 §9 / RFC 7523 §2.2).</summary>
    public static readonly string PrivateKeyJwt = Utf8Constants.ToInternedString(PrivateKeyJwtUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TlsClientAuth"/>.</summary>
    public static ReadOnlySpan<byte> TlsClientAuthUtf8 => "tls_client_auth"u8;

    /// <summary>The <c>tls_client_auth</c> method — PKI mutual TLS (RFC 8705 §2.1).</summary>
    public static readonly string TlsClientAuth = Utf8Constants.ToInternedString(TlsClientAuthUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SelfSignedTlsClientAuth"/>.</summary>
    public static ReadOnlySpan<byte> SelfSignedTlsClientAuthUtf8 => "self_signed_tls_client_auth"u8;

    /// <summary>The <c>self_signed_tls_client_auth</c> method — self-signed mutual TLS (RFC 8705 §2.2).</summary>
    public static readonly string SelfSignedTlsClientAuth = Utf8Constants.ToInternedString(SelfSignedTlsClientAuthUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AttestJwtClientAuth"/>.</summary>
    public static ReadOnlySpan<byte> AttestJwtClientAuthUtf8 => "attest_jwt_client_auth"u8;

    /// <summary>The <c>attest_jwt_client_auth</c> method (OAuth Attestation-Based Client Authentication).</summary>
    public static readonly string AttestJwtClientAuth = Utf8Constants.ToInternedString(AttestJwtClientAuthUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SpiffeJwt"/>.</summary>
    public static ReadOnlySpan<byte> SpiffeJwtUtf8 => "spiffe_jwt"u8;

    /// <summary>The <c>spiffe_jwt</c> method — SPIFFE JWT-SVID client authentication.</summary>
    public static readonly string SpiffeJwt = Utf8Constants.ToInternedString(SpiffeJwtUtf8);


    /// <summary>Whether <paramref name="value"/> is <see cref="None"/>.</summary>
    public static bool IsNone(string value) => string.Equals(value, None, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="ClientSecretBasic"/>.</summary>
    public static bool IsClientSecretBasic(string value) => string.Equals(value, ClientSecretBasic, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="ClientSecretPost"/>.</summary>
    public static bool IsClientSecretPost(string value) => string.Equals(value, ClientSecretPost, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="ClientSecretJwt"/>.</summary>
    public static bool IsClientSecretJwt(string value) => string.Equals(value, ClientSecretJwt, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="PrivateKeyJwt"/>.</summary>
    public static bool IsPrivateKeyJwt(string value) => string.Equals(value, PrivateKeyJwt, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="TlsClientAuth"/>.</summary>
    public static bool IsTlsClientAuth(string value) => string.Equals(value, TlsClientAuth, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="SelfSignedTlsClientAuth"/>.</summary>
    public static bool IsSelfSignedTlsClientAuth(string value) => string.Equals(value, SelfSignedTlsClientAuth, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="AttestJwtClientAuth"/>.</summary>
    public static bool IsAttestJwtClientAuth(string value) => string.Equals(value, AttestJwtClientAuth, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="SpiffeJwt"/>.</summary>
    public static bool IsSpiffeJwt(string value) => string.Equals(value, SpiffeJwt, StringComparison.Ordinal);
}
