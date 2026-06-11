using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Jarm;

/// <summary>
/// Client metadata parameter NAMES introduced by JARM per
/// <see href="https://openid.net/specs/oauth-v2-jarm-final.html#section-3">JARM §3</see>,
/// registered in the IANA OAuth Dynamic Client Registration Metadata registry.
/// </summary>
[DebuggerDisplay("JarmClientMetadataParameterNames")]
public static class JarmClientMetadataParameterNames
{
    /// <summary>The UTF-8 source literal of <see cref="AuthorizationSignedResponseAlg"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationSignedResponseAlgUtf8 => "authorization_signed_response_alg"u8;

    /// <summary>
    /// The <c>authorization_signed_response_alg</c> parameter — the JWS <c>alg</c>
    /// REQUIRED for signing authorization responses. Defaults to <c>RS256</c> when
    /// unspecified; <c>none</c> is not allowed.
    /// </summary>
    public static readonly string AuthorizationSignedResponseAlg = Utf8Constants.ToInternedString(AuthorizationSignedResponseAlgUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthorizationEncryptedResponseAlg"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationEncryptedResponseAlgUtf8 => "authorization_encrypted_response_alg"u8;

    /// <summary>
    /// The <c>authorization_encrypted_response_alg</c> parameter — the JWE <c>alg</c>
    /// REQUIRED for encrypting authorization responses (sign-then-encrypt Nested JWT
    /// when both are requested). No encryption when omitted.
    /// </summary>
    public static readonly string AuthorizationEncryptedResponseAlg = Utf8Constants.ToInternedString(AuthorizationEncryptedResponseAlgUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthorizationEncryptedResponseEnc"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationEncryptedResponseEncUtf8 => "authorization_encrypted_response_enc"u8;

    /// <summary>
    /// The <c>authorization_encrypted_response_enc</c> parameter — the JWE <c>enc</c>
    /// REQUIRED for encrypting authorization responses. Defaults to
    /// <c>A128CBC-HS256</c> when <c>authorization_encrypted_response_alg</c> is
    /// specified; requires it when present.
    /// </summary>
    public static readonly string AuthorizationEncryptedResponseEnc = Utf8Constants.ToInternedString(AuthorizationEncryptedResponseEncUtf8);


    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>authorization_signed_response_alg</c>.</summary>
    public static bool IsAuthorizationSignedResponseAlg(string value) =>
        string.Equals(value, AuthorizationSignedResponseAlg, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>authorization_encrypted_response_alg</c>.</summary>
    public static bool IsAuthorizationEncryptedResponseAlg(string value) =>
        string.Equals(value, AuthorizationEncryptedResponseAlg, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>authorization_encrypted_response_enc</c>.</summary>
    public static bool IsAuthorizationEncryptedResponseEnc(string value) =>
        string.Equals(value, AuthorizationEncryptedResponseEnc, StringComparison.Ordinal);
}
