using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Jarm;

/// <summary>
/// Authorization Server metadata parameter NAMES introduced by JARM per
/// <see href="https://openid.net/specs/oauth-v2-jarm-final.html#section-4">JARM §4</see>,
/// registered in the IANA OAuth Authorization Server Metadata registry. The four JARM
/// <c>response_modes_supported</c> values an AS additionally advertises live in
/// <see cref="JarmResponseModes"/>.
/// </summary>
[DebuggerDisplay("JarmServerMetadataParameterNames")]
public static class JarmServerMetadataParameterNames
{
    /// <summary>The UTF-8 source literal of <see cref="AuthorizationSigningAlgValuesSupported"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationSigningAlgValuesSupportedUtf8 => "authorization_signing_alg_values_supported"u8;

    /// <summary>
    /// The <c>authorization_signing_alg_values_supported</c> parameter — the JWS
    /// <c>alg</c> values the authorization endpoint supports for signing the response.
    /// </summary>
    public static readonly string AuthorizationSigningAlgValuesSupported = Utf8Constants.ToInternedString(AuthorizationSigningAlgValuesSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthorizationEncryptionAlgValuesSupported"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationEncryptionAlgValuesSupportedUtf8 => "authorization_encryption_alg_values_supported"u8;

    /// <summary>
    /// The <c>authorization_encryption_alg_values_supported</c> parameter — the JWE
    /// <c>alg</c> values the authorization endpoint supports for encrypting the response.
    /// </summary>
    public static readonly string AuthorizationEncryptionAlgValuesSupported = Utf8Constants.ToInternedString(AuthorizationEncryptionAlgValuesSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthorizationEncryptionEncValuesSupported"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationEncryptionEncValuesSupportedUtf8 => "authorization_encryption_enc_values_supported"u8;

    /// <summary>
    /// The <c>authorization_encryption_enc_values_supported</c> parameter — the JWE
    /// <c>enc</c> values the authorization endpoint supports for encrypting the response.
    /// </summary>
    public static readonly string AuthorizationEncryptionEncValuesSupported = Utf8Constants.ToInternedString(AuthorizationEncryptionEncValuesSupportedUtf8);


    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>authorization_signing_alg_values_supported</c>.</summary>
    public static bool IsAuthorizationSigningAlgValuesSupported(string value) =>
        string.Equals(value, AuthorizationSigningAlgValuesSupported, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>authorization_encryption_alg_values_supported</c>.</summary>
    public static bool IsAuthorizationEncryptionAlgValuesSupported(string value) =>
        string.Equals(value, AuthorizationEncryptionAlgValuesSupported, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>authorization_encryption_enc_values_supported</c>.</summary>
    public static bool IsAuthorizationEncryptionEncValuesSupported(string value) =>
        string.Equals(value, AuthorizationEncryptionEncValuesSupported, StringComparison.Ordinal);
}
