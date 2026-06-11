using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Introspection;

/// <summary>
/// Authorization Server metadata parameter NAMES introduced by RFC 9701 per
/// <see href="https://www.rfc-editor.org/rfc/rfc9701#section-7">RFC 9701 §7</see>,
/// registered in the IANA OAuth Authorization Server Metadata registry. Resource
/// servers use these to parametrise their client registration requests.
/// </summary>
[DebuggerDisplay("IntrospectionServerMetadataParameterNames")]
public static class IntrospectionServerMetadataParameterNames
{
    /// <summary>The UTF-8 source literal of <see cref="IntrospectionSigningAlgValuesSupported"/>.</summary>
    public static ReadOnlySpan<byte> IntrospectionSigningAlgValuesSupportedUtf8 => "introspection_signing_alg_values_supported"u8;

    /// <summary>
    /// The <c>introspection_signing_alg_values_supported</c> parameter — the JWS
    /// <c>alg</c> values the introspection endpoint supports for signing the response.
    /// </summary>
    public static readonly string IntrospectionSigningAlgValuesSupported = Utf8Constants.ToInternedString(IntrospectionSigningAlgValuesSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IntrospectionEncryptionAlgValuesSupported"/>.</summary>
    public static ReadOnlySpan<byte> IntrospectionEncryptionAlgValuesSupportedUtf8 => "introspection_encryption_alg_values_supported"u8;

    /// <summary>
    /// The <c>introspection_encryption_alg_values_supported</c> parameter — the JWE
    /// <c>alg</c> values the introspection endpoint supports for content key encryption.
    /// </summary>
    public static readonly string IntrospectionEncryptionAlgValuesSupported = Utf8Constants.ToInternedString(IntrospectionEncryptionAlgValuesSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IntrospectionEncryptionEncValuesSupported"/>.</summary>
    public static ReadOnlySpan<byte> IntrospectionEncryptionEncValuesSupportedUtf8 => "introspection_encryption_enc_values_supported"u8;

    /// <summary>
    /// The <c>introspection_encryption_enc_values_supported</c> parameter — the JWE
    /// <c>enc</c> values the introspection endpoint supports for content encryption.
    /// </summary>
    public static readonly string IntrospectionEncryptionEncValuesSupported = Utf8Constants.ToInternedString(IntrospectionEncryptionEncValuesSupportedUtf8);


    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>introspection_signing_alg_values_supported</c>.</summary>
    public static bool IsIntrospectionSigningAlgValuesSupported(string value) =>
        string.Equals(value, IntrospectionSigningAlgValuesSupported, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>introspection_encryption_alg_values_supported</c>.</summary>
    public static bool IsIntrospectionEncryptionAlgValuesSupported(string value) =>
        string.Equals(value, IntrospectionEncryptionAlgValuesSupported, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>introspection_encryption_enc_values_supported</c>.</summary>
    public static bool IsIntrospectionEncryptionEncValuesSupported(string value) =>
        string.Equals(value, IntrospectionEncryptionEncValuesSupported, StringComparison.Ordinal);
}
