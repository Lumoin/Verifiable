using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Introspection;

/// <summary>
/// Client metadata parameter NAMES introduced by RFC 9701 per
/// <see href="https://www.rfc-editor.org/rfc/rfc9701#section-6">RFC 9701 §6</see>,
/// registered in the IANA OAuth Dynamic Client Registration Metadata registry. The
/// resource server registers as a client; these parameters configure how its JWT
/// introspection responses are secured.
/// </summary>
[DebuggerDisplay("IntrospectionClientMetadataParameterNames")]
public static class IntrospectionClientMetadataParameterNames
{
    /// <summary>The UTF-8 source literal of <see cref="IntrospectionSignedResponseAlg"/>.</summary>
    public static ReadOnlySpan<byte> IntrospectionSignedResponseAlgUtf8 => "introspection_signed_response_alg"u8;

    /// <summary>
    /// The <c>introspection_signed_response_alg</c> parameter — the JWS <c>alg</c> for
    /// signing introspection responses. Defaults to <c>RS256</c> when omitted.
    /// </summary>
    public static readonly string IntrospectionSignedResponseAlg = Utf8Constants.ToInternedString(IntrospectionSignedResponseAlgUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IntrospectionEncryptedResponseAlg"/>.</summary>
    public static ReadOnlySpan<byte> IntrospectionEncryptedResponseAlgUtf8 => "introspection_encrypted_response_alg"u8;

    /// <summary>
    /// The <c>introspection_encrypted_response_alg</c> parameter — the JWE <c>alg</c>
    /// for content key encryption (sign-then-encrypt Nested JWT when both are
    /// requested). No encryption when omitted.
    /// </summary>
    public static readonly string IntrospectionEncryptedResponseAlg = Utf8Constants.ToInternedString(IntrospectionEncryptedResponseAlgUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IntrospectionEncryptedResponseEnc"/>.</summary>
    public static ReadOnlySpan<byte> IntrospectionEncryptedResponseEncUtf8 => "introspection_encrypted_response_enc"u8;

    /// <summary>
    /// The <c>introspection_encrypted_response_enc</c> parameter — the JWE <c>enc</c>
    /// for content encryption. Defaults to <c>A128CBC-HS256</c>; MUST NOT be specified
    /// without <c>introspection_encrypted_response_alg</c>.
    /// </summary>
    public static readonly string IntrospectionEncryptedResponseEnc = Utf8Constants.ToInternedString(IntrospectionEncryptedResponseEncUtf8);


    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>introspection_signed_response_alg</c>.</summary>
    public static bool IsIntrospectionSignedResponseAlg(string value) =>
        string.Equals(value, IntrospectionSignedResponseAlg, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>introspection_encrypted_response_alg</c>.</summary>
    public static bool IsIntrospectionEncryptedResponseAlg(string value) =>
        string.Equals(value, IntrospectionEncryptedResponseAlg, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>introspection_encrypted_response_enc</c>.</summary>
    public static bool IsIntrospectionEncryptedResponseEnc(string value) =>
        string.Equals(value, IntrospectionEncryptedResponseEnc, StringComparison.Ordinal);
}
