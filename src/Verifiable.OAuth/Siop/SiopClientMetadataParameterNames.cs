using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Siop;

/// <summary>
/// Member NAMES of the SIOPv2 <c>client_metadata</c> (Relying Party Metadata) object per
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-7.5">SIOPv2 §7.5</see>.
/// </summary>
/// <remarks>
/// The sibling of <see cref="SiopAuthorizationRequestParameterNames"/>: that class names
/// the top-level Authorization Request parameters (§9), this one names the members
/// carried INSIDE the <c>client_metadata</c> parameter's value. Other OpenID Connect
/// Dynamic Client Registration member names MAY appear alongside these
/// (<c>redirect_uris</c>, <c>jwks_uri</c>, <c>id_token_encrypted_response_alg</c>, …).
/// </remarks>
[DebuggerDisplay("SiopClientMetadataParameterNames")]
public static class SiopClientMetadataParameterNames
{
    /// <summary>The UTF-8 source literal of <see cref="SubjectSyntaxTypesSupported"/>.</summary>
    public static ReadOnlySpan<byte> SubjectSyntaxTypesSupportedUtf8 => "subject_syntax_types_supported"u8;

    /// <summary>
    /// The §7.5 <c>subject_syntax_types_supported</c> member (REQUIRED) — the Subject
    /// Syntax Type identifiers the RP supports; values per
    /// <see cref="SiopSubjectSyntaxTypes"/>. Also a Self-Issued OP Discovery Metadata
    /// member (§6.1).
    /// </summary>
    public static readonly string SubjectSyntaxTypesSupported = Utf8Constants.ToInternedString(SubjectSyntaxTypesSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IdTokenSignedResponseAlg"/>.</summary>
    public static ReadOnlySpan<byte> IdTokenSignedResponseAlgUtf8 => "id_token_signed_response_alg"u8;

    /// <summary>
    /// The <c>id_token_signed_response_alg</c> OpenID Connect Dynamic Client
    /// Registration member — the JWS algorithm the RP expects for the ID Token.
    /// </summary>
    public static readonly string IdTokenSignedResponseAlg = Utf8Constants.ToInternedString(IdTokenSignedResponseAlgUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IdTokenTypesSupported"/>.</summary>
    public static ReadOnlySpan<byte> IdTokenTypesSupportedUtf8 => "id_token_types_supported"u8;

    /// <summary>
    /// The <c>id_token_types_supported</c> Self-Issued OP Discovery Metadata member
    /// (§6.1) — the ID Token types the OP supports; values per
    /// <see cref="SiopIdTokenTypes"/>.
    /// </summary>
    public static readonly string IdTokenTypesSupported = Utf8Constants.ToInternedString(IdTokenTypesSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RequestObjectSigningAlgValuesSupported"/>.</summary>
    public static ReadOnlySpan<byte> RequestObjectSigningAlgValuesSupportedUtf8 => "request_object_signing_alg_values_supported"u8;

    /// <summary>
    /// The <c>request_object_signing_alg_values_supported</c> Self-Issued OP Discovery
    /// Metadata member (§6.1) — the JWS signing algorithms the OP supports for Request
    /// Objects (OIDC Core §6.1). Valid values include <c>none</c>, <c>RS256</c>,
    /// <c>ES256</c>, <c>ES256K</c>, and <c>EdDSA</c>.
    /// </summary>
    public static readonly string RequestObjectSigningAlgValuesSupported = Utf8Constants.ToInternedString(RequestObjectSigningAlgValuesSupportedUtf8);


    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>subject_syntax_types_supported</c>.</summary>
    public static bool IsSubjectSyntaxTypesSupported(string value) =>
        string.Equals(value, SubjectSyntaxTypesSupported, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>id_token_signed_response_alg</c>.</summary>
    public static bool IsIdTokenSignedResponseAlg(string value) =>
        string.Equals(value, IdTokenSignedResponseAlg, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>id_token_types_supported</c>.</summary>
    public static bool IsIdTokenTypesSupported(string value) =>
        string.Equals(value, IdTokenTypesSupported, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>request_object_signing_alg_values_supported</c>.</summary>
    public static bool IsRequestObjectSigningAlgValuesSupported(string value) =>
        string.Equals(value, RequestObjectSigningAlgValuesSupported, StringComparison.Ordinal);
}
