using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Siop;

/// <summary>
/// Error codes a Self-Issued OP returns to the RP in addition to the OAuth 2.0 and
/// OpenID Connect Core Authentication Error Response codes, per
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-10.3">SIOPv2 §10.3</see>.
/// </summary>
/// <remarks>
/// The RP consumes these when interpreting an error Authorization Response; a wallet
/// acting as a Self-Issued OP produces them. Base OAuth error codes live in
/// <see cref="OAuthErrors"/>.
/// </remarks>
[DebuggerDisplay("SiopErrors")]
public static class SiopErrors
{
    /// <summary>The UTF-8 source literal of <see cref="UserCancelled"/>.</summary>
    public static ReadOnlySpan<byte> UserCancelledUtf8 => "user_cancelled"u8;

    /// <summary>
    /// The <c>user_cancelled</c> error — the End-User cancelled the Authorization
    /// Request from the RP.
    /// </summary>
    public static readonly string UserCancelled = Utf8Constants.ToInternedString(UserCancelledUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClientMetadataValueNotSupported"/>.</summary>
    public static ReadOnlySpan<byte> ClientMetadataValueNotSupportedUtf8 => "client_metadata_value_not_supported"u8;

    /// <summary>
    /// The <c>client_metadata_value_not_supported</c> error — the Self-Issued OP does
    /// not support some Relying Party parameter values received in the request.
    /// </summary>
    public static readonly string ClientMetadataValueNotSupported = Utf8Constants.ToInternedString(ClientMetadataValueNotSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SubjectSyntaxTypesNotSupported"/>.</summary>
    public static ReadOnlySpan<byte> SubjectSyntaxTypesNotSupportedUtf8 => "subject_syntax_types_not_supported"u8;

    /// <summary>
    /// The <c>subject_syntax_types_not_supported</c> error — the Self-Issued OP supports
    /// none of the Subject Syntax Types the RP communicated in
    /// <c>subject_syntax_types_supported</c>.
    /// </summary>
    public static readonly string SubjectSyntaxTypesNotSupported = Utf8Constants.ToInternedString(SubjectSyntaxTypesNotSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidClientMetadataUri"/>.</summary>
    public static ReadOnlySpan<byte> InvalidClientMetadataUriUtf8 => "invalid_client_metadata_uri"u8;

    /// <summary>
    /// The <c>invalid_client_metadata_uri</c> error — the <c>client_metadata_uri</c> in
    /// the Authorization Request returns an error or contains invalid data.
    /// </summary>
    public static readonly string InvalidClientMetadataUri = Utf8Constants.ToInternedString(InvalidClientMetadataUriUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidClientMetadataObject"/>.</summary>
    public static ReadOnlySpan<byte> InvalidClientMetadataObjectUtf8 => "invalid_client_metadata_object"u8;

    /// <summary>
    /// The <c>invalid_client_metadata_object</c> error — the <c>client_metadata</c>
    /// parameter contains an invalid RP parameter Object.
    /// </summary>
    public static readonly string InvalidClientMetadataObject = Utf8Constants.ToInternedString(InvalidClientMetadataObjectUtf8);


    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>user_cancelled</c>.</summary>
    public static bool IsUserCancelled(string value) =>
        string.Equals(value, UserCancelled, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>client_metadata_value_not_supported</c>.</summary>
    public static bool IsClientMetadataValueNotSupported(string value) =>
        string.Equals(value, ClientMetadataValueNotSupported, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>subject_syntax_types_not_supported</c>.</summary>
    public static bool IsSubjectSyntaxTypesNotSupported(string value) =>
        string.Equals(value, SubjectSyntaxTypesNotSupported, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>invalid_client_metadata_uri</c>.</summary>
    public static bool IsInvalidClientMetadataUri(string value) =>
        string.Equals(value, InvalidClientMetadataUri, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>invalid_client_metadata_object</c>.</summary>
    public static bool IsInvalidClientMetadataObject(string value) =>
        string.Equals(value, InvalidClientMetadataObject, StringComparison.Ordinal);


    /// <summary>
    /// Returns the canonical form of a well-known SIOPv2 error code, or the original
    /// value when not recognized. Comparison is case-sensitive.
    /// </summary>
    public static string GetCanonicalizedValue(string value) => value switch
    {
        _ when IsUserCancelled(value) => UserCancelled,
        _ when IsClientMetadataValueNotSupported(value) => ClientMetadataValueNotSupported,
        _ when IsSubjectSyntaxTypesNotSupported(value) => SubjectSyntaxTypesNotSupported,
        _ when IsInvalidClientMetadataUri(value) => InvalidClientMetadataUri,
        _ when IsInvalidClientMetadataObject(value) => InvalidClientMetadataObject,
        _ => value
    };
}
