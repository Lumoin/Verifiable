using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Siop;

/// <summary>
/// Authorization Request parameter NAMES native to Self-Issued OpenID Provider v2 per
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-9">SIOPv2 §9</see>.
/// </summary>
/// <remarks>
/// <para>
/// Contains only parameters SIOPv2 defines on top of OpenID Connect Core. Parameters
/// inherited without semantic change — <c>response_type</c>, <c>client_id</c>,
/// <c>redirect_uri</c>, <c>scope</c>, <c>state</c>, <c>response_mode</c>, <c>nonce</c> —
/// are defined in <see cref="OAuthRequestParameterNames"/>. The <c>client_metadata</c>
/// parameter is shared with OpenID for Verifiable Presentations (SIOPv2 §7.3 defers to
/// it) and lives in <see cref="Oid4Vp.Oid4VpAuthorizationRequestParameterNames.ClientMetadata"/>.
/// </para>
/// <para>
/// Values for <c>id_token_type</c> live in <see cref="SiopIdTokenTypes"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("SiopAuthorizationRequestParameterNames")]
public static class SiopAuthorizationRequestParameterNames
{
    /// <summary>The UTF-8 source literal of <see cref="IdTokenType"/>.</summary>
    public static ReadOnlySpan<byte> IdTokenTypeUtf8 => "id_token_type"u8;

    /// <summary>
    /// The <c>id_token_type</c> parameter — a space-separated string of the ID Token
    /// types the RP wants to obtain, in order of preference. SIOPv2 §9. The default
    /// when absent is <see cref="SiopIdTokenTypes.AttesterSignedIdToken"/>.
    /// </summary>
    public static readonly string IdTokenType = Utf8Constants.ToInternedString(IdTokenTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClientMetadataUri"/>.</summary>
    public static ReadOnlySpan<byte> ClientMetadataUriUtf8 => "client_metadata_uri"u8;

    /// <summary>
    /// The <c>client_metadata_uri</c> parameter — a URL the Self-Issued OP fetches
    /// the RP's metadata from. SIOPv2 §9: mutually exclusive with
    /// <c>client_metadata</c>, and MUST NOT be present when the RP passes its
    /// metadata via OpenID Federation 1.0 Automatic Registration.
    /// </summary>
    public static readonly string ClientMetadataUri = Utf8Constants.ToInternedString(ClientMetadataUriUtf8);


    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>id_token_type</c>.</summary>
    public static bool IsIdTokenType(string value) =>
        string.Equals(value, IdTokenType, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>client_metadata_uri</c>.</summary>
    public static bool IsClientMetadataUri(string value) =>
        string.Equals(value, ClientMetadataUri, StringComparison.Ordinal);


    /// <summary>
    /// Returns the canonical form of a well-known SIOPv2-native Authorization
    /// Request parameter name, or the original value when not recognized.
    /// Comparison is case-sensitive.
    /// </summary>
    public static string GetCanonicalizedValue(string value) => value switch
    {
        _ when IsIdTokenType(value) => IdTokenType,
        _ when IsClientMetadataUri(value) => ClientMetadataUri,
        _ => value
    };
}
