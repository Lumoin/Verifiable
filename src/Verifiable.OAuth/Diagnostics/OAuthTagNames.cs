using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Diagnostics;

/// <summary>
/// Tag (attribute) names for OAuth wire facts the library already holds typed at the point of
/// use, added to <see cref="System.Diagnostics.Activity.Current"/> — the host-loop dispatch span
/// — from that point, with no new parsing.
/// </summary>
/// <remarks>
/// <para>
/// Distinct from <see cref="OAuthEventNames"/>, which names anomaly and defect span events;
/// these are routine per-request facts every applicable grant carries. Never a token, a code, a
/// subject identifier, or a secret: see <c>documents/AuthorizationServerDesign.md</c> §4.3 for
/// the tenant key's own, stricter rule.
/// </para>
/// </remarks>
public static class OAuthTagNames
{
    /// <summary>The UTF-8 source literal of <see cref="GrantType"/>.</summary>
    public static ReadOnlySpan<byte> GrantTypeUtf8 => "oauth.token.grant_type"u8;

    /// <summary>The wire <c>grant_type</c> value the token endpoint issued tokens for.</summary>
    public static string GrantType { get; } = Utf8Constants.ToInternedString(GrantTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClientId"/>.</summary>
    public static ReadOnlySpan<byte> ClientIdUtf8 => "oauth.token.client_id"u8;

    /// <summary>The requesting client's <c>client_id</c>.</summary>
    public static string ClientId { get; } = Utf8Constants.ToInternedString(ClientIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="GrantedScope"/>.</summary>
    public static ReadOnlySpan<byte> GrantedScopeUtf8 => "oauth.token.granted_scope"u8;

    /// <summary>The granted scope string carried by the tokens issued for the request.</summary>
    public static string GrantedScope { get; } = Utf8Constants.ToInternedString(GrantedScopeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="PkceMethod"/>.</summary>
    public static ReadOnlySpan<byte> PkceMethodUtf8 => "oauth.token.pkce_method"u8;

    /// <summary>
    /// The RFC 7636 §4.3 <c>code_challenge_method</c> the redeemed authorization code carried.
    /// </summary>
    public static string PkceMethod { get; } = Utf8Constants.ToInternedString(PkceMethodUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AccessTokenJti"/>.</summary>
    public static ReadOnlySpan<byte> AccessTokenJtiUtf8 => "oauth.token.access_token_jti"u8;

    /// <summary>The <c>jti</c> claim of the issued access token.</summary>
    public static string AccessTokenJti { get; } = Utf8Constants.ToInternedString(AccessTokenJtiUtf8);
}
