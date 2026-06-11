using Verifiable.Cryptography.Text;


namespace Verifiable.OAuth;

/// <summary>
/// Well-known VALUES for OAuth 2.0 wire request parameters per
/// RFC 6749 + extensions. Distinct from
/// <see cref="OAuthRequestParameterNames"/> which holds the NAMES of
/// those parameters; this class holds the canonical VALUES the wire
/// can carry for a small set of name-constrained parameters
/// (<c>grant_type</c>, <c>code_challenge_method</c>, <c>response_type</c>).
/// </summary>
/// <remarks>
/// Most OAuth parameter values are flow-specific (a code, a URL, a scope
/// string, etc.) and don't have well-known canonical forms. Only the
/// parameters whose values are constrained to a small enumerated set
/// have entries here.
/// </remarks>
public static class OAuthRequestParameterValues
{
    //grant_type values — RFC 6749.

    /// <summary>The UTF-8 source literal of <see cref="GrantTypeAuthorizationCode"/>.</summary>
    public static ReadOnlySpan<byte> GrantTypeAuthorizationCodeUtf8 => "authorization_code"u8;

    /// <summary>
    /// The <c>authorization_code</c> value for the
    /// <see cref="OAuthRequestParameterNames.GrantType"/> parameter per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3">RFC 6749 §4.1.3</see>.
    /// </summary>
    public static readonly string GrantTypeAuthorizationCode = Utf8Constants.ToInternedString(GrantTypeAuthorizationCodeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="GrantTypeRefreshToken"/>.</summary>
    public static ReadOnlySpan<byte> GrantTypeRefreshTokenUtf8 => "refresh_token"u8;

    /// <summary>
    /// The <c>refresh_token</c> value for the
    /// <see cref="OAuthRequestParameterNames.GrantType"/> parameter per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 §6</see>.
    /// </summary>
    public static readonly string GrantTypeRefreshToken = Utf8Constants.ToInternedString(GrantTypeRefreshTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="GrantTypeClientCredentials"/>.</summary>
    public static ReadOnlySpan<byte> GrantTypeClientCredentialsUtf8 => "client_credentials"u8;

    /// <summary>
    /// The <c>client_credentials</c> value for the
    /// <see cref="OAuthRequestParameterNames.GrantType"/> parameter per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.4.2">RFC 6749 §4.4.2</see>.
    /// </summary>
    public static readonly string GrantTypeClientCredentials = Utf8Constants.ToInternedString(GrantTypeClientCredentialsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="GrantTypePreAuthorizedCode"/>.</summary>
    public static ReadOnlySpan<byte> GrantTypePreAuthorizedCodeUtf8 => "urn:ietf:params:oauth:grant-type:pre-authorized_code"u8;

    /// <summary>
    /// The <c>urn:ietf:params:oauth:grant-type:pre-authorized_code</c> value for the
    /// <see cref="OAuthRequestParameterNames.GrantType"/> parameter per
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">OID4VCI 1.0 §6.1</see>
    /// (registered in Appendix G.1.1). Selects the Pre-Authorized Code Flow, in which
    /// the Wallet exchanges a <see cref="OAuthRequestParameterNames.PreAuthorizedCode"/>
    /// (and optional <see cref="OAuthRequestParameterNames.TxCode"/>) for an access token
    /// without a prior Authorization Request.
    /// </summary>
    public static readonly string GrantTypePreAuthorizedCode = Utf8Constants.ToInternedString(GrantTypePreAuthorizedCodeUtf8);

    //code_challenge_method values — RFC 7636.

    /// <summary>The UTF-8 source literal of <see cref="CodeChallengeMethodS256"/>.</summary>
    public static ReadOnlySpan<byte> CodeChallengeMethodS256Utf8 => "S256"u8;

    /// <summary>
    /// The <c>S256</c> value for the
    /// <see cref="OAuthRequestParameterNames.CodeChallengeMethod"/> parameter
    /// per <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>.
    /// The only permitted value per HAIP 1.0 and RFC 9700 §2.1.1; the
    /// plain method must not be used as it negates PKCE's protection
    /// against downgrade attacks.
    /// </summary>
    public static readonly string CodeChallengeMethodS256 = Utf8Constants.ToInternedString(CodeChallengeMethodS256Utf8);

    //response_type values — RFC 6749.

    /// <summary>The UTF-8 source literal of <see cref="ResponseTypeCode"/>.</summary>
    public static ReadOnlySpan<byte> ResponseTypeCodeUtf8 => "code"u8;

    /// <summary>
    /// The <c>code</c> value for the
    /// <see cref="OAuthRequestParameterNames.ResponseType"/> parameter per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749 §4.1.1</see>.
    /// Triggers the authorization-code flow.
    /// </summary>
    public static readonly string ResponseTypeCode = Utf8Constants.ToInternedString(ResponseTypeCodeUtf8);
}
