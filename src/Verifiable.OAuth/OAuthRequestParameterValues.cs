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

    /// <summary>
    /// The <c>authorization_code</c> value for the
    /// <see cref="OAuthRequestParameterNames.GrantType"/> parameter per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3">RFC 6749 §4.1.3</see>.
    /// </summary>
    public static readonly string GrantTypeAuthorizationCode = "authorization_code";

    /// <summary>
    /// The <c>refresh_token</c> value for the
    /// <see cref="OAuthRequestParameterNames.GrantType"/> parameter per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 §6</see>.
    /// </summary>
    public static readonly string GrantTypeRefreshToken = "refresh_token";

    /// <summary>
    /// The <c>client_credentials</c> value for the
    /// <see cref="OAuthRequestParameterNames.GrantType"/> parameter per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.4.2">RFC 6749 §4.4.2</see>.
    /// </summary>
    public static readonly string GrantTypeClientCredentials = "client_credentials";

    //code_challenge_method values — RFC 7636.

    /// <summary>
    /// The <c>S256</c> value for the
    /// <see cref="OAuthRequestParameterNames.CodeChallengeMethod"/> parameter
    /// per <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>.
    /// The only permitted value per HAIP 1.0 and RFC 9700 §2.1.1; the
    /// plain method must not be used as it negates PKCE's protection
    /// against downgrade attacks.
    /// </summary>
    public static readonly string CodeChallengeMethodS256 = "S256";

    //response_type values — RFC 6749.

    /// <summary>
    /// The <c>code</c> value for the
    /// <see cref="OAuthRequestParameterNames.ResponseType"/> parameter per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749 §4.1.1</see>.
    /// Triggers the authorization-code flow.
    /// </summary>
    public static readonly string ResponseTypeCode = "code";
}
