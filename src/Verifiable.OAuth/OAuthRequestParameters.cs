using System.Diagnostics;

namespace Verifiable.OAuth;

/// <summary>
/// Parameter name constants for OAuth 2.0 authorization and token endpoint requests.
/// </summary>
/// <remarks>
/// <para>
/// All names are defined in the following specifications:
/// </para>
/// <list type="bullet">
///   <item><description><see href="https://www.rfc-editor.org/rfc/rfc6749">RFC 6749</see> — OAuth 2.0 Authorization Framework.</description></item>
///   <item><description><see href="https://www.rfc-editor.org/rfc/rfc7636">RFC 7636</see> — Proof Key for Code Exchange (PKCE).</description></item>
///   <item><description><see href="https://www.rfc-editor.org/rfc/rfc9126">RFC 9126</see> — Pushed Authorization Requests (PAR).</description></item>
///   <item><description><see href="https://www.rfc-editor.org/rfc/rfc9207">RFC 9207</see> — Authorization Server Issuer Identification.</description></item>
///   <item><description><see href="https://www.rfc-editor.org/rfc/rfc9700">RFC 9700</see> — OAuth 2.0 Security Best Current Practice.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("OAuthRequestParameters")]
public static class OAuthRequestParameters
{
    //Authorization request parameters — RFC 6749 §4.1.1.

    /// <summary>
    /// The <c>response_type</c> parameter.
    /// Required in authorization requests.
    /// Value <c>code</c> requests an authorization code per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749 §4.1.1</see>.
    /// </summary>
    public const string ResponseType = "response_type";

    /// <summary>
    /// The <c>client_id</c> parameter.
    /// The client identifier issued to the client during registration per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-2.2">RFC 6749 §2.2</see>.
    /// </summary>
    public const string ClientId = "client_id";

    /// <summary>
    /// The <c>redirect_uri</c> parameter.
    /// The URI to which the authorization server redirects the user-agent per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2">RFC 6749 §3.1.2</see>.
    /// Comparison MUST use exact string matching per RFC 9700 §2.1.
    /// </summary>
    public const string RedirectUri = "redirect_uri";

    /// <summary>
    /// The <c>scope</c> parameter.
    /// The scope of the access request per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see>.
    /// </summary>
    public const string Scope = "scope";

    /// <summary>
    /// The <c>state</c> parameter.
    /// An opaque value used to maintain state between the request and callback.
    /// Provides CSRF protection per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.12">RFC 6749 §10.12</see>
    /// and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.7">RFC 9700 §4.7</see>.
    /// </summary>
    public const string State = "state";

    //Authorization response parameters — RFC 6749 §4.1.2.

    /// <summary>
    /// The <c>code</c> parameter.
    /// The authorization code returned by the authorization server per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>.
    /// </summary>
    public const string Code = "code";

    /// <summary>
    /// The <c>iss</c> parameter.
    /// The issuer identifier of the authorization server included in the authorization response
    /// as a countermeasure against mix-up attacks per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9207">RFC 9207</see>
    /// and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC 9700 §4.4</see>.
    /// </summary>
    public const string Iss = "iss";

    //Token request parameters — RFC 6749 §4.1.3.

    /// <summary>
    /// The <c>grant_type</c> parameter.
    /// Specifies the grant type being used per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3">RFC 6749 §4.1.3</see>.
    /// </summary>
    public const string GrantType = "grant_type";

    //Token response parameters — RFC 6749 §5.1.

    /// <summary>
    /// The <c>access_token</c> parameter.
    /// The access token issued by the authorization server per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>.
    /// </summary>
    public const string AccessToken = "access_token";

    /// <summary>
    /// The <c>token_type</c> parameter.
    /// The type of the token issued per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>.
    /// </summary>
    public const string TokenType = "token_type";

    /// <summary>
    /// The <c>expires_in</c> parameter.
    /// The lifetime in seconds of the access token per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>.
    /// </summary>
    public const string ExpiresIn = "expires_in";

    /// <summary>
    /// The <c>refresh_token</c> parameter.
    /// The refresh token used to obtain a new access token per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>.
    /// </summary>
    public const string RefreshToken = "refresh_token";

    //Revocation parameters — RFC 7009.

    /// <summary>
    /// The <c>token</c> parameter.
    /// The token to be revoked per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7009#section-2.1">RFC 7009 §2.1</see>.
    /// </summary>
    public const string Token = "token";

    /// <summary>
    /// The <c>token_type_hint</c> parameter.
    /// A hint about the type of the token submitted for revocation per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7009#section-2.1">RFC 7009 §2.1</see>.
    /// </summary>
    public const string TokenTypeHint = "token_type_hint";

    //PKCE parameters — RFC 7636.

    /// <summary>
    /// The <c>code_challenge</c> parameter.
    /// The PKCE code challenge sent in the authorization request per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>.
    /// Absence of this parameter from a PAR body indicates a PKCE downgrade vulnerability
    /// per <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.8">RFC 9700 §4.8</see>.
    /// </summary>
    public const string CodeChallenge = "code_challenge";

    /// <summary>
    /// The <c>code_challenge_method</c> parameter.
    /// The method used to derive the code challenge per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>.
    /// Must be <c>S256</c> per HAIP 1.0 and RFC 9700 §2.1.1.
    /// </summary>
    public const string CodeChallengeMethod = "code_challenge_method";

    /// <summary>
    /// The <c>code_verifier</c> parameter.
    /// The PKCE code verifier sent in the token request per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.5">RFC 7636 §4.5</see>.
    /// Absence of this parameter from a token request when a <c>code_challenge</c> was
    /// registered indicates an authorization code injection attempt per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.5">RFC 9700 §4.5</see>.
    /// </summary>
    public const string CodeVerifier = "code_verifier";

    //PAR parameters — RFC 9126.

    /// <summary>
    /// The <c>request_uri</c> parameter.
    /// The URI reference returned by the PAR endpoint and used in the subsequent
    /// authorization request per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">RFC 9126 §2.2</see>.
    /// </summary>
    public const string RequestUri = "request_uri";

    //Grant type values — RFC 6749.

    /// <summary>
    /// The <c>authorization_code</c> grant type value.
    /// </summary>
    public const string GrantTypeAuthorizationCode = "authorization_code";

    /// <summary>
    /// The <c>refresh_token</c> grant type value.
    /// </summary>
    public const string GrantTypeRefreshToken = "refresh_token";

    //Code challenge method values — RFC 7636.

    /// <summary>
    /// The <c>S256</c> code challenge method value.
    /// The only permitted value per HAIP 1.0 and RFC 9700 §2.1.1. The plain method
    /// must not be used as it negates PKCE's protection against downgrade attacks.
    /// </summary>
    public const string CodeChallengeMethodS256 = "S256";

    //Response type values — RFC 6749.

    /// <summary>The <c>code</c> response type value.</summary>
    public const string ResponseTypeCode = "code";
}