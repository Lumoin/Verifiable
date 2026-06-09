using System.Diagnostics;

namespace Verifiable.OAuth;

/// <summary>
/// Well-known parameter NAMES for OAuth 2.0 wire requests per RFC 6749
/// + extensions. These are form-urlencoded field names, query-string
/// parameter names, and JSON-object keys inside JAR request objects.
/// </summary>
/// <remarks>
/// <para>
/// These are the NAMES of request parameters (e.g., <c>"code_challenge"</c>,
/// <c>"response_type"</c>, <c>"client_id"</c>), not their VALUES. Most
/// parameter values are flow-specific (codes, identifiers, URIs, scope
/// strings); the small enumerated-set values
/// (<c>grant_type</c> = <c>authorization_code</c> | <c>refresh_token</c>,
/// <c>code_challenge_method</c> = <c>S256</c>,
/// <c>response_type</c> = <c>code</c>) live in
/// <see cref="OAuthRequestParameterValues"/>.
/// </para>
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
[DebuggerDisplay("OAuthRequestParameterNames")]
public static class OAuthRequestParameterNames
{
    //Authorization request parameters — RFC 6749 §4.1.1.

    /// <summary>
    /// The <c>response_type</c> parameter.
    /// Required in authorization requests.
    /// Value <c>code</c> requests an authorization code per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749 §4.1.1</see>.
    /// </summary>
    public static readonly string ResponseType = "response_type";

    /// <summary>
    /// The <c>client_id</c> parameter.
    /// The client identifier issued to the client during registration per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-2.2">RFC 6749 §2.2</see>.
    /// </summary>
    public static readonly string ClientId = "client_id";

    /// <summary>
    /// The <c>redirect_uri</c> parameter.
    /// The URI to which the authorization server redirects the user-agent per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2">RFC 6749 §3.1.2</see>.
    /// Comparison MUST use exact string matching per RFC 9700 §2.1.
    /// </summary>
    public static readonly string RedirectUri = "redirect_uri";

    /// <summary>
    /// The <c>scope</c> parameter.
    /// The scope of the access request per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see>.
    /// </summary>
    public static readonly string Scope = "scope";

    /// <summary>
    /// The <c>acr_values</c> parameter. A space-separated, preference-ordered list of
    /// requested Authentication Context Class Reference values per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">OIDC Core §3.1.2.1</see>;
    /// used by <see href="https://www.rfc-editor.org/rfc/rfc9470#section-4">RFC 9470 §4</see>
    /// step-up authentication to convey the authentication strength the resource server demands.
    /// </summary>
    public static readonly string AcrValues = "acr_values";

    /// <summary>
    /// The <c>max_age</c> parameter. The maximum allowable elapsed time in seconds since the
    /// End-User's last active authentication per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">OIDC Core §3.1.2.1</see>;
    /// a non-negative integer. When present, the issued ID Token MUST carry an <c>auth_time</c>
    /// claim, and <c>max_age=0</c> requires a fresh authentication (equivalent to <c>prompt=login</c>).
    /// Used by <see href="https://www.rfc-editor.org/rfc/rfc9470#section-4">RFC 9470 §4</see> step-up.
    /// </summary>
    public static readonly string MaxAge = "max_age";

    /// <summary>
    /// The <c>state</c> parameter.
    /// An opaque value used to maintain state between the request and callback.
    /// Provides CSRF protection per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.12">RFC 6749 §10.12</see>
    /// and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.7">RFC 9700 §4.7</see>.
    /// </summary>
    public static readonly string State = "state";

    /// <summary>
    /// The <c>id_token_hint</c> parameter — a previously-issued ID Token passed to the
    /// end-session endpoint as a hint about the End-User's session, per
    /// <see href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout">OIDC RP-Initiated Logout §2</see>.
    /// </summary>
    public static readonly string IdTokenHint = "id_token_hint";

    /// <summary>
    /// The <c>post_logout_redirect_uri</c> parameter — where the OP redirects the
    /// User Agent after logout; validated against the client's registered values
    /// (RP-Initiated Logout §2).
    /// </summary>
    public static readonly string PostLogoutRedirectUri = "post_logout_redirect_uri";

    /// <summary>
    /// The <c>logout_hint</c> parameter — a hint to the OP about the End-User to log
    /// out (RP-Initiated Logout §2).
    /// </summary>
    public static readonly string LogoutHint = "logout_hint";

    /// <summary>
    /// The <c>ui_locales</c> parameter — the End-User's preferred languages for any
    /// logout-confirmation UI (RP-Initiated Logout §2).
    /// </summary>
    public static readonly string UiLocales = "ui_locales";

    /// <summary>
    /// The <c>response_mode</c> parameter.
    /// Informs the authorization server of the mechanism to be used for returning
    /// parameters from the authorization endpoint, per
    /// <see href="https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html">OAuth 2.0 Multiple Response Type Encoding Practices</see>.
    /// </summary>
    public static readonly string ResponseMode = "response_mode";

    //Authorization response parameters — RFC 6749 §4.1.2.

    /// <summary>
    /// The <c>code</c> parameter.
    /// The authorization code returned by the authorization server per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>.
    /// </summary>
    public static readonly string Code = "code";

    /// <summary>
    /// The <c>iss</c> parameter.
    /// The issuer identifier of the authorization server included in the authorization response
    /// as a countermeasure against mix-up attacks per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9207">RFC 9207</see>
    /// and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC 9700 §4.4</see>.
    /// </summary>
    public static readonly string Iss = "iss";

    //Token request parameters — RFC 6749 §4.1.3.

    /// <summary>
    /// The <c>grant_type</c> parameter.
    /// Specifies the grant type being used per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3">RFC 6749 §4.1.3</see>.
    /// </summary>
    public static readonly string GrantType = "grant_type";

    //Token response parameters — RFC 6749 §5.1.

    /// <summary>
    /// The <c>access_token</c> parameter.
    /// The access token issued by the authorization server per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>.
    /// </summary>
    public static readonly string AccessToken = "access_token";

    /// <summary>
    /// The <c>token_type</c> parameter.
    /// The type of the token issued per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>.
    /// </summary>
    public static readonly string TokenType = "token_type";

    /// <summary>
    /// The <c>expires_in</c> parameter.
    /// The lifetime in seconds of the access token per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>.
    /// </summary>
    public static readonly string ExpiresIn = "expires_in";

    /// <summary>
    /// The <c>refresh_token</c> parameter.
    /// The refresh token used to obtain a new access token per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>.
    /// </summary>
    public static readonly string RefreshToken = "refresh_token";

    /// <summary>
    /// The <c>id_token</c> parameter.
    /// The ID Token issued alongside the access token in an OpenID Connect token
    /// response per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse">OpenID Connect Core 1.0 §3.1.3.3</see>.
    /// </summary>
    public static readonly string IdToken = "id_token";

    //Revocation parameters — RFC 7009.

    /// <summary>
    /// The <c>token</c> parameter.
    /// The token to be revoked per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7009#section-2.1">RFC 7009 §2.1</see>.
    /// </summary>
    public static readonly string Token = "token";

    /// <summary>
    /// The <c>token_type_hint</c> parameter.
    /// A hint about the type of the token submitted for revocation per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7009#section-2.1">RFC 7009 §2.1</see>.
    /// </summary>
    public static readonly string TokenTypeHint = "token_type_hint";

    //PKCE parameters — RFC 7636.

    /// <summary>
    /// The <c>code_challenge</c> parameter.
    /// The PKCE code challenge sent in the authorization request per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>.
    /// Absence of this parameter from a PAR body indicates a PKCE downgrade vulnerability
    /// per <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.8">RFC 9700 §4.8</see>.
    /// </summary>
    public static readonly string CodeChallenge = "code_challenge";

    /// <summary>
    /// The <c>code_challenge_method</c> parameter.
    /// The method used to derive the code challenge per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>.
    /// Must be <c>S256</c> per HAIP 1.0 and RFC 9700 §2.1.1.
    /// </summary>
    public static readonly string CodeChallengeMethod = "code_challenge_method";

    /// <summary>
    /// The <c>code_verifier</c> parameter.
    /// The PKCE code verifier sent in the token request per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.5">RFC 7636 §4.5</see>.
    /// Absence of this parameter from a token request when a <c>code_challenge</c> was
    /// registered indicates an authorization code injection attempt per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.5">RFC 9700 §4.5</see>.
    /// </summary>
    public static readonly string CodeVerifier = "code_verifier";

    //PAR parameters — RFC 9126.

    /// <summary>
    /// The <c>request_uri</c> parameter.
    /// The URI reference returned by the PAR endpoint and used in the subsequent
    /// authorization request per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">RFC 9126 §2.2</see>.
    /// </summary>
    public static readonly string RequestUri = "request_uri";

    /// <summary>
    /// The <c>request</c> parameter.
    /// Carries a signed JWT Authorization Request (JAR) per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-5">RFC 9101 §5</see>
    /// either in the body of a Pushed Authorization Request per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-3">RFC 9126 §3</see>
    /// or in the query of a direct authorization request per RFC 9101 §6.1.
    /// </summary>
    public static readonly string Request = "request";

    //Device authorization parameters — RFC 8628.

    /// <summary>
    /// The <c>device_code</c> parameter.
    /// Used by the client when polling the token endpoint during the Device
    /// Authorization Grant per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8628#section-3.4">RFC 8628 §3.4</see>.
    /// Acts as the correlation key for the device flow — stored at device authorization
    /// time and presented at each polling request.
    /// </summary>
    public static readonly string DeviceCode = "device_code";

    //OID4VP response parameter — OID4VP 1.0 §8.2.

    /// <summary>
    /// The <c>response</c> parameter.
    /// The encrypted Authorization Response JWE POSTed by the Wallet to the
    /// <c>response_uri</c> per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0 §8.2</see>.
    /// </summary>
    public static readonly string Response = "response";
}
