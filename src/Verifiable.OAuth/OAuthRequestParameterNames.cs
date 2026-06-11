using System.Diagnostics;
using System.Text;
using Verifiable.Cryptography.Text;

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

    /// <summary>The UTF-8 source literal of <see cref="ResponseType"/>.</summary>
    public static ReadOnlySpan<byte> ResponseTypeUtf8 => "response_type"u8;

    /// <summary>
    /// The <c>response_type</c> parameter.
    /// Required in authorization requests.
    /// Value <c>code</c> requests an authorization code per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749 §4.1.1</see>.
    /// </summary>
    public static readonly string ResponseType = Utf8Constants.ToInternedString(ResponseTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClientId"/>.</summary>
    public static ReadOnlySpan<byte> ClientIdUtf8 => "client_id"u8;

    /// <summary>
    /// The <c>client_id</c> parameter.
    /// The client identifier issued to the client during registration per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-2.2">RFC 6749 §2.2</see>.
    /// </summary>
    public static readonly string ClientId = Utf8Constants.ToInternedString(ClientIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RedirectUri"/>.</summary>
    public static ReadOnlySpan<byte> RedirectUriUtf8 => "redirect_uri"u8;

    /// <summary>
    /// The <c>redirect_uri</c> parameter.
    /// The URI to which the authorization server redirects the user-agent per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2">RFC 6749 §3.1.2</see>.
    /// Comparison MUST use exact string matching per RFC 9700 §2.1.
    /// </summary>
    public static readonly string RedirectUri = Utf8Constants.ToInternedString(RedirectUriUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Scope"/>.</summary>
    public static ReadOnlySpan<byte> ScopeUtf8 => "scope"u8;

    /// <summary>
    /// The <c>scope</c> parameter.
    /// The scope of the access request per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see>.
    /// </summary>
    public static readonly string Scope = Utf8Constants.ToInternedString(ScopeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AcrValues"/>.</summary>
    public static ReadOnlySpan<byte> AcrValuesUtf8 => "acr_values"u8;

    /// <summary>
    /// The <c>acr_values</c> parameter. A space-separated, preference-ordered list of
    /// requested Authentication Context Class Reference values per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">OIDC Core §3.1.2.1</see>;
    /// used by <see href="https://www.rfc-editor.org/rfc/rfc9470#section-4">RFC 9470 §4</see>
    /// step-up authentication to convey the authentication strength the resource server demands.
    /// </summary>
    public static readonly string AcrValues = Utf8Constants.ToInternedString(AcrValuesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="MaxAge"/>.</summary>
    public static ReadOnlySpan<byte> MaxAgeUtf8 => "max_age"u8;

    /// <summary>
    /// The <c>max_age</c> parameter. The maximum allowable elapsed time in seconds since the
    /// End-User's last active authentication per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">OIDC Core §3.1.2.1</see>;
    /// a non-negative integer. When present, the issued ID Token MUST carry an <c>auth_time</c>
    /// claim, and <c>max_age=0</c> requires a fresh authentication (equivalent to <c>prompt=login</c>).
    /// Used by <see href="https://www.rfc-editor.org/rfc/rfc9470#section-4">RFC 9470 §4</see> step-up.
    /// </summary>
    public static readonly string MaxAge = Utf8Constants.ToInternedString(MaxAgeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="State"/>.</summary>
    public static ReadOnlySpan<byte> StateUtf8 => "state"u8;

    /// <summary>
    /// The <c>state</c> parameter.
    /// An opaque value used to maintain state between the request and callback.
    /// Provides CSRF protection per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.12">RFC 6749 §10.12</see>
    /// and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.7">RFC 9700 §4.7</see>.
    /// </summary>
    public static readonly string State = Utf8Constants.ToInternedString(StateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IdTokenHint"/>.</summary>
    public static ReadOnlySpan<byte> IdTokenHintUtf8 => "id_token_hint"u8;

    /// <summary>
    /// The <c>id_token_hint</c> parameter — a previously-issued ID Token passed to the
    /// end-session endpoint as a hint about the End-User's session, per
    /// <see href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout">OIDC RP-Initiated Logout §2</see>.
    /// </summary>
    public static readonly string IdTokenHint = Utf8Constants.ToInternedString(IdTokenHintUtf8);

    /// <summary>The UTF-8 source literal of <see cref="PostLogoutRedirectUri"/>.</summary>
    public static ReadOnlySpan<byte> PostLogoutRedirectUriUtf8 => "post_logout_redirect_uri"u8;

    /// <summary>
    /// The <c>post_logout_redirect_uri</c> parameter — where the OP redirects the
    /// User Agent after logout; validated against the client's registered values
    /// (RP-Initiated Logout §2).
    /// </summary>
    public static readonly string PostLogoutRedirectUri = Utf8Constants.ToInternedString(PostLogoutRedirectUriUtf8);

    /// <summary>The UTF-8 source literal of <see cref="LogoutHint"/>.</summary>
    public static ReadOnlySpan<byte> LogoutHintUtf8 => "logout_hint"u8;

    /// <summary>
    /// The <c>logout_hint</c> parameter — a hint to the OP about the End-User to log
    /// out (RP-Initiated Logout §2).
    /// </summary>
    public static readonly string LogoutHint = Utf8Constants.ToInternedString(LogoutHintUtf8);

    /// <summary>The UTF-8 source literal of <see cref="UiLocales"/>.</summary>
    public static ReadOnlySpan<byte> UiLocalesUtf8 => "ui_locales"u8;

    /// <summary>
    /// The <c>ui_locales</c> parameter — the End-User's preferred languages for any
    /// logout-confirmation UI (RP-Initiated Logout §2).
    /// </summary>
    public static readonly string UiLocales = Utf8Constants.ToInternedString(UiLocalesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ResponseMode"/>.</summary>
    public static ReadOnlySpan<byte> ResponseModeUtf8 => "response_mode"u8;

    /// <summary>
    /// The <c>response_mode</c> parameter.
    /// Informs the authorization server of the mechanism to be used for returning
    /// parameters from the authorization endpoint, per
    /// <see href="https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html">OAuth 2.0 Multiple Response Type Encoding Practices</see>.
    /// </summary>
    public static readonly string ResponseMode = Utf8Constants.ToInternedString(ResponseModeUtf8);

    //Authorization response parameters — RFC 6749 §4.1.2.

    /// <summary>The UTF-8 source literal of <see cref="Code"/>.</summary>
    public static ReadOnlySpan<byte> CodeUtf8 => "code"u8;

    /// <summary>
    /// The <c>code</c> parameter.
    /// The authorization code returned by the authorization server per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>.
    /// </summary>
    public static readonly string Code = Utf8Constants.ToInternedString(CodeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Iss"/>.</summary>
    public static ReadOnlySpan<byte> IssUtf8 => "iss"u8;

    /// <summary>
    /// The <c>iss</c> parameter.
    /// The issuer identifier of the authorization server included in the authorization response
    /// as a countermeasure against mix-up attacks per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9207">RFC 9207</see>
    /// and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC 9700 §4.4</see>.
    /// </summary>
    public static readonly string Iss = Utf8Constants.ToInternedString(IssUtf8);

    //Token request parameters — RFC 6749 §4.1.3.

    /// <summary>The UTF-8 source literal of <see cref="GrantType"/>.</summary>
    public static ReadOnlySpan<byte> GrantTypeUtf8 => "grant_type"u8;

    /// <summary>
    /// The <c>grant_type</c> parameter.
    /// Specifies the grant type being used per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3">RFC 6749 §4.1.3</see>.
    /// </summary>
    public static readonly string GrantType = Utf8Constants.ToInternedString(GrantTypeUtf8);

    //Token response parameters — RFC 6749 §5.1.

    /// <summary>The UTF-8 source literal of <see cref="AccessToken"/>.</summary>
    public static ReadOnlySpan<byte> AccessTokenUtf8 => "access_token"u8;

    /// <summary>
    /// The <c>access_token</c> parameter.
    /// The access token issued by the authorization server per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>.
    /// </summary>
    public static readonly string AccessToken = Utf8Constants.ToInternedString(AccessTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TokenType"/>.</summary>
    public static ReadOnlySpan<byte> TokenTypeUtf8 => "token_type"u8;

    /// <summary>
    /// The <c>token_type</c> parameter.
    /// The type of the token issued per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>.
    /// </summary>
    public static readonly string TokenType = Utf8Constants.ToInternedString(TokenTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ExpiresIn"/>.</summary>
    public static ReadOnlySpan<byte> ExpiresInUtf8 => "expires_in"u8;

    /// <summary>
    /// The <c>expires_in</c> parameter.
    /// The lifetime in seconds of the access token per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>.
    /// </summary>
    public static readonly string ExpiresIn = Utf8Constants.ToInternedString(ExpiresInUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RefreshToken"/>.</summary>
    public static ReadOnlySpan<byte> RefreshTokenUtf8 => "refresh_token"u8;

    /// <summary>
    /// The <c>refresh_token</c> parameter.
    /// The refresh token used to obtain a new access token per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>.
    /// </summary>
    public static readonly string RefreshToken = Utf8Constants.ToInternedString(RefreshTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IdToken"/>.</summary>
    public static ReadOnlySpan<byte> IdTokenUtf8 => "id_token"u8;

    /// <summary>
    /// The <c>id_token</c> parameter.
    /// The ID Token issued alongside the access token in an OpenID Connect token
    /// response per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse">OpenID Connect Core 1.0 §3.1.3.3</see>.
    /// </summary>
    public static readonly string IdToken = Utf8Constants.ToInternedString(IdTokenUtf8);

    //Revocation parameters — RFC 7009.

    /// <summary>The UTF-8 source literal of <see cref="Token"/>.</summary>
    public static ReadOnlySpan<byte> TokenUtf8 => "token"u8;

    /// <summary>
    /// The <c>token</c> parameter.
    /// The token to be revoked per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7009#section-2.1">RFC 7009 §2.1</see>.
    /// </summary>
    public static readonly string Token = Utf8Constants.ToInternedString(TokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TokenTypeHint"/>.</summary>
    public static ReadOnlySpan<byte> TokenTypeHintUtf8 => "token_type_hint"u8;

    /// <summary>
    /// The <c>token_type_hint</c> parameter.
    /// A hint about the type of the token submitted for revocation per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7009#section-2.1">RFC 7009 §2.1</see>.
    /// </summary>
    public static readonly string TokenTypeHint = Utf8Constants.ToInternedString(TokenTypeHintUtf8);

    //PKCE parameters — RFC 7636.

    /// <summary>The UTF-8 source literal of <see cref="CodeChallenge"/>.</summary>
    public static ReadOnlySpan<byte> CodeChallengeUtf8 => "code_challenge"u8;

    /// <summary>
    /// The <c>code_challenge</c> parameter.
    /// The PKCE code challenge sent in the authorization request per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>.
    /// Absence of this parameter from a PAR body indicates a PKCE downgrade vulnerability
    /// per <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.8">RFC 9700 §4.8</see>.
    /// </summary>
    public static readonly string CodeChallenge = Utf8Constants.ToInternedString(CodeChallengeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CodeChallengeMethod"/>.</summary>
    public static ReadOnlySpan<byte> CodeChallengeMethodUtf8 => "code_challenge_method"u8;

    /// <summary>
    /// The <c>code_challenge_method</c> parameter.
    /// The method used to derive the code challenge per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>.
    /// Must be <c>S256</c> per HAIP 1.0 and RFC 9700 §2.1.1.
    /// </summary>
    public static readonly string CodeChallengeMethod = Utf8Constants.ToInternedString(CodeChallengeMethodUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CodeVerifier"/>.</summary>
    public static ReadOnlySpan<byte> CodeVerifierUtf8 => "code_verifier"u8;

    /// <summary>
    /// The <c>code_verifier</c> parameter.
    /// The PKCE code verifier sent in the token request per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.5">RFC 7636 §4.5</see>.
    /// Absence of this parameter from a token request when a <c>code_challenge</c> was
    /// registered indicates an authorization code injection attempt per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.5">RFC 9700 §4.5</see>.
    /// </summary>
    public static readonly string CodeVerifier = Utf8Constants.ToInternedString(CodeVerifierUtf8);

    //PAR parameters — RFC 9126.

    /// <summary>The UTF-8 source literal of <see cref="RequestUri"/>.</summary>
    public static ReadOnlySpan<byte> RequestUriUtf8 => "request_uri"u8;

    /// <summary>
    /// The <c>request_uri</c> parameter.
    /// The URI reference returned by the PAR endpoint and used in the subsequent
    /// authorization request per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">RFC 9126 §2.2</see>.
    /// </summary>
    public static readonly string RequestUri = Utf8Constants.ToInternedString(RequestUriUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Request"/>.</summary>
    public static ReadOnlySpan<byte> RequestUtf8 => "request"u8;

    /// <summary>
    /// The <c>request</c> parameter.
    /// Carries a signed JWT Authorization Request (JAR) per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-5">RFC 9101 §5</see>
    /// either in the body of a Pushed Authorization Request per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-3">RFC 9126 §3</see>
    /// or in the query of a direct authorization request per RFC 9101 §6.1.
    /// </summary>
    public static readonly string Request = Utf8Constants.ToInternedString(RequestUtf8);

    //Device authorization parameters — RFC 8628.

    /// <summary>The UTF-8 source literal of <see cref="DeviceCode"/>.</summary>
    public static ReadOnlySpan<byte> DeviceCodeUtf8 => "device_code"u8;

    /// <summary>
    /// The <c>device_code</c> parameter.
    /// Used by the client when polling the token endpoint during the Device
    /// Authorization Grant per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8628#section-3.4">RFC 8628 §3.4</see>.
    /// Acts as the correlation key for the device flow — stored at device authorization
    /// time and presented at each polling request.
    /// </summary>
    public static readonly string DeviceCode = Utf8Constants.ToInternedString(DeviceCodeUtf8);

    //OID4VP response parameter — OID4VP 1.0 §8.2.

    /// <summary>The UTF-8 source literal of <see cref="Response"/>.</summary>
    public static ReadOnlySpan<byte> ResponseUtf8 => "response"u8;

    /// <summary>
    /// The <c>response</c> parameter.
    /// The encrypted Authorization Response JWE POSTed by the Wallet to the
    /// <c>response_uri</c> per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0 §8.2</see>.
    /// </summary>
    public static readonly string Response = Utf8Constants.ToInternedString(ResponseUtf8);

    //OID4VCI Pre-Authorized Code Flow token-request parameters — OID4VCI 1.0 §6.1.

    /// <summary>The UTF-8 source literal of <see cref="PreAuthorizedCode"/>.</summary>
    public static ReadOnlySpan<byte> PreAuthorizedCodeUtf8 => "pre-authorized_code"u8;

    /// <summary>
    /// The <c>pre-authorized_code</c> parameter.
    /// The code representing the authorization to obtain Credentials of a certain
    /// type, presented at the token endpoint when <c>grant_type</c> is
    /// <see cref="OAuthRequestParameterValues.GrantTypePreAuthorizedCode"/> per
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">OID4VCI 1.0 §6.1</see>.
    /// MUST be present when that grant type is used.
    /// </summary>
    public static readonly string PreAuthorizedCode = Utf8Constants.ToInternedString(PreAuthorizedCodeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TxCode"/>.</summary>
    public static ReadOnlySpan<byte> TxCodeUtf8 => "tx_code"u8;

    /// <summary>
    /// The <c>tx_code</c> parameter.
    /// The Transaction Code value the End-User conveys out-of-band, presented at
    /// the token endpoint in the Pre-Authorized Code Flow per
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">OID4VCI 1.0 §6.1</see>.
    /// MUST be present if a <c>tx_code</c> object was present in the Credential
    /// Offer, and MUST only be used with the Pre-Authorized Code grant type.
    /// </summary>
    public static readonly string TxCode = Utf8Constants.ToInternedString(TxCodeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthorizationDetails"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationDetailsUtf8 => "authorization_details"u8;

    /// <summary>
    /// The <c>authorization_details</c> parameter — a JSON array of authorization details
    /// objects conveying fine-grained authorization data per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9396#section-2">RFC 9396 §2</see>.
    /// Accepted at the authorization endpoint (and PAR) and at the token endpoint
    /// (RFC 9396 §6.1 / OID4VCI 1.0 §6.1.1), and returned enriched in the token response
    /// (RFC 9396 §7 / OID4VCI 1.0 §6.2).
    /// </summary>
    public static readonly string AuthorizationDetails = Utf8Constants.ToInternedString(AuthorizationDetailsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IssuerState"/>.</summary>
    public static ReadOnlySpan<byte> IssuerStateUtf8 => "issuer_state"u8;

    /// <summary>
    /// The <c>issuer_state</c> Authorization Request parameter — the opaque value the Wallet
    /// echoes from a Credential Offer's <c>grants.authorization_code.issuer_state</c> back to
    /// the issuer's Authorization Server, identifying a processing context the issuer set up
    /// per
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-5.1.3">OID4VCI 1.0 §5.1.3</see>.
    /// The offer-side member name is defined in
    /// <see cref="Oid4Vci.CredentialOfferParameterNames.IssuerState"/>; this is the request-side
    /// parameter. Per §5.1.3 the issuer MUST treat the value as not guaranteed to originate from
    /// this Credential Issuer — it could have been injected by an attacker — so the library
    /// surfaces it to the application as untrusted input and validates nothing about it itself.
    /// </summary>
    public static readonly string IssuerState = Utf8Constants.ToInternedString(IssuerStateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Resource"/>.</summary>
    public static ReadOnlySpan<byte> ResourceUtf8 => "resource"u8;

    /// <summary>
    /// The <c>resource</c> Authorization Request / Token Request parameter — the
    /// protected-resource indicator per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>, an
    /// absolute URI that MAY appear more than once to name multiple target resources. OID4VCI
    /// 1.0 §5.1.2 RECOMMENDS its use — with the Credential Issuer's identifier value — when the
    /// Credential Issuer metadata carries an <c>authorization_servers</c> property, so the
    /// Authorization Server can differentiate Credential Issuers. The library reads and surfaces
    /// the value(s); honoring them is the application's decision.
    /// </summary>
    public static readonly string Resource = Utf8Constants.ToInternedString(ResourceUtf8);
}
