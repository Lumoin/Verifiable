using Verifiable.Cryptography.Text;


namespace Verifiable.OAuth;

/// <summary>
/// OAuth 2.0 wire error code constants for use in error responses.
/// </summary>
/// <remarks>
/// Values are defined in
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>
/// and extended by subsequent specifications.
/// </remarks>
public static class OAuthErrors
{
    /// <summary>The UTF-8 source literal of <see cref="InvalidRequest"/>.</summary>
    public static ReadOnlySpan<byte> InvalidRequestUtf8 => "invalid_request"u8;

    /// <summary>The request is missing a required parameter or is otherwise malformed.</summary>
    public static readonly string InvalidRequest = Utf8Constants.ToInternedString(InvalidRequestUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidClient"/>.</summary>
    public static ReadOnlySpan<byte> InvalidClientUtf8 => "invalid_client"u8;

    /// <summary>Client authentication failed.</summary>
    public static readonly string InvalidClient = Utf8Constants.ToInternedString(InvalidClientUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidGrant"/>.</summary>
    public static ReadOnlySpan<byte> InvalidGrantUtf8 => "invalid_grant"u8;

    /// <summary>The provided authorization grant or refresh token is invalid or expired.</summary>
    public static readonly string InvalidGrant = Utf8Constants.ToInternedString(InvalidGrantUtf8);

    /// <summary>The UTF-8 source literal of <see cref="UnauthorizedClient"/>.</summary>
    public static ReadOnlySpan<byte> UnauthorizedClientUtf8 => "unauthorized_client"u8;

    /// <summary>The client is not authorized to request an authorization code.</summary>
    public static readonly string UnauthorizedClient = Utf8Constants.ToInternedString(UnauthorizedClientUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ServerError"/>.</summary>
    public static ReadOnlySpan<byte> ServerErrorUtf8 => "server_error"u8;

    /// <summary>The authorization server encountered an unexpected condition.</summary>
    public static readonly string ServerError = Utf8Constants.ToInternedString(ServerErrorUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidScope"/>.</summary>
    public static ReadOnlySpan<byte> InvalidScopeUtf8 => "invalid_scope"u8;

    /// <summary>The requested scope is invalid, unknown, or malformed.</summary>
    public static readonly string InvalidScope = Utf8Constants.ToInternedString(InvalidScopeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidTarget"/>.</summary>
    public static ReadOnlySpan<byte> InvalidTargetUtf8 => "invalid_target"u8;

    /// <summary>
    /// The requested <c>resource</c> or <c>audience</c> target is unknown, or the named target is
    /// unacceptable for issuing the requested token, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2">RFC 8693 §2.2.2</see>.
    /// </summary>
    public static readonly string InvalidTarget = Utf8Constants.ToInternedString(InvalidTargetUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AccessDenied"/>.</summary>
    public static ReadOnlySpan<byte> AccessDeniedUtf8 => "access_denied"u8;

    /// <summary>
    /// The resource owner or authorization server denied the request — for example the
    /// End-User declined consent, or deployment policy refused it. Returned from the
    /// authorization endpoint as an OAuth 2.0 Authorization Error Response (RFC 6749
    /// §4.1.2.1 redirect).
    /// </summary>
    public static readonly string AccessDenied = Utf8Constants.ToInternedString(AccessDeniedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TemporarilyUnavailable"/>.</summary>
    public static ReadOnlySpan<byte> TemporarilyUnavailableUtf8 => "temporarily_unavailable"u8;

    /// <summary>The authorization server is temporarily unable to handle the request.</summary>
    public static readonly string TemporarilyUnavailable = Utf8Constants.ToInternedString(TemporarilyUnavailableUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidRequestObject"/>.</summary>
    public static ReadOnlySpan<byte> InvalidRequestObjectUtf8 => "invalid_request_object"u8;

    /// <summary>
    /// The <c>request</c> parameter contains a JWT that fails validation per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-5">RFC 9101 §5</see> —
    /// signature verification failed, <c>typ</c> is wrong, a required claim is missing,
    /// or a timing claim is outside the acceptable window.
    /// </summary>
    public static readonly string InvalidRequestObject = Utf8Constants.ToInternedString(InvalidRequestObjectUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidRequestUri"/>.</summary>
    public static ReadOnlySpan<byte> InvalidRequestUriUtf8 => "invalid_request_uri"u8;

    /// <summary>
    /// The <c>request_uri</c> parameter could not be dereferenced or the dereferenced
    /// value is not a valid Request Object per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-5">RFC 9101 §5</see>.
    /// </summary>
    public static readonly string InvalidRequestUri = Utf8Constants.ToInternedString(InvalidRequestUriUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidClientMetadata"/>.</summary>
    public static ReadOnlySpan<byte> InvalidClientMetadataUtf8 => "invalid_client_metadata"u8;

    /// <summary>
    /// The request body submitted to the dynamic client registration endpoint
    /// was not a valid RFC 7591 §2 client metadata document, or one of the
    /// requested fields conflicts with policy per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-3.2.2">RFC 7591 §3.2.2</see>.
    /// </summary>
    public static readonly string InvalidClientMetadata = Utf8Constants.ToInternedString(InvalidClientMetadataUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidToken"/>.</summary>
    public static ReadOnlySpan<byte> InvalidTokenUtf8 => "invalid_token"u8;

    /// <summary>
    /// The bearer token presented at an RFC 7592 management endpoint is
    /// missing, malformed, or does not match the persisted registration access
    /// token.
    /// </summary>
    public static readonly string InvalidToken = Utf8Constants.ToInternedString(InvalidTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InsufficientScope"/>.</summary>
    public static ReadOnlySpan<byte> InsufficientScopeUtf8 => "insufficient_scope"u8;

    /// <summary>
    /// RFC 6750 §3.1: the request requires higher privileges than provided by
    /// the access token. Emitted by the OIDC Core §5.3 UserInfo endpoint when
    /// the validated access token does not carry the <c>openid</c> scope.
    /// </summary>
    public static readonly string InsufficientScope = Utf8Constants.ToInternedString(InsufficientScopeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InsufficientUserAuthentication"/>.</summary>
    public static ReadOnlySpan<byte> InsufficientUserAuthenticationUtf8 => "insufficient_user_authentication"u8;

    /// <summary>
    /// RFC 9470 §3: the authentication event associated with the presented access
    /// token does not meet the protected resource's authentication requirements —
    /// the subject must step up (a stronger <c>acr</c> and/or a fresher
    /// authentication per <c>max_age</c>). Emitted with HTTP 401 in a
    /// <c>WWW-Authenticate</c> step-up challenge.
    /// </summary>
    public static readonly string InsufficientUserAuthentication = Utf8Constants.ToInternedString(InsufficientUserAuthenticationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="UseDpopNonce"/>.</summary>
    public static ReadOnlySpan<byte> UseDpopNonceUtf8 => "use_dpop_nonce"u8;

    /// <summary>
    /// RFC 9449 §8: the server requires the client to retry with a fresh
    /// DPoP nonce. Emitted with HTTP 401 (token endpoint, resource server)
    /// or HTTP 400 (other endpoints) and a <c>DPoP-Nonce</c> response header
    /// carrying the new nonce value.
    /// </summary>
    public static readonly string UseDpopNonce = Utf8Constants.ToInternedString(UseDpopNonceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidDpopProof"/>.</summary>
    public static ReadOnlySpan<byte> InvalidDpopProofUtf8 => "invalid_dpop_proof"u8;

    /// <summary>
    /// RFC 9449 §8: the presented DPoP proof failed validation — signature,
    /// required claims, replay defense, or thumbprint-binding mismatch.
    /// </summary>
    public static readonly string InvalidDpopProof = Utf8Constants.ToInternedString(InvalidDpopProofUtf8);

    /// <summary>The UTF-8 source literal of <see cref="UnmetAuthenticationRequirements"/>.</summary>
    public static ReadOnlySpan<byte> UnmetAuthenticationRequirementsUtf8 => "unmet_authentication_requirements"u8;

    /// <summary>
    /// The authorization server is unable to meet the Relying Party's authentication
    /// requirements for the End-User — a requested Authentication Context Class Reference
    /// (<c>acr_values</c>) could not be satisfied, or the established authentication is
    /// older than the requested <c>max_age</c>. Returned from the authorization endpoint
    /// as an OAuth 2.0 Authorization Error Response (RFC 6749 §4.1.2.1 redirect) per the
    /// <see href="https://openid.net/specs/openid-connect-unmet-authentication-requirements-1_0.html">OpenID Connect Core Error Code <c>unmet_authentication_requirements</c></see>
    /// extension, invoked for step-up authentication by
    /// <see href="https://www.rfc-editor.org/rfc/rfc9470#section-5">RFC 9470 §5</see>.
    /// </summary>
    public static readonly string UnmetAuthenticationRequirements = Utf8Constants.ToInternedString(UnmetAuthenticationRequirementsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidAuthorizationDetails"/>.</summary>
    public static ReadOnlySpan<byte> InvalidAuthorizationDetailsUtf8 => "invalid_authorization_details"u8;

    /// <summary>
    /// RFC 9396 §5: the <c>authorization_details</c> parameter is missing a required field,
    /// carries an unsupported authorization details type, or requests authorization the server
    /// cannot grant. Usable wherever <c>invalid_scope</c> is — the authorization endpoint
    /// (redirect) and the token endpoint (400 JSON body).
    /// </summary>
    public static readonly string InvalidAuthorizationDetails = Utf8Constants.ToInternedString(InvalidAuthorizationDetailsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="UnsupportedParameter"/>.</summary>
    public static ReadOnlySpan<byte> UnsupportedParameterUtf8 => "unsupported_parameter"u8;

    /// <summary>
    /// OpenID Federation 1.0 §8.2.1: a request carried a query parameter the endpoint
    /// does not support (for example a subordinate-listing <c>trust_marked</c>,
    /// <c>trust_mark_type</c>, or <c>intermediate</c> filter the responder cannot honor).
    /// The endpoint MUST reject such a request with HTTP 400 and content type
    /// <c>application/json</c> rather than silently ignoring the unsupported filter and
    /// returning an under-filtered result.
    /// </summary>
    public static readonly string UnsupportedParameter = Utf8Constants.ToInternedString(UnsupportedParameterUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidIssuer"/>.</summary>
    public static ReadOnlySpan<byte> InvalidIssuerUtf8 => "invalid_issuer"u8;

    /// <summary>
    /// OpenID Federation 1.0 §8.9: a federation endpoint cannot serve the requested
    /// issuer. The HTTP response status code SHOULD be 404 (Not Found).
    /// </summary>
    public static readonly string InvalidIssuer = Utf8Constants.ToInternedString(InvalidIssuerUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidSubject"/>.</summary>
    public static ReadOnlySpan<byte> InvalidSubjectUtf8 => "invalid_subject"u8;

    /// <summary>
    /// OpenID Federation 1.0 §8.9: a federation endpoint cannot serve the requested
    /// subject. The HTTP response status code SHOULD be 404 (Not Found).
    /// </summary>
    public static readonly string InvalidSubject = Utf8Constants.ToInternedString(InvalidSubjectUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidTrustAnchor"/>.</summary>
    public static ReadOnlySpan<byte> InvalidTrustAnchorUtf8 => "invalid_trust_anchor"u8;

    /// <summary>
    /// OpenID Federation 1.0 §8.9: the requested Trust Anchor cannot be found or used.
    /// The HTTP response status code SHOULD be 404 (Not Found). Also returned in §12.1.3
    /// Pushed Authorization Request error responses when trust could not be established.
    /// </summary>
    public static readonly string InvalidTrustAnchor = Utf8Constants.ToInternedString(InvalidTrustAnchorUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidTrustChain"/>.</summary>
    public static ReadOnlySpan<byte> InvalidTrustChainUtf8 => "invalid_trust_chain"u8;

    /// <summary>
    /// OpenID Federation 1.0 §8.9: the Trust Chain cannot be validated. The HTTP response
    /// status code SHOULD be 400 (Bad Request). Also returned in §12.1.3 Pushed
    /// Authorization Request error responses when trust could not be established.
    /// </summary>
    public static readonly string InvalidTrustChain = Utf8Constants.ToInternedString(InvalidTrustChainUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidMetadata"/>.</summary>
    public static ReadOnlySpan<byte> InvalidMetadataUtf8 => "invalid_metadata"u8;

    /// <summary>
    /// OpenID Federation 1.0 §8.9: Metadata or Metadata Policy values are invalid or
    /// conflict. The HTTP response status code SHOULD be 400 (Bad Request). Also returned
    /// in §12.1.3 Pushed Authorization Request error responses when the RP metadata was
    /// invalid or in conflict with policy.
    /// </summary>
    public static readonly string InvalidMetadata = Utf8Constants.ToInternedString(InvalidMetadataUtf8);

    /// <summary>The UTF-8 source literal of <see cref="NotFound"/>.</summary>
    public static ReadOnlySpan<byte> NotFoundUtf8 => "not_found"u8;

    /// <summary>
    /// OpenID Federation 1.0 §8.9: the requested Entity Identifier cannot be found.
    /// The HTTP response status code SHOULD be 404 (Not Found).
    /// </summary>
    public static readonly string NotFound = Utf8Constants.ToInternedString(NotFoundUtf8);
}
