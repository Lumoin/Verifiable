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
    /// <summary>The request is missing a required parameter or is otherwise malformed.</summary>
    public static readonly string InvalidRequest = "invalid_request";

    /// <summary>Client authentication failed.</summary>
    public static readonly string InvalidClient = "invalid_client";

    /// <summary>The provided authorization grant or refresh token is invalid or expired.</summary>
    public static readonly string InvalidGrant = "invalid_grant";

    /// <summary>The client is not authorized to request an authorization code.</summary>
    public static readonly string UnauthorizedClient = "unauthorized_client";

    /// <summary>The authorization server encountered an unexpected condition.</summary>
    public static readonly string ServerError = "server_error";

    /// <summary>The requested scope is invalid, unknown, or malformed.</summary>
    public static readonly string InvalidScope = "invalid_scope";

    /// <summary>The authorization server is temporarily unable to handle the request.</summary>
    public static readonly string TemporarilyUnavailable = "temporarily_unavailable";

    /// <summary>
    /// The <c>request</c> parameter contains a JWT that fails validation per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-5">RFC 9101 §5</see> —
    /// signature verification failed, <c>typ</c> is wrong, a required claim is missing,
    /// or a timing claim is outside the acceptable window.
    /// </summary>
    public static readonly string InvalidRequestObject = "invalid_request_object";

    /// <summary>
    /// The <c>request_uri</c> parameter could not be dereferenced or the dereferenced
    /// value is not a valid Request Object per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-5">RFC 9101 §5</see>.
    /// </summary>
    public static readonly string InvalidRequestUri = "invalid_request_uri";

    /// <summary>
    /// The request body submitted to the dynamic client registration endpoint
    /// was not a valid RFC 7591 §2 client metadata document, or one of the
    /// requested fields conflicts with policy per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-3.2.2">RFC 7591 §3.2.2</see>.
    /// </summary>
    public static readonly string InvalidClientMetadata = "invalid_client_metadata";

    /// <summary>
    /// The bearer token presented at an RFC 7592 management endpoint is
    /// missing, malformed, or does not match the persisted registration access
    /// token.
    /// </summary>
    public static readonly string InvalidToken = "invalid_token";

    /// <summary>
    /// RFC 6750 §3.1: the request requires higher privileges than provided by
    /// the access token. Emitted by the OIDC Core §5.3 UserInfo endpoint when
    /// the validated access token does not carry the <c>openid</c> scope.
    /// </summary>
    public static readonly string InsufficientScope = "insufficient_scope";

    /// <summary>
    /// RFC 9449 §8: the server requires the client to retry with a fresh
    /// DPoP nonce. Emitted with HTTP 401 (token endpoint, resource server)
    /// or HTTP 400 (other endpoints) and a <c>DPoP-Nonce</c> response header
    /// carrying the new nonce value.
    /// </summary>
    public static readonly string UseDpopNonce = "use_dpop_nonce";

    /// <summary>
    /// RFC 9449 §8: the presented DPoP proof failed validation — signature,
    /// required claims, replay defense, or thumbprint-binding mismatch.
    /// </summary>
    public static readonly string InvalidDpopProof = "invalid_dpop_proof";
}
