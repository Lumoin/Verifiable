namespace Verifiable.OAuth.Server;

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
    public const string InvalidRequest = "invalid_request";

    /// <summary>Client authentication failed.</summary>
    public const string InvalidClient = "invalid_client";

    /// <summary>The provided authorization grant or refresh token is invalid or expired.</summary>
    public const string InvalidGrant = "invalid_grant";

    /// <summary>The client is not authorized to request an authorization code.</summary>
    public const string UnauthorizedClient = "unauthorized_client";

    /// <summary>The authorization server encountered an unexpected condition.</summary>
    public const string ServerError = "server_error";

    /// <summary>The requested scope is invalid, unknown, or malformed.</summary>
    public const string InvalidScope = "invalid_scope";

    /// <summary>The authorization server is temporarily unable to handle the request.</summary>
    public const string TemporarilyUnavailable = "temporarily_unavailable";
}
