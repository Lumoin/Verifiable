namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// Conventional route path constants and field name constants for the Authorization
/// Code flow.
/// </summary>
/// <remarks>
/// <para>
/// These are the paths the library uses in its documentation examples. They are not
/// mandated by any RFC — the application author chooses the actual paths when wiring
/// routes and may use any values. Reference these constants in application wiring code
/// to stay consistent with the library's conventions and to make path changes
/// propagate automatically.
/// </para>
/// <para>
/// Example ASP.NET wiring using these constants:
/// </para>
/// <code>
/// var group = app.MapGroup(AuthCodeFlowRoutes.Base);
/// group.MapPost(AuthCodeFlowRoutes.Par,      (fields, ct) => AuthCodeFlowHandlers.HandleParAsync(fields, options, ct));
/// group.MapGet(AuthCodeFlowRoutes.Callback,  (fields, ct) => AuthCodeFlowHandlers.HandleCallbackAsync(fields, options, ct));
/// group.MapPost(AuthCodeFlowRoutes.Token,    (fields, ct) => AuthCodeFlowHandlers.HandleTokenAsync(fields, options, ct));
/// group.MapPost(AuthCodeFlowRoutes.Revocation,(fields, ct) => AuthCodeFlowHandlers.HandleRevocationAsync(fields, options, ct));
/// </code>
/// </remarks>
public static class AuthCodeFlowRoutes
{
    /// <summary>
    /// Base path for the Authorization Code flow route group.
    /// </summary>
    public const string Base = "/oauth";

    /// <summary>
    /// Relative path for the pushed authorization request endpoint.
    /// Receives the initial PAR POST and returns a <c>request_uri</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126">RFC 9126</see>.
    /// </summary>
    public const string Par = "par";

    /// <summary>
    /// Relative path for the authorization redirect callback endpoint.
    /// Receives the authorization code and <c>state</c> from the authorization server
    /// per <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>.
    /// </summary>
    public const string Callback = "callback";

    /// <summary>
    /// Relative path for the token exchange endpoint.
    /// Receives authorization code exchange and token refresh requests per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3">RFC 6749 §4.1.3</see>.
    /// </summary>
    public const string Token = "token";

    /// <summary>
    /// Relative path for the token revocation endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7009">RFC 7009</see>.
    /// </summary>
    public const string Revocation = "revoke";

    /// <summary>
    /// The internal field name used to carry the flow identifier from the callback
    /// response into the subsequent token exchange request. This is a library
    /// convention, not an RFC-defined parameter name.
    /// </summary>
    public const string FlowIdField = "flow_id";
}