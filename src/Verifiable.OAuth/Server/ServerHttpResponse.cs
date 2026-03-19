using System.Diagnostics;
using System.Net;

namespace Verifiable.OAuth.Server;

/// <summary>
/// A neutral HTTP response produced by Authorization Server handlers.
/// </summary>
/// <remarks>
/// <para>
/// Carries the minimum information the ASP.NET skin needs to form an HTTP response:
/// status code, body, content type, and an optional redirect location. No ASP.NET
/// types appear here — the skin translates this to whatever its framework expects.
/// </para>
/// <para>
/// Use the static factory methods to construct instances. The body is always a
/// UTF-8 JSON string for data responses and empty for redirects and 404 responses.
/// </para>
/// </remarks>
[DebuggerDisplay("HttpResponseData StatusCode={StatusCode}")]
public sealed record ServerHttpResponse
{
    /// <summary>The HTTP status code.</summary>
    public required int StatusCode { get; init; }

    /// <summary>The response body. Empty string for redirects and 404 responses.</summary>
    public required string Body { get; init; }

    /// <summary>
    /// The <c>Content-Type</c> header value. Empty string when no body is present.
    /// </summary>
    public required string ContentType { get; init; }

    /// <summary>
    /// The <c>Location</c> header value for redirect responses.
    /// <see langword="null"/> for non-redirect responses.
    /// </summary>
    public string? Location { get; init; }


    /// <summary>Returns a 200 OK response with a JSON body.</summary>
    public static ServerHttpResponse Ok(string body, string contentType) =>
        new()
        {
            StatusCode = (int)HttpStatusCode.OK,
            Body = body,
            ContentType = contentType
        };


    /// <summary>
    /// Returns a 302 Found redirect response to <paramref name="location"/>.
    /// </summary>
    public static ServerHttpResponse Redirect(string location) =>
        new()
        {
            StatusCode = (int)HttpStatusCode.Found,
            Body = string.Empty,
            ContentType = string.Empty,
            Location = location
        };


    /// <summary>Returns a 400 Bad Request with an OAuth error JSON body.</summary>
    public static ServerHttpResponse BadRequest(string error, string description) =>
        new()
        {
            StatusCode = (int)HttpStatusCode.BadRequest,
            Body = BuildErrorBody(error, description),
            ContentType = "application/json"
        };


    /// <summary>Returns a 401 Unauthorized with an OAuth error JSON body.</summary>
    public static ServerHttpResponse Unauthorized(string error, string description) =>
        new()
        {
            StatusCode = (int)HttpStatusCode.Unauthorized,
            Body = BuildErrorBody(error, description),
            ContentType = "application/json"
        };


    /// <summary>Returns a 403 Forbidden with an OAuth error JSON body.</summary>
    public static ServerHttpResponse Forbidden(string error, string description) =>
        new()
        {
            StatusCode = (int)HttpStatusCode.Forbidden,
            Body = BuildErrorBody(error, description),
            ContentType = "application/json"
        };


    /// <summary>Returns a 404 Not Found with an empty body.</summary>
    public static ServerHttpResponse NotFound() =>
        new()
        {
            StatusCode = (int)HttpStatusCode.NotFound,
            Body = string.Empty,
            ContentType = string.Empty
        };


    /// <summary>Returns a 500 Internal Server Error with an OAuth error JSON body.</summary>
    public static ServerHttpResponse ServerError(string error, string description) =>
        new()
        {
            StatusCode = (int)HttpStatusCode.InternalServerError,
            Body = BuildErrorBody(error, description),
            ContentType = "application/json"
        };


    private static string BuildErrorBody(string error, string description) =>
        $"{{\"error\":\"{error}\",\"error_description\":\"{description}\"}}";
}
