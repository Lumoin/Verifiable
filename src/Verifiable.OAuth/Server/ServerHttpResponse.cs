using System.Collections.Immutable;
using System.Diagnostics;
using System.Net;
using Verifiable.JCose;

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

    /// <summary>
    /// <see langword="true"/> when <see cref="StatusCode"/> is in the 2xx range
    /// (RFC 9110 §15.3 — a successful response, e.g. 200 OK or 201 Created).
    /// </summary>
    public bool IsSuccessStatusCode => StatusCode is >= 200 and < 300;

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

    /// <summary>
    /// Additional response headers to emit alongside the standard
    /// <c>Content-Type</c> / <c>Location</c> slots. Used by RFC 9449 §8.1
    /// for the <c>DPoP-Nonce</c> challenge response and similar header-bound
    /// protocol signals.
    /// </summary>
    public ImmutableDictionary<string, string> Headers { get; init; } =
        ImmutableDictionary<string, string>.Empty;


    /// <summary>
    /// Returns a copy of this response with <paramref name="name"/> set to
    /// <paramref name="value"/> in <see cref="Headers"/>, replacing any
    /// previous value for the same header name.
    /// </summary>
    public ServerHttpResponse WithHeader(string name, string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(value);
        return this with { Headers = Headers.SetItem(name, value) };
    }


    /// <summary>Returns a 200 OK response with a JSON body.</summary>
    public static ServerHttpResponse Ok(string body, string contentType) =>
        new()
        {
            StatusCode = (int)HttpStatusCode.OK,
            Body = body,
            ContentType = contentType
        };


    /// <summary>
    /// Returns a 200 OK response with an empty body — for example the RFC 7009
    /// §2.2 revocation response, which conveys all information in the status
    /// code and is read by the client for the code alone.
    /// </summary>
    public static ServerHttpResponse Ok() =>
        new()
        {
            StatusCode = (int)HttpStatusCode.OK,
            Body = string.Empty,
            ContentType = string.Empty
        };


    /// <summary>Returns a 201 Created response with a JSON body.</summary>
    public static ServerHttpResponse Created(string body, string contentType) =>
        new()
        {
            StatusCode = (int)HttpStatusCode.Created,
            Body = body,
            ContentType = contentType
        };


    /// <summary>Returns a 204 No Content response with an empty body.</summary>
    public static ServerHttpResponse NoContent() =>
        new()
        {
            StatusCode = (int)HttpStatusCode.NoContent,
            Body = string.Empty,
            ContentType = string.Empty
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
            ContentType = WellKnownMediaTypes.Application.Json
        };


    /// <summary>Returns a 401 Unauthorized with an OAuth error JSON body.</summary>
    public static ServerHttpResponse Unauthorized(string error, string description) =>
        new()
        {
            StatusCode = (int)HttpStatusCode.Unauthorized,
            Body = BuildErrorBody(error, description),
            ContentType = WellKnownMediaTypes.Application.Json
        };


    /// <summary>Returns a 403 Forbidden with an OAuth error JSON body.</summary>
    public static ServerHttpResponse Forbidden(string error, string description) =>
        new()
        {
            StatusCode = (int)HttpStatusCode.Forbidden,
            Body = BuildErrorBody(error, description),
            ContentType = WellKnownMediaTypes.Application.Json
        };


    /// <summary>Returns a 404 Not Found with an empty body.</summary>
    public static ServerHttpResponse NotFound() =>
        new()
        {
            StatusCode = (int)HttpStatusCode.NotFound,
            Body = string.Empty,
            ContentType = string.Empty
        };


    /// <summary>
    /// Returns a 409 Conflict with an OAuth error JSON body — for example a
    /// Shared Signals stream-creation request when the Transmitter does not
    /// support multiple streams per Receiver (SSF 1.0 §8.1.1.1).
    /// </summary>
    public static ServerHttpResponse Conflict(string error, string description) =>
        new()
        {
            StatusCode = (int)HttpStatusCode.Conflict,
            Body = BuildErrorBody(error, description),
            ContentType = WellKnownMediaTypes.Application.Json
        };


    /// <summary>
    /// Returns a 422 Unprocessable Content with an OAuth error JSON body — a
    /// well-formed request the server understood but cannot act on, for example a
    /// Global Token Revocation command (draft-parecki-oauth-global-token-revocation)
    /// for a subject the server cannot process.
    /// </summary>
    public static ServerHttpResponse UnprocessableEntity(string error, string description) =>
        new()
        {
            StatusCode = (int)HttpStatusCode.UnprocessableEntity,
            Body = BuildErrorBody(error, description),
            ContentType = WellKnownMediaTypes.Application.Json
        };


    /// <summary>
    /// Returns a 202 Accepted with an empty body — a request accepted but not
    /// yet processed (for example SSF 1.0 §8.1.1.3 stream-configuration updates).
    /// </summary>
    public static ServerHttpResponse Accepted() =>
        new()
        {
            StatusCode = (int)HttpStatusCode.Accepted,
            Body = string.Empty,
            ContentType = string.Empty
        };


    /// <summary>
    /// Returns a 429 Too Many Requests with an OAuth error JSON body — for
    /// example an SSF subject or verification request exceeding the stream's
    /// rate limits (SSF 1.0 §8.1.3/§8.1.4, <c>min_verification_interval</c>).
    /// </summary>
    public static ServerHttpResponse TooManyRequests(string error, string description) =>
        new()
        {
            StatusCode = (int)HttpStatusCode.TooManyRequests,
            Body = BuildErrorBody(error, description),
            ContentType = WellKnownMediaTypes.Application.Json
        };


    /// <summary>Returns a 500 Internal Server Error with an OAuth error JSON body.</summary>
    public static ServerHttpResponse ServerError(string error, string description) =>
        new()
        {
            StatusCode = (int)HttpStatusCode.InternalServerError,
            Body = BuildErrorBody(error, description),
            ContentType = WellKnownMediaTypes.Application.Json
        };


    private static string BuildErrorBody(string error, string description) =>
        $"{{\"error\":\"{error}\",\"error_description\":\"{description}\"}}";
}
