using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Cryptography.Text;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth;

/// <summary>
/// The response from an HTTP endpoint call made via <see cref="SendFormPostDelegate"/>.
/// </summary>
/// <remarks>
/// <para>
/// Carries the response body alongside transport-level metadata the application
/// chooses to surface — HTTP status code, OTel trace context from response
/// headers, RFC 9457 <c>instance</c> URIs, server-supplied request identifiers.
/// The library does not mandate which metadata fields are populated; it is the
/// application's <see cref="SendFormPostDelegate"/> implementation that decides
/// what to capture from the underlying HTTP response.
/// </para>
/// <para>
/// In the in-process development configuration, where the delegate calls directly
/// into a server handler rather than making a network request, the delegate can
/// populate <see cref="TransportMetadata"/> with server-side context — such as
/// the flow ID or a synthetic trace identifier — that would normally arrive via
/// response headers.
/// </para>
/// <para>
/// <strong>Metadata key conventions.</strong>
/// Keys follow a <c>category.field</c> naming convention. Recommended keys:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       <c>transport.status_code</c> — HTTP status code as a string, e.g. <c>"400"</c>.
///     </description>
///   </item>
///   <item>
///     <description>
///       <c>transport.traceparent</c> — W3C TraceContext <c>traceparent</c> header
///       value from the response, enabling OTel correlation with the server trace.
///     </description>
///   </item>
///   <item>
///     <description>
///       <c>transport.tracestate</c> — W3C TraceContext <c>tracestate</c> header value.
///     </description>
///   </item>
///   <item>
///     <description>
///       <c>transport.content_type</c> — response <c>Content-Type</c> header.
///       Relevant when detecting RFC 9457 <c>application/problem+json</c> responses.
///     </description>
///   </item>
///   <item>
///     <description>
///       <c>transport.request_id</c> — server-supplied request identifier from
///       a vendor-specific response header such as <c>X-Request-ID</c>.
///     </description>
///   </item>
/// </list>
/// </remarks>
[DebuggerDisplay("HttpResponseData StatusCode={StatusCode} BodyLength={Body.Length}")]
public readonly struct HttpResponseData: IEquatable<HttpResponseData>
{
    /// <summary>
    /// Initialises an empty <see cref="HttpResponseData"/> with empty body,
    /// zero status code, and <see cref="ResponseHeaders.Empty"/>. Required
    /// by C# (CS8983) because the struct carries field initializers — the
    /// public usage path is always object-initialiser syntax that supplies
    /// the required values via <c>init</c>.
    /// </summary>
    public HttpResponseData()
    {
        Body = string.Empty;
        StatusCode = 0;
        TransportMetadata = null;
        Headers = ResponseHeaders.Empty;
    }


    /// <summary>
    /// The response body. For OAuth protocol endpoints this is typically a
    /// JSON object. May be empty for endpoints that return no body.
    /// </summary>
    public string Body { get; init; }

    /// <summary>
    /// The HTTP status code. For example: 200, 400, 401, 500.
    /// </summary>
    public int StatusCode { get; init; }

    /// <summary>
    /// Optional transport-level metadata captured by the delegate implementation.
    /// See the remarks on <see cref="HttpResponseData"/> for recommended key names.
    /// <see langword="null"/> when the delegate did not capture any metadata.
    /// </summary>
    public IReadOnlyDictionary<string, string>? TransportMetadata { get; init; }

    /// <summary>
    /// Response headers. Defaults to <see cref="ResponseHeaders.Empty"/>.
    /// Populated by the production HttpClient-based transport from
    /// <c>HttpResponseMessage.Headers</c>. Consumed by future library work
    /// (RFC 9449 DPoP nonce flow, OID4VCI deferred credential
    /// <c>Retry-After</c>); the slot currently has no active consumers.
    /// </summary>
    public ResponseHeaders Headers { get; init; } = ResponseHeaders.Empty;


    /// <summary>
    /// Returns the value associated with <paramref name="key"/> in
    /// <see cref="TransportMetadata"/>, or <see langword="null"/> if the key
    /// is absent or <see cref="TransportMetadata"/> is <see langword="null"/>.
    /// </summary>
    public string? GetMetadata(string key)
    {
        if(TransportMetadata is null)
        {
            return null;
        }

        return TransportMetadata.TryGetValue(key, out string? value) ? value : null;
    }


    /// <summary>
    /// Returns <see langword="true"/> when the status code indicates a
    /// successful response (200–299).
    /// </summary>
    public bool IsSuccessStatusCode =>
        StatusCode >= 200 && StatusCode <= 299;


    /// <summary>
    /// Returns <see langword="true"/> when the <c>transport.content_type</c>
    /// metadata entry indicates the response body is an RFC 9457
    /// <c>application/problem+json</c> document.
    /// </summary>
    public bool IsProblemJson =>
        GetMetadata(HttpResponseDataKeys.ContentType)
            ?.Contains("application/problem+json", System.StringComparison.OrdinalIgnoreCase)
        ?? false;


    /// <inheritdoc/>
    public bool Equals(HttpResponseData other) =>
        StatusCode == other.StatusCode
            && Body == other.Body
            && ReferenceEquals(TransportMetadata, other.TransportMetadata);

    /// <inheritdoc/>
    public override bool Equals(object? obj) =>
        obj is HttpResponseData other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() =>
        System.HashCode.Combine(StatusCode, Body);

    /// <summary>Determines whether two instances are equal.</summary>
    public static bool operator ==(HttpResponseData left, HttpResponseData right) =>
        left.Equals(right);

    /// <summary>Determines whether two instances differ.</summary>
    public static bool operator !=(HttpResponseData left, HttpResponseData right) =>
        !left.Equals(right);
}


/// <summary>
/// Well-known key constants for <see cref="HttpResponseData.TransportMetadata"/>.
/// </summary>
public static class HttpResponseDataKeys
{
    /// <summary>The UTF-8 source literal of <see cref="StatusCode"/>.</summary>
    public static ReadOnlySpan<byte> StatusCodeUtf8 => "transport.status_code"u8;

    /// <summary>The HTTP status code as a string. Example: <c>"200"</c>.</summary>
    public static readonly string StatusCode = Utf8Constants.ToInternedString(StatusCodeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TraceParent"/>.</summary>
    public static ReadOnlySpan<byte> TraceParentUtf8 => "transport.traceparent"u8;

    /// <summary>
    /// W3C TraceContext <c>traceparent</c> header value from the response.
    /// </summary>
    public static readonly string TraceParent = Utf8Constants.ToInternedString(TraceParentUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TraceState"/>.</summary>
    public static ReadOnlySpan<byte> TraceStateUtf8 => "transport.tracestate"u8;

    /// <summary>
    /// W3C TraceContext <c>tracestate</c> header value from the response.
    /// </summary>
    public static readonly string TraceState = Utf8Constants.ToInternedString(TraceStateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ContentType"/>.</summary>
    public static ReadOnlySpan<byte> ContentTypeUtf8 => "transport.content_type"u8;

    /// <summary>
    /// Response <c>Content-Type</c> header. Used to detect RFC 9457
    /// <c>application/problem+json</c> responses.
    /// </summary>
    public static readonly string ContentType = Utf8Constants.ToInternedString(ContentTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RequestId"/>.</summary>
    public static ReadOnlySpan<byte> RequestIdUtf8 => "transport.request_id"u8;

    /// <summary>
    /// Server-supplied request identifier from a vendor-specific header
    /// such as <c>X-Request-ID</c>.
    /// </summary>
    public static readonly string RequestId = Utf8Constants.ToInternedString(RequestIdUtf8);
}
