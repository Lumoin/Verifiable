using Verifiable.Core.Transport;

namespace Verifiable.Core.Outbound;

/// <summary>
/// The completed response read by the guarded fetch from a single outbound HTTP hop — the status code, response headers
/// (including <c>Location</c> on a redirect), and the body as a tracked carrier.
/// </summary>
/// <remarks>
/// The transport that supplies the body stream MUST NOT follow redirects itself
/// (auto-redirect off): the guarded <see cref="OutboundFetch"/> owns the
/// redirect loop so it can re-validate every hop against the policy. The
/// <see cref="Body"/> is a <see cref="TaggedMemory{T}"/> (GC-managed, no dispose
/// dance); intermediate redirect bodies are simply dropped by the loop.
/// </remarks>
public sealed record OutboundResponse
{
    /// <summary>The HTTP status code.</summary>
    public required int StatusCode { get; init; }

    /// <summary>Response headers. Defaults to <see cref="HttpHeaderSet.Empty"/>.</summary>
    public HttpHeaderSet Headers { get; init; } = HttpHeaderSet.Empty;

    /// <summary>The response body. Defaults to empty.</summary>
    public TaggedMemory<byte> Body { get; init; } = TaggedMemory<byte>.Empty;
}
