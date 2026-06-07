using System;
using System.Collections.Generic;
using Verifiable.Cryptography;

namespace Verifiable.Core.OutboundFetch;

/// <summary>
/// The result of a single outbound HTTP hop returned by an
/// <see cref="OutboundTransportDelegate"/> — the status code, response headers
/// (including <c>Location</c> on a redirect), and the body as a tracked carrier.
/// </summary>
/// <remarks>
/// The transport that produces this MUST NOT follow redirects itself
/// (auto-redirect off): the guarded <see cref="OutboundFetch"/> owns the
/// redirect loop so it can re-validate every hop against the policy. The
/// <see cref="Body"/> is a <see cref="TaggedMemory{T}"/> (GC-managed, no dispose
/// dance); intermediate redirect bodies are simply dropped by the loop.
/// </remarks>
public sealed record OutboundResponse
{
    /// <summary>The HTTP status code.</summary>
    public required int StatusCode { get; init; }

    /// <summary>Response headers (case-insensitive lookup via <see cref="TryGetHeader"/>).</summary>
    public IReadOnlyDictionary<string, string> Headers { get; init; } = OutboundRequest.EmptyHeaders;

    /// <summary>The response body. Defaults to empty.</summary>
    public TaggedMemory<byte> Body { get; init; } = TaggedMemory<byte>.Empty;


    /// <summary>
    /// Looks up a response header case-insensitively, independent of the backing
    /// dictionary's comparer (the transport supplies the dictionary, so its
    /// comparer is not assumed).
    /// </summary>
    /// <param name="name">The header name.</param>
    /// <param name="value">The header value when found.</param>
    /// <returns><see langword="true"/> when the header is present.</returns>
    public bool TryGetHeader(string name, out string? value)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        foreach(KeyValuePair<string, string> header in Headers)
        {
            if(string.Equals(header.Key, name, StringComparison.OrdinalIgnoreCase))
            {
                value = header.Value;
                return true;
            }
        }

        value = null;
        return false;
    }
}
