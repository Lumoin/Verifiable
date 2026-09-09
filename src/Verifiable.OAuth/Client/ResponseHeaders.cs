using System.Diagnostics;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Headers returned with an HTTP response. Surfaces protocol-relevant
/// headers up to library handler code — for example RFC 9449 §10.1
/// <c>DPoP-Nonce</c> challenges and OID4VCI §9 <c>Retry-After</c> for
/// deferred credential polling.
/// </summary>
/// <remarks>
/// A thin view over <see cref="Headers"/> (an <see cref="HttpHeaderSet"/>) — the
/// case-insensitive, multi-valued storage lives there.
/// </remarks>
[DebuggerDisplay("ResponseHeaders ({Headers.Count} headers)")]
public sealed record ResponseHeaders
{
    /// <summary>The underlying header set.</summary>
    public required HttpHeaderSet Headers { get; init; }

    /// <summary>The empty header set.</summary>
    public static ResponseHeaders Empty { get; } = new() { Headers = HttpHeaderSet.Empty };

    /// <summary>
    /// Returns the first value for <paramref name="name"/> if present, otherwise
    /// <see langword="null"/>. Name comparison is case-insensitive per
    /// RFC 9110 §5.1.
    /// </summary>
    public string? TryGetSingle(string name) =>
        Headers.TryGetValue(name, out string? value) ? value : null;
}
