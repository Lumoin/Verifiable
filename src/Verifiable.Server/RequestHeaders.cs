using System.Diagnostics;

namespace Verifiable.Server;

/// <summary>
/// Case-insensitive HTTP request headers as parsed from the wire.
/// </summary>
/// <remarks>
/// <para>
/// The skin populates this from whatever the HTTP framework surfaces.
/// Header names are case-insensitive per RFC 9110 §5.1; values are
/// preserved verbatim.
/// </para>
/// <para>
/// Multi-value headers are represented as a list per name. Most matchers
/// read single values via <see cref="TryGetSingle"/>; matchers that care
/// about repeated values (Forwarded, Set-Cookie on responses, etc.) read
/// via <see cref="TryGetAll"/>.
/// </para>
/// <para>
/// Immutable. The skin builds the headers once when constructing the
/// <see cref="IncomingRequest"/>; matchers and handlers read.
/// </para>
/// </remarks>
[DebuggerDisplay("RequestHeaders({Count} headers)")]
public sealed class RequestHeaders
{
    private Dictionary<string, string[]> Headers { get; }


    /// <summary>
    /// Creates a <see cref="RequestHeaders"/> from a header dictionary.
    /// Header names are normalized to case-insensitive lookups.
    /// </summary>
    /// <param name="source">
    /// Header name to value-list mapping. Names are case-insensitive on
    /// lookup; the skin may pass them in any case.
    /// </param>
    public RequestHeaders(IReadOnlyDictionary<string, string[]> source)
    {
        ArgumentNullException.ThrowIfNull(source);

        Headers = new Dictionary<string, string[]>(source.Count, StringComparer.OrdinalIgnoreCase);
        foreach(KeyValuePair<string, string[]> entry in source)
        {
            Headers[entry.Key] = entry.Value;
        }
    }


    /// <summary>
    /// An empty <see cref="RequestHeaders"/> instance for tests and
    /// pipelines that have no headers to surface.
    /// </summary>
    public static RequestHeaders Empty { get; } =
        new RequestHeaders(new Dictionary<string, string[]>(0));


    /// <summary>
    /// The number of distinct header names present.
    /// </summary>
    public int Count => Headers.Count;


    /// <summary>
    /// Tries to read the single value for <paramref name="name"/>. When the
    /// header has multiple values, returns <see langword="false"/> — callers
    /// that need multi-value semantics should use <see cref="TryGetAll"/>.
    /// </summary>
    /// <param name="name">Case-insensitive header name.</param>
    /// <param name="value">The single value when found; otherwise <see langword="null"/>.</param>
    /// <returns>
    /// <see langword="true"/> when the header is present with exactly one
    /// value; otherwise <see langword="false"/>.
    /// </returns>
    public bool TryGetSingle(string name, out string? value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        if(Headers.TryGetValue(name, out string[]? values) && values.Length == 1)
        {
            value = values[0];
            return true;
        }

        value = null;
        return false;
    }


    /// <summary>
    /// Tries to read all values for <paramref name="name"/>.
    /// </summary>
    /// <param name="name">Case-insensitive header name.</param>
    /// <param name="values">The values when the header is present; otherwise <see langword="null"/>.</param>
    /// <returns>
    /// <see langword="true"/> when the header is present with at least one
    /// value; otherwise <see langword="false"/>.
    /// </returns>
    public bool TryGetAll(string name, out IReadOnlyList<string>? values)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        if(Headers.TryGetValue(name, out string[]? raw))
        {
            values = raw;
            return true;
        }

        values = null;
        return false;
    }


    /// <summary>
    /// Whether <paramref name="name"/> is present at all.
    /// </summary>
    /// <param name="name">Case-insensitive header name.</param>
    public bool Contains(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        return Headers.ContainsKey(name);
    }
}
