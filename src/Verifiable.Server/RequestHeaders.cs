using System.Diagnostics;

namespace Verifiable.Server;

/// <summary>
/// Case-insensitive HTTP request headers as parsed from the wire.
/// </summary>
/// <remarks>
/// <para>
/// The skin populates this from whatever the HTTP framework surfaces. Header names are
/// case-insensitive per RFC 9110 §5.1; a value is preserved verbatim except that a CR, LF, or
/// NUL character is replaced with SP per RFC 9110 §5.5's recipient arm (see
/// <see cref="HttpHeaderSet.FromReceived"/>).
/// </para>
/// <para>
/// Multi-value headers are represented as a list per name. Most matchers
/// read single values via <see cref="TryGetSingle"/>; matchers that care
/// about repeated values (Forwarded, Set-Cookie on responses, etc.) read
/// via <see cref="TryGetAll"/>.
/// </para>
/// <para>
/// Immutable. The skin builds the headers once when constructing the
/// <see cref="IncomingRequest"/>; matchers and handlers read. A thin view
/// over <see cref="Headers"/> (an <see cref="HttpHeaderSet"/>) — the multi-value
/// storage and the RFC 9110 §5.3 field-order/case-insensitivity rules live there.
/// </para>
/// </remarks>
[DebuggerDisplay("RequestHeaders({Count} headers)")]
public sealed class RequestHeaders
{
    /// <summary>The underlying header set.</summary>
    public HttpHeaderSet Headers { get; }


    /// <summary>
    /// Creates a <see cref="RequestHeaders"/> from an <see cref="HttpHeaderSet"/> directly.
    /// </summary>
    /// <param name="headers">The header set.</param>
    public RequestHeaders(HttpHeaderSet headers)
    {
        ArgumentNullException.ThrowIfNull(headers);

        Headers = headers;
    }


    /// <summary>
    /// Creates a <see cref="RequestHeaders"/> from a header name to value-list mapping — the skin's raw
    /// wire capture, built through <see cref="HttpHeaderSet.FromReceived"/> rather than the composing-side
    /// <see cref="HttpHeaderSet.Builder"/>: a hostile field line (a non-token name, a case-insensitively
    /// colliding name, or a value carrying CR/LF/NUL) is sanitized or dropped per RFC 9110 §5.5/§5.3
    /// instead of throwing out of request parsing.
    /// </summary>
    /// <param name="source">
    /// Header name to value-list mapping, as received. Names are case-insensitive on
    /// lookup; the skin may pass them in any case, including two entries colliding
    /// case-insensitively (an ordinal-keyed map holding both <c>X-Foo</c> and <c>x-foo</c>).
    /// </param>
    public RequestHeaders(IReadOnlyDictionary<string, string[]> source)
    {
        ArgumentNullException.ThrowIfNull(source);

        Headers = HttpHeaderSet.FromReceived(FlattenToFieldLines(source));
    }


    /// <summary>Flattens a name to value-array mapping into one field line per value, in enumeration order.</summary>
    /// <param name="source">The mapping to flatten.</param>
    private static IEnumerable<(string Name, string Value)> FlattenToFieldLines(IReadOnlyDictionary<string, string[]> source)
    {
        foreach(KeyValuePair<string, string[]> entry in source)
        {
            foreach(string value in entry.Value)
            {
                yield return (entry.Key, value);
            }
        }
    }


    /// <summary>
    /// An empty <see cref="RequestHeaders"/> instance for tests and
    /// pipelines that have no headers to surface.
    /// </summary>
    public static RequestHeaders Empty { get; } = new RequestHeaders(HttpHeaderSet.Empty);


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

        IReadOnlyList<string> values = Headers.GetValues(name);
        if(values.Count == 1)
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

        if(Headers.Contains(name))
        {
            values = Headers.GetValues(name);

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

        return Headers.Contains(name);
    }
}
