using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Server;

/// <summary>
/// The parsed HTTP request parameters from a form body and/or query string, carrying type
/// identity so API boundaries distinguish request fields from other string collections.
/// </summary>
/// <remarks>
/// <para>
/// HTTP request parameters are inherently <em>multi-valued</em>: a key can appear more than once in a
/// query string or form body. This type models that faithfully — each key maps to the ordered list of
/// values it carried — and exposes two deliberately distinct read paths so a consumer states its
/// expectation:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <see cref="TryGetValue"/> is the <strong>single-valued</strong> read with <em>exactly-one</em>
///     semantics — it succeeds only when the key carried a single value, and fails closed when the key is
///     absent <em>or repeated</em>. A parameter that a caller expects once can therefore never silently
///     resolve to the first (or a space-joined) value of several. This is the
///     <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 §3.1</see> "parameters MUST
///     NOT be included more than once" rule made structural: a duplicated single-valued parameter flows
///     into the endpoint's missing/invalid path.
///   </description></item>
///   <item><description>
///     <see cref="GetValues"/> / <see cref="TryGetValues"/> is the <strong>multi-valued</strong> read used
///     only by the parameters a specification permits to repeat (for example OpenID Federation §8.2.1
///     <c>entity_type</c> and RFC 8707 <c>resource</c>).
///   </description></item>
/// </list>
/// <para>
/// The application skin populates a <see cref="RequestFields"/> from the HTTP request before calling the
/// dispatcher — for POST endpoints from the form body, for GET endpoints from the query string, preserving
/// every value per key. The library never sees <c>HttpContext</c> or any framework type. Keys are the
/// OAuth/protocol parameter names; values are the raw strings, with no decoding or validation applied here.
/// </para>
/// </remarks>
[DebuggerDisplay("RequestFields({Count} keys)")]
public sealed class RequestFields: IEquatable<RequestFields>
{
    /// <summary>The backing store: each key maps to the ordered list of values it carried.</summary>
    private Dictionary<string, List<string>> Values { get; }


    /// <summary>Creates an empty <see cref="RequestFields"/> instance.</summary>
    public RequestFields()
    {
        Values = new Dictionary<string, List<string>>(StringComparer.Ordinal);
    }


    /// <summary>Creates a <see cref="RequestFields"/> instance with the specified initial key capacity.</summary>
    /// <param name="capacity">The initial number of distinct keys the collection can contain.</param>
    public RequestFields(int capacity)
    {
        Values = new Dictionary<string, List<string>>(capacity, StringComparer.Ordinal);
    }


    /// <summary>
    /// Creates a <see cref="RequestFields"/> populated from a single-valued key-value source — each pair
    /// appends a value, so a source with a repeated key carries every value.
    /// </summary>
    /// <param name="fields">The key-value pairs to copy.</param>
    public RequestFields(IEnumerable<KeyValuePair<string, string>> fields) : this()
    {
        ArgumentNullException.ThrowIfNull(fields);
        foreach(KeyValuePair<string, string> field in fields)
        {
            Add(field.Key, field.Value);
        }
    }


    /// <summary>The number of distinct parameter keys present.</summary>
    public int Count => Values.Count;


    /// <summary>The distinct parameter keys present, in no particular order.</summary>
    public IReadOnlyCollection<string> Keys => Values.Keys;


    /// <summary>
    /// Gets the single value of <paramref name="key"/> (fail-closed: throws when the key is absent or was
    /// repeated, mirroring <see cref="TryGetValue"/>'s exactly-one semantics), or sets it to a single value
    /// replacing any values already present. The setter is used by the skins and test fixtures that build a
    /// request with one value per key.
    /// </summary>
    /// <param name="key">The parameter name.</param>
    /// <exception cref="KeyNotFoundException">The key is absent or does not carry exactly one value.</exception>
    public string this[string key]
    {
        get => Values.TryGetValue(key, out List<string>? list) && list.Count == 1
            ? list[0]
            : throw new KeyNotFoundException(
                $"Request parameter '{key}' is not present with exactly one value.");
        set => Values[key] = [value];
    }


    /// <summary>
    /// Appends <paramref name="value"/> to <paramref name="key"/>, preserving any values already present —
    /// the skin uses this to carry a repeated parameter's every value.
    /// </summary>
    /// <param name="key">The parameter name.</param>
    /// <param name="value">A value to append.</param>
    public void Add(string key, string value)
    {
        if(Values.TryGetValue(key, out List<string>? list))
        {
            list.Add(value);
        }
        else
        {
            Values[key] = [value];
        }
    }


    /// <summary>
    /// Reads <paramref name="key"/> as a single value with <em>exactly-one</em> semantics: returns
    /// <see langword="true"/> and the value only when the key carried exactly one value; returns
    /// <see langword="false"/> when the key is absent or was repeated.
    /// </summary>
    /// <param name="key">The parameter name.</param>
    /// <param name="value">The single value, or <see langword="null"/> when not exactly one is present.</param>
    /// <returns><see langword="true"/> when exactly one value is present; otherwise <see langword="false"/>.</returns>
    public bool TryGetValue(string key, [NotNullWhen(true)] out string? value)
    {
        if(Values.TryGetValue(key, out List<string>? list) && list.Count == 1)
        {
            value = list[0];
            return true;
        }

        value = null;
        return false;
    }


    /// <summary>Whether <paramref name="key"/> is present with at least one value.</summary>
    /// <param name="key">The parameter name.</param>
    /// <returns><see langword="true"/> when the key carried at least one value.</returns>
    public bool ContainsKey(string key) => Values.ContainsKey(key);


    /// <summary>
    /// Reads every value carried for <paramref name="key"/>, in order. Returns an empty list when the key
    /// is absent. Used by the parameters a specification permits to repeat.
    /// </summary>
    /// <param name="key">The parameter name.</param>
    /// <returns>The ordered values, or an empty list when the key is absent.</returns>
    public IReadOnlyList<string> GetValues(string key) =>
        Values.TryGetValue(key, out List<string>? list) ? list : [];


    /// <summary>
    /// Reads every value carried for <paramref name="key"/>, in order, when the key is present.
    /// </summary>
    /// <param name="key">The parameter name.</param>
    /// <param name="values">The ordered values when present; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the key carried at least one value.</returns>
    public bool TryGetValues(string key, [NotNullWhen(true)] out IReadOnlyList<string>? values)
    {
        if(this.Values.TryGetValue(key, out List<string>? list))
        {
            values = list;
            return true;
        }

        values = null;
        return false;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(RequestFields? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        if(Values.Count != other.Values.Count)
        {
            return false;
        }

        foreach(KeyValuePair<string, List<string>> entry in Values)
        {
            if(!other.Values.TryGetValue(entry.Key, out List<string>? otherList)
                || !entry.Value.SequenceEqual(otherList, StringComparer.Ordinal))
            {
                return false;
            }
        }

        return true;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is RequestFields other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        HashCode hash = new();
        foreach(KeyValuePair<string, List<string>> entry in Values.OrderBy(
            static x => x.Key, StringComparer.Ordinal))
        {
            hash.Add(entry.Key, StringComparer.Ordinal);
            foreach(string value in entry.Value)
            {
                hash.Add(value, StringComparer.Ordinal);
            }
        }

        return hash.ToHashCode();
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(RequestFields? left, RequestFields? right) =>
        left is null ? right is null : left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(RequestFields? left, RequestFields? right) =>
        !(left == right);
}
