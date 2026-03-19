using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The parsed HTTP request fields from a form body or query string, carrying type
/// identity so that API boundaries distinguish fields from other string dictionaries.
/// </summary>
/// <remarks>
/// <para>
/// The ASP.NET skin populates a <see cref="RequestFields"/> instance from the HTTP
/// request before calling <see cref="AuthorizationServerDispatcher.DispatchAsync"/>.
/// For POST endpoints the entries come from the form body; for GET endpoints from
/// the query string. The skin populates both the same way — the library never sees
/// <c>HttpContext</c> or any framework type.
/// </para>
/// <para>
/// Inheriting from <see cref="Dictionary{TKey, TValue}"/> follows the same pattern
/// as <see cref="Verifiable.JCose.JwtHeader"/> and <see cref="Verifiable.JCose.JwtPayload"/>:
/// full dictionary API with type identity that prevents accidental argument swapping
/// at compile time.
/// </para>
/// <para>
/// Keys are the OAuth parameter names defined in <see cref="OAuthRequestParameters"/>.
/// Values are the raw string values from the HTTP request. No decoding, validation,
/// or transformation is applied by this type — that is the responsibility of the
/// <see cref="BuildInputDelegate"/> on each <see cref="ServerEndpoint"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("RequestFields({Count} entries)")]
public sealed class RequestFields: Dictionary<string, string>, IEquatable<RequestFields>
{
    /// <summary>
    /// Creates an empty <see cref="RequestFields"/> instance.
    /// </summary>
    public RequestFields() : base(StringComparer.Ordinal) { }

    /// <summary>
    /// Creates a <see cref="RequestFields"/> instance with the specified initial capacity.
    /// </summary>
    /// <param name="capacity">The initial number of entries the collection can contain.</param>
    public RequestFields(int capacity) : base(capacity, StringComparer.Ordinal) { }

    /// <summary>
    /// Creates a <see cref="RequestFields"/> instance populated from any key-value
    /// enumerable, including <see cref="Dictionary{TKey, TValue}"/> and
    /// <see cref="IReadOnlyDictionary{TKey, TValue}"/>.
    /// </summary>
    /// <param name="fields">The key-value pairs to copy.</param>
    public RequestFields(IEnumerable<KeyValuePair<string, string>> fields)
        : base(fields, StringComparer.Ordinal) { }


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

        if(Count != other.Count)
        {
            return false;
        }

        foreach(KeyValuePair<string, string> kvp in this)
        {
            if(!other.TryGetValue(kvp.Key, out string? value)
                || !string.Equals(kvp.Value, value, StringComparison.Ordinal))
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
        var hash = new HashCode();
        foreach(KeyValuePair<string, string> kvp in this.OrderBy(
            static x => x.Key, StringComparer.Ordinal))
        {
            hash.Add(kvp.Key, StringComparer.Ordinal);
            hash.Add(kvp.Value, StringComparer.Ordinal);
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
