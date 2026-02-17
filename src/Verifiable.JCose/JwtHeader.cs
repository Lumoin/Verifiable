using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.JCose;

/// <summary>
/// A JWT protected header represented as a string-keyed dictionary.
/// </summary>
/// <remarks>
/// <para>
/// This type inherits from <see cref="Dictionary{TKey, TValue}"/> and provides
/// type identity at API boundaries, preventing accidental swapping of header and
/// payload arguments. Typical entries include <c>alg</c>, <c>typ</c>, and <c>kid</c>
/// (see <see cref="JwkProperties"/>).
/// </para>
/// <para>
/// Equality is based on dictionary contents: two headers are equal if they contain
/// the same key-value pairs.
/// </para>
/// </remarks>
[DebuggerDisplay("JwtHeader({Count} entries)")]
public class JwtHeader: Dictionary<string, object>, IEquatable<JwtHeader>
{
    /// <summary>
    /// Creates an empty JWT header.
    /// </summary>
    public JwtHeader() : base() { }

    /// <summary>
    /// Creates a JWT header with the specified initial capacity.
    /// </summary>
    /// <param name="capacity">The initial number of entries the header can contain.</param>
    public JwtHeader(int capacity) : base(capacity) { }

    /// <summary>
    /// Creates a JWT header populated from an existing dictionary.
    /// </summary>
    /// <param name="dictionary">The dictionary whose entries are copied.</param>
    public JwtHeader(IDictionary<string, object> dictionary) : base(dictionary) { }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(JwtHeader? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return DictionaryEquality.DictionariesEqual(this, other);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj)
    {
        return obj is JwtHeader other && Equals(other);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        return DictionaryEquality.GetDictionaryHashCode(this);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(JwtHeader? left, JwtHeader? right)
    {
        return left is null ? right is null : left.Equals(right);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(JwtHeader? left, JwtHeader? right)
    {
        return !(left == right);
    }
}