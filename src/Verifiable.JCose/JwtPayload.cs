using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.JCose;

/// <summary>
/// A JWT payload (claims set) represented as a string-keyed dictionary.
/// </summary>
/// <remarks>
/// <para>
/// This type inherits from <see cref="Dictionary{TKey, TValue}"/> and provides
/// type identity at API boundaries, preventing accidental swapping of header and
/// payload arguments. Entries are JWT claims such as <c>iss</c>, <c>sub</c>,
/// <c>iat</c>, <c>vct</c> (see <see cref="WellKnownJwtClaims"/>).
/// </para>
/// <para>
/// For SD-JWT payloads, the <c>_sd</c> and <c>_sd_alg</c> claims are added
/// by the caller or by extension methods (see <see cref="Sd.SdConstants"/>).
/// </para>
/// <para>
/// Equality is based on dictionary contents: two payloads are equal if they contain
/// the same key-value pairs.
/// </para>
/// </remarks>
[DebuggerDisplay("JwtPayload({Count} claims)")]
public class JwtPayload: Dictionary<string, object>, IEquatable<JwtPayload>
{
    /// <summary>
    /// Creates an empty JWT payload.
    /// </summary>
    public JwtPayload() : base() { }

    /// <summary>
    /// Creates a JWT payload with the specified initial capacity.
    /// </summary>
    /// <param name="capacity">The initial number of claims the payload can contain.</param>
    public JwtPayload(int capacity) : base(capacity) { }

    /// <summary>
    /// Creates a JWT payload populated from an existing dictionary.
    /// </summary>
    /// <param name="dictionary">The dictionary whose entries are copied.</param>
    public JwtPayload(IDictionary<string, object> dictionary) : base(dictionary) { }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(JwtPayload? other)
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
        return obj is JwtPayload other && Equals(other);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        return DictionaryEquality.GetDictionaryHashCode(this);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(JwtPayload? left, JwtPayload? right)
    {
        return left is null ? right is null : left.Equals(right);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(JwtPayload? left, JwtPayload? right)
    {
        return !(left == right);
    }
}