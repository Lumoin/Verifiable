using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.JCose;

/// <summary>
/// A verified JWT protected header represented as a string-keyed dictionary.
/// </summary>
/// <remarks>
/// <para>
/// One of four sibling leaves under <see cref="JoseDictionary"/>. The grid
/// position is <em>verified header</em>: the enclosing JWS signature has been
/// checked, and entries such as <c>alg</c>, <c>typ</c>, and <c>kid</c>
/// (see <see cref="WellKnownJwkValues"/>) are trustworthy.
/// </para>
/// <para>
/// <strong>Why a distinct type.</strong>
/// A function signature <c>(JwtHeader header, JwtPayload payload)</c> cannot
/// be miscalled with the arguments reversed (role distinction), and a
/// function expecting <see cref="JwtHeader"/> cannot accept an
/// <see cref="UnverifiedJwtHeader"/> (trust-state distinction). Both
/// guarantees come from the type identity of this sealed leaf; see
/// <see cref="JoseDictionary"/> for the full rationale.
/// </para>
/// <para>
/// Equality is by dictionary contents, but never crosses to siblings — a
/// <see cref="JwtHeader"/> with the same entries as an
/// <see cref="UnverifiedJwtHeader"/> or a <see cref="JwtPayload"/> is not
/// equal to either.
/// </para>
/// </remarks>
[DebuggerDisplay("JwtHeader({Count} entries)")]
public sealed class JwtHeader: JoseDictionary, IEquatable<JwtHeader>
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
    /// Creates a JWT header populated from any key-value enumerable,
    /// including <see cref="Dictionary{TKey,TValue}"/>,
    /// <see cref="IReadOnlyDictionary{TKey,TValue}"/>, and
    /// <see cref="IDictionary{TKey,TValue}"/>.
    /// </summary>
    /// <param name="parameters">The key-value pairs to copy.</param>
    public JwtHeader(IEnumerable<KeyValuePair<string, object>> parameters)
        : base(parameters) { }


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
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is JwtHeader other && Equals(other);


    /// <summary>
    /// Returns the hash code from <see cref="JoseDictionary.GetHashCode"/>.
    /// Declared on this leaf to satisfy the C# rule (CS0659/CS0661) that any
    /// type overriding <see cref="object.Equals(object)"/> or defining
    /// equality operators must also declare <see cref="object.GetHashCode"/>
    /// directly — inheriting the override from <see cref="JoseDictionary"/>
    /// alone does not satisfy the rule.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(JwtHeader? left, JwtHeader? right) =>
        left is null ? right is null : left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(JwtHeader? left, JwtHeader? right) =>
        !(left == right);
}
