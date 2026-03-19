using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.JCose;

/// <summary>
/// A JWT protected header parsed from untrusted input. The parameters are
/// attacker-controlled until the enclosing JWS signature has been verified.
/// </summary>
/// <remarks>
/// <para>
/// This type exists to make the trust level explicit in the type system. A function
/// accepting <see cref="JwtHeader"/> cannot receive an <see cref="UnverifiedJwtHeader"/>
/// without an explicit conversion, preventing accidental use of unverified material
/// where verified material is required.
/// </para>
/// <para>
/// Once the signature covering this header has been verified by the caller, construct
/// a <see cref="JwtHeader"/> from the same parameters and proceed with verified checks.
/// </para>
/// </remarks>
[DebuggerDisplay("UnverifiedJwtHeader({Count} parameters)")]
public sealed class UnverifiedJwtHeader: Dictionary<string, object>, IEquatable<UnverifiedJwtHeader>
{
    /// <summary>Creates an empty unverified JWT header.</summary>
    public UnverifiedJwtHeader() : base() { }

    /// <summary>Creates an unverified JWT header with the specified initial capacity.</summary>
    /// <param name="capacity">The initial number of entries the header can contain.</param>
    public UnverifiedJwtHeader(int capacity) : base(capacity) { }

    /// <summary>
    /// Creates an unverified JWT header populated from any key-value enumerable,
    /// including <see cref="Dictionary{TKey,TValue}"/>,
    /// <see cref="IReadOnlyDictionary{TKey,TValue}"/>, and
    /// <see cref="IDictionary{TKey,TValue}"/>.
    /// </summary>
    /// <remarks>
    /// The source type is deliberately broad — the decision of whether the data is
    /// trusted or untrusted belongs to the caller, not to the deserializer or other
    /// producer of the key-value pairs.
    /// </remarks>
    /// <param name="parameters">The key-value pairs to copy.</param>
    public UnverifiedJwtHeader(IEnumerable<KeyValuePair<string, object>> parameters)
        : base(parameters) { }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(UnverifiedJwtHeader? other)
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
        obj is UnverifiedJwtHeader other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() =>
        DictionaryEquality.GetDictionaryHashCode(this);


    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(UnverifiedJwtHeader? left, UnverifiedJwtHeader? right) =>
        left is null ? right is null : left.Equals(right);


    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(UnverifiedJwtHeader? left, UnverifiedJwtHeader? right) =>
        !(left == right);
}