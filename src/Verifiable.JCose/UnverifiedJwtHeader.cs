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
/// One of four sibling leaves under <see cref="JoseDictionary"/>. The grid
/// position is <em>unverified header</em>: the bytes have been parsed into a
/// dictionary, but the enclosing JWS signature has not been checked. Every
/// value in this dictionary — <c>alg</c>, <c>kid</c>, <c>jku</c>,
/// <c>x5c</c>, anything else — is attacker-controlled.
/// </para>
/// <para>
/// <strong>Why a distinct type.</strong>
/// A function expecting <see cref="JwtHeader"/> rejects this type at compile
/// time, preventing the alg-confusion and kid-confusion attack class:
/// reading <c>alg</c> from an unverified header to select a verification
/// algorithm is the canonical mistake; the type system makes that mistake
/// fail to compile when the function is correctly typed against
/// <see cref="JwtHeader"/>. See <see cref="JoseDictionary"/> for the full
/// rationale on why trust state is not a subtype axis.
/// </para>
/// <para>
/// Once the signature covering this header has been verified by the caller,
/// construct a <see cref="JwtHeader"/> from the same parameters and proceed
/// with verified checks.
/// </para>
/// <para>
/// Equality is by dictionary contents, but never crosses to siblings — an
/// <see cref="UnverifiedJwtHeader"/> with the same entries as a
/// <see cref="JwtHeader"/> or an <see cref="UnverifiedJwtPayload"/> is not
/// equal to either.
/// </para>
/// </remarks>
[DebuggerDisplay("UnverifiedJwtHeader({Count} parameters)")]
public sealed class UnverifiedJwtHeader: JoseDictionary, IEquatable<UnverifiedJwtHeader>
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


    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(UnverifiedJwtHeader? left, UnverifiedJwtHeader? right) =>
        left is null ? right is null : left.Equals(right);


    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(UnverifiedJwtHeader? left, UnverifiedJwtHeader? right) =>
        !(left == right);
}
