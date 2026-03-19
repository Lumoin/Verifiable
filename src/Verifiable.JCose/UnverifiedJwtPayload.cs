using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.JCose;

/// <summary>
/// A JWT payload (claims set) parsed from untrusted input. The claims are
/// attacker-controlled until the enclosing JWS signature has been verified.
/// </summary>
/// <remarks>
/// <para>
/// One of four sibling leaves under <see cref="JoseDictionary"/>. The grid
/// position is <em>unverified payload</em>: the bytes have been parsed into
/// a dictionary, but the enclosing JWS signature has not been checked. Every
/// claim in this dictionary — <c>iss</c>, <c>sub</c>, <c>exp</c>, anything
/// else — is attacker-controlled.
/// </para>
/// <para>
/// <strong>Why a distinct type.</strong>
/// A function expecting <see cref="JwtPayload"/> rejects this type at
/// compile time, preventing the use of unverified claims in code paths that
/// require verified ones. See <see cref="JoseDictionary"/> for the full
/// rationale on why trust state is not a subtype axis.
/// </para>
/// <para>
/// Running time-bound checks via <see cref="JwtChecks"/> on this type before
/// verifying the signature is a valid early-exit optimization — a token
/// that is already expired need not have its signature verified. The result
/// of those checks must still be treated as unverified until the signature
/// check passes.
/// </para>
/// <para>
/// Once the signature has been verified, construct a <see cref="JwtPayload"/>
/// from the same claims and proceed with verified checks.
/// </para>
/// <para>
/// Equality is by dictionary contents, but never crosses to siblings — an
/// <see cref="UnverifiedJwtPayload"/> with the same entries as a
/// <see cref="JwtPayload"/> or an <see cref="UnverifiedJwtHeader"/> is not
/// equal to either.
/// </para>
/// </remarks>
[DebuggerDisplay("UnverifiedJwtPayload({Count} claims)")]
public sealed class UnverifiedJwtPayload: JoseDictionary, IEquatable<UnverifiedJwtPayload>
{
    /// <summary>Creates an empty unverified JWT payload.</summary>
    public UnverifiedJwtPayload() : base() { }

    /// <summary>Creates an unverified JWT payload with the specified initial capacity.</summary>
    /// <param name="capacity">The initial number of claims the payload can contain.</param>
    public UnverifiedJwtPayload(int capacity) : base(capacity) { }

    /// <summary>
    /// Creates an unverified JWT payload populated from any key-value enumerable,
    /// including <see cref="Dictionary{TKey,TValue}"/>,
    /// <see cref="IReadOnlyDictionary{TKey,TValue}"/>, and
    /// <see cref="IDictionary{TKey,TValue}"/>.
    /// </summary>
    /// <remarks>
    /// The source type is deliberately broad — the decision of whether the data is
    /// trusted or untrusted belongs to the caller, not to the deserializer or other
    /// producer of the key-value pairs.
    /// </remarks>
    /// <param name="claims">The key-value pairs to copy.</param>
    public UnverifiedJwtPayload(IEnumerable<KeyValuePair<string, object>> claims)
        : base(claims) { }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(UnverifiedJwtPayload? other)
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
        obj is UnverifiedJwtPayload other && Equals(other);


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
    public static bool operator ==(UnverifiedJwtPayload? left, UnverifiedJwtPayload? right) =>
        left is null ? right is null : left.Equals(right);


    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(UnverifiedJwtPayload? left, UnverifiedJwtPayload? right) =>
        !(left == right);
}
