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
/// This type exists to make the trust level explicit in the type system. A function
/// accepting <see cref="JwtPayload"/> cannot receive an <see cref="UnverifiedJwtPayload"/>
/// without an explicit conversion, preventing accidental use of unverified claims
/// where verified claims are required.
/// </para>
/// <para>
/// Running time-bound checks via <see cref="JwtChecks"/> on this type before
/// verifying the signature is a valid early-exit optimization — a token that is
/// already expired need not have its signature verified. The result of those checks
/// must still be treated as unverified until the signature check passes.
/// </para>
/// <para>
/// Once the signature has been verified, construct a <see cref="JwtPayload"/> from
/// the same claims and proceed with verified checks.
/// </para>
/// </remarks>
[DebuggerDisplay("UnverifiedJwtPayload({Count} claims)")]
public sealed class UnverifiedJwtPayload: Dictionary<string, object>, IEquatable<UnverifiedJwtPayload>
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


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() =>
        DictionaryEquality.GetDictionaryHashCode(this);


    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(UnverifiedJwtPayload? left, UnverifiedJwtPayload? right) =>
        left is null ? right is null : left.Equals(right);


    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(UnverifiedJwtPayload? left, UnverifiedJwtPayload? right) =>
        !(left == right);
}