using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.JCose;

/// <summary>
/// A verified JWT payload (claims set) represented as a string-keyed dictionary.
/// </summary>
/// <remarks>
/// <para>
/// One of four sibling leaves under <see cref="JoseDictionary"/>. The grid
/// position is <em>verified payload</em>: the enclosing JWS signature has
/// been checked, and entries such as <c>iss</c>, <c>sub</c>, <c>iat</c>,
/// <c>vct</c> (see <see cref="WellKnownJwtClaimNames"/>) are trustworthy.
/// </para>
/// <para>
/// For SD-JWT payloads, the <c>_sd</c> and <c>_sd_alg</c> claims are added
/// by the caller or by extension methods (see <c>SdConstants</c>).
/// </para>
/// <para>
/// <strong>Why a distinct type.</strong>
/// A function signature <c>(JwtHeader header, JwtPayload payload)</c> cannot
/// be miscalled with the arguments reversed (role distinction), and a
/// function expecting <see cref="JwtPayload"/> cannot accept an
/// <see cref="UnverifiedJwtPayload"/> (trust-state distinction). Both
/// guarantees come from the type identity of this sealed leaf; see
/// <see cref="JoseDictionary"/> for the full rationale.
/// </para>
/// <para>
/// Equality is by dictionary contents, but never crosses to siblings — a
/// <see cref="JwtPayload"/> with the same entries as an
/// <see cref="UnverifiedJwtPayload"/> or a <see cref="JwtHeader"/> is not
/// equal to either.
/// </para>
/// </remarks>
[DebuggerDisplay("JwtPayload({Count} claims)")]
public sealed class JwtPayload: JoseDictionary, IEquatable<JwtPayload>
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
    /// Creates a JWT payload populated from any key-value enumerable,
    /// including <see cref="Dictionary{TKey,TValue}"/>,
    /// <see cref="IReadOnlyDictionary{TKey,TValue}"/>, and
    /// <see cref="IDictionary{TKey,TValue}"/>.
    /// </summary>
    /// <param name="claims">The key-value pairs to copy.</param>
    public JwtPayload(IEnumerable<KeyValuePair<string, object>> claims)
        : base(claims) { }


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
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is JwtPayload other && Equals(other);


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
    public static bool operator ==(JwtPayload? left, JwtPayload? right) =>
        left is null ? right is null : left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(JwtPayload? left, JwtPayload? right) =>
        !(left == right);
}
