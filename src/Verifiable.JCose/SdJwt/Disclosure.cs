using System.ComponentModel;
using System.Diagnostics;

namespace Verifiable.Jose.SdJwt;

/// <summary>
/// Represents a disclosure in an SD-JWT, containing the salt, optional claim name, and claim value.
/// </summary>
/// <remarks>
/// <para>
/// A disclosure is a base64url-encoded JSON array that reveals a selectively disclosable claim.
/// The format depends on whether the claim is an object property or an array element:
/// </para>
/// <list type="bullet">
/// <item><description>Object property: <c>[salt, claim_name, claim_value]</c></description></item>
/// <item><description>Array element: <c>[salt, claim_value]</c></description></item>
/// </list>
/// <para>
/// The <see cref="ClaimValue"/> property holds the claim value as a CLR object. At runtime this will be:
/// </para>
/// <list type="bullet">
/// <item><description><see cref="string"/> for JSON strings.</description></item>
/// <item><description><see cref="bool"/> for JSON booleans.</description></item>
/// <item><description><see cref="long"/> or <see cref="decimal"/> for JSON numbers.</description></item>
/// <item><description><see langword="null"/> for JSON null.</description></item>
/// <item><description><see cref="Dictionary{TKey,TValue}"/> of string to object for JSON objects.</description></item>
/// <item><description><see cref="List{T}"/> of object for JSON arrays.</description></item>
/// </list>
/// <para>
/// See <see href="https://www.rfc-editor.org/rfc/rfc9901.html#section-4.2">RFC 9901 Section 4.2</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Disclosure: IEquatable<Disclosure>
{
    /// <summary>
    /// Gets the salt value used to prevent guessing of undisclosed claim values.
    /// </summary>
    /// <remarks>
    /// The salt should be a base64url-encoded string of at least 128 bits of
    /// cryptographically secure random data.
    /// </remarks>
    public string Salt { get; }

    /// <summary>
    /// Gets the claim name for object property disclosures, or null for array element disclosures.
    /// </summary>
    public string? ClaimName { get; }

    /// <summary>
    /// Gets the claim value.
    /// </summary>
    /// <remarks>
    /// The value can be any valid JSON type represented as a CLR object:
    /// string, bool, long, decimal, null, Dictionary&lt;string, object&gt;, or List&lt;object&gt;.
    /// </remarks>
    public object? ClaimValue { get; }

    /// <summary>
    /// Gets a value indicating whether this disclosure is for an array element.
    /// </summary>
    public bool IsArrayElement => ClaimName is null;

    /// <summary>
    /// Gets the base64url-encoded disclosure string.
    /// </summary>
    /// <remarks>
    /// This is the encoded form that appears in the SD-JWT after the tilde separator.
    /// </remarks>
    public string EncodedValue { get; }


    /// <summary>
    /// Initializes a new instance of the <see cref="Disclosure"/> class for an object property.
    /// </summary>
    /// <param name="salt">The salt value.</param>
    /// <param name="claimName">The claim name.</param>
    /// <param name="claimValue">The claim value.</param>
    /// <param name="encodedValue">The base64url-encoded disclosure string.</param>
    public Disclosure(string salt, string claimName, object? claimValue, string encodedValue)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(salt, nameof(salt));
        ArgumentException.ThrowIfNullOrWhiteSpace(claimName, nameof(claimName));
        ArgumentException.ThrowIfNullOrWhiteSpace(encodedValue, nameof(encodedValue));

        Salt = salt;
        ClaimName = claimName;
        ClaimValue = claimValue;
        EncodedValue = encodedValue;
    }


    /// <summary>
    /// Initializes a new instance of the <see cref="Disclosure"/> class for an array element.
    /// </summary>
    /// <param name="salt">The salt value.</param>
    /// <param name="claimValue">The array element value.</param>
    /// <param name="encodedValue">The base64url-encoded disclosure string.</param>
    public Disclosure(string salt, object? claimValue, string encodedValue)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(salt, nameof(salt));
        ArgumentException.ThrowIfNullOrWhiteSpace(encodedValue, nameof(encodedValue));

        Salt = salt;
        ClaimName = null;
        ClaimValue = claimValue;
        EncodedValue = encodedValue;
    }


    private string DebuggerDisplay =>
        ClaimName is not null
            ? $"Disclosure: {ClaimName} = {ClaimValue}"
            : $"Disclosure: [array] = {ClaimValue}";


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(Disclosure? other)
    {
        if(other is null)
        {
            return false;
        }

        return string.Equals(EncodedValue, other.EncodedValue, StringComparison.Ordinal);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj) => obj is Disclosure other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => EncodedValue.GetHashCode(StringComparison.Ordinal);


    /// <summary>
    /// Returns the base64url-encoded disclosure string.
    /// </summary>
    public override string ToString() => EncodedValue;


    /// <summary>
    /// Equality operator.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(Disclosure? left, Disclosure? right) =>
        left is null ? right is null : left.Equals(right);


    /// <summary>
    /// Inequality operator.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(Disclosure? left, Disclosure? right) => !(left == right);
}