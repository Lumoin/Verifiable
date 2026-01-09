using System.ComponentModel;
using System.Diagnostics;

namespace Verifiable.JCose.Sd;

/// <summary>
/// A selective disclosure element containing salt, optional claim name, and value.
/// </summary>
/// <remarks>
/// <para>
/// This is a format-agnostic representation used by both SD-JWT (JSON-based, RFC 9901)
/// and SD-CWT (CBOR-based). Serialization to wire format is handled by format-specific
/// serializers in Verifiable.Json and Verifiable.Cbor.
/// </para>
/// <para>
/// <strong>Structure:</strong>
/// </para>
/// <code>
/// ┌─────────────────────────────────────────────────────────────────┐
/// │                    SdDisclosure Structure                       │
/// ├─────────────────────────────────────────────────────────────────┤
/// │  Object property disclosure: [salt, claim_name, claim_value]    │
/// │  Array element disclosure:   [salt, claim_value]                │
/// └─────────────────────────────────────────────────────────────────┘
/// </code>
/// <para>
/// <strong>Salt Requirements (RFC 9901 Section 4.2.2):</strong>
/// </para>
/// <list type="bullet">
/// <item><description>Minimum 128 bits of cryptographically secure random data.</description></item>
/// <item><description>Unique per disclosure to prevent correlation attacks.</description></item>
/// </list>
/// <para>
/// <strong>Claim Value Types:</strong>
/// </para>
/// <para>
/// The <see cref="ClaimValue"/> property holds the claim value as a CLR object.
/// At runtime this will be:
/// </para>
/// <list type="bullet">
/// <item><description><see cref="string"/> for JSON/CBOR strings.</description></item>
/// <item><description><see cref="bool"/> for booleans.</description></item>
/// <item><description><see cref="long"/> or <see cref="decimal"/> for numbers.</description></item>
/// <item><description><see langword="null"/> for null values.</description></item>
/// <item><description><see cref="Dictionary{TKey,TValue}"/> of string to object for objects/maps.</description></item>
/// <item><description><see cref="List{T}"/> of object for arrays.</description></item>
/// </list>
/// <para>
/// <strong>Equality:</strong>
/// </para>
/// <para>
/// Two disclosures are equal if they have the same salt bytes. The salt serves as
/// the cryptographic identity of the disclosure.
/// </para>
/// <para>
/// <strong>Thread Safety:</strong> This class is immutable and thread-safe.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// //Create an object property disclosure.
/// var salt = RandomNumberGenerator.GetBytes(16);
/// var disclosure = SdDisclosure.CreateProperty(salt, "given_name", "John");
///
/// //Create an array element disclosure.
/// var arrayDisclosure = SdDisclosure.CreateArrayElement(salt, "US");
///
/// //Check disclosure type.
/// if (disclosure.IsArrayElement)
/// {
///     Console.WriteLine($"Array value: {disclosure.ClaimValue}");
/// }
/// else
/// {
///     Console.WriteLine($"{disclosure.ClaimName}: {disclosure.ClaimValue}");
/// }
/// </code>
/// </example>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class SdDisclosure: IEquatable<SdDisclosure>
{
    /// <summary>
    /// The salt value used to prevent guessing of undisclosed claim values.
    /// </summary>
    /// <remarks>
    /// Per RFC 9901 Section 4.2.2, the salt should be at least 128 bits of
    /// cryptographically secure random data.
    /// </remarks>
    public ReadOnlyMemory<byte> Salt { get; }

    /// <summary>
    /// The claim name for object property disclosures, or <c>null</c> for array element disclosures.
    /// </summary>
    /// <remarks>
    /// Per RFC 9901, certain claim names are reserved and cannot be used:
    /// <c>_sd</c> and <c>...</c> (the array digest marker).
    /// </remarks>
    public string? ClaimName { get; }

    /// <summary>
    /// The claim value.
    /// </summary>
    /// <remarks>
    /// The value can be any valid JSON/CBOR type represented as a CLR object.
    /// See class remarks for the type mapping.
    /// </remarks>
    public object? ClaimValue { get; }

    /// <summary>
    /// Whether this disclosure is for an array element (no claim name).
    /// </summary>
    public bool IsArrayElement => ClaimName is null;

    /// <summary>
    /// Whether this disclosure is for an object property (has claim name).
    /// </summary>
    public bool IsObjectProperty => ClaimName is not null;


    /// <summary>
    /// Creates a disclosure for an object property.
    /// </summary>
    /// <param name="salt">The cryptographic salt (minimum 128 bits recommended).</param>
    /// <param name="claimName">The claim name.</param>
    /// <param name="claimValue">The claim value.</param>
    /// <returns>A new object property disclosure.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="salt"/> is empty or <paramref name="claimName"/> is null/empty.
    /// </exception>
    public static SdDisclosure CreateProperty(ReadOnlyMemory<byte> salt, string claimName, object? claimValue)
    {
        if(salt.IsEmpty)
        {
            throw new ArgumentException("Salt cannot be empty.", nameof(salt));
        }

        ArgumentException.ThrowIfNullOrEmpty(claimName);

        return new SdDisclosure(salt, claimName, claimValue);
    }


    /// <summary>
    /// Creates a disclosure for an array element.
    /// </summary>
    /// <param name="salt">The cryptographic salt (minimum 128 bits recommended).</param>
    /// <param name="claimValue">The array element value.</param>
    /// <returns>A new array element disclosure.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="salt"/> is empty.
    /// </exception>
    public static SdDisclosure CreateArrayElement(ReadOnlyMemory<byte> salt, object? claimValue)
    {
        if(salt.IsEmpty)
        {
            throw new ArgumentException("Salt cannot be empty.", nameof(salt));
        }

        return new SdDisclosure(salt, null, claimValue);
    }


    private SdDisclosure(ReadOnlyMemory<byte> salt, string? claimName, object? claimValue)
    {
        Salt = salt;
        ClaimName = claimName;
        ClaimValue = claimValue;
    }


    private string DebuggerDisplay =>
        ClaimName is not null
            ? $"SdDisclosure: {ClaimName} = {ClaimValue}"
            : $"SdDisclosure: [array] = {ClaimValue}";


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(SdDisclosure? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        //Equality based on salt (cryptographic identity).
        return Salt.Span.SequenceEqual(other.Salt.Span);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj) => obj is SdDisclosure other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(Salt.Span);
        return hash.ToHashCode();
    }


    /// <summary>
    /// Returns a debug string representation.
    /// </summary>
    public override string ToString() => DebuggerDisplay;


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(SdDisclosure? left, SdDisclosure? right) =>
        left is null ? right is null : left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(SdDisclosure? left, SdDisclosure? right) => !(left == right);
}