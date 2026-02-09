using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace Verifiable.JsonPointer;

/// <summary>
/// Represents a single reference token in a JSON Pointer (RFC 6901).
/// </summary>
/// <remarks>
/// <para>
/// A reference token is an unescaped string that identifies a location within a JSON document.
/// Per RFC 6901 §4, interpretation depends on the document node encountered during evaluation:
/// </para>
/// <list type="bullet">
/// <item><description>
/// Against a JSON object, the token is used as a property name.
/// </description></item>
/// <item><description>
/// Against a JSON array, the token must be a valid non-negative integer index or "-".
/// </description></item>
/// </list>
/// <para>
/// This type stores only the raw token string. It does not decide whether the token
/// represents a property name or array index — that determination is made at evaluation
/// time by the code that navigates a specific document format.
/// </para>
/// <para>
/// <strong>Design Rationale:</strong> RFC 6901 defines reference tokens as strings.
/// The token "0" in <c>/items/0</c> could address either an array element or an object
/// property named "0" — only the document structure determines which. Premature
/// classification at parse time would lose information and prevent correct handling
/// of documents with numeric property keys (common in JSON-LD, JSON Schema, and others).
/// </para>
/// <para>
/// <strong>Thread Safety:</strong> This type is immutable and thread-safe.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// //Create segments from tokens.
/// var name = JsonPointerSegment.Create("name");
/// var index = JsonPointerSegment.Create("0");
/// var append = JsonPointerSegment.AppendMarker;
///
/// //Check token characteristics for evaluation.
/// if(segment.TryGetArrayIndex(out int idx))
/// {
///     Console.WriteLine($"Can be used as array index: {idx}");
/// }
///
/// //The token is always available as a string.
/// Console.WriteLine($"Token: {segment.Value}");
/// </code>
/// </example>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly struct JsonPointerSegment: IEquatable<JsonPointerSegment>, IComparable<JsonPointerSegment>
{
    /// <summary>
    /// The raw, unescaped reference token.
    /// </summary>
    /// <remarks>
    /// This is the decoded token value. Escape sequences (<c>~0</c> for <c>~</c>,
    /// <c>~1</c> for <c>/</c>) have already been resolved. The value may be empty,
    /// which is a valid property name.
    /// </remarks>
    public string Value { get; }

    /// <summary>
    /// Whether this token could be interpreted as a non-negative array index.
    /// </summary>
    /// <remarks>
    /// Returns <c>true</c> when the token is a string of digits with no leading zeros
    /// (or exactly "0") that fits in an <see cref="int"/>. This does not mean it
    /// <em>is</em> an array index — that depends on the document node at evaluation time.
    /// </remarks>
    public bool CanBeArrayIndex => TryGetArrayIndex(out _);

    /// <summary>
    /// Whether this token is the append marker ("-").
    /// </summary>
    /// <remarks>
    /// Per RFC 6901 §4, the "-" character references the nonexistent member after
    /// the last array element. It is primarily used in JSON Patch (RFC 6902) to
    /// append to arrays.
    /// </remarks>
    public bool IsAppendMarker => Value == "-";


    /// <summary>
    /// The append marker segment ("-").
    /// </summary>
    /// <remarks>
    /// Per RFC 6901 §4, the "-" character represents the member after the last
    /// array element. It is used in JSON Patch to append to arrays.
    /// </remarks>
    public static JsonPointerSegment AppendMarker { get; } = new("-");


    /// <summary>
    /// Creates a segment from an unescaped reference token.
    /// </summary>
    /// <param name="token">
    /// The unescaped reference token. May be empty but not <c>null</c>.
    /// </param>
    /// <returns>A segment representing the token.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="token"/> is <c>null</c>.
    /// </exception>
    public static JsonPointerSegment Create(string token)
    {
        ArgumentNullException.ThrowIfNull(token);
        return new JsonPointerSegment(token);
    }


    /// <summary>
    /// Creates a segment from an array index.
    /// </summary>
    /// <param name="index">The array index (must be non-negative).</param>
    /// <returns>A segment whose token is the decimal string representation of the index.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="index"/> is negative.
    /// </exception>
    /// <remarks>
    /// This is a convenience method. The resulting segment stores the index as its
    /// string representation. At evaluation time, the evaluator determines whether
    /// to use it as an array index or property name based on the document structure.
    /// </remarks>
    public static JsonPointerSegment FromIndex(int index)
    {
        if(index < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(index), index, "Array index must be non-negative.");
        }

        return new JsonPointerSegment(index.ToString(CultureInfo.InvariantCulture));
    }


    private JsonPointerSegment(string value)
    {
        Value = value;
    }


    /// <summary>
    /// Attempts to interpret this token as a non-negative array index.
    /// </summary>
    /// <param name="index">
    /// When this method returns <c>true</c>, contains the parsed index value.
    /// </param>
    /// <returns>
    /// <c>true</c> if the token is a valid RFC 6901 array index (digits with no
    /// leading zeros, fits in an <see cref="int"/>); otherwise, <c>false</c>.
    /// </returns>
    /// <remarks>
    /// Per RFC 6901, valid array indexes are "0" or a digit 1-9 followed by
    /// zero or more digits 0-9. Leading zeros are not permitted.
    /// </remarks>
    public bool TryGetArrayIndex(out int index)
    {
        index = 0;

        if(Value.Length == 0)
        {
            return false;
        }

        if(Value.Length == 1)
        {
            if(char.IsAsciiDigit(Value[0]))
            {
                index = Value[0] - '0';
                return true;
            }

            return false;
        }

        //No leading zeros per RFC 6901.
        if(Value[0] == '0')
        {
            return false;
        }

        foreach(char c in Value)
        {
            if(!char.IsAsciiDigit(c))
            {
                return false;
            }
        }

        return int.TryParse(Value, NumberStyles.None, CultureInfo.InvariantCulture, out index) && index >= 0;
    }


    /// <summary>
    /// Returns the escaped form of this token for use in a JSON Pointer string.
    /// </summary>
    /// <returns>
    /// The token with <c>~</c> escaped as <c>~0</c> and <c>/</c> escaped as <c>~1</c>.
    /// </returns>
    public string ToEscapedString() => JsonPointer.Escape(Value);


    /// <summary>
    /// Returns the raw, unescaped token value.
    /// </summary>
    public override string ToString() => Value;


    /// <summary>
    /// Gets the debugger display string.
    /// </summary>
    private string DebuggerDisplay
    {
        get
        {
            if(Value.Length == 0)
            {
                return "(empty)";
            }

            if(IsAppendMarker)
            {
                return "[-]";
            }

            if(TryGetArrayIndex(out int idx))
            {
                return $"{Value} (index {idx})";
            }

            return Value;
        }
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(JsonPointerSegment other)
    {
        return string.Equals(Value, other.Value, StringComparison.Ordinal);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj)
    {
        return obj is JsonPointerSegment other && Equals(other);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        return string.GetHashCode(Value, StringComparison.Ordinal);
    }


    /// <inheritdoc/>
    /// <remarks>
    /// Ordering is ordinal string comparison of the raw token values. This provides
    /// a consistent, deterministic ordering suitable for sorted collections and
    /// canonicalization. Tokens that can be interpreted as array indexes are compared
    /// as strings, not numerically — use a custom comparer if numeric ordering is needed.
    /// </remarks>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public int CompareTo(JsonPointerSegment other)
    {
        return string.Compare(Value, other.Value, StringComparison.Ordinal);
    }


    /// <summary>
    /// Determines whether two segments are equal.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(JsonPointerSegment left, JsonPointerSegment right) => left.Equals(right);

    /// <summary>
    /// Determines whether two segments are not equal.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(JsonPointerSegment left, JsonPointerSegment right) => !left.Equals(right);

    /// <summary>
    /// Determines whether the left segment precedes the right segment.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator <(JsonPointerSegment left, JsonPointerSegment right) => left.CompareTo(right) < 0;

    /// <summary>
    /// Determines whether the left segment precedes or equals the right segment.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator <=(JsonPointerSegment left, JsonPointerSegment right) => left.CompareTo(right) <= 0;

    /// <summary>
    /// Determines whether the left segment follows the right segment.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator >(JsonPointerSegment left, JsonPointerSegment right) => left.CompareTo(right) > 0;

    /// <summary>
    /// Determines whether the left segment follows or equals the right segment.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator >=(JsonPointerSegment left, JsonPointerSegment right) => left.CompareTo(right) >= 0;

    /// <summary>
    /// Implicitly converts a string to a segment.
    /// </summary>
    /// <param name="token">The unescaped reference token.</param>
    public static implicit operator JsonPointerSegment(string token) => Create(token);

    /// <summary>
    /// Implicitly converts an integer to a segment.
    /// </summary>
    /// <param name="index">The array index.</param>
    public static implicit operator JsonPointerSegment(int index) => FromIndex(index);
}