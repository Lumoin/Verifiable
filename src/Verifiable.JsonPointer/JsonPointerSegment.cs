using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace Verifiable.JsonPointer;

/// <summary>
/// Represents a single segment (reference token) in a JSON Pointer.
/// </summary>
/// <remarks>
/// <para>
/// A JSON Pointer segment identifies either:
/// </para>
/// <list type="bullet">
/// <item><description>
/// A property name in a JSON object (any string, including empty string).
/// </description></item>
/// <item><description>
/// An array index in a JSON array (non-negative integer).
/// </description></item>
/// <item><description>
/// The array append marker ("-") for inserting at the end of an array.
/// </description></item>
/// </list>
/// <para>
/// <strong>Design Decisions:</strong>
/// </para>
/// <list type="bullet">
/// <item><description>
/// Immutable value type for efficient storage and comparison.
/// </description></item>
/// <item><description>
/// Uses a discriminated union pattern with exactly one of <see cref="PropertyName"/>,
/// <see cref="ArrayIndex"/>, or <see cref="IsAppendMarker"/> being meaningful.
/// </description></item>
/// <item><description>
/// Factory methods (<see cref="Property"/>, <see cref="Index"/>) enforce validity.
/// </description></item>
/// </list>
/// <para>
/// <strong>Thread Safety:</strong> This type is immutable and thread-safe.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// //Create segments.
/// var property = JsonPointerSegment.Property("name");
/// var index = JsonPointerSegment.Index(0);
/// var append = JsonPointerSegment.AppendMarker;
/// 
/// //Inspect segments.
/// if (segment.IsProperty)
/// {
///     Console.WriteLine($"Property: {segment.PropertyName}");
/// }
/// else if (segment.IsArrayIndex)
/// {
///     Console.WriteLine($"Index: {segment.ArrayIndex}");
/// }
/// </code>
/// </example>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly struct JsonPointerSegment: IEquatable<JsonPointerSegment>, IComparable<JsonPointerSegment>
{
    /// <summary>
    /// Property name for object property access, or <c>null</c> if this is an index.
    /// </summary>
    /// <remarks>
    /// May be an empty string, which is a valid JSON property name.
    /// </remarks>
    public string? PropertyName { get; }

    /// <summary>
    /// Array index for array element access, or <c>null</c> if this is a property.
    /// </summary>
    /// <remarks>
    /// Always non-negative when present. Use <see cref="IsAppendMarker"/> to check
    /// for the special "-" append position.
    /// </remarks>
    public int? ArrayIndex { get; }

    /// <summary>
    /// Whether this segment represents a property name.
    /// </summary>
    /// <remarks>
    /// Mutually exclusive with <see cref="IsArrayIndex"/> and <see cref="IsAppendMarker"/>.
    /// </remarks>
    public bool IsProperty => PropertyName is not null;

    /// <summary>
    /// Whether this segment represents an array index.
    /// </summary>
    /// <remarks>
    /// Mutually exclusive with <see cref="IsProperty"/> and <see cref="IsAppendMarker"/>.
    /// </remarks>
    public bool IsArrayIndex => ArrayIndex.HasValue;

    /// <summary>
    /// Whether this segment is the append marker ("-").
    /// </summary>
    /// <remarks>
    /// <para>
    /// The append marker is used in JSON Patch operations to indicate insertion
    /// at the end of an array. When evaluating a pointer, this typically results
    /// in an error unless specifically handled.
    /// </para>
    /// <para>
    /// Mutually exclusive with <see cref="IsProperty"/> and <see cref="IsArrayIndex"/>.
    /// </para>
    /// </remarks>
    public bool IsAppendMarker { get; }

    /// <summary>
    /// The append marker segment ("-").
    /// </summary>
    /// <remarks>
    /// Per RFC 6901 §4, the "-" character represents the member after the last
    /// array element. It is used in JSON Patch to append to arrays.
    /// </remarks>
    public static JsonPointerSegment AppendMarker { get; } = new(null, null, isAppendMarker: true);


    /// <summary>
    /// Creates a segment. Use factory methods <see cref="Property"/> or <see cref="Index"/> instead.
    /// </summary>
    private JsonPointerSegment(string? propertyName, int? arrayIndex, bool isAppendMarker = false)
    {
        PropertyName = propertyName;
        ArrayIndex = arrayIndex;
        IsAppendMarker = isAppendMarker;
    }


    /// <summary>
    /// Creates a property name segment.
    /// </summary>
    /// <param name="name">
    /// The property name. May be empty but not <c>null</c>.
    /// </param>
    /// <returns>A segment representing the property.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="name"/> is <c>null</c>.
    /// </exception>
    /// <remarks>
    /// The name should be the unescaped property name. Escaping is handled
    /// during serialization to string form.
    /// </remarks>
    public static JsonPointerSegment Property(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        return new JsonPointerSegment(name, null);
    }


    /// <summary>
    /// Creates an array index segment.
    /// </summary>
    /// <param name="index">The array index (must be non-negative).</param>
    /// <returns>A segment representing the array index.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="index"/> is negative.
    /// </exception>
    public static JsonPointerSegment Index(int index)
    {
        if(index < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(index), index, "Array index must be non-negative.");
        }

        return new JsonPointerSegment(null, index);
    }


    /// <summary>
    /// Converts this segment to its escaped string representation for use in a JSON Pointer.
    /// </summary>
    /// <returns>
    /// The escaped string. '~' becomes '~0' and '/' becomes '~1'.
    /// </returns>
    /// <remarks>
    /// For array indexes, returns the decimal string representation.
    /// For the append marker, returns "-".
    /// </remarks>
    public string ToEscapedString()
    {
        if(IsAppendMarker)
        {
            return "-";
        }

        if(IsArrayIndex)
        {
            return ArrayIndex!.Value.ToString(CultureInfo.InvariantCulture);
        }

        return JsonPointer.Escape(PropertyName!);
    }


    /// <summary>
    /// Returns the unescaped string value of this segment.
    /// </summary>
    /// <returns>
    /// The property name, index as string, or "-" for append marker.
    /// </returns>
    public string ToUnescapedString()
    {
        if(IsAppendMarker)
        {
            return "-";
        }

        if(IsArrayIndex)
        {
            return ArrayIndex!.Value.ToString(CultureInfo.InvariantCulture);
        }

        return PropertyName!;
    }


    /// <summary>
    /// Gets the debugger display string.
    /// </summary>
    private string DebuggerDisplay
    {
        get
        {
            if(IsAppendMarker)
            {
                return "[-]";
            }

            if(IsArrayIndex)
            {
                return $"[{ArrayIndex}]";
            }

            if(IsProperty)
            {
                return PropertyName!.Length == 0 ? "(empty)" : PropertyName!;
            }

            return "(invalid)";
        }
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(JsonPointerSegment other)
    {
        if(IsAppendMarker && other.IsAppendMarker)
        {
            return true;
        }

        if(IsProperty && other.IsProperty)
        {
            return string.Equals(PropertyName, other.PropertyName, StringComparison.Ordinal);
        }

        if(IsArrayIndex && other.IsArrayIndex)
        {
            return ArrayIndex == other.ArrayIndex;
        }

        return false;
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
        if(IsAppendMarker)
        {
            return HashCode.Combine(3, "-");
        }

        if(IsProperty)
        {
            return HashCode.Combine(1, PropertyName);
        }

        if(IsArrayIndex)
        {
            return HashCode.Combine(2, ArrayIndex);
        }

        return 0;
    }


    /// <inheritdoc/>
    /// <remarks>
    /// <para>
    /// Ordering is defined as:
    /// </para>
    /// <list type="number">
    /// <item><description>Properties (sorted alphabetically by ordinal comparison).</description></item>
    /// <item><description>Array indexes (sorted numerically).</description></item>
    /// <item><description>Append marker (sorts after all indexes).</description></item>
    /// </list>
    /// <para>
    /// This ordering ensures that traversing a sorted collection of segments
    /// visits object properties before array elements.
    /// </para>
    /// </remarks>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public int CompareTo(JsonPointerSegment other)
    {
        //Properties sort first.
        if(IsProperty && other.IsProperty)
        {
            return string.Compare(PropertyName, other.PropertyName, StringComparison.Ordinal);
        }

        if(IsProperty)
        {
            return -1;
        }

        if(other.IsProperty)
        {
            return 1;
        }

        //Then array indexes.
        if(IsArrayIndex && other.IsArrayIndex)
        {
            return ArrayIndex!.Value.CompareTo(other.ArrayIndex!.Value);
        }

        if(IsArrayIndex)
        {
            return -1;
        }

        if(other.IsArrayIndex)
        {
            return 1;
        }

        //Append markers are equal to each other.
        if(IsAppendMarker && other.IsAppendMarker)
        {
            return 0;
        }

        return 0;
    }


    /// <summary>
    /// Returns the unescaped string representation.
    /// </summary>
    public override string ToString() => ToUnescapedString();


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
    /// Implicitly converts a string to a property segment.
    /// </summary>
    /// <param name="propertyName">The property name.</param>
    public static implicit operator JsonPointerSegment(string propertyName) => Property(propertyName);

    /// <summary>
    /// Implicitly converts an integer to an index segment.
    /// </summary>
    /// <param name="index">The array index.</param>
    public static implicit operator JsonPointerSegment(int index) => Index(index);
}