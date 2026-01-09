using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text;

namespace Verifiable.JsonPointer;

/// <summary>
/// Represents a JSON Pointer as defined in RFC 6901.
/// </summary>
/// <remarks>
/// <para>
/// A JSON Pointer is a string syntax for identifying a specific value within a JSON document.
/// It consists of a sequence of reference tokens separated by '/' characters. Each token
/// identifies a specific element: an object property name or an array index.
/// </para>
/// <para>
/// <strong>RFC 6901 Specification:</strong>
/// </para>
/// <list type="bullet">
/// <item><description>The empty string "" points to the root document.</description></item>
/// <item><description>All other pointers must start with '/'.</description></item>
/// <item><description>'~' is escaped as '~0' and '/' is escaped as '~1'.</description></item>
/// <item><description>Array indexes are non-negative integers or '-' for appending.</description></item>
/// </list>
/// <para>
/// <strong>Design Decisions:</strong>
/// </para>
/// <list type="bullet">
/// <item><description>
/// Immutable value type for zero-allocation equality checks and safe sharing.
/// </description></item>
/// <item><description>
/// Segments are stored as an array for O(1) depth queries and efficient slicing.
/// </description></item>
/// <item><description>
/// This library has no external dependencies - evaluation against specific document
/// formats (JSON, CBOR, POCOs) is provided by separate extension libraries.
/// </description></item>
/// </list>
/// <para>
/// <strong>Thread Safety:</strong> This type is immutable and thread-safe.
/// </para>
/// </remarks>
[DebuggerDisplay("{ToString()}")]
public readonly struct JsonPointer: IEquatable<JsonPointer>, IComparable<JsonPointer>
{
    private readonly JsonPointerSegment[]? _segments;
    private readonly string? _cachedString;

    /// <summary>
    /// The root pointer representing the entire document.
    /// </summary>
    public static JsonPointer Root { get; } = new([], "");

    /// <summary>
    /// The segments comprising this pointer.
    /// </summary>
    public ReadOnlySpan<JsonPointerSegment> Segments => _segments ?? [];

    /// <summary>
    /// The number of segments in this pointer (depth in tree).
    /// </summary>
    public int Depth => _segments?.Length ?? 0;

    /// <summary>
    /// Whether this is the root pointer (empty string).
    /// </summary>
    public bool IsRoot => Depth == 0;

    /// <summary>
    /// The final segment of this pointer, or <c>null</c> for the root.
    /// </summary>
    public JsonPointerSegment? LastSegment => Depth > 0 ? _segments![^1] : default(JsonPointerSegment?);


    private JsonPointer(JsonPointerSegment[] segments, string? cachedString = null)
    {
        _segments = segments;
        _cachedString = cachedString;
    }


    /// <summary>
    /// Parses a JSON Pointer string according to RFC 6901.
    /// </summary>
    /// <param name="pointer">The JSON Pointer string. Must be empty (root) or start with '/'.</param>
    /// <returns>The parsed JSON Pointer.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="pointer"/> is <c>null</c>.</exception>
    /// <exception cref="FormatException">Thrown when the format is invalid.</exception>
    public static JsonPointer Parse(string pointer)
    {
        ArgumentNullException.ThrowIfNull(pointer);

        if(pointer.Length == 0)
        {
            return Root;
        }

        if(pointer[0] != '/')
        {
            throw new FormatException(
                $"JSON Pointer must be empty or start with '/'. Got: \"{Truncate(pointer, 50)}\"");
        }

        if(pointer.Length == 1)
        {
            return new JsonPointer([JsonPointerSegment.Property("")], pointer);
        }

        return ParseCore(pointer);
    }


    /// <summary>
    /// Attempts to parse a JSON Pointer string.
    /// </summary>
    /// <param name="pointer">The JSON Pointer string to parse.</param>
    /// <param name="result">The parsed pointer if successful.</param>
    /// <returns><c>true</c> if parsing succeeded; otherwise, <c>false</c>.</returns>
    public static bool TryParse(string? pointer, out JsonPointer result)
    {
        if(pointer is null)
        {
            result = default;
            return false;
        }

        if(pointer.Length == 0)
        {
            result = Root;
            return true;
        }

        if(pointer[0] != '/')
        {
            result = default;
            return false;
        }

        try
        {
            result = ParseCore(pointer);
            return true;
        }
        catch(FormatException)
        {
            result = default;
            return false;
        }
    }


    private static JsonPointer ParseCore(string pointer)
    {
        var segments = new List<JsonPointerSegment>();
        int start = 1;

        for(int i = 1; i <= pointer.Length; i++)
        {
            if(i == pointer.Length || pointer[i] == '/')
            {
                string raw = pointer[start..i];
                string unescaped = Unescape(raw);
                segments.Add(ParseSegment(unescaped));
                start = i + 1;
            }
        }

        return new JsonPointer([.. segments], pointer);
    }


    private static JsonPointerSegment ParseSegment(string unescaped)
    {
        if(unescaped.Length > 0 && IsValidArrayIndex(unescaped, out int index))
        {
            return JsonPointerSegment.Index(index);
        }

        if(unescaped == "-")
        {
            return JsonPointerSegment.AppendMarker;
        }

        return JsonPointerSegment.Property(unescaped);
    }


    private static bool IsValidArrayIndex(string value, out int index)
    {
        index = 0;

        if(value.Length == 0)
        {
            return false;
        }

        if(value.Length == 1)
        {
            if(char.IsAsciiDigit(value[0]))
            {
                index = value[0] - '0';
                return true;
            }
            return false;
        }

        //No leading zeros per RFC 6901.
        if(value[0] == '0')
        {
            return false;
        }

        foreach(char c in value)
        {
            if(!char.IsAsciiDigit(c))
            {
                return false;
            }
        }

        return int.TryParse(value, out index) && index >= 0;
    }


    /// <summary>
    /// Creates a pointer from segments.
    /// </summary>
    public static JsonPointer FromSegments(ReadOnlySpan<JsonPointerSegment> segments)
    {
        return segments.Length == 0 ? Root : new JsonPointer(segments.ToArray());
    }


    /// <summary>
    /// Creates a pointer from a single property name.
    /// </summary>
    public static JsonPointer FromProperty(string propertyName)
    {
        ArgumentNullException.ThrowIfNull(propertyName);
        return new JsonPointer([JsonPointerSegment.Property(propertyName)]);
    }


    /// <summary>
    /// Creates a pointer from a single array index.
    /// </summary>
    public static JsonPointer FromIndex(int index)
    {
        if(index < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(index), index, "Array index must be non-negative.");
        }

        return new JsonPointer([JsonPointerSegment.Index(index)]);
    }


    /// <summary>
    /// Returns the parent pointer, or <c>null</c> if this is the root.
    /// </summary>
    public JsonPointer? Parent
    {
        get
        {
            if(Depth == 0)
            {
                return null;
            }

            return Depth == 1 ? Root : new JsonPointer(_segments![..^1]);
        }
    }


    /// <summary>
    /// Enumerates all ancestor pointers from root to parent (exclusive of this pointer).
    /// </summary>
    public IEnumerable<JsonPointer> Ancestors()
    {
        for(int i = 0; i < Depth; i++)
        {
            yield return i == 0 ? Root : new JsonPointer(_segments![..i]);
        }
    }


    /// <summary>
    /// Enumerates this pointer and all ancestor pointers.
    /// </summary>
    public IEnumerable<JsonPointer> SelfAndAncestors()
    {
        for(int i = 0; i <= Depth; i++)
        {
            yield return i == 0 ? Root : new JsonPointer(_segments![..i]);
        }
    }


    /// <summary>
    /// Creates a new pointer by appending a property name segment.
    /// </summary>
    public JsonPointer Append(string propertyName)
    {
        ArgumentNullException.ThrowIfNull(propertyName);

        var newSegments = new JsonPointerSegment[Depth + 1];
        Segments.CopyTo(newSegments);
        newSegments[Depth] = JsonPointerSegment.Property(propertyName);

        return new JsonPointer(newSegments);
    }


    /// <summary>
    /// Creates a new pointer by appending an array index segment.
    /// </summary>
    public JsonPointer Append(int index)
    {
        if(index < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(index), index, "Array index must be non-negative.");
        }

        var newSegments = new JsonPointerSegment[Depth + 1];
        Segments.CopyTo(newSegments);
        newSegments[Depth] = JsonPointerSegment.Index(index);

        return new JsonPointer(newSegments);
    }


    /// <summary>
    /// Creates a new pointer by appending a segment.
    /// </summary>
    public JsonPointer Append(JsonPointerSegment segment)
    {
        var newSegments = new JsonPointerSegment[Depth + 1];
        Segments.CopyTo(newSegments);
        newSegments[Depth] = segment;

        return new JsonPointer(newSegments);
    }


    /// <summary>
    /// Creates a new pointer by appending another pointer's segments.
    /// </summary>
    public JsonPointer Append(JsonPointer other)
    {
        if(other.IsRoot)
        {
            return this;
        }

        if(IsRoot)
        {
            return other;
        }

        var newSegments = new JsonPointerSegment[Depth + other.Depth];
        Segments.CopyTo(newSegments);
        other.Segments.CopyTo(newSegments.AsSpan(Depth));

        return new JsonPointer(newSegments);
    }


    /// <summary>
    /// Checks if this pointer is an ancestor of another pointer.
    /// </summary>
    public bool IsAncestorOf(JsonPointer other)
    {
        if(Depth >= other.Depth)
        {
            return false;
        }

        ReadOnlySpan<JsonPointerSegment> thisSegments = Segments;
        ReadOnlySpan<JsonPointerSegment> otherSegments = other.Segments;

        for(int i = 0; i < Depth; i++)
        {
            if(!thisSegments[i].Equals(otherSegments[i]))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Checks if this pointer is a descendant of another pointer.
    /// </summary>
    public bool IsDescendantOf(JsonPointer other) => other.IsAncestorOf(this);


    /// <summary>
    /// Checks if this pointer is an ancestor of or equal to another pointer.
    /// </summary>
    public bool IsAncestorOfOrEqualTo(JsonPointer other) => Equals(other) || IsAncestorOf(other);


    /// <summary>
    /// Checks if this pointer is a descendant of or equal to another pointer.
    /// </summary>
    public bool IsDescendantOfOrEqualTo(JsonPointer other) => other.IsAncestorOfOrEqualTo(this);


    /// <summary>
    /// Computes the relative pointer from an ancestor to this pointer.
    /// </summary>
    public JsonPointer RelativeTo(JsonPointer ancestor)
    {
        if(!ancestor.IsAncestorOfOrEqualTo(this))
        {
            throw new ArgumentException(
                $"Pointer \"{ancestor}\" is not an ancestor of \"{this}\".",
                nameof(ancestor));
        }

        if(ancestor.Equals(this))
        {
            return Root;
        }

        return new JsonPointer(_segments![ancestor.Depth..]);
    }


    private static string Unescape(string token)
    {
        if(!token.Contains('~', StringComparison.Ordinal))
        {
            return token;
        }

        var result = new StringBuilder(token.Length);

        for(int i = 0; i < token.Length; i++)
        {
            if(token[i] == '~')
            {
                if(i + 1 >= token.Length)
                {
                    throw new FormatException("Invalid escape sequence: '~' at end of token.");
                }

                char next = token[i + 1];
                result.Append(next switch
                {
                    '0' => '~',
                    '1' => '/',
                    _ => throw new FormatException(
                        $"Invalid escape sequence: '~{next}'. Only '~0' and '~1' are valid.")
                });

                i++;
            }
            else
            {
                result.Append(token[i]);
            }
        }

        return result.ToString();
    }


    /// <summary>
    /// Escapes a string for use as a JSON Pointer token.
    /// </summary>
    public static string Escape(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        if(!value.Contains('~', StringComparison.Ordinal) && !value.Contains('/', StringComparison.Ordinal))
        {
            return value;
        }

        return value.Replace("~", "~0", StringComparison.Ordinal).Replace("/", "~1", StringComparison.Ordinal);
    }


    /// <summary>
    /// Converts this pointer to its RFC 6901 string representation.
    /// </summary>
    public override string ToString()
    {
        if(_cachedString is not null)
        {
            return _cachedString;
        }

        if(Depth == 0)
        {
            return "";
        }

        var builder = new StringBuilder();

        foreach(JsonPointerSegment segment in Segments)
        {
            builder.Append('/');
            builder.Append(segment.ToEscapedString());
        }

        return builder.ToString();
    }


    /// <summary>
    /// Converts this pointer to a URI fragment identifier representation.
    /// </summary>
    /// <returns>The URI fragment starting with '#'.</returns>
    public string ToUriFragment()
    {
        string pointerString = ToString();
        var result = new StringBuilder("#");

        foreach(char c in pointerString)
        {
            if(RequiresPercentEncoding(c))
            {
                foreach(byte b in Encoding.UTF8.GetBytes([c]))
                {
                    result.Append('%');
                    result.Append(b.ToString("X2"));
                }
            }
            else
            {
                result.Append(c);
            }
        }

        return result.ToString();
    }


    /// <summary>
    /// Parses a JSON Pointer from a URI fragment identifier.
    /// </summary>
    /// <param name="fragment">The URI fragment, which must start with '#'.</param>
    /// <returns>The parsed JSON Pointer.</returns>
    public static JsonPointer ParseUriFragment(string fragment)
    {
        ArgumentNullException.ThrowIfNull(fragment);

        if(fragment.Length == 0 || fragment[0] != '#')
        {
            throw new FormatException("URI fragment identifier must start with '#'.");
        }

        string decoded = Uri.UnescapeDataString(fragment[1..]);
        return Parse(decoded);
    }


    /// <summary>
    /// Attempts to parse a JSON Pointer from a URI fragment identifier.
    /// </summary>
    public static bool TryParseUriFragment(string? fragment, out JsonPointer result)
    {
        if(fragment is null || fragment.Length == 0 || fragment[0] != '#')
        {
            result = default;
            return false;
        }

        try
        {
            string decoded = Uri.UnescapeDataString(fragment[1..]);
            return TryParse(decoded, out result);
        }
        catch
        {
            result = default;
            return false;
        }
    }


    private static bool RequiresPercentEncoding(char c)
    {
        if(char.IsAsciiLetterOrDigit(c))
        {
            return false;
        }

        return c switch
        {
            '-' or '.' or '_' or '~' => false,
            '/' or '?' => false,
            ':' or '@' => false,
            '!' or '$' or '&' or '\'' or '(' or ')' => false,
            '*' or '+' or ',' or ';' or '=' => false,
            _ => true
        };
    }


    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string Truncate(string value, int maxLength)
    {
        return value.Length <= maxLength ? value : value[..maxLength] + "...";
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(JsonPointer other)
    {
        if(Depth != other.Depth)
        {
            return false;
        }

        ReadOnlySpan<JsonPointerSegment> thisSegments = Segments;
        ReadOnlySpan<JsonPointerSegment> otherSegments = other.Segments;

        for(int i = 0; i < Depth; i++)
        {
            if(!thisSegments[i].Equals(otherSegments[i]))
            {
                return false;
            }
        }

        return true;
    }

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is JsonPointer other && Equals(other);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Depth);

        foreach(JsonPointerSegment segment in Segments)
        {
            hash.Add(segment);
        }

        return hash.ToHashCode();
    }

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public int CompareTo(JsonPointer other)
    {
        int minDepth = Math.Min(Depth, other.Depth);

        for(int i = 0; i < minDepth; i++)
        {
            int comparison = _segments![i].CompareTo(other._segments![i]);
            if(comparison != 0)
            {
                return comparison;
            }
        }

        return Depth.CompareTo(other.Depth);
    }

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(JsonPointer left, JsonPointer right) => left.Equals(right);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(JsonPointer left, JsonPointer right) => !left.Equals(right);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator <(JsonPointer left, JsonPointer right) => left.CompareTo(right) < 0;

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator <=(JsonPointer left, JsonPointer right) => left.CompareTo(right) <= 0;

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator >(JsonPointer left, JsonPointer right) => left.CompareTo(right) > 0;

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator >=(JsonPointer left, JsonPointer right) => left.CompareTo(right) >= 0;

    /// <summary>
    /// Implicitly converts a string to a JSON Pointer by parsing it.
    /// </summary>
    public static implicit operator JsonPointer(string pointer) => Parse(pointer);

    /// <summary>
    /// Explicitly converts a JSON Pointer to its string representation.
    /// </summary>
    public static explicit operator string(JsonPointer pointer) => pointer.ToString();
}