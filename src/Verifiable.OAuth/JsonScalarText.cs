using System.Globalization;
using System.Text;
using Verifiable.Server;

namespace Verifiable.OAuth;

/// <summary>
/// Reads a JSON scalar from the raw JSON text of one value, the inverse of the string escaping
/// <see cref="JsonAppender.AppendEscapedString"/> performs. It lets the library inspect a single
/// member's value carried verbatim in <see cref="AuthorizationDetail.ExtensionData"/> without
/// crossing the <c>Verifiable.OAuth</c> serialization firewall (no <c>System.Text.Json</c>).
/// </summary>
/// <remarks>
/// Only the string scalar is decoded here, the one shape the library's built-in authorization
/// details handlers read from their type-specific members; object, array, number, boolean, and
/// null values are preserved as their raw text for handlers that need them.
/// </remarks>
public static class JsonScalarText
{
    /// <summary>
    /// Decodes <paramref name="rawJsonValue"/> as a JSON string scalar, or returns
    /// <see langword="null"/> when the value is not a JSON string (an object, array, number,
    /// boolean, <c>null</c>, or malformed text). The input is the raw JSON text of one value,
    /// including the surrounding quotes for a string.
    /// </summary>
    /// <param name="rawJsonValue">The raw JSON text of one value.</param>
    /// <returns>The decoded string, or <see langword="null"/> when the value is not a JSON string.</returns>
    public static string? AsString(string rawJsonValue)
    {
        ArgumentNullException.ThrowIfNull(rawJsonValue);

        string trimmed = rawJsonValue.Trim();
        if(trimmed.Length < 2 || trimmed[0] != '"' || trimmed[^1] != '"')
        {
            return null;
        }

        StringBuilder sb = new(trimmed.Length - 2);
        int i = 1;
        int end = trimmed.Length - 1;
        while(i < end)
        {
            char c = trimmed[i];
            if(c != '\\')
            {
                sb.Append(c);
                i++;

                continue;
            }

            if(i + 1 >= end)
            {
                return null;
            }

            char escape = trimmed[i + 1];
            switch(escape)
            {
                case '"':
                {
                    sb.Append('"');
                    i += 2;
                    break;
                }

                case '\\':
                {
                    sb.Append('\\');
                    i += 2;
                    break;
                }

                case '/':
                {
                    sb.Append('/');
                    i += 2;
                    break;
                }

                case 'b':
                {
                    sb.Append('\b');
                    i += 2;
                    break;
                }

                case 'f':
                {
                    sb.Append('\f');
                    i += 2;
                    break;
                }

                case 'n':
                {
                    sb.Append('\n');
                    i += 2;
                    break;
                }

                case 'r':
                {
                    sb.Append('\r');
                    i += 2;
                    break;
                }

                case 't':
                {
                    sb.Append('\t');
                    i += 2;
                    break;
                }

                case 'u':
                {
                    if(i + 6 > end
                        || !ushort.TryParse(
                            trimmed.AsSpan(i + 2, 4),
                            NumberStyles.HexNumber,
                            CultureInfo.InvariantCulture,
                            out ushort code))
                    {
                        return null;
                    }

                    sb.Append((char)code);
                    i += 6;
                    break;
                }

                default:
                {
                    return null;
                }
            }
        }

        return sb.ToString();
    }


    /// <summary>
    /// Classifies the JSON kind of <paramref name="rawJsonValue"/> from its raw text, looking
    /// only at the leading non-whitespace character (and the literal spelling for
    /// <c>true</c>/<c>false</c>/<c>null</c>). It lets a strict authorization details handler
    /// reject a type-specific member of the wrong JSON type (RFC 9396 §5: "contains fields of the
    /// wrong type for the authorization details type") without crossing the
    /// <c>Verifiable.OAuth</c> serialization firewall.
    /// </summary>
    /// <param name="rawJsonValue">The raw JSON text of one value.</param>
    /// <returns>The classified <see cref="JsonValueShape"/>.</returns>
    public static JsonValueShape ClassifyKind(string rawJsonValue)
    {
        ArgumentNullException.ThrowIfNull(rawJsonValue);

        string trimmed = rawJsonValue.Trim();
        if(trimmed.Length == 0)
        {
            return JsonValueShape.Malformed;
        }

        return trimmed[0] switch
        {
            '"' => trimmed.Length >= 2 && trimmed[^1] == '"' ? JsonValueShape.String : JsonValueShape.Malformed,
            '[' => trimmed[^1] == ']' ? JsonValueShape.Array : JsonValueShape.Malformed,
            '{' => trimmed[^1] == '}' ? JsonValueShape.Object : JsonValueShape.Malformed,
            't' => string.Equals(trimmed, "true", StringComparison.Ordinal) ? JsonValueShape.Boolean : JsonValueShape.Malformed,
            'f' => string.Equals(trimmed, "false", StringComparison.Ordinal) ? JsonValueShape.Boolean : JsonValueShape.Malformed,
            'n' => string.Equals(trimmed, "null", StringComparison.Ordinal) ? JsonValueShape.Null : JsonValueShape.Malformed,
            '-' or (>= '0' and <= '9') => JsonValueShape.Number,
            _ => JsonValueShape.Malformed
        };
    }


    /// <summary>
    /// Whether <paramref name="rawJsonValue"/> is a JSON array whose every element is a JSON
    /// string — the wire shape RFC 9396 §2.2 defines for the array-of-strings common fields and
    /// the shape a strict handler can require of a type-specific array member. Decodes the array
    /// and inspects each element; an empty array satisfies it.
    /// </summary>
    /// <param name="rawJsonValue">The raw JSON text of one value.</param>
    /// <returns>
    /// <see langword="true"/> when the value is a JSON array of JSON strings; otherwise
    /// <see langword="false"/>.
    /// </returns>
    public static bool IsArrayOfStrings(string rawJsonValue)
    {
        ArgumentNullException.ThrowIfNull(rawJsonValue);

        string trimmed = rawJsonValue.Trim();
        if(trimmed.Length < 2 || trimmed[0] != '[' || trimmed[^1] != ']')
        {
            return false;
        }

        int i = 1;
        int end = trimmed.Length - 1;
        bool isExpectingValue = false;
        while(i < end)
        {
            char c = trimmed[i];
            if(char.IsWhiteSpace(c))
            {
                i++;

                continue;
            }

            if(c == ',')
            {
                if(isExpectingValue)
                {
                    return false;
                }

                isExpectingValue = true;
                i++;

                continue;
            }

            if(c != '"')
            {
                return false;
            }

            int closingQuote = FindStringEnd(trimmed, i, end);
            if(closingQuote < 0)
            {
                return false;
            }

            i = closingQuote + 1;
            isExpectingValue = false;
        }

        return !isExpectingValue;
    }


    /// <summary>
    /// Decodes <paramref name="rawJsonValue"/> — the raw JSON text of one value carried verbatim
    /// in <see cref="AuthorizationDetail.ExtensionData"/> — into the CLR object graph the library's
    /// JSON writers render natively: a JSON string becomes a <see cref="string"/>, a number a
    /// <see cref="long"/> when integral else a <see cref="double"/>, a boolean a <see cref="bool"/>,
    /// <c>null</c> a <see langword="null"/> reference, an array a <c>List&lt;object?&gt;</c>, and an
    /// object a <c>Dictionary&lt;string, object?&gt;</c>. Returns <see langword="null"/> when the
    /// text is not a single well-formed JSON value. This is the inverse of
    /// <see cref="JsonAppender.AppendValue"/>, keeping the conversion inside the
    /// <c>Verifiable.OAuth</c> serialization firewall (no <c>System.Text.Json</c>) so a decoded
    /// value round-trips identically through the manual writer and the wired JWT serializer.
    /// </summary>
    /// <param name="rawJsonValue">The raw JSON text of one value.</param>
    /// <returns>
    /// The decoded CLR object graph, or <see langword="null"/> when the text is not a single
    /// well-formed JSON value. A successfully decoded JSON <c>null</c> also yields
    /// <see langword="null"/>; callers needing to distinguish the two inspect
    /// <see cref="ClassifyKind"/> first.
    /// </returns>
    public static object? DecodeValue(string rawJsonValue)
    {
        ArgumentNullException.ThrowIfNull(rawJsonValue);

        int position = 0;
        if(!TryDecodeValue(rawJsonValue, ref position, out object? value))
        {
            return null;
        }

        SkipWhitespace(rawJsonValue, ref position);

        return position == rawJsonValue.Length ? value : null;
    }


    //Decodes one JSON value starting at position, advancing it past the consumed text. Returns
    //false on malformed input. Bounded recursion: the depth of the call stack tracks the nesting
    //depth of the value, which the caller's ExtensionData raw text already bounds.
    private static bool TryDecodeValue(string text, ref int position, out object? value)
    {
        value = null;
        SkipWhitespace(text, ref position);
        if(position >= text.Length)
        {
            return false;
        }

        char c = text[position];

        return c switch
        {
            '"' => TryDecodeString(text, ref position, out value),
            '{' => TryDecodeObject(text, ref position, out value),
            '[' => TryDecodeArray(text, ref position, out value),
            't' or 'f' => TryDecodeBoolean(text, ref position, out value),
            'n' => TryDecodeNull(text, ref position, out value),
            '-' or (>= '0' and <= '9') => TryDecodeNumber(text, ref position, out value),
            _ => false
        };
    }


    private static bool TryDecodeString(string text, ref int position, out object? value)
    {
        value = null;
        int closingQuote = FindStringEnd(text, position, text.Length);
        if(closingQuote < 0)
        {
            return false;
        }

        string decoded = AsString(text[position..(closingQuote + 1)]) ?? string.Empty;
        value = decoded;
        position = closingQuote + 1;

        return true;
    }


    private static bool TryDecodeObject(string text, ref int position, out object? value)
    {
        value = null;
        var map = new Dictionary<string, object?>(StringComparer.Ordinal);
        position++;
        SkipWhitespace(text, ref position);
        if(position < text.Length && text[position] == '}')
        {
            position++;
            value = map;

            return true;
        }

        while(true)
        {
            SkipWhitespace(text, ref position);
            if(position >= text.Length || text[position] != '"')
            {
                return false;
            }

            int closingQuote = FindStringEnd(text, position, text.Length);
            if(closingQuote < 0)
            {
                return false;
            }

            string name = AsString(text[position..(closingQuote + 1)]) ?? string.Empty;
            position = closingQuote + 1;

            SkipWhitespace(text, ref position);
            if(position >= text.Length || text[position] != ':')
            {
                return false;
            }

            position++;
            if(!TryDecodeValue(text, ref position, out object? member))
            {
                return false;
            }

            map[name] = member;

            SkipWhitespace(text, ref position);
            if(position >= text.Length)
            {
                return false;
            }

            if(text[position] == ',')
            {
                position++;

                continue;
            }

            if(text[position] == '}')
            {
                position++;
                value = map;

                return true;
            }

            return false;
        }
    }


    private static bool TryDecodeArray(string text, ref int position, out object? value)
    {
        value = null;
        var list = new List<object?>();
        position++;
        SkipWhitespace(text, ref position);
        if(position < text.Length && text[position] == ']')
        {
            position++;
            value = list;

            return true;
        }

        while(true)
        {
            if(!TryDecodeValue(text, ref position, out object? element))
            {
                return false;
            }

            list.Add(element);

            SkipWhitespace(text, ref position);
            if(position >= text.Length)
            {
                return false;
            }

            if(text[position] == ',')
            {
                position++;

                continue;
            }

            if(text[position] == ']')
            {
                position++;
                value = list;

                return true;
            }

            return false;
        }
    }


    private static bool TryDecodeBoolean(string text, ref int position, out object? value)
    {
        value = null;
        if(text.AsSpan(position).StartsWith("true", StringComparison.Ordinal))
        {
            value = true;
            position += 4;

            return true;
        }

        if(text.AsSpan(position).StartsWith("false", StringComparison.Ordinal))
        {
            value = false;
            position += 5;

            return true;
        }

        return false;
    }


    private static bool TryDecodeNull(string text, ref int position, out object? value)
    {
        value = null;
        if(text.AsSpan(position).StartsWith("null", StringComparison.Ordinal))
        {
            position += 4;

            return true;
        }

        return false;
    }


    private static bool TryDecodeNumber(string text, ref int position, out object? value)
    {
        value = null;
        int start = position;
        while(position < text.Length && IsNumberChar(text[position]))
        {
            position++;
        }

        ReadOnlySpan<char> token = text.AsSpan(start, position - start);
        if(long.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out long integral))
        {
            value = integral;

            return true;
        }

        if(double.TryParse(token, NumberStyles.Float, CultureInfo.InvariantCulture, out double fractional))
        {
            value = fractional;

            return true;
        }

        return false;
    }


    private static bool IsNumberChar(char c) =>
        c is (>= '0' and <= '9') or '-' or '+' or '.' or 'e' or 'E';


    private static void SkipWhitespace(string text, ref int position)
    {
        while(position < text.Length && char.IsWhiteSpace(text[position]))
        {
            position++;
        }
    }


    /// <summary>
    /// Finds the index of the closing quote of the JSON string that starts at the opening quote
    /// <paramref name="start"/>, honoring backslash escapes, or <c>-1</c> when the string is
    /// unterminated before <paramref name="end"/>.
    /// </summary>
    private static int FindStringEnd(string text, int start, int end)
    {
        int i = start + 1;
        while(i < end)
        {
            char c = text[i];
            if(c == '\\')
            {
                i += 2;

                continue;
            }

            if(c == '"')
            {
                return i;
            }

            i++;
        }

        return -1;
    }
}


/// <summary>
/// The JSON kind of one value classified from its raw text by
/// <see cref="JsonScalarText.ClassifyKind"/>: the coarse type a strict RFC 9396 authorization
/// details handler matches a type-specific member against. <see cref="Malformed"/> covers text
/// that is not well-formed JSON of any single value.
/// </summary>
public enum JsonValueShape
{
    /// <summary>The text is not well-formed JSON for a single value.</summary>
    Malformed = 0,

    /// <summary>A JSON string.</summary>
    String,

    /// <summary>A JSON number.</summary>
    Number,

    /// <summary>A JSON boolean (<c>true</c> or <c>false</c>).</summary>
    Boolean,

    /// <summary>The JSON <c>null</c> literal.</summary>
    Null,

    /// <summary>A JSON array.</summary>
    Array,

    /// <summary>A JSON object.</summary>
    Object
}
