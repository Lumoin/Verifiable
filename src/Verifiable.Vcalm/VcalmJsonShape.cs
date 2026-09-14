namespace Verifiable.Vcalm;

/// <summary>
/// Byte-level JSON shape operations for the credential-template evaluation path: whether a UTF-8 JSON
/// fragment is an object, and (for the §3.6.1 wrapper case) where a named top-level member's value
/// lives inside one — without parsing the fragment into a value model. <c>Verifiable.Vcalm</c> carries
/// no JSON parser (<c>System.Text.Json</c> is banned in this library — the serialization firewall);
/// the §3.6 engine only ever needs shape and member-location facts, never a materialized document.
/// </summary>
public static class VcalmJsonShape
{
    /// <summary>
    /// Whether <paramref name="json"/> is a JSON object: its first non-whitespace byte is
    /// <c>{</c> (U+007B). RFC 8259 §2 defines JSON whitespace as space, tab, line feed, and carriage
    /// return; a fragment that is entirely whitespace, empty, or begins with anything else (an array's
    /// <c>[</c>, a quoted string, a number, or a literal) is refused.
    /// </summary>
    /// <param name="json">The UTF-8 JSON fragment to inspect.</param>
    /// <returns><see langword="true"/> when the first non-whitespace byte is <c>{</c>.</returns>
    public static bool IsObject(ReadOnlySpan<byte> json)
    {
        for(int i = 0; i < json.Length; ++i)
        {
            byte current = json[i];
            if(IsJsonWhitespace(current))
            {
                continue;
            }

            return current == (byte)'{';
        }

        return false;
    }


    /// <summary>
    /// The <see cref="ReadOnlySpan{Char}"/> counterpart of <see cref="IsObject(ReadOnlySpan{byte})"/>,
    /// for a §3.6.1 variables fragment that is already a UTF-16 <see cref="string"/> on the caller's
    /// side: checking the shape of the character text directly avoids an intermediate UTF-8 byte-array
    /// allocation solely to look at the leading byte.
    /// </summary>
    /// <param name="json">The JSON fragment to inspect, as UTF-16 characters.</param>
    /// <returns><see langword="true"/> when the first non-whitespace character is <c>{</c>.</returns>
    public static bool IsObject(ReadOnlySpan<char> json)
    {
        for(int i = 0; i < json.Length; ++i)
        {
            char current = json[i];
            if(IsJsonWhitespace(current))
            {
                continue;
            }

            return current == '{';
        }

        return false;
    }


    /// <summary>
    /// Locates the value of a top-level member named <paramref name="memberName"/> inside a JSON
    /// object's UTF-8 bytes, by scanning member names and skipping values at depth 1 (tracking string
    /// escaping and bracket nesting just far enough to skip a value correctly, never materializing
    /// one). This backs the <see href="https://www.w3.org/TR/vcalm-1.0/#example-a-basic-workflow">VCALM
    /// 1.0 Example 13</see> unwrap: a rendered <c>jsonata</c> template following the POST
    /// <c>/credentials/issue</c> body shape wraps the credential under a <c>credential</c> member, and
    /// the engine must sign that inner value, not the wrapper.
    /// </summary>
    /// <param name="json">The UTF-8 JSON object to scan; the caller has already established it satisfies <see cref="IsObject(ReadOnlySpan{byte})"/>.</param>
    /// <param name="memberName">The UTF-8 bytes of the member name to locate, unescaped (the member names this seam looks for carry no characters requiring JSON escaping).</param>
    /// <param name="valueRange">The byte range of the member's value within <paramref name="json"/>, set only when the method returns <see langword="true"/>.</param>
    /// <returns><see langword="true"/> when a top-level member named <paramref name="memberName"/> is found and its value could be skipped without hitting malformed JSON.</returns>
    public static bool TryGetTopLevelMemberValue(
        ReadOnlySpan<byte> json, ReadOnlySpan<byte> memberName, out Range valueRange)
    {
        valueRange = default;

        int length = json.Length;
        int index = SkipWhitespace(json, 0);
        if(index >= length || json[index] != (byte)'{')
        {
            return false;
        }

        ++index;

        while(true)
        {
            index = SkipWhitespace(json, index);
            if(index >= length)
            {
                return false;
            }

            if(json[index] == (byte)'}')
            {
                return false;
            }

            if(json[index] != (byte)'"')
            {
                return false;
            }

            int nameStart = index;
            if(!TrySkipString(json, ref index))
            {
                return false;
            }

            ReadOnlySpan<byte> rawName = json[(nameStart + 1)..(index - 1)];

            index = SkipWhitespace(json, index);
            if(index >= length || json[index] != (byte)':')
            {
                return false;
            }

            ++index;
            index = SkipWhitespace(json, index);

            int valueStart = index;
            if(!TrySkipValue(json, ref index))
            {
                return false;
            }

            if(rawName.SequenceEqual(memberName))
            {
                valueRange = new Range(valueStart, index);

                return true;
            }

            index = SkipWhitespace(json, index);
            if(index < length && json[index] == (byte)',')
            {
                ++index;

                continue;
            }

            return false;
        }
    }


    /// <summary>
    /// Advances past one JSON string, object, array, or bare literal (number / <c>true</c> / <c>false</c>
    /// / <c>null</c>) starting at <paramref name="index"/>, tracking string escapes and bracket nesting
    /// so a value containing its own nested strings or structures is skipped as a whole rather than
    /// stopping at the first inner delimiter.
    /// </summary>
    /// <param name="json">The UTF-8 JSON bytes being scanned.</param>
    /// <param name="index">The index of the value's first byte on entry; the index just past the value on success.</param>
    /// <returns><see langword="true"/> when a complete value was skipped; <see langword="false"/> on malformed or truncated JSON.</returns>
    private static bool TrySkipValue(ReadOnlySpan<byte> json, ref int index)
    {
        int length = json.Length;
        if(index >= length)
        {
            return false;
        }

        byte first = json[index];
        if(first == (byte)'"')
        {
            return TrySkipString(json, ref index);
        }

        if(first is ((byte)'{') or ((byte)'['))
        {
            byte open = first;
            byte close = open == (byte)'{' ? (byte)'}' : (byte)']';
            int depth = 0;
            bool isInString = false;
            bool isEscaped = false;
            for(; index < length; ++index)
            {
                byte current = json[index];
                if(isInString)
                {
                    if(isEscaped)
                    {
                        isEscaped = false;
                    }
                    else if(current == (byte)'\\')
                    {
                        isEscaped = true;
                    }
                    else if(current == (byte)'"')
                    {
                        isInString = false;
                    }

                    continue;
                }

                if(current == (byte)'"')
                {
                    isInString = true;
                }
                else if(current == open)
                {
                    ++depth;
                }
                else if(current == close)
                {
                    --depth;
                    if(depth == 0)
                    {
                        ++index;

                        return true;
                    }
                }
            }

            return false;
        }

        //A number, boolean, or null literal ends at a structural delimiter or whitespace; the caller
        //never needs the literal's own text, only where it ends.
        for(; index < length; ++index)
        {
            byte current = json[index];
            if(current == (byte)',' || current == (byte)'}' || current == (byte)']' || IsJsonWhitespace(current))
            {
                return true;
            }
        }

        return true;
    }


    /// <summary>
    /// Advances past one JSON string starting at <paramref name="index"/> (which must address the
    /// opening <c>"</c>), honouring backslash escapes so an escaped quote does not end the string
    /// early.
    /// </summary>
    /// <param name="json">The UTF-8 JSON bytes being scanned.</param>
    /// <param name="index">The index of the opening <c>"</c> on entry; the index just past the closing <c>"</c> on success.</param>
    /// <returns><see langword="true"/> when a complete, properly terminated string was skipped.</returns>
    private static bool TrySkipString(ReadOnlySpan<byte> json, ref int index)
    {
        int length = json.Length;
        if(index >= length || json[index] != (byte)'"')
        {
            return false;
        }

        ++index;
        while(index < length)
        {
            byte current = json[index];
            if(current == (byte)'\\')
            {
                index += 2;

                continue;
            }

            if(current == (byte)'"')
            {
                ++index;

                return true;
            }

            ++index;
        }

        return false;
    }


    /// <summary>
    /// Advances <paramref name="index"/> past a run of RFC 8259 §2 JSON whitespace (space, tab, line
    /// feed, carriage return) and returns the resulting index.
    /// </summary>
    /// <param name="json">The UTF-8 JSON bytes being scanned.</param>
    /// <param name="index">The index to start skipping from.</param>
    /// <returns>The index of the first non-whitespace byte at or after <paramref name="index"/>, or <see cref="ReadOnlySpan{T}.Length"/> when none remains.</returns>
    private static int SkipWhitespace(ReadOnlySpan<byte> json, int index)
    {
        while(index < json.Length && IsJsonWhitespace(json[index]))
        {
            ++index;
        }

        return index;
    }


    /// <summary>RFC 8259 §2 JSON whitespace: space, tab, line feed, and carriage return.</summary>
    /// <param name="value">The byte to classify.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is one of the four JSON whitespace bytes.</returns>
    private static bool IsJsonWhitespace(byte value) =>
        value is (byte)' ' or (byte)'\t' or (byte)'\n' or (byte)'\r';


    /// <summary>The <see cref="char"/> counterpart of <see cref="IsJsonWhitespace(byte)"/>, for the <see cref="ReadOnlySpan{Char}"/> overload of <see cref="IsObject(ReadOnlySpan{char})"/>.</summary>
    /// <param name="value">The character to classify.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is one of the four JSON whitespace characters.</returns>
    private static bool IsJsonWhitespace(char value) =>
        value is ' ' or '\t' or '\n' or '\r';
}
