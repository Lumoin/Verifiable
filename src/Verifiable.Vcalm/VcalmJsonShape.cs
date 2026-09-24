namespace Verifiable.Vcalm;

/// <summary>
/// Byte-level JSON shape checks for the credential-template evaluation path: whether a JSON fragment is an object,
/// decided from its first non-whitespace character without parsing the fragment into a value model.
/// <c>Verifiable.Vcalm</c> carries no JSON parser (<c>System.Text.Json</c> is banned in this library, the serialization
/// firewall); a fact about a member of an object, such as whether it carries one of a given name, is read through the
/// JSON leaf's <see cref="FindVcalmJsonMemberDelegate"/>, which decodes member names as a parser does.
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
