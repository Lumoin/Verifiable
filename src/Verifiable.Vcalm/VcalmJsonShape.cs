using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Verifiable.Vcalm;

/// <summary>
/// Byte-level JSON shape checks for the credential-template evaluation path: whether a JSON fragment is an object,
/// decided from its first non-whitespace character without parsing the fragment into a value model; for the
/// §3.3.3 <c>POST /challenges</c> body check: whether a body is exactly the empty JSON object, the one body besides
/// none that endpoint accepts; and the strict UTF-8 decode every endpoint's request-boundary check reads a body
/// through before any JSON parsing.
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
    /// Whether <paramref name="json"/> is exactly the empty JSON object: optional RFC 8259 §2 whitespace, <c>{</c>
    /// (U+007B), optional whitespace, <c>}</c> (U+007D), optional whitespace, and nothing else.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#create-challenge">VCALM §3.3.3</see>: "POST /challenges - Passing
    /// an empty body to this endpoint creates and returns a challenge string in the response body."; the empty object
    /// is the empty body an API whose entity bodies
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#content-serialization">§2.4 Content Serialization</see> says "MUST
    /// be serialized as JSON" can carry; any other bytes (a member, an array, a scalar, text that is not JSON) are
    /// refused. The bytes are scanned once, with no parser and no allocation.
    /// </summary>
    /// <param name="json">The UTF-8 bytes to inspect.</param>
    /// <returns><see langword="true"/> when the bytes are the empty JSON object, surrounding whitespace allowed.</returns>
    public static bool IsEmptyObject(ReadOnlySpan<byte> json)
    {
        ReadOnlySpan<byte> remaining = SkipJsonWhitespace(json);
        if(remaining.IsEmpty || remaining[0] != (byte)'{')
        {
            return false;
        }

        remaining = SkipJsonWhitespace(remaining[1..]);
        if(remaining.IsEmpty || remaining[0] != (byte)'}')
        {
            return false;
        }

        return SkipJsonWhitespace(remaining[1..]).IsEmpty;
    }


    /// <summary>
    /// The part of <paramref name="json"/> that follows its leading RFC 8259 §2 whitespace, the step
    /// <see cref="IsEmptyObject(ReadOnlySpan{byte})"/> takes before and after each of its two structural characters.
    /// </summary>
    /// <param name="json">The UTF-8 bytes to trim.</param>
    /// <returns>The bytes from the first non-whitespace byte on; empty when every byte is whitespace.</returns>
    private static ReadOnlySpan<byte> SkipJsonWhitespace(ReadOnlySpan<byte> json)
    {
        int start = 0;
        while(start < json.Length && IsJsonWhitespace(json[start]))
        {
            ++start;
        }

        return json[start..];
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
    /// Strictly decodes <paramref name="bytes"/> as UTF-8, refusing a byte sequence that is not valid UTF-8 instead of
    /// silently substituting the Unicode replacement character U+FFFD, the default lenient behaviour of
    /// <see cref="Encoding.UTF8"/>. <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.1">RFC 8259 §8.1</see>
    /// requires JSON text exchanged between systems to be "encoded using UTF-8", so this API's §2.4
    /// <c>application/json</c> bodies carry no bytes a strict decoder rejects; a body that does is data this holder
    /// cannot process, refused at the boundary rather than parsed as if the client had sent the replacement
    /// character in place of its damaged bytes.
    /// </summary>
    /// <param name="bytes">The request body's raw UTF-8 bytes.</param>
    /// <param name="text">The decoded text when every byte is valid UTF-8; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when <paramref name="bytes"/> decodes as valid UTF-8; otherwise <see langword="false"/>.</returns>
    public static bool TryDecodeStrictUtf8(ReadOnlySpan<byte> bytes, [NotNullWhen(true)] out string? text)
    {
        try
        {
            text = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetString(bytes);

            return true;
        }
        catch(DecoderFallbackException)
        {
            text = null;

            return false;
        }
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
