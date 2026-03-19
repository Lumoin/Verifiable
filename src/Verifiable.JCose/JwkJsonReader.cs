using System.Text;

namespace Verifiable.JCose;

/// <summary>
/// Span-based, zero-allocation JSON reader for extracting string field values from
/// JWK and JWE header JSON representations.
/// </summary>
/// <remarks>
/// <para>
/// Operates directly on UTF-8 byte spans without allocating or depending on a JSON
/// serialisation library. Suitable for use in <c>Verifiable.Cryptography</c> types
/// that must remain serialisation-library-free.
/// </para>
/// <para>
/// The scanner handles only the subset of JSON required for JWK and JOSE headers:
/// string-valued properties and one level of object nesting (for the <c>epk</c>
/// parameter). Array values, numbers, and booleans are not parsed but are skipped
/// correctly during key search.
/// </para>
/// </remarks>
public static class JwkJsonReader
{
    /// <summary>
    /// Extracts the string value of a top-level JSON property by key.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes to search.</param>
    /// <param name="key">The property key as a UTF-8 literal.</param>
    /// <returns>The string value, or <see langword="null"/> if the key is absent or malformed.</returns>
    public static string? ExtractStringValue(ReadOnlySpan<byte> json, ReadOnlySpan<byte> key)
    {
        int keyStart = IndexOfKey(json, key);
        if(keyStart < 0)
        {
            return null;
        }

        int afterKey = keyStart + key.Length + 1;
        afterKey = SkipWhitespaceAndColon(json, afterKey);
        if(afterKey < 0 || afterKey >= json.Length || json[afterKey] != (byte)'"')
        {
            return null;
        }

        return ExtractStringAt(json, afterKey + 1);
    }


    /// <summary>
    /// Extracts the string value of a property nested one level inside a named object.
    /// For example, extracts <c>x</c> from inside the <c>epk</c> object.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes to search.</param>
    /// <param name="outerKey">The outer object property key as a UTF-8 literal.</param>
    /// <param name="innerKey">The inner property key as a UTF-8 literal.</param>
    /// <returns>The string value, or <see langword="null"/> if either key is absent or malformed.</returns>
    public static string? ExtractNestedStringValue(
        ReadOnlySpan<byte> json,
        ReadOnlySpan<byte> outerKey,
        ReadOnlySpan<byte> innerKey)
    {
        int outerStart = IndexOfKey(json, outerKey);
        if(outerStart < 0)
        {
            return null;
        }

        int afterOuter = outerStart + outerKey.Length + 1;
        afterOuter = SkipWhitespaceAndColon(json, afterOuter);
        if(afterOuter < 0 || afterOuter >= json.Length || json[afterOuter] != (byte)'{')
        {
            return null;
        }

        int nestedStart = afterOuter + 1;
        int depth = 1;
        int nestedEnd = nestedStart;

        while(nestedEnd < json.Length && depth > 0)
        {
            if(json[nestedEnd] == (byte)'{')
            {
                depth++;
            }
            else if(json[nestedEnd] == (byte)'}')
            {
                depth--;
            }

            nestedEnd++;
        }

        if(depth != 0)
        {
            return null;
        }

        return ExtractStringValue(json[nestedStart..(nestedEnd - 1)], innerKey);
    }


    /// <summary>
    /// Extracts the string value of a property nested inside the first object element
    /// of an array-valued outer property. Handles the RFC 7517 JWKS structure where
    /// <c>"keys"</c> contains an array of JWK objects: <c>{"keys":[{"crv":"..."}]}</c>.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes to search.</param>
    /// <param name="outerKey">The array property key as a UTF-8 literal, e.g. <c>"keys"</c>.</param>
    /// <param name="innerKey">The inner property key as a UTF-8 literal.</param>
    /// <returns>The string value, or <see langword="null"/> if either key is absent or malformed.</returns>
    public static string? ExtractNestedStringValueFromArray(
        ReadOnlySpan<byte> json,
        ReadOnlySpan<byte> outerKey,
        ReadOnlySpan<byte> innerKey)
    {
        int outerStart = IndexOfKey(json, outerKey);
        if(outerStart < 0)
        {
            return null;
        }

        int afterOuter = outerStart + outerKey.Length + 1;
        afterOuter = SkipWhitespaceAndColon(json, afterOuter);
        if(afterOuter < 0 || afterOuter >= json.Length || json[afterOuter] != (byte)'[')
        {
            return null;
        }

        //Advance past '[' to find the first '{'.
        int firstObject = afterOuter + 1;
        while(firstObject < json.Length
            && (json[firstObject] == (byte)' ' || json[firstObject] == (byte)'\t'
                || json[firstObject] == (byte)'\r' || json[firstObject] == (byte)'\n'))
        {
            firstObject++;
        }

        if(firstObject >= json.Length || json[firstObject] != (byte)'{')
        {
            return null;
        }

        //Find the extent of the first object element.
        int depth = 1;
        int objectEnd = firstObject + 1;
        while(objectEnd < json.Length && depth > 0)
        {
            if(json[objectEnd] == (byte)'{') { depth++; }
            else if(json[objectEnd] == (byte)'}') { depth--; }
            objectEnd++;
        }

        if(depth != 0)
        {
            return null;
        }

        return ExtractStringValue(json[(firstObject + 1)..(objectEnd - 1)], innerKey);
    }


    /// <summary>
    /// Extracts all string-valued properties from an object nested two levels deep.
    /// For example, extracts all JWK fields from <c>{"cnf":{"jwk":{"kty":"OKP","crv":"Ed25519","x":"..."}}}</c>.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes to search.</param>
    /// <param name="outerKey">The outer object property key (e.g., <c>"cnf"</c>).</param>
    /// <param name="innerKey">The inner object property key (e.g., <c>"jwk"</c>).</param>
    /// <returns>
    /// A dictionary of string-valued properties from the inner object,
    /// or <see langword="null"/> if either key is absent or malformed.
    /// Non-string values (arrays, objects, numbers, booleans) are skipped.
    /// </returns>
    public static Dictionary<string, object>? ExtractNestedObjectProperties(
        ReadOnlySpan<byte> json,
        ReadOnlySpan<byte> outerKey,
        ReadOnlySpan<byte> innerKey)
    {
        //Find the outer object and slice to its content.
        ReadOnlySpan<byte> outerSpan = FindObjectContent(json, outerKey);
        if(outerSpan.IsEmpty)
        {
            return null;
        }

        //Find the inner object within the outer span and slice to its content.
        ReadOnlySpan<byte> innerSpan = FindObjectContent(outerSpan, innerKey);
        if(innerSpan.IsEmpty)
        {
            return null;
        }

        //Extract all string properties from the inner object.
        return ExtractAllStringProperties(innerSpan);
    }


    /// <summary>
    /// Extracts a <see cref="long"/> value from a top-level JSON property by key.
    /// Used for numeric JWT claims such as <c>iat</c>, <c>exp</c>, and <c>nbf</c>.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes to search.</param>
    /// <param name="key">The property key as a UTF-8 literal.</param>
    /// <param name="value">The parsed value if found.</param>
    /// <returns><see langword="true"/> if the key was found and the value parsed; otherwise, <see langword="false"/>.</returns>
    public static bool TryExtractLongValue(ReadOnlySpan<byte> json, ReadOnlySpan<byte> key, out long value)
    {
        value = 0;

        int keyStart = IndexOfKey(json, key);
        if(keyStart < 0)
        {
            return false;
        }

        int afterKey = keyStart + key.Length + 1;
        afterKey = SkipWhitespaceAndColon(json, afterKey);
        if(afterKey < 0 || afterKey >= json.Length)
        {
            return false;
        }

        //Read digits and optional leading minus sign.
        int start = afterKey;
        int end = start;

        if(end < json.Length && json[end] == (byte)'-')
        {
            end++;
        }

        while(end < json.Length && json[end] >= (byte)'0' && json[end] <= (byte)'9')
        {
            end++;
        }

        if(end == start)
        {
            return false;
        }

        ReadOnlySpan<byte> digits = json[start..end];
        string text = Encoding.UTF8.GetString(digits);
        return long.TryParse(text, System.Globalization.NumberStyles.Integer,
            System.Globalization.CultureInfo.InvariantCulture, out value);
    }


    /// <summary>
    /// Finds the content span of an object-valued property (between the outermost
    /// <c>{</c> and <c>}</c> after the key's colon).
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes to search.</param>
    /// <param name="key">The property key as a UTF-8 literal.</param>
    /// <returns>
    /// The span between the braces (exclusive), or an empty span if the key
    /// is absent or the value is not an object.
    /// </returns>
    private static ReadOnlySpan<byte> FindObjectContent(ReadOnlySpan<byte> json, ReadOnlySpan<byte> key)
    {
        int keyStart = IndexOfKey(json, key);
        if(keyStart < 0)
        {
            return ReadOnlySpan<byte>.Empty;
        }

        int afterKey = keyStart + key.Length + 1;
        afterKey = SkipWhitespaceAndColon(json, afterKey);
        if(afterKey < 0 || afterKey >= json.Length || json[afterKey] != (byte)'{')
        {
            return ReadOnlySpan<byte>.Empty;
        }

        int contentStart = afterKey + 1;
        int depth = 1;
        int pos = contentStart;

        while(pos < json.Length && depth > 0)
        {
            if(json[pos] == (byte)'{')
            {
                depth++;
            }
            else if(json[pos] == (byte)'}')
            {
                depth--;
            }

            pos++;
        }

        if(depth != 0)
        {
            return ReadOnlySpan<byte>.Empty;
        }

        return json[contentStart..(pos - 1)];
    }


    /// <summary>
    /// Scans a JSON object's content span and extracts all string-valued properties.
    /// Non-string values (arrays, nested objects, numbers, booleans, nulls) are skipped.
    /// </summary>
    /// <param name="objectContent">
    /// The UTF-8 bytes between the <c>{</c> and <c>}</c> of a JSON object.
    /// </param>
    /// <returns>A dictionary of all string-valued properties.</returns>
    private static Dictionary<string, object> ExtractAllStringProperties(ReadOnlySpan<byte> objectContent)
    {
        var result = new Dictionary<string, object>();
        int pos = 0;

        while(pos < objectContent.Length)
        {
            //Find the next opening quote (start of a key).
            int quotePos = objectContent[pos..].IndexOf((byte)'"');
            if(quotePos < 0)
            {
                break;
            }

            int keyStart = pos + quotePos + 1;

            //Find the closing quote of the key.
            int keyEnd = keyStart;
            while(keyEnd < objectContent.Length && objectContent[keyEnd] != (byte)'"')
            {
                if(objectContent[keyEnd] == (byte)'\\')
                {
                    keyEnd++;
                }

                keyEnd++;
            }

            if(keyEnd >= objectContent.Length)
            {
                break;
            }

            string keyName = Encoding.UTF8.GetString(objectContent[keyStart..keyEnd]);

            //Skip past the closing quote and colon to the value.
            int afterColon = SkipWhitespaceAndColon(objectContent, keyEnd + 1);
            if(afterColon < 0 || afterColon >= objectContent.Length)
            {
                break;
            }

            //Only extract string values; skip everything else.
            if(objectContent[afterColon] == (byte)'"')
            {
                string? value = ExtractStringAt(objectContent, afterColon + 1);
                if(value is not null)
                {
                    result[keyName] = value;
                }

                //Advance past the closing quote of the value.
                pos = afterColon + 1;
                while(pos < objectContent.Length && objectContent[pos] != (byte)'"')
                {
                    if(objectContent[pos] == (byte)'\\')
                    {
                        pos++;
                    }

                    pos++;
                }

                pos++;
            }
            else
            {
                //Skip non-string values (objects, arrays, numbers, booleans, null).
                pos = SkipValue(objectContent, afterColon);
            }
        }

        return result;
    }


    /// <summary>
    /// Advances past a JSON value starting at <paramref name="pos"/>.
    /// Handles strings, objects, arrays, numbers, booleans, and null.
    /// </summary>
    private static int SkipValue(ReadOnlySpan<byte> json, int pos)
    {
        if(pos >= json.Length)
        {
            return json.Length;
        }

        byte c = json[pos];

        //Object or array: track depth.
        if(c == (byte)'{' || c == (byte)'[')
        {
            byte open = c;
            byte close = c == (byte)'{' ? (byte)'}' : (byte)']';
            int depth = 1;
            pos++;

            while(pos < json.Length && depth > 0)
            {
                if(json[pos] == open)
                {
                    depth++;
                }
                else if(json[pos] == close)
                {
                    depth--;
                }
                else if(json[pos] == (byte)'"')
                {
                    //Skip past strings inside nested structures.
                    pos++;
                    while(pos < json.Length && json[pos] != (byte)'"')
                    {
                        if(json[pos] == (byte)'\\')
                        {
                            pos++;
                        }

                        pos++;
                    }
                }

                pos++;
            }

            return pos;
        }

        //String: find closing quote.
        if(c == (byte)'"')
        {
            pos++;
            while(pos < json.Length && json[pos] != (byte)'"')
            {
                if(json[pos] == (byte)'\\')
                {
                    pos++;
                }

                pos++;
            }

            return pos + 1;
        }

        //Number, boolean, null: advance to next structural character.
        while(pos < json.Length
            && json[pos] != (byte)',' && json[pos] != (byte)'}'
            && json[pos] != (byte)']' && json[pos] != (byte)' '
            && json[pos] != (byte)'\t' && json[pos] != (byte)'\r'
            && json[pos] != (byte)'\n')
        {
            pos++;
        }

        return pos;
    }


    /// <param name="json">UTF-8 JSON bytes to search.</param>
    /// <param name="key">The property key as a UTF-8 literal.</param>
    public static bool ContainsKey(ReadOnlySpan<byte> json, ReadOnlySpan<byte> key) =>
        IndexOfKey(json, key) >= 0;


    /// <summary>
    /// Returns the byte offset of the first character of the key name (after the opening quote)
    /// for the given property key, or -1 if not found.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes to search.</param>
    /// <param name="key">The property key as a UTF-8 literal.</param>
    public static int IndexOfKey(ReadOnlySpan<byte> json, ReadOnlySpan<byte> key)
    {
        int searchFrom = 0;

        while(searchFrom < json.Length)
        {
            int quotePos = json[searchFrom..].IndexOf((byte)'"');
            if(quotePos < 0)
            {
                return -1;
            }

            int absPos = searchFrom + quotePos + 1;

            if(absPos + key.Length < json.Length
                && json.Slice(absPos, key.Length).SequenceEqual(key)
                && json[absPos + key.Length] == (byte)'"')
            {
                return absPos;
            }

            searchFrom = absPos + 1;
        }

        return -1;
    }


    /// <summary>
    /// Advances past optional whitespace then a colon separator, then past optional
    /// whitespace again. Returns the position of the value start, or -1 if no colon
    /// is found.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes.</param>
    /// <param name="pos">Starting position immediately after the closing quote of a key.</param>
    public static int SkipWhitespaceAndColon(ReadOnlySpan<byte> json, int pos)
    {
        while(pos < json.Length
            && (json[pos] == (byte)' ' || json[pos] == (byte)'\t'
                || json[pos] == (byte)'\r' || json[pos] == (byte)'\n'))
        {
            pos++;
        }

        if(pos >= json.Length || json[pos] != (byte)':')
        {
            return -1;
        }

        pos++;

        while(pos < json.Length
            && (json[pos] == (byte)' ' || json[pos] == (byte)'\t'
                || json[pos] == (byte)'\r' || json[pos] == (byte)'\n'))
        {
            pos++;
        }

        return pos;
    }


    /// <summary>
    /// Reads the UTF-8 string value starting at <paramref name="start"/>, up to the
    /// next unescaped closing double-quote. Returns <see langword="null"/> if the
    /// closing quote is not found.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes.</param>
    /// <param name="start">Position of the first character inside the string (after the opening quote).</param>
    public static string? ExtractStringAt(ReadOnlySpan<byte> json, int start)
    {
        int end = start;

        while(end < json.Length && json[end] != (byte)'"')
        {
            if(json[end] == (byte)'\\')
            {
                end++;
            }

            end++;
        }

        if(end >= json.Length)
        {
            return null;
        }

        return Encoding.UTF8.GetString(json[start..end]);
    }
}
