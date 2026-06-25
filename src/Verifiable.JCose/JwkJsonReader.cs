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
    /// Extracts the <paramref name="innerKey"/> string value from EVERY object element of an
    /// array-valued outer property — the plural form of
    /// <see cref="ExtractNestedStringValueFromArray"/>. Handles the OID4VCI 1.0 §8.3 batch
    /// <c>credentials</c> structure <c>{"credentials":[{"credential":"a"},{"credential":"b"}]}</c>
    /// where a batch carries more than one Credential.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes to search.</param>
    /// <param name="outerKey">The array property key as a UTF-8 literal, e.g. <c>"credentials"</c>.</param>
    /// <param name="innerKey">The inner property key as a UTF-8 literal, e.g. <c>"credential"</c>.</param>
    /// <returns>
    /// The inner string of each object element in array order; an empty list for an empty array;
    /// or <see langword="null"/> when the outer key is absent, its value is not an array, or an
    /// element is not an object. An object element lacking the inner key is skipped.
    /// </returns>
    public static List<string>? ExtractNestedStringValuesFromArray(
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

        List<string> result = [];
        int cursor = afterOuter + 1;

        while(cursor < json.Length)
        {
            while(cursor < json.Length
                && (json[cursor] == (byte)' ' || json[cursor] == (byte)'\t'
                    || json[cursor] == (byte)'\r' || json[cursor] == (byte)'\n'
                    || json[cursor] == (byte)','))
            {
                cursor++;
            }

            if(cursor >= json.Length)
            {
                return null;
            }

            if(json[cursor] == (byte)']')
            {
                return result;
            }

            if(json[cursor] != (byte)'{')
            {
                //A non-object array element is a structural mismatch for an array-of-objects.
                return null;
            }

            int objectStart = cursor;
            int depth = 1;
            int objectEnd = objectStart + 1;
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

            string? value = ExtractStringValue(json[(objectStart + 1)..(objectEnd - 1)], innerKey);
            if(value is not null)
            {
                result.Add(value);
            }

            cursor = objectEnd;
        }

        return null;
    }


    /// <summary>
    /// Extracts the first string element of an array-valued property. Handles the
    /// OID4VP 1.0 §8.1 <c>vp_token</c> structure where each credential-query-id
    /// key maps to an array of one or more compact presentation strings:
    /// <c>{"my_credential":["eyJhbGci..."]}</c>.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes to search.</param>
    /// <param name="key">The array property key as a UTF-8 literal.</param>
    /// <returns>
    /// The first string in the array, or <see langword="null"/> when the key is
    /// absent, the value is not an array, the array is empty, or the first
    /// element is not a string.
    /// </returns>
    public static string? ExtractFirstStringFromArrayProperty(
        ReadOnlySpan<byte> json,
        ReadOnlySpan<byte> key)
    {
        int keyStart = IndexOfKey(json, key);
        if(keyStart < 0)
        {
            return null;
        }

        int afterKey = keyStart + key.Length + 1;
        afterKey = SkipWhitespaceAndColon(json, afterKey);
        if(afterKey < 0 || afterKey >= json.Length || json[afterKey] != (byte)'[')
        {
            return null;
        }

        int cursor = afterKey + 1;
        while(cursor < json.Length
            && (json[cursor] == (byte)' ' || json[cursor] == (byte)'\t'
                || json[cursor] == (byte)'\r' || json[cursor] == (byte)'\n'))
        {
            cursor++;
        }

        if(cursor >= json.Length || json[cursor] != (byte)'"')
        {
            return null;
        }

        return ExtractStringAt(json, cursor + 1);
    }


    /// <summary>
    /// Extracts every string element of a JSON array property at the top level
    /// of <paramref name="json"/>. Returns <see langword="null"/> when the key
    /// is absent or its value is not an array; returns an empty list when the
    /// array is well-formed but empty. Non-string entries are a structural
    /// error and surface as <see langword="null"/>.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes to search.</param>
    /// <param name="key">The property key whose value is the array.</param>
    /// <returns>
    /// The decoded string values in array order, an empty list for an empty
    /// array, or <see langword="null"/> when the key is missing or the value
    /// is not a string-only array.
    /// </returns>
    public static List<string>? ExtractStringArrayProperty(
        ReadOnlySpan<byte> json,
        ReadOnlySpan<byte> key)
    {
        int keyStart = IndexOfKey(json, key);
        if(keyStart < 0)
        {
            return null;
        }

        int afterKey = keyStart + key.Length + 1;
        afterKey = SkipWhitespaceAndColon(json, afterKey);
        if(afterKey < 0 || afterKey >= json.Length || json[afterKey] != (byte)'[')
        {
            return null;
        }

        List<string> result = [];
        int cursor = afterKey + 1;

        while(cursor < json.Length)
        {
            while(cursor < json.Length
                && (json[cursor] == (byte)' ' || json[cursor] == (byte)'\t'
                    || json[cursor] == (byte)'\r' || json[cursor] == (byte)'\n'
                    || json[cursor] == (byte)','))
            {
                cursor++;
            }

            if(cursor >= json.Length)
            {
                return null;
            }

            if(json[cursor] == (byte)']')
            {
                return result;
            }

            if(json[cursor] != (byte)'"')
            {
                //Non-string entry: structural mismatch for a hashes array.
                return null;
            }

            int stringStart = cursor + 1;
            string? value = ExtractStringAt(json, stringStart);
            if(value is null)
            {
                return null;
            }

            result.Add(value);

            //Step past the closing quote of the string we just read.
            cursor = stringStart;
            while(cursor < json.Length && json[cursor] != (byte)'"')
            {
                if(json[cursor] == (byte)'\\' && cursor + 1 < json.Length)
                {
                    cursor++;
                }
                cursor++;
            }
            cursor++;
        }

        return null;
    }


    /// <summary>
    /// Extracts all string-valued properties from an object-valued property at the
    /// top level of <paramref name="json"/>. For example, extracts all JWK fields
    /// from <c>{"sub_jwk":{"kty":"EC","crv":"P-256","x":"...","y":"..."}}</c>.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes to search.</param>
    /// <param name="key">The object property key (e.g., <c>"sub_jwk"</c>).</param>
    /// <returns>
    /// A dictionary of string-valued properties from the object, or
    /// <see langword="null"/> if the key is absent or its value is not an object.
    /// Non-string values (arrays, objects, numbers, booleans) are skipped.
    /// </returns>
    public static Dictionary<string, object>? ExtractObjectProperties(
        ReadOnlySpan<byte> json,
        ReadOnlySpan<byte> key)
    {
        ReadOnlySpan<byte> objectSpan = FindObjectContent(json, key);
        if(objectSpan.IsEmpty)
        {
            return null;
        }

        return ExtractAllStringProperties(objectSpan);
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

        //The digit run MUST be the whole number: the next byte, if any, must close the
        //value (a JSON structural byte or whitespace). Otherwise the token is a non-integer
        //JSON number — exponent (1e10), decimal (1.5), or garbage (12abc) — and reading only
        //the leading digits would silently misparse it. A misread NumericDate (exp/iat/nbf)
        //would corrupt temporal checks, so such values are rejected rather than truncated.
        if(end < json.Length && !IsNumberTerminator(json[end]))
        {
            return false;
        }

        ReadOnlySpan<byte> digits = json[start..end];
        string text = Encoding.UTF8.GetString(digits);

        return long.TryParse(text, System.Globalization.NumberStyles.Integer,
            System.Globalization.CultureInfo.InvariantCulture, out value);
    }


    /// <summary>
    /// Extracts an object-valued JSON property and returns it as a string,
    /// including the outer braces. The returned string is a self-contained
    /// JSON object: <c>{...}</c>.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes to search.</param>
    /// <param name="key">The property key as a UTF-8 literal.</param>
    /// <returns>
    /// The full JSON text of the object value (braces included), or
    /// <see langword="null"/> if the key is absent or the value is not an
    /// object. Used to slice a sub-object out of a wallet_metadata blob —
    /// e.g. <c>jwks</c> — for further independent parsing.
    /// </returns>
    public static string? ExtractObjectAsString(
        ReadOnlySpan<byte> json,
        ReadOnlySpan<byte> key)
    {
        int keyStart = IndexOfKey(json, key);
        if(keyStart < 0)
        {
            return null;
        }

        int afterKey = keyStart + key.Length + 1;
        afterKey = SkipWhitespaceAndColon(json, afterKey);
        if(afterKey < 0 || afterKey >= json.Length || json[afterKey] != (byte)'{')
        {
            return null;
        }

        int braceStart = afterKey;
        int depth = 1;
        int pos = braceStart + 1;

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
            else if(json[pos] == (byte)'"')
            {
                //Skip string content so braces inside strings don't
                //bias the depth counter.
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

        if(depth != 0)
        {
            return null;
        }

        return Encoding.UTF8.GetString(json[braceStart..pos]);
    }


    /// <summary>
    /// Extracts an array-valued JSON property and returns it as a string, including
    /// the outer brackets. The returned string is a self-contained JSON array:
    /// <c>[...]</c>.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes to search.</param>
    /// <param name="key">The property key as a UTF-8 literal.</param>
    /// <returns>
    /// The full JSON text of the array value (brackets included), or
    /// <see langword="null"/> if the key is absent or the value is not an array.
    /// Used to slice a native-JSON array out of a JWT payload verbatim — e.g. the
    /// RFC 9396 <c>authorization_details</c> of a signed Request Object — for
    /// downstream processing that operates on the exact signed text.
    /// </returns>
    public static string? ExtractArrayAsString(
        ReadOnlySpan<byte> json,
        ReadOnlySpan<byte> key)
    {
        int keyStart = IndexOfKey(json, key);
        if(keyStart < 0)
        {
            return null;
        }

        int afterKey = keyStart + key.Length + 1;
        afterKey = SkipWhitespaceAndColon(json, afterKey);
        if(afterKey < 0 || afterKey >= json.Length || json[afterKey] != (byte)'[')
        {
            return null;
        }

        int bracketStart = afterKey;
        int depth = 1;
        int pos = bracketStart + 1;

        while(pos < json.Length && depth > 0)
        {
            if(json[pos] == (byte)'[')
            {
                depth++;
            }
            else if(json[pos] == (byte)']')
            {
                depth--;
            }
            else if(json[pos] == (byte)'"')
            {
                //Skip string content so brackets inside strings don't
                //bias the depth counter.
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

        if(depth != 0)
        {
            return null;
        }

        return Encoding.UTF8.GetString(json[bracketStart..pos]);
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
            else if(json[pos] == (byte)'"')
            {
                //Skip string content so braces inside a string value do not bias
                //the depth counter (mirrors ExtractObjectAsString). Without this a
                //value such as "a}b" truncates the object span early.
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
        int pos = 0;

        //Consume the object's own opening brace, if present, so the object's
        //members sit at relative depth 0. A full-object span (a JWT payload,
        //a JWKS) starts with '{'; an inner-content span produced by
        //FindObjectContent is already between an object's braces and starts at
        //a member key. Either way, top-level members are then at depth 0.
        while(pos < json.Length && IsJsonWhitespace(json[pos]))
        {
            pos++;
        }

        if(pos < json.Length && json[pos] == (byte)'{')
        {
            pos++;
        }

        int depth = 0;

        while(pos < json.Length)
        {
            byte b = json[pos];

            if(b == (byte)'"')
            {
                //A quoted token. It is the key we seek ONLY at the base level
                //(depth 0) and in key position (followed by a colon). A
                //same-named key nested in a deeper object sits at depth > 0 and
                //is skipped, so it cannot shadow a top-level lookup. The whole
                //string is skipped via SkipString so braces or quotes inside a
                //value never bias the depth counter.
                int nameStart = pos + 1;
                if(depth == 0
                    && nameStart + key.Length < json.Length
                    && json.Slice(nameStart, key.Length).SequenceEqual(key)
                    && json[nameStart + key.Length] == (byte)'"'
                    && IsKeyPosition(json, nameStart + key.Length + 1))
                {
                    return nameStart;
                }

                pos = SkipString(json, pos);
                continue;
            }

            if(b == (byte)'{' || b == (byte)'[')
            {
                depth++;
            }
            else if(b == (byte)'}' || b == (byte)']')
            {
                depth--;
            }

            pos++;
        }

        return -1;
    }


    /// <summary>
    /// Reports whether <paramref name="json"/> carries the same top-level key more than once.
    /// JSON permits duplicate object keys, and readers disagree on which occurrence wins —
    /// this span scanner returns the FIRST (<see cref="IndexOfKey"/>) while a typical
    /// deserializer keeps the LAST. On a SIGNED payload that reader disagreement is a
    /// validate-one / act-on-another smuggling vector (e.g. a duplicated RFC 9396
    /// <c>authorization_details</c>), so a verified payload should be rejected outright when
    /// a top-level key repeats. Only depth-0 keys are considered; a key reused inside a
    /// nested object is legitimate and not flagged.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes to scan (an object, optionally with its braces).</param>
    /// <returns><see langword="true"/> when any top-level key appears twice.</returns>
    public static bool HasDuplicateTopLevelKeys(ReadOnlySpan<byte> json)
    {
        int pos = 0;
        while(pos < json.Length && IsJsonWhitespace(json[pos]))
        {
            pos++;
        }

        if(pos < json.Length && json[pos] == (byte)'{')
        {
            pos++;
        }

        int depth = 0;
        HashSet<string> seenKeys = new(StringComparer.Ordinal);

        while(pos < json.Length)
        {
            byte b = json[pos];

            if(b == (byte)'"')
            {
                int nameStart = pos + 1;
                int afterString = SkipString(json, pos);
                if(depth == 0 && afterString >= 1 && IsKeyPosition(json, afterString))
                {
                    //afterString is one past the closing quote; the name spans
                    //[nameStart, afterString - 1).
                    string keyName = Encoding.UTF8.GetString(json[nameStart..(afterString - 1)]);
                    if(!seenKeys.Add(keyName))
                    {
                        return true;
                    }
                }

                pos = afterString;
                continue;
            }

            if(b == (byte)'{' || b == (byte)'[')
            {
                depth++;
            }
            else if(b == (byte)'}' || b == (byte)']')
            {
                depth--;
            }

            pos++;
        }

        return false;
    }


    /// <summary>
    /// Returns the names of every top-level (depth-0) member of a JSON object, in document order
    /// and including repeats. Mirrors the <see cref="HasDuplicateTopLevelKeys"/> scan but collects
    /// the names rather than detecting the first repeat; nested-object keys are not included.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes to scan (an object, optionally with its braces).</param>
    /// <returns>The top-level member names; an empty list when the span is not an object or is empty.</returns>
    public static List<string> GetTopLevelKeyNames(ReadOnlySpan<byte> json)
    {
        var names = new List<string>();

        int pos = 0;
        while(pos < json.Length && IsJsonWhitespace(json[pos]))
        {
            pos++;
        }

        if(pos < json.Length && json[pos] == (byte)'{')
        {
            pos++;
        }

        int depth = 0;

        while(pos < json.Length)
        {
            byte b = json[pos];

            if(b == (byte)'"')
            {
                int nameStart = pos + 1;
                int afterString = SkipString(json, pos);
                if(depth == 0 && afterString >= 1 && IsKeyPosition(json, afterString))
                {
                    names.Add(Encoding.UTF8.GetString(json[nameStart..(afterString - 1)]));
                }

                pos = afterString;
                continue;
            }

            if(b == (byte)'{' || b == (byte)'[')
            {
                depth++;
            }
            else if(b == (byte)'}' || b == (byte)']')
            {
                depth--;
            }

            pos++;
        }

        return names;
    }


    /// <summary>
    /// Returns the top-level member names of an object-valued property, or an empty list when the
    /// property is absent or its value is not an object.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes to search.</param>
    /// <param name="key">The property key as a UTF-8 literal.</param>
    /// <returns>The member names of the named object; empty when absent or non-object.</returns>
    public static List<string> GetObjectMemberNames(ReadOnlySpan<byte> json, ReadOnlySpan<byte> key) =>
        GetTopLevelKeyNames(FindObjectContent(json, key));


    /// <summary>Whether <paramref name="b"/> closes a JSON number — a structural byte or whitespace.</summary>
    private static bool IsNumberTerminator(byte b) =>
        b == (byte)',' || b == (byte)'}' || b == (byte)']' || IsJsonWhitespace(b);


    /// <summary>
    /// Returns the index immediately after the closing quote of the string whose
    /// opening quote is at <paramref name="openQuotePos"/>, honoring backslash
    /// escapes; or <paramref name="json"/>.Length for an unterminated string.
    /// </summary>
    private static int SkipString(ReadOnlySpan<byte> json, int openQuotePos)
    {
        int pos = openQuotePos + 1;
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


    /// <summary>Whether <paramref name="b"/> is a JSON insignificant-whitespace byte.</summary>
    private static bool IsJsonWhitespace(byte b) =>
        b == (byte)' ' || b == (byte)'\t' || b == (byte)'\r' || b == (byte)'\n';


    /// <summary>
    /// Determines whether a quoted token whose closing quote is immediately before
    /// <paramref name="pos"/> sits in key position — that is, the next non-whitespace
    /// byte is a colon. This distinguishes an object key from a string value that
    /// merely equals the key name: a value is always followed by <c>,</c>, <c>}</c>,
    /// or <c>]</c>, never <c>:</c>. Without this guard a value such as <c>"x"</c>
    /// would shadow a later property whose key is <c>"x"</c>.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes.</param>
    /// <param name="pos">Position immediately after the candidate token's closing quote.</param>
    private static bool IsKeyPosition(ReadOnlySpan<byte> json, int pos)
    {
        while(pos < json.Length
            && (json[pos] == (byte)' ' || json[pos] == (byte)'\t'
                || json[pos] == (byte)'\r' || json[pos] == (byte)'\n'))
        {
            pos++;
        }

        return pos < json.Length && json[pos] == (byte)':';
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

        ReadOnlySpan<byte> raw = json[start..end];

        //Fast path: a value carrying no backslash carries no JSON escape, so the raw
        //bytes ARE the logical string. base64url key material (x/y/d/n/e) and every
        //unescaped header value take this path unchanged. Only when an escape is present
        //is the value decoded, which is what a conformant JSON reader returns: a JOSE
        //'typ' such as openid4vci-proof+jwt serialized by System.Text.Json's default
        //encoder arrives as "openid4vci-proof+jwt", and the string equality the
        //callers perform is against the decoded '+' form.
        if(raw.IndexOf((byte)'\\') < 0)
        {
            return Encoding.UTF8.GetString(raw);
        }

        return DecodeJsonStringEscapes(Encoding.UTF8.GetString(raw));
    }


    //Decodes the JSON string escape sequences of RFC 8259 §7 in an already-UTF-8-decoded
    //value: the two-character escapes and \uXXXX (each emitted as one UTF-16 code unit, so
    //a surrogate pair's two \u escapes compose the astral code point naturally). A
    //malformed or unknown escape is preserved verbatim rather than dropped.
    private static string DecodeJsonStringEscapes(string value)
    {
        StringBuilder builder = new(value.Length);
        int index = 0;
        while(index < value.Length)
        {
            char current = value[index];
            if(current != '\\' || index + 1 >= value.Length)
            {
                builder.Append(current);
                index++;

                continue;
            }

            char escape = value[index + 1];
            char? simple = escape switch
            {
                '"' => '"',
                '\\' => '\\',
                '/' => '/',
                'b' => '\b',
                'f' => '\f',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                _ => null
            };

            if(simple is char decoded)
            {
                builder.Append(decoded);
                index += 2;

                continue;
            }

            if(escape == 'u' && TryDecodeHex4(value, index + 2, out char unicode))
            {
                builder.Append(unicode);
                index += 6;

                continue;
            }

            //Unknown or truncated escape: keep the backslash literally and continue.
            builder.Append(current);
            index++;
        }

        return builder.ToString();
    }


    private static bool TryDecodeHex4(string value, int start, out char result)
    {
        result = '\0';
        if(start + 4 > value.Length)
        {
            return false;
        }

        int code = 0;
        for(int offset = 0; offset < 4; offset++)
        {
            int nibble = HexNibble(value[start + offset]);
            if(nibble < 0)
            {
                return false;
            }

            code = (code << 4) | nibble;
        }

        result = (char)code;

        return true;
    }


    private static int HexNibble(char character) =>
        character switch
        {
            >= '0' and <= '9' => character - '0',
            >= 'a' and <= 'f' => character - 'a' + 10,
            >= 'A' and <= 'F' => character - 'A' + 10,
            _ => -1
        };
}
