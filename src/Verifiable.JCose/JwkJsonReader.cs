using System.Buffers;
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
/// <para>
/// <see cref="IndexOfKey"/> and every extraction method built on it (
/// <see cref="ExtractStringValue"/> and its siblings) are FIRST-MATCH scans: on a
/// member name repeated in the same object they return the first occurrence, while a
/// typical deserializer keeps the last. That disagreement is a validate-one/act-on-another
/// vector on a document a caller did not author (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 §4</see>).
/// A caller reading a document that arrived from outside the process and whose content
/// drives an authentication or key-selection decision therefore runs
/// <see cref="IsWellFormedJsonDocument"/> once over the whole document before calling any
/// extraction method here, and refuses the document when it returns
/// <see langword="false"/>; every method below assumes that has already happened and does
/// no well-formedness or uniqueness checking of its own.
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
    /// Extracts a JSON Boolean value (<c>true</c>/<c>false</c>) from a top-level property by key. Used for the
    /// RFC 7797 <c>b64</c> JWS header parameter.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes to search.</param>
    /// <param name="key">The property key as a UTF-8 literal.</param>
    /// <param name="value">The parsed Boolean if found.</param>
    /// <returns><see langword="true"/> if the key was found and its value is a JSON Boolean; otherwise <see langword="false"/>.</returns>
    public static bool TryExtractBooleanValue(ReadOnlySpan<byte> json, ReadOnlySpan<byte> key, out bool value)
    {
        value = false;

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

        //The value must be exactly the literal true or false, closed by a JSON structural byte or whitespace —
        //so a token such as "truething" is not misread as true.
        ReadOnlySpan<byte> remaining = json[afterKey..];
        if(remaining.StartsWith("true"u8) && IsValueClosed(json, afterKey + 4))
        {
            value = true;

            return true;
        }

        if(remaining.StartsWith("false"u8) && IsValueClosed(json, afterKey + 5))
        {
            value = false;

            return true;
        }

        return false;
    }


    /// <summary>Whether the byte at <paramref name="index"/> closes a JSON value: end of input, or a
    /// structural/whitespace terminator.</summary>
    /// <param name="json">UTF-8 JSON bytes.</param>
    /// <param name="index">The position to test.</param>
    /// <returns><see langword="true"/> when the position is past the end or at a terminator byte.</returns>
    private static bool IsValueClosed(ReadOnlySpan<byte> json, int index)
    {
        return index >= json.Length || IsNumberTerminator(json[index]);
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
    /// Extracts the content span of an object-valued property — the bytes between its outermost
    /// <c>{</c> and <c>}</c> — without allocating a string. The public, span-returning sibling of
    /// <see cref="ExtractObjectAsString(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/> for a caller that
    /// wants to keep reading key-by-key off the nested object (via <see cref="ExtractStringValue"/>,
    /// <see cref="TryExtractLongValue"/>, or a further nested <see cref="ExtractObjectContent"/> call)
    /// rather than re-parsing a re-encoded string.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes to search.</param>
    /// <param name="key">The property key as a UTF-8 literal.</param>
    /// <returns>
    /// The span between the braces (exclusive), or an empty span if the key
    /// is absent or the value is not an object.
    /// </returns>
    public static ReadOnlySpan<byte> ExtractObjectContent(ReadOnlySpan<byte> json, ReadOnlySpan<byte> key) =>
        FindObjectContent(json, key);


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
        if(c is ((byte)'{') or ((byte)'['))
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
    /// for the given property key, or -1 if not found. A FIRST-MATCH scan: see the class remarks
    /// for why a caller reading an externally supplied document validates it with
    /// <see cref="IsWellFormedJsonDocument"/> first.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes to search, already validated by the caller when it did not author them.</param>
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

            if(b is ((byte)'{') or ((byte)'['))
            {
                depth++;
            }
            else if(b is ((byte)'}') or ((byte)']'))
            {
                depth--;
            }

            pos++;
        }

        return -1;
    }


    /// <summary>
    /// Returns the names of every top-level (depth-0) member of a JSON object, in document order
    /// and including repeats; nested-object keys are not included. A caller checking for a
    /// duplicate member name uses <see cref="IsWellFormedJsonDocument"/> instead, which refuses a
    /// repeat at any nesting depth rather than the top level alone.
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

            if(b is ((byte)'{') or ((byte)'['))
            {
                depth++;
            }
            else if(b is ((byte)'}') or ((byte)']'))
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


    /// <summary>
    /// The greatest container nesting <see cref="IsWellFormedJsonDocument"/> admits before it refuses
    /// a document outright. No JWK set, JOSE header, client identifier metadata document, or federation
    /// entity statement this reader parses nests past roughly ten containers (a JWKS's <c>keys</c> array
    /// of key objects is two; a nested <c>cnf.jwk</c> or <c>epk</c> object adds one or two more); thirty-two
    /// leaves headroom for a legitimately deep document while still bounding the fixed-size frame stack
    /// this validator allocates against an attacker-supplied, arbitrarily deep one.
    /// </summary>
    public static int MaximumNestingDepth { get; } = 32;


    /// <summary>
    /// The greatest number of member names <see cref="IsWellFormedJsonDocument"/> keeps live at once, summed
    /// across every object currently open — a name is discarded the instant its own object closes (see
    /// <see cref="RemoveNamesAtDepth"/>), so sibling objects that open and close in turn never accumulate.
    /// A JWK set, a JOSE header, a client identifier metadata document, and a federation entity statement
    /// each carry at most tens of members per object, so five hundred twelve leaves generous headroom while
    /// still bounding the fixed-size buffer this validator allocates against an attacker-supplied document
    /// built from one very large flat object.
    /// </summary>
    public static int MaximumLiveMemberNames { get; } = 512;


    /// <summary>
    /// The greatest length in bytes <see cref="IsWellFormedJsonDocument"/> accepts before refusing the
    /// document outright, without scanning any of it. A JWK set carrying certificate chains
    /// (<c>x5c</c>) stays far below one mebibyte, so this bound caps the validator's total work against an
    /// attacker-supplied, arbitrarily long document.
    /// </summary>
    public static int MaximumDocumentLength { get; } = 1_048_576;


    /// <summary>
    /// Determines whether <paramref name="json"/> is exactly one well-formed JSON value per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-2">RFC 8259 §2</see>, with no object at
    /// any nesting depth repeating a member name (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">
    /// RFC 8259 §4</see>: "the behavior of software that receives such an object is unpredictable"). A caller
    /// runs this once over a document that arrived from outside the process and whose content drives an
    /// authentication or key-selection decision — a registered or fetched JWK set, a client identifier
    /// metadata document, a federation entity statement, or a JOSE header decoded from a compact token —
    /// before calling any extraction method on it, so that this reader's first-match scans (see the class
    /// remarks) only ever run over text already known to parse exactly one way.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes to validate.</param>
    /// <returns>
    /// <see langword="true"/> when the whole span is exactly one JSON value with only insignificant
    /// whitespace before and after it, every string escape (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-7">
    /// RFC 8259 §7</see>) and number (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-6">RFC 8259 §6</see>)
    /// is grammatically valid, no object at any depth repeats a decoded member name, the nesting depth never
    /// exceeds <see cref="MaximumNestingDepth"/>, no object ever has more than <see cref="MaximumLiveMemberNames"/>
    /// member names live at once, and the document is no longer than <see cref="MaximumDocumentLength"/> bytes.
    /// <see langword="false"/> for every other input, including empty input, a document ending inside a token,
    /// or a lone surrogate escape (accepted by the grammar, so not a reason to refuse). Exceeding any of the
    /// three bounds is reported as a refusal, never an exception. This method never throws.
    /// </returns>
    public static bool IsWellFormedJsonDocument(ReadOnlySpan<byte> json)
    {
        if(json.Length > MaximumDocumentLength)
        {
            return false;
        }

        int pos = 0;
        SkipWhitespace(json, ref pos);
        if(pos >= json.Length)
        {
            return false;
        }

        Span<NestingFrame> frames = stackalloc NestingFrame[MaximumNestingDepth];
        int top = -1;
        int depth = 0;
        Span<SeenName> seenNames = stackalloc SeenName[MaximumLiveMemberNames];
        int seenNameCount = 0;

        if(!ValidateFrames(json, ref pos, frames, ref top, ref depth, seenNames, ref seenNameCount, bareRootObject: false))
        {
            return false;
        }

        SkipWhitespace(json, ref pos);

        return pos == json.Length;
    }


    /// <summary>
    /// Determines whether <paramref name="objectContent"/> is exactly the well-formed member list of
    /// one JSON object — the bytes <see cref="ExtractObjectContent"/> returns, between an object's
    /// outermost <c>{</c> and <c>}</c> but without them — with no member name repeated at any nesting
    /// depth (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 §4</see>: "the
    /// behavior of software that receives such an object is unpredictable"). A caller that already
    /// holds an object's content span, rather than a self-contained document, runs this instead of
    /// copying the span between synthetic braces before calling <see cref="IsWellFormedJsonDocument"/>.
    /// Shares that method's iterative frame-stack core (<see cref="ValidateFrames"/>), started already
    /// inside an object frame instead of at an empty root.
    /// </summary>
    /// <param name="objectContent">
    /// UTF-8 bytes of one object's members, without the enclosing braces. Empty or whitespace-only
    /// content is the empty object and is accepted.
    /// </param>
    /// <returns>
    /// <see langword="true"/> when the content is a sequence of well-formed, comma-separated
    /// <c>"name":value</c> members with no leading or trailing comma, no member name repeated at any
    /// depth, every nested string escape (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-7">
    /// RFC 8259 §7</see>) and number (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-6">
    /// RFC 8259 §6</see>) grammatically valid, the nesting depth never exceeds
    /// <see cref="MaximumNestingDepth"/>, no object ever has more than <see cref="MaximumLiveMemberNames"/>
    /// member names live at once, and the content is no longer than <see cref="MaximumDocumentLength"/>
    /// bytes. <see langword="false"/> for every other input, including a stray closing brace, truncation
    /// inside a member, or content ending mid-value. This method never throws.
    /// </returns>
    public static bool IsWellFormedJsonObjectContent(ReadOnlySpan<byte> objectContent)
    {
        if(objectContent.Length > MaximumDocumentLength)
        {
            return false;
        }

        Span<NestingFrame> frames = stackalloc NestingFrame[MaximumNestingDepth];
        frames[0] = new NestingFrame { IsObject = true, Phase = (byte)ObjectPhase.ExpectKeyOrClose };
        int top = 0;
        int depth = 1;
        Span<SeenName> seenNames = stackalloc SeenName[MaximumLiveMemberNames];
        int seenNameCount = 0;
        int pos = 0;

        if(!ValidateFrames(objectContent, ref pos, frames, ref top, ref depth, seenNames, ref seenNameCount, bareRootObject: true))
        {
            return false;
        }

        SkipWhitespace(objectContent, ref pos);

        return pos == objectContent.Length;
    }


    /// <summary>
    /// Runs the object/array grammar-and-uniqueness state machine shared by
    /// <see cref="IsWellFormedJsonDocument"/> and <see cref="IsWellFormedJsonObjectContent"/>, starting
    /// from whichever frame the caller has already set up on <paramref name="frames"/>.
    /// <see cref="IsWellFormedJsonDocument"/> starts with an empty stack (<paramref name="top"/> of -1)
    /// and reads one root value through <see cref="TryConsumeValue"/> before this loop ever runs.
    /// <see cref="IsWellFormedJsonObjectContent"/> instead starts already inside an object frame at
    /// <paramref name="top"/> 0, because its input carries no enclosing braces of its own; for that one
    /// frame, <paramref name="bareRootObject"/> makes end of input the valid closer in place of a
    /// literal <c>}</c>, and turns a literal <c>}</c> there into a grammar violation, since none was
    /// ever opened.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes being validated.</param>
    /// <param name="pos">The read position, advanced as bytes are consumed.</param>
    /// <param name="frames">The open-container frame stack.</param>
    /// <param name="top">The index of the current top frame, or -1 once every frame has closed.</param>
    /// <param name="depth">The current nesting depth.</param>
    /// <param name="seenNames">The live member-name buffer shared across every open object.</param>
    /// <param name="seenNameCount">The number of live entries in <paramref name="seenNames"/>.</param>
    /// <param name="bareRootObject">
    /// Whether the frame at index 0 is a virtual object with no bytes of its own for <c>{</c> or
    /// <c>}</c>, so that frame closes on end of input rather than on a literal <c>}</c>.
    /// </param>
    /// <returns><see langword="true"/> when every frame closed without a grammar or uniqueness violation.</returns>
    private static bool ValidateFrames(
        ReadOnlySpan<byte> json,
        ref int pos,
        Span<NestingFrame> frames,
        ref int top,
        ref int depth,
        Span<SeenName> seenNames,
        ref int seenNameCount,
        bool bareRootObject)
    {
        bool rootParsed = false;

        while(true)
        {
            if(top < 0)
            {
                if(rootParsed || bareRootObject)
                {
                    break;
                }

                if(!TryConsumeValue(json, ref pos, frames, ref top, ref depth))
                {
                    return false;
                }

                if(top < 0)
                {
                    rootParsed = true;
                }

                continue;
            }

            if(frames[top].IsObject)
            {
                switch((ObjectPhase)frames[top].Phase)
                {
                    case ObjectPhase.ExpectKeyOrClose:
                    case ObjectPhase.ExpectKeyRequired:
                        SkipWhitespace(json, ref pos);
                        if(pos >= json.Length)
                        {
                            if(bareRootObject && top == 0
                                && (ObjectPhase)frames[top].Phase == ObjectPhase.ExpectKeyOrClose)
                            {
                                RemoveNamesAtDepth(seenNames, ref seenNameCount, depth);
                                top--;
                                depth--;
                                _ = AdvanceAfterValue(frames, top);

                                continue;
                            }

                            return false;
                        }

                        if(json[pos] == (byte)'}')
                        {
                            if(bareRootObject && top == 0)
                            {
                                return false;
                            }

                            if((ObjectPhase)frames[top].Phase == ObjectPhase.ExpectKeyRequired)
                            {
                                return false;
                            }

                            RemoveNamesAtDepth(seenNames, ref seenNameCount, depth);
                            pos++;
                            top--;
                            depth--;
                            if(!AdvanceAfterValue(frames, top))
                            {
                                rootParsed = true;
                            }

                            continue;
                        }

                        if(json[pos] != (byte)'"'
                            || !TryValidateString(json, ref pos, out int nameStart, out int nameLength))
                        {
                            return false;
                        }

                        if(HasNameAtDepth(json, seenNames, seenNameCount, depth, nameStart, nameLength))
                        {
                            return false;
                        }

                        if(seenNameCount >= MaximumLiveMemberNames)
                        {
                            return false;
                        }

                        seenNames[seenNameCount] = new SeenName(nameStart, nameLength, depth);
                        seenNameCount++;
                        frames[top].Phase = (byte)ObjectPhase.ExpectColon;

                        continue;

                    case ObjectPhase.ExpectColon:
                        SkipWhitespace(json, ref pos);
                        if(pos >= json.Length || json[pos] != (byte)':')
                        {
                            return false;
                        }

                        pos++;
                        frames[top].Phase = (byte)ObjectPhase.ExpectValue;

                        continue;

                    case ObjectPhase.ExpectValue:
                        if(!TryConsumeValue(json, ref pos, frames, ref top, ref depth))
                        {
                            return false;
                        }

                        continue;

                    case ObjectPhase.ExpectCommaOrClose:
                        SkipWhitespace(json, ref pos);
                        if(pos >= json.Length)
                        {
                            if(bareRootObject && top == 0)
                            {
                                RemoveNamesAtDepth(seenNames, ref seenNameCount, depth);
                                top--;
                                depth--;
                                _ = AdvanceAfterValue(frames, top);

                                continue;
                            }

                            return false;
                        }

                        if(json[pos] == (byte)'}')
                        {
                            if(bareRootObject && top == 0)
                            {
                                return false;
                            }

                            RemoveNamesAtDepth(seenNames, ref seenNameCount, depth);
                            pos++;
                            top--;
                            depth--;
                            if(!AdvanceAfterValue(frames, top))
                            {
                                rootParsed = true;
                            }

                            continue;
                        }

                        if(json[pos] != (byte)',')
                        {
                            return false;
                        }

                        pos++;
                        frames[top].Phase = (byte)ObjectPhase.ExpectKeyRequired;

                        continue;

                    default:
                        return false;
                }
            }
            else
            {
                switch((ArrayPhase)frames[top].Phase)
                {
                    case ArrayPhase.ExpectValueOrClose:
                    case ArrayPhase.ExpectValueRequired:
                        SkipWhitespace(json, ref pos);
                        if(pos >= json.Length)
                        {
                            return false;
                        }

                        if(json[pos] == (byte)']')
                        {
                            if((ArrayPhase)frames[top].Phase == ArrayPhase.ExpectValueRequired)
                            {
                                return false;
                            }

                            pos++;
                            top--;
                            depth--;
                            if(!AdvanceAfterValue(frames, top))
                            {
                                rootParsed = true;
                            }

                            continue;
                        }

                        if(!TryConsumeValue(json, ref pos, frames, ref top, ref depth))
                        {
                            return false;
                        }

                        continue;

                    case ArrayPhase.ExpectCommaOrClose:
                        SkipWhitespace(json, ref pos);
                        if(pos >= json.Length)
                        {
                            return false;
                        }

                        if(json[pos] == (byte)']')
                        {
                            pos++;
                            top--;
                            depth--;
                            if(!AdvanceAfterValue(frames, top))
                            {
                                rootParsed = true;
                            }

                            continue;
                        }

                        if(json[pos] != (byte)',')
                        {
                            return false;
                        }

                        pos++;
                        frames[top].Phase = (byte)ArrayPhase.ExpectValueRequired;

                        continue;

                    default:
                        return false;
                }
            }
        }

        return true;
    }


    /// <summary>The phases <see cref="IsWellFormedJsonDocument"/> cycles an open object frame through.</summary>
    private enum ObjectPhase: byte
    {
        /// <summary>Just past <c>{</c>: a member name or the closing <c>}</c> (empty object) is next.</summary>
        ExpectKeyOrClose,

        /// <summary>A member name was just read: <c>:</c> is next.</summary>
        ExpectColon,

        /// <summary><c>:</c> was just read: the member's value is next.</summary>
        ExpectValue,

        /// <summary>A member was just completed: <c>,</c> or the closing <c>}</c> is next.</summary>
        ExpectCommaOrClose,

        /// <summary>Just past <c>,</c>: a member name is next; the closer is not allowed here (RFC 8259 §2, no trailing comma).</summary>
        ExpectKeyRequired
    }


    /// <summary>The phases <see cref="IsWellFormedJsonDocument"/> cycles an open array frame through.</summary>
    private enum ArrayPhase: byte
    {
        /// <summary>Just past <c>[</c>: an element or the closing <c>]</c> (empty array) is next.</summary>
        ExpectValueOrClose,

        /// <summary>An element was just completed: <c>,</c> or the closing <c>]</c> is next.</summary>
        ExpectCommaOrClose,

        /// <summary>Just past <c>,</c>: an element is next; the closer is not allowed here (RFC 8259 §2, no trailing comma).</summary>
        ExpectValueRequired
    }


    /// <summary>
    /// One open container frame on <see cref="IsWellFormedJsonDocument"/>'s explicit, fixed-size frame
    /// stack. Its <see cref="Phase"/> is an <see cref="ObjectPhase"/> when <see cref="IsObject"/> holds,
    /// an <see cref="ArrayPhase"/> otherwise.
    /// </summary>
    private struct NestingFrame
    {
        /// <summary>Whether this frame is an object (<see langword="true"/>) or an array (<see langword="false"/>).</summary>
        public bool IsObject;

        /// <summary>The frame's current phase, as the enum <see cref="IsObject"/> selects.</summary>
        public byte Phase;
    }


    /// <summary>
    /// One member name <see cref="IsWellFormedJsonDocument"/> has read inside the object currently open
    /// at <see cref="Depth"/>, recorded as a span into the original document so a later sibling name can
    /// be compared against it without allocating.
    /// </summary>
    /// <param name="Start">The byte offset of the name's first content byte (after the opening quote).</param>
    /// <param name="Length">The number of raw content bytes, excluding both quotes.</param>
    /// <param name="Depth">The nesting depth of the object this member belongs to.</param>
    private readonly record struct SeenName(int Start, int Length, int Depth);


    /// <summary>
    /// Consumes one JSON value at <paramref name="pos"/>: a scalar advances <paramref name="pos"/> past it
    /// and folds it into the current top frame via <see cref="AdvanceAfterValue"/>, while an object or array
    /// pushes a new frame onto <paramref name="frames"/> for the caller's loop to continue processing —
    /// nesting is therefore driven by the caller's iteration, never by this method calling itself.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes being validated.</param>
    /// <param name="pos">The read position, advanced past the value's first token.</param>
    /// <param name="frames">The open-container frame stack.</param>
    /// <param name="top">The index of the current top frame, or -1 at the root; updated on a container push.</param>
    /// <param name="depth">The current nesting depth; updated on a container push.</param>
    /// <returns><see langword="true"/> when a value's first token was consumed without a grammar violation.</returns>
    private static bool TryConsumeValue(
        ReadOnlySpan<byte> json,
        ref int pos,
        Span<NestingFrame> frames,
        ref int top,
        ref int depth)
    {
        SkipWhitespace(json, ref pos);
        if(pos >= json.Length)
        {
            return false;
        }

        byte current = json[pos];

        return current switch
        {
            (byte)'{' => TryPushContainer(true, frames, ref top, ref depth, ref pos),
            (byte)'[' => TryPushContainer(false, frames, ref top, ref depth, ref pos),
            (byte)'"' => TryConsumeString(json, ref pos, frames, top),
            (byte)'t' => TryConsumeLiteral(json, ref pos, "true"u8, frames, top),
            (byte)'f' => TryConsumeLiteral(json, ref pos, "false"u8, frames, top),
            (byte)'n' => TryConsumeLiteral(json, ref pos, "null"u8, frames, top),
            (byte)'-' or (>= (byte)'0' and <= (byte)'9') => TryConsumeNumber(json, ref pos, frames, top),
            _ => false,
        };
    }


    /// <summary>Pushes a new object or array frame after checking <see cref="MaximumNestingDepth"/>.</summary>
    private static bool TryPushContainer(bool isObject, Span<NestingFrame> frames, ref int top, ref int depth, ref int pos)
    {
        depth++;
        if(depth > MaximumNestingDepth)
        {
            return false;
        }

        top++;
        frames[top] = new NestingFrame { IsObject = isObject, Phase = 0 };
        pos++;

        return true;
    }


    /// <summary>Validates a string value and folds it into the current top frame as a completed value.</summary>
    private static bool TryConsumeString(ReadOnlySpan<byte> json, ref int pos, Span<NestingFrame> frames, int top)
    {
        if(!TryValidateString(json, ref pos, out _, out _))
        {
            return false;
        }

        _ = AdvanceAfterValue(frames, top);

        return true;
    }


    /// <summary>Matches a literal value (<c>true</c>/<c>false</c>/<c>null</c>) and folds it into the current top frame.</summary>
    private static bool TryConsumeLiteral(ReadOnlySpan<byte> json, ref int pos, ReadOnlySpan<byte> literal, Span<NestingFrame> frames, int top)
    {
        if(!TryMatchLiteral(json, ref pos, literal))
        {
            return false;
        }

        _ = AdvanceAfterValue(frames, top);

        return true;
    }


    /// <summary>Validates a number value per RFC 8259 §6 and folds it into the current top frame.</summary>
    private static bool TryConsumeNumber(ReadOnlySpan<byte> json, ref int pos, Span<NestingFrame> frames, int top)
    {
        if(!TryValidateNumber(json, ref pos))
        {
            return false;
        }

        _ = AdvanceAfterValue(frames, top);

        return true;
    }


    /// <summary>
    /// Folds a just-completed value into the frame now on top of the stack: an object frame moves to
    /// <see cref="ObjectPhase.ExpectCommaOrClose"/>, an array frame to <see cref="ArrayPhase.ExpectCommaOrClose"/>.
    /// Called both right after an inline scalar (the top frame is unchanged) and right after a container
    /// frame is popped (the top frame is now its parent), so the same transition covers both cases.
    /// </summary>
    /// <returns><see langword="true"/> when there was a parent frame to advance; <see langword="false"/> at the root.</returns>
    private static bool AdvanceAfterValue(Span<NestingFrame> frames, int top)
    {
        if(top < 0)
        {
            return false;
        }

        ref NestingFrame frame = ref frames[top];
        frame.Phase = frame.IsObject ? (byte)ObjectPhase.ExpectCommaOrClose : (byte)ArrayPhase.ExpectCommaOrClose;

        return true;
    }


    /// <summary>
    /// Removes every recorded member name at <paramref name="depth"/> as its object closes, by shrinking
    /// <paramref name="seenNameCount"/> back past them; their slots in <paramref name="seenNames"/> are
    /// simply overwritten by whatever is recorded next.
    /// </summary>
    private static void RemoveNamesAtDepth(ReadOnlySpan<SeenName> seenNames, ref int seenNameCount, int depth)
    {
        while(seenNameCount > 0 && seenNames[seenNameCount - 1].Depth == depth)
        {
            seenNameCount--;
        }
    }


    /// <summary>
    /// Reports whether a member name just read at <paramref name="depth"/> decoded-equals one already
    /// recorded for the object currently open at that depth.
    /// </summary>
    private static bool HasNameAtDepth(ReadOnlySpan<byte> json, ReadOnlySpan<SeenName> seenNames, int seenNameCount, int depth, int start, int length)
    {
        for(int index = seenNameCount - 1; index >= 0 && seenNames[index].Depth == depth; index--)
        {
            if(NamesEqualDecoded(json, seenNames[index].Start, seenNames[index].Length, start, length))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Compares two raw (still-escaped) member-name spans by their DECODED value, ordinally, so
    /// <c>"kid"</c> and <c>"kid"</c> compare equal. Decodes both spans one UTF-16 code unit at a
    /// time via <see cref="NameCursor"/> rather than materializing either as a <see cref="string"/>.
    /// </summary>
    private static bool NamesEqualDecoded(ReadOnlySpan<byte> json, int startA, int lengthA, int startB, int lengthB)
    {
        NameCursor cursorA = new(startA, startA + lengthA);
        NameCursor cursorB = new(startB, startB + lengthB);

        while(true)
        {
            bool hasA = cursorA.TryReadNext(json, out char charA);
            bool hasB = cursorB.TryReadNext(json, out char charB);
            if(hasA != hasB)
            {
                return false;
            }

            if(!hasA)
            {
                return true;
            }

            if(charA != charB)
            {
                return false;
            }
        }
    }


    /// <summary>
    /// Decodes one already-validated JSON string's raw content span one UTF-16 code unit at a time —
    /// one call to <see cref="TryReadNext"/> per unit — so two names can be compared in
    /// <see cref="NamesEqualDecoded"/> without either being materialized as a <see cref="string"/>. An
    /// escape decodes to exactly one code unit; a raw multi-byte UTF-8 sequence above the BMP decodes to
    /// two, the second held in <see cref="_pendingLowSurrogate"/> until the next call.
    /// </summary>
    private struct NameCursor
    {
        private int _position;
        private char _pendingLowSurrogate;

        /// <summary>The exclusive end of the cursor's span into the document.</summary>
        private int End { get; }

        /// <summary>
        /// Whether a backslash in the cursor's span is a JSON escape introducer, per the constructor's
        /// <c>decodeEscapes</c> argument.
        /// </summary>
        private bool DecodeEscapes { get; }

        /// <summary>
        /// Creates a cursor over the content span <c>[start, end)</c> of an already-validated string.
        /// </summary>
        /// <param name="start">The start of the span.</param>
        /// <param name="end">The exclusive end of the span.</param>
        /// <param name="decodeEscapes">
        /// Whether a backslash in the span is a JSON escape introducer. <see langword="true"/> for a
        /// span taken from the JSON document itself; <see langword="false"/> for a plain, already-decoded
        /// UTF-8 literal supplied by a caller, whose backslash bytes (if any) are ordinary content, not
        /// JSON syntax the cursor should interpret.
        /// </param>
        public NameCursor(int start, int end, bool decodeEscapes = true)
        {
            _position = start;
            End = end;
            _pendingLowSurrogate = '\0';
            DecodeEscapes = decodeEscapes;
        }


        /// <summary>Reads the next decoded UTF-16 code unit, or reports there are none left.</summary>
        /// <param name="json">The document the cursor's span was taken from.</param>
        /// <param name="result">The decoded code unit, or <c>'\0'</c> when the span is exhausted.</param>
        /// <returns><see langword="true"/> when a code unit was produced.</returns>
        public bool TryReadNext(ReadOnlySpan<byte> json, out char result)
        {
            if(_pendingLowSurrogate != '\0')
            {
                result = _pendingLowSurrogate;
                _pendingLowSurrogate = '\0';

                return true;
            }

            if(_position >= End)
            {
                result = '\0';

                return false;
            }

            byte current = json[_position];
            if(current != (byte)'\\' || !DecodeEscapes)
            {
                OperationStatus status = Rune.DecodeFromUtf8(json[_position..End], out Rune rune, out int consumed);
                if(status != OperationStatus.Done || consumed <= 0)
                {
                    //Defensive fallback only: the structural pass already validated this span, so
                    //every unescaped byte here is part of well-formed UTF-8.
                    result = (char)current;
                    _position++;

                    return true;
                }

                _position += consumed;
                if(rune.IsBmp)
                {
                    result = (char)rune.Value;

                    return true;
                }

                Span<char> utf16 = stackalloc char[2];
                _ = rune.EncodeToUtf16(utf16);
                _pendingLowSurrogate = utf16[1];
                result = utf16[0];

                return true;
            }

            _position++;
            if(_position >= End)
            {
                result = '\0';

                return false;
            }

            byte escape = json[_position];
            char? simple = escape switch
            {
                (byte)'"' => '"',
                (byte)'\\' => '\\',
                (byte)'/' => '/',
                (byte)'b' => '\b',
                (byte)'f' => '\f',
                (byte)'n' => '\n',
                (byte)'r' => '\r',
                (byte)'t' => '\t',
                _ => null,
            };

            if(simple is char decoded)
            {
                _position++;
                result = decoded;

                return true;
            }

            if(escape == (byte)'u' && _position + 5 <= End)
            {
                result = (char)DecodeHex4(json, _position + 1);
                _position += 5;

                return true;
            }

            //Not reached over a span the structural pass already validated; kept for defense in depth.
            result = '\0';

            return false;
        }
    }


    /// <summary>Decodes the four hex digits at <paramref name="start"/>, treating an out-of-range or non-hex digit as 0.</summary>
    private static int DecodeHex4(ReadOnlySpan<byte> json, int start)
    {
        int code = 0;
        for(int offset = 0; offset < 4; offset++)
        {
            int index = start + offset;
            int nibble = index < json.Length ? HexNibble((char)json[index]) : -1;
            code = (code << 4) | (nibble < 0 ? 0 : nibble);
        }

        return code;
    }


    /// <summary>
    /// Validates a JSON string starting at <paramref name="pos"/> (which must index its opening quote)
    /// per <see href="https://www.rfc-editor.org/rfc/rfc8259#section-7">RFC 8259 §7</see>: every escape is
    /// one of the two-character forms or <c>\u</c> followed by exactly four hex digits, and no unescaped
    /// control character (below U+0020) appears in its content.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes.</param>
    /// <param name="pos">The opening quote's position; advanced past the closing quote on success.</param>
    /// <param name="contentStart">The byte offset of the string's first content byte.</param>
    /// <param name="contentLength">The number of raw content bytes, excluding both quotes.</param>
    /// <returns><see langword="true"/> when the string is well formed.</returns>
    private static bool TryValidateString(ReadOnlySpan<byte> json, ref int pos, out int contentStart, out int contentLength)
    {
        contentStart = pos + 1;
        contentLength = 0;
        int index = pos + 1;

        while(true)
        {
            if(index >= json.Length)
            {
                return false;
            }

            byte current = json[index];
            if(current == (byte)'"')
            {
                contentLength = index - contentStart;
                pos = index + 1;

                return true;
            }

            if(current == (byte)'\\')
            {
                index++;
                if(index >= json.Length)
                {
                    return false;
                }

                byte escape = json[index];
                switch(escape)
                {
                    case (byte)'"':
                    case (byte)'\\':
                    case (byte)'/':
                    case (byte)'b':
                    case (byte)'f':
                    case (byte)'n':
                    case (byte)'r':
                    case (byte)'t':
                        index++;

                        break;

                    case (byte)'u':
                        index++;
                        if(index + 4 > json.Length)
                        {
                            return false;
                        }

                        for(int offset = 0; offset < 4; offset++)
                        {
                            if(HexNibble((char)json[index + offset]) < 0)
                            {
                                return false;
                            }
                        }

                        index += 4;

                        break;

                    default:
                        return false;
                }

                continue;
            }

            if(current < 0x20)
            {
                return false;
            }

            index++;
        }
    }


    /// <summary>
    /// Validates a JSON number starting at <paramref name="pos"/> against the
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-6">RFC 8259 §6</see> grammar: an optional
    /// leading minus, an integer part with no leading zero (unless it is exactly <c>0</c>), an optional
    /// fraction, and an optional exponent.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes.</param>
    /// <param name="pos">The number's first byte; advanced past its last digit on success.</param>
    /// <returns><see langword="true"/> when the number is well formed.</returns>
    private static bool TryValidateNumber(ReadOnlySpan<byte> json, ref int pos)
    {
        int index = pos;
        if(index < json.Length && json[index] == (byte)'-')
        {
            index++;
        }

        if(index >= json.Length)
        {
            return false;
        }

        if(json[index] == (byte)'0')
        {
            index++;
        }
        else if(json[index] is >= (byte)'1' and <= (byte)'9')
        {
            index++;
            while(index < json.Length && json[index] >= (byte)'0' && json[index] <= (byte)'9')
            {
                index++;
            }
        }
        else
        {
            return false;
        }

        if(index < json.Length && json[index] == (byte)'.')
        {
            index++;
            if(index >= json.Length || json[index] < (byte)'0' || json[index] > (byte)'9')
            {
                return false;
            }

            while(index < json.Length && json[index] >= (byte)'0' && json[index] <= (byte)'9')
            {
                index++;
            }
        }

        if(index < json.Length && (json[index] == (byte)'e' || json[index] == (byte)'E'))
        {
            index++;
            if(index < json.Length && (json[index] == (byte)'+' || json[index] == (byte)'-'))
            {
                index++;
            }

            if(index >= json.Length || json[index] < (byte)'0' || json[index] > (byte)'9')
            {
                return false;
            }

            while(index < json.Length && json[index] >= (byte)'0' && json[index] <= (byte)'9')
            {
                index++;
            }
        }

        pos = index;

        return true;
    }


    /// <summary>Matches an exact literal (<c>true</c>, <c>false</c>, or <c>null</c>) at <paramref name="pos"/>.</summary>
    /// <param name="json">UTF-8 JSON bytes.</param>
    /// <param name="pos">The literal's first byte; advanced past its last byte on success.</param>
    /// <param name="literal">The exact UTF-8 literal to match.</param>
    /// <returns><see langword="true"/> when <paramref name="literal"/> matches at <paramref name="pos"/>.</returns>
    private static bool TryMatchLiteral(ReadOnlySpan<byte> json, ref int pos, ReadOnlySpan<byte> literal)
    {
        if(pos + literal.Length > json.Length || !json.Slice(pos, literal.Length).SequenceEqual(literal))
        {
            return false;
        }

        pos += literal.Length;

        return true;
    }


    /// <summary>Advances <paramref name="pos"/> past every insignificant-whitespace byte.</summary>
    private static void SkipWhitespace(ReadOnlySpan<byte> json, ref int pos)
    {
        while(pos < json.Length && IsJsonWhitespace(json[pos]))
        {
            pos++;
        }
    }


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
        b is ((byte)' ') or ((byte)'\t') or ((byte)'\r') or ((byte)'\n');


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
                _ = builder.Append(current);
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
                _ = builder.Append(decoded);
                index += 2;

                continue;
            }

            if(escape == 'u' && TryDecodeHex4(value, index + 2, out char unicode))
            {
                _ = builder.Append(unicode);
                index += 6;

                continue;
            }

            //Unknown or truncated escape: keep the backslash literally and continue.
            _ = builder.Append(current);
            index++;
        }

        return builder.ToString();
    }


    /// <summary>Decodes the four hex digits at <paramref name="start"/> of a <c>\uXXXX</c> JSON escape.</summary>
    /// <param name="value">The string carrying the escape.</param>
    /// <param name="start">The position of the first hex digit, immediately after <c>\u</c>.</param>
    /// <param name="result">The decoded character when the four digits are valid hex.</param>
    /// <returns><see langword="true"/> when four valid hex digits were present and decoded.</returns>
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


    /// <summary>Maps one hex digit character to its numeric value, or -1 when it is not a hex digit.</summary>
    /// <param name="character">The character to map.</param>
    /// <returns>The nibble value 0-15, or -1 when <paramref name="character"/> is not a hex digit.</returns>
    private static int HexNibble(char character) =>
        character switch
        {
            >= '0' and <= '9' => character - '0',
            >= 'a' and <= 'f' => character - 'a' + 10,
            >= 'A' and <= 'F' => character - 'A' + 10,
            _ => -1
        };


    /// <summary>
    /// Selects the JWK from a JWK Set's <c>keys</c> array whose <c>kid</c> member equals
    /// <paramref name="keyId"/>, scanning every element rather than stopping at the first match.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517 §4.5</see> makes
    /// distinct <c>kid</c> values within a set a SHOULD, so a duplicate is possible; when two or more
    /// elements carry the requested identifier this refuses with
    /// <see cref="JwkSelectionOutcome.MultipleKeysMatched"/> rather than
    /// trusting whichever element a first-match scan happens to reach first — the array's order is
    /// attacker-controlled input, not a tiebreaker. An absent or empty <paramref name="keyId"/> is
    /// never a match (<see cref="JwkSelectionOutcome.KeyIdRequired"/>); a caller with no key
    /// identifier to present calls <see cref="SelectSoleKey(ReadOnlySpan{byte})"/> instead. Runs
    /// <see cref="IsWellFormedJsonDocument"/> over <paramref name="jwksJson"/> before any scan, per
    /// the class remarks.
    /// </summary>
    /// <param name="jwksJson">The JWK Set document as UTF-8 JSON bytes.</param>
    /// <param name="keyId">The requested <c>kid</c>, or <see langword="null"/>/empty when none was presented.</param>
    /// <returns>
    /// A <see cref="JwkSelectionResult"/> carrying <see cref="JwkSelectionOutcome.Selected"/> and the
    /// matched key's string-valued members, or one of the refusal outcomes.
    /// </returns>
    public static JwkSelectionResult SelectKeyByKeyId(ReadOnlySpan<byte> jwksJson, string? keyId)
    {
        if(!IsWellFormedJsonDocument(jwksJson))
        {
            return JwkSelectionResult.MalformedDocument();
        }

        if(string.IsNullOrEmpty(keyId))
        {
            return JwkSelectionResult.KeyIdRequired();
        }

        return ScanKeysArray(jwksJson, keyId);
    }


    /// <summary>
    /// Selects the JWK from a JWK Set's <c>keys</c> array whose <c>kid</c> member equals
    /// <paramref name="keyId"/> AND whose <c>use</c> makes it eligible for <paramref name="publicKeyUse"/>,
    /// refusing the whole set when any element — a candidate or not — carries private or symmetric key
    /// material. <c>use</c> eligibility (<see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.2">RFC
    /// 7517 §4.2</see>) is: absent, since the member is OPTIONAL; present as a JSON string whose decoded
    /// value ordinally equals <paramref name="publicKeyUse"/>; never present in any other form (another
    /// value, a number, an array, an object, or JSON <see langword="null"/>). The duplicate-<c>kid</c>
    /// refusal is computed over every element whose <c>kid</c> matches WHATEVER its <c>use</c> — a member
    /// of the same attacker-influenced document never narrows it, and
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-3.1.1">OpenID Federation
    /// §3.1.1</see> requires every key of an Entity's JWK Set to have a unique <c>kid</c> regardless. The
    /// private-or-symmetric-material refusal is this library's own policy for a JWK Set of verification
    /// keys, not a requirement of any RFC; <c>key_ops</c> and <c>alg</c> are not consulted. Every name this
    /// scan looks for — <c>keys</c>, <c>kid</c>, <c>use</c>, and each private or symmetric member name — is
    /// matched by its DECODED spelling, so a JSON escape in a member's name never hides it, and per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-6">RFC 7517 §6</see> (adopting
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.3">RFC 7515 §5.3</see>) the <c>use</c>
    /// VALUE is compared decoded the same way. Runs <see cref="IsWellFormedJsonDocument"/> over
    /// <paramref name="jwksJson"/> before any scan; a non-object element anywhere in <c>keys</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7517#section-5.1">RFC 7517 §5.1</see>: <c>keys</c> is
    /// an array of JWK VALUES, and a JWK is an object) also answers <see cref="JwkSelectionOutcome.MalformedDocument"/>.
    /// A refusal result's <see cref="JwkSelectionResult.Members"/> is always <see langword="null"/>. A
    /// <see cref="JwkSelectionOutcome.Selected"/> result's <see cref="JwkSelectionResult.Members"/> is
    /// keyed by each member's DECODED name, so a key matched through an escaped <c>kid</c> or
    /// <c>kty</c> spelling hands its consumer the plain <c>kid</c>/<c>kty</c> key — unlike
    /// <see cref="SelectKeyByKeyId(ReadOnlySpan{byte}, string?)"/>, whose <c>Members</c> is keyed by
    /// each member's document spelling exactly as written, decoded or not.
    /// </summary>
    /// <param name="jwksJson">The JWK Set document as UTF-8 JSON bytes.</param>
    /// <param name="keyId">The requested <c>kid</c>, or <see langword="null"/>/empty when none was presented.</param>
    /// <param name="publicKeyUse">The eligible <c>use</c> value, as UTF-8 bytes; never empty.</param>
    /// <returns>
    /// A <see cref="JwkSelectionResult"/> carrying <see cref="JwkSelectionOutcome.Selected"/> and the
    /// matched key's string-valued members, or one of the refusal outcomes.
    /// </returns>
    /// <exception cref="ArgumentException"><paramref name="publicKeyUse"/> is empty.</exception>
    public static JwkSelectionResult SelectKeyByKeyId(ReadOnlySpan<byte> jwksJson, string? keyId, ReadOnlySpan<byte> publicKeyUse)
    {
        if(publicKeyUse.IsEmpty)
        {
            throw new ArgumentException("The public key use to filter by must not be empty.", nameof(publicKeyUse));
        }

        if(!IsWellFormedJsonDocument(jwksJson))
        {
            return JwkSelectionResult.MalformedDocument();
        }

        if(string.IsNullOrEmpty(keyId))
        {
            return JwkSelectionResult.KeyIdRequired();
        }

        return ScanKeysArrayFiltered(jwksJson, keyId, publicKeyUse);
    }


    /// <summary>
    /// Selects the sole JWK in a JWK Set's <c>keys</c> array, refusing when the set carries anything
    /// other than exactly one key. This is the selection a legitimate single-key set with no
    /// <c>kid</c> needs — <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517
    /// §4.5</see> makes <c>kid</c> optional — without ever falling back to "the first key" when the
    /// set in fact carries more than one. Runs <see cref="IsWellFormedJsonDocument"/> over
    /// <paramref name="jwksJson"/> before any scan, per the class remarks.
    /// </summary>
    /// <param name="jwksJson">The JWK Set document as UTF-8 JSON bytes.</param>
    /// <returns>
    /// A <see cref="JwkSelectionResult"/> carrying <see cref="JwkSelectionOutcome.Selected"/> and the
    /// sole key's string-valued members, <see cref="JwkSelectionOutcome.NoMatch"/> for an empty set,
    /// <see cref="JwkSelectionOutcome.MultipleKeysMatched"/> for two or more keys, or
    /// <see cref="JwkSelectionOutcome.MalformedDocument"/>.
    /// </returns>
    public static JwkSelectionResult SelectSoleKey(ReadOnlySpan<byte> jwksJson)
    {
        if(!IsWellFormedJsonDocument(jwksJson))
        {
            return JwkSelectionResult.MalformedDocument();
        }

        return ScanKeysArray(jwksJson, keyId: null);
    }


    /// <summary>
    /// Selects the sole JWK in a JWK Set's <c>keys</c> array whose <c>use</c> makes it eligible for
    /// <paramref name="publicKeyUse"/>, refusing when the set carries anything other than exactly one
    /// eligible key, or when any element — eligible or not — carries private or symmetric key
    /// material. This is where the filter earns its keep over
    /// <see cref="SelectSoleKey(ReadOnlySpan{byte})"/>: a set holding one <c>sig</c> key and one
    /// <c>enc</c> key selects the <c>sig</c> key, where the unfiltered selector refuses the set
    /// outright for carrying two keys — counting ELIGIBLE keys, not every key the set holds.
    /// <c>use</c> eligibility (<see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.2">RFC 7517
    /// §4.2</see>) is: absent, since the member is OPTIONAL; present as a JSON string whose decoded
    /// value ordinally equals <paramref name="publicKeyUse"/>; never present in any other form. The
    /// private-or-symmetric-material refusal is this library's own policy for a JWK Set of
    /// verification keys, not a requirement of any RFC; <c>key_ops</c> and <c>alg</c> are not
    /// consulted. The decoded-name matching and the non-object-element refusal are exactly as
    /// documented on
    /// <see cref="SelectKeyByKeyId(ReadOnlySpan{byte}, string?, ReadOnlySpan{byte})"/>, whose
    /// <c>Members</c>-decoding guarantee for a <see cref="JwkSelectionOutcome.Selected"/> result
    /// applies here too. Runs <see cref="IsWellFormedJsonDocument"/> over <paramref name="jwksJson"/>
    /// before any scan. A refusal result's <see cref="JwkSelectionResult.Members"/> is always
    /// <see langword="null"/>.
    /// </summary>
    /// <param name="jwksJson">The JWK Set document as UTF-8 JSON bytes.</param>
    /// <param name="publicKeyUse">The eligible <c>use</c> value, as UTF-8 bytes; never empty.</param>
    /// <returns>
    /// A <see cref="JwkSelectionResult"/> carrying <see cref="JwkSelectionOutcome.Selected"/> and the
    /// eligible key's string-valued members, <see cref="JwkSelectionOutcome.NoMatch"/> when no element
    /// is eligible, <see cref="JwkSelectionOutcome.MultipleKeysMatched"/> for two or more eligible
    /// keys, <see cref="JwkSelectionOutcome.PrivateOrSymmetricMemberPresent"/>, or
    /// <see cref="JwkSelectionOutcome.MalformedDocument"/>.
    /// </returns>
    /// <exception cref="ArgumentException"><paramref name="publicKeyUse"/> is empty.</exception>
    public static JwkSelectionResult SelectSoleKey(ReadOnlySpan<byte> jwksJson, ReadOnlySpan<byte> publicKeyUse)
    {
        if(publicKeyUse.IsEmpty)
        {
            throw new ArgumentException("The public key use to filter by must not be empty.", nameof(publicKeyUse));
        }

        if(!IsWellFormedJsonDocument(jwksJson))
        {
            return JwkSelectionResult.MalformedDocument();
        }

        return ScanKeysArrayFiltered(jwksJson, keyId: null, publicKeyUse);
    }


    /// <summary>
    /// Walks every element of a JWK Set's <c>keys</c> array, counting the elements that satisfy the
    /// query: with <paramref name="keyId"/> supplied, an element whose <c>kid</c> ordinal-equals it;
    /// with <paramref name="keyId"/> <see langword="null"/>, every element (the
    /// <see cref="SelectSoleKey(ReadOnlySpan{byte})"/> query). The whole array is scanned even after a
    /// first match, so a second one is never missed — the shared core behind both
    /// <see cref="SelectKeyByKeyId(ReadOnlySpan{byte}, string?)"/> and
    /// <see cref="SelectSoleKey(ReadOnlySpan{byte})"/>.
    /// </summary>
    /// <param name="json">The JWK Set document, already confirmed well formed.</param>
    /// <param name="keyId">The <c>kid</c> to match, or <see langword="null"/> to count every element.</param>
    private static JwkSelectionResult ScanKeysArray(ReadOnlySpan<byte> json, string? keyId)
    {
        int cursor = FindKeysArrayContentStart(json);
        if(cursor < 0)
        {
            return JwkSelectionResult.NoMatch();
        }

        Dictionary<string, string>? selected = null;
        int matchCount = 0;

        while(cursor < json.Length)
        {
            while(cursor < json.Length && IsJwkArraySeparator(json[cursor]))
            {
                cursor++;
            }

            if(cursor >= json.Length || json[cursor] == (byte)']')
            {
                break;
            }

            if(json[cursor] != (byte)'{')
            {
                break;
            }

            int objectStart = cursor;
            int objectEnd = FindJwkObjectEnd(json, objectStart);
            if(objectEnd < 0)
            {
                break;
            }

            ReadOnlySpan<byte> candidate = json[objectStart..objectEnd];
            bool isMatch = keyId is null
                || string.Equals(ExtractStringValue(candidate, WellKnownJwkMemberNames.KidUtf8), keyId, StringComparison.Ordinal);

            if(isMatch)
            {
                matchCount++;
                if(matchCount > 1)
                {
                    return JwkSelectionResult.MultipleKeysMatched();
                }

                selected = ExtractJwkStringMembers(candidate);
            }

            cursor = objectEnd;
        }

        return matchCount == 1 && selected is not null
            ? JwkSelectionResult.Selected(selected)
            : JwkSelectionResult.NoMatch();
    }


    /// <summary>
    /// Walks every element of a JWK Set's <c>keys</c> array to its END, whatever it finds along the
    /// way — unlike <see cref="ScanKeysArray"/>, which stops at the first non-object element or the
    /// second <c>kid</c> match. Decides, per element: whether it carries private or symmetric key
    /// material (set-wide, ruling regardless of eligibility); with <paramref name="keyId"/> supplied,
    /// whether its <c>kid</c> matches, whatever its <c>use</c>; whether it is eligible for
    /// <paramref name="publicKeyUse"/>. A non-object element, or one whose braces never balance,
    /// answers <see cref="JwkSelectionOutcome.MalformedDocument"/> immediately — the walk never
    /// produces a partial match past one. During the walk, only the WINNING candidate's span
    /// (<c>[selectedStart, selectedEnd)</c>) is remembered — never its members — so a candidate that
    /// turns out not to be the answer, above all one the set-wide private-material refusal was going
    /// to discard anyway, is never turned into a string. Its members are extracted exactly ONCE, after
    /// the walk ends, and only when precedence has settled on <see cref="JwkSelectionOutcome.Selected"/>.
    /// Precedence once the walk completes:
    /// <see cref="JwkSelectionOutcome.PrivateOrSymmetricMemberPresent"/> outranks
    /// <see cref="JwkSelectionOutcome.MultipleKeysMatched"/> outranks
    /// <see cref="JwkSelectionOutcome.Selected"/>/<see cref="JwkSelectionOutcome.NoMatch"/>.
    /// The shared core behind
    /// <see cref="SelectKeyByKeyId(ReadOnlySpan{byte}, string?, ReadOnlySpan{byte})"/> and
    /// <see cref="SelectSoleKey(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>.
    /// </summary>
    /// <param name="json">The JWK Set document, already confirmed well formed.</param>
    /// <param name="keyId">The <c>kid</c> to match, or <see langword="null"/> for the sole-key query.</param>
    /// <param name="publicKeyUse">The eligible <c>use</c> value.</param>
    private static JwkSelectionResult ScanKeysArrayFiltered(ReadOnlySpan<byte> json, string? keyId, ReadOnlySpan<byte> publicKeyUse)
    {
        int cursor = FindKeysArrayContentStartDecoded(json);
        if(cursor < 0)
        {
            return JwkSelectionResult.NoMatch();
        }

        bool carriesPrivateOrSymmetricMember = false;
        int selectedStart = -1;
        int selectedEnd = -1;
        int eligibleMatchCount = 0;
        int keyIdMatchCount = 0;

        while(cursor < json.Length)
        {
            while(cursor < json.Length && IsJwkArraySeparator(json[cursor]))
            {
                cursor++;
            }

            if(cursor >= json.Length || json[cursor] == (byte)']')
            {
                break;
            }

            if(json[cursor] != (byte)'{')
            {
                return JwkSelectionResult.MalformedDocument();
            }

            int objectStart = cursor;
            int objectEnd = FindJwkObjectEnd(json, objectStart);
            if(objectEnd < 0)
            {
                return JwkSelectionResult.MalformedDocument();
            }

            ReadOnlySpan<byte> candidate = json[objectStart..objectEnd];

            if(!carriesPrivateOrSymmetricMember && ElementCarriesPrivateOrSymmetricMember(candidate))
            {
                carriesPrivateOrSymmetricMember = true;
            }

            bool isUseEligible = IsUseEligible(candidate, publicKeyUse);

            if(keyId is not null)
            {
                if(KeyIdMatches(candidate, keyId))
                {
                    keyIdMatchCount++;
                    if(keyIdMatchCount == 1 && isUseEligible)
                    {
                        selectedStart = objectStart;
                        selectedEnd = objectEnd;
                    }
                }
            }
            else if(isUseEligible)
            {
                eligibleMatchCount++;
                if(eligibleMatchCount == 1)
                {
                    selectedStart = objectStart;
                    selectedEnd = objectEnd;
                }
            }

            cursor = objectEnd;
        }

        if(carriesPrivateOrSymmetricMember)
        {
            return JwkSelectionResult.PrivateOrSymmetricMemberPresent();
        }

        int matchCount = keyId is not null ? keyIdMatchCount : eligibleMatchCount;

        return matchCount switch
        {
            0 => JwkSelectionResult.NoMatch(),
            1 => selectedStart >= 0
                ? JwkSelectionResult.Selected(ExtractJwkStringMembersDecoded(json[selectedStart..selectedEnd]))
                : JwkSelectionResult.NoMatch(),
            _ => JwkSelectionResult.MultipleKeysMatched()
        };
    }


    /// <summary>
    /// The UTF-8 spellings of every name in
    /// <see cref="WellKnownJwkMemberNames.PrivateAndSymmetricMembers"/>, encoded once so
    /// <see cref="ElementCarriesPrivateOrSymmetricMember"/> tracks the catalog directly instead of
    /// repeating its member names as a fixed set of literals that could silently drift from it.
    /// </summary>
    private static ReadOnlyMemory<byte>[] PrivateAndSymmetricMemberNamesUtf8 { get; } =
        [.. WellKnownJwkMemberNames.PrivateAndSymmetricMembers.Select(name => (ReadOnlyMemory<byte>)Encoding.UTF8.GetBytes(name))];


    /// <summary>
    /// Whether one JWK object carries a top-level member whose DECODED name is one of
    /// <see cref="WellKnownJwkMemberNames.PrivateAndSymmetricMembers"/>, whatever that member's JSON
    /// type — <c>oth</c> (<see href="https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7">RFC 7518
    /// §6.3.2.7</see>) is an ARRAY, and the refusal this backs works off the member's NAME alone.
    /// </summary>
    /// <param name="jwkObject">One JWK object's UTF-8 bytes, braces included.</param>
    private static bool ElementCarriesPrivateOrSymmetricMember(ReadOnlySpan<byte> jwkObject)
    {
        foreach(ReadOnlyMemory<byte> name in PrivateAndSymmetricMemberNamesUtf8)
        {
            if(FindTopLevelValueStart(jwkObject, name.Span) >= 0)
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Whether one JWK object is eligible for <paramref name="publicKeyUse"/> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.2">RFC 7517 §4.2</see>: an absent
    /// <c>use</c> is eligible (the member is OPTIONAL); a <c>use</c> present as a JSON string whose
    /// DECODED value ordinally equals <paramref name="publicKeyUse"/> is eligible; a <c>use</c>
    /// present in any other JSON form is not.
    /// </summary>
    /// <param name="jwkObject">One JWK object's UTF-8 bytes, braces included.</param>
    /// <param name="publicKeyUse">The eligible <c>use</c> value.</param>
    private static bool IsUseEligible(ReadOnlySpan<byte> jwkObject, ReadOnlySpan<byte> publicKeyUse)
    {
        int valueStart = FindTopLevelValueStart(jwkObject, WellKnownJwkMemberNames.UseUtf8);
        if(valueStart < 0)
        {
            return true;
        }

        if(valueStart >= jwkObject.Length || jwkObject[valueStart] != (byte)'"')
        {
            return false;
        }

        int afterValue = SkipString(jwkObject, valueStart);
        int contentStart = valueStart + 1;
        int contentLength = afterValue - 1 - contentStart;

        return DecodedContentEqualsPlain(jwkObject, contentStart, contentLength, publicKeyUse);
    }


    /// <summary>
    /// Whether one JWK object's <c>kid</c> — located by its DECODED member name — equals
    /// <paramref name="keyId"/> ordinally, once the <c>kid</c> value itself is decoded. Compares the
    /// decoded content directly against <paramref name="keyId"/>'s characters rather than
    /// materializing the candidate's <c>kid</c> as a <see cref="string"/> first, so a non-matching
    /// candidate — the common case in a set of any size — allocates nothing for the comparison.
    /// </summary>
    /// <param name="jwkObject">One JWK object's UTF-8 bytes, braces included.</param>
    /// <param name="keyId">The requested <c>kid</c>.</param>
    private static bool KeyIdMatches(ReadOnlySpan<byte> jwkObject, string keyId)
    {
        int valueStart = FindTopLevelValueStart(jwkObject, WellKnownJwkMemberNames.KidUtf8);
        if(valueStart < 0 || valueStart >= jwkObject.Length || jwkObject[valueStart] != (byte)'"')
        {
            return false;
        }

        int afterValue = SkipString(jwkObject, valueStart);
        int contentStart = valueStart + 1;
        int contentLength = afterValue - 1 - contentStart;

        return DecodedContentEqualsString(jwkObject, contentStart, contentLength, keyId);
    }


    /// <summary>
    /// Compares an already-validated JSON string's raw (possibly escaped) content span against a
    /// materialized <see cref="string"/>, decoding the document side one UTF-16 code unit at a time
    /// with <see cref="NameCursor"/> rather than allocating a decoded copy of the span first.
    /// </summary>
    /// <param name="json">The document the raw span was taken from.</param>
    /// <param name="start">The start of the raw span, immediately after its opening quote.</param>
    /// <param name="length">The length of the raw span, up to (not including) its closing quote.</param>
    /// <param name="value">The already-decoded string to compare against.</param>
    private static bool DecodedContentEqualsString(ReadOnlySpan<byte> json, int start, int length, string value)
    {
        NameCursor documentCursor = new(start, start + length);
        int index = 0;

        while(true)
        {
            bool hasDocumentChar = documentCursor.TryReadNext(json, out char documentChar);
            bool hasValueChar = index < value.Length;
            if(hasDocumentChar != hasValueChar)
            {
                return false;
            }

            if(!hasDocumentChar)
            {
                return true;
            }

            if(documentChar != value[index])
            {
                return false;
            }

            index++;
        }
    }


    /// <summary>
    /// Locates the content start of a JWK Set's <c>keys</c> array by the member's DECODED name, so an
    /// escaped spelling of <c>keys</c> is read exactly as the plain spelling — the filtered
    /// counterpart of <see cref="FindKeysArrayContentStart"/>.
    /// </summary>
    /// <param name="json">The JWK Set document, already confirmed well formed.</param>
    private static int FindKeysArrayContentStartDecoded(ReadOnlySpan<byte> json)
    {
        int valueStart = FindTopLevelValueStart(json, WellKnownJwkMemberNames.KeysUtf8);
        if(valueStart < 0 || valueStart >= json.Length || json[valueStart] != (byte)'[')
        {
            return -1;
        }

        return valueStart + 1;
    }


    /// <summary>
    /// Finds the value-start position — the first byte after the member's colon and any whitespace —
    /// of the top-level (depth-0) member of <paramref name="json"/> whose DECODED name equals
    /// <paramref name="decodedName"/>, or -1 when absent. Mirrors the structural walk
    /// <see cref="GetTopLevelKeyNames"/> already performs, decoding each candidate name with
    /// <see cref="DecodedContentEqualsPlain"/> instead of comparing raw bytes, so this is the one
    /// place an escaped <c>keys</c>, <c>kid</c>, <c>use</c>, or private/symmetric member name is seen
    /// as its plain spelling.
    /// </summary>
    /// <param name="json">UTF-8 JSON bytes to scan (an object, optionally with its braces).</param>
    /// <param name="decodedName">The member name to match, already in its decoded (plain) spelling.</param>
    private static int FindTopLevelValueStart(ReadOnlySpan<byte> json, ReadOnlySpan<byte> decodedName)
    {
        int pos = 0;
        SkipWhitespace(json, ref pos);

        if(pos < json.Length && json[pos] == (byte)'{')
        {
            pos++;
        }

        int depth = 0;

        while(pos < json.Length)
        {
            byte current = json[pos];
            if(current == (byte)'"')
            {
                int nameStart = pos + 1;
                int afterName = SkipString(json, pos);
                if(depth == 0 && afterName >= 1 && IsKeyPosition(json, afterName))
                {
                    int nameLength = afterName - 1 - nameStart;
                    if(DecodedContentEqualsPlain(json, nameStart, nameLength, decodedName))
                    {
                        return SkipWhitespaceAndColon(json, afterName);
                    }
                }

                pos = afterName;
                continue;
            }

            if(current is ((byte)'{') or ((byte)'['))
            {
                depth++;
            }
            else if(current is ((byte)'}') or ((byte)']'))
            {
                depth--;
            }

            pos++;
        }

        return -1;
    }


    /// <summary>
    /// Compares an already-validated JSON string's raw (possibly escaped) content span against a
    /// plain, already-decoded UTF-8 literal — used for both a member NAME and a member string VALUE,
    /// including a caller-supplied <c>publicKeyUse</c> argument. Decodes the document side one UTF-16
    /// code unit at a time with <see cref="NameCursor"/>, the same decoder
    /// <see cref="IsWellFormedJsonDocument"/>'s duplicate-name check uses. The literal side is stepped
    /// through the very same cursor rather than writing a second decoder, but with JSON escape
    /// interpretation turned OFF: <paramref name="plainLiteral"/> is already decoded, so a backslash
    /// byte in it (however unlikely for a <c>use</c> value) is ordinary content, never a <c>\u0000</c>
    /// or <c>\n</c> introducer, and comparing it as an escape would make an argument compare equal to
    /// a document value it does not spell.
    /// </summary>
    /// <param name="json">The document the raw span was taken from.</param>
    /// <param name="start">The start of the raw span, immediately after its opening quote.</param>
    /// <param name="length">The length of the raw span, up to (not including) its closing quote.</param>
    /// <param name="plainLiteral">The plain, already-decoded UTF-8 literal to compare against.</param>
    private static bool DecodedContentEqualsPlain(ReadOnlySpan<byte> json, int start, int length, ReadOnlySpan<byte> plainLiteral)
    {
        NameCursor documentCursor = new(start, start + length);
        NameCursor literalCursor = new(0, plainLiteral.Length, decodeEscapes: false);

        while(true)
        {
            bool hasDocumentChar = documentCursor.TryReadNext(json, out char documentChar);
            bool hasLiteralChar = literalCursor.TryReadNext(plainLiteral, out char literalChar);
            if(hasDocumentChar != hasLiteralChar)
            {
                return false;
            }

            if(!hasDocumentChar)
            {
                return true;
            }

            if(documentChar != literalChar)
            {
                return false;
            }
        }
    }


    /// <summary>
    /// Locates the content start of a JWK Set's <c>keys</c> array — the byte immediately after its
    /// opening <c>[</c> — or -1 when the <c>keys</c> member is absent or is not an array.
    /// </summary>
    /// <param name="json">The JWK Set document, already confirmed well formed.</param>
    private static int FindKeysArrayContentStart(ReadOnlySpan<byte> json)
    {
        int keysStart = IndexOfKey(json, WellKnownJwkMemberNames.KeysUtf8);
        if(keysStart < 0)
        {
            return -1;
        }

        int afterKeysKey = keysStart + WellKnownJwkMemberNames.KeysUtf8.Length + 1;
        afterKeysKey = SkipWhitespaceAndColon(json, afterKeysKey);
        if(afterKeysKey < 0 || afterKeysKey >= json.Length || json[afterKeysKey] != (byte)'[')
        {
            return -1;
        }

        return afterKeysKey + 1;
    }


    /// <summary>
    /// Returns the index one past the <c>}</c> that closes the object opening at
    /// <paramref name="objectStart"/>, or -1 when the braces never balance. String content is skipped
    /// so a brace inside a quoted value never biases the depth counter.
    /// </summary>
    /// <param name="json">The document being scanned.</param>
    /// <param name="objectStart">The index of the object's opening <c>{</c>.</param>
    private static int FindJwkObjectEnd(ReadOnlySpan<byte> json, int objectStart)
    {
        int depth = 1;
        int pos = objectStart + 1;

        while(pos < json.Length && depth > 0)
        {
            byte current = json[pos];
            if(current == (byte)'{')
            {
                depth++;
            }
            else if(current == (byte)'}')
            {
                depth--;
            }
            else if(current == (byte)'"')
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
            }

            pos++;
        }

        return depth == 0 ? pos : -1;
    }


    /// <summary>Whether <paramref name="value"/> separates elements of a <c>keys</c> array: whitespace or a comma.</summary>
    /// <param name="value">The byte to test.</param>
    private static bool IsJwkArraySeparator(byte value) =>
        value is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or (byte)',';


    /// <summary>Extracts every top-level string-valued member of one JWK object.</summary>
    /// <param name="jwkObject">The UTF-8 bytes of one JWK object, braces included.</param>
    private static Dictionary<string, string> ExtractJwkStringMembers(ReadOnlySpan<byte> jwkObject)
    {
        List<string> names = GetTopLevelKeyNames(jwkObject);
        Dictionary<string, string> members = new(names.Count, StringComparer.Ordinal);
        foreach(string name in names)
        {
            string? value = ExtractStringValue(jwkObject, Encoding.UTF8.GetBytes(name));
            if(value is not null)
            {
                members[name] = value;
            }
        }

        return members;
    }


    /// <summary>
    /// Extracts every top-level string-valued member of one JWK object with its member NAME decoded,
    /// for a <see cref="JwkSelectionOutcome.Selected"/> result from the filtered overloads
    /// (<see cref="SelectKeyByKeyId(ReadOnlySpan{byte}, string?, ReadOnlySpan{byte})"/> and
    /// <see cref="SelectSoleKey(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>): a key matched through an
    /// escaped <c>kid</c> or <c>kty</c> spelling hands its consumer the plain <c>kid</c>/<c>kty</c>
    /// key, not the escaped one. Unlike <see cref="ExtractJwkStringMembers"/> — the unfiltered
    /// selectors' unchanged extraction, which keys its dictionary by the member's undecoded document
    /// spelling — this walks the object once, decoding each top-level name as it goes rather than
    /// re-searching the object by a re-encoded name.
    /// </summary>
    /// <param name="jwkObject">The UTF-8 bytes of one JWK object, braces included.</param>
    private static Dictionary<string, string> ExtractJwkStringMembersDecoded(ReadOnlySpan<byte> jwkObject)
    {
        Dictionary<string, string> members = new(StringComparer.Ordinal);

        int pos = 0;
        SkipWhitespace(jwkObject, ref pos);
        if(pos < jwkObject.Length && jwkObject[pos] == (byte)'{')
        {
            pos++;
        }

        int depth = 0;

        while(pos < jwkObject.Length)
        {
            byte current = jwkObject[pos];
            if(current == (byte)'"')
            {
                int nameStart = pos + 1;
                int afterName = SkipString(jwkObject, pos);
                if(depth == 0 && afterName >= 1 && IsKeyPosition(jwkObject, afterName))
                {
                    int nameLength = afterName - 1 - nameStart;
                    string decodedName = DecodeContentToString(jwkObject, nameStart, nameLength);
                    int valueStart = SkipWhitespaceAndColon(jwkObject, afterName);
                    if(valueStart >= 0 && valueStart < jwkObject.Length && jwkObject[valueStart] == (byte)'"')
                    {
                        string? value = ExtractStringAt(jwkObject, valueStart + 1);
                        if(value is not null)
                        {
                            members[decodedName] = value;
                        }
                    }
                }

                pos = afterName;
                continue;
            }

            if(current is ((byte)'{') or ((byte)'['))
            {
                depth++;
            }
            else if(current is ((byte)'}') or ((byte)']'))
            {
                depth--;
            }

            pos++;
        }

        return members;
    }


    /// <summary>
    /// Decodes an already-validated JSON string's raw content span into a <see cref="string"/>, one
    /// UTF-16 code unit at a time via <see cref="NameCursor"/> — the materializing counterpart of
    /// <see cref="DecodedContentEqualsPlain"/> and <see cref="DecodedContentEqualsString"/>, used where
    /// the decoded spelling itself, not just a comparison against it, is the answer a caller needs.
    /// </summary>
    /// <param name="json">The document the raw span was taken from.</param>
    /// <param name="start">The start of the raw span, immediately after its opening quote.</param>
    /// <param name="length">The length of the raw span, up to (not including) its closing quote.</param>
    private static string DecodeContentToString(ReadOnlySpan<byte> json, int start, int length)
    {
        NameCursor cursor = new(start, start + length);
        StringBuilder builder = new(length);
        while(cursor.TryReadNext(json, out char next))
        {
            _ = builder.Append(next);
        }

        return builder.ToString();
    }
}
