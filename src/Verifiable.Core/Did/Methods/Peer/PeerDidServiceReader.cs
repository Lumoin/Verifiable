using System;
using System.Collections.Generic;
using System.Text;
using Verifiable.Core.Model.Did;

namespace Verifiable.Core.Did.Methods.Peer;

/// <summary>
/// Span-based, zero-allocation reader for the abbreviated service block of a
/// <c>did:peer:2</c> identifier. A service element is base64url-decoded into a small
/// JSON object whose key names and the <c>DIDCommMessaging</c> type are abbreviated per the
/// <see href="https://identity.foundation/peer-did-method-spec/#generating-a-didpeer2">Peer DID
/// Method specification</see> lookup tables: <c>t</c>→<c>type</c>, <c>dm</c>→<c>DIDCommMessaging</c>,
/// <c>s</c>→<c>serviceEndpoint</c>, <c>a</c>→<c>accept</c>, <c>r</c>→<c>routingKeys</c>.
/// </summary>
/// <remarks>
/// <para>
/// Operates directly on UTF-8 byte spans without allocating intermediate buffers or depending on a
/// JSON serialisation library, so it is usable from <see cref="Verifiable.Core"/> which keeps
/// <c>System.Text.Json</c> out of its own source. It scans only the subset of JSON the peer DID
/// service block uses: string-valued properties, string arrays, and one level of object nesting
/// (the <c>serviceEndpoint</c> object). The DID-method abbreviation expansion is peer-specific
/// semantics owned here rather than in a general JSON layer.
/// </para>
/// <para>
/// The default <c>#service</c> / <c>#service-N</c> identifier is NOT assigned here because it
/// depends on the position of an id-less service among all services in the DID; the resolver
/// assigns it. Only an <c>id</c> carried explicitly in the JSON is set on the returned service.
/// </para>
/// </remarks>
internal static class PeerDidServiceReader
{
    /// <summary>
    /// Reads one base64url-decoded peer DID service block into a <see cref="Service"/>, expanding
    /// the abbreviated key names and the <c>dm</c> type value.
    /// </summary>
    /// <param name="json">The UTF-8 JSON bytes of a single decoded service element.</param>
    /// <param name="service">
    /// On success, the parsed service with its type, endpoint, and an explicit id when present.
    /// The id-less default (<c>#service</c>/<c>#service-N</c>) is left for the caller to assign.
    /// </param>
    /// <returns>
    /// <see langword="true"/> when the block is a well-formed object carrying a service type;
    /// <see langword="false"/> when the bytes are not a JSON object or no type is present.
    /// </returns>
    public static bool TryRead(ReadOnlySpan<byte> json, out Service? service)
    {
        service = null;

        //A service block must be a JSON object. The type ("t", or the already-expanded
        //"type") is mandatory: the abbreviation table exists to carry a service type.
        string? type = ReadStringValue(json, "t"u8) ?? ReadStringValue(json, "type"u8);
        if(type is null)
        {
            return false;
        }

        Service parsed = new()
        {
            Type = ExpandType(type)
        };

        string? id = ReadStringValue(json, "id"u8);
        if(id is not null)
        {
            //The id comes from the (attacker-controlled) service JSON; an id that is neither an
            //absolute DID URL nor a fragment reference makes the service block malformed. Fail
            //closed here so the resolver surfaces it as InvalidDid rather than throwing.
            if(!DidUrl.TryParse(id, out DidUrl? parsedId))
            {
                return false;
            }

            parsed.Id = parsedId;
        }

        //The serviceEndpoint ("s", or the expanded "serviceEndpoint") is either a bare string URL
        //or a structured object. A DIDCommMessaging endpoint is an object carrying uri/accept/
        //routingKeys; other service types may use a plain string.
        string? endpointString = ReadStringValue(json, "s"u8) ?? ReadStringValue(json, "serviceEndpoint"u8);
        if(endpointString is not null)
        {
            parsed.ServiceEndpoint = endpointString;
            service = parsed;

            return true;
        }

        ReadOnlySpan<byte> endpointObject = SliceObjectValue(json, "s"u8);
        if(endpointObject.IsEmpty)
        {
            endpointObject = SliceObjectValue(json, "serviceEndpoint"u8);
        }

        if(!endpointObject.IsEmpty)
        {
            Dictionary<string, object> endpointMap = new(StringComparer.Ordinal);

            string? uri = ReadStringValue(endpointObject, "uri"u8);
            if(uri is not null)
            {
                endpointMap["uri"] = uri;
            }

            List<string>? accept = ReadStringArray(endpointObject, "a"u8) ?? ReadStringArray(endpointObject, "accept"u8);
            if(accept is not null)
            {
                endpointMap["accept"] = accept;
            }

            List<string>? routingKeys = ReadStringArray(endpointObject, "r"u8) ?? ReadStringArray(endpointObject, "routingKeys"u8);
            if(routingKeys is not null)
            {
                endpointMap["routingKeys"] = routingKeys;
            }

            if(endpointMap.Count > 0)
            {
                parsed.ServiceEndpointMap = endpointMap;
            }
        }

        service = parsed;

        return true;
    }


    //Expands the abbreviated DIDCommMessaging type value. Any other type is carried verbatim,
    //which preserves a full type a producer may have spelled out (the abbreviation table only
    //defines a common string for DIDCommMessaging).
    private static string ExpandType(string type) => type switch
    {
        "dm" => "DIDCommMessaging",
        _ => type
    };


    //Reads the string value of a top-level property, or null when the key is absent or its value
    //is not a string. Mirrors the scanning discipline of the JOSE-domain JwkJsonReader.
    private static string? ReadStringValue(ReadOnlySpan<byte> json, ReadOnlySpan<byte> key)
    {
        int keyStart = IndexOfKey(json, key);
        if(keyStart < 0)
        {
            return null;
        }

        int afterKey = SkipWhitespaceAndColon(json, keyStart + key.Length + 1);
        if(afterKey < 0 || afterKey >= json.Length || json[afterKey] != (byte)'"')
        {
            return null;
        }

        return ExtractStringAt(json, afterKey + 1);
    }


    //Reads a top-level array of strings, or null when the key is absent or its value is not an
    //array. A well-formed empty array yields an empty list; a non-string element is a structural
    //error and surfaces as null.
    private static List<string>? ReadStringArray(ReadOnlySpan<byte> json, ReadOnlySpan<byte> key)
    {
        int keyStart = IndexOfKey(json, key);
        if(keyStart < 0)
        {
            return null;
        }

        int afterKey = SkipWhitespaceAndColon(json, keyStart + key.Length + 1);
        if(afterKey < 0 || afterKey >= json.Length || json[afterKey] != (byte)'[')
        {
            return null;
        }

        List<string> result = [];
        int cursor = afterKey + 1;

        while(cursor < json.Length)
        {
            while(cursor < json.Length && (IsJsonWhitespace(json[cursor]) || json[cursor] == (byte)','))
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
                return null;
            }

            string? value = ExtractStringAt(json, cursor + 1);
            if(value is null)
            {
                return null;
            }

            result.Add(value);
            cursor = SkipString(json, cursor);
        }

        return null;
    }


    //Returns the full object value (braces included) of a top-level property as a sub-span, or an
    //empty span when the key is absent or its value is not an object. Quotes inside strings are
    //skipped so braces in a value do not bias the depth counter.
    private static ReadOnlySpan<byte> SliceObjectValue(ReadOnlySpan<byte> json, ReadOnlySpan<byte> key)
    {
        int keyStart = IndexOfKey(json, key);
        if(keyStart < 0)
        {
            return default;
        }

        int afterKey = SkipWhitespaceAndColon(json, keyStart + key.Length + 1);
        if(afterKey < 0 || afterKey >= json.Length || json[afterKey] != (byte)'{')
        {
            return default;
        }

        int depth = 1;
        int pos = afterKey + 1;
        while(pos < json.Length && depth > 0)
        {
            byte b = json[pos];
            if(b == (byte)'"')
            {
                pos = SkipString(json, pos);

                continue;
            }

            if(b == (byte)'{')
            {
                depth++;
            }
            else if(b == (byte)'}')
            {
                depth--;
            }

            pos++;
        }

        if(depth != 0)
        {
            return default;
        }

        return json[afterKey..pos];
    }


    //Returns the offset of the first byte of the key name (after its opening quote) for a property
    //at object depth 0, or -1. A leading '{' (a full-object span) is consumed so members sit at
    //depth 0; an inner-content span already starts at a member. A same-named key nested deeper sits
    //at depth > 0 and cannot shadow the top-level lookup.
    private static int IndexOfKey(ReadOnlySpan<byte> json, ReadOnlySpan<byte> key)
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
        while(pos < json.Length)
        {
            byte b = json[pos];
            if(b == (byte)'"')
            {
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


    //Given the offset of an opening quote, returns the offset one past the closing quote, honoring
    //backslash escapes so an escaped quote does not end the string early.
    private static int SkipString(ReadOnlySpan<byte> json, int quotePos)
    {
        int pos = quotePos + 1;
        while(pos < json.Length && json[pos] != (byte)'"')
        {
            if(json[pos] == (byte)'\\' && pos + 1 < json.Length)
            {
                pos++;
            }

            pos++;
        }

        return pos + 1;
    }


    //Reports whether the byte at pos begins a value-position colon for a key just read, i.e. after
    //optional whitespace the next byte is ':'.
    private static bool IsKeyPosition(ReadOnlySpan<byte> json, int pos)
    {
        while(pos < json.Length && IsJsonWhitespace(json[pos]))
        {
            pos++;
        }

        return pos < json.Length && json[pos] == (byte)':';
    }


    //Skips whitespace, requires a colon, then skips trailing whitespace; returns the value offset
    //or -1 when no colon follows.
    private static int SkipWhitespaceAndColon(ReadOnlySpan<byte> json, int pos)
    {
        while(pos < json.Length && IsJsonWhitespace(json[pos]))
        {
            pos++;
        }

        if(pos >= json.Length || json[pos] != (byte)':')
        {
            return -1;
        }

        pos++;
        while(pos < json.Length && IsJsonWhitespace(json[pos]))
        {
            pos++;
        }

        return pos;
    }


    //Reads the UTF-8 string starting at the first byte inside the quotes, up to the next unescaped
    //closing quote, decoding RFC 8259 §7 escapes only when a backslash is present.
    private static string? ExtractStringAt(ReadOnlySpan<byte> json, int start)
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
        if(raw.IndexOf((byte)'\\') < 0)
        {
            return Encoding.UTF8.GetString(raw);
        }

        return DecodeJsonStringEscapes(Encoding.UTF8.GetString(raw));
    }


    //Decodes the JSON string escape sequences of RFC 8259 §7 in an already-UTF-8-decoded value. A
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
            char digit = value[start + offset];
            int nibble = digit switch
            {
                >= '0' and <= '9' => digit - '0',
                >= 'a' and <= 'f' => digit - 'a' + 10,
                >= 'A' and <= 'F' => digit - 'A' + 10,
                _ => -1
            };

            if(nibble < 0)
            {
                return false;
            }

            code = (code << 4) | nibble;
        }

        result = (char)code;

        return true;
    }


    private static bool IsJsonWhitespace(byte b) =>
        b == (byte)' ' || b == (byte)'\t' || b == (byte)'\r' || b == (byte)'\n';
}
