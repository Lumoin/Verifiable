using System;
using System.Collections.Generic;
using System.Text.Json;
using Verifiable.WebFinger;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> parser for a WebFinger JSON Resource Descriptor (JRD), per
/// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4">RFC 7033 §4.4</see> — the JSON side the
/// <c>Verifiable.WebFinger</c> serialization firewall keeps out of the library. Its
/// <see cref="ParseJrd"/> method matches the <see cref="WebFingerJrdDeserializer"/> delegate shape
/// exactly, so it can be assigned directly: <c>WebFingerJrdDeserializer d = WebFingerJrdJsonParsing.ParseJrd;</c>.
/// This is the parser both the WebFinger client's shipped resolve path
/// (<see cref="Verifiable.WebFinger.WebFingerClient.BuildResolving"/>) and a firewalled cross-wire test
/// wire up.
/// </summary>
/// <remarks>
/// <para>
/// Reads directly off a <see cref="Utf8JsonReader"/> positioned over the supplied span — no intermediate
/// <see cref="JsonDocument"/> buffering, so a fetched JRD is parsed without copying it first. A known
/// member of the wrong shape is a parse failure (faithful, strict) and yields <see langword="null"/>; any
/// member this type does not recognise is skipped via <see cref="Utf8JsonReader.Skip"/>, satisfying
/// §4.4's "a client MUST ignore any members ... that it does not understand" by construction — the
/// resulting <see cref="JsonResourceDescriptor"/> carries only the members RFC 7033 specifies. Never
/// throws to the caller.
/// </para>
/// <para>
/// The <c>properties</c> member (§4.4.3) and a link's <c>properties</c> member (§4.4.4.5) preserve a JSON
/// <c>null</c> value distinctly from an absent member: the key is retained in the resulting map with a
/// <see langword="null"/> CLR value rather than being dropped.
/// </para>
/// </remarks>
public static class WebFingerJrdJsonParsing
{
    /// <summary>
    /// Bounds JSON nesting depth for an untrusted, network-fetched JRD. JRDs are shallow by
    /// specification (an object with a links array of flat objects), so 32 is generous while still
    /// capping recursion depth at parse time.
    /// </summary>
    private static JsonReaderOptions ReaderOptions { get; } = new() { MaxDepth = 32 };


    /// <summary>
    /// Parses a JSON Resource Descriptor. Returns <see langword="null"/> on any structural or
    /// conformance failure — malformed JSON, a non-object root, or a known member of the wrong shape.
    /// </summary>
    /// <param name="jrdJsonUtf8">The fetched JRD as UTF-8 JSON bytes.</param>
    public static JsonResourceDescriptor? ParseJrd(ReadOnlySpan<byte> jrdJsonUtf8)
    {
        try
        {
            Utf8JsonReader reader = new(jrdJsonUtf8, ReaderOptions);
            if(!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                return null;
            }

            string? subject = null;
            List<string> aliases = [];
            Dictionary<string, string?> properties = new(StringComparer.Ordinal);
            List<WebFingerLink> links = [];

            while(reader.Read())
            {
                if(reader.TokenType == JsonTokenType.EndObject)
                {
                    break;
                }

                if(reader.TokenType != JsonTokenType.PropertyName)
                {
                    return null;
                }

                string memberName = reader.GetString()!;
                if(!reader.Read())
                {
                    return null;
                }

                if(string.Equals(memberName, WellKnownJrdMemberNames.Subject, StringComparison.Ordinal))
                {
                    if(reader.TokenType != JsonTokenType.String) { return null; }
                    subject = reader.GetString();
                }
                else if(string.Equals(memberName, WellKnownJrdMemberNames.Aliases, StringComparison.Ordinal))
                {
                    if(!TryReadStringArray(ref reader, aliases)) { return null; }
                }
                else if(string.Equals(memberName, WellKnownJrdMemberNames.Properties, StringComparison.Ordinal))
                {
                    if(!TryReadNullableStringMap(ref reader, properties)) { return null; }
                }
                else if(string.Equals(memberName, WellKnownJrdMemberNames.Links, StringComparison.Ordinal))
                {
                    if(!TryReadLinks(ref reader, links)) { return null; }
                }
                else
                {
                    //§4.4: an unrecognised member MUST be ignored, not treated as an error.
                    reader.Skip();
                }
            }

            if(reader.TokenType != JsonTokenType.EndObject)
            {
                return null;
            }

            return new JsonResourceDescriptor
            {
                Subject = subject,
                Aliases = aliases,
                Properties = properties,
                Links = links
            };
        }
        catch(Exception ex) when(IsParseFailure(ex))
        {
            return null;
        }
    }


    /// <summary>
    /// Reads a JSON array of strings — the reader positioned at its opening token — into
    /// <paramref name="destination"/>, in order.
    /// </summary>
    private static bool TryReadStringArray(ref Utf8JsonReader reader, List<string> destination)
    {
        if(reader.TokenType != JsonTokenType.StartArray)
        {
            return false;
        }

        while(reader.Read() && reader.TokenType != JsonTokenType.EndArray)
        {
            if(reader.TokenType != JsonTokenType.String)
            {
                return false;
            }

            destination.Add(reader.GetString()!);
        }

        return reader.TokenType == JsonTokenType.EndArray;
    }


    /// <summary>
    /// Reads a JSON object of string-or-null values — the §4.4.3 <c>properties</c> shape, reader
    /// positioned at its opening token — into <paramref name="destination"/>, preserving a JSON
    /// <c>null</c> value distinctly from an absent member.
    /// </summary>
    private static bool TryReadNullableStringMap(ref Utf8JsonReader reader, Dictionary<string, string?> destination)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            return false;
        }

        while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            if(reader.TokenType != JsonTokenType.PropertyName)
            {
                return false;
            }

            string name = reader.GetString()!;
            if(!reader.Read())
            {
                return false;
            }

            if(reader.TokenType == JsonTokenType.Null)
            {
                destination[name] = null;
            }
            else if(reader.TokenType == JsonTokenType.String)
            {
                destination[name] = reader.GetString();
            }
            else
            {
                return false;
            }
        }

        return reader.TokenType == JsonTokenType.EndObject;
    }


    /// <summary>
    /// Reads a JSON object of string values — the §4.4.4.4 <c>titles</c> shape, reader positioned at its
    /// opening token — into <paramref name="destination"/>.
    /// </summary>
    private static bool TryReadStringMap(ref Utf8JsonReader reader, Dictionary<string, string> destination)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            return false;
        }

        while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            if(reader.TokenType != JsonTokenType.PropertyName)
            {
                return false;
            }

            string name = reader.GetString()!;
            if(!reader.Read() || reader.TokenType != JsonTokenType.String)
            {
                return false;
            }

            //§4.4.4.4 SHOULD NOT repeat a language tag; last value wins if the source did — a Dictionary
            //key can hold only one value regardless, making the guidance structural on read.
            destination[name] = reader.GetString()!;
        }

        return reader.TokenType == JsonTokenType.EndObject;
    }


    /// <summary>
    /// Reads the §4.4.4 <c>links</c> array — the reader positioned at its opening token — into
    /// <paramref name="destination"/>. A link relation object missing its required <c>rel</c>
    /// (§4.4.4.1) is dropped rather than failing the whole document.
    /// </summary>
    private static bool TryReadLinks(ref Utf8JsonReader reader, List<WebFingerLink> destination)
    {
        if(reader.TokenType != JsonTokenType.StartArray)
        {
            return false;
        }

        while(reader.Read() && reader.TokenType != JsonTokenType.EndArray)
        {
            if(reader.TokenType != JsonTokenType.StartObject)
            {
                return false;
            }

            if(!TryReadLink(ref reader, out WebFingerLink? link))
            {
                return false;
            }

            if(link is not null)
            {
                destination.Add(link);
            }
        }

        return reader.TokenType == JsonTokenType.EndArray;
    }


    /// <summary>
    /// Reads one §4.4.4 link relation object — the reader positioned at its opening token. Succeeds with
    /// <paramref name="link"/> set to <see langword="null"/> when the object is well-formed JSON but
    /// carries no <c>rel</c> (§4.4.4.1 MUST), so the caller drops it rather than failing the document.
    /// </summary>
    private static bool TryReadLink(ref Utf8JsonReader reader, out WebFingerLink? link)
    {
        link = null;

        string? rel = null;
        string? type = null;
        string? href = null;
        Dictionary<string, string> titles = new(StringComparer.Ordinal);
        Dictionary<string, string?> properties = new(StringComparer.Ordinal);

        while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            if(reader.TokenType != JsonTokenType.PropertyName)
            {
                return false;
            }

            string memberName = reader.GetString()!;
            if(!reader.Read())
            {
                return false;
            }

            if(string.Equals(memberName, WellKnownJrdMemberNames.Rel, StringComparison.Ordinal))
            {
                if(reader.TokenType != JsonTokenType.String) { return false; }
                rel = reader.GetString();
            }
            else if(string.Equals(memberName, WellKnownJrdMemberNames.Type, StringComparison.Ordinal))
            {
                if(reader.TokenType != JsonTokenType.String) { return false; }
                type = reader.GetString();
            }
            else if(string.Equals(memberName, WellKnownJrdMemberNames.Href, StringComparison.Ordinal))
            {
                if(reader.TokenType != JsonTokenType.String) { return false; }
                href = reader.GetString();
            }
            else if(string.Equals(memberName, WellKnownJrdMemberNames.Titles, StringComparison.Ordinal))
            {
                if(!TryReadStringMap(ref reader, titles)) { return false; }
            }
            else if(string.Equals(memberName, WellKnownJrdMemberNames.Properties, StringComparison.Ordinal))
            {
                if(!TryReadNullableStringMap(ref reader, properties)) { return false; }
            }
            else
            {
                //§4.4: an unrecognised member MUST be ignored, not treated as an error.
                reader.Skip();
            }
        }

        if(reader.TokenType != JsonTokenType.EndObject)
        {
            return false;
        }

        if(string.IsNullOrEmpty(rel))
        {
            return true;
        }

        link = new WebFingerLink
        {
            Rel = rel,
            Type = type,
            Href = href,
            Titles = titles,
            Properties = properties
        };

        return true;
    }


    /// <summary>
    /// Whether <paramref name="ex"/> is a recognised JSON-parse failure this parser turns into a
    /// <see langword="null"/> result rather than propagating.
    /// </summary>
    private static bool IsParseFailure(Exception ex) =>
        ex is JsonException or InvalidOperationException or FormatException or ArgumentOutOfRangeException;
}
