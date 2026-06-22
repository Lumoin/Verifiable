using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using Verifiable.Core.Model.Did;

namespace Verifiable.Core.Did.Methods.Peer;

/// <summary>
/// Writes the abbreviated service block of a <c>did:peer:2</c> service element — the inverse of the
/// resolution-side reader. The block is a closed format (the abbreviated DIDCommMessaging shape), so it is
/// produced directly here rather than through a JSON serializer: key names and the <c>DIDCommMessaging</c>
/// type value are abbreviated per the Peer DID Method lookup tables (<c>type</c>→<c>t</c>,
/// <c>DIDCommMessaging</c>→<c>dm</c>, <c>serviceEndpoint</c>→<c>s</c>, <c>accept</c>→<c>a</c>,
/// <c>routingKeys</c>→<c>r</c>) and string values are JSON-escaped.
/// </summary>
internal static class PeerDidServiceWriter
{
    /// <summary>
    /// Writes the compact, whitespace-free abbreviated JSON for a service, ready to be base64url-encoded
    /// into a <c>.S</c> element.
    /// </summary>
    public static string Write(Service service)
    {
        //The abbreviated format carries a single mandatory type and one endpoint (string or object). A
        //service that uses the multi-type, multi-endpoint, or extension carriers is unrepresentable here and
        //must be rejected rather than silently truncated.
        if(string.IsNullOrEmpty(service.Type))
        {
            throw new ArgumentException("A did:peer:2 service requires a single non-empty type.", nameof(service));
        }

        if(service.Types is { Count: > 0 })
        {
            throw new ArgumentException("A did:peer:2 service cannot express multiple types.", nameof(service));
        }

        if(service.ServiceEndpoints is { Count: > 0 })
        {
            throw new ArgumentException("A did:peer:2 service cannot express multiple endpoints.", nameof(service));
        }

        if(service.AdditionalData is { Count: > 0 })
        {
            throw new ArgumentException("A did:peer:2 service cannot express additional properties.", nameof(service));
        }

        StringBuilder builder = new();
        builder.Append("{\"t\":");
        AppendQuoted(builder, AbbreviateType(service.Type));

        if(service.ServiceEndpoint is not null)
        {
            builder.Append(",\"s\":");
            AppendQuoted(builder, service.ServiceEndpoint);
        }
        else if(service.ServiceEndpointMap is not null)
        {
            AppendEndpointMap(builder, service.ServiceEndpointMap);
        }

        //An explicit id is carried verbatim; an id-less service takes its positional default on resolution.
        if(service.Id is not null)
        {
            builder.Append(",\"id\":");
            AppendQuoted(builder, service.Id.ToString());
        }

        builder.Append('}');

        return builder.ToString();
    }


    //The abbreviated endpoint object preserves the lookup-table order: uri, then accept (a), then routingKeys (r).
    private static void AppendEndpointMap(StringBuilder builder, IDictionary<string, object> endpoint)
    {
        builder.Append(",\"s\":{");
        bool wrote = false;

        if(endpoint.TryGetValue("uri", out object? uri) && uri is string uriValue)
        {
            builder.Append("\"uri\":");
            AppendQuoted(builder, uriValue);
            wrote = true;
        }

        if(endpoint.TryGetValue("accept", out object? accept) && accept is IEnumerable<string> acceptValues)
        {
            wrote = AppendArray(builder, "\"a\":", acceptValues, wrote);
        }

        if(endpoint.TryGetValue("routingKeys", out object? routing) && routing is IEnumerable<string> routingValues)
        {
            AppendArray(builder, "\"r\":", routingValues, wrote);
        }

        builder.Append('}');
    }


    private static bool AppendArray(StringBuilder builder, string key, IEnumerable<string> values, bool needsLeadingComma)
    {
        if(needsLeadingComma)
        {
            builder.Append(',');
        }

        builder.Append(key).Append('[');
        bool first = true;
        foreach(string value in values)
        {
            if(!first)
            {
                builder.Append(',');
            }

            AppendQuoted(builder, value);
            first = false;
        }

        builder.Append(']');

        return true;
    }


    //The DIDCommMessaging common string is the only abbreviated type value; any other type is written verbatim.
    private static string AbbreviateType(string type) => type == "DIDCommMessaging" ? "dm" : type;


    //Writes a JSON string literal, escaping the RFC 8259 §7 mandatory characters.
    private static void AppendQuoted(StringBuilder builder, string value)
    {
        builder.Append('"');
        foreach(char character in value)
        {
            switch(character)
            {
                case '"':
                    builder.Append("\\\"");
                    break;
                case '\\':
                    builder.Append("\\\\");
                    break;
                case '\b':
                    builder.Append("\\b");
                    break;
                case '\f':
                    builder.Append("\\f");
                    break;
                case '\n':
                    builder.Append("\\n");
                    break;
                case '\r':
                    builder.Append("\\r");
                    break;
                case '\t':
                    builder.Append("\\t");
                    break;
                default:
                    if(character < ' ')
                    {
                        builder.Append("\\u").Append(((int)character).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        builder.Append(character);
                    }

                    break;
            }
        }

        builder.Append('"');
    }
}
