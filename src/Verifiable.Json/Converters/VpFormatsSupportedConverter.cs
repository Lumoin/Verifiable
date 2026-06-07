using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.OAuth.Oid4Vp;

namespace Verifiable.Json.Converters;

/// <summary>
/// Converts a <see cref="VpFormatsSupported"/> to and from its OID4VP 1.0 §11.1 wire
/// shape: a bare JSON object mapping each credential format identifier to a map of
/// format-specific algorithm properties.
/// </summary>
/// <remarks>
/// The C# type wraps the map in a single <see cref="VpFormatsSupported.Formats"/>
/// property; this converter writes and reads the map directly so the wrapper name
/// never leaks onto the wire. The format-identifier and algorithm-property keys are
/// protocol tokens (for example <c>dc+sd-jwt</c>, <c>sd-jwt_alg_values</c>) and are
/// written verbatim — no naming policy is applied to them.
/// </remarks>
public sealed class VpFormatsSupportedConverter: JsonConverter<VpFormatsSupported>
{
    /// <inheritdoc/>
    [return: NotNull]
    public override VpFormatsSupported Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException($"Expected StartObject for vp_formats_supported but got {reader.TokenType}.");
        }

        var formats = new Dictionary<string, IReadOnlyDictionary<string, IReadOnlyList<string>>>(StringComparer.Ordinal);

        while(reader.Read())
        {
            if(reader.TokenType == JsonTokenType.EndObject)
            {
                break;
            }

            if(reader.TokenType != JsonTokenType.PropertyName)
            {
                throw new JsonException($"Expected PropertyName but got {reader.TokenType}.");
            }

            string formatId = reader.GetString()!;
            reader.Read();
            formats[formatId] = ReadPropertyMap(ref reader);
        }

        return new VpFormatsSupported(formats);
    }


    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, VpFormatsSupported value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        writer.WriteStartObject();

        foreach(KeyValuePair<string, IReadOnlyDictionary<string, IReadOnlyList<string>>> format in value.Formats)
        {
            writer.WritePropertyName(format.Key);
            writer.WriteStartObject();

            foreach(KeyValuePair<string, IReadOnlyList<string>> property in format.Value)
            {
                writer.WritePropertyName(property.Key);
                writer.WriteStartArray();
                foreach(string algorithm in property.Value)
                {
                    writer.WriteStringValue(algorithm);
                }

                writer.WriteEndArray();
            }

            writer.WriteEndObject();
        }

        writer.WriteEndObject();
    }


    private static Dictionary<string, IReadOnlyList<string>> ReadPropertyMap(ref Utf8JsonReader reader)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException($"Expected StartObject for a vp_formats_supported entry but got {reader.TokenType}.");
        }

        var map = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);

        while(reader.Read())
        {
            if(reader.TokenType == JsonTokenType.EndObject)
            {
                break;
            }

            if(reader.TokenType != JsonTokenType.PropertyName)
            {
                throw new JsonException($"Expected PropertyName but got {reader.TokenType}.");
            }

            string property = reader.GetString()!;
            reader.Read();
            map[property] = ReadStringArray(ref reader);
        }

        return map;
    }


    private static List<string> ReadStringArray(ref Utf8JsonReader reader)
    {
        if(reader.TokenType != JsonTokenType.StartArray)
        {
            throw new JsonException($"Expected StartArray but got {reader.TokenType}.");
        }

        var list = new List<string>();

        while(reader.Read())
        {
            if(reader.TokenType == JsonTokenType.EndArray)
            {
                break;
            }

            if(reader.TokenType != JsonTokenType.String)
            {
                throw new JsonException($"Expected String but got {reader.TokenType}.");
            }

            list.Add(reader.GetString()!);
        }

        return list;
    }
}
