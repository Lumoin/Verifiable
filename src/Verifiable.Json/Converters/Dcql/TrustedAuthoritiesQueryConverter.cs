using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Dcql;

namespace Verifiable.Json.Converters.Dcql;

/// <summary>
/// Converts a <see cref="TrustedAuthoritiesQuery"/> to and from JSON, mapping
/// the trusted authorities query properties from their snake_case JSON representation.
/// </summary>
public sealed class TrustedAuthoritiesQueryConverter: JsonConverter<TrustedAuthoritiesQuery>
{
    /// <inheritdoc/>
    [return: NotNull]
    public override TrustedAuthoritiesQuery Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            JsonThrowHelper.ThrowJsonException();
        }

        string? type = null;
        List<string>? values = null;

        while(reader.Read())
        {
            if(reader.TokenType == JsonTokenType.EndObject)
            {
                break;
            }

            if(reader.TokenType != JsonTokenType.PropertyName)
            {
                JsonThrowHelper.ThrowJsonException();
            }

            string propertyName = reader.GetString()!;
            reader.Read();

            switch(propertyName)
            {
                case TrustedAuthoritiesQuery.TypePropertyName:
                {
                    type = reader.GetString();
                    break;
                }
                case TrustedAuthoritiesQuery.ValuesPropertyName:
                {
                    values = ReadStringArray(ref reader);
                    break;
                }
                default:
                {
                    reader.Skip();
                    break;
                }
            }
        }

        if(type is null)
        {
            throw new JsonException("The 'type' property is required.");
        }

        return new TrustedAuthoritiesQuery
        {
            Type = type,
            Values = values ?? []
        };
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, TrustedAuthoritiesQuery value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        writer.WriteStartObject();

        writer.WriteString(TrustedAuthoritiesQuery.TypePropertyName, value.Type);

        writer.WritePropertyName(TrustedAuthoritiesQuery.ValuesPropertyName);
        writer.WriteStartArray();
        foreach(var item in value.Values)
        {
            writer.WriteStringValue(item);
        }

        writer.WriteEndArray();

        writer.WriteEndObject();
    }


    /// <summary>
    /// Reads a JSON array of strings manually without calling into <see cref="JsonSerializer"/>.
    /// </summary>
    private static List<string> ReadStringArray(ref Utf8JsonReader reader)
    {
        if(reader.TokenType != JsonTokenType.StartArray)
        {
            throw new JsonException("Expected StartArray for string array.");
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