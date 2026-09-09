using System;
using System.Collections.Generic;
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
            JsonThrowHelper.ThrowJsonException(
                $"Each 'trusted_authorities' entry must be a JSON object (OpenID for Verifiable Presentations 1.0, Section 6.1.1); got {reader.TokenType}.");
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
                case var name when DcqlParameterNames.IsType(name):
                {
                    if(reader.TokenType != JsonTokenType.String)
                    {
                        throw new JsonException(
                            "The 'type' property must be a string (OpenID for Verifiable Presentations 1.0, Section 6.1.1).");
                    }

                    type = reader.GetString();
                    break;
                }
                case var name when DcqlParameterNames.IsValues(name):
                {
                    values = ReadStringArray(ref reader, "values");
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
            throw new JsonException(
                "The 'type' property is required (OpenID for Verifiable Presentations 1.0, Section 6.1.1).");
        }

        if(values is null)
        {
            throw new JsonException(
                "The 'values' property is required (OpenID for Verifiable Presentations 1.0, Section 6.1.1).");
        }

        if(values.Count == 0)
        {
            throw new JsonException(
                "The 'values' property must be a non-empty array of strings (OpenID for Verifiable Presentations 1.0, Section 6.1.1).");
        }

        return new TrustedAuthoritiesQuery
        {
            Type = type,
            Values = values
        };
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, TrustedAuthoritiesQuery value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        writer.WriteStartObject();

        writer.WriteString(DcqlParameterNames.Type, value.Type);

        writer.WritePropertyName(DcqlParameterNames.Values);
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
    /// <param name="reader">The reader, positioned at the array's start token.</param>
    /// <param name="propertyName">The property name, for the exception message when an element is not a string.</param>
    private static List<string> ReadStringArray(ref Utf8JsonReader reader, string propertyName)
    {
        if(reader.TokenType != JsonTokenType.StartArray)
        {
            throw new JsonException(
                $"The '{propertyName}' property must be an array of strings (OpenID for Verifiable Presentations 1.0, Section 6.1.1); got {reader.TokenType}.");
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
                throw new JsonException(
                    $"Every element of the '{propertyName}' property must be a string (OpenID for Verifiable Presentations 1.0, Section 6.1.1); got {reader.TokenType}.");
            }

            list.Add(reader.GetString()!);
        }

        return list;
    }
}
