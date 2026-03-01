using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Dcql;

namespace Verifiable.Json.Converters.Dcql;

/// <summary>
/// Converts a <see cref="CredentialSetQuery"/> to and from JSON, mapping
/// the credential set query properties from their snake_case JSON representation.
/// </summary>
public sealed class CredentialSetQueryConverter: JsonConverter<CredentialSetQuery>
{
    /// <inheritdoc/>
    [return: NotNull]
    public override CredentialSetQuery Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            JsonThrowHelper.ThrowJsonException();
        }

        List<IReadOnlyList<string>>? queryOptions = null;
        bool required = true;
        string? purpose = null;

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
                case CredentialSetQuery.OptionsPropertyName:
                {
                    queryOptions = ReadNestedStringArrays(ref reader);
                    break;
                }
                case CredentialSetQuery.RequiredPropertyName:
                {
                    required = reader.GetBoolean();
                    break;
                }
                case CredentialSetQuery.PurposePropertyName:
                {
                    purpose = reader.GetString();
                    break;
                }
                default:
                {
                    reader.Skip();
                    break;
                }
            }
        }

        if(queryOptions is null || queryOptions.Count == 0)
        {
            throw new JsonException("The 'options' property is required and must not be empty.");
        }

        return new CredentialSetQuery
        {
            Options = queryOptions,
            Required = required,
            Purpose = purpose
        };
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, CredentialSetQuery value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        writer.WriteStartObject();

        writer.WritePropertyName(CredentialSetQuery.OptionsPropertyName);
        writer.WriteStartArray();
        foreach(var option in value.Options)
        {
            writer.WriteStartArray();
            foreach(var item in option)
            {
                writer.WriteStringValue(item);
            }

            writer.WriteEndArray();
        }

        writer.WriteEndArray();

        if(!value.Required)
        {
            writer.WriteBoolean(CredentialSetQuery.RequiredPropertyName, false);
        }

        if(value.Purpose is not null)
        {
            writer.WriteString(CredentialSetQuery.PurposePropertyName, value.Purpose);
        }

        writer.WriteEndObject();
    }


    /// <summary>
    /// Reads a JSON array of string arrays manually without calling into <see cref="JsonSerializer"/>.
    /// </summary>
    private static List<IReadOnlyList<string>> ReadNestedStringArrays(ref Utf8JsonReader reader)
    {
        if(reader.TokenType != JsonTokenType.StartArray)
        {
            throw new JsonException("Expected an array for 'options'.");
        }

        var result = new List<IReadOnlyList<string>>();
        while(reader.Read())
        {
            if(reader.TokenType == JsonTokenType.EndArray)
            {
                break;
            }

            result.Add(ReadStringArray(ref reader));
        }

        return result;
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