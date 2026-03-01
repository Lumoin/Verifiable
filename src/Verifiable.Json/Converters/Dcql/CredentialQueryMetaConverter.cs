using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Dcql;

namespace Verifiable.Json.Converters.Dcql;

/// <summary>
/// Converts a <see cref="CredentialQueryMeta"/> to and from JSON, handling
/// the format-specific metadata properties from their snake_case JSON representation.
/// </summary>
public sealed class CredentialQueryMetaConverter: JsonConverter<CredentialQueryMeta>
{
    /// <inheritdoc/>
    [return: NotNull]
    public override CredentialQueryMeta Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            JsonThrowHelper.ThrowJsonException();
        }

        string? doctypeValue = null;
        List<string>? vctValues = null;

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
                case CredentialQueryMeta.DoctypeValuePropertyName:
                {
                    doctypeValue = reader.GetString();
                    break;
                }
                case CredentialQueryMeta.VctValuesPropertyName:
                {
                    vctValues = ReadStringArray(ref reader);
                    break;
                }
                default:
                {
                    reader.Skip();
                    break;
                }
            }
        }

        return new CredentialQueryMeta
        {
            DoctypeValue = doctypeValue,
            VctValues = vctValues
        };
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, CredentialQueryMeta value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        writer.WriteStartObject();

        if(value.DoctypeValue is not null)
        {
            writer.WriteString(CredentialQueryMeta.DoctypeValuePropertyName, value.DoctypeValue);
        }

        if(value.VctValues is not null)
        {
            writer.WritePropertyName(CredentialQueryMeta.VctValuesPropertyName);
            writer.WriteStartArray();
            foreach(var vct in value.VctValues)
            {
                writer.WriteStringValue(vct);
            }

            writer.WriteEndArray();
        }

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