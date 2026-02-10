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
                    values = JsonSerializer.Deserialize<List<string>>(ref reader, options);
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
        JsonSerializer.Serialize(writer, value.Values, options);

        writer.WriteEndObject();
    }
}