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
                    vctValues = JsonSerializer.Deserialize<List<string>>(ref reader, options);
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
            JsonSerializer.Serialize(writer, value.VctValues, options);
        }

        writer.WriteEndObject();
    }
}