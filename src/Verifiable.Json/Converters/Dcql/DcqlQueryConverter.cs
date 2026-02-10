using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Dcql;

namespace Verifiable.Json.Converters.Dcql;

/// <summary>
/// Converts a <see cref="DcqlQuery"/> to and from JSON using the snake_case
/// property naming convention defined by the DCQL specification.
/// </summary>
public sealed class DcqlQueryConverter: JsonConverter<DcqlQuery>
{
    /// <inheritdoc/>
    [return: NotNull]
    public override DcqlQuery Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            JsonThrowHelper.ThrowJsonException();
        }

        List<CredentialQuery>? credentials = null;
        List<CredentialSetQuery>? credentialSets = null;

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
                case DcqlQuery.CredentialsPropertyName:
                {
                    credentials = JsonSerializer.Deserialize<List<CredentialQuery>>(ref reader, options);
                    break;
                }
                case DcqlQuery.CredentialSetsPropertyName:
                {
                    credentialSets = JsonSerializer.Deserialize<List<CredentialSetQuery>>(ref reader, options);
                    break;
                }
                default:
                {
                    reader.Skip();
                    break;
                }
            }
        }

        if(credentials is null || credentials.Count == 0)
        {
            throw new JsonException("The 'credentials' property is required and must not be empty.");
        }

        return new DcqlQuery
        {
            Credentials = credentials,
            CredentialSets = credentialSets
        };
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, DcqlQuery value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        writer.WriteStartObject();

        writer.WritePropertyName(DcqlQuery.CredentialsPropertyName);
        JsonSerializer.Serialize(writer, value.Credentials, options);

        if(value.CredentialSets is not null)
        {
            writer.WritePropertyName(DcqlQuery.CredentialSetsPropertyName);
            JsonSerializer.Serialize(writer, value.CredentialSets, options);
        }

        writer.WriteEndObject();
    }
}