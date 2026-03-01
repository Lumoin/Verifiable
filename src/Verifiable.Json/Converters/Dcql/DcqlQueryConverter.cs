using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
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
        ArgumentNullException.ThrowIfNull(options);

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
                    credentials = ReadArray<CredentialQuery>(ref reader, options);
                    break;
                }
                case DcqlQuery.CredentialSetsPropertyName:
                {
                    credentialSets = ReadArray<CredentialSetQuery>(ref reader, options);
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
        ArgumentNullException.ThrowIfNull(options);

        writer.WriteStartObject();

        if(value.Credentials is not null)
        {
            writer.WritePropertyName(DcqlQuery.CredentialsPropertyName);
            WriteArray(writer, value.Credentials, options);
        }

        if(value.CredentialSets is not null)
        {
            writer.WritePropertyName(DcqlQuery.CredentialSetsPropertyName);
            WriteArray(writer, value.CredentialSets, options);
        }

        writer.WriteEndObject();
    }


    /// <summary>
    /// Reads a JSON array by deserializing each element individually via
    /// <see cref="JsonSerializerOptions.GetTypeInfo"/>. This avoids needing
    /// <c>List&lt;T&gt;</c> in the source-generated context.
    /// </summary>
    private static List<T> ReadArray<T>(ref Utf8JsonReader reader, JsonSerializerOptions options)
    {
        if(reader.TokenType != JsonTokenType.StartArray)
        {
            throw new JsonException($"Expected StartArray but got {reader.TokenType}.");
        }

        var typeInfo = (JsonTypeInfo<T>)options.GetTypeInfo(typeof(T));
        var list = new List<T>();

        while(reader.Read())
        {
            if(reader.TokenType == JsonTokenType.EndArray)
            {
                break;
            }

            var item = JsonSerializer.Deserialize(ref reader, typeInfo);
            if(item is not null)
            {
                list.Add(item);
            }
        }

        return list;
    }


    /// <summary>
    /// Writes a list as a JSON array by serializing each element individually via
    /// <see cref="JsonSerializerOptions.GetTypeInfo"/>.
    /// </summary>
    private static void WriteArray<T>(Utf8JsonWriter writer, IReadOnlyList<T> items, JsonSerializerOptions options)
    {
        var typeInfo = (JsonTypeInfo<T>)options.GetTypeInfo(typeof(T));

        writer.WriteStartArray();
        foreach(var item in items)
        {
            JsonSerializer.Serialize(writer, item, typeInfo);
        }

        writer.WriteEndArray();
    }
}