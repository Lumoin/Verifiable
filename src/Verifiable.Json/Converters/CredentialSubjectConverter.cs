using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Credentials;

namespace Verifiable.Json.Converters
{
    /// <summary>
    /// Converts <see cref="CredentialSubject"/> lists to and from JSON, handling both
    /// single object and array forms.
    /// </summary>
    /// <remarks>
    /// <para>
    /// In the VC Data Model, <c>credentialSubject</c> can be expressed as either:
    /// </para>
    /// <list type="bullet">
    /// <item><description>A single object with claims about one subject.</description></item>
    /// <item><description>An array of objects with claims about multiple subjects.</description></item>
    /// </list>
    /// <para>
    /// This converter handles both forms transparently, always deserializing to a list.
    /// </para>
    /// </remarks>
    public class CredentialSubjectConverter: JsonConverter<List<CredentialSubject>>
    {
        /// <inheritdoc/>
        public override bool CanConvert(Type typeToConvert)
        {
            return typeToConvert == typeof(List<CredentialSubject>);
        }


        /// <inheritdoc/>
        public override List<CredentialSubject>? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if(reader.TokenType == JsonTokenType.Null)
            {
                return null;
            }

            var list = new List<CredentialSubject>();

            if(reader.TokenType == JsonTokenType.StartArray)
            {
                while(reader.Read())
                {
                    if(reader.TokenType == JsonTokenType.EndArray)
                    {
                        break;
                    }

                    var subject = ReadSingleSubject(ref reader);
                    if(subject is not null)
                    {
                        list.Add(subject);
                    }
                }
            }
            else if(reader.TokenType == JsonTokenType.StartObject)
            {
                var subject = ReadSingleSubject(ref reader);
                if(subject is not null)
                {
                    list.Add(subject);
                }
            }
            else
            {
                throw new JsonException($"Unexpected token type {reader.TokenType} when parsing credentialSubject.");
            }

            return list;
        }


        /// <inheritdoc/>
        public override void Write(Utf8JsonWriter writer, List<CredentialSubject> value, JsonSerializerOptions options)
        {
            if(value is null)
            {
                writer.WriteNullValue();

                return;
            }

            if(value.Count == 1)
            {
                WriteSingleSubject(writer, value[0], options);
            }
            else
            {
                writer.WriteStartArray();
                for(int i = 0; i < value.Count; ++i)
                {
                    WriteSingleSubject(writer, value[i], options);
                }

                writer.WriteEndArray();
            }
        }


        private static CredentialSubject? ReadSingleSubject(ref Utf8JsonReader reader)
        {
            if(reader.TokenType != JsonTokenType.StartObject)
            {
                throw new JsonException($"Expected StartObject, got {reader.TokenType}.");
            }

            string? id = null;
            var additionalData = new Dictionary<string, object>();

            while(reader.Read())
            {
                if(reader.TokenType == JsonTokenType.EndObject)
                {
                    break;
                }

                if(reader.TokenType != JsonTokenType.PropertyName)
                {
                    throw new JsonException("Expected property name.");
                }

                string? propertyName = reader.GetString();
                reader.Read();

                if(propertyName == "id")
                {
                    id = reader.GetString();
                }
                else if(propertyName is not null)
                {
                    object? value = ReadJsonValue(ref reader);
                    if(value is not null)
                    {
                        additionalData[propertyName] = value;
                    }
                }
            }

            return new CredentialSubject
            {
                Id = id,
                AdditionalData = additionalData.Count > 0 ? additionalData : null
            };
        }


        private static object? ReadJsonValue(ref Utf8JsonReader reader)
        {
            return reader.TokenType switch
            {
                JsonTokenType.String => reader.GetString(),
                JsonTokenType.Number => reader.TryGetInt64(out long l) ? l : reader.GetDouble(),
                JsonTokenType.True => true,
                JsonTokenType.False => false,
                JsonTokenType.Null => null,
                JsonTokenType.StartObject => JsonSerializer.Deserialize<Dictionary<string, object>>(ref reader),
                JsonTokenType.StartArray => JsonSerializer.Deserialize<List<object>>(ref reader),
                _ => throw new JsonException($"Unexpected token type {reader.TokenType}.")
            };
        }


        private static void WriteSingleSubject(Utf8JsonWriter writer, CredentialSubject subject, JsonSerializerOptions options)
        {
            writer.WriteStartObject();

            if(subject.Id is not null)
            {
                writer.WriteString("id", subject.Id);
            }

            if(subject.AdditionalData is not null)
            {
                foreach(var kvp in subject.AdditionalData)
                {
                    writer.WritePropertyName(kvp.Key);
                    JsonSerializer.Serialize(writer, kvp.Value, options);
                }
            }

            writer.WriteEndObject();
        }
    }
}