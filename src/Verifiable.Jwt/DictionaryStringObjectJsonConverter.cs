using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Verifiable.Jwt
{
    /// <summary>
    /// A converter for <see cref="System.Text.Json."/>
    /// </summary>
    public sealed class DictionaryStringObjectJsonConverter: JsonConverter<Dictionary<string, object>>
    {
        public override Dictionary<string, object> Read(ref Utf8JsonReader reader, Type? typeToConvert, JsonSerializerOptions options)
        {
            if(reader.TokenType != JsonTokenType.StartObject)
            {
                throw new JsonException($"JsonTokenType was of type {reader.TokenType}, only objects are supported");
            }

            var dic = new Dictionary<string, object>();
            while(reader.Read())
            {
                if(reader.TokenType == JsonTokenType.EndObject)
                {
                    return dic;
                }

                if(reader.TokenType != JsonTokenType.PropertyName)
                {
                    throw new JsonException("JsonTokenType was not PropertyName");
                }

                string? propertyName = reader.GetString();
                if(string.IsNullOrWhiteSpace(propertyName))
                {
                    throw new JsonException("Failed to get property name");
                }

                _ = reader.Read();
                dic.Add(propertyName, ExtractValue(ref reader, options)!);
            }

            return dic;
        }


        public override void Write(Utf8JsonWriter writer, Dictionary<string, object> value, JsonSerializerOptions options)
        {
            if(value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            writer.WriteStartObject();

            foreach(var keyValuePair in value)
            {
                writer.WritePropertyName(keyValuePair.Key);
                WriteValue(writer, keyValuePair.Value, options);
            }

            writer.WriteEndObject();
        }

        private void WriteValue(Utf8JsonWriter writer, object? value, JsonSerializerOptions options)
        {
            if(value == null)
            {
                writer.WriteNullValue();
            }
            else if(value is string stringValue)
            {
                writer.WriteStringValue(stringValue);
            }
            else if(value is bool boolValue)
            {
                writer.WriteBooleanValue(boolValue);
            }
            else if(value is int intValue)
            {
                writer.WriteNumberValue(intValue);
            }
            else if(value is long longValue)
            {
                writer.WriteNumberValue(longValue);
            }
            else if(value is float floatValue)
            {
                writer.WriteNumberValue(floatValue);
            }
            else if(value is double doubleValue)
            {
                writer.WriteNumberValue(doubleValue);
            }
            else if(value is decimal decimalValue)
            {
                writer.WriteNumberValue(decimalValue);
            }
            else if(value is DateTime dateTimeValue)
            {
                writer.WriteStringValue(dateTimeValue);
            }
            else if(value is Dictionary<string, object> dictionaryValue)
            {
                Write(writer, dictionaryValue, options);
            }
            else if(value is IList<object> listValue)
            {
                writer.WriteStartArray();

                foreach(var item in listValue)
                {
                    WriteValue(writer, item, options);
                }

                writer.WriteEndArray();
            }
            else
            {
                throw new NotSupportedException($"Type '{value.GetType()}' is not supported.");
            }
        }


        [return: MaybeNull]
        private object? ExtractValue(ref Utf8JsonReader reader, JsonSerializerOptions options)
        {
            switch(reader.TokenType)
            {
                case JsonTokenType.String:
                {
                    return reader.TryGetDateTime(out DateTime date) ? date : reader.GetString();
                }
                case JsonTokenType.False:
                {
                    return false;
                }
                case JsonTokenType.True:
                {
                    return true;
                }
                case JsonTokenType.Null:
                {
                    return null;
                }
                case JsonTokenType.Number:
                {
                    return reader.TryGetInt64(out long result) ? result : reader.GetDecimal();
                }
                case JsonTokenType.StartObject:
                {
                    return Read(ref reader, null, options);
                }
                case JsonTokenType.StartArray:
                {
                    var list = new List<object>();
                    while(reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                    {
                        list.Add(ExtractValue(ref reader, options)!);
                    }

                    return list;
                }
                default:
                {
                    throw new JsonException($"Token '{reader.TokenType}' is not supported");
                }
            }
        }
    }
}
