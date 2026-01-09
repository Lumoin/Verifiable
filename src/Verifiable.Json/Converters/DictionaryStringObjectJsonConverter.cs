using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Verifiable.Json.Converters
{
    /// <summary>
    /// A JSON converter for <see cref="Dictionary{TKey, TValue}"/> with string keys and object values.
    /// Handles nested objects, arrays, and primitive types including <see cref="JsonElement"/> for roundtripping.
    /// </summary>
    public sealed class DictionaryStringObjectJsonConverter: JsonConverter<Dictionary<string, object>>
    {
        public override Dictionary<string, object> Read(ref Utf8JsonReader reader, Type? typeToConvert, JsonSerializerOptions options)
        {
            if(reader.TokenType != JsonTokenType.StartObject)
            {
                throw new JsonException($"JsonTokenType was of type {reader.TokenType}, only objects are supported.");
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
                    throw new JsonException("JsonTokenType was not PropertyName.");
                }

                string? propertyName = reader.GetString();
                if(string.IsNullOrWhiteSpace(propertyName))
                {
                    throw new JsonException("Failed to get property name.");
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
            switch(value)
            {
                case null:
                    writer.WriteNullValue();
                    break;
                case string stringValue:
                    writer.WriteStringValue(stringValue);
                    break;
                case bool boolValue:
                    writer.WriteBooleanValue(boolValue);
                    break;
                case int intValue:
                    writer.WriteNumberValue(intValue);
                    break;
                case long longValue:
                    writer.WriteNumberValue(longValue);
                    break;
                case float floatValue:
                    writer.WriteNumberValue(floatValue);
                    break;
                case double doubleValue:
                    writer.WriteNumberValue(doubleValue);
                    break;
                case decimal decimalValue:
                    writer.WriteNumberValue(decimalValue);
                    break;
                case DateTime dateTimeValue:
                    writer.WriteStringValue(dateTimeValue);
                    break;
                case Dictionary<string, object> dictionaryValue:
                    Write(writer, dictionaryValue, options);
                    break;
                case IList<object> listValue:
                    writer.WriteStartArray();
                    foreach(var item in listValue)
                    {
                        WriteValue(writer, item, options);
                    }
                    writer.WriteEndArray();
                    break;
                case JsonElement jsonElement:
                    WriteJsonElement(writer, jsonElement, options);
                    break;
                default:
                    throw new NotSupportedException($"Type '{value.GetType()}' is not supported.");
            }
        }

        [return: MaybeNull]
        private object? ExtractValue(ref Utf8JsonReader reader, JsonSerializerOptions options)
        {
            return reader.TokenType switch
            {
                JsonTokenType.String => reader.TryGetDateTime(out DateTime date) ? date : reader.GetString(),
                JsonTokenType.False => false,
                JsonTokenType.True => true,
                JsonTokenType.Null => null,
                JsonTokenType.Number => reader.TryGetInt64(out long result) ? result : reader.GetDecimal(),
                JsonTokenType.StartObject => Read(ref reader, null, options),
                JsonTokenType.StartArray => ExtractArray(ref reader, options),
                _ => throw new JsonException($"Token '{reader.TokenType}' is not supported.")
            };
        }

        private List<object> ExtractArray(ref Utf8JsonReader reader, JsonSerializerOptions options)
        {
            var list = new List<object>();
            while(reader.Read() && reader.TokenType != JsonTokenType.EndArray)
            {
                list.Add(ExtractValue(ref reader, options)!);
            }

            return list;
        }

        private void WriteJsonElement(Utf8JsonWriter writer, JsonElement element, JsonSerializerOptions options)
        {
            switch(element.ValueKind)
            {
                case JsonValueKind.Object:
                    writer.WriteStartObject();
                    foreach(var property in element.EnumerateObject())
                    {
                        writer.WritePropertyName(property.Name);
                        WriteJsonElement(writer, property.Value, options);
                    }
                    writer.WriteEndObject();
                    break;
                case JsonValueKind.Array:
                    writer.WriteStartArray();
                    foreach(var item in element.EnumerateArray())
                    {
                        WriteJsonElement(writer, item, options);
                    }
                    writer.WriteEndArray();
                    break;
                case JsonValueKind.String:
                    writer.WriteStringValue(element.GetString());
                    break;
                case JsonValueKind.Number:
                    writer.WriteRawValue(element.GetRawText());
                    break;
                case JsonValueKind.True:
                    writer.WriteBooleanValue(true);
                    break;
                case JsonValueKind.False:
                    writer.WriteBooleanValue(false);
                    break;
                case JsonValueKind.Null:
                    writer.WriteNullValue();
                    break;
                case JsonValueKind.Undefined:
                default:
                    throw new JsonException($"Unsupported JsonValueKind: {element.ValueKind}.");
            }
        }
    }
}