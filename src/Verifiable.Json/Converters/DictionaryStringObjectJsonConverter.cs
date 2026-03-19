using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace Verifiable.Json.Converters
{
    /// <summary>
    /// A JSON converter for <see cref="Dictionary{TKey, TValue}"/> with string keys and object values.
    /// Handles nested objects, arrays, and primitive types including <see cref="JsonElement"/> for roundtripping.
    /// </summary>
    /// <remarks>
    /// <para>
    /// For values whose types are not handled by an explicit case in the write switch — such as domain model
    /// types placed directly into the dictionary — the converter delegates to <paramref name="resolver"/>.
    /// This keeps the fallback path AOT-safe: no runtime reflection is used, and any unregistered type
    /// produces a clear <see cref="NotSupportedException"/> pointing at the missing
    /// <c>[JsonSerializable]</c> annotation.
    /// </para>
    /// <para>
    /// Pass the application's <see cref="JsonSerializerContext"/> (e.g. <c>VerifiableJsonContext.Default</c>)
    /// as the resolver. The same context must also be set as <see cref="JsonSerializerOptions.TypeInfoResolver"/>
    /// on the enclosing options instance.
    /// </para>
    /// </remarks>
    public sealed class DictionaryStringObjectJsonConverter: JsonConverter<Dictionary<string, object>>
    {
        private readonly IJsonTypeInfoResolver resolver;

        /// <summary>
        /// Initializes a new instance of <see cref="DictionaryStringObjectJsonConverter"/>.
        /// </summary>
        /// <param name="resolver">
        /// The resolver used to obtain <see cref="JsonTypeInfo"/> for domain model types that appear
        /// as values in <c>Dictionary&lt;string, object&gt;</c> and are not handled by an explicit
        /// switch case. Must be a source-generated <see cref="JsonSerializerContext"/> for AOT safety.
        /// </param>
        public DictionaryStringObjectJsonConverter(IJsonTypeInfoResolver resolver)
        {
            ArgumentNullException.ThrowIfNull(resolver);
            this.resolver = resolver;
        }


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
            ArgumentNullException.ThrowIfNull(writer);
            ArgumentNullException.ThrowIfNull(value);

            writer.WriteStartObject();
            foreach(var (key, val) in value)
            {
                writer.WritePropertyName(key);
                WriteValue(writer, val, options);
            }
            writer.WriteEndObject();
        }


        private void WriteValue(Utf8JsonWriter writer, object? value, JsonSerializerOptions options)
        {
            switch(value)
            {
                case null:
                {
                    writer.WriteNullValue();
                    break;
                }
                case string s:
                {
                    writer.WriteStringValue(s);
                    break;
                }
                case bool b:
                {
                    writer.WriteBooleanValue(b);
                    break;
                }
                case int i:
                {
                    writer.WriteNumberValue(i);
                    break;
                }
                case long l:
                {
                    writer.WriteNumberValue(l);
                    break;
                }
                case float f:
                {
                    writer.WriteNumberValue(f);
                    break;
                }
                case double d:
                {
                    writer.WriteNumberValue(d);
                    break;
                }
                case decimal m:
                {
                    writer.WriteNumberValue(m);
                    break;
                }
                case DateTime dt:
                {
                    writer.WriteStringValue(dt);
                    break;
                }
                case Dictionary<string, string> { } dict:
                {
                    writer.WriteStartObject();
                    foreach(var (k, v) in dict)
                    {
                        writer.WritePropertyName(k);
                        writer.WriteStringValue(v);
                    }
                    writer.WriteEndObject();
                    break;
                }
                case Dictionary<string, object> { } dict:
                {
                    Write(writer, dict, options);
                    break;
                }
                case IList<object> { } list:
                {
                    writer.WriteStartArray();
                    foreach(var item in list)
                    {
                        WriteValue(writer, item, options);
                    }
                    writer.WriteEndArray();
                    break;
                }
                case JsonElement jsonElement:
                {
                    WriteJsonElement(writer, jsonElement, options);
                    break;
                }
                default:
                {
                    Type runtimeType = value.GetType();
                    JsonTypeInfo? typeInfo = resolver.GetTypeInfo(runtimeType, options);
                    if(typeInfo is null)
                    {
                        throw new NotSupportedException(
                            $"Type '{runtimeType}' is not supported. Ensure it is annotated with " +
                            $"[JsonSerializable] in the JsonSerializerContext passed to " +
                            $"{nameof(DictionaryStringObjectJsonConverter)}.");
                    }
                    JsonSerializer.Serialize(writer, value, typeInfo);
                    break;
                }
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


        private static void WriteJsonElement(Utf8JsonWriter writer, JsonElement element, JsonSerializerOptions options)
        {
            switch(element.ValueKind)
            {
                case JsonValueKind.Object:
                {
                    writer.WriteStartObject();
                    foreach(var property in element.EnumerateObject())
                    {
                        writer.WritePropertyName(property.Name);
                        WriteJsonElement(writer, property.Value, options);
                    }
                    writer.WriteEndObject();
                    break;
                }
                case JsonValueKind.Array:
                {
                    writer.WriteStartArray();
                    foreach(var item in element.EnumerateArray())
                    {
                        WriteJsonElement(writer, item, options);
                    }
                    writer.WriteEndArray();
                    break;
                }
                case JsonValueKind.String:
                {
                    writer.WriteStringValue(element.GetString());
                    break;
                }
                case JsonValueKind.Number:
                {
                    writer.WriteRawValue(element.GetRawText());
                    break;
                }
                case JsonValueKind.True:
                {
                    writer.WriteBooleanValue(true);
                    break;
                }
                case JsonValueKind.False:
                {
                    writer.WriteBooleanValue(false);
                    break;
                }
                case JsonValueKind.Null:
                {
                    writer.WriteNullValue();
                    break;
                }
                case JsonValueKind.Undefined:
                default:
                {
                    throw new JsonException($"Unsupported JsonValueKind: {element.ValueKind}.");
                }
            }
        }
    }
}