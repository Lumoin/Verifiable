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
        private IJsonTypeInfoResolver Resolver { get; }

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
            this.Resolver = resolver;
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
            _ = value switch
            {
                null => WriteNull(writer),
                string s => WriteString(writer, s),
                bool b => WriteBoolean(writer, b),
                int i => WriteInt(writer, i),
                long l => WriteLong(writer, l),
                float f => WriteFloat(writer, f),
                double d => WriteDouble(writer, d),
                decimal m => WriteDecimal(writer, m),
                DateTime dt => WriteDateTime(writer, dt),
                Dictionary<string, string> dict => WriteStringDictionary(writer, dict),
                Dictionary<string, object> dict => WriteNestedDictionary(this, writer, dict, options),
                IList<object> list => WriteList(this, writer, list, options),
                JsonElement jsonElement => WriteElement(writer, jsonElement, options),
                _ => WriteFallback(Resolver, writer, value, options)
            };

            static object? WriteNull(Utf8JsonWriter writer)
            {
                writer.WriteNullValue();

                return null;
            }

            static object? WriteString(Utf8JsonWriter writer, string s)
            {
                writer.WriteStringValue(s);

                return null;
            }

            static object? WriteBoolean(Utf8JsonWriter writer, bool b)
            {
                writer.WriteBooleanValue(b);

                return null;
            }

            static object? WriteInt(Utf8JsonWriter writer, int i)
            {
                writer.WriteNumberValue(i);

                return null;
            }

            static object? WriteLong(Utf8JsonWriter writer, long l)
            {
                writer.WriteNumberValue(l);

                return null;
            }

            static object? WriteFloat(Utf8JsonWriter writer, float f)
            {
                writer.WriteNumberValue(f);

                return null;
            }

            static object? WriteDouble(Utf8JsonWriter writer, double d)
            {
                writer.WriteNumberValue(d);

                return null;
            }

            static object? WriteDecimal(Utf8JsonWriter writer, decimal m)
            {
                writer.WriteNumberValue(m);

                return null;
            }

            static object? WriteDateTime(Utf8JsonWriter writer, DateTime dt)
            {
                writer.WriteStringValue(dt);

                return null;
            }

            static object? WriteStringDictionary(Utf8JsonWriter writer, Dictionary<string, string> dict)
            {
                writer.WriteStartObject();
                foreach(var (k, v) in dict)
                {
                    writer.WritePropertyName(k);
                    writer.WriteStringValue(v);
                }
                writer.WriteEndObject();

                return null;
            }

            static object? WriteNestedDictionary(DictionaryStringObjectJsonConverter converter, Utf8JsonWriter writer, Dictionary<string, object> dict, JsonSerializerOptions options)
            {
                converter.Write(writer, dict, options);

                return null;
            }

            static object? WriteList(DictionaryStringObjectJsonConverter converter, Utf8JsonWriter writer, IList<object> list, JsonSerializerOptions options)
            {
                writer.WriteStartArray();
                foreach(var item in list)
                {
                    converter.WriteValue(writer, item, options);
                }
                writer.WriteEndArray();

                return null;
            }

            static object? WriteElement(Utf8JsonWriter writer, JsonElement jsonElement, JsonSerializerOptions options)
            {
                WriteJsonElement(writer, jsonElement, options);

                return null;
            }

            static object? WriteFallback(IJsonTypeInfoResolver resolver, Utf8JsonWriter writer, object? value, JsonSerializerOptions options)
            {
                Type runtimeType = value!.GetType();
                JsonTypeInfo? typeInfo = resolver.GetTypeInfo(runtimeType, options);
                if(typeInfo is null)
                {
                    throw new NotSupportedException(
                        $"Type '{runtimeType}' is not supported. Ensure it is annotated with " +
                        $"[JsonSerializable] in the JsonSerializerContext passed to " +
                        $"{nameof(DictionaryStringObjectJsonConverter)}.");
                }
                JsonSerializer.Serialize(writer, value, typeInfo);

                return null;
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
                JsonTokenType.Number => reader.TryGetInt64(out long result) ? (object)result : reader.GetDecimal(),
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
            _ = element.ValueKind switch
            {
                JsonValueKind.Object => WriteObject(writer, element, options),
                JsonValueKind.Array => WriteArray(writer, element, options),
                JsonValueKind.String => WriteString(writer, element),
                JsonValueKind.Number => WriteNumber(writer, element),
                JsonValueKind.True => WriteBoolean(writer, true),
                JsonValueKind.False => WriteBoolean(writer, false),
                JsonValueKind.Null => WriteNull(writer),
                _ => throw new JsonException($"Unsupported JsonValueKind: {element.ValueKind}.")
            };

            static object? WriteObject(Utf8JsonWriter writer, JsonElement element, JsonSerializerOptions options)
            {
                writer.WriteStartObject();
                foreach(var property in element.EnumerateObject())
                {
                    writer.WritePropertyName(property.Name);
                    WriteJsonElement(writer, property.Value, options);
                }
                writer.WriteEndObject();

                return null;
            }

            static object? WriteArray(Utf8JsonWriter writer, JsonElement element, JsonSerializerOptions options)
            {
                writer.WriteStartArray();
                foreach(var item in element.EnumerateArray())
                {
                    WriteJsonElement(writer, item, options);
                }
                writer.WriteEndArray();

                return null;
            }

            static object? WriteString(Utf8JsonWriter writer, JsonElement element)
            {
                writer.WriteStringValue(element.GetString());

                return null;
            }

            static object? WriteNumber(Utf8JsonWriter writer, JsonElement element)
            {
                writer.WriteRawValue(element.GetRawText());

                return null;
            }

            static object? WriteBoolean(Utf8JsonWriter writer, bool value)
            {
                writer.WriteBooleanValue(value);

                return null;
            }

            static object? WriteNull(Utf8JsonWriter writer)
            {
                writer.WriteNullValue();

                return null;
            }
        }
    }
}