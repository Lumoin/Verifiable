using System.Collections;
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
    /// A value whose runtime type is a non-string <see cref="IEnumerable"/> — an array, a
    /// <see cref="List{T}"/>, or any other sequence, whatever its element type — writes as a JSON array
    /// of its elements, each through the same write rules, whether or not that concrete sequence type
    /// has a dedicated case in the write switch.
    /// </para>
    /// <para>
    /// For values whose types are not handled by an explicit case or by that sequence rule — such as
    /// domain model types placed directly into the dictionary — the converter delegates to the
    /// <c>resolver</c>. This keeps the fallback path AOT-safe: no runtime reflection is used, and any
    /// unregistered type produces a clear <see cref="NotSupportedException"/> pointing at the missing
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


        /// <summary>
        /// Reads a JSON object into a <see cref="Dictionary{TKey, TValue}"/>, recursing into nested
        /// objects and arrays and preserving primitive value shapes (string, number, boolean, null).
        /// </summary>
        /// <param name="reader">The reader positioned at the JSON object's <c>StartObject</c> token.</param>
        /// <param name="typeToConvert">The type being converted; unused, since this converter always
        /// produces a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="options">The active <see cref="JsonSerializerOptions"/>, passed through to
        /// nested value extraction.</param>
        /// <returns>The decoded dictionary.</returns>
        /// <exception cref="JsonException">
        /// The object is not well-formed, or repeats a member name at this or any nested depth
        /// (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 §4</see>: "the behavior
        /// of software that receives such an object is unpredictable") — a producer showing one reader
        /// one value under a name and a differently-behaving reader another value under its repeat.
        /// </exception>
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
                object? value = ExtractValue(ref reader, options);
                if(!dic.TryAdd(propertyName, value!))
                {
                    throw new JsonException($"The JSON object repeats the member name '{propertyName}'.");
                }
            }

            return dic;
        }


        /// <summary>
        /// Writes a <see cref="Dictionary{TKey, TValue}"/> as a JSON object, recursing into nested
        /// values and falling back to the <c>resolver</c> for any value type without an explicit case.
        /// </summary>
        /// <param name="writer">The writer to emit the JSON object to.</param>
        /// <param name="value">The dictionary to write.</param>
        /// <param name="options">The active <see cref="JsonSerializerOptions"/>, passed through to
        /// nested value writes.</param>
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


        /// <summary>
        /// Writes one dictionary value by its runtime shape: a primitive, one of the two dictionary
        /// shapes, an <see cref="IList{T}"/> of <see cref="object"/>, a <see cref="JsonElement"/>, any
        /// other non-string <see cref="IEnumerable"/> written as a JSON array of its own elements (each
        /// through this same method), or, failing all of those, the <c>resolver</c>.
        /// </summary>
        /// <param name="writer">The writer to emit the value to.</param>
        /// <param name="value">The value to write.</param>
        /// <param name="options">The active <see cref="JsonSerializerOptions"/>, passed through to nested writes and the fallback.</param>
        /// <exception cref="NotSupportedException"><paramref name="value"/>'s runtime type matches no explicit shape and the <c>resolver</c> has no <see cref="JsonTypeInfo"/> for it.</exception>
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
                IEnumerable enumerable => WriteEnumerable(this, writer, enumerable, options),
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

            static object? WriteEnumerable(DictionaryStringObjectJsonConverter converter, Utf8JsonWriter writer, IEnumerable enumerable, JsonSerializerOptions options)
            {
                writer.WriteStartArray();
                foreach(object? item in enumerable)
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
                JsonTokenType.None => throw new JsonException($"Token '{reader.TokenType}' is not supported."),
                JsonTokenType.StartObject => Read(ref reader, null, options),
                JsonTokenType.EndObject => throw new JsonException($"Token '{reader.TokenType}' is not supported."),
                JsonTokenType.StartArray => ExtractArray(ref reader, options),
                JsonTokenType.EndArray => throw new JsonException($"Token '{reader.TokenType}' is not supported."),
                JsonTokenType.PropertyName => throw new JsonException($"Token '{reader.TokenType}' is not supported."),
                JsonTokenType.Comment => throw new JsonException($"Token '{reader.TokenType}' is not supported."),
                JsonTokenType.String => reader.TryGetDateTime(out DateTime date) ? date : reader.GetString(),
                JsonTokenType.Number => reader.TryGetInt64(out long result) ? (object)result : reader.GetDecimal(),
                JsonTokenType.True => true,
                JsonTokenType.False => false,
                JsonTokenType.Null => null,
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
                JsonValueKind.Undefined => throw new JsonException($"Unsupported JsonValueKind: {element.ValueKind}."),
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
