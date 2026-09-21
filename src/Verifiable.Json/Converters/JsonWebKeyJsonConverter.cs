using System.Collections;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.JCose;

namespace Verifiable.Json.Converters;

/// <summary>
/// Converts a <see cref="JsonWebKey"/> to and from JSON by its own member shapes, so a deserialized
/// key holds the same CLR values a built key holds. Without this converter, STJ's default dictionary
/// handling for a <see cref="System.Collections.Generic.Dictionary{TKey, TValue}"/> subclass boxes
/// every member value as a <see cref="JsonElement"/>, leaving every one of <see cref="JsonWebKey"/>'s
/// typed accessors <see langword="null"/> after deserialization.
/// </summary>
/// <remarks>
/// Read member value shapes match <see cref="DictionaryStringObjectJsonConverter"/> — a number becomes
/// a <see cref="long"/> when integral, otherwise a <see cref="decimal"/>; <c>true</c>/<c>false</c>
/// become <see cref="bool"/>; a nested object becomes a <see cref="System.Collections.Generic.Dictionary{TKey, TValue}"/>;
/// an array becomes a <see cref="System.Collections.Generic.List{T}"/> — with one difference: a JSON
/// string always becomes a CLR <see cref="string"/>, never a <see cref="DateTime"/>. A JWK member such
/// as <c>kid</c> can hold text that happens to parse as a date (an ISO 8601 timestamp, or an all-digit
/// string), and <see cref="DictionaryStringObjectJsonConverter"/> deliberately tries
/// <see cref="Utf8JsonReader.TryGetDateTime(out DateTime)"/> before falling back to a plain string,
/// which this converter does not repeat.
/// </remarks>
public sealed class JsonWebKeyJsonConverter: JsonConverter<JsonWebKey>
{
    /// <summary>
    /// Reads a JSON object into a <see cref="JsonWebKey"/>. A member the library declares no typed
    /// accessor for is kept in the resulting dictionary rather than rejected, per RFC 7517 §4
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7517#section-4">RFC 7517 §4</see>): "Additional
    /// members can be present in the JWK; if not understood by implementations encountering them, they
    /// MUST be ignored."
    /// </summary>
    /// <param name="reader">The reader positioned at the JWK's token.</param>
    /// <param name="typeToConvert">The type being converted; unused, since this converter always produces a <see cref="JsonWebKey"/>.</param>
    /// <param name="options">The active <see cref="JsonSerializerOptions"/>; unused, since every member value is read by its own JSON shape.</param>
    /// <returns>The decoded key.</returns>
    /// <exception cref="JsonException">
    /// The token is not a JSON object, or the object repeats a member name. RFC 7517 §4
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7517#section-4">RFC 7517 §4</see>): "The member
    /// names within a JWK MUST be unique; JWK parsers MUST either reject JWKs with duplicate member
    /// names or use a JSON parser that returns only the lexically last duplicate member name." This
    /// converter rejects.
    /// </exception>
    public override JsonWebKey Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException($"Expected a JSON object for a '{nameof(JsonWebKey)}', found '{reader.TokenType}'.");
        }

        var jsonWebKey = new JsonWebKey();
        while(reader.Read())
        {
            if(reader.TokenType == JsonTokenType.EndObject)
            {
                return jsonWebKey;
            }

            if(reader.TokenType != JsonTokenType.PropertyName)
            {
                throw new JsonException($"Expected a JSON property name, found '{reader.TokenType}'.");
            }

            string memberName = reader.GetString()!;
            _ = reader.Read();
            object? memberValue = ExtractValue(ref reader);

            if(!jsonWebKey.TryAdd(memberName, memberValue!))
            {
                throw new JsonException($"The JSON Web Key repeats the member name '{memberName}'.");
            }
        }

        throw new JsonException($"Unexpected end of JSON while reading a '{nameof(JsonWebKey)}'.");
    }


    /// <summary>
    /// Writes a <see cref="JsonWebKey"/> as a JSON object, one member per dictionary entry in
    /// insertion order, each by its runtime shape.
    /// </summary>
    /// <param name="writer">The writer to emit the JSON object to.</param>
    /// <param name="value">The key to write.</param>
    /// <param name="options">The active <see cref="JsonSerializerOptions"/>; unused, since every member value is written by its own runtime type.</param>
    /// <exception cref="JsonException">A member's runtime value is none of the shapes <see cref="WriteValue(Utf8JsonWriter, string, object?)"/> knows.</exception>
    public override void Write(Utf8JsonWriter writer, JsonWebKey value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        writer.WriteStartObject();
        foreach(var (memberName, memberValue) in value)
        {
            writer.WritePropertyName(memberName);
            WriteValue(writer, memberName, memberValue);
        }

        writer.WriteEndObject();
    }


    /// <summary>
    /// Reads one member value at the reader's current token: a string, a number (<see cref="long"/>
    /// when integral, otherwise <see cref="decimal"/>), a boolean, <see langword="null"/>, a nested
    /// object, or an array, recursing by these same rules.
    /// </summary>
    /// <param name="reader">The reader positioned at the value's token.</param>
    /// <returns>The decoded value.</returns>
    /// <exception cref="JsonException">The token is not a value token.</exception>
    private static object? ExtractValue(ref Utf8JsonReader reader) => reader.TokenType switch
    {
        JsonTokenType.String => reader.GetString(),
        JsonTokenType.Number => reader.TryGetInt64(out long longValue) ? (object)longValue : reader.GetDecimal(),
        JsonTokenType.True => true,
        JsonTokenType.False => false,
        JsonTokenType.Null => null,
        JsonTokenType.StartObject => ExtractObject(ref reader),
        JsonTokenType.StartArray => ExtractArray(ref reader),
        _ => throw new JsonException($"Unexpected token '{reader.TokenType}' in a '{nameof(JsonWebKey)}' member value.")
    };


    /// <summary>
    /// Reads a nested JSON object into a <see cref="System.Collections.Generic.Dictionary{TKey, TValue}"/>,
    /// rejecting a repeated member name the same way <see cref="Read(ref Utf8JsonReader, Type, JsonSerializerOptions)"/> does.
    /// </summary>
    /// <param name="reader">The reader positioned at the object's <c>StartObject</c> token.</param>
    /// <returns>The decoded nested object.</returns>
    /// <exception cref="JsonException">The object repeats a member name.</exception>
    private static Dictionary<string, object> ExtractObject(ref Utf8JsonReader reader)
    {
        var nested = new Dictionary<string, object>();
        while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            if(reader.TokenType != JsonTokenType.PropertyName)
            {
                throw new JsonException($"Expected a JSON property name, found '{reader.TokenType}'.");
            }

            string memberName = reader.GetString()!;
            _ = reader.Read();
            object? memberValue = ExtractValue(ref reader);

            if(!nested.TryAdd(memberName, memberValue!))
            {
                throw new JsonException($"The JSON object repeats the member name '{memberName}'.");
            }
        }

        return nested;
    }


    /// <summary>
    /// Reads a JSON array into a <see cref="System.Collections.Generic.List{T}"/>, decoding each
    /// element by <see cref="ExtractValue(ref Utf8JsonReader)"/>.
    /// </summary>
    /// <param name="reader">The reader positioned at the array's <c>StartArray</c> token.</param>
    /// <returns>The decoded elements.</returns>
    private static List<object> ExtractArray(ref Utf8JsonReader reader)
    {
        var list = new List<object>();
        while(reader.Read() && reader.TokenType != JsonTokenType.EndArray)
        {
            list.Add(ExtractValue(ref reader)!);
        }

        return list;
    }


    /// <summary>
    /// Writes one member value by its runtime type: a <see cref="string"/>, a <see cref="bool"/>, a
    /// <see cref="long"/>, a <see cref="decimal"/>, a <see langword="null"/> reference, a
    /// <see cref="string"/>[], a <see cref="System.Collections.Generic.List{T}"/> of <see cref="object"/>,
    /// or a <see cref="System.Collections.Generic.Dictionary{TKey, TValue}"/> — the shapes
    /// <see cref="ExtractValue(ref Utf8JsonReader)"/> produces on read, plus <see cref="string"/>[] for
    /// the array members the library's own builders assign directly rather than through this converter —
    /// or, for any other value whose runtime type is a non-string <see cref="IEnumerable"/>, a JSON array
    /// of its elements, each through this same method, per RFC 7517 §4
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7517#section-4">RFC 7517 §4</see>): an additional
    /// member's value may take any JSON shape a producer chooses to give it.
    /// </summary>
    /// <param name="writer">The writer to emit the value to.</param>
    /// <param name="memberName">The member name the value is written under, folded into the exception when the value's type is unsupported.</param>
    /// <param name="memberValue">The value to write.</param>
    /// <exception cref="JsonException"><paramref name="memberValue"/>'s runtime type is none of the shapes this method knows.</exception>
    private static void WriteValue(Utf8JsonWriter writer, string memberName, object? memberValue)
    {
        _ = memberValue switch
        {
            null => WriteNull(writer),
            string stringValue => WriteString(writer, stringValue),
            bool boolValue => WriteBoolean(writer, boolValue),
            long longValue => WriteLong(writer, longValue),
            decimal decimalValue => WriteDecimal(writer, decimalValue),
            string[] stringArray => WriteStringArray(writer, stringArray),
            List<object> list => WriteList(writer, memberName, list),
            Dictionary<string, object> nested => WriteNested(writer, nested),
            IEnumerable enumerable => WriteEnumerable(writer, memberName, enumerable),
            _ => throw new JsonException($"The '{memberName}' member of a '{nameof(JsonWebKey)}' has an unsupported runtime type '{memberValue.GetType()}'.")
        };

        static object? WriteNull(Utf8JsonWriter writer)
        {
            writer.WriteNullValue();

            return null;
        }

        static object? WriteString(Utf8JsonWriter writer, string value)
        {
            writer.WriteStringValue(value);

            return null;
        }

        static object? WriteBoolean(Utf8JsonWriter writer, bool value)
        {
            writer.WriteBooleanValue(value);

            return null;
        }

        static object? WriteLong(Utf8JsonWriter writer, long value)
        {
            writer.WriteNumberValue(value);

            return null;
        }

        static object? WriteDecimal(Utf8JsonWriter writer, decimal value)
        {
            writer.WriteNumberValue(value);

            return null;
        }

        static object? WriteStringArray(Utf8JsonWriter writer, string[] values)
        {
            writer.WriteStartArray();
            foreach(string item in values)
            {
                writer.WriteStringValue(item);
            }

            writer.WriteEndArray();

            return null;
        }

        static object? WriteList(Utf8JsonWriter writer, string memberName, List<object> values)
        {
            writer.WriteStartArray();
            foreach(object? item in values)
            {
                WriteValue(writer, memberName, item);
            }

            writer.WriteEndArray();

            return null;
        }

        static object? WriteEnumerable(Utf8JsonWriter writer, string memberName, IEnumerable values)
        {
            writer.WriteStartArray();
            foreach(object? item in values)
            {
                WriteValue(writer, memberName, item);
            }

            writer.WriteEndArray();

            return null;
        }

        static object? WriteNested(Utf8JsonWriter writer, Dictionary<string, object> nested)
        {
            writer.WriteStartObject();
            foreach(var (nestedName, nestedValue) in nested)
            {
                writer.WritePropertyName(nestedName);
                WriteValue(writer, nestedName, nestedValue);
            }

            writer.WriteEndObject();

            return null;
        }
    }
}
