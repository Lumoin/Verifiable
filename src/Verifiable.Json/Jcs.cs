using System.Buffers;
using System.Text;
using System.Text.Json;

namespace Verifiable.Json;

/// <summary>
/// Implements JSON Canonicalization Scheme (JCS) as defined in RFC 8785.
/// </summary>
/// <remarks>
/// <para>
/// JCS produces a deterministic serialization of JSON data by applying the following rules:
/// </para>
/// <list type="bullet">
/// <item><description>Object members are sorted lexicographically by their property names.</description></item>
/// <item><description>No whitespace is used between tokens.</description></item>
/// <item><description>Numbers are serialized using ECMAScript number-to-string rules.</description></item>
/// <item><description>Strings use minimal escaping with lowercase hex for Unicode escapes.</description></item>
/// </list>
/// <para>
/// See <see href="https://datatracker.ietf.org/doc/html/rfc8785">RFC 8785</see> for the full specification.
/// </para>
/// 
/// <h3>System.Text.Json Integration Rationale (.NET 10)</h3>
/// <para>
/// JCS requires post-serialization transformation (property sorting) that System.Text.Json (STJ)
/// does not natively support. The STJ serialization pipeline is:
/// </para>
/// <code>
/// Object → JsonConverter(s) → Utf8JsonWriter → Output bytes/string
/// </code>
/// <para>
/// There is no hook to intercept or transform the final output. The following .NET 10 STJ
/// extensibility points were evaluated but do not solve the JCS requirements:
/// </para>
/// <list type="bullet">
/// <item>
/// <term><see cref="System.Text.Json.Serialization.JsonConverter{T}"/></term>
/// <description>
/// Operates on individual values during serialization. Each converter only sees its own value
/// and cannot access or reorder sibling properties. Cannot perform document-wide transformations.
/// Even a converter wrapping the root object cannot sort properties of nested objects or
/// dictionaries without reimplementing the entire serialization logic.
/// </description>
/// </item>
/// <item>
/// <term><see cref="IJsonTypeInfoResolver"/></term>
/// <description>
/// <para>
/// Provides metadata about types for serialization including property names, converters, and ordering.
/// Can customize property ordering via <see cref="JsonTypeInfo.Properties"/>
/// at resolver creation time.
/// </para>
/// <para>
/// Even if the resolver computed lexicographic order for <see cref="JsonPropertyOrderAttribute"/>
/// based on final property names (respecting <see cref="JsonPropertyNameAttribute"/>),
/// this approach fundamentally cannot handle:
/// </para>
/// <list type="bullet">
/// <item><description><c>Dictionary&lt;string, T&gt;</c> where keys are determined at serialization time, not type resolution time.</description></item>
/// <item><description><see cref="JsonExtensionDataAttribute"/> properties that capture overflow or dynamic properties unknown until runtime.</description></item>
/// <item><description>Nested objects containing dictionaries or extension data at any depth.</description></item>
/// <item><description>Anonymous types or <c>ExpandoObject</c> with dynamic members.</description></item>
/// </list>
/// <para>
/// The resolver runs once per type during initialization, not per-serialization, so runtime-determined
/// keys cannot influence property ordering.
/// </para>
/// </description>
/// </item>
/// <item>
/// <term><see cref="Metadata.DefaultJsonTypeInfoResolver"/> with Modifiers</term>
/// <description>
/// Allows runtime modification of serialization contracts via the <c>Modifiers</c> collection.
/// Properties can be reordered by manipulating <c>JsonTypeInfo.Properties</c>, but modifiers
/// execute once during type info creation. The same fundamental limitations apply: dictionary keys
/// and extension data properties are unknown at modifier execution time.
/// </description>
/// </item>
/// <item>
/// <term><see cref="JsonPropertyOrderAttribute"/></term>
/// <description>
/// Specifies static property order at compile time via numeric ordering. JCS requires lexicographic
/// sorting based on the actual serialized property names, not a predetermined numeric order.
/// The sort order depends on the output names which may differ from source property names.
/// </description>
/// </item>
/// <item>
/// <term><see cref="JsonNamingPolicy"/></term>
/// <description>
/// Transforms property names (e.g., <see cref="JsonNamingPolicy.CamelCase"/>)
/// but does not affect property ordering. The naming policy is applied before writing,
/// but the write order follows the type's property declaration order or <c>JsonPropertyOrder</c>.
/// </description>
/// </item>
/// <item>
/// <term>Runtime attribute injection via <c>TypeDescriptor</c> or source generators</term>
/// <description>
/// Adding <see cref="JsonPropertyOrderAttribute"/> dynamically
/// at runtime is not supported by STJ. Source generators (<c>JsonSerializable</c>) generate
/// static metadata at compile time. Even if attributes could be injected, the fundamental
/// limitation remains: dictionary and extension data keys are unknown until serialization.
/// </description>
/// </item>
/// <item>
/// <term><see cref="JsonNode"/> manipulation</term>
/// <description>
/// <see cref="JsonObject"/> is an ordered dictionary that preserves
/// insertion order, but provides no built-in sorting. Manual sorting requires removing and
/// re-adding all properties in sorted order, which is equivalent to the reparse approach
/// but with mutable state and additional complexity.
/// </description>
/// </item>
/// </list>
/// <para>
/// Therefore, JCS implementation requires a two-phase approach as described in
/// <see href="https://datatracker.ietf.org/doc/html/rfc8785#appendix-B">RFC 8785 Appendix B</see>:
/// </para>
/// <code>
/// Object → STJ Serialize → JSON string → JsonDocument.Parse → WriteCanonical (sorted) → Output
/// </code>
/// <para>
/// This approach:
/// </para>
/// <list type="bullet">
/// <item><description>Works with any object structure including dictionaries, extension data, and dynamic properties.</description></item>
/// <item><description>Handles nested objects and arrays recursively with consistent sorting at every level.</description></item>
/// <item><description>Is independent of how the original object was serialized or what converters were used.</description></item>
/// <item><description>Uses immutable <see cref="JsonDocument"/> for efficient read-only traversal.</description></item>
/// </list>
/// <para>
/// If future versions of System.Text.Json add a post-serialization transformation hook,
/// output stream wrapper, or native lexicographic property sorting option that handles
/// dynamic keys, this implementation could be optimized to avoid the reparse step.
/// </para>
/// </remarks>
public static class Jcs
{
    private static readonly JsonSerializerOptions DefaultSerializerOptions = new()
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private static readonly JsonWriterOptions CanonicalWriterOptions = new()
    {
        Indented = false,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };


    /// <summary>
    /// Serializes an object to canonical JSON according to RFC 8785.
    /// </summary>
    /// <typeparam name="T">The type of the object to serialize.</typeparam>
    /// <param name="value">The object to serialize.</param>
    /// <param name="options">Optional serializer options. Only encoder settings are used; output is always unindented.</param>
    /// <returns>The canonical JSON string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is null.</exception>
    public static string Serialize<T>(T value, JsonSerializerOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(value);

        var json = JsonSerializer.Serialize(value, options ?? DefaultSerializerOptions);

        return Canonicalize(json);
    }


    /// <summary>
    /// Serializes an object to canonical JSON bytes according to RFC 8785.
    /// </summary>
    /// <typeparam name="T">The type of the object to serialize.</typeparam>
    /// <param name="value">The object to serialize.</param>
    /// <param name="options">Optional serializer options. Only encoder settings are used; output is always unindented.</param>
    /// <returns>The canonical JSON as UTF-8 bytes.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is null.</exception>
    public static byte[] SerializeToUtf8Bytes<T>(T value, JsonSerializerOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(value);

        var json = JsonSerializer.Serialize(value, options ?? DefaultSerializerOptions);

        return CanonicalizeToUtf8Bytes(json);
    }


    /// <summary>
    /// Canonicalizes a JSON string according to RFC 8785.
    /// </summary>
    /// <param name="json">The JSON string to canonicalize.</param>
    /// <returns>The canonicalized JSON string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="json"/> is null.</exception>
    /// <exception cref="JsonException">Thrown when <paramref name="json"/> is not valid JSON.</exception>
    public static string Canonicalize(string json)
    {
        ArgumentNullException.ThrowIfNull(json);

        using var document = JsonDocument.Parse(json);

        return Canonicalize(document.RootElement);
    }


    /// <summary>
    /// Canonicalizes a JSON document according to RFC 8785.
    /// </summary>
    /// <param name="document">The JSON document to canonicalize.</param>
    /// <returns>The canonicalized JSON string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="document"/> is null.</exception>
    public static string Canonicalize(JsonDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);

        return Canonicalize(document.RootElement);
    }


    /// <summary>
    /// Canonicalizes a JSON element according to RFC 8785.
    /// </summary>
    /// <param name="element">The JSON element to canonicalize.</param>
    /// <returns>The canonicalized JSON string.</returns>
    public static string Canonicalize(JsonElement element)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using var writer = new Utf8JsonWriter(buffer, CanonicalWriterOptions);

        WriteCanonical(writer, element);
        writer.Flush();

        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }


    /// <summary>
    /// Canonicalizes a JSON string and returns the result as UTF-8 bytes.
    /// </summary>
    /// <param name="json">The JSON string to canonicalize.</param>
    /// <returns>The canonicalized JSON as UTF-8 bytes.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="json"/> is null.</exception>
    /// <exception cref="JsonException">Thrown when <paramref name="json"/> is not valid JSON.</exception>
    public static byte[] CanonicalizeToUtf8Bytes(string json)
    {
        ArgumentNullException.ThrowIfNull(json);

        using var document = JsonDocument.Parse(json);
        var buffer = new ArrayBufferWriter<byte>();
        using var writer = new Utf8JsonWriter(buffer, CanonicalWriterOptions);

        WriteCanonical(writer, document.RootElement);
        writer.Flush();

        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Writes a JSON element in canonical form to the specified writer.
    /// </summary>
    private static void WriteCanonical(Utf8JsonWriter writer, JsonElement element)
    {
        switch(element.ValueKind)
        {
            case JsonValueKind.Object:
            {
                WriteCanonicalObject(writer, element);
                return;
            }
            case JsonValueKind.Array:
            {
                WriteCanonicalArray(writer, element);
                return;
            }
            case JsonValueKind.String:
            {
                writer.WriteStringValue(element.GetString());
                return;
            }
            case JsonValueKind.Number:
            {
                WriteCanonicalNumber(writer, element);
                return;
            }
            case JsonValueKind.True:
            {
                writer.WriteBooleanValue(true);
                return;
            }
            case JsonValueKind.False:
            {
                writer.WriteBooleanValue(false);
                return;
            }
            case JsonValueKind.Null:
            {
                writer.WriteNullValue();
                return;
            }
        }

        JsonThrowHelper.ThrowJsonException($"Unexpected JSON value kind: {element.ValueKind}.");
    }


    /// <summary>
    /// Writes a JSON object with properties sorted lexicographically by name.
    /// </summary>
    private static void WriteCanonicalObject(Utf8JsonWriter writer, JsonElement element)
    {
        writer.WriteStartObject();

        //RFC 8785 requires lexicographic sorting of property names.
        //Sort by UTF-16 code units (default .NET string comparison).
        var properties = new System.Collections.Generic.List<JsonProperty>();
        foreach(var property in element.EnumerateObject())
        {
            properties.Add(property);
        }

        properties.Sort((a, b) => string.CompareOrdinal(a.Name, b.Name));

        foreach(var property in properties)
        {
            writer.WritePropertyName(property.Name);
            WriteCanonical(writer, property.Value);
        }

        writer.WriteEndObject();
    }


    /// <summary>
    /// Writes a JSON array with elements in their original order.
    /// </summary>
    private static void WriteCanonicalArray(Utf8JsonWriter writer, JsonElement element)
    {
        writer.WriteStartArray();

        foreach(var item in element.EnumerateArray())
        {
            WriteCanonical(writer, item);
        }

        writer.WriteEndArray();
    }


    /// <summary>
    /// Writes a number in canonical form following ECMAScript number serialization rules.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 8785 requires numbers to be serialized according to ECMAScript's ToString applied to Number type.
    /// System.Text.Json already handles most cases correctly. This method ensures proper handling of
    /// edge cases like negative zero and ensures no trailing zeros in decimal representation.
    /// </para>
    /// </remarks>
    private static void WriteCanonicalNumber(Utf8JsonWriter writer, JsonElement element)
    {
        //Try to get as integer first for precise integer representation.
        if(element.TryGetInt64(out var longValue))
        {
            writer.WriteNumberValue(longValue);

            return;
        }

        //For decimals, get the raw value and let the writer handle it.
        var doubleValue = element.GetDouble();

        //Handle negative zero per RFC 8785 - should serialize as "0".
        if(doubleValue == 0.0)
        {
            writer.WriteNumberValue(0);

            return;
        }

        writer.WriteNumberValue(doubleValue);
    }
}