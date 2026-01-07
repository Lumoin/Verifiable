using System.Buffers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Cryptography;
using Verifiable.Jose.SdJwt;

namespace Verifiable.Json.Converters;

/// <summary>
/// JSON converter for <see cref="Disclosure"/> that handles base64url-encoded disclosure strings.
/// </summary>
/// <remarks>
/// <para>
/// This converter reads and writes disclosures in their base64url-encoded format.
/// When reading, it decodes the JSON array structure to extract salt, claim name, and value.
/// When writing, it outputs the pre-computed <see cref="Disclosure.EncodedValue"/>.
/// </para>
/// <para>
/// The converter requires <see cref="EncodeDelegate"/> and <see cref="DecodeDelegate"/> to be
/// provided via constructor for reading operations.
/// </para>
/// </remarks>
public sealed class DisclosureJsonConverter: JsonConverter<Disclosure>
{
    /// <summary>
    /// Gets the delegate for base64url encoding.
    /// </summary>
    public EncodeDelegate? Encoder { get; }

    /// <summary>
    /// Gets the delegate for base64url decoding.
    /// </summary>
    public DecodeDelegate? Decoder { get; }

    /// <summary>
    /// Gets the memory pool for allocations.
    /// </summary>
    public MemoryPool<byte> MemoryPool { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="DisclosureJsonConverter"/> class.
    /// </summary>
    public DisclosureJsonConverter()
    {
        MemoryPool = MemoryPool<byte>.Shared;
    }


    /// <summary>
    /// Initializes a new instance of the <see cref="DisclosureJsonConverter"/> class with encoding delegates.
    /// </summary>
    /// <param name="encoder">Delegate for base64url encoding.</param>
    /// <param name="decoder">Delegate for base64url decoding.</param>
    /// <param name="memoryPool">Memory pool for allocations. If null, uses the shared pool.</param>
    public DisclosureJsonConverter(EncodeDelegate encoder, DecodeDelegate decoder, MemoryPool<byte>? memoryPool = null)
    {
        Encoder = encoder;
        Decoder = decoder;
        MemoryPool = memoryPool ?? MemoryPool<byte>.Shared;
    }


    /// <inheritdoc />
    public override Disclosure? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if(reader.TokenType == JsonTokenType.Null)
        {
            return null;
        }

        if(reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException("Expected a string containing a base64url-encoded disclosure.");
        }

        string? encodedDisclosure = reader.GetString();
        if(string.IsNullOrEmpty(encodedDisclosure))
        {
            throw new JsonException("Disclosure string cannot be null or empty.");
        }

        DecodeDelegate decodeDelegate = Decoder
            ?? throw new InvalidOperationException(
                "DecodeDelegate must be provided via constructor.");

        //Decode the base64url string.
        using IMemoryOwner<byte> decodedBytes = decodeDelegate(encodedDisclosure, MemoryPool);

        //Parse the JSON array.
        using JsonDocument document = JsonDocument.Parse((ReadOnlyMemory<byte>)decodedBytes.Memory);
        JsonElement root = document.RootElement;

        if(root.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException("Disclosure must be a JSON array.");
        }

        int arrayLength = root.GetArrayLength();

        string salt;
        string? claimName;
        object? claimValue;

        if(arrayLength == 2)
        {
            //Array element disclosure: [salt, value].
            salt = root[0].GetString()
                ?? throw new JsonException("Salt must be a string.");
            claimName = null;
            claimValue = ExtractValue(root[1]);

            return new Disclosure(salt, claimValue, encodedDisclosure);
        }
        else if(arrayLength == 3)
        {
            //Object property disclosure: [salt, claim_name, value].
            salt = root[0].GetString()
                ?? throw new JsonException("Salt must be a string.");
            claimName = root[1].GetString()
                ?? throw new JsonException("Claim name must be a string.");
            claimValue = ExtractValue(root[2]);

            return new Disclosure(salt, claimName, claimValue, encodedDisclosure);
        }
        else
        {
            throw new JsonException($"Disclosure array must have 2 or 3 elements, but has {arrayLength}.");
        }
    }


    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, Disclosure value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(value, nameof(value));

        writer.WriteStringValue(value.EncodedValue);
    }


    /// <summary>
    /// Creates a <see cref="Disclosure"/> from its components and computes the encoded value.
    /// </summary>
    /// <param name="salt">The salt value.</param>
    /// <param name="claimName">The claim name.</param>
    /// <param name="claimValue">The claim value.</param>
    /// <param name="encoder">Delegate for base64url encoding.</param>
    /// <returns>A new disclosure with computed encoded value.</returns>
    public static Disclosure Create(string salt, string claimName, object? claimValue, EncodeDelegate encoder)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(salt, nameof(salt));
        ArgumentException.ThrowIfNullOrWhiteSpace(claimName, nameof(claimName));
        ArgumentNullException.ThrowIfNull(encoder, nameof(encoder));

        if(!SdJwtExtensions.IsValidDisclosureClaimName(claimName))
        {
            throw new ArgumentException(
                $"Claim name cannot be '{SdJwtConstants.SdClaimName}' or '{SdJwtConstants.ArrayDigestKey}'.",
                nameof(claimName));
        }

        string encodedValue = EncodeDisclosure(salt, claimName, claimValue, encoder);
        return new Disclosure(salt, claimName, claimValue, encodedValue);
    }


    /// <summary>
    /// Creates a <see cref="Disclosure"/> for an array element from its components and computes the encoded value.
    /// </summary>
    /// <param name="salt">The salt value.</param>
    /// <param name="claimValue">The claim value.</param>
    /// <param name="encoder">Delegate for base64url encoding.</param>
    /// <returns>A new disclosure with computed encoded value.</returns>
    public static Disclosure CreateArrayElement(string salt, object? claimValue, EncodeDelegate encoder)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(salt, nameof(salt));
        ArgumentNullException.ThrowIfNull(encoder, nameof(encoder));

        string encodedValue = EncodeDisclosureArrayElement(salt, claimValue, encoder);
        return new Disclosure(salt, claimValue, encodedValue);
    }


    private static string EncodeDisclosure(string salt, string claimName, object? claimValue, EncodeDelegate encoder)
    {
        using var stream = new MemoryStream();
        using(var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartArray();
            writer.WriteStringValue(salt);
            writer.WriteStringValue(claimName);
            WriteValue(writer, claimValue);
            writer.WriteEndArray();
        }

        return encoder(stream.ToArray());
    }


    private static string EncodeDisclosureArrayElement(string salt, object? claimValue, EncodeDelegate encoder)
    {
        using var stream = new MemoryStream();
        using(var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartArray();
            writer.WriteStringValue(salt);
            WriteValue(writer, claimValue);
            writer.WriteEndArray();
        }

        return encoder(stream.ToArray());
    }


    private static void WriteValue(Utf8JsonWriter writer, object? value)
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

            case Dictionary<string, object> dictionaryValue:
                writer.WriteStartObject();
                foreach(KeyValuePair<string, object> kvp in dictionaryValue)
                {
                    writer.WritePropertyName(kvp.Key);
                    WriteValue(writer, kvp.Value);
                }
                writer.WriteEndObject();
                break;

            case IList<object> listValue:
                writer.WriteStartArray();
                foreach(object item in listValue)
                {
                    WriteValue(writer, item);
                }
                writer.WriteEndArray();
                break;

            default:
                throw new NotSupportedException($"Type '{value.GetType()}' is not supported.");
        }
    }


    private static object? ExtractValue(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => element.TryGetDateTime(out DateTime date) ? date : element.GetString(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => null,
            JsonValueKind.Number => ExtractNumber(element),
            JsonValueKind.Object => ExtractObject(element),
            JsonValueKind.Array => ExtractArray(element),
            _ => throw new JsonException($"Unsupported JSON value kind: {element.ValueKind}")
        };
    }


    private static object ExtractNumber(JsonElement element)
    {
        //JSON has no integer type - all numbers are IEEE 754 doubles.
        //Try to return the most appropriate CLR type.
        if(element.TryGetInt64(out long longValue))
        {
            return longValue;
        }

        decimal decimalValue = element.GetDecimal();

        //Check if decimal is actually a whole number.
        if(decimalValue == Math.Truncate(decimalValue) && decimalValue >= long.MinValue && decimalValue <= long.MaxValue)
        {
            return (long)decimalValue;
        }

        return decimalValue;
    }


    private static Dictionary<string, object> ExtractObject(JsonElement element)
    {
        var dictionary = new Dictionary<string, object>();

        foreach(JsonProperty property in element.EnumerateObject())
        {
            dictionary[property.Name] = ExtractValue(property.Value)!;
        }

        return dictionary;
    }


    private static List<object> ExtractArray(JsonElement element)
    {
        var list = new List<object>();

        foreach(JsonElement item in element.EnumerateArray())
        {
            list.Add(ExtractValue(item)!);
        }

        return list;
    }
}