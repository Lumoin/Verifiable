using System.Buffers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Cryptography;
using Verifiable.Jose.SdJwt;

namespace Verifiable.Json.Converters;

/// <summary>
/// JSON converter for <see cref="SdJwtToken"/> that handles SD-JWT compact serialization.
/// </summary>
public sealed class SdJwtTokenJsonConverter: JsonConverter<SdJwtToken>
{
    /// <summary>
    /// Gets the delegate for base64url decoding.
    /// </summary>
    public DecodeDelegate? Decoder { get; }

    /// <summary>
    /// Gets the memory pool for allocations.
    /// </summary>
    public MemoryPool<byte> MemoryPool { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="SdJwtTokenJsonConverter"/> class.
    /// </summary>
    public SdJwtTokenJsonConverter()
    {
        MemoryPool = MemoryPool<byte>.Shared;
    }


    /// <summary>
    /// Initializes a new instance of the <see cref="SdJwtTokenJsonConverter"/> class with a decoding delegate.
    /// </summary>
    /// <param name="decoder">Delegate for base64url decoding.</param>
    /// <param name="memoryPool">Memory pool for allocations. If null, uses the shared pool.</param>
    public SdJwtTokenJsonConverter(DecodeDelegate decoder, MemoryPool<byte>? memoryPool = null)
    {
        Decoder = decoder;
        MemoryPool = memoryPool ?? MemoryPool<byte>.Shared;
    }


    /// <inheritdoc />
    public override SdJwtToken? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if(reader.TokenType == JsonTokenType.Null)
        {
            return null;
        }

        if(reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException("Expected a string containing an SD-JWT compact serialization.");
        }

        string? sdJwt = reader.GetString();
        if(string.IsNullOrEmpty(sdJwt))
        {
            throw new JsonException("SD-JWT string cannot be null or empty.");
        }

        DecodeDelegate decodeDelegate = Decoder
            ?? throw new InvalidOperationException("DecodeDelegate must be provided via constructor.");

        return Parse(sdJwt, decodeDelegate, MemoryPool);
    }


    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, SdJwtToken value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(value, nameof(value));

        writer.WriteStringValue(value.Serialize());
    }


    /// <summary>
    /// Parses an SD-JWT or SD-JWT+KB from its compact serialization.
    /// </summary>
    /// <param name="sdJwt">The SD-JWT compact serialization.</param>
    /// <param name="base64UrlDecoder">Delegate for base64url decoding.</param>
    /// <param name="memoryPool">Memory pool for allocation.</param>
    /// <returns>The parsed SD-JWT token.</returns>
    /// <exception cref="ArgumentException">Thrown when the format is invalid.</exception>
    public static SdJwtToken Parse(string sdJwt, DecodeDelegate base64UrlDecoder, MemoryPool<byte> memoryPool)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sdJwt, nameof(sdJwt));
        ArgumentNullException.ThrowIfNull(base64UrlDecoder, nameof(base64UrlDecoder));
        ArgumentNullException.ThrowIfNull(memoryPool, nameof(memoryPool));

        string[] parts = sdJwt.Split(SdJwtConstants.Separator);

        if(parts.Length < 2)
        {
            throw new ArgumentException(
                "SD-JWT must have at least two parts (JWT and trailing separator).",
                nameof(sdJwt));
        }

        string issuerSignedJwt = parts[0];

        if(!IsValidJwt(issuerSignedJwt))
        {
            throw new ArgumentException("First part must be a valid JWT.", nameof(sdJwt));
        }

        //Parse disclosures (middle parts, excluding first JWT and last part).
        var disclosures = new List<Disclosure>();
        string? keyBindingJwt = null;

        var disclosureConverter = new DisclosureJsonConverter(
            null!,
            base64UrlDecoder);

        for(int i = 1; i < parts.Length - 1; i++)
        {
            if(!string.IsNullOrEmpty(parts[i]))
            {
                Disclosure disclosure = ParseDisclosure(parts[i], base64UrlDecoder, memoryPool);
                disclosures.Add(disclosure);
            }
        }

        //Check the last part - empty means SD-JWT, non-empty means SD-JWT+KB.
        string lastPart = parts[^1];
        if(!string.IsNullOrEmpty(lastPart))
        {
            if(!IsValidJwt(lastPart))
            {
                throw new ArgumentException("Last non-empty part must be a valid KB-JWT.", nameof(sdJwt));
            }

            keyBindingJwt = lastPart;
        }

        return new SdJwtToken(issuerSignedJwt, disclosures, keyBindingJwt);
    }


    /// <summary>
    /// Tries to parse an SD-JWT or SD-JWT+KB from its compact serialization.
    /// </summary>
    /// <param name="sdJwt">The SD-JWT compact serialization.</param>
    /// <param name="base64UrlDecoder">Delegate for base64url decoding.</param>
    /// <param name="memoryPool">Memory pool for allocation.</param>
    /// <param name="token">The parsed token if successful; otherwise, null.</param>
    /// <returns>True if parsing succeeded; otherwise, false.</returns>
    public static bool TryParse(
        string sdJwt,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> memoryPool,
        out SdJwtToken? token)
    {
        try
        {
            token = Parse(sdJwt, base64UrlDecoder, memoryPool);
            return true;
        }
        catch
        {
            token = null;
            return false;
        }
    }


    private static Disclosure ParseDisclosure(string encodedDisclosure, DecodeDelegate decoder, MemoryPool<byte> memoryPool)
    {
        using IMemoryOwner<byte> decodedBytes = decoder(encodedDisclosure, memoryPool);

        using JsonDocument document = JsonDocument.Parse((ReadOnlyMemory<byte>)decodedBytes.Memory);
        JsonElement root = document.RootElement;

        if(root.ValueKind != JsonValueKind.Array)
        {
            throw new ArgumentException("Disclosure must be a JSON array.");
        }

        int arrayLength = root.GetArrayLength();

        string salt;
        string? claimName;
        object? claimValue;

        if(arrayLength == 2)
        {
            //Array element disclosure: [salt, value].
            salt = root[0].GetString()
                ?? throw new ArgumentException("Salt must be a string.");
            claimName = null;
            claimValue = ExtractValue(root[1]);

            return new Disclosure(salt, claimValue, encodedDisclosure);
        }
        else if(arrayLength == 3)
        {
            //Object property disclosure: [salt, claim_name, value].
            salt = root[0].GetString()
                ?? throw new ArgumentException("Salt must be a string.");
            claimName = root[1].GetString()
                ?? throw new ArgumentException("Claim name must be a string.");
            claimValue = ExtractValue(root[2]);

            return new Disclosure(salt, claimName, claimValue, encodedDisclosure);
        }
        else
        {
            throw new ArgumentException($"Disclosure array must have 2 or 3 elements, but has {arrayLength}.");
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
            JsonValueKind.Object => ExtractDictionary(element),
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


    private static Dictionary<string, object> ExtractDictionary(JsonElement element)
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


    private static bool IsValidJwt(string jwt)
    {
        //A valid JWT has exactly 3 base64url-encoded parts separated by dots.
        string[] parts = jwt.Split('.');
        if(parts.Length != 3)
        {
            return false;
        }

        //Each part should be non-empty and contain only valid base64url characters.
        foreach(string part in parts)
        {
            if(string.IsNullOrEmpty(part))
            {
                return false;
            }

            foreach(char c in part)
            {
                if(!IsBase64UrlChar(c))
                {
                    return false;
                }
            }
        }

        return true;
    }


    private static bool IsBase64UrlChar(char c)
    {
        return (c >= 'A' && c <= 'Z') ||
               (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') ||
               c == '-' ||
               c == '_';
    }
}