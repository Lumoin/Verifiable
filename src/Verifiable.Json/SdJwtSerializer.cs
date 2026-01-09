using System.Buffers;
using System.Text;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.JCose.Sd;

namespace Verifiable.Json.Sd;

/// <summary>
/// JSON serialization for SD-JWT disclosures and tokens.
/// </summary>
/// <remarks>
/// <para>
/// SD-JWT uses a compact serialization format:
/// <c>&lt;issuer-jwt&gt;~&lt;disclosure1&gt;~&lt;disclosure2&gt;~...~[kb-jwt]</c>
/// </para>
/// <para>
/// Disclosures are Base64Url-encoded JSON arrays: <c>[salt, name?, value]</c>.
/// </para>
/// </remarks>
public static class SdJwtSerializer
{
    /// <summary>
    /// Serializes a disclosure to its Base64Url-encoded form.
    /// </summary>
    /// <param name="disclosure">The disclosure to serialize.</param>
    /// <param name="encoder">Delegate for Base64Url encoding.</param>
    /// <returns>The Base64Url-encoded disclosure string.</returns>
    public static string SerializeDisclosure(SdDisclosure disclosure, EncodeDelegate encoder)
    {
        ArgumentNullException.ThrowIfNull(disclosure);
        ArgumentNullException.ThrowIfNull(encoder);

        string saltString = encoder(disclosure.Salt.Span);

        using var stream = new MemoryStream();
        using(var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartArray();
            writer.WriteStringValue(saltString);

            if(disclosure.ClaimName is not null)
            {
                writer.WriteStringValue(disclosure.ClaimName);
            }

            WriteClaimValue(writer, disclosure.ClaimValue);
            writer.WriteEndArray();
        }

        return encoder(stream.ToArray());
    }


    /// <summary>
    /// Parses a disclosure from its Base64Url-encoded form.
    /// </summary>
    /// <param name="encoded">The Base64Url-encoded disclosure string.</param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <returns>The parsed disclosure.</returns>
    /// <exception cref="FormatException">Thrown when the format is invalid.</exception>
    public static SdDisclosure ParseDisclosure(string encoded, DecodeDelegate decoder, MemoryPool<byte> pool)
    {
        ArgumentException.ThrowIfNullOrEmpty(encoded);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> jsonBytes;
        try
        {
            jsonBytes = decoder(encoded, pool);
        }
        catch(Exception ex)
        {
            throw new FormatException("Invalid Base64Url encoding in disclosure.", ex);
        }

        using(jsonBytes)
        {
            using JsonDocument doc = JsonDocument.Parse(jsonBytes.Memory);
            JsonElement root = doc.RootElement;

            if(root.ValueKind != JsonValueKind.Array)
            {
                throw new FormatException("Disclosure must be a JSON array.");
            }

            int length = root.GetArrayLength();

            if(length < 2 || length > 3)
            {
                throw new FormatException($"Disclosure array must have 2 or 3 elements, got {length}.");
            }

            string saltString = root[0].GetString()
                ?? throw new FormatException("Salt cannot be null.");

            IMemoryOwner<byte> saltBytes;
            try
            {
                saltBytes = decoder(saltString, pool);
            }
            catch(Exception ex)
            {
                throw new FormatException("Invalid Base64Url encoding in salt.", ex);
            }

            using(saltBytes)
            {
                byte[] salt = saltBytes.Memory.ToArray();

                if(length == 2)
                {
                    object? value = ConvertJsonElement(root[1]);
                    return SdDisclosure.CreateArrayElement(salt, value);
                }
                else
                {
                    string claimName = root[1].GetString()
                        ?? throw new FormatException("Claim name cannot be null.");

                    object? value = ConvertJsonElement(root[2]);
                    return SdDisclosure.CreateProperty(salt, claimName, value);
                }
            }
        }
    }


    /// <summary>
    /// Serializes an SD-JWT token to its wire format.
    /// </summary>
    /// <param name="token">The token to serialize.</param>
    /// <param name="encoder">Delegate for Base64Url encoding.</param>
    /// <returns>The serialized SD-JWT string.</returns>
    public static string SerializeToken(SdJwtToken token, EncodeDelegate encoder)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(encoder);

        var builder = new StringBuilder();
        builder.Append(token.IssuerSigned);
        builder.Append(SdConstants.JwtSeparator);

        foreach(SdDisclosure disclosure in token.Disclosures)
        {
            builder.Append(SerializeDisclosure(disclosure, encoder));
            builder.Append(SdConstants.JwtSeparator);
        }

        if(token.KeyBinding is not null)
        {
            builder.Length--;
            builder.Append(SdConstants.JwtSeparator);
            builder.Append(token.KeyBinding);
        }

        return builder.ToString();
    }


    /// <summary>
    /// Parses an SD-JWT token from its wire format.
    /// </summary>
    /// <param name="sdJwt">The SD-JWT string.</param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <returns>The parsed token.</returns>
    /// <exception cref="FormatException">Thrown when the format is invalid.</exception>
    public static SdJwtToken ParseToken(string sdJwt, DecodeDelegate decoder, MemoryPool<byte> pool)
    {
        ArgumentException.ThrowIfNullOrEmpty(sdJwt);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(pool);

        string[] parts = sdJwt.Split(SdConstants.JwtSeparator);

        if(parts.Length < 2)
        {
            throw new FormatException("SD-JWT must have at least an issuer JWT and one separator.");
        }

        string issuerJwt = parts[0];

        if(!IsValidJwtStructure(issuerJwt))
        {
            throw new FormatException("Invalid issuer JWT structure.");
        }

        var disclosures = new List<SdDisclosure>();
        string? keyBindingJwt = null;

        for(int i = 1; i < parts.Length; i++)
        {
            string part = parts[i];

            if(string.IsNullOrEmpty(part))
            {
                continue;
            }

            if(IsValidJwtStructure(part))
            {
                keyBindingJwt = part;
            }
            else
            {
                SdDisclosure disclosure = ParseDisclosure(part, decoder, pool);
                disclosures.Add(disclosure);
            }
        }

        return new SdJwtToken(issuerJwt, disclosures, keyBindingJwt);
    }


    /// <summary>
    /// Attempts to parse an SD-JWT token.
    /// </summary>
    /// <param name="sdJwt">The SD-JWT string.</param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="token">The parsed token if successful.</param>
    /// <returns><c>true</c> if parsing succeeded; otherwise, <c>false</c>.</returns>
    public static bool TryParseToken(string? sdJwt, DecodeDelegate decoder, MemoryPool<byte> pool, out SdJwtToken? token)
    {
        token = null;

        if(string.IsNullOrEmpty(sdJwt))
        {
            return false;
        }

        try
        {
            token = ParseToken(sdJwt, decoder, pool);
            return true;
        }
        catch
        {
            return false;
        }
    }


    /// <summary>
    /// Gets the SD-JWT string suitable for hashing (without key binding, with trailing tilde).
    /// </summary>
    /// <param name="token">The SD-JWT token.</param>
    /// <param name="encoder">Delegate for Base64Url encoding.</param>
    /// <returns>The SD-JWT string for hashing.</returns>
    public static string GetSdJwtForHashing(SdJwtToken token, EncodeDelegate encoder)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(encoder);

        var builder = new StringBuilder();
        builder.Append(token.IssuerSigned);
        builder.Append(SdConstants.JwtSeparator);

        foreach(SdDisclosure disclosure in token.Disclosures)
        {
            builder.Append(SerializeDisclosure(disclosure, encoder));
            builder.Append(SdConstants.JwtSeparator);
        }

        return builder.ToString();
    }


    /// <summary>
    /// Checks if a string has valid JWT structure (three dot-separated non-empty Base64Url parts).
    /// </summary>
    /// <param name="value">The string to check.</param>
    /// <returns><c>true</c> if the string has valid JWT structure; otherwise, <c>false</c>.</returns>
    public static bool IsValidJwtStructure(string value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }

        string[] parts = value.Split('.');
        if(parts.Length != 3)
        {
            return false;
        }

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


    private static void WriteClaimValue(Utf8JsonWriter writer, object? value)
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

            case JsonElement jsonElement:
                jsonElement.WriteTo(writer);
                break;

            case IDictionary<string, object?> dictValue:
                writer.WriteStartObject();
                foreach(KeyValuePair<string, object?> kvp in dictValue)
                {
                    writer.WritePropertyName(kvp.Key);
                    WriteClaimValue(writer, kvp.Value);
                }
                writer.WriteEndObject();
                break;

            case IEnumerable<object?> listValue:
                writer.WriteStartArray();
                foreach(object? item in listValue)
                {
                    WriteClaimValue(writer, item);
                }
                writer.WriteEndArray();
                break;

            default:
                throw new NotSupportedException($"Type '{value.GetType()}' is not supported.");
        }
    }


    private static object? ConvertJsonElement(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => element.GetString(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => null,
            JsonValueKind.Number => element.TryGetInt64(out long l) ? l : element.GetDecimal(),
            JsonValueKind.Object => ConvertJsonObject(element),
            JsonValueKind.Array => ConvertJsonArray(element),
            _ => throw new NotSupportedException($"Unsupported JSON value kind: {element.ValueKind}")
        };
    }


    private static Dictionary<string, object?> ConvertJsonObject(JsonElement element)
    {
        var dict = new Dictionary<string, object?>();
        foreach(JsonProperty prop in element.EnumerateObject())
        {
            dict[prop.Name] = ConvertJsonElement(prop.Value);
        }
        return dict;
    }


    private static List<object?> ConvertJsonArray(JsonElement element)
    {
        var list = new List<object?>();
        foreach(JsonElement item in element.EnumerateArray())
        {
            list.Add(ConvertJsonElement(item));
        }
        return list;
    }
}