using System.Buffers;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.Jose;
using Verifiable.Jose.SdJwt;

namespace Verifiable.Json;

/// <summary>
/// JSON-specific extension methods for Key Binding JWT operations.
/// </summary>
public static class KeyBindingJwtJsonExtensions
{
    /// <summary>
    /// Parses a Key Binding JWT and extracts its header and payload as dictionaries.
    /// </summary>
    /// <param name="kbJwt">The Key Binding JWT string.</param>
    /// <param name="base64UrlDecoder">Delegate for base64url decoding.</param>
    /// <param name="memoryPool">Memory pool for allocation.</param>
    /// <returns>A tuple containing the header and payload as dictionaries.</returns>
    /// <exception cref="ArgumentException">Thrown when the KB-JWT format is invalid.</exception>
    public static (Dictionary<string, object> Header, Dictionary<string, object> Payload) ParseToDictionary(
        string kbJwt,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> memoryPool)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(kbJwt, nameof(kbJwt));
        ArgumentNullException.ThrowIfNull(base64UrlDecoder, nameof(base64UrlDecoder));
        ArgumentNullException.ThrowIfNull(memoryPool, nameof(memoryPool));

        string[] parts = kbJwt.Split('.');
        if(parts.Length != 3)
        {
            throw new ArgumentException("Key Binding JWT must have exactly three parts.", nameof(kbJwt));
        }

        Dictionary<string, object> header;
        Dictionary<string, object> payload;

        using(IMemoryOwner<byte> headerBytes = base64UrlDecoder(parts[0], memoryPool))
        {
            using JsonDocument headerDoc = JsonDocument.Parse((ReadOnlyMemory<byte>)headerBytes.Memory);
            header = ExtractDictionary(headerDoc.RootElement);
        }

        using(IMemoryOwner<byte> payloadBytes = base64UrlDecoder(parts[1], memoryPool))
        {
            using JsonDocument payloadDoc = JsonDocument.Parse((ReadOnlyMemory<byte>)payloadBytes.Memory);
            payload = ExtractDictionary(payloadDoc.RootElement);
        }

        //Validate typ header.
        if(header.TryGetValue(JwkProperties.Typ, out object? typObj) && typObj is string typ)
        {
            if(!string.Equals(typ, SdJwtConstants.KeyBindingJwtType, StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    $"Key Binding JWT typ must be '{SdJwtConstants.KeyBindingJwtType}', but was '{typ}'.",
                    nameof(kbJwt));
            }
        }

        return (header, payload);
    }


    /// <summary>
    /// Validates the sd_hash claim in a Key Binding JWT payload against an SD-JWT.
    /// </summary>
    /// <param name="kbJwtPayload">The parsed KB-JWT payload as a JsonElement.</param>
    /// <param name="sdJwtToken">The SD-JWT token to validate against.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use.</param>
    /// <param name="base64UrlEncoder">Delegate for base64url encoding.</param>
    /// <returns>True if the sd_hash matches; otherwise, false.</returns>
    public static bool ValidateSdHash(
        JsonElement kbJwtPayload,
        SdJwtToken sdJwtToken,
        string hashAlgorithm,
        EncodeDelegate base64UrlEncoder)
    {
        ArgumentNullException.ThrowIfNull(sdJwtToken, nameof(sdJwtToken));
        ArgumentNullException.ThrowIfNull(base64UrlEncoder, nameof(base64UrlEncoder));

        if(!kbJwtPayload.TryGetProperty(SdJwtConstants.SdHashClaimName, out JsonElement sdHashElement))
        {
            return false;
        }

        string? claimedSdHash = sdHashElement.GetString();
        if(string.IsNullOrEmpty(claimedSdHash))
        {
            return false;
        }

        string expectedSdHash = sdJwtToken.ComputeSdHash(hashAlgorithm, base64UrlEncoder);

        return string.Equals(claimedSdHash, expectedSdHash, StringComparison.Ordinal);
    }


    /// <summary>
    /// Validates the required claims in a Key Binding JWT payload.
    /// </summary>
    /// <param name="payload">The KB-JWT payload as a JsonElement.</param>
    /// <param name="expectedAudience">The expected audience value, or null to skip audience validation.</param>
    /// <param name="expectedNonce">The expected nonce value, or null to skip nonce validation.</param>
    /// <param name="timeProvider">Time provider for iat validation.</param>
    /// <param name="allowedClockSkew">Maximum allowed clock skew for time validation.</param>
    /// <returns>A validation result indicating success or the specific validation failure.</returns>
    public static KeyBindingValidationResult ValidateClaims(
        JsonElement payload,
        string? expectedAudience,
        string? expectedNonce,
        TimeProvider timeProvider,
        TimeSpan allowedClockSkew)
    {
        ArgumentNullException.ThrowIfNull(timeProvider, nameof(timeProvider));

        //Validate iat (required).
        if(!payload.TryGetProperty(WellKnownJwtClaims.Iat, out JsonElement iatElement))
        {
            return KeyBindingValidationResult.MissingIat;
        }

        if(!iatElement.TryGetInt64(out long iatValue))
        {
            return KeyBindingValidationResult.InvalidIat;
        }

        DateTimeOffset iat = DateTimeOffset.FromUnixTimeSeconds(iatValue);
        DateTimeOffset now = timeProvider.GetUtcNow();

        //Check if iat is too far in the future.
        if(iat > now.Add(allowedClockSkew))
        {
            return KeyBindingValidationResult.IatInFuture;
        }

        //Validate aud (required).
        if(!payload.TryGetProperty(WellKnownJwtClaims.Aud, out JsonElement audElement))
        {
            return KeyBindingValidationResult.MissingAud;
        }

        string? aud = audElement.GetString();
        if(string.IsNullOrEmpty(aud))
        {
            return KeyBindingValidationResult.InvalidAud;
        }

        if(expectedAudience is not null && !string.Equals(aud, expectedAudience, StringComparison.Ordinal))
        {
            return KeyBindingValidationResult.AudienceMismatch;
        }

        //Validate nonce (required).
        if(!payload.TryGetProperty(SdJwtConstants.NonceClaim, out JsonElement nonceElement))
        {
            return KeyBindingValidationResult.MissingNonce;
        }

        string? nonce = nonceElement.GetString();
        if(string.IsNullOrEmpty(nonce))
        {
            return KeyBindingValidationResult.InvalidNonce;
        }

        if(expectedNonce is not null && !string.Equals(nonce, expectedNonce, StringComparison.Ordinal))
        {
            return KeyBindingValidationResult.NonceMismatch;
        }

        //Validate sd_hash (required).
        if(!payload.TryGetProperty(SdJwtConstants.SdHashClaimName, out JsonElement sdHashElement))
        {
            return KeyBindingValidationResult.MissingSdHash;
        }

        string? sdHash = sdHashElement.GetString();
        if(string.IsNullOrEmpty(sdHash))
        {
            return KeyBindingValidationResult.InvalidSdHash;
        }

        return KeyBindingValidationResult.Valid;
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