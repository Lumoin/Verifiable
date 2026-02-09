using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Cryptography;

namespace Verifiable.JCose;

/// <summary>
/// Functions for parsing JWS messages from various JOSE formats.
/// Returns <see cref="UnverifiedJwsMessage"/> containing untrusted data that must be verified.
/// </summary>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The caller is responsible for disposing the returned UnverifiedJwsMessage.")]
public static class JwsParsing
{
    /// <summary>
    /// Parses a JWS from compact serialization format.
    /// </summary>
    /// <param name="compact">The compact serialization string (header.payload.signature).</param>
    /// <param name="base64UrlDecoder">Delegate for Base64Url decoding.</param>
    /// <param name="headerDeserializer">Delegate for deserializing the header from JSON bytes.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <returns>The parsed unverified JWS message. Caller must dispose.</returns>
    public static UnverifiedJwsMessage ParseCompact(
        string compact,
        DecodeDelegate base64UrlDecoder,
        Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>> headerDeserializer,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(compact);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(headerDeserializer);
        ArgumentNullException.ThrowIfNull(pool);

        string[] parts = compact.Split('.');

        if(parts.Length != 3)
        {
            throw new FormatException(
                $"JWS compact serialization must have exactly three parts separated by '.'. Found {parts.Length} parts.");
        }

        string protectedEncoded = parts[0];
        string payloadEncoded = parts[1];
        string signatureEncoded = parts[2];

        if(string.IsNullOrEmpty(protectedEncoded))
        {
            throw new FormatException("Protected header segment must not be empty.");
        }

        if(string.IsNullOrEmpty(signatureEncoded))
        {
            throw new FormatException("Signature segment must not be empty.");
        }

        using IMemoryOwner<byte> headerBytesOwner = base64UrlDecoder(protectedEncoded, pool);
        IReadOnlyDictionary<string, object> protectedHeader = headerDeserializer(headerBytesOwner.Memory.Span);

        bool isDetached = string.IsNullOrEmpty(payloadEncoded);
        IMemoryOwner<byte>? payloadOwner = null;
        ReadOnlyMemory<byte> payload;

        if(isDetached)
        {
            payload = ReadOnlyMemory<byte>.Empty;
        }
        else
        {
            payloadOwner = base64UrlDecoder(payloadEncoded, pool);
            payload = payloadOwner.Memory;
        }

        IMemoryOwner<byte> signatureOwner = base64UrlDecoder(signatureEncoded, pool);

        var signature = new UnverifiedJwsSignature(
            protectedEncoded,
            protectedHeader,
            signatureOwner);

        return new UnverifiedJwsMessage(payloadOwner, payload, signature, isDetached);
    }


    /// <summary>
    /// Parses a JWS from Flattened JSON serialization format.
    /// </summary>
    /// <param name="json">The Flattened JSON serialization bytes.</param>
    /// <param name="base64UrlDecoder">Delegate for Base64Url decoding.</param>
    /// <param name="headerDeserializer">Delegate for deserializing the header from JSON bytes.</param>
    /// <param name="jsonDeserializer">Delegate for deserializing the JSON object.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <returns>The parsed unverified JWS message. Caller must dispose.</returns>
    public static UnverifiedJwsMessage ParseFlattenedJson(
        ReadOnlySpan<byte> json,
        DecodeDelegate base64UrlDecoder,
        Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>> headerDeserializer,
        Func<ReadOnlySpan<byte>, Dictionary<string, object>> jsonDeserializer,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(headerDeserializer);
        ArgumentNullException.ThrowIfNull(jsonDeserializer);
        ArgumentNullException.ThrowIfNull(pool);

        Dictionary<string, object> jsonObject = jsonDeserializer(json);

        if(!jsonObject.TryGetValue("protected", out object? protectedObj) || protectedObj is not string protectedEncoded)
        {
            throw new FormatException("Flattened JSON JWS must contain a 'protected' property.");
        }

        if(!jsonObject.TryGetValue("signature", out object? signatureObj) || signatureObj is not string signatureEncoded)
        {
            throw new FormatException("Flattened JSON JWS must contain a 'signature' property.");
        }

        using IMemoryOwner<byte> headerBytesOwner = base64UrlDecoder(protectedEncoded, pool);
        IReadOnlyDictionary<string, object> protectedHeader = headerDeserializer(headerBytesOwner.Memory.Span);

        bool isDetached = !jsonObject.TryGetValue("payload", out object? payloadObj);
        IMemoryOwner<byte>? payloadOwner = null;
        ReadOnlyMemory<byte> payload;

        if(isDetached || payloadObj is not string payloadEncoded)
        {
            payload = ReadOnlyMemory<byte>.Empty;
            isDetached = true;
        }
        else
        {
            payloadOwner = base64UrlDecoder(payloadEncoded, pool);
            payload = payloadOwner.Memory;
        }

        IReadOnlyDictionary<string, object>? unprotectedHeader = null;

        if(jsonObject.TryGetValue("header", out object? headerObj) && headerObj is Dictionary<string, object> headerDict)
        {
            unprotectedHeader = headerDict;
        }

        IMemoryOwner<byte> signatureOwner = base64UrlDecoder(signatureEncoded, pool);

        var signature = new UnverifiedJwsSignature(
            protectedEncoded,
            protectedHeader,
            signatureOwner,
            unprotectedHeader);

        return new UnverifiedJwsMessage(payloadOwner, payload, signature, isDetached);
    }


    /// <summary>
    /// Parses a JWS from General JSON serialization format.
    /// </summary>
    /// <param name="json">The General JSON serialization bytes.</param>
    /// <param name="base64UrlDecoder">Delegate for Base64Url decoding.</param>
    /// <param name="headerDeserializer">Delegate for deserializing the header from JSON bytes.</param>
    /// <param name="jsonDeserializer">Delegate for deserializing the JSON object.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <returns>The parsed unverified JWS message. Caller must dispose.</returns>
    public static UnverifiedJwsMessage ParseGeneralJson(
        ReadOnlySpan<byte> json,
        DecodeDelegate base64UrlDecoder,
        Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>> headerDeserializer,
        Func<ReadOnlySpan<byte>, Dictionary<string, object>> jsonDeserializer,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(headerDeserializer);
        ArgumentNullException.ThrowIfNull(jsonDeserializer);
        ArgumentNullException.ThrowIfNull(pool);

        Dictionary<string, object> jsonObject = jsonDeserializer(json);

        if(!jsonObject.TryGetValue("signatures", out object? signaturesObj))
        {
            throw new FormatException("General JSON JWS must contain a 'signatures' property.");
        }

        IList<object>? signaturesList = signaturesObj as IList<object>;

        if(signaturesList is null || signaturesList.Count == 0)
        {
            throw new FormatException("General JSON JWS 'signatures' must be a non-empty array.");
        }

        bool isDetached = !jsonObject.TryGetValue("payload", out object? payloadObj);
        IMemoryOwner<byte>? payloadOwner = null;
        ReadOnlyMemory<byte> payload;

        if(isDetached || payloadObj is not string payloadEncoded)
        {
            payload = ReadOnlyMemory<byte>.Empty;
            isDetached = true;
        }
        else
        {
            payloadOwner = base64UrlDecoder(payloadEncoded, pool);
            payload = payloadOwner.Memory;
        }

        var signatures = new List<UnverifiedJwsSignature>();

        foreach(object sigObj in signaturesList)
        {
            if(sigObj is not Dictionary<string, object> sigDict)
            {
                throw new FormatException("Each element in 'signatures' must be an object.");
            }

            if(!sigDict.TryGetValue("protected", out object? protectedObj) || protectedObj is not string protectedEncoded)
            {
                throw new FormatException("Each signature must contain a 'protected' property.");
            }

            if(!sigDict.TryGetValue("signature", out object? signatureObj) || signatureObj is not string signatureEncoded)
            {
                throw new FormatException("Each signature must contain a 'signature' property.");
            }

            using IMemoryOwner<byte> headerBytesOwner = base64UrlDecoder(protectedEncoded, pool);
            IReadOnlyDictionary<string, object> protectedHeader = headerDeserializer(headerBytesOwner.Memory.Span);

            IReadOnlyDictionary<string, object>? unprotectedHeader = null;

            if(sigDict.TryGetValue("header", out object? headerObj) && headerObj is Dictionary<string, object> headerDict)
            {
                unprotectedHeader = headerDict;
            }

            IMemoryOwner<byte> signatureOwner = base64UrlDecoder(signatureEncoded, pool);

            signatures.Add(new UnverifiedJwsSignature(
                protectedEncoded,
                protectedHeader,
                signatureOwner,
                unprotectedHeader));
        }

        return new UnverifiedJwsMessage(payloadOwner, payload, signatures, isDetached);
    }


    /// <summary>
    /// Attempts to detect the format and parse a JWS.
    /// </summary>
    /// <param name="input">The JWS input bytes.</param>
    /// <param name="base64UrlDecoder">Delegate for Base64Url decoding.</param>
    /// <param name="headerDeserializer">Delegate for deserializing the header from JSON bytes.</param>
    /// <param name="jsonDeserializer">Delegate for deserializing the JSON object.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="message">The parsed unverified JWS message if successful. Caller must dispose.</param>
    /// <param name="format">The detected format if successful.</param>
    /// <returns>True if parsing succeeded, false otherwise.</returns>
    public static bool TryParse(
        ReadOnlySpan<byte> input,
        DecodeDelegate base64UrlDecoder,
        Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>> headerDeserializer,
        Func<ReadOnlySpan<byte>, Dictionary<string, object>> jsonDeserializer,
        MemoryPool<byte> pool,
        out UnverifiedJwsMessage? message,
        out JoseSerializationFormat format)
    {
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(headerDeserializer);
        ArgumentNullException.ThrowIfNull(jsonDeserializer);
        ArgumentNullException.ThrowIfNull(pool);
        message = null;
        format = JoseSerializationFormat.Compact;

        if(input.IsEmpty)
        {
            return false;
        }

        if(input[0] == (byte)'{')
        {
            try
            {
                Dictionary<string, object> jsonObject = jsonDeserializer(input);

                if(jsonObject.ContainsKey("signatures"))
                {
                    message = ParseGeneralJson(input, base64UrlDecoder, headerDeserializer, jsonDeserializer, pool);
                    format = JoseSerializationFormat.GeneralJson;
                    return true;
                }

                if(jsonObject.ContainsKey("protected") && jsonObject.ContainsKey("signature"))
                {
                    message = ParseFlattenedJson(input, base64UrlDecoder, headerDeserializer, jsonDeserializer, pool);
                    format = JoseSerializationFormat.FlattenedJson;
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }
        else
        {
            try
            {
                string compact = Encoding.ASCII.GetString(input);
                message = ParseCompact(compact, base64UrlDecoder, headerDeserializer, pool);
                format = JoseSerializationFormat.Compact;
                return true;
            }
            catch
            {
                return false;
            }
        }

        return false;
    }
}