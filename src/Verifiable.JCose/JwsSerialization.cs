using System.Text;
using Verifiable.Cryptography;

namespace Verifiable.JCose;

/// <summary>
/// Functions for serializing <see cref="JwsMessage"/> to various JOSE formats.
/// </summary>
/// <remarks>
/// <para>
/// Supports three serialization formats per RFC 7515:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Compact</strong>: URL-safe string with three Base64Url-encoded parts.
/// Requires exactly one signature and non-detached payload.
/// </description></item>
/// <item><description>
/// <strong>Flattened JSON</strong>: Single signature in a JSON object.
/// Supports unprotected headers and detached payloads.
/// </description></item>
/// <item><description>
/// <strong>General JSON</strong>: Multiple signatures in a JSON object.
/// Most flexible format, supports all JWS features.
/// </description></item>
/// </list>
/// </remarks>
public static class JwsSerialization
{
    /// <summary>
    /// Serializes a JWS message to compact serialization format.
    /// </summary>
    /// <param name="message">The JWS message to serialize.</param>
    /// <param name="base64UrlEncoder">Delegate for Base64Url encoding.</param>
    /// <returns>The compact serialization string (header.payload.signature).</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="message"/> or <paramref name="base64UrlEncoder"/> is null.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the message has multiple signatures or a detached payload.
    /// </exception>
    public static string SerializeCompact(JwsMessage message, EncodeDelegate base64UrlEncoder)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);

        if(message.Signatures.Count != 1)
        {
            throw new InvalidOperationException(
                $"Compact serialization requires exactly one signature. Message has {message.Signatures.Count} signatures. Use General JSON serialization for multiple signatures.");
        }

        if(message.IsDetachedPayload)
        {
            throw new InvalidOperationException(
                "Compact serialization does not support detached payloads. Use Flattened or General JSON serialization.");
        }

        JwsSignatureComponent signature = message.Signatures[0];
        string payloadSegment = base64UrlEncoder(message.Payload.Span);
        string signatureSegment = base64UrlEncoder(signature.Signature.AsReadOnlySpan());

        return $"{signature.Protected}.{payloadSegment}.{signatureSegment}";
    }


    /// <summary>
    /// Serializes a JWS message to Flattened JSON serialization format.
    /// </summary>
    /// <param name="message">The JWS message to serialize.</param>
    /// <param name="base64UrlEncoder">Delegate for Base64Url encoding.</param>
    /// <param name="jsonSerializer">Delegate for serializing objects to JSON.</param>
    /// <returns>The Flattened JSON serialization as UTF-8 bytes.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when any parameter is null.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the message has multiple signatures.
    /// </exception>
    public static byte[] SerializeFlattenedJson(
        JwsMessage message,
        EncodeDelegate base64UrlEncoder,
        Func<object, byte[]> jsonSerializer)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(jsonSerializer);

        if(message.Signatures.Count != 1)
        {
            throw new InvalidOperationException(
                $"Flattened JSON serialization requires exactly one signature. Message has {message.Signatures.Count} signatures. Use General JSON serialization for multiple signatures.");
        }

        JwsSignatureComponent signature = message.Signatures[0];

        var jsonObject = new Dictionary<string, object>
        {
            ["protected"] = signature.Protected,
            ["signature"] = base64UrlEncoder(signature.Signature)
        };

        if(!message.IsDetachedPayload)
        {
            jsonObject["payload"] = base64UrlEncoder(message.Payload.Span);
        }

        if(signature.UnprotectedHeader is not null && signature.UnprotectedHeader.Count > 0)
        {
            jsonObject["header"] = signature.UnprotectedHeader;
        }

        return jsonSerializer(jsonObject);
    }


    /// <summary>
    /// Serializes a JWS message to General JSON serialization format.
    /// </summary>
    /// <param name="message">The JWS message to serialize.</param>
    /// <param name="base64UrlEncoder">Delegate for Base64Url encoding.</param>
    /// <param name="jsonSerializer">Delegate for serializing objects to JSON.</param>
    /// <returns>The General JSON serialization as UTF-8 bytes.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when any parameter is null.
    /// </exception>
    public static byte[] SerializeGeneralJson(
        JwsMessage message,
        EncodeDelegate base64UrlEncoder,
        Func<object, byte[]> jsonSerializer)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(jsonSerializer);

        var signatures = new List<Dictionary<string, object>>();

        foreach(JwsSignatureComponent sig in message.Signatures)
        {
            var sigObject = new Dictionary<string, object>
            {
                ["protected"] = sig.Protected,
                ["signature"] = base64UrlEncoder(sig.Signature)
            };

            if(sig.UnprotectedHeader is not null && sig.UnprotectedHeader.Count > 0)
            {
                sigObject["header"] = sig.UnprotectedHeader;
            }

            signatures.Add(sigObject);
        }

        var jsonObject = new Dictionary<string, object>
        {
            ["signatures"] = signatures
        };

        if(!message.IsDetachedPayload)
        {
            jsonObject["payload"] = base64UrlEncoder(message.Payload.Span);
        }

        return jsonSerializer(jsonObject);
    }


    /// <summary>
    /// Serializes a JWS message to the specified format.
    /// </summary>
    /// <param name="message">The JWS message to serialize.</param>
    /// <param name="format">The serialization format to use.</param>
    /// <param name="base64UrlEncoder">Delegate for Base64Url encoding.</param>
    /// <param name="jsonSerializer">Delegate for serializing objects to JSON.</param>
    /// <returns>The serialized JWS as UTF-8 bytes.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when any parameter is null.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="format"/> is not a valid format.
    /// </exception>
    public static byte[] Serialize(
        JwsMessage message,
        JoseSerializationFormat format,
        EncodeDelegate base64UrlEncoder,
        Func<object, byte[]> jsonSerializer)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(jsonSerializer);

        return format switch
        {
            JoseSerializationFormat.Compact => Encoding.ASCII.GetBytes(SerializeCompact(message, base64UrlEncoder)),
            JoseSerializationFormat.FlattenedJson => SerializeFlattenedJson(message, base64UrlEncoder, jsonSerializer),
            JoseSerializationFormat.GeneralJson => SerializeGeneralJson(message, base64UrlEncoder, jsonSerializer),
            _ => throw new ArgumentOutOfRangeException(nameof(format), format, "Unknown serialization format.")
        };
    }
}