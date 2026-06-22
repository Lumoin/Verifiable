using System.Collections.Generic;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.DidComm;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json.Converters;

namespace Verifiable.Json;

/// <summary>
/// The concrete JSON implementations of the DIDComm signed-message seams —
/// <see cref="JwtPartEncoder{TJwtPart}"/> for the protected header, <see cref="JwsMessageSerializer"/>
/// for the signed envelope, and <see cref="JwsMessageParser"/> for unpack — plugging the JWS JSON
/// serialization (RFC 7515 §7.2) into the transport-agnostic
/// <see cref="DidCommSignedExtensions"/> pipeline.
/// </summary>
/// <remarks>
/// <para>
/// The DIDComm project is serialization-agnostic and receives these as delegates; this leaf package
/// supplies them. The envelope is materialized as a <c>Dictionary&lt;string, object&gt;</c> whose
/// <c>signatures</c> member is an <see cref="IList{T}"/> of <see cref="object"/> so the shared
/// <see cref="DictionaryStringObjectJsonConverter"/> can write it, and parsing runs through
/// <see cref="JwsParsing"/> whose object-graph expectation that same converter satisfies.
/// </para>
/// </remarks>
public static class DidCommSignedMessageJson
{
    /// <summary>
    /// The serialization options the signed-message delegates use: the source-generated
    /// <see cref="VerifiableJsonContext"/> resolver plus the
    /// <see cref="DictionaryStringObjectJsonConverter"/> for the JOSE object graph.
    /// </summary>
    public static JsonSerializerOptions Options { get; } = CreateOptions();


    /// <summary>
    /// The <see cref="JwtPartEncoder{TJwtPart}"/> that serializes a JWS protected
    /// <see cref="JwtHeader"/> to its UTF-8 JSON bytes, tagged <see cref="JoseBufferTags.JwtHeader"/>.
    /// </summary>
    public static JwtPartEncoder<JwtHeader> ProtectedHeaderEncoder { get; } =
        header => new TaggedMemory<byte>(
            JsonSerializerExtensions.SerializeToUtf8Bytes((Dictionary<string, object>)header, Options),
            JoseBufferTags.JwtHeader);


    /// <summary>
    /// The <see cref="JwsMessageSerializer"/> that serializes a signed JWS message to its
    /// <c>application/didcomm-signed+json</c> <see cref="DidCommSignedMessage"/> wire artifact.
    /// </summary>
    public static JwsMessageSerializer Serializer { get; } =
        (message, format, base64UrlEncoder, memoryPool) =>
        {
            Dictionary<string, object> envelope = BuildEnvelope(message, format, base64UrlEncoder);
            byte[] wire = JsonSerializerExtensions.SerializeToUtf8Bytes(envelope, Options);

            return DidCommSignedMessage.Create(wire, BufferTags.Json, memoryPool);
        };


    /// <summary>
    /// The <see cref="JwsMessageParser"/> that parses <c>application/didcomm-signed+json</c> wire
    /// bytes (General or Flattened JSON) into the parsed-but-unverified <see cref="UnverifiedJwsMessage"/>.
    /// </summary>
    public static JwsMessageParser Parser { get; } =
        (signedJson, base64UrlDecoder, memoryPool) =>
        {
            if(!JwsParsing.TryParse(
                    signedJson,
                    base64UrlDecoder,
                    HeaderDeserializer,
                    JsonDeserializer,
                    memoryPool,
                    out UnverifiedJwsMessage? message,
                    out JoseSerializationFormat format)
                || message is null)
            {
                throw new FormatException("A DIDComm signed message MUST be a JWS JSON serialization (General or Flattened).");
            }

            if(format == JoseSerializationFormat.Compact)
            {
                message.Dispose();

                throw new FormatException(
                    "A DIDComm signed message MUST use the JSON serialization, not compact (DIDComm v2.1 §DIDComm Signed Messages).");
            }

            return message;
        };


    //Materializes the JWS JSON envelope as a Dictionary<string, object> whose `signatures` member is
    //an IList<object> (each element a Dictionary<string, object>), the shape the
    //DictionaryStringObjectJsonConverter writes. Mirrors JwsSerialization's General / Flattened forms;
    //compact is rejected upstream so only the two JSON forms reach here.
    private static Dictionary<string, object> BuildEnvelope(JwsMessage message, JoseSerializationFormat format, EncodeDelegate base64UrlEncoder)
    {
        if(format == JoseSerializationFormat.FlattenedJson)
        {
            JwsSignatureComponent only = message.Signatures[0];
            var flattened = new Dictionary<string, object>
            {
                ["payload"] = base64UrlEncoder(message.Payload.Span),
                ["protected"] = only.Protected,
                ["signature"] = base64UrlEncoder(only.SignatureBytes.Span)
            };

            if(only.UnprotectedHeader is { Count: > 0 })
            {
                flattened["header"] = new Dictionary<string, object>(only.UnprotectedHeader);
            }

            return flattened;
        }

        var signatures = new List<object>(message.Signatures.Count);
        foreach(JwsSignatureComponent signature in message.Signatures)
        {
            var signatureObject = new Dictionary<string, object>
            {
                ["protected"] = signature.Protected,
                ["signature"] = base64UrlEncoder(signature.SignatureBytes.Span)
            };

            if(signature.UnprotectedHeader is { Count: > 0 })
            {
                signatureObject["header"] = new Dictionary<string, object>(signature.UnprotectedHeader);
            }

            signatures.Add(signatureObject);
        }

        return new Dictionary<string, object>
        {
            ["payload"] = base64UrlEncoder(message.Payload.Span),
            ["signatures"] = signatures
        };
    }


    //Adapts the leaf's dictionary deserialization to the JCose JwsParsing header-deserializer Func
    //(a contained boundary adaptation, as in the OAuth JarVerification pattern).
    private static IReadOnlyDictionary<string, object> HeaderDeserializer(ReadOnlySpan<byte> headerJson) =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(headerJson, Options)
            ?? throw new FormatException("A JWS header MUST NOT be JSON null.");


    //Adapts the leaf's dictionary deserialization to the JCose JwsParsing json-deserializer Func.
    private static Dictionary<string, object> JsonDeserializer(ReadOnlySpan<byte> json) =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(json, Options)
            ?? throw new FormatException("A JWS JSON serialization MUST NOT be JSON null.");


    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            TypeInfoResolver = VerifiableJsonContext.Default
        };

        options.Converters.Add(new DictionaryStringObjectJsonConverter(VerifiableJsonContext.Default));

        return options;
    }
}
