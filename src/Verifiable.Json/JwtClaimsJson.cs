using System;
using System.Collections.Generic;
using System.Text.Json;
using Verifiable.JCose;
using Verifiable.Json.Converters;

namespace Verifiable.Json;

/// <summary>
/// The concrete JSON implementations of the JWT-claims seams a DID Rotation <c>from_prior</c> JWT
/// crosses — <see cref="JwtHeaderSerializer"/> and <see cref="JwtPayloadSerializer"/> for minting, and
/// <see cref="JwtClaimsDeserializer"/> plus <see cref="HeaderDeserializer"/> for verifying — over the
/// source-generated <see cref="VerifiableJsonContext"/> (which registers <see cref="JwtHeader"/> and
/// <see cref="JwtPayload"/>).
/// </summary>
/// <remarks>
/// <para>
/// The <c>Verifiable.DidComm</c> rotation pipeline is serialization-agnostic and receives these as
/// delegates, exactly as <c>PackSignedAsync</c>/<c>UnpackSignedAsync</c> receive their serializers;
/// this leaf package is the only place the <see cref="System.Text.Json"/> machinery touches the
/// compact <c>from_prior</c> JWT. A <see cref="JwtHeader"/>/<see cref="JwtPayload"/> is a
/// <see cref="Dictionary{TKey, TValue}"/> of <see cref="string"/> to <see cref="object"/>, so the
/// shared <see cref="DictionaryStringObjectJsonConverter"/> writes and reads its object graph (the
/// same converter the DIDComm signed-message envelope uses).
/// </para>
/// </remarks>
public static class JwtClaimsJson
{
    /// <summary>
    /// The serialization options the JWT-claims delegates use: the source-generated
    /// <see cref="VerifiableJsonContext"/> resolver plus the
    /// <see cref="DictionaryStringObjectJsonConverter"/> for the claims object graph.
    /// </summary>
    public static JsonSerializerOptions Options { get; } = CreateOptions();


    /// <summary>
    /// The <see cref="JwtHeaderSerializer"/> that serializes a <see cref="JwtHeader"/> to its UTF-8
    /// JSON bytes — the protected header of the <c>from_prior</c> JWT.
    /// </summary>
    public static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes((Dictionary<string, object>)header, Options);


    /// <summary>
    /// The <see cref="JwtPayloadSerializer"/> that serializes a <see cref="JwtPayload"/> to its UTF-8
    /// JSON bytes — the claims set (<c>iss</c>/<c>sub</c>/<c>iat</c>) of the <c>from_prior</c> JWT.
    /// </summary>
    public static JwtPayloadSerializer PayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes((Dictionary<string, object>)payload, Options);


    /// <summary>
    /// The <see cref="JwtClaimsDeserializer"/> that parses the UTF-8 JSON bytes of a <c>from_prior</c>
    /// JWT payload into a <see cref="JwtPayload"/>.
    /// </summary>
    public static JwtClaimsDeserializer PayloadDeserializer { get; } = DeserializePayload;


    /// <summary>
    /// The protected-header deserializer <see cref="JwsParsing.ParseCompact"/> takes — adapts the
    /// leaf's dictionary deserialization to the parser's header-deserializer <see cref="System.Func{T, TResult}"/>.
    /// </summary>
    public static IReadOnlyDictionary<string, object> HeaderDeserializer(System.ReadOnlySpan<byte> headerJson)
    {
        return DeserializeObject(headerJson, "header");
    }


    //Deserializes the from_prior payload, translating a malformed-JSON failure into the framework-neutral
    //FormatException the DID-rotation pipeline keys on — so the System.Text.Json exception never crosses out
    //of this leaf into Verifiable.DidComm (the serialization firewall boundary).
    private static JwtPayload DeserializePayload(System.ReadOnlySpan<byte> payloadJson)
    {
        return new JwtPayload(DeserializeObject(payloadJson, "payload"));
    }


    //Deserializes a from_prior JWT segment's UTF-8 JSON object, translating System.Text.Json's JsonException
    //(and a JSON-null result) into FormatException so no STJ type escapes this leaf.
    private static Dictionary<string, object> DeserializeObject(System.ReadOnlySpan<byte> json, string segment)
    {
        Dictionary<string, object>? value;
        try
        {
            value = JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(json, Options);
        }
        catch(JsonException exception)
        {
            throw new FormatException($"The from_prior JWT {segment} is not valid JSON.", exception);
        }

        return value ?? throw new FormatException($"A from_prior JWT {segment} MUST NOT be JSON null.");
    }


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
