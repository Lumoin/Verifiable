using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.DidComm;
using Verifiable.Foundation;
using Verifiable.Json.Converters;

namespace Verifiable.Json;

/// <summary>
/// The concrete JSON implementations of the DIDComm <see cref="DidCommMessageSerializer"/> and
/// <see cref="DidCommMessageParser"/> seams, plugging the <see cref="DidCommMessageConverter"/> into
/// the transport-agnostic pack/unpack pipeline of
/// <see cref="DidCommPlaintextExtensions"/>.
/// </summary>
/// <remarks>
/// <para>
/// The DIDComm project is serialization-agnostic and receives the serializer and parser as
/// delegates; this leaf package supplies them. Both delegates run through the AOT-clean
/// <see cref="JsonSerializerExtensions"/> helpers — which resolve the
/// <see cref="System.Text.Json.Serialization.Metadata.JsonTypeInfo{T}"/> for
/// <see cref="DidCommMessage"/> from the source-generated <see cref="VerifiableJsonContext"/> — so
/// no reflection-based <c>JsonSerializer</c> overload is taken.
/// </para>
/// <para>
/// The produced bytes are the <c>application/didcomm-plain+json</c> plaintext JWM that a signed or
/// encrypted envelope subsequently wraps.
/// </para>
/// </remarks>
public static class DidCommMessageJson
{
    /// <summary>
    /// The serialization options the DIDComm plaintext delegates use: the source-generated
    /// <see cref="VerifiableJsonContext"/> resolver, the <see cref="DidCommMessageConverter"/>, and
    /// null-member suppression so optional headers are omitted rather than emitted as JSON null.
    /// </summary>
    /// <remarks>
    /// No property naming policy is needed — the converter writes the snake_case spec member names
    /// (<c>created_time</c>, <c>from_prior</c>, …) verbatim.
    /// </remarks>
    public static JsonSerializerOptions Options { get; } = CreateOptions();


    /// <summary>
    /// The <see cref="DidCommMessageSerializer"/> that serializes a <see cref="DidCommMessage"/> to
    /// its <c>application/didcomm-plain+json</c> <see cref="DidCommPlaintextMessage"/> artifact.
    /// </summary>
    public static DidCommMessageSerializer Serializer { get; } =
        (message, memoryPool) => DidCommPlaintextMessage.Create(
            JsonSerializerExtensions.SerializeToUtf8Bytes(message, Options), BufferTags.Json, memoryPool);


    /// <summary>
    /// The <see cref="DidCommMessageParser"/> that parses <c>application/didcomm-plain+json</c>
    /// UTF-8 bytes into a <see cref="DidCommMessage"/>.
    /// </summary>
    public static DidCommMessageParser Parser { get; } =
        plaintextJson => JsonSerializerExtensions.Deserialize<DidCommMessage>(plaintextJson, Options)
            ?? throw new JsonException("A DIDComm plaintext message MUST NOT be JSON null.");


    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            TypeInfoResolver = VerifiableJsonContext.Default
        };

        options.Converters.Add(new DidCommMessageConverter());

        return options;
    }
}
