using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Resolvers;

namespace Verifiable.Json.Converters;

/// <summary>
/// Converts <see cref="DidResolutionMetadata"/> to and from the DID resolution metadata JSON object
/// (<c>{ "contentType"?, "error"?, "proof"? }</c>). Member handling is shared with
/// <see cref="DidDereferencingMetadataConverter"/> through <see cref="DidResolutionMetadataJson"/>.
/// </summary>
public class DidResolutionMetadataConverter: JsonConverter<DidResolutionMetadata>
{
    /// <inheritdoc />
    public override bool CanConvert(Type typeToConvert)
    {
        return typeToConvert == typeof(DidResolutionMetadata);
    }


    /// <inheritdoc />
    public override DidResolutionMetadata Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if(reader.TokenType != JsonTokenType.StartObject)
        {
            JsonThrowHelper.ThrowJsonException("DID resolution metadata must be a JSON object.");
        }

        using(var document = JsonDocument.ParseValue(ref reader))
        {
            var (contentType, error, proof) = DidResolutionMetadataJson.ReadMembers(document.RootElement, options);

            return new DidResolutionMetadata
            {
                ContentType = contentType,
                Error = error,
                Proof = proof
            };
        }
    }


    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, DidResolutionMetadata value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(options);

        writer.WriteStartObject();
        DidResolutionMetadataJson.WriteMembers(writer, value.ContentType, value.Error, value.Proof, options);
        writer.WriteEndObject();
    }
}
