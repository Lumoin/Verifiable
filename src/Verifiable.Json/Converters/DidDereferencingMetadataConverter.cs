using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Resolvers;

namespace Verifiable.Json.Converters;

/// <summary>
/// Converts <see cref="DidDereferencingMetadata"/> to and from the DID dereferencing metadata JSON
/// object (<c>{ "contentType"?, "error"?, "proof"? }</c>). Member handling is shared with
/// <see cref="DidResolutionMetadataConverter"/> through <see cref="DidResolutionMetadataJson"/>.
/// </summary>
public class DidDereferencingMetadataConverter: JsonConverter<DidDereferencingMetadata>
{
    /// <inheritdoc />
    public override bool CanConvert(Type typeToConvert)
    {
        return typeToConvert == typeof(DidDereferencingMetadata);
    }


    /// <inheritdoc />
    public override DidDereferencingMetadata Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if(reader.TokenType != JsonTokenType.StartObject)
        {
            JsonThrowHelper.ThrowJsonException("DID dereferencing metadata must be a JSON object.");
        }

        using(var document = JsonDocument.ParseValue(ref reader))
        {
            var (contentType, error, proof) = DidResolutionMetadataJson.ReadMembers(document.RootElement, options);

            return new DidDereferencingMetadata
            {
                ContentType = contentType,
                Error = error,
                Proof = proof
            };
        }
    }


    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, DidDereferencingMetadata value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(options);

        writer.WriteStartObject();
        DidResolutionMetadataJson.WriteMembers(writer, value.ContentType, value.Error, value.Proof, options);
        writer.WriteEndObject();
    }
}
