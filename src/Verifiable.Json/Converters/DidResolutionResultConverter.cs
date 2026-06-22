using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Resolvers;

namespace Verifiable.Json.Converters;

/// <summary>
/// Converts <see cref="DidResolutionResult"/> to and from the W3C DID Resolution Result envelope
/// (<c>{ "didDocument", "didResolutionMetadata", "didDocumentMetadata" }</c>, media type
/// <c>application/did-resolution</c>).
/// </summary>
/// <remarks>
/// <para>
/// <c>didDocument</c> is written as JSON <c>null</c> when the result carries no document (the failure
/// case the spec requires). The internal <see cref="DidResolutionResult.Kind"/> and
/// <see cref="DidResolutionResult.DocumentUrl"/> are NOT W3C envelope members and are not emitted.
/// </para>
/// </remarks>
public class DidResolutionResultConverter: JsonConverter<DidResolutionResult>
{
    /// <inheritdoc />
    public override bool CanConvert(Type typeToConvert)
    {
        return typeToConvert == typeof(DidResolutionResult);
    }


    /// <inheritdoc />
    public override DidResolutionResult Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if(reader.TokenType != JsonTokenType.StartObject)
        {
            JsonThrowHelper.ThrowJsonException("A DID resolution result must be a JSON object.");
        }

        using(var document = JsonDocument.ParseValue(ref reader))
        {
            JsonElement root = document.RootElement;

            DidDocument? didDocument = null;
            if(root.TryGetProperty("didDocument"u8, out JsonElement documentElement)
                && documentElement.ValueKind != JsonValueKind.Null)
            {
                didDocument = documentElement.Deserialize((JsonTypeInfo<DidDocument>)options.GetTypeInfo(typeof(DidDocument)));
            }

            DidResolutionMetadata resolutionMetadata = root.TryGetProperty("didResolutionMetadata"u8, out JsonElement resolutionElement)
                ? resolutionElement.Deserialize((JsonTypeInfo<DidResolutionMetadata>)options.GetTypeInfo(typeof(DidResolutionMetadata))) ?? new DidResolutionMetadata()
                : new DidResolutionMetadata();

            DidDocumentMetadata documentMetadata = root.TryGetProperty("didDocumentMetadata"u8, out JsonElement documentMetadataElement)
                ? documentMetadataElement.Deserialize((JsonTypeInfo<DidDocumentMetadata>)options.GetTypeInfo(typeof(DidDocumentMetadata))) ?? DidDocumentMetadata.Empty
                : DidDocumentMetadata.Empty;

            //The envelope carries no Kind discriminator (it is an internal dispatch concern); a
            //round-tripped result is reconstructed as a Document-kind result, the only kind the
            //envelope can represent.
            return new DidResolutionResult
            {
                Kind = DidResolutionKind.Document,
                Document = didDocument,
                ResolutionMetadata = resolutionMetadata,
                DocumentMetadata = documentMetadata
            };
        }
    }


    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, DidResolutionResult value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(options);

        writer.WriteStartObject();

        writer.WritePropertyName("didDocument"u8);
        if(value.Document is null)
        {
            writer.WriteNullValue();
        }
        else
        {
            JsonSerializer.Serialize(writer, value.Document, options.GetTypeInfo(typeof(DidDocument)));
        }

        writer.WritePropertyName("didResolutionMetadata"u8);
        JsonSerializer.Serialize(writer, value.ResolutionMetadata, options.GetTypeInfo(typeof(DidResolutionMetadata)));

        writer.WritePropertyName("didDocumentMetadata"u8);
        JsonSerializer.Serialize(writer, value.DocumentMetadata, options.GetTypeInfo(typeof(DidDocumentMetadata)));

        writer.WriteEndObject();
    }
}
