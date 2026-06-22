using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Resolvers;

namespace Verifiable.Json.Converters;

/// <summary>
/// Converts <see cref="DidDereferencingResult"/> to and from the W3C DID URL Dereferencing Result
/// envelope (<c>{ "contentStream", "dereferencingMetadata", "contentMetadata" }</c>, media type
/// <c>application/did-url-dereferencing</c>).
/// </summary>
/// <remarks>
/// <para>
/// <see cref="DidDereferencingResult.ContentStream"/> is an open <see cref="object"/> because
/// dereferencing yields different resource shapes. The writer dispatches on the runtime type:
/// </para>
/// <list type="bullet">
///   <item><description><see cref="DidDocument"/> — serialized as the DID document object.</description></item>
///   <item><description><see cref="VerifiablePresentation"/> / <see cref="DataIntegritySecuredPresentation"/> — serialized as the presentation object (the did:webvh <c>/whois</c> case).</description></item>
///   <item><description><see cref="Service"/> / <see cref="VerificationMethod"/> — serialized as the fragment-dereferenced resource object.</description></item>
///   <item><description><see cref="string"/> — written as a JSON string (a service-endpoint URI).</description></item>
///   <item><description><see cref="TaggedMemory{Byte}"/> / <see cref="ReadOnlyMemory{Byte}"/> — decoded as UTF-8; written raw when it parses as JSON, otherwise as a base64 JSON string.</description></item>
///   <item><description><see langword="null"/> — written as JSON <c>null</c> (the failure case).</description></item>
/// </list>
/// <para>
/// On read, the <c>contentStream</c> is a structurally open value; it is materialized best-effort as a
/// <see cref="DidDocument"/> when it is a DID-document-shaped object, otherwise as a
/// <see cref="JsonElement"/>. Callers that need a specific typed resource should drive the result
/// through <see cref="DidResolver.DereferenceAsync"/> rather than reconstructing it from JSON.
/// </para>
/// </remarks>
public class DidDereferencingResultConverter: JsonConverter<DidDereferencingResult>
{
    /// <inheritdoc />
    public override bool CanConvert(Type typeToConvert)
    {
        return typeToConvert == typeof(DidDereferencingResult);
    }


    /// <inheritdoc />
    public override DidDereferencingResult Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if(reader.TokenType != JsonTokenType.StartObject)
        {
            JsonThrowHelper.ThrowJsonException("A DID URL dereferencing result must be a JSON object.");
        }

        using(var document = JsonDocument.ParseValue(ref reader))
        {
            JsonElement root = document.RootElement;

            object? contentStream = null;
            if(root.TryGetProperty("contentStream"u8, out JsonElement contentStreamElement)
                && contentStreamElement.ValueKind != JsonValueKind.Null)
            {
                contentStream = ReadContentStream(contentStreamElement, options);
            }

            DidDereferencingMetadata dereferencingMetadata = root.TryGetProperty("dereferencingMetadata"u8, out JsonElement metadataElement)
                ? metadataElement.Deserialize((JsonTypeInfo<DidDereferencingMetadata>)options.GetTypeInfo(typeof(DidDereferencingMetadata))) ?? new DidDereferencingMetadata()
                : new DidDereferencingMetadata();

            DidDocumentMetadata? contentMetadata = null;
            if(root.TryGetProperty("contentMetadata"u8, out JsonElement contentMetadataElement)
                && contentMetadataElement.ValueKind == JsonValueKind.Object)
            {
                contentMetadata = contentMetadataElement.Deserialize((JsonTypeInfo<DidDocumentMetadata>)options.GetTypeInfo(typeof(DidDocumentMetadata)));
            }

            return new DidDereferencingResult
            {
                DereferencingMetadata = dereferencingMetadata,
                ContentStream = contentStream,
                ContentMetadata = contentMetadata
            };
        }
    }


    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, DidDereferencingResult value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(options);

        writer.WriteStartObject();

        writer.WritePropertyName("contentStream"u8);
        DidContentStreamJson.Write(writer, value.ContentStream, options);

        writer.WritePropertyName("dereferencingMetadata"u8);
        JsonSerializer.Serialize(writer, value.DereferencingMetadata, options.GetTypeInfo(typeof(DidDereferencingMetadata)));

        if(value.ContentMetadata is not null)
        {
            writer.WritePropertyName("contentMetadata"u8);
            JsonSerializer.Serialize(writer, value.ContentMetadata, options.GetTypeInfo(typeof(DidDocumentMetadata)));
        }

        writer.WriteEndObject();
    }


    private static object ReadContentStream(JsonElement element, JsonSerializerOptions options)
    {
        if(element.ValueKind == JsonValueKind.String)
        {
            return element.GetString()!;
        }

        if(element.ValueKind == JsonValueKind.Object
            && element.TryGetProperty("id"u8, out _)
            && element.TryGetProperty("@context"u8, out _))
        {
            DidDocument? document = element.Deserialize((JsonTypeInfo<DidDocument>)options.GetTypeInfo(typeof(DidDocument)));
            if(document is not null)
            {
                return document;
            }
        }

        return element.Clone();
    }
}
