using System.Buffers;
using System.Text;
using System.Text.Json;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Resolvers;
using Verifiable.Json.Converters;

namespace Verifiable.Json;

/// <summary>
/// The <c>Verifiable.Json</c>-leaf implementations of the DID resolution-result serialization
/// delegates declared in <c>Verifiable.Core</c>. A host binds these to the Core delegate seams so
/// the library serializes the W3C DID Resolution / DID URL Dereferencing envelopes without taking a
/// <c>System.Text.Json</c> dependency in <c>Verifiable.Core</c>.
/// </summary>
public static class DidResolutionResultJson
{
    /// <summary>
    /// Creates a <see cref="DidResolutionResultSerializer"/> that serializes the full DID Resolution
    /// Result envelope using <paramref name="options"/>.
    /// </summary>
    /// <param name="options">The serializer options whose converters render the envelope.</param>
    /// <returns>A delegate that serializes a resolution result to its envelope JSON.</returns>
    public static DidResolutionResultSerializer CreateResultSerializer(JsonSerializerOptions options)
    {
        return result => JsonSerializerExtensions.Serialize(result, options);
    }


    /// <summary>
    /// Creates a <see cref="DidDereferencingResultSerializer"/> that serializes the full DID URL
    /// Dereferencing Result envelope using <paramref name="options"/>.
    /// </summary>
    /// <param name="options">The serializer options whose converters render the envelope.</param>
    /// <returns>A delegate that serializes a dereferencing result to its envelope JSON.</returns>
    public static DidDereferencingResultSerializer CreateDereferencingSerializer(JsonSerializerOptions options)
    {
        return result => JsonSerializerExtensions.Serialize(result, options);
    }


    /// <summary>
    /// Creates a <see cref="DidDocumentSerializer"/> that serializes a bare DID document using
    /// <paramref name="options"/>, for the binding's plain-media-type content-negotiation case.
    /// </summary>
    /// <param name="options">The serializer options whose converters render the document.</param>
    /// <returns>A delegate that serializes a DID document to its JSON.</returns>
    public static DidDocumentSerializer CreateDocumentSerializer(JsonSerializerOptions options)
    {
        return document => JsonSerializerExtensions.Serialize(document, options);
    }


    /// <summary>
    /// Creates a <see cref="DidContentStreamSerializer"/> that serializes a bare dereferenced content stream
    /// (the open <see cref="DidDereferencingResult.ContentStream"/> object) using <paramref name="options"/>,
    /// for the binding's plain-media-type dereferencing case where the body is the resource itself rather than
    /// the full dereferencing-result envelope.
    /// </summary>
    /// <param name="options">The serializer options whose converters render the resource.</param>
    /// <returns>A delegate that serializes a content stream to its JSON representation.</returns>
    public static DidContentStreamSerializer CreateContentStreamSerializer(JsonSerializerOptions options)
    {
        return contentStream =>
        {
            ArrayBufferWriter<byte> buffer = new();
            using(Utf8JsonWriter writer = new(buffer, new JsonWriterOptions { Encoder = options.Encoder, Indented = options.WriteIndented }))
            {
                DidContentStreamJson.Write(writer, contentStream, options);
            }

            return Encoding.UTF8.GetString(buffer.WrittenSpan);
        };
    }
}
