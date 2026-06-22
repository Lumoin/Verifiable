using Verifiable.Core.Model.Did;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// Serializes a <see cref="DidResolutionResult"/> to the W3C DID Resolution Result envelope
/// (<c>{ "didDocument", "didResolutionMetadata", "didDocumentMetadata" }</c>, media type
/// <c>application/did-resolution</c>).
/// </summary>
/// <remarks>
/// Implemented by the <c>Verifiable.Json</c> leaf so <c>Verifiable.Core</c> takes no
/// <c>System.Text.Json</c> dependency; serialization crosses the firewall as this delegate.
/// </remarks>
/// <param name="result">The resolution result to serialize.</param>
/// <returns>The JSON text of the resolution result envelope.</returns>
public delegate string DidResolutionResultSerializer(DidResolutionResult result);


/// <summary>
/// Serializes a <see cref="DidDereferencingResult"/> to the W3C DID URL Dereferencing Result
/// envelope (<c>{ "contentStream", "dereferencingMetadata", "contentMetadata" }</c>, media type
/// <c>application/did-url-dereferencing</c>).
/// </summary>
/// <remarks>
/// Implemented by the <c>Verifiable.Json</c> leaf so <c>Verifiable.Core</c> takes no
/// <c>System.Text.Json</c> dependency; serialization crosses the firewall as this delegate.
/// </remarks>
/// <param name="result">The dereferencing result to serialize.</param>
/// <returns>The JSON text of the dereferencing result envelope.</returns>
public delegate string DidDereferencingResultSerializer(DidDereferencingResult result);


/// <summary>
/// Serializes a bare <see cref="DidDocument"/>, used for the HTTP(S) binding's
/// "<c>accept</c> a plain media type" content-negotiation case where the body is the DID document
/// itself rather than the full resolution result envelope.
/// </summary>
/// <remarks>
/// Implemented by the <c>Verifiable.Json</c> leaf so <c>Verifiable.Core</c> takes no
/// <c>System.Text.Json</c> dependency; serialization crosses the firewall as this delegate.
/// </remarks>
/// <param name="document">The DID document to serialize.</param>
/// <returns>The JSON text of the DID document.</returns>
public delegate string DidDocumentSerializer(DidDocument document);


/// <summary>
/// Serializes a bare dereferenced <see cref="DidDereferencingResult.ContentStream"/> resource, used for the
/// HTTP(S) binding's "<c>accept</c> a plain media type" dereferencing case where the body is the
/// dereferenced resource itself rather than the full DID URL Dereferencing Result envelope.
/// </summary>
/// <remarks>
/// Implemented by the <c>Verifiable.Json</c> leaf so <c>Verifiable.Core</c> takes no
/// <c>System.Text.Json</c> dependency; serialization crosses the firewall as this delegate. The content stream
/// is an open <see cref="object"/> dispatched on its runtime type (DID document, presentation, service,
/// verification method, URI string, or bytes).
/// </remarks>
/// <param name="contentStream">The dereferenced resource to serialize, or <see langword="null"/>.</param>
/// <returns>The JSON text (or JSON-encoded representation) of the content stream.</returns>
public delegate string DidContentStreamSerializer(object? contentStream);
