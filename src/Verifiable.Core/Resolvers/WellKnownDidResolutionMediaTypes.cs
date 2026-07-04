namespace Verifiable.Core.Resolvers;

/// <summary>
/// Well-known media types and HTTP(S)-binding path constants defined by the W3C DID Resolution
/// specification. The media types select the result form during content negotiation and label the
/// response body; the base path is the GET interface the binding mounts.
/// </summary>
/// <remarks>
/// See <see href="https://www.w3.org/TR/did-resolution/#bindings-https">DID Resolution HTTP(S) Binding</see>.
/// </remarks>
public static class WellKnownDidResolutionMediaTypes
{
    /// <summary>
    /// The media type whose presence in the <c>Accept</c> header requests the full DID Resolution
    /// Result envelope (<c>{ "didDocument", "didResolutionMetadata", "didDocumentMetadata" }</c>),
    /// and which labels that response body.
    /// </summary>
    public const string DidResolution = "application/did-resolution";

    /// <summary>
    /// The media type whose presence in the <c>Accept</c> header requests the full DID URL
    /// Dereferencing Result envelope (<c>{ "contentStream", "dereferencingMetadata",
    /// "contentMetadata" }</c>), and which labels that response body.
    /// </summary>
    public const string DidUrlDereferencing = "application/did-url-dereferencing";

    /// <summary>
    /// The default media type of a bare DID document representation, returned when the client
    /// requests a plain media type rather than the resolution-result envelope.
    /// </summary>
    public const string DidJson = "application/did+json";

    /// <summary>
    /// The abstract DID document media type a client may request to select the DID document
    /// representation (in the resolver's default concrete encoding) rather than the resolution-result
    /// envelope.
    /// </summary>
    public const string DidAbstract = "application/did";

    /// <summary>
    /// The media type of a dereferenced service-endpoint URI list. A content stream carrying this
    /// type is returned to the HTTP(S) client as a 303 redirect to the endpoint URL rather than as
    /// a body.
    /// </summary>
    public const string TextUriList = "text/uri-list";

    /// <summary>
    /// The base path of the GET interface the HTTP(S) binding mounts; the URL-encoded DID or DID URL
    /// is appended as the final path segment.
    /// </summary>
    public const string IdentifiersBasePath = "/1.0/identifiers/";
}
