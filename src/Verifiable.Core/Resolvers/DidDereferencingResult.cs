using System.Diagnostics;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// The complete result of DID URL dereferencing per W3C DID Resolution v0.3 §5.
/// </summary>
/// <remarks>
/// <para>
/// The <see cref="ContentStream"/> is typed as <see cref="object"/> because dereferencing
/// can return a <c>DidDocument</c>, a <c>VerificationMethod</c>, a <c>Service</c>, a URI
/// string for a service endpoint, or any other resource format identified via a media type.
/// </para>
/// <para>
/// See <see href="https://w3c.github.io/did-resolution/#did-url-dereferencing-result">DID Resolution §8.2</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("IsSuccessful={IsSuccessful} Error={DereferencingMetadata.Error.Type.AbsoluteUri,nq} ContentStream={ContentStream}")]
public sealed class DidDereferencingResult
{
    /// <summary>
    /// Metadata about the dereferencing process.
    /// </summary>
    public required DidDereferencingMetadata DereferencingMetadata { get; init; }

    /// <summary>
    /// The dereferenced resource, or <see langword="null"/> if dereferencing failed.
    /// May be a <c>DidDocument</c>, <c>VerificationMethod</c>, <c>Service</c>,
    /// a service endpoint URI string, or a caller-defined type.
    /// </summary>
    public object? ContentStream { get; init; }

    /// <summary>
    /// Metadata about the content. When <see cref="ContentStream"/> is or was derived from
    /// a DID document, this MUST be a <see cref="DidDocumentMetadata"/> structure. Empty
    /// when dereferencing was unsuccessful.
    /// </summary>
    public DidDocumentMetadata? ContentMetadata { get; init; }

    /// <summary>
    /// Whether the dereferencing was successful.
    /// </summary>
    public bool IsSuccessful => DereferencingMetadata.Error is null && ContentStream is not null;

    /// <summary>
    /// Creates a successful dereferencing result.
    /// </summary>
    /// <param name="content">The dereferenced resource.</param>
    /// <param name="contentMetadata">Metadata about the content.</param>
    /// <param name="contentType">The media type of the resource.</param>
    public static DidDereferencingResult Success(
        object content,
        DidDocumentMetadata? contentMetadata = null,
        string? contentType = null)
    {
        return new DidDereferencingResult
        {
            DereferencingMetadata = new DidDereferencingMetadata { ContentType = contentType },
            ContentStream = content,
            ContentMetadata = contentMetadata
        };
    }

    /// <summary>
    /// Creates a failed dereferencing result. Per the W3C DID Resolution specification, the
    /// content stream and content metadata MUST be empty when dereferencing is unsuccessful.
    /// </summary>
    /// <param name="error">
    /// The RFC 9457 problem details object. Use a pre-built instance from
    /// <see cref="DidResolutionErrors"/> for standard error conditions.
    /// </param>
    public static DidDereferencingResult Failure(DidProblemDetails error)
    {
        return new DidDereferencingResult
        {
            DereferencingMetadata = new DidDereferencingMetadata { Error = error },
            ContentStream = null,
            ContentMetadata = null
        };
    }
}