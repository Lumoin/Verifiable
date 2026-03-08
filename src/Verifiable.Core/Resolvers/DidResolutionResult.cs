using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Model.Did;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// The complete result of DID resolution, containing the document, resolution metadata,
/// and document metadata per W3C DID Resolution v0.3 §4.
/// </summary>
/// <remarks>
/// <para>
/// A successful result is always one of three kinds, discriminated by <see cref="Kind"/>:
/// </para>
/// <list type="bullet">
///   <item><description><see cref="DidResolutionKind.Document"/>: <see cref="Document"/> is populated.</description></item>
///   <item><description><see cref="DidResolutionKind.DocumentUrl"/>: <see cref="DocumentUrl"/> is populated. The caller must fetch the document.</description></item>
///   <item><description><see cref="DidResolutionKind.VerifiedLog"/>: <see cref="DocumentUrl"/> points to a verifiable history log.</description></item>
/// </list>
/// <para>
/// See <see href="https://w3c.github.io/did-resolution/#did-resolution-result">DID Resolution §8</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("{Kind} IsSuccessful={IsSuccessful} Error={ResolutionMetadata.Error.Type.AbsoluteUri,nq} Document={Document?.Id,nq} DocumentUrl={DocumentUrl,nq}")]
public sealed class DidResolutionResult
{
    /// <summary>
    /// Discriminates the kind of this result.
    /// </summary>
    public DidResolutionKind Kind { get; init; }

    /// <summary>
    /// Metadata about the resolution process itself.
    /// </summary>
    public required DidResolutionMetadata ResolutionMetadata { get; init; }

    /// <summary>
    /// The resolved DID document, or <see langword="null"/> if resolution did not produce
    /// a document directly.
    /// </summary>
    public DidDocument? Document { get; init; }

    /// <summary>
    /// Metadata about the DID document.
    /// </summary>
    public DidDocumentMetadata DocumentMetadata { get; init; } = DidDocumentMetadata.Empty;

    /// <summary>
    /// The HTTPS URL at which the DID document (or log) can be fetched, populated when
    /// <see cref="Kind"/> is <see cref="DidResolutionKind.DocumentUrl"/> or
    /// <see cref="DidResolutionKind.VerifiedLog"/>.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "DID document URLs contain method-specific syntax that System.Uri does not handle correctly.")]
    public string? DocumentUrl { get; init; }

    /// <summary>
    /// Whether the resolution was successful.
    /// </summary>
    public bool IsSuccessful => ResolutionMetadata.Error is null && (Document is not null || DocumentUrl is not null);

    /// <summary>
    /// Creates a successful resolution result containing a fully resolved DID document.
    /// </summary>
    /// <param name="document">The resolved DID document.</param>
    /// <param name="documentMetadata">Metadata about the document.</param>
    /// <param name="contentType">The media type of the representation.</param>
    public static DidResolutionResult Success(
        DidDocument document,
        DidDocumentMetadata documentMetadata,
        string? contentType = null)
    {
        return new DidResolutionResult
        {
            Kind = DidResolutionKind.Document,
            ResolutionMetadata = new DidResolutionMetadata { ContentType = contentType },
            Document = document,
            DocumentMetadata = documentMetadata
        };
    }

    /// <summary>
    /// Creates a successful resolution result carrying an HTTPS URL at which the DID document
    /// can be fetched. Used by methods that compute a redirect URL rather than returning a
    /// document directly.
    /// </summary>
    /// <param name="documentUrl">The HTTPS URL of the DID document.</param>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "DID document URLs contain method-specific syntax that System.Uri does not handle correctly.")]
    public static DidResolutionResult SuccessUrl(string documentUrl)
    {
        return new DidResolutionResult
        {
            Kind = DidResolutionKind.DocumentUrl,
            ResolutionMetadata = new DidResolutionMetadata(),
            DocumentUrl = documentUrl
        };
    }

    /// <summary>
    /// Creates a successful resolution result carrying an HTTPS URL pointing to a verifiable
    /// history log.
    /// </summary>
    /// <param name="documentUrl">The HTTPS URL of the verifiable history log.</param>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "DID document URLs contain method-specific syntax that System.Uri does not handle correctly.")]
    public static DidResolutionResult SuccessVerifiedLog(string documentUrl)
    {
        return new DidResolutionResult
        {
            Kind = DidResolutionKind.VerifiedLog,
            ResolutionMetadata = new DidResolutionMetadata(),
            DocumentUrl = documentUrl
        };
    }

    /// <summary>
    /// Creates a failed resolution result. Per the W3C DID Resolution specification, the
    /// document and document metadata MUST be empty when resolution is unsuccessful.
    /// </summary>
    /// <param name="error">
    /// The RFC 9457 problem details object. Use a pre-built instance from
    /// <see cref="DidResolutionErrors"/> for standard error conditions.
    /// </param>
    public static DidResolutionResult Failure(DidProblemDetails error)
    {
        return new DidResolutionResult
        {
            ResolutionMetadata = new DidResolutionMetadata { Error = error },
            DocumentMetadata = DidDocumentMetadata.Empty
        };
    }
}
