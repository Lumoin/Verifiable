using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Outbound;

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
/// See <see href="https://www.w3.org/TR/did-resolution/#did-resolution-result">DID Resolution §8</see>.
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
    /// Why the resolver refused the retrieved document when <see cref="DidResolutionMetadata.Error"/> is
    /// <see cref="DidErrorTypes.InvalidDidDocument"/>, or <see langword="null"/> when the resolver states no
    /// reason. It refines that DID Resolution error, which stays the primary signal, and a resolver sets it on
    /// no other result: never on a success and never on another error type. A caller running
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID 1.0 §3.3 Retrieve Verification
    /// Method</see> reads <see cref="InvalidDidDocumentReason.IdMismatch"/> as step 6 ("If controllerDocument.id
    /// does not match the controllerDocumentUrl") and every other reason as step 5 ("If controllerDocument is not
    /// a conforming controlled identifier document"), because the resolver refuses the document before the caller
    /// could compare it itself.
    /// </summary>
    public InvalidDidDocumentReason? InvalidDocumentReason { get; init; }

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
    public bool IsSuccessful => ResolutionMetadata.Error is null
        && (Document is not null || DocumentUrl is not null || DocumentMetadata.Deactivated);

    /// <summary>
    /// Creates a successful resolution result containing a fully resolved DID document.
    /// </summary>
    /// <param name="document">The resolved DID document.</param>
    /// <param name="documentMetadata">Metadata about the document.</param>
    /// <param name="contentType">The media type of the representation.</param>
    /// <param name="freshness">
    /// The freshness the method's own wire fetch reports for <paramref name="document"/>, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-5.2">RFC 9111 §5.2</see>. Left at its
    /// default (not storable) by a method that resolves without an HTTP fetch.
    /// </param>
    public static DidResolutionResult Success(
        DidDocument document,
        DidDocumentMetadata documentMetadata,
        string? contentType = null,
        HttpCacheFreshness freshness = default)
    {
        return new DidResolutionResult
        {
            Kind = DidResolutionKind.Document,
            ResolutionMetadata = new DidResolutionMetadata { ContentType = contentType, Freshness = freshness },
            Document = document,
            DocumentMetadata = documentMetadata
        };
    }

    /// <summary>
    /// Creates a successful resolution result for a deactivated DID: the DIDDoc is intentionally absent
    /// (<see cref="Document"/> is <see langword="null"/>) and the document metadata carries
    /// <see cref="DidDocumentMetadata.Deactivated"/> set to <see langword="true"/>.
    /// </summary>
    /// <param name="documentMetadata">The document metadata, which MUST have <c>Deactivated == true</c>.</param>
    /// <param name="contentType">The media type the representation would have carried.</param>
    /// <param name="freshness">
    /// The freshness the method's own wire fetch reports for the deactivation record, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-5.2">RFC 9111 §5.2</see>. Left at its
    /// default (not storable) by a method that resolves without an HTTP fetch.
    /// </param>
    /// <remarks>
    /// A resolver MUST NOT return the DIDDoc for a deactivated DID and MUST include <c>deactivated: true</c>
    /// in the resolution metadata. This factory produces that shape: a successful document-kind result with a
    /// null document and deactivated metadata.
    /// </remarks>
    public static DidResolutionResult SuccessDeactivated(
        DidDocumentMetadata documentMetadata,
        string? contentType = null,
        HttpCacheFreshness freshness = default)
    {
        return new DidResolutionResult
        {
            Kind = DidResolutionKind.Document,
            ResolutionMetadata = new DidResolutionMetadata { ContentType = contentType, Freshness = freshness },
            Document = null,
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

/// <summary>
/// The reason a resolver refused a retrieved DID document with <see cref="DidErrorTypes.InvalidDidDocument"/>,
/// carried on <see cref="DidResolutionResult.InvalidDocumentReason"/>. The DID Resolution error names one condition
/// for all of these; the reason lets a caller of
/// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID 1.0 §3.3 Retrieve Verification
/// Method</see> tell step 5 (the document is not a conforming controlled identifier document) from step 6 (its
/// <c>id</c> does not match the URL it was retrieved from).
/// </summary>
public enum InvalidDidDocumentReason
{
    /// <summary>
    /// The retrieved representation could not be read as a DID document: it did not parse, or it parsed to no
    /// document. CID 1.0 §3.3 step 5.
    /// </summary>
    Malformed,

    /// <summary>
    /// The document omits a property a conforming document requires, such as the top-level <c>id</c>
    /// (<see href="https://www.w3.org/TR/cid-1.0/#subjects">CID 1.0 §2.1.1</see>: "A controlled identifier
    /// document MUST contain an id value in the topmost map"). CID 1.0 §3.3 step 5.
    /// </summary>
    MissingRequiredProperty,

    /// <summary>
    /// The document embeds a verification method, service or controller identifier that does not resolve under
    /// the requested DID, so accepting it would bind another subject's keys to that DID. CID 1.0 §3.3 step 5.
    /// </summary>
    EmbeddedIdentifierOutsideDid,

    /// <summary>
    /// The document's <see cref="DidDocument.Id"/> is not the requested DID, and the resolving method gives no
    /// guarantee that the two are equivalent. CID 1.0 §3.3 step 6.
    /// </summary>
    IdMismatch
}
