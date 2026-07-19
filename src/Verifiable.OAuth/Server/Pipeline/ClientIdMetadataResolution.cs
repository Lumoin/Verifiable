using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.Server.Pipeline;

/// <summary>
/// Why a <see cref="ResolveClientMetadataDelegate"/> call ended.
/// </summary>
public enum ClientIdMetadataResolutionOutcome
{
    /// <summary>
    /// The document was fetched, parsed, and validated; <see cref="ClientIdMetadataResolution.Document"/>
    /// is set.
    /// </summary>
    Resolved = 0,

    /// <summary>
    /// The outbound-fetch policy denied the target (or a redirect hop) before any terminal
    /// response was obtained — an SSRF-relevant refusal, per
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-8.6">
    /// draft-ietf-oauth-client-id-metadata-document-02 Section 8.6</see>.
    /// </summary>
    PolicyDenied,

    /// <summary>
    /// The document could not be fetched: a non-200 status, an unfollowed or excessive
    /// redirect chain, an oversized response, or a transport failure.
    /// </summary>
    FetchFailed,

    /// <summary>
    /// The fetched response was not a usable Client ID Metadata Document: an unacceptable
    /// content type, a parse or conformance defect, a <c>client_id</c> mismatch, or rejection
    /// by <see cref="ClientIdMetadataDocumentResolverOptions.AdditionalDocumentValidation"/>.
    /// </summary>
    InvalidDocument
}


/// <summary>
/// The result of a <see cref="ResolveClientMetadataDelegate"/> call.
/// </summary>
/// <remarks>
/// Only a <see cref="ClientIdMetadataResolutionOutcome.Resolved"/> result carries
/// <see cref="Document"/>; every other outcome leaves it <see langword="null"/> and
/// <see cref="Defect"/> carries internal diagnostics for logs and traces — never surface it in
/// a wire response, since the document is served from a URL the client itself controls.
/// </remarks>
public sealed record ClientIdMetadataResolution
{
    /// <summary>Why this resolution ended.</summary>
    public required ClientIdMetadataResolutionOutcome Outcome { get; init; }

    /// <summary>
    /// The parsed, conformant client metadata when <see cref="Outcome"/> is
    /// <see cref="ClientIdMetadataResolutionOutcome.Resolved"/>; otherwise <see langword="null"/>.
    /// </summary>
    public ClientMetadata? Document { get; init; }

    /// <summary>
    /// The document's <c>client_id</c> property value, when the document was parsed far enough
    /// to extract one. Set even for some <see cref="ClientIdMetadataResolutionOutcome.InvalidDocument"/>
    /// results (for example a <c>client_id</c> mismatch) so a caller can log which identity the
    /// document claimed.
    /// </summary>
    public string? DocumentClientId { get; init; }

    /// <summary>
    /// Internal diagnostic detail for a non-<see cref="ClientIdMetadataResolutionOutcome.Resolved"/>
    /// outcome. For logs and traces only — never surface this text in a wire response.
    /// </summary>
    public string? Defect { get; init; }

    /// <summary>
    /// The prefetched <c>logo_uri</c> bytes when
    /// <see cref="ClientIdMetadataDocumentResolverOptions.PrefetchLogo"/> is enabled, the
    /// document carries a <c>logo_uri</c>, and the prefetch succeeded. <see langword="null"/>
    /// when prefetch is disabled, the document carries no <c>logo_uri</c>, or the prefetch
    /// failed — a failed prefetch is non-fatal to <see cref="Outcome"/> per
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-8.8">
    /// draft-ietf-oauth-client-id-metadata-document-02 Section 8.8</see>.
    /// </summary>
    public ReadOnlyMemory<byte>? PrefetchedLogo { get; init; }

    /// <summary>The <c>Content-Type</c> the logo host reported, when <see cref="PrefetchedLogo"/> is set.</summary>
    public string? PrefetchedLogoContentType { get; init; }


    /// <summary>Whether <see cref="Outcome"/> is <see cref="ClientIdMetadataResolutionOutcome.Resolved"/>.</summary>
    public bool IsResolved => Outcome == ClientIdMetadataResolutionOutcome.Resolved;
}
