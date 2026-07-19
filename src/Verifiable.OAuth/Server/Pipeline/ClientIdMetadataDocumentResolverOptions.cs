using Verifiable.Core;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.Server.Pipeline;

/// <summary>
/// An application-supplied additional restriction on an otherwise-conformant Client ID
/// Metadata Document, per
/// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-4">
/// draft-ietf-oauth-client-id-metadata-document-02 Section 4</see> — "Other specifications MAY
/// place additional restrictions on the contents of the Client ID Metadata Document accepted
/// by authorization servers implementing their specification. For example, requiring the
/// <c>token_endpoint_auth_method</c> property be set to <c>private_key_jwt</c>". Returning
/// <see langword="false"/> rejects the document with
/// <see cref="ClientIdMetadataResolutionOutcome.InvalidDocument"/>.
/// </summary>
/// <param name="document">The library-parsed, already spec-conformant metadata.</param>
/// <param name="clientMetadataUri">The Client Identifier URL the document was fetched from.</param>
/// <param name="context">The per-request context.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<bool> AdditionalClientIdMetadataDocumentValidationDelegate(
    ClientMetadata document,
    Uri clientMetadataUri,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Tunables for <see cref="ClientIdMetadataDocuments.BuildResolving"/>: byte caps, cache
/// lifetime bounds, logo prefetch, the Section 4 additional-validation hook, and how Section 3
/// SHOULD/NOT-RECOMMENDED-tier advisories are treated.
/// </summary>
public sealed record ClientIdMetadataDocumentResolverOptions
{
    /// <summary>
    /// The maximum Client ID Metadata Document size, in bytes, the resolver reads before
    /// treating the response as an error, per
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-8.7">
    /// draft-ietf-oauth-client-id-metadata-document-02 Section 8.7</see> — "The recommended
    /// maximum size to read is 5 kilobytes." Enforced both as a transport hint
    /// (<see cref="Verifiable.Core.OutboundFetch.OutboundRequest.MaxResponseBytes"/>) and as an
    /// authoritative post-read check, the repo's established double-application size-limit
    /// pattern.
    /// </summary>
    public long MaximumDocumentBytes { get; init; } = 5120;

    /// <summary>
    /// The maximum <c>logo_uri</c> prefetch size, in bytes, per
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-8.8">
    /// draft-ietf-oauth-client-id-metadata-document-02 Section 8.8</see>. The specification sets
    /// no numeric bound for the logo; this default is a library-chosen ceiling against an
    /// oversized or hostile logo response.
    /// </summary>
    public long MaximumLogoBytes { get; init; } = 51_200;

    /// <summary>
    /// The lower bound the resolver clamps a header-derived cache lifetime to, per
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-5.2">
    /// draft-ietf-oauth-client-id-metadata-document-02 Section 5.2</see> — "MAY define its own
    /// upper and/or lower bounds on an acceptable cache lifetime." <see langword="null"/> applies
    /// no lower bound. Never overrides a <c>Cache-Control: no-store</c> response, which is never
    /// cached regardless of this bound.
    /// </summary>
    public TimeSpan? MinimumCacheLifetime { get; init; }

    /// <summary>
    /// The upper bound the resolver clamps a header-derived cache lifetime to (Section 5.2, same
    /// clause as <see cref="MinimumCacheLifetime"/>). <see langword="null"/> applies no upper
    /// bound.
    /// </summary>
    public TimeSpan? MaximumCacheLifetime { get; init; }

    /// <summary>
    /// Whether the resolver prefetches the document's <c>logo_uri</c> through the same guarded
    /// outbound-fetch policy and caches it alongside the document, per
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-8.8">
    /// draft-ietf-oauth-client-id-metadata-document-02 Section 8.8</see>. Defaults to
    /// <see langword="false"/> — logo prefetch is opt-in.
    /// </summary>
    public bool PrefetchLogo { get; init; }

    /// <summary>
    /// An application-supplied additional restriction on the document's contents (Section 4).
    /// <see langword="null"/> applies no additional restriction beyond the library's own
    /// conformance checks.
    /// </summary>
    public AdditionalClientIdMetadataDocumentValidationDelegate? AdditionalDocumentValidation { get; init; }

    /// <summary>
    /// Whether a Section 3 SHOULD-NOT/NOT-RECOMMENDED-tier advisory on the Client Identifier
    /// URL — a query component
    /// (<see cref="ClientIdentifierUrlValidationResult.HasQueryComponent"/>) or a root path
    /// (<see cref="ClientIdentifierUrlValidationResult.IsRootPath"/>) — is treated as a
    /// resolution failure rather than a tolerated advisory. Defaults to <see langword="false"/>:
    /// both rules are SHOULD/NOT-RECOMMENDED-tier, not MUST-tier, so a candidate carrying either
    /// is still resolved unless a deployment opts into the stricter posture.
    /// </summary>
    public bool TreatAdvisoriesAsErrors { get; init; }
}
