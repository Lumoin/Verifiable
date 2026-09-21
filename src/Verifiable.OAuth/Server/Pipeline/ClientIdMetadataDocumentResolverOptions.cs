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
/// Tunables for <see cref="ClientIdMetadataDocuments.ResolveAsync"/>: byte caps, logo prefetch, the
/// Section 4 additional-validation hook, how Section 3 SHOULD/NOT-RECOMMENDED-tier advisories are
/// treated, and the key-set resolution seam. Caching — for how long a resolved document is kept — is
/// an application-layer concern; see <see cref="ResolveClientMetadataDelegate"/>.
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

    /// <summary>
    /// The OPTIONAL key-set resolution seam a <c>private_key_jwt</c> client's <c>jwks_uri</c> is
    /// discovered through, per
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-8.2">
    /// draft-ietf-oauth-client-id-metadata-document-02 Section 8.2</see> — at Step 9a of
    /// <see cref="ClientIdMetadataDocuments.ResolveAsync"/>, and again through
    /// <see cref="ClientIdMetadataDocuments.RefreshJwksAsync"/> whenever a caller's own cache serves
    /// a fresh document whose key set was discovered this way. <see langword="null"/> (the default)
    /// leaves a <c>jwks_uri</c> never dereferenced: the document still resolves with no key set, and
    /// the token endpoint later rejects the client for want of one.
    /// </summary>
    public ResolveJwksUriDelegate? ResolveJwksUri { get; init; }
}
