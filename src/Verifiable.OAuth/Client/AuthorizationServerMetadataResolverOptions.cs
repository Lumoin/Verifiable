namespace Verifiable.OAuth.Client;

/// <summary>
/// Tunables for <see cref="AuthorizationServerMetadataDocuments.ResolveAsync"/>: the document byte
/// cap. Caching — for how long a resolved document is kept, and what follows a failed attempt — is
/// an application-layer concern; see <see cref="ResolveAuthorizationServerMetadataDelegate"/>.
/// </summary>
public sealed record AuthorizationServerMetadataResolverOptions
{
    /// <summary>
    /// The maximum authorization server metadata document size, in bytes, the resolver reads before
    /// treating the response as an error. Enforced both as a transport hint
    /// (<see cref="Verifiable.Core.OutboundFetch.OutboundRequest.MaxResponseBytes"/>) and as an
    /// authoritative post-read check, the repo's established double-application size-limit pattern.
    /// </summary>
    public long MaximumDocumentBytes { get; init; } = 8192;
}
