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
    /// treating the response as an error. Enforced by the guarded fetch while reading the response, through
    /// <see cref="Verifiable.Core.Outbound.OutboundRequest.MaxResponseBytes"/>.
    /// </summary>
    public long MaximumDocumentBytes { get; init; } = 8192;
}
