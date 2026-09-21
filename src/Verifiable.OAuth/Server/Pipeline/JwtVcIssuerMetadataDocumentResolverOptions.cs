namespace Verifiable.OAuth.Server.Pipeline;

/// <summary>
/// Tunables for <see cref="JwtVcIssuerMetadataDocuments.ResolveAsync"/>: the document byte cap.
/// Caching — for how long a resolved document is kept — is an application-layer concern; the app's
/// own <see cref="Verifiable.OAuth.Oid4Vp.Server.ResolveIssuerKeyDelegate"/> implementation owns it.
/// </summary>
public sealed record JwtVcIssuerMetadataDocumentResolverOptions
{
    /// <summary>
    /// The maximum JWT VC Issuer Metadata document size, in bytes, the resolver reads before
    /// treating the response as an error. Enforced both as a transport hint
    /// (<see cref="Verifiable.Core.Outbound.OutboundRequest.MaxResponseBytes"/>) and as an
    /// authoritative post-read check, the repo's established double-application size-limit pattern.
    /// </summary>
    public long MaximumDocumentBytes { get; init; } = 5120;
}
