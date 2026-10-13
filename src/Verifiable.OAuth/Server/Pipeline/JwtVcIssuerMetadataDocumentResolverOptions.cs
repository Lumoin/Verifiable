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
    /// treating the response as an error. Enforced by the guarded fetch while reading the response, through
    /// <see cref="Verifiable.Core.Outbound.OutboundRequest.MaxResponseBytes"/>.
    /// </summary>
    public long MaximumDocumentBytes { get; init; } = 5120;
}
