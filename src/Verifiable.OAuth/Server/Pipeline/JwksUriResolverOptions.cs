namespace Verifiable.OAuth.Server.Pipeline;

/// <summary>
/// Tunables for <see cref="JwksUriResolver.ResolveAsync"/>: the key-set byte cap. Caching — for how
/// long a resolved key set is kept, and how soon a failed <c>jwks_uri</c> is dialled again — is an
/// application-layer concern; see <see cref="ResolveJwksUriDelegate"/>.
/// </summary>
public sealed record JwksUriResolverOptions
{
    /// <summary>
    /// The maximum JWK Set document size, in bytes, the resolver reads before treating the response
    /// as an error. Enforced both as a transport hint
    /// (<see cref="Verifiable.Core.Outbound.OutboundRequest.MaxResponseBytes"/>) and as an
    /// authoritative post-read check, the repo's established double-application size-limit pattern.
    /// </summary>
    public long MaximumDocumentBytes { get; init; } = 5120;
}
