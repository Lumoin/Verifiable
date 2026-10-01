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
    /// as an error. Enforced by the guarded fetch while reading the response, through
    /// <see cref="Verifiable.Core.Outbound.OutboundRequest.MaxResponseBytes"/>.
    /// </summary>
    public long MaximumDocumentBytes { get; init; } = 5120;
}
