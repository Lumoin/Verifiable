using Verifiable.Core;
using Verifiable.JCose;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Resolves a complete trust chain via a federation resolver's
/// <c>federation_resolve_endpoint</c> per OpenID Federation 1.0 §8.3.
/// </summary>
/// <param name="subject">The Entity Identifier whose chain is being resolved.</param>
/// <param name="trustAnchor">The Trust Anchor the chain must terminate at.</param>
/// <param name="entityTypeFilter">
/// Optional filter restricting which entity-type's metadata is included
/// in the resolution.
/// </param>
/// <param name="resolveEndpoint">The full URL of the resolver's endpoint.</param>
/// <param name="context">
/// The per-call exchange context. Carried so an implementation can make
/// per-call decisions from request-scoped data — capability/functionality
/// gating, and the outbound-fetch (SSRF) policy that governs which
/// <paramref name="resolveEndpoint"/> URLs may be contacted.
/// </param>
/// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
/// <returns>
/// The resolved <see cref="FetchedTrustChain"/> when the resolver returned
/// a parseable chain; otherwise <see langword="null"/>.
/// </returns>
/// <remarks>
/// The resolver endpoint is operated by a federation resolver service —
/// a federation entity offering chain-walking and validation as a
/// service to consumers that don't implement the §10 protocol themselves.
/// Receivers using a resolver still verify the resolved chain locally
/// against their own trust-anchor allow-list and signature-verification
/// policies.
/// </remarks>
public delegate ValueTask<FetchedTrustChain?> ResolveTrustChainDelegate(
    EntityIdentifier subject,
    EntityIdentifier trustAnchor,
    EntityTypeIdentifier? entityTypeFilter,
    Uri resolveEndpoint,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Output of a successful <see cref="ResolveTrustChainDelegate"/> call.
/// Carries the parsed <see cref="TrustChain"/> alongside the per-position
/// unverified headers and raw compact JWS strings needed for downstream
/// signature verification — positionally aligned with the chain's
/// <see cref="TrustChain.Statements"/>.
/// </summary>
public sealed record FetchedTrustChain(
    TrustChain Chain,
    IReadOnlyList<UnverifiedJwtHeader> HeadersByPosition,
    IReadOnlyList<string> CompactJwsByPosition);
