using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Application-supplied gate run after a Trust Mark has structurally
/// validated (signature verified, issuer authorised, not expired) but
/// before its assertion is consumed by downstream policy. Each presented
/// trust mark passes through this delegate independently. The returned
/// <see cref="Claim"/> joins the chain's
/// <see cref="ClaimIssueResult"/> via the
/// <see cref="WellKnownFederationClaimIds.TrustMarkSignatureVerifies"/>
/// family of ids.
/// </summary>
/// <param name="trustMarkJwt">The compact-form Trust Mark JWT presented by the subject.</param>
/// <param name="trustMarkIssuer">
/// The Entity Identifier that issued the Trust Mark (the JWT's <c>iss</c>).
/// </param>
/// <param name="trustMarkId">
/// The Trust Mark identifier the JWT asserts (the JWT's <c>id</c> claim per
/// Federation §7.1).
/// </param>
/// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
/// <returns>
/// A <see cref="Claim"/> recording the application's approval. The default
/// implementation (<see cref="FederationDefaultHooks.ApproveTrustMark"/>)
/// admits every trust mark that reached this point; deployments override
/// to enforce per-mark allow-lists, freshness windows, or business
/// constraints not expressed by the spec.
/// </returns>
public delegate ValueTask<Claim> ApproveTrustMarkDelegate(
    string trustMarkJwt,
    EntityIdentifier trustMarkIssuer,
    string trustMarkId,
    CancellationToken cancellationToken);
