using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Resolves the <c>openid_federation</c> trusted-authority evidence
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.3">
/// OpenID for Verifiable Presentations 1.0, Section 6.1.1.3</see> compares against: every statement
/// subject on a validated OpenID Federation trust chain from a credential's issuer to one of the
/// wallet's own familiar Trust Anchors.
/// </summary>
/// <remarks>
/// Runs entirely against <paramref name="familiarTrustAnchors"/>: an anchor absent from that
/// collection is neither fetched from nor validated against, which is how
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-15.10">
/// Section 15.10</see>'s "Wallets SHOULD NOT access URLs included in a request from the Verifier ...
/// treated purely as identifiers and not actually retrieved by the Wallet upon receiving the
/// request" is met structurally — the caller resolves evidence from ITS OWN anchors, ahead of and
/// independently of any Verifier request, and the resulting set is later compared, never dereferenced,
/// against request-supplied values by
/// <see cref="Verifiable.Core.Model.Dcql.TrustedAuthoritiesQuery.Matches(Verifiable.Core.Model.Dcql.TrustedAuthorityEvidence)"/>.
/// </remarks>
public static class FederationTrustPathEvidence
{
    /// <summary>
    /// Builds, for each of <paramref name="familiarTrustAnchors"/>, a trust chain from
    /// <paramref name="issuer"/> to that anchor via <see cref="TrustChainResolver.BuildAsync"/> and
    /// validates it with <paramref name="validateTrustChain"/>; the union of every subject on every
    /// chain that validates is the resolved evidence, per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.3">
    /// OID4VP 1.0 §6.1.1.3</see>: "A valid trust path, including the given Entity Identifier, must be
    /// constructible from a matching credential."
    /// </summary>
    /// <param name="issuer">The credential issuer's Entity Identifier — the trust chain's leaf.</param>
    /// <param name="familiarTrustAnchors">
    /// The wallet's own Trust Anchor allow-list. The only anchors ever fetched toward or validated
    /// against — an anchor named only in a Verifier's request and absent here contributes nothing.
    /// </param>
    /// <param name="fetchEntityConfiguration">Fetches an entity's self-issued Entity Configuration (Federation §9).</param>
    /// <param name="fetchSubordinateStatement">Fetches a superior's Subordinate Statement about a subject (Federation §8.1).</param>
    /// <param name="validateTrustChain">Verifies an assembled chain's signatures and Federation §10.2 rules.</param>
    /// <param name="context">The per-call exchange context carrying the outbound-fetch policy.</param>
    /// <param name="maxChainLength">The maximum number of entities on a path, leaf through anchor inclusive.</param>
    /// <param name="validationTime">The instant against which a chain's temporal claims are evaluated.</param>
    /// <param name="clockSkew">Maximum acceptable clock skew for temporal checks.</param>
    /// <param name="pool">Memory pool for transient buffer allocations during validation.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>
    /// Every statement subject's Entity Identifier on every validated chain, across all of
    /// <paramref name="familiarTrustAnchors"/>; empty when <paramref name="issuer"/> has no valid
    /// chain to any of them.
    /// </returns>
    public static async ValueTask<IReadOnlySet<EntityIdentifier>> ResolveAsync(
        EntityIdentifier issuer,
        IReadOnlyCollection<EntityIdentifier> familiarTrustAnchors,
        FetchEntityConfigurationDelegate fetchEntityConfiguration,
        FetchEntityStatementDelegate fetchSubordinateStatement,
        ValidateTrustChainAsyncDelegate validateTrustChain,
        ExchangeContext context,
        int maxChainLength,
        DateTimeOffset validationTime,
        TimeSpan clockSkew,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(familiarTrustAnchors);
        ArgumentNullException.ThrowIfNull(fetchEntityConfiguration);
        ArgumentNullException.ThrowIfNull(fetchSubordinateStatement);
        ArgumentNullException.ThrowIfNull(validateTrustChain);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);

        HashSet<EntityIdentifier> entities = [];
        foreach(EntityIdentifier anchor in familiarTrustAnchors)
        {
            EntityIdentifier[] anchorAllowList = [anchor];
            IReadOnlyList<string>? compactJwsChain = await TrustChainResolver.BuildAsync(
                issuer,
                anchorAllowList,
                fetchEntityConfiguration,
                fetchSubordinateStatement,
                context,
                maxChainLength,
                cancellationToken).ConfigureAwait(false);

            if(compactJwsChain is null)
            {
                continue;
            }

            TrustChainValidationOutcome outcome = await validateTrustChain(
                compactJwsChain,
                anchorAllowList,
                validationTime,
                clockSkew,
                pool,
                cancellationToken).ConfigureAwait(false);

            if(outcome.IsValid && outcome.Chain is { } chain)
            {
                foreach(EntityStatement statement in chain.Statements)
                {
                    _ = entities.Add(statement.Subject);
                }
            }
        }

        return entities;
    }
}
