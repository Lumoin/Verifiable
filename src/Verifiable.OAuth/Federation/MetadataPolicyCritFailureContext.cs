using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// <see cref="ClaimContext"/> carrying the unknown operator names that
/// caused a <see cref="WellKnownFederationClaimIds.MetadataPolicyCritOperatorsUnderstood"/>
/// failure per OpenID Federation 1.0 §6.1.3.2.
/// </summary>
/// <remarks>
/// Reports every unknown operator encountered across the chain's
/// accumulated <c>metadata_policy_crit</c> claims so downstream observers
/// see the full set of operators the deployment would need to teach the
/// receiver about before the chain can be honoured.
/// </remarks>
public sealed record MetadataPolicyCritFailureContext: ClaimContext
{
    /// <summary>
    /// The operators listed in some statement's <c>metadata_policy_crit</c>
    /// that the receiver does not understand. Ordered by first encounter
    /// walking the chain from anchor toward leaf; duplicates collapsed.
    /// </summary>
    public required IReadOnlyList<MetadataPolicyOperator> UnknownOperators { get; init; }
}
