using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Evaluates the legality of operator combinations within a single
/// <c>metadata_policy</c> object per OpenID Federation 1.0 §6.1.3.1.8.
/// Run by the orchestrator before
/// <see cref="ApplyMetadataPolicyDelegate"/>; the returned
/// <see cref="Claim"/> carries
/// <see cref="WellKnownFederationClaimIds.MetadataPolicyOperatorCombinationLegal"/>.
/// </summary>
/// <param name="metadataPolicy">
/// The metadata_policy object as decoded from the statement payload —
/// keyed by metadata parameter name, with each value an object whose keys
/// are operator names (<c>value</c>, <c>add</c>, <c>default</c>,
/// <c>one_of</c>, <c>subset_of</c>, <c>superset_of</c>, <c>essential</c>,
/// or deployment-defined operators registered via
/// <c>metadata_policy_crit</c>).
/// </param>
/// <param name="entityType">
/// The <see cref="EntityTypeIdentifier"/> under which this policy is
/// evaluated. Policies are scoped per entity type.
/// </param>
/// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
/// <returns>
/// A <see cref="Claim"/> with
/// <see cref="WellKnownFederationClaimIds.MetadataPolicyOperatorCombinationLegal"/>
/// outcome. The library default
/// (<see cref="FederationDefaultHooks.EvaluateMetadataPolicy"/>) ships as a
/// permissive stub returning <see cref="ClaimOutcome.Success"/>; the
/// full §6.1.3 algorithm is not yet implemented. Deployments needing strict
/// §6.1.3 enforcement supply their own implementation.
/// </returns>
public delegate ValueTask<Claim> EvaluateMetadataPolicyDelegate(
    IReadOnlyDictionary<string, object> metadataPolicy,
    EntityTypeIdentifier entityType,
    CancellationToken cancellationToken);
