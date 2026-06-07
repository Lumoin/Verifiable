namespace Verifiable.OAuth.Federation;

/// <summary>
/// Applies an accumulated <c>metadata_policy</c> to a subject's declared
/// metadata, producing the effective metadata the resolved party operates
/// under per OpenID Federation 1.0 §6.1.4. Run by the orchestrator after
/// <see cref="EvaluateMetadataPolicyDelegate"/> reports a legal operator
/// combination and before <see cref="ApprovePartyDelegate"/>.
/// </summary>
/// <param name="declaredMetadata">
/// The subject's own metadata as published in its Entity Configuration
/// for the entity type being resolved.
/// </param>
/// <param name="accumulatedPolicy">
/// The metadata policy accumulated by merging every Subordinate
/// Statement's metadata_policy entry walking the chain from Trust Anchor
/// to subject, per §6.1.4's merge algorithm.
/// </param>
/// <param name="entityType">
/// The <see cref="EntityTypeIdentifier"/> under which metadata is being
/// computed.
/// </param>
/// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
/// <returns>
/// A <see cref="MetadataPolicyApplyResult"/> carrying either the effective
/// metadata (success) or a structured failure reason when a constraint
/// is violated (declared value outside <c>one_of</c>, declared array not
/// a subset under <c>subset_of</c>, essential parameter missing, etc.).
/// The library default
/// (<see cref="FederationDefaultHooks.ApplyMetadataPolicy"/>) implements
/// the full §6.1.4.2 algorithm via
/// <see cref="MetadataPolicyApplicator.Apply(IReadOnlyDictionary{string, object}, IReadOnlyDictionary{string, object}, EntityTypeIdentifier)"/>.
/// </returns>
public delegate ValueTask<MetadataPolicyApplyResult> ApplyMetadataPolicyDelegate(
    IReadOnlyDictionary<string, object> declaredMetadata,
    IReadOnlyDictionary<string, object> accumulatedPolicy,
    EntityTypeIdentifier entityType,
    CancellationToken cancellationToken);
