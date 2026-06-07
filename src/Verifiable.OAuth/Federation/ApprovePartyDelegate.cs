using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Application-supplied gate run after a trust chain has validated and
/// metadata policy has been applied. The orchestrator calls this once
/// per resolved party; the returned <see cref="Claim"/> joins the chain's
/// <see cref="ClaimIssueResult"/> via the
/// <see cref="WellKnownFederationClaimIds.PartyApproved"/> id.
/// </summary>
/// <param name="chain">The validated trust chain.</param>
/// <param name="entityType">
/// The role under which the party is being approved (Relying Party,
/// OpenID Provider, Wallet Provider, etc.). Same party may be approved
/// independently for distinct roles.
/// </param>
/// <param name="effectiveMetadata">
/// The metadata that survived the chain's accumulated
/// <c>metadata_policy</c>. Read-only; the application reads what it needs
/// to decide.
/// </param>
/// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
/// <returns>
/// A <see cref="Claim"/> with <see cref="WellKnownFederationClaimIds.PartyApproved"/>
/// and <see cref="ClaimOutcome.Success"/> when the party is admitted, or
/// <see cref="ClaimOutcome.Failure"/> with a context subclass carrying the
/// rejection reason. The default implementation
/// (<see cref="FederationDefaultHooks.ApproveParty"/>) admits every chain
/// that reached this point; deployments override to add their gate.
/// </returns>
public delegate ValueTask<Claim> ApprovePartyDelegate(
    TrustChain chain,
    EntityTypeIdentifier entityType,
    IReadOnlyDictionary<string, object> effectiveMetadata,
    CancellationToken cancellationToken);
