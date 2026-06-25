using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Pure-observation hook called once per chain-resolution attempt with the
/// full <see cref="ClaimIssueResult"/> produced by
/// <see cref="TrustChainValidator"/>. Implementations record / project the
/// outcome (audit log, telemetry, status cache) but MUST NOT influence the
/// validation result — the orchestrator does not consume any return value.
/// </summary>
/// <param name="chain">The trust chain that was resolved.</param>
/// <param name="validationOutcome">
/// The <see cref="ClaimIssueResult"/> produced by the chain validator —
/// every claim emitted, partial-completion status, correlation id.
/// </param>
/// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
/// <returns>A task that completes when recording finishes.</returns>
/// <remarks>
/// <para>
/// Separate from the generic observation slots
/// (<c>RecordDecisionDelegate</c> / <c>ProjectDecisionDelegate</c>) — this
/// delegate is federation-scoped and receives the validation outcome
/// in its native shape, where the generic observers receive a serialised
/// projection across all decision points (federation, OAuth, OID4VP, etc.).
/// Deployments that want one observation surface can plug the generic
/// observers into this delegate and dispatch from there.
/// </para>
/// </remarks>
public delegate ValueTask RecordTrustChainStatusDelegate(
    TrustChain chain,
    ClaimIssueResult validationOutcome,
    CancellationToken cancellationToken);
