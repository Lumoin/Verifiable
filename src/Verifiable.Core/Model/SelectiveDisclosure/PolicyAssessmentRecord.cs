using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Captures the outcome of a policy assessor for a single credential.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Effect"/>, <see cref="RemovedPaths"/> and <see cref="AddedPaths"/> describe what
/// happened to the disclosure set: they are diffed against the set the pipeline actually
/// adopted, which is the assessor's return value clamped into the credential's lattice.
/// </para>
/// <para>
/// An assessor returning a set outside those bounds is an auditable event in its own right —
/// a component that tried to disclose what the credential does not offer, to drop a claim the
/// issuer made mandatory, or to hand over a nested value without its ancestors. The clamp
/// prevents it from taking effect; <see cref="OutOfBoundsPaths"/>,
/// <see cref="RestoredMandatoryPaths"/> and <see cref="RestoredAncestorPaths"/> keep the
/// attempt, one field per violation shape, so the provenance trail can show it. All three are
/// <see langword="null"/> when the assessor stayed inside the lattice.
/// </para>
/// </remarks>
[DebuggerDisplay("Policy(QueryId={QueryRequirementId}, Assessor={AssessorName}, Approved={Approved}, Effect={Effect})")]
public sealed class PolicyAssessmentRecord
{
    /// <summary>
    /// The query requirement this assessment applies to.
    /// </summary>
    public required string QueryRequirementId { get; init; }

    /// <summary>
    /// The name or identifier of the policy assessor.
    /// </summary>
    public required string AssessorName { get; init; }

    /// <summary>
    /// Whether the assessor approved the disclosure.
    /// </summary>
    public required bool Approved { get; init; }

    /// <summary>
    /// The effect this assessment had on the disclosure set.
    /// </summary>
    public required PolicyAssessmentEffect Effect { get; init; }

    /// <summary>
    /// Paths removed from the adopted disclosure set — the clamped return value — relative to
    /// the proposed set, if any. What the assessor itself attempted beyond the bounds is carried
    /// by the escape fields below, never here.
    /// </summary>
    public IReadOnlySet<CredentialPath>? RemovedPaths { get; init; }

    /// <summary>
    /// Paths added to the adopted disclosure set — the clamped return value — relative to the
    /// proposed set, if any. The clamp guarantees every path here lies within the lattice
    /// bounds; the escape fields below record what it refused.
    /// </summary>
    public IReadOnlySet<CredentialPath>? AddedPaths { get; init; }

    /// <summary>
    /// Paths the assessor returned that lie above the lattice top and the clamp therefore
    /// removed, if any — an attempt to disclose beyond what the credential offers.
    /// </summary>
    public IReadOnlySet<CredentialPath>? OutOfBoundsPaths { get; init; }

    /// <summary>
    /// Mandatory paths the assessor dropped and the clamp restored, if any — an attempt to
    /// disclose below the lattice bottom.
    /// </summary>
    public IReadOnlySet<CredentialPath>? RestoredMandatoryPaths { get; init; }

    /// <summary>
    /// Ancestor paths the assessor omitted and upward closure restored, if any — a structurally
    /// invalid set that would have named a nested claim without the claims containing it.
    /// </summary>
    public IReadOnlySet<CredentialPath>? RestoredAncestorPaths { get; init; }

    /// <summary>
    /// Human-readable reason for the decision.
    /// </summary>
    public string? Reason { get; init; }
}
