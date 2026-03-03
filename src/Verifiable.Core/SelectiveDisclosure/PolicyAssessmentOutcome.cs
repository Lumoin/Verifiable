using System.Collections.Generic;

namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// The outcome of a <see cref="PolicyAssessorDelegate{TCredential}"/> evaluation.
/// </summary>
/// <remarks>
/// <para>
/// Each outcome is recorded in the <see cref="DisclosureDecisionRecord{TCredential}"/>
/// for full audit traceability. The <see cref="AssessorName"/> and <see cref="Reason"/>
/// fields enable reconstruction of the decision chain — which assessor made what decision
/// and why — supporting ISO 27560 consent records, GDPR Article 30 processing records,
/// and AI accountability requirements.
/// </para>
/// <para>
/// <strong>Expansion and narrowing:</strong> Assessors can both narrow (remove paths)
/// and expand (add paths within lattice bounds). The <see cref="Effect"/> field records
/// which direction the assessment moved the disclosure set, enabling downstream builders
/// to distinguish verifier-initiated disclosures from regulatory expansions.
/// </para>
/// </remarks>
public sealed class PolicyAssessmentOutcome
{
    /// <summary>
    /// Whether the assessor approves the disclosure.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When <see langword="false"/>, the credential is excluded from the
    /// disclosure plan entirely. The computation continues evaluating other
    /// credentials that may satisfy the same query requirement.
    /// </para>
    /// </remarks>
    public required bool Approved { get; init; }

    /// <summary>
    /// The approved set of paths, potentially narrowed or expanded from the proposed set.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When <see langword="null"/> and <see cref="Approved"/> is <see langword="true"/>,
    /// the proposed paths are used as-is. When non-null, this set replaces the proposed
    /// paths for subsequent assessors in the pipeline.
    /// </para>
    /// <para>
    /// Expansion (adding paths not in the proposed set) is valid when the added paths
    /// are within the lattice top. The computation validates this postcondition.
    /// </para>
    /// </remarks>
    public IReadOnlySet<CredentialPath>? ApprovedPaths { get; init; }

    /// <summary>
    /// The effect this assessment had on the disclosure set.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The <see cref="DisclosureComputation{TCredential}"/> computes this by diffing the
    /// proposed paths against <see cref="ApprovedPaths"/>. When <see cref="ApprovedPaths"/>
    /// is <see langword="null"/>, the effect is <see cref="PolicyAssessmentEffect.Unchanged"/>.
    /// </para>
    /// </remarks>
    public PolicyAssessmentEffect Effect { get; init; }

    /// <summary>
    /// The name or identifier of the assessor, for the decision record.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Used in audit logs and consent receipts to attribute the decision.
    /// Examples: <c>"GdprDataMinimization"</c>, <c>"EdpEnforcement"</c>,
    /// <c>"AiRiskScorer"</c>, <c>"SatConstraintSolver"</c>.
    /// </para>
    /// </remarks>
    public required string AssessorName { get; init; }

    /// <summary>
    /// Human-readable reason for the decision, for the decision record.
    /// </summary>
    /// <remarks>
    /// <para>
    /// For rule-based assessors, this describes which rule triggered. For AI assessors,
    /// this may contain feature importance explanations. For SAT solvers, this may
    /// describe which constraint was binding or unsatisfiable.
    /// </para>
    /// </remarks>
    public string? Reason { get; init; }
}