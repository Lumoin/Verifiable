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
/// and AI accountability requirements (e.g., SHAP-style explanations for AI-driven decisions).
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
    /// The approved set of paths, potentially narrowed from the proposed set.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When <see langword="null"/> and <see cref="Approved"/> is <see langword="true"/>,
    /// the proposed paths are used as-is. When non-null, this set replaces
    /// the proposed paths for subsequent assessors in the pipeline. This enables
    /// assessors to progressively narrow the disclosure: each assessor in the
    /// chain sees the output of the previous one.
    /// </para>
    /// </remarks>
    public IReadOnlySet<CredentialPath>? ApprovedPaths { get; init; }

    /// <summary>
    /// The name or identifier of the assessor, for the decision record.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Used in audit logs and consent receipts to attribute the decision.
    /// Examples: <c>"GdprComplianceFilter"</c>, <c>"OrganizationPolicy"</c>,
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
    /// this may contain a SHAP-style explanation of the decision factors. For SAT solvers,
    /// this may describe which constraint was unsatisfiable. The reason is included in
    /// both the <see cref="DisclosureDecisionRecord{TCredential}"/> and any downstream
    /// consent receipts.
    /// </para>
    /// </remarks>
    public string? Reason { get; init; }
}