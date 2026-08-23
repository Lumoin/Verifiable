namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Classifies the effect of a policy assessment on the disclosure set.
/// </summary>
/// <remarks>
/// <para>
/// The effect is determined by comparing the ADOPTED set — the assessor's returned paths
/// after the lattice clamp — against the proposed paths the assessor received. The
/// computation diffs those two sets itself; it trusts neither the assessor's self-reported
/// effect nor its unclamped return value. Whether the assessor attempted to leave its
/// bounds is a separate question answered by the escape fields on
/// <see cref="PolicyAssessmentRecord"/>. The computed effect is recorded in the
/// <see cref="DisclosureDecisionRecord{TCredential}"/> for audit trail construction,
/// enabling downstream builders to distinguish between verifier-initiated disclosures,
/// regulatory expansions, and privacy-motivated narrowings.
/// </para>
/// </remarks>
public enum PolicyAssessmentEffect
{
    /// <summary>
    /// The adopted set equals the proposed set.
    /// </summary>
    Unchanged,

    /// <summary>
    /// The adopted set removed paths from the proposed set.
    /// </summary>
    Narrowed,

    /// <summary>
    /// The adopted set added paths to the proposed set. The clamp guarantees every addition
    /// lies within the lattice bounds; what the assessor attempted beyond them is carried by
    /// <see cref="PolicyAssessmentRecord"/>'s escape fields, not by this effect.
    /// </summary>
    Expanded,

    /// <summary>
    /// The assessor both added and removed paths.
    /// </summary>
    Modified,

    /// <summary>
    /// The assessor rejected the disclosure entirely.
    /// </summary>
    Rejected
}
