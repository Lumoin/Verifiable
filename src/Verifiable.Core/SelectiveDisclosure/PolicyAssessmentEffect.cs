namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// Classifies the effect of a policy assessment on the disclosure set.
/// </summary>
/// <remarks>
/// <para>
/// The effect is determined by comparing the assessor's approved paths against the
/// proposed paths it received. The computation computes this by diffing input versus
/// output path sets — it does not trust the assessor's self-reported effect. The
/// computed effect is recorded in the <see cref="DisclosureDecisionRecord{TCredential}"/>
/// for audit trail construction, enabling downstream builders to distinguish between
/// verifier-initiated disclosures, regulatory expansions, and privacy-motivated narrowings.
/// </para>
/// </remarks>
public enum PolicyAssessmentEffect
{
    /// <summary>
    /// The assessor approved the proposed paths without modification.
    /// </summary>
    Unchanged,

    /// <summary>
    /// The assessor removed paths from the proposed set.
    /// </summary>
    Narrowed,

    /// <summary>
    /// The assessor added paths to the proposed set while staying within lattice bounds.
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