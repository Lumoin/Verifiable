using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// Captures the outcome of a policy assessor for a single credential.
/// </summary>
[DebuggerDisplay("Policy(QueryId={QueryRequirementId}, Assessor={AssessorName}, Approved={Approved})")]
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
    /// Paths the assessor removed from the disclosure set, if any.
    /// </summary>
    public IReadOnlySet<CredentialPath>? RemovedPaths { get; init; }

    /// <summary>
    /// Human-readable reason for the decision.
    /// </summary>
    public string? Reason { get; init; }
}