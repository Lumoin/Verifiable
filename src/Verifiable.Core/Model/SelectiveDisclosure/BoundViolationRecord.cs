using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Captures one cross-credential optimizer result whose selected paths left the decision's
/// lattice bounds and were clamped back inside them.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="CrossCredentialOptimizerDelegate{TCredential}"/> is contracted to keep every
/// decision within its credential's lattice. An optimizer that breaks the contract does not
/// get to widen the disclosure: the clamp bounds the returned set, and this record preserves
/// what the optimizer attempted so the audit trail keeps the event. The three path sets are
/// disjoint and each is <see langword="null"/> when that violation shape did not occur.
/// </para>
/// </remarks>
[DebuggerDisplay("BoundViolation(QueryId={QueryRequirementId}, Optimizer={OptimizerIndex})")]
public sealed class BoundViolationRecord
{
    /// <summary>
    /// The query requirement whose decision left its lattice bounds.
    /// </summary>
    public required string QueryRequirementId { get; init; }

    /// <summary>
    /// The zero-based position of the optimizer in the cross-credential pipeline, which
    /// identifies the offending pass when several optimizers run in sequence.
    /// </summary>
    public required int OptimizerIndex { get; init; }

    /// <summary>
    /// Paths outside the decision's lattice top that the clamp removed.
    /// </summary>
    public IReadOnlySet<CredentialPath>? OutOfBoundsPaths { get; init; }

    /// <summary>
    /// Mandatory paths the optimizer dropped that the clamp restored.
    /// </summary>
    public IReadOnlySet<CredentialPath>? RestoredMandatoryPaths { get; init; }

    /// <summary>
    /// Ancestor paths the optimizer omitted that upward closure restored.
    /// </summary>
    public IReadOnlySet<CredentialPath>? RestoredAncestorPaths { get; init; }
}
