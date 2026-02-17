using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// Captures the lattice computation for a single credential.
/// </summary>
[DebuggerDisplay("Lattice(QueryId={QueryRequirementId}, Min={MinimumPaths.Count}, Max={MaximumPaths.Count})")]
public sealed class LatticeComputationRecord
{
    /// <summary>
    /// The query requirement this lattice was computed for.
    /// </summary>
    public required string QueryRequirementId { get; init; }

    /// <summary>
    /// The minimum disclosure set (lattice bottom + verifier requirements).
    /// </summary>
    public required IReadOnlySet<CredentialPath> MinimumPaths { get; init; }

    /// <summary>
    /// The maximum disclosure set (lattice top - user exclusions).
    /// </summary>
    public required IReadOnlySet<CredentialPath> MaximumPaths { get; init; }

    /// <summary>
    /// Paths where verifier requirements conflict with user exclusions.
    /// </summary>
    public IReadOnlySet<CredentialPath>? ConflictPaths { get; init; }

    /// <summary>
    /// The final selected paths after lattice computation (before policy).
    /// </summary>
    public required IReadOnlySet<CredentialPath> SelectedPaths { get; init; }
}