using System.Collections.Generic;

namespace Verifiable.Core.SelectiveDisclosure;


/// <summary>
/// Result of a disclosure selection operation.
/// </summary>
/// <typeparam name="TClaim">The type representing individual claims.</typeparam>
/// <param name="SelectedClaims">The claims selected for disclosure.</param>
/// <param name="SatisfiesRequirements">Whether all verifier requirements are satisfied.</param>
/// <param name="UnavailableClaims">Claims requested but not available in the credential.</param>
/// <param name="ConflictingClaims">Claims that conflict with user exclusions.</param>
public readonly record struct DisclosureSelectionResult<TClaim>(
    IReadOnlySet<TClaim> SelectedClaims,
    bool SatisfiesRequirements,
    IReadOnlySet<TClaim>? UnavailableClaims = null,
    IReadOnlySet<TClaim>? ConflictingClaims = null)
{
    /// <summary>
    /// Gets whether the selection has any issues (unavailable or conflicting claims).
    /// </summary>
    public bool HasIssues => (UnavailableClaims?.Count ?? 0) > 0 || (ConflictingClaims?.Count ?? 0) > 0;
}
