using System.Collections.Generic;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// The outcome of clamping a proposed disclosure set back into its lattice: the bounded set
/// itself, and the claims the clamp had to correct in order to produce it.
/// </summary>
/// <typeparam name="TClaim">The type representing individual claims.</typeparam>
/// <remarks>
/// <para>
/// A proposal can leave the lattice in three distinguishable ways, and the three are kept
/// apart here so an audit trail can state which one occurred: the proposal can name claims
/// above the top (<see cref="OutOfBoundsClaims"/>), drop claims below the bottom
/// (<see cref="RestoredMandatoryClaims"/>), or select a claim without its ancestors
/// (<see cref="RestoredAncestorClaims"/>). The three sets are disjoint.
/// </para>
/// <para>
/// <see cref="IsWithinBounds"/> answers the single question "was the proposal already
/// inside the lattice", which is what a caller checks before deciding whether the event is
/// worth recording.
/// </para>
/// </remarks>
public sealed class DisclosureClampResult<TClaim>
{
    /// <summary>
    /// The bounded, upward-closed set: (proposal ∩ <see cref="SetDisclosureLattice{TClaim}.Top"/>)
    /// ∪ <see cref="SetDisclosureLattice{TClaim}.Bottom"/>, plus every ancestor the closure requires.
    /// </summary>
    public required IReadOnlySet<TClaim> ClampedClaims { get; init; }

    /// <summary>
    /// Proposed claims that lie outside <see cref="SetDisclosureLattice{TClaim}.Top"/> and were
    /// dropped by the clamp, or <see langword="null"/> when the proposal named none.
    /// </summary>
    public IReadOnlySet<TClaim>? OutOfBoundsClaims { get; init; }

    /// <summary>
    /// Mandatory claims (<see cref="SetDisclosureLattice{TClaim}.Bottom"/>) that the proposal
    /// omitted and the clamp restored, or <see langword="null"/> when the proposal kept them all.
    /// </summary>
    public IReadOnlySet<TClaim>? RestoredMandatoryClaims { get; init; }

    /// <summary>
    /// Ancestors that the proposal omitted and upward closure restored, or
    /// <see langword="null"/> when the proposal was already structurally valid.
    /// </summary>
    public IReadOnlySet<TClaim>? RestoredAncestorClaims { get; init; }

    /// <summary>
    /// Whether the proposal was already inside the lattice, so that
    /// <see cref="ClampedClaims"/> equals it and the clamp corrected nothing.
    /// </summary>
    public bool IsWithinBounds =>
        OutOfBoundsClaims is null && RestoredMandatoryClaims is null && RestoredAncestorClaims is null;
}
