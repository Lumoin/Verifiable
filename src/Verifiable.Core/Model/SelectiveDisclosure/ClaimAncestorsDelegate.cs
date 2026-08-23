using System.Collections.Generic;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Yields the ancestors of a claim, giving a <see cref="SetDisclosureLattice{TClaim}"/> the
/// hierarchy it needs to compute upward closure.
/// </summary>
/// <typeparam name="TClaim">The type representing individual claims.</typeparam>
/// <param name="claim">The claim whose ancestors are requested.</param>
/// <returns>
/// Every ancestor of <paramref name="claim"/>, transitively up to the root and excluding the
/// claim itself. Order is irrelevant, and an empty sequence declares that the claim has no
/// ancestors.
/// </returns>
/// <remarks>
/// <para>
/// The lattice is claim-type-neutral: a claim may be a hierarchical JSON Pointer path
/// (<see cref="CredentialPath"/>), a flat N-Quad statement index, or a bare claim name.
/// Hierarchy is therefore supplied as a seam rather than assumed. A lattice constructed
/// without one treats every claim as unrelated, so
/// <see cref="SetDisclosureLattice{TClaim}.ComputeClosure"/> reduces to the mandatory floor
/// and <see cref="SetDisclosureLattice{TClaim}.IsValid"/> reduces to the bounds check.
/// </para>
/// <para>
/// The sequence must be transitive. The lattice walks it once per claim rather than to a
/// fixpoint, so an implementation that yields only the immediate parent leaves the closure
/// incomplete. <see cref="CredentialPath.Ancestry"/> is the well-known implementation for
/// credential paths.
/// </para>
/// </remarks>
public delegate IEnumerable<TClaim> ClaimAncestorsDelegate<TClaim>(TClaim claim);
