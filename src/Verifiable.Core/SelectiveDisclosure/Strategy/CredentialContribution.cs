using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Core.SelectiveDisclosure.Strategy;

/// <summary>
/// One credential's contribution to a disclosure strategy: which paths it discloses,
/// which predicates it proves, and its entropic footprint.
/// </summary>
/// <typeparam name="TCredential">The type representing credentials.</typeparam>
/// <remarks>
/// <para>
/// A <see cref="CredentialContribution{TCredential}"/> is a leaf node in the strategy
/// graph's recursive structure. It represents the atomic unit of disclosure: one
/// credential contributing a set of paths (some disclosed, some proven via ZKP) to
/// satisfy one or more requirements.
/// </para>
/// <para>
/// The separation between <see cref="Disclosures"/> and <see cref="Predicates"/>
/// supports downstream formatting: SD-JWT handlers consume disclosures, ZKP handlers
/// consume predicates, and entropy computation iterates over all contributions uniformly
/// via <see cref="AllContributions"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("{Credential}: {Disclosures.Count} disclosures, {Predicates.Count} predicates")]
public sealed class CredentialContribution<TCredential>
{
    /// <summary>
    /// The credential providing this contribution.
    /// </summary>
    public required TCredential Credential { get; init; }

    /// <summary>
    /// The requirement this contribution helps satisfy.
    /// </summary>
    public required string QueryRequirementId { get; init; }

    /// <summary>
    /// Paths disclosed directly (full attribute values revealed to verifier).
    /// </summary>
    public required IReadOnlyList<PathContribution> Disclosures { get; init; }

    /// <summary>
    /// Paths satisfied via zero-knowledge predicate proofs.
    /// </summary>
    public required IReadOnlyList<PathContribution> Predicates { get; init; }

    /// <summary>
    /// The disclosure lattice for this credential, if available.
    /// Used by the strategy graph to verify that contributions remain within
    /// lattice bounds (Bottom is a subset of selected which is a subset of Top).
    /// </summary>
    public SetDisclosureLattice<CredentialPath>? Lattice { get; init; }

    /// <summary>
    /// All contributions (disclosures and predicates) for uniform iteration.
    /// Supports entropy aggregation without distinguishing satisfaction mode.
    /// Yields lazily to avoid materializing a combined collection.
    /// </summary>
    public IEnumerable<PathContribution> AllContributions
    {
        get
        {
            foreach(var d in Disclosures)
            {
                yield return d;
            }

            foreach(var p in Predicates)
            {
                yield return p;
            }
        }
    }
}