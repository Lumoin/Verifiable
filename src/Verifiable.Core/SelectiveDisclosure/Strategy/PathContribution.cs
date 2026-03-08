using System.Diagnostics;


namespace Verifiable.Core.SelectiveDisclosure.Strategy;

/// <summary>
/// A single path contribution within a strategy, recording how the path satisfies
/// a requirement and its entropy weight.
/// </summary>
/// <remarks>
/// <para>
/// Each <see cref="PathContribution"/> represents one atomic decision: "disclose
/// path P from credential C" or "prove predicate over path P from credential C."
/// The <see cref="EntropyWeight"/> is determined by the path's identifying power —
/// how much the disclosed value narrows the holder's anonymity set.
/// </para>
/// <para>
/// Entropy weights are provided externally via attestation metadata from the issuer
/// or via a deployment-specific entropy model. The strategy graph does not compute
/// weights itself — it aggregates them. This separation follows the same principle
/// as the signal architecture: issuers declare what a credential contains (including
/// its statistical properties), the computation infrastructure reasons over those
/// declarations.
/// </para>
/// </remarks>
[DebuggerDisplay("{Path} via {Mode}, entropy={EntropyWeight}")]
public sealed class PathContribution
{
    /// <summary>
    /// The credential path being contributed.
    /// </summary>
    public required CredentialPath Path { get; init; }

    /// <summary>
    /// How this path satisfies the requirement.
    /// </summary>
    public required SatisfactionMode Mode { get; init; }

    /// <summary>
    /// The entropy weight of this contribution. For <see cref="SatisfactionMode.Disclosure"/>,
    /// this reflects the identifying power of the revealed value. For
    /// <see cref="SatisfactionMode.PredicateProof"/>, this is typically zero or
    /// a small value reflecting predicate selectivity.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Entropy weights use a simple additive model by default: the total entropy
    /// of a strategy is the sum of its path contributions' weights. More sophisticated
    /// models accounting for correlations between paths (e.g., birthdate + postal code
    /// is more identifying than either alone) can be implemented via
    /// <see cref="EntropyComputeDelegate{TCredential}"/>.
    /// </para>
    /// </remarks>
    public required double EntropyWeight { get; init; }
}
