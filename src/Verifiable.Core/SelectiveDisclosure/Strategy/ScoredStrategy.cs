using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Core.SelectiveDisclosure.Strategy;

/// <summary>
/// A disclosure strategy with computed scoring dimensions.
/// </summary>
/// <typeparam name="TCredential">The type representing credentials.</typeparam>
/// <remarks>
/// <para>
/// A scored strategy represents one complete way to satisfy all disclosure requirements.
/// It is the output of the strategy graph's enumeration and scoring process. The scoring
/// dimensions — <see cref="Entropy"/>, <see cref="CredentialCount"/>, and
/// <see cref="PredicateCount"/> — are the axes along which the Pareto frontier is computed.
/// </para>
/// <para>
/// <strong>Entropy and the preservation of structure.</strong> Every path disclosed without
/// necessity increases entropic exposure — the irreversible release of identifying
/// information. A ZKP predicate proof satisfies the verifier without releasing the
/// underlying value, contributing zero or near-zero entropy. The entropy dimension makes
/// this trade-off explicit: a strategy with lower entropy preserves more of the holder's
/// anonymity set.
/// </para>
/// <para>
/// Entropy connects the information-theoretic concept with the practical concern of
/// preserving structure and context in data systems. Each verified connection preserves
/// a degree of order that would otherwise be lost. Each ZKP preserves a degree of privacy
/// that disclosure would irreversibly destroy. The entropy dimension on the Pareto frontier
/// makes this preservation measurable.
/// </para>
/// </remarks>
[DebuggerDisplay("Entropy={Entropy}, Credentials={CredentialCount}, ZkpCount={PredicateCount}, Status={Status}")]
public sealed class ScoredStrategy<TCredential>
{
    /// <summary>
    /// The credential contributions composing this strategy.
    /// </summary>
    public required IReadOnlyList<CredentialContribution<TCredential>> Contributions { get; init; }

    /// <summary>
    /// Computed entropy: total identifying information released by this strategy.
    /// Lower is better for privacy. Computed by the <see cref="EntropyComputeDelegate{TCredential}"/>
    /// provided to the strategy graph.
    /// </summary>
    public required double Entropy { get; init; }

    /// <summary>
    /// Number of distinct credentials involved in this strategy.
    /// Fewer credentials means fewer issuers contacted and lower presentation complexity.
    /// </summary>
    public required int CredentialCount { get; init; }

    /// <summary>
    /// Number of zero-knowledge predicate proofs in this strategy.
    /// ZKPs have computational cost but preserve privacy (low entropy contribution).
    /// </summary>
    public required int PredicateCount { get; init; }

    /// <summary>
    /// Whether this strategy is feasible, policy-rejected, constraint-infeasible, or dominated.
    /// </summary>
    public required StrategyStatus Status { get; init; }

    /// <summary>
    /// Policy assessment records from the per-credential assessor pipeline, if any.
    /// Provides traceability for why a strategy was accepted or rejected.
    /// </summary>
    public IReadOnlyList<PolicyAssessmentRecord>? PolicyAssessments { get; init; }
}
