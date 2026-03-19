using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace Verifiable.Core.SelectiveDisclosure.Strategy;

/// <summary>
/// The disclosure strategy graph: a lazily enumerable structure of all candidate
/// strategies for satisfying a set of disclosure requirements.
/// </summary>
/// <typeparam name="TCredential">The type representing credentials.</typeparam>
/// <remarks>
/// <para>
/// <strong>Architecture.</strong> The strategy graph sits between the per-credential
/// policy pipeline (Layer 4a in <see cref="DisclosureComputation{TCredential}"/>) and
/// the final disclosure plan. Where the computation pipeline processes each credential
/// match independently, the strategy graph reasons about <em>combinations</em> of
/// credentials and their collective properties: total entropy, credential count, ZKP
/// utilization, and constraint feasibility.
/// </para>
///
/// <para>
/// <strong>Pipeline integration.</strong> The extended pipeline is:
/// </para>
/// <list type="number">
/// <item><description>
/// Matches arrive from DCQL query evaluation (Layer 1-2).
/// </description></item>
/// <item><description>
/// Lattice construction (Layer 3) builds <see cref="SetDisclosureLattice{TClaim}"/>
/// for each credential, establishing Bottom (mandatory) and Top (available) bounds.
/// </description></item>
/// <item><description>
/// Per-credential policy assessment (Layer 4a) runs the assessor pipeline, producing
/// <see cref="CredentialDisclosureDecision{TCredential}"/> with effect tracking.
/// Each decision becomes a candidate <see cref="CredentialContribution{TCredential}"/>
/// — potentially duplicated when ZKP alternatives exist for the same requirement.
/// </description></item>
/// <item><description>
/// Strategy enumeration (Layer 5, this class) combines per-requirement candidates
/// into complete strategies. Each strategy is scored along entropy, credential count,
/// and predicate count dimensions. The SAT solver prunes infeasible branches during
/// enumeration via the <see cref="Unfold"/> pruner.
/// </description></item>
/// <item><description>
/// Cross-credential optimization (Layer 4b) operates on frontier strategies rather
/// than raw decisions, redistributing paths for global optimality.
/// </description></item>
/// <item><description>
/// The <see cref="Decisions"/> property is a flat projection of the best
/// strategy from the Pareto frontier.
/// </description></item>
/// </list>
///
/// <para>
/// <strong>Recursive structure and graph algebra.</strong> The graph has a natural
/// rose tree structure where each node represents a partial strategy (some requirements
/// satisfied) and children represent extensions (adding a credential contribution to
/// satisfy more requirements). This supports standard recursive schemes:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Catamorphism (fold):</strong> Bottom-up aggregation over the tree.
/// Compute entropy by folding leaf contributions. Count credentials. Collect all
/// disclosed paths. Any function from <c>Strategy -&gt; T</c> that decomposes into
/// leaf-level computation and combination of children's results.
/// Accessed via <see cref="Fold{TResult}"/>.
/// </description></item>
/// <item><description>
/// <strong>Anamorphism (unfold):</strong> Top-down generation of the tree from a seed.
/// The seed is the set of unsatisfied requirements. At each step, a credential is chosen
/// to contribute, producing children for the remaining requirements. The SAT solver prunes
/// branches whose constraint sets are infeasible before they are generated.
/// Accessed via <see cref="Unfold"/>.
/// </description></item>
/// <item><description>
/// <strong>Hylomorphism (unfold then fold):</strong> Generate strategies and immediately
/// aggregate their scores without materializing the full tree. This is the efficient path
/// for large search spaces — the frontier can be extracted in a single pass.
/// Accessed via <see cref="HyloFold{TResult}"/>.
/// </description></item>
/// </list>
///
/// <para>
/// <strong>Entropy and the preservation of structure.</strong> Every path disclosed
/// without necessity increases entropic exposure — the irreversible release of
/// identifying information. The entropy measure quantifies this: it is the total
/// identifying information released by a strategy, computed as a function of the
/// disclosed paths' individual weights and their correlations. ZKP predicate proofs
/// satisfy requirements without releasing values, contributing zero or near-zero entropy.
/// </para>
///
/// <para>
/// Entropy connects the mathematical concept from information theory with the practical
/// concern of preserving structure and context in data systems. Each verified connection
/// preserves a degree of order that would otherwise be lost. Each ZKP preserves a degree
/// of privacy that disclosure would irreversibly destroy. The entropy dimension on the
/// Pareto frontier makes this preservation measurable and navigable.
/// See <see href="https://lumoin.com/writings/mydata2025entropy">Imagination Architectures
/// and the Work of Trust</see> for the conceptual foundation connecting entropy,
/// verifiable data, and trust infrastructure.
/// </para>
///
/// <para>
/// <strong>Entropy picking example.</strong> Consider a verifier requesting name, birthdate,
/// and address. The holder has three credentials: national ID, driver's license, utility bill.
/// </para>
/// <para>
/// Strategy A: national ID discloses name (entropy 2.1), driver's license discloses
/// birthdate (entropy 4.3) and address (entropy 3.8). Total entropy: 10.2, credential
/// count: 2, ZKP count: 0.
/// </para>
/// <para>
/// Strategy B: driver's license discloses name (entropy 2.1) and address (entropy 3.8),
/// proves "birthdate before 2008-03-03" via ZKP (entropy 0.3 — only confirms age cohort).
/// Total entropy: 6.2, credential count: 1, ZKP count: 1.
/// </para>
/// <para>
/// Strategy B has lower entropy and fewer credentials, but higher ZKP count. Neither
/// dominates the other on all three dimensions — both appear on the Pareto frontier.
/// The deployment's <see cref="FrontierExtractDelegate{TCredential}"/> or downstream
/// LINQ query selects the preferred strategy based on deployment-specific priorities.
/// </para>
///
/// <para>
/// <strong>Lazy enumeration.</strong> The graph yields strategies lazily via depth-first
/// traversal. LINQ operators compose naturally:
/// </para>
/// <code>
/// //Find the lowest-entropy feasible strategy using at most two credentials.
/// var best = graph.EnumerateStrategies()
///     .Where(s =&gt; s.Status == StrategyStatus.Feasible)
///     .Where(s =&gt; s.CredentialCount &lt;= 2)
///     .OrderBy(s =&gt; s.Entropy)
///     .FirstOrDefault();
/// </code>
///
/// <para>
/// <strong>Future optimization paths.</strong> The current implementation uses depth-first
/// enumeration. For large strategy spaces, van Emde Boas trees could provide O(log log n)
/// predecessor queries for finding next-best strategies along bounded scoring dimensions.
/// Burrows-Wheeler style transforms could identify structural regularities in the strategy
/// space (credentials that always co-occur, paths that are always mutual alternatives)
/// to compress the enumeration. The architecture supports these optimizations without
/// changing the public API.
/// </para>
/// </remarks>
public sealed class DisclosureStrategyGraph<TCredential>
{
    /// <summary>
    /// Per-requirement candidate contributions. Each element contains the list of
    /// credential contributions that can satisfy one requirement. The graph enumerates
    /// combinations by selecting one contribution per requirement.
    /// </summary>
    private IReadOnlyList<CredentialContribution<TCredential>>[] CandidateContributions { get; }

    /// <summary>
    /// Delegate for computing entropy of a complete strategy from its contributions
    /// and any available signals.
    /// </summary>
    private EntropyComputeDelegate<TCredential> EntropyCompute { get; }

    /// <summary>
    /// Requesting party signals and attestation metadata passed to the entropy
    /// computation delegate.
    /// </summary>
    private IReadOnlyDictionary<Type, object>? Signals { get; }

    /// <summary>
    /// The selected strategy from the Pareto frontier. Set by
    /// <see cref="SelectLowestEntropy"/> or by the caller after frontier inspection.
    /// <see langword="null"/> until a strategy is selected.
    /// </summary>
    public ScoredStrategy<TCredential>? SelectedStrategy { get; set; }

    /// <summary>
    /// The cached Pareto frontier. Populated on first call to <see cref="ExtractFrontier"/>
    /// or <see cref="SelectLowestEntropy"/>.
    /// </summary>
    public IReadOnlyList<ScoredStrategy<TCredential>>? Frontier { get; private set; }

    /// <summary>
    /// Whether all query requirements were satisfied. Set by
    /// <see cref="DisclosureComputation{TCredential}"/> when the graph is produced
    /// from a full computation pipeline.
    /// </summary>
    public bool Satisfied { get; init; }

    /// <summary>
    /// Per-credential disclosure decisions from the selected strategy.
    /// This is the flat projection that protocol handlers (SD-JWT, ECDSA-SD, mso_mdoc)
    /// consume. Wallet UI and AI agents use the full graph via <see cref="EnumerateStrategies"/>
    /// and <see cref="Frontier"/> instead.
    /// </summary>
    public IReadOnlyList<CredentialDisclosureDecision<TCredential>> Decisions { get; set; } = [];

    /// <summary>
    /// Query requirement IDs that could not be satisfied by any credential.
    /// Candidates for credential discovery (Layer 2 extensibility).
    /// </summary>
    public IReadOnlyList<string>? UnsatisfiedRequirements { get; init; }

    /// <summary>
    /// The decision record capturing the full computation trace for audit and consent.
    /// Contains evaluation records, lattice computations, policy assessments, OTel trace
    /// context, and final decisions. <see langword="null"/> when the graph is constructed
    /// standalone outside the computation pipeline.
    /// </summary>
    public DisclosureDecisionRecord<TCredential>? DecisionRecord { get; init; }


    /// <summary>
    /// Creates a strategy graph from per-requirement candidate contributions.
    /// </summary>
    /// <param name="candidateContributions">
    /// For each requirement, the list of credential contributions that can satisfy it.
    /// The graph enumerates combinations by selecting one contribution per requirement.
    /// </param>
    /// <param name="entropyCompute">
    /// Delegate for computing entropy of a strategy. If <see langword="null"/>,
    /// <see cref="AdditiveEntropy"/> is used.
    /// </param>
    /// <param name="signals">Requesting party signals and attestation metadata for entropy computation.</param>
    public DisclosureStrategyGraph(
        IReadOnlyList<CredentialContribution<TCredential>>[] candidateContributions,
        EntropyComputeDelegate<TCredential>? entropyCompute = null,
        IReadOnlyDictionary<Type, object>? signals = null)
    {
        ArgumentNullException.ThrowIfNull(candidateContributions);

        CandidateContributions = candidateContributions;
        EntropyCompute = entropyCompute ?? AdditiveEntropy;
        Signals = signals;
    }


    /// <summary>
    /// Lazily enumerates all strategies via depth-first traversal of the combination tree.
    /// Each strategy is scored as it is yielded, without materializing the full tree.
    /// </summary>
    public IEnumerable<ScoredStrategy<TCredential>> EnumerateStrategies()
    {
        if(CandidateContributions.Length == 0)
        {
            yield break;
        }

        var current = new CredentialContribution<TCredential>[CandidateContributions.Length];
        foreach(var strategy in EnumerateRecursive(current, 0))
        {
            yield return strategy;
        }
    }


    /// <summary>
    /// Catamorphism: folds over all strategies bottom-up, aggregating results.
    /// </summary>
    /// <typeparam name="TResult">The result type of the fold.</typeparam>
    /// <param name="seed">The initial accumulator value.</param>
    /// <param name="folder">
    /// Combines the current accumulator with a scored strategy. Called once per strategy
    /// in enumeration order.
    /// </param>
    /// <returns>The final accumulated result.</returns>
    /// <remarks>
    /// <para>
    /// Example: compute the minimum entropy across all feasible strategies.
    /// </para>
    /// <code>
    /// double minEntropy = graph.Fold(
    ///     double.MaxValue,
    ///     (min, strategy) => strategy.Status == StrategyStatus.Feasible
    ///         ? Math.Min(min, strategy.Entropy)
    ///         : min);
    /// </code>
    /// </remarks>
    public TResult Fold<TResult>(TResult seed, Func<TResult, ScoredStrategy<TCredential>, TResult> folder)
    {
        ArgumentNullException.ThrowIfNull(folder);

        var result = seed;
        foreach(var strategy in EnumerateStrategies())
        {
            result = folder(result, strategy);
        }

        return result;
    }


    /// <summary>
    /// Anamorphism: unfolds the strategy tree from a seed, applying a pruning predicate
    /// at each level to avoid generating infeasible branches.
    /// </summary>
    /// <param name="pruner">
    /// Given a partial strategy (contributions selected so far) and the candidate for
    /// the next requirement, returns <see langword="false"/> to prune this branch.
    /// This is where the SAT solver integrates: check whether adding this candidate
    /// leaves the remaining constraints satisfiable.
    /// </param>
    /// <returns>A lazy sequence of strategies surviving the pruning.</returns>
    public IEnumerable<ScoredStrategy<TCredential>> Unfold(
        Func<IReadOnlyList<CredentialContribution<TCredential>>, CredentialContribution<TCredential>, bool> pruner)
    {
        ArgumentNullException.ThrowIfNull(pruner);

        if(CandidateContributions.Length == 0)
        {
            yield break;
        }

        var current = new List<CredentialContribution<TCredential>>();
        foreach(var strategy in UnfoldRecursive(current, 0, pruner))
        {
            yield return strategy;
        }
    }


    /// <summary>
    /// Hylomorphism: unfolds the strategy tree with pruning and immediately folds
    /// results without materializing intermediate strategies.
    /// </summary>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="seed">The initial accumulator value.</param>
    /// <param name="pruner">Branch pruning predicate (same as <see cref="Unfold"/>).</param>
    /// <param name="folder">Accumulates each surviving strategy into the result.</param>
    /// <returns>The folded result over all surviving strategies.</returns>
    /// <remarks>
    /// <para>
    /// This is the efficient path for large search spaces. Strategies are generated,
    /// scored, and accumulated in a single pass. No intermediate collections are allocated.
    /// </para>
    /// <code>
    /// //Count feasible strategies and track minimum entropy in one pass.
    /// var (count, minEntropy) = graph.HyloFold(
    ///     (Count: 0, MinEntropy: double.MaxValue),
    ///     pruner: (partial, next) => !HasConstraintConflict(partial, next),
    ///     folder: (acc, strategy) => strategy.Status == StrategyStatus.Feasible
    ///         ? (acc.Count + 1, Math.Min(acc.MinEntropy, strategy.Entropy))
    ///         : acc);
    /// </code>
    /// </remarks>
    public TResult HyloFold<TResult>(
        TResult seed,
        Func<IReadOnlyList<CredentialContribution<TCredential>>, CredentialContribution<TCredential>, bool> pruner,
        Func<TResult, ScoredStrategy<TCredential>, TResult> folder)
    {
        ArgumentNullException.ThrowIfNull(pruner);
        ArgumentNullException.ThrowIfNull(folder);

        var result = seed;
        foreach(var strategy in Unfold(pruner))
        {
            result = folder(result, strategy);
        }

        return result;
    }


    /// <summary>
    /// Extracts the Pareto frontier from all feasible strategies.
    /// </summary>
    /// <param name="extractor">
    /// The frontier extraction delegate. If <see langword="null"/>, the default
    /// three-dimension extractor (entropy, credential count, predicate count) is used.
    /// </param>
    /// <returns>The non-dominated strategies on the Pareto frontier.</returns>
    public IReadOnlyList<ScoredStrategy<TCredential>> ExtractFrontier(
        FrontierExtractDelegate<TCredential>? extractor = null)
    {
        if(Frontier is not null && extractor is null)
        {
            return Frontier;
        }

        var feasible = EnumerateStrategies()
            .Where(s => s.Status == StrategyStatus.Feasible)
            .ToList();

        var extract = extractor ?? DefaultFrontierExtract;
        var frontier = extract(feasible);

        if(extractor is null)
        {
            Frontier = frontier;
        }

        return frontier;
    }


    /// <summary>
    /// Extracts the Pareto frontier and selects the lowest-entropy strategy.
    /// Sets <see cref="SelectedStrategy"/> and <see cref="Frontier"/>.
    /// </summary>
    /// <returns>
    /// The selected lowest-entropy strategy, or <see langword="null"/> if no
    /// feasible strategies exist.
    /// </returns>
    public ScoredStrategy<TCredential>? SelectLowestEntropy()
    {
        var frontier = ExtractFrontier();

        if(frontier.Count == 0)
        {
            return null;
        }

        ScoredStrategy<TCredential> best = frontier[0];
        for(int i = 1; i < frontier.Count; i++)
        {
            if(frontier[i].Entropy < best.Entropy)
            {
                best = frontier[i];
            }
        }

        Debug.Assert(best.Status == StrategyStatus.Feasible,
            "Selected strategy must be feasible.");
        Debug.Assert(best.Entropy >= 0.0,
            "Selected strategy entropy must be non-negative.");

        SelectedStrategy = best;
        return best;
    }


    /// <summary>
    /// Default additive entropy model: sums <see cref="PathContribution.EntropyWeight"/>
    /// across all contributions in a strategy. Suitable when path entropy weights are
    /// pre-computed and approximately independent.
    /// </summary>
    public static double AdditiveEntropy(
        IReadOnlyList<CredentialContribution<TCredential>> contributions,
        IReadOnlyDictionary<Type, object>? signals)
    {
        ArgumentNullException.ThrowIfNull(contributions);

        double total = 0.0;
        foreach(var contribution in contributions)
        {
            foreach(var path in contribution.AllContributions)
            {
                total += path.EntropyWeight;
            }
        }

        return total;
    }


    /// <summary>
    /// Default Pareto frontier extraction across three dimensions: entropy (minimize),
    /// credential count (minimize), and predicate count (minimize).
    /// </summary>
    private static IReadOnlyList<ScoredStrategy<TCredential>> DefaultFrontierExtract(
        IReadOnlyList<ScoredStrategy<TCredential>> strategies)
    {
        var frontier = new List<ScoredStrategy<TCredential>>();

        foreach(var candidate in strategies)
        {
            bool dominated = false;

            for(int i = frontier.Count - 1; i >= 0; i--)
            {
                var existing = frontier[i];

                if(Dominates(existing, candidate))
                {
                    dominated = true;
                    break;
                }

                if(Dominates(candidate, existing))
                {
                    frontier.RemoveAt(i);
                }
            }

            if(!dominated)
            {
                frontier.Add(candidate);
            }
        }

        return frontier;
    }


    /// <summary>
    /// Returns <see langword="true"/> if strategy <paramref name="a"/> dominates
    /// <paramref name="b"/>: better or equal on all dimensions and strictly better on
    /// at least one.
    /// </summary>
    private static bool Dominates(ScoredStrategy<TCredential> a, ScoredStrategy<TCredential> b)
    {
        bool betterOnAny = false;

        if(a.Entropy > b.Entropy)
        {
            return false;
        }

        if(a.Entropy < b.Entropy)
        {
            betterOnAny = true;
        }

        if(a.CredentialCount > b.CredentialCount)
        {
            return false;
        }

        if(a.CredentialCount < b.CredentialCount)
        {
            betterOnAny = true;
        }

        if(a.PredicateCount > b.PredicateCount)
        {
            return false;
        }

        if(a.PredicateCount < b.PredicateCount)
        {
            betterOnAny = true;
        }

        return betterOnAny;
    }


    /// <summary>
    /// Stack-based depth-first enumeration of all strategy combinations.
    /// Uses an explicit stack instead of recursive yield to avoid creating
    /// O(depth) nested enumerator chains per yielded strategy.
    /// </summary>
    private IEnumerable<ScoredStrategy<TCredential>> EnumerateRecursive(
        CredentialContribution<TCredential>[] current,
        int depth)
    {
        //Each frame tracks the depth and index within that depth's candidate list.
        var stack = new Stack<(int Depth, int CandidateIndex)>();
        stack.Push((depth, 0));

        while(stack.Count > 0)
        {
            var (d, idx) = stack.Pop();

            if(d == CandidateContributions.Length)
            {
                yield return ScoreStrategy(current);
                continue;
            }

            if(idx >= CandidateContributions[d].Count)
            {
                continue;
            }

            //Push the next sibling first (will be processed after current subtree).
            if(idx + 1 < CandidateContributions[d].Count)
            {
                stack.Push((d, idx + 1));
            }

            //Select this candidate and push the child level.
            current[d] = CandidateContributions[d][idx];
            stack.Push((d + 1, 0));
        }
    }


    /// <summary>
    /// Stack-based depth-first enumeration with branch pruning.
    /// Uses an explicit stack instead of recursive yield to avoid creating
    /// O(depth) nested enumerator chains per yielded strategy.
    /// </summary>
    private IEnumerable<ScoredStrategy<TCredential>> UnfoldRecursive(
        List<CredentialContribution<TCredential>> current,
        int depth,
        Func<IReadOnlyList<CredentialContribution<TCredential>>, CredentialContribution<TCredential>, bool> pruner)
    {
        var stack = new Stack<(int Depth, int CandidateIndex)>();
        stack.Push((depth, 0));

        while(stack.Count > 0)
        {
            var (d, idx) = stack.Pop();

            //Trim the current list back to match the depth we're at.
            while(current.Count > d)
            {
                current.RemoveAt(current.Count - 1);
            }

            if(d == CandidateContributions.Length)
            {
                yield return ScoreStrategy([.. current]);
                continue;
            }

            if(idx >= CandidateContributions[d].Count)
            {
                continue;
            }

            //Push the next sibling first (will be processed after current subtree).
            if(idx + 1 < CandidateContributions[d].Count)
            {
                stack.Push((d, idx + 1));
            }

            var candidate = CandidateContributions[d][idx];
            if(!pruner(current, candidate))
            {
                continue;
            }

            //Select this candidate and push the child level.
            current.Add(candidate);
            stack.Push((d + 1, 0));
        }
    }


    /// <summary>
    /// Computes scoring dimensions for a complete strategy.
    /// </summary>
    private ScoredStrategy<TCredential> ScoreStrategy(CredentialContribution<TCredential>[] contributions)
    {
        Debug.Assert(contributions.Length > 0, "Cannot score an empty strategy.");

        CredentialContribution<TCredential>[] contributionList = [.. contributions];

        double entropy = EntropyCompute(contributionList, Signals);
        int predicateCount = 0;

        var distinctCredentials = new HashSet<TCredential?>();
        for(int i = 0; i < contributionList.Length; i++)
        {
            distinctCredentials.Add(contributionList[i].Credential);
            predicateCount += contributionList[i].Predicates.Count;
        }

        Debug.Assert(entropy >= 0.0, "Entropy must be non-negative.");
        Debug.Assert(distinctCredentials.Count > 0, "Strategy must use at least one credential.");

        return new ScoredStrategy<TCredential>
        {
            Contributions = contributionList,
            Entropy = entropy,
            CredentialCount = distinctCredentials.Count,
            PredicateCount = predicateCount,
            Status = StrategyStatus.Feasible
        };
    }
}
