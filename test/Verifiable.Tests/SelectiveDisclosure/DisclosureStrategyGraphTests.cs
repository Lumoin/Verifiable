using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Core.SelectiveDisclosure.Strategy;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Tests for <see cref="DisclosureStrategyGraph{TCredential}"/> covering strategy
/// enumeration, entropy scoring, recursive schemes, Pareto frontier extraction,
/// and ZKP alternative branching.
/// </summary>
[TestClass]
internal sealed class DisclosureStrategyGraphTests
{
    public TestContext TestContext { get; set; } = null!;

    private static CredentialPath GivenName { get; } = CredentialPath.FromJsonPointer("/given_name");
    private static CredentialPath Birthdate { get; } = CredentialPath.FromJsonPointer("/birthdate");
    private static CredentialPath Address { get; } = CredentialPath.FromJsonPointer("/address");


    [TestMethod]
    public void EnumeratesAllCombinations()
    {
        //Two requirements, each with two candidates = 2x2 = 4 strategies.
        var graph = new DisclosureStrategyGraph<string>(
        [
            [MakeContribution("cred-a", "req-1", GivenName, 2.0),
             MakeContribution("cred-b", "req-1", GivenName, 2.5)],
            [MakeContribution("cred-a", "req-2", Birthdate, 4.3),
             MakeContribution("cred-c", "req-2", Birthdate, 3.8)]
        ]);

        var strategies = graph.EnumerateStrategies().ToList();

        Assert.HasCount(4, strategies);
    }


    [TestMethod]
    public void SingleRequirementSingleCandidateYieldsOneStrategy()
    {
        var graph = new DisclosureStrategyGraph<string>(
        [
            [MakeContribution("cred-a", "req-1", GivenName, 2.0)]
        ]);

        var strategies = graph.EnumerateStrategies().ToList();

        Assert.HasCount(1, strategies);
        Assert.AreEqual(2.0, strategies[0].Entropy);
        Assert.AreEqual(1, strategies[0].CredentialCount);
    }


    [TestMethod]
    public void EmptyCandidatesYieldsNoStrategies()
    {
        var graph = new DisclosureStrategyGraph<string>([]);

        var strategies = graph.EnumerateStrategies().ToList();

        Assert.IsEmpty(strategies);
    }


    [TestMethod]
    public void AdditiveEntropySumsPathWeights()
    {
        var graph = new DisclosureStrategyGraph<string>(
        [
            [MakeContribution("cred-a", "req-1", GivenName, 2.1)],
            [MakeContribution("cred-b", "req-2", Birthdate, 4.3)]
        ]);

        var strategy = graph.EnumerateStrategies().Single();

        Assert.AreEqual(6.4, strategy.Entropy, 0.001);
    }


    [TestMethod]
    public void ZkpContributionHasLowerEntropyThanDisclosure()
    {
        var disclosureOption = MakeContribution("cred-a", "req-1", Birthdate, 4.3);
        var zkpOption = MakeZkpContribution("cred-a", "req-1", Birthdate, 0.3);

        var graph = new DisclosureStrategyGraph<string>(
        [
            [disclosureOption, zkpOption]
        ]);

        var strategies = graph.EnumerateStrategies()
            .OrderBy(s => s.Entropy)
            .ToList();

        Assert.HasCount(2, strategies);
        Assert.AreEqual(0.3, strategies[0].Entropy, 0.001);
        Assert.AreEqual(4.3, strategies[1].Entropy, 0.001);
        Assert.AreEqual(1, strategies[0].PredicateCount);
        Assert.AreEqual(0, strategies[1].PredicateCount);
    }


    [TestMethod]
    public void DistinctCredentialCountTracksUniqueCredentials()
    {
        //Same credential satisfies both requirements — credential count should be 1.
        var graph = new DisclosureStrategyGraph<string>(
        [
            [MakeContribution("cred-a", "req-1", GivenName, 2.0)],
            [MakeContribution("cred-a", "req-2", Birthdate, 4.3)]
        ]);

        var strategy = graph.EnumerateStrategies().Single();

        Assert.AreEqual(1, strategy.CredentialCount);
    }


    [TestMethod]
    public void DifferentCredentialsCountedSeparately()
    {
        var graph = new DisclosureStrategyGraph<string>(
        [
            [MakeContribution("cred-a", "req-1", GivenName, 2.0)],
            [MakeContribution("cred-b", "req-2", Birthdate, 4.3)]
        ]);

        var strategy = graph.EnumerateStrategies().Single();

        Assert.AreEqual(2, strategy.CredentialCount);
    }


    [TestMethod]
    public void FoldComputesMinimumEntropy()
    {
        var graph = new DisclosureStrategyGraph<string>(
        [
            [MakeContribution("cred-a", "req-1", GivenName, 2.0),
             MakeContribution("cred-b", "req-1", GivenName, 5.0)],
            [MakeContribution("cred-c", "req-2", Address, 3.0)]
        ]);

        double minEntropy = graph.Fold(
            double.MaxValue,
            (min, strategy) => Math.Min(min, strategy.Entropy));

        Assert.AreEqual(5.0, minEntropy, 0.001);
    }


    [TestMethod]
    public void UnfoldPrunesInfeasibleBranches()
    {
        //Pruner rejects any strategy that would combine cred-a and cred-c.
        var graph = new DisclosureStrategyGraph<string>(
        [
            [MakeContribution("cred-a", "req-1", GivenName, 2.0),
             MakeContribution("cred-b", "req-1", GivenName, 3.0)],
            [MakeContribution("cred-c", "req-2", Address, 1.0),
             MakeContribution("cred-d", "req-2", Address, 4.0)]
        ]);

        var strategies = graph.Unfold(
            (partial, next) => !(partial.Any(p => p.Credential == "cred-a") && next.Credential == "cred-c"))
            .ToList();

        //Without pruning: 4 strategies. With pruning: cred-a+cred-c is removed = 3.
        Assert.HasCount(3, strategies);
        foreach(var strategy in strategies)
        {
            bool hasCombination = strategy.Contributions.Any(c => c.Credential == "cred-a") &&
                strategy.Contributions.Any(c => c.Credential == "cred-c");
            Assert.IsFalse(hasCombination, "Pruned combination must not appear.");
        }
    }


    [TestMethod]
    public void HyloFoldCombinesPruningAndAggregation()
    {
        var graph = new DisclosureStrategyGraph<string>(
        [
            [MakeContribution("cred-a", "req-1", GivenName, 2.0),
             MakeContribution("cred-b", "req-1", GivenName, 3.0)],
            [MakeContribution("cred-c", "req-2", Address, 1.0),
             MakeContribution("cred-d", "req-2", Address, 4.0)]
        ]);

        var (count, minEntropy) = graph.HyloFold(
            (Count: 0, MinEntropy: double.MaxValue),
            pruner: (partial, next) => !(partial.Any(p => p.Credential == "cred-a") && next.Credential == "cred-c"),
            folder: (acc, strategy) => (acc.Count + 1, Math.Min(acc.MinEntropy, strategy.Entropy)));

        Assert.AreEqual(3, count);
        Assert.AreEqual(4.0, minEntropy, 0.001);
    }


    [TestMethod]
    public void ParetoFrontierExcludesDominatedStrategies()
    {
        //Strategy with entropy=6.0, creds=1, zkps=0 dominates
        //strategy with entropy=8.0, creds=2, zkps=0.
        var graph = new DisclosureStrategyGraph<string>(
        [
            [MakeContribution("cred-a", "req-1", GivenName, 2.0),
             MakeContribution("cred-b", "req-1", GivenName, 3.0)],
            [MakeContribution("cred-a", "req-2", Address, 4.0),
             MakeContribution("cred-b", "req-2", Address, 5.0)]
        ]);

        var frontier = graph.ExtractFrontier();

        //cred-a for both (entropy=6.0, creds=1) dominates cred-b for both (entropy=8.0, creds=1).
        //Mixed strategies (entropy=7.0, creds=2) are dominated by same-credential strategies.
        Assert.IsGreaterThanOrEqualTo(1, frontier.Count, "Frontier must contain at least one strategy.");
        Assert.IsTrue(frontier.All(s => s.Status == StrategyStatus.Feasible),
            "All frontier strategies must be feasible.");

        var best = frontier.OrderBy(s => s.Entropy).First();
        Assert.AreEqual(6.0, best.Entropy, 0.001);
    }


    [TestMethod]
    public void ParetoFrontierRetainsBothWhenNeitherDominates()
    {
        //Strategy A: entropy=6.0, creds=1, zkps=1 (ZKP for birthdate).
        //Strategy B: entropy=10.0, creds=1, zkps=0 (full disclosure).
        //A is better on entropy, B is better on zkp count. Neither dominates.
        var zkpOption = MakeZkpContribution("cred-a", "req-1", Birthdate, 0.3);
        var disclosureOption = MakeContribution("cred-a", "req-1", Birthdate, 4.3);

        var graph = new DisclosureStrategyGraph<string>(
        [
            [zkpOption, disclosureOption],
            [MakeContribution("cred-a", "req-2", Address, 5.7)]
        ]);

        var frontier = graph.ExtractFrontier();

        Assert.HasCount(2, frontier);

        var lowEntropy = frontier.OrderBy(s => s.Entropy).First();
        var noZkp = frontier.OrderBy(s => s.PredicateCount).First();

        Assert.AreEqual(1, lowEntropy.PredicateCount);
        Assert.AreEqual(0, noZkp.PredicateCount);
        Assert.IsLessThan(noZkp.Entropy, lowEntropy.Entropy,
            "ZKP strategy must have lower entropy.");
    }


    [TestMethod]
    public void CustomEntropyDelegateIsUsed()
    {
        //Custom entropy: double the additive total.
        EntropyComputeDelegate<string> doubleEntropy = (contributions, signals) =>
        {
            double total = 0.0;
            foreach(var contribution in contributions)
            {
                foreach(var path in contribution.AllContributions)
                {
                    total += path.EntropyWeight;
                }
            }

            return total * 2.0;
        };

        var graph = new DisclosureStrategyGraph<string>(
        [
            [MakeContribution("cred-a", "req-1", GivenName, 3.0)]
        ],
        entropyCompute: doubleEntropy);

        var strategy = graph.EnumerateStrategies().Single();

        Assert.AreEqual(6.0, strategy.Entropy, 0.001);
    }


    [TestMethod]
    public void EntropyDelegateReceivesSignals()
    {
        IReadOnlyDictionary<Type, object>? receivedSignals = null;

        EntropyComputeDelegate<string> signalCapture = (contributions, signals) =>
        {
            receivedSignals = signals;
            return 0.0;
        };

        var signals = new Dictionary<Type, object>
        {
            [typeof(double)] = 0.5
        };

        var graph = new DisclosureStrategyGraph<string>(
        [
            [MakeContribution("cred-a", "req-1", GivenName, 1.0)]
        ],
        entropyCompute: signalCapture,
        signals: signals);

        var _ = graph.EnumerateStrategies().ToList();

        Assert.IsNotNull(receivedSignals);
        Assert.AreEqual(0.5, (double)receivedSignals![typeof(double)]);
    }


    [TestMethod]
    public void ThreeCredentialRealisticScenario()
    {
        //National ID: name (2.1), birthdate (4.3), SSN (8.5).
        //Driver's license: name (2.1), birthdate (4.3), address (3.8).
        //Utility bill: name (2.1), address (3.8), account (6.2).
        //Requirements: name, birthdate, address.
        //Also include ZKP option for birthdate from driver's license.
        var graph = new DisclosureStrategyGraph<string>(
        [
            //Name: three options.
            [MakeContribution("national-id", "req-name", GivenName, 2.1),
             MakeContribution("drivers-license", "req-name", GivenName, 2.1),
             MakeContribution("utility-bill", "req-name", GivenName, 2.1)],
            //Birthdate: two disclosure options + one ZKP option.
            [MakeContribution("national-id", "req-birthdate", Birthdate, 4.3),
             MakeContribution("drivers-license", "req-birthdate", Birthdate, 4.3),
             MakeZkpContribution("drivers-license", "req-birthdate", Birthdate, 0.3)],
            //Address: two options.
            [MakeContribution("drivers-license", "req-address", Address, 3.8),
             MakeContribution("utility-bill", "req-address", Address, 3.8)]
        ]);

        var frontier = graph.ExtractFrontier();

        Assert.IsGreaterThanOrEqualTo(1, frontier.Count, "Frontier must have at least one strategy.");

        //The best entropy strategy should use driver's license for all three
        //with ZKP for birthdate: entropy = 2.1 + 0.3 + 3.8 = 6.2, creds = 1.
        var lowestEntropy = frontier.OrderBy(s => s.Entropy).First();
        Assert.AreEqual(6.2, lowestEntropy.Entropy, 0.01);
        Assert.AreEqual(1, lowestEntropy.CredentialCount);
        Assert.AreEqual(1, lowestEntropy.PredicateCount);
    }


    [TestMethod]
    public void LazyEnumerationStopsEarly()
    {
        //Build a graph with many combinations, but only take the first.
        var req1Candidates = new CredentialContribution<string>[10];
        for(int i = 0; i < 10; i++)
        {
            req1Candidates[i] = MakeContribution($"cred-{i}", "req-1", GivenName, i * 1.0);
        }

        var req2Candidates = new CredentialContribution<string>[10];
        for(int i = 0; i < 10; i++)
        {
            req2Candidates[i] = MakeContribution($"cred-{i + 10}", "req-2", Address, i * 0.5);
        }

        var graph = new DisclosureStrategyGraph<string>(
            [req1Candidates, req2Candidates]);

        //100 total combinations, but we only take 3 — lazy enumeration should not
        //evaluate all 100.
        var first3 = graph.EnumerateStrategies().Take(3).ToList();

        Assert.HasCount(3, first3);
    }


    [TestMethod]
    public void AllStrategiesAreFeasibleByDefault()
    {
        var graph = new DisclosureStrategyGraph<string>(
        [
            [MakeContribution("cred-a", "req-1", GivenName, 2.0),
             MakeContribution("cred-b", "req-1", GivenName, 3.0)]
        ]);

        var strategies = graph.EnumerateStrategies().ToList();

        Assert.IsTrue(strategies.All(s => s.Status == StrategyStatus.Feasible),
            "All enumerated strategies must be feasible before frontier extraction.");
    }


    /// <summary>
    /// Creates a disclosure <see cref="CredentialContribution{TCredential}"/> with a single
    /// disclosed path at the given entropy weight.
    /// </summary>
    private static CredentialContribution<string> MakeContribution(
        string credential,
        string requirementId,
        CredentialPath path,
        double entropyWeight)
    {
        return new CredentialContribution<string>
        {
            Credential = credential,
            QueryRequirementId = requirementId,
            Disclosures =
            [
                new PathContribution
                {
                    Path = path,
                    Mode = SatisfactionMode.Disclosure,
                    EntropyWeight = entropyWeight
                }
            ],
            Predicates = []
        };
    }


    /// <summary>
    /// Creates a ZKP <see cref="CredentialContribution{TCredential}"/> with a single
    /// predicate proof at the given entropy weight (typically near zero).
    /// </summary>
    private static CredentialContribution<string> MakeZkpContribution(
        string credential,
        string requirementId,
        CredentialPath path,
        double entropyWeight)
    {
        return new CredentialContribution<string>
        {
            Credential = credential,
            QueryRequirementId = requirementId,
            Disclosures = [],
            Predicates =
            [
                new PathContribution
                {
                    Path = path,
                    Mode = SatisfactionMode.PredicateProof,
                    EntropyWeight = entropyWeight
                }
            ]
        };
    }
}