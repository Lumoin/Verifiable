using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Core.SelectiveDisclosure.Strategy;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SelectiveDisclosure;

[TestClass]
internal sealed class DisclosureComputationTests
{
    public TestContext TestContext { get; set; } = null!;

    private static CredentialPath GivenName { get; } = CredentialPath.FromJsonPointer("/given_name");
    private static CredentialPath FamilyName { get; } = CredentialPath.FromJsonPointer("/family_name");
    private static CredentialPath Email { get; } = CredentialPath.FromJsonPointer("/email");
    private static CredentialPath Birthdate { get; } = CredentialPath.FromJsonPointer("/birthdate");
    private static CredentialPath Phone { get; } = CredentialPath.FromJsonPointer("/phone");
    private static CredentialPath Address { get; } = CredentialPath.FromJsonPointer("/address");
    private static CredentialPath Ssn { get; } = CredentialPath.FromJsonPointer("/ssn");
    private static CredentialPath Nationality { get; } = CredentialPath.FromJsonPointer("/nationality");
    private static CredentialPath Category { get; } = CredentialPath.FromJsonPointer("/category");
    private static CredentialPath AccountNumber { get; } = CredentialPath.FromJsonPointer("/account_number");
    private static CredentialPath Iss { get; } = CredentialPath.FromJsonPointer("/iss");
    private static CredentialPath Type { get; } = CredentialPath.FromJsonPointer("/type");


    [TestMethod]
    public async Task ComputesSingleCredentialDisclosure()
    {
        var computation = new DisclosureComputation<string>();

        var matches = new[]
        {
            CreateMatch("cred-1", "req-1",
                required: [GivenName, FamilyName],
                available: [GivenName, FamilyName, Email, Birthdate])
        };

        var graph = await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(graph.Satisfied);
        Assert.HasCount(1, graph.Decisions);
        Assert.IsTrue(graph.Decisions[0].SatisfiesRequirements);
        Assert.Contains(GivenName, graph.Decisions[0].SelectedPaths);
        Assert.Contains(FamilyName, graph.Decisions[0].SelectedPaths);
    }


    [TestMethod]
    public async Task MinimizesDisclosureToRequiredPaths()
    {
        var computation = new DisclosureComputation<string>();

        var matches = new[]
        {
            CreateMatch("cred-1", "req-1",
                required: [GivenName],
                available: [GivenName, FamilyName, Email, Birthdate, Phone])
        };

        var graph = await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(graph.Satisfied);
        var selected = graph.Decisions[0].SelectedPaths;

        //Should contain required path but not optional ones.
        Assert.Contains(GivenName, selected);
        Assert.DoesNotContain(Email, selected);
        Assert.DoesNotContain(Birthdate, selected);
        Assert.DoesNotContain(Phone, selected);
    }


    [TestMethod]
    public async Task IncludesMandatoryPathsEvenWhenNotRequested()
    {
        var computation = new DisclosureComputation<string>();

        var mandatory = new HashSet<CredentialPath> { Iss, Type };
        var matches = new[]
        {
            CreateMatch("cred-1", "req-1",
                required: [GivenName],
                available: [Iss, Type, GivenName, FamilyName],
                mandatory: mandatory)
        };

        var graph = await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(graph.Satisfied);
        var selected = graph.Decisions[0].SelectedPaths;

        Assert.Contains(Iss, selected);
        Assert.Contains(Type, selected);
        Assert.Contains(GivenName, selected);
    }


    [TestMethod]
    public async Task RespectsUserExclusions()
    {
        var computation = new DisclosureComputation<string>();

        var matches = new[]
        {
            CreateMatch("cred-1", "req-1",
                required: [GivenName, Email],
                available: [GivenName, FamilyName, Email, Birthdate])
        };

        var exclusions = new Dictionary<string, IReadOnlySet<CredentialPath>>
        {
            ["req-1"] = new HashSet<CredentialPath> { Email }
        };

        var graph = await computation.ComputeAsync(matches, exclusions,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(graph.Satisfied);
        var decision = graph.Decisions[0];

        //Email excluded by user but required by verifier — conflict.
        Assert.IsFalse(decision.SatisfiesRequirements);
        Assert.IsNotNull(decision.ConflictingPaths);
        Assert.Contains(Email, decision.ConflictingPaths!);
    }


    [TestMethod]
    public async Task PolicyAssessorCanRejectDisclosure()
    {
        var rejectAll = new PolicyAssessorDelegate<string>((context, ct) =>
            Task.FromResult(new PolicyAssessmentOutcome
            {
                Approved = false,
                AssessorName = "RejectAll"
            }));

        var computation = new DisclosureComputation<string>([rejectAll]);

        var matches = new[]
        {
            CreateMatch("cred-1", "req-1",
                required: [GivenName],
                available: [GivenName, FamilyName])
        };

        var graph = await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(graph.Satisfied);
        Assert.IsEmpty(graph.Decisions);
        Assert.IsNotNull(graph.UnsatisfiedRequirements);
        Assert.Contains("req-1", graph.UnsatisfiedRequirements!);
        Assert.IsNull(graph.SelectedStrategy);
    }


    [TestMethod]
    public async Task PolicyAssessorCanNarrowDisclosure()
    {
        var narrowToGivenNameOnly = new PolicyAssessorDelegate<string>((context, ct) =>
            Task.FromResult(new PolicyAssessmentOutcome
            {
                Approved = true,
                ApprovedPaths = new HashSet<CredentialPath> { GivenName },
                AssessorName = "NarrowPolicy"
            }));

        var computation = new DisclosureComputation<string>([narrowToGivenNameOnly]);

        var matches = new[]
        {
            CreateMatch("cred-1", "req-1",
                required: [GivenName, FamilyName],
                available: [GivenName, FamilyName, Email])
        };

        var graph = await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(graph.Satisfied);
        var selected = graph.Decisions[0].SelectedPaths;

        Assert.Contains(GivenName, selected);
        Assert.DoesNotContain(FamilyName, selected);

        //Policy narrowed below verifier requirements.
        Assert.IsFalse(graph.Decisions[0].SatisfiesRequirements);
    }


    [TestMethod]
    public async Task PolicyPipelineExecutesInOrder()
    {
        var executionOrder = new List<string>();

        PolicyAssessorDelegate<string> first = (context, ct) =>
        {
            executionOrder.Add("first");
            return Task.FromResult(new PolicyAssessmentOutcome
            {
                Approved = true,
                AssessorName = "First"
            });
        };

        PolicyAssessorDelegate<string> second = (context, ct) =>
        {
            executionOrder.Add("second");
            return Task.FromResult(new PolicyAssessmentOutcome
            {
                Approved = true,
                AssessorName = "Second"
            });
        };

        var computation = new DisclosureComputation<string>([first, second]);

        var matches = new[]
        {
            CreateMatch("cred-1", "req-1",
                required: [GivenName],
                available: [GivenName])
        };

        await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(2, executionOrder);
        Assert.AreEqual("first", executionOrder[0]);
        Assert.AreEqual("second", executionOrder[1]);
    }


    [TestMethod]
    public async Task PolicyRejectionStopsPipeline()
    {
        var executionOrder = new List<string>();

        PolicyAssessorDelegate<string> rejecter = (context, ct) =>
        {
            executionOrder.Add("rejecter");
            return Task.FromResult(new PolicyAssessmentOutcome
            {
                Approved = false,
                AssessorName = "Rejecter"
            });
        };

        PolicyAssessorDelegate<string> shouldNotRun = (context, ct) =>
        {
            executionOrder.Add("shouldNotRun");
            return Task.FromResult(new PolicyAssessmentOutcome
            {
                Approved = true,
                AssessorName = "ShouldNotRun"
            });
        };

        var computation = new DisclosureComputation<string>([rejecter, shouldNotRun]);

        var matches = new[]
        {
            CreateMatch("cred-1", "req-1",
                required: [GivenName],
                available: [GivenName])
        };

        await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, executionOrder);
        Assert.AreEqual("rejecter", executionOrder[0]);
    }


    [TestMethod]
    public async Task DecisionRecordCapturesAllPhases()
    {
        var computation = new DisclosureComputation<string>();

        var matches = new[]
        {
            CreateMatch("cred-1", "req-1",
                required: [GivenName],
                available: [GivenName, FamilyName])
        };

        var graph = await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var record = graph.DecisionRecord!;

        Assert.IsNotNull(record);
        Assert.IsTrue(record.Satisfied);
        Assert.AreEqual(1, record.CandidateCount);
        Assert.IsGreaterThan(TimeSpan.Zero, record.Duration);
        Assert.HasCount(1, record.Evaluations);
        Assert.HasCount(1, record.LatticeComputations);
        Assert.HasCount(1, record.FinalDecisions);
    }


    [TestMethod]
    public async Task DecisionRecordCapturesLatticeDetails()
    {
        var computation = new DisclosureComputation<string>();

        var mandatory = new HashSet<CredentialPath> { Iss };
        var matches = new[]
        {
            CreateMatch("cred-1", "req-1",
                required: [GivenName],
                available: [Iss, GivenName, FamilyName, Email],
                mandatory: mandatory)
        };

        var graph = await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var latticeRecord = graph.DecisionRecord!.LatticeComputations[0];

        Assert.AreEqual("req-1", latticeRecord.QueryRequirementId);

        //Minimum should contain mandatory + required.
        Assert.Contains(Iss, latticeRecord.MinimumPaths);
        Assert.Contains(GivenName, latticeRecord.MinimumPaths);

        //Maximum should contain all available.
        Assert.Contains(Iss, latticeRecord.MaximumPaths);
        Assert.Contains(GivenName, latticeRecord.MaximumPaths);
        Assert.Contains(FamilyName, latticeRecord.MaximumPaths);
        Assert.Contains(Email, latticeRecord.MaximumPaths);
    }


    [TestMethod]
    public async Task DecisionRecordCapturesPolicyAssessments()
    {
        var assessor = new PolicyAssessorDelegate<string>((context, ct) =>
            Task.FromResult(new PolicyAssessmentOutcome
            {
                Approved = true,
                AssessorName = "TestAssessor",
                Reason = "Approved for testing."
            }));

        var computation = new DisclosureComputation<string>([assessor]);

        var matches = new[]
        {
            CreateMatch("cred-1", "req-1",
                required: [GivenName],
                available: [GivenName])
        };

        var graph = await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(graph.DecisionRecord!.PolicyAssessments);
        Assert.HasCount(1, graph.DecisionRecord!.PolicyAssessments!);

        var assessment = graph.DecisionRecord!.PolicyAssessments[0];
        Assert.AreEqual("TestAssessor", assessment.AssessorName);
        Assert.IsTrue(assessment.Approved);
        Assert.AreEqual("Approved for testing.", assessment.Reason);
    }


    [TestMethod]
    public async Task EmptyMatchListProducesSatisfiedEmptyGraph()
    {
        var computation = new DisclosureComputation<string>();

        var graph = await computation.ComputeAsync([],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(graph.Satisfied);
        Assert.IsEmpty(graph.Decisions);
    }


    [TestMethod]
    public async Task LatticeIsExposedOnDecision()
    {
        var computation = new DisclosureComputation<string>();

        var matches = new[]
        {
            CreateMatch("cred-1", "req-1",
                required: [GivenName],
                available: [GivenName, FamilyName])
        };

        var graph = await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(graph.Decisions[0].Lattice);
        Assert.Contains(GivenName, graph.Decisions[0].Lattice!.Top);
        Assert.Contains(FamilyName, graph.Decisions[0].Lattice!.Top);
    }


    [TestMethod]
    public async Task GraphAlwaysHasSelectedStrategyAndFrontier()
    {
        var computation = new DisclosureComputation<string>();

        var matches = new[]
        {
            CreateMatch("cred-1", "req-1",
                required: [GivenName],
                available: [GivenName, Birthdate])
        };

        var graph = await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(graph.SelectedStrategy);
        Assert.IsNotNull(graph.Frontier);
        Assert.AreEqual(StrategyStatus.Feasible, graph.SelectedStrategy!.Status);
    }


    [TestMethod]
    public async Task EntropyWeightsAffectStrategyScoring()
    {
        var computation = new DisclosureComputation<string>();

        //All three paths are required so the lattice keeps them all.
        var matches = new[]
        {
            CreateMatch("cred-1", "req-1",
                required: [GivenName, Birthdate],
                available: [Iss, GivenName, Birthdate],
                mandatory: new HashSet<CredentialPath> { Iss })
        };

        var weights = new Dictionary<CredentialPath, double>
        {
            [Iss] = 0.1,
            [GivenName] = 2.1,
            [Birthdate] = 4.3
        };

        var graph = await computation.ComputeAsync(matches,
            entropyWeights: weights,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Entropy is iss=0.1 + given_name=2.1 + birthdate=4.3 = 6.5.
        Assert.AreEqual(6.5, graph.SelectedStrategy!.Entropy, 0.01);
    }


    [TestMethod]
    public async Task LowestEntropyStrategyIsSelectedByDefault()
    {
        var computation = new DisclosureComputation<string>();

        //Both credentials provide given_name. National ID also discloses SSN
        //(required by its match), driver's license discloses address (required
        //by its match). The lattice keeps all required paths, making entropy
        //differ between the two strategies.
        var matches = new[]
        {
            CreateMatch("national-id", "req-name",
                required: [GivenName, Ssn],
                available: [Iss, GivenName, Ssn],
                mandatory: new HashSet<CredentialPath> { Iss }),
            CreateMatch("drivers-license", "req-name",
                required: [GivenName, Address],
                available: [Iss, GivenName, Address],
                mandatory: new HashSet<CredentialPath> { Iss })
        };

        var weights = new Dictionary<CredentialPath, double>
        {
            [Iss] = 0.1,
            [GivenName] = 2.1,
            [Ssn] = 8.5,
            [Address] = 3.8
        };

        var graph = await computation.ComputeAsync(matches,
            entropyWeights: weights,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Driver's license: iss=0.1 + given_name=2.1 + address=3.8 = 6.0.
        //National ID: iss=0.1 + given_name=2.1 + ssn=8.5 = 10.7.
        Assert.AreEqual(6.0, graph.SelectedStrategy!.Entropy, 0.01);
        Assert.HasCount(1, graph.Decisions);
        Assert.AreEqual("drivers-license", graph.Decisions[0].Credential);
    }


    [TestMethod]
    public async Task PolicyNarrowingReducesEntropyInGraph()
    {
        var narrower = new PolicyAssessorDelegate<string>((context, ct) =>
        {
            var narrowed = new HashSet<CredentialPath>(context.ProposedPaths);
            narrowed.Remove(Birthdate);

            return Task.FromResult(new PolicyAssessmentOutcome
            {
                Approved = true,
                ApprovedPaths = narrowed,
                AssessorName = "DataMinimization"
            });
        });

        var weights = new Dictionary<CredentialPath, double>
        {
            [GivenName] = 2.1,
            [Birthdate] = 4.3
        };

        var withPolicy = new DisclosureComputation<string>([narrower]);
        var withoutPolicy = new DisclosureComputation<string>();

        var matches = new[]
        {
            CreateMatch("cred-1", "req-1",
                required: [GivenName, Birthdate],
                available: [GivenName, Birthdate])
        };

        var graphWithPolicy = await withPolicy.ComputeAsync(matches,
            entropyWeights: weights,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        var graphWithoutPolicy = await withoutPolicy.ComputeAsync(matches,
            entropyWeights: weights,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsLessThan(
            graphWithoutPolicy.SelectedStrategy!.Entropy,
            graphWithPolicy.SelectedStrategy!.Entropy,
            "Policy-narrowed strategy must have lower entropy.");
    }


    [TestMethod]
    public async Task CustomEntropyDelegateIsUsedByComputation()
    {
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

        var computation = new DisclosureComputation<string>([], entropyCompute: doubleEntropy);

        var matches = new[]
        {
            CreateMatch("cred-1", "req-1",
                required: [GivenName],
                available: [GivenName])
        };

        var weights = new Dictionary<CredentialPath, double>
        {
            [GivenName] = 3.0
        };

        var graph = await computation.ComputeAsync(matches,
            entropyWeights: weights,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(6.0, graph.SelectedStrategy!.Entropy, 0.001);
    }


    [TestMethod]
    public async Task GraphEnumerationIsAccessibleForDebugging()
    {
        var computation = new DisclosureComputation<string>();

        var matches = new[]
        {
            CreateMatch("cred-a", "req-1",
                required: [GivenName],
                available: [GivenName, Birthdate]),
            CreateMatch("cred-b", "req-1",
                required: [GivenName],
                available: [GivenName])
        };

        var weights = new Dictionary<CredentialPath, double>
        {
            [GivenName] = 2.0,
            [Birthdate] = 4.0
        };

        var graph = await computation.ComputeAsync(matches,
            entropyWeights: weights,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(graph.Frontier);
        Assert.IsGreaterThanOrEqualTo(1, graph.Frontier!.Count);

        var allStrategies = graph.EnumerateStrategies().ToList();
        Assert.IsGreaterThanOrEqualTo(1, allStrategies.Count);

        foreach(var strategy in allStrategies)
        {
            Assert.IsGreaterThanOrEqualTo(0.0, strategy.Entropy);
            Assert.IsGreaterThanOrEqualTo(1, strategy.CredentialCount);
        }
    }


    [TestMethod]
    public async Task SatOptimizerEnforcesMutualExclusionAcrossCredentials()
    {
        //Verifier requests name, birthdate, and address. Wallet holds three
        //credentials with overlapping claims. Constraint: never disclose SSN
        //and account number to the same verifier.
        var optimizer = BuildSatOptimizer(
            sensitivePathPairs: [(Ssn, AccountNumber)]);

        var computation = new DisclosureComputation<string>(
            [], crossCredentialOptimizers: [optimizer]);

        var matches = new[]
        {
            CreateMatch("national-id", "req-name",
                required: [GivenName],
                available: [Iss, GivenName, FamilyName, Birthdate, Ssn, Nationality],
                mandatory: new HashSet<CredentialPath> { Iss }),
            CreateMatch("drivers-license", "req-birthdate",
                required: [Birthdate],
                available: [Iss, GivenName, Birthdate, Category, Address],
                mandatory: new HashSet<CredentialPath> { Iss }),
            CreateMatch("utility-bill", "req-address",
                required: [Address],
                available: [Iss, GivenName, Address, AccountNumber],
                mandatory: new HashSet<CredentialPath> { Iss })
        };

        var graph = await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(graph.Satisfied);
        Assert.HasCount(3, graph.Decisions);

        //Verify the constraint: SSN and account number are not both disclosed.
        bool ssnDisclosed = false;
        bool accountDisclosed = false;

        foreach(var decision in graph.Decisions)
        {
            if(decision.SelectedPaths.Contains(Ssn))
            {
                ssnDisclosed = true;
            }

            if(decision.SelectedPaths.Contains(AccountNumber))
            {
                accountDisclosed = true;
            }
        }

        Assert.IsFalse(ssnDisclosed && accountDisclosed,
            "SSN and account number must not both be disclosed.");
    }


    [TestMethod]
    public async Task SatOptimizerPassesSignalsToConstraintEncoding()
    {
        bool signalsReceived = false;
        double receivedRiskTolerance = 0.0;

        var signalAwareOptimizer = new CrossCredentialOptimizerDelegate<string>(
            (decisions, signals, ct) =>
            {
                if(signals is not null && signals.TryGetValue(typeof(double), out object? value))
                {
                    signalsReceived = true;
                    receivedRiskTolerance = (double)value;
                }

                return Task.FromResult(decisions);
            });

        var computation = new DisclosureComputation<string>(
            [], crossCredentialOptimizers: [signalAwareOptimizer]);

        var requestingPartySignals = new Dictionary<Type, object>
        {
            [typeof(double)] = 0.3
        };

        var matches = new[]
        {
            CreateMatch("cred-1", "req-1",
                required: [GivenName],
                available: [GivenName])
        };

        await computation.ComputeAsync(matches,
            requestingPartySignals: requestingPartySignals,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(signalsReceived, "Optimizer must receive requesting party signals.");
        Assert.AreEqual(0.3, receivedRiskTolerance);
    }


    /// <summary>
    /// Builds a <see cref="CrossCredentialOptimizerDelegate{TCredential}"/> backed
    /// by the <see cref="DpllSolver"/>. Encodes mutual exclusion constraints for
    /// specified path pairs and uses the solver to find a feasible assignment.
    /// </summary>
    private static CrossCredentialOptimizerDelegate<string> BuildSatOptimizer(
        (CredentialPath A, CredentialPath B)[] sensitivePathPairs)
    {
        return (decisions, signals, ct) =>
        {
            if(decisions.Count <= 1)
            {
                return Task.FromResult(decisions);
            }

            //Build variable mapping: each (credential index, path) pair gets a variable.
            var variableMap = new Dictionary<(int CredentialIndex, CredentialPath Path), int>();
            int nextVariable = 0;

            for(int i = 0; i < decisions.Count; i++)
            {
                foreach(var path in decisions[i].SelectedPaths)
                {
                    variableMap[(i, path)] = nextVariable++;
                }
            }

            var clauses = new List<Literal[]>();

            //Mandatory path constraints: if a credential has mandatory paths, they must be true.
            for(int i = 0; i < decisions.Count; i++)
            {
                if(decisions[i].Lattice is not null)
                {
                    foreach(var mandatoryPath in decisions[i].Lattice!.Bottom)
                    {
                        if(variableMap.TryGetValue((i, mandatoryPath), out int variable))
                        {
                            clauses.Add([new Literal(variable, true)]);
                        }
                    }
                }
            }

            //Mutual exclusion constraints for sensitive path pairs.
            foreach(var (pathA, pathB) in sensitivePathPairs)
            {
                var variablesWithA = new List<int>();
                var variablesWithB = new List<int>();

                for(int i = 0; i < decisions.Count; i++)
                {
                    if(variableMap.TryGetValue((i, pathA), out int varA))
                    {
                        variablesWithA.Add(varA);
                    }

                    if(variableMap.TryGetValue((i, pathB), out int varB))
                    {
                        variablesWithB.Add(varB);
                    }
                }

                //For each pair (a, b) across credentials: ~a | ~b.
                foreach(int a in variablesWithA)
                {
                    foreach(int b in variablesWithB)
                    {
                        clauses.Add([new Literal(a, false), new Literal(b, false)]);
                    }
                }
            }

            //Required path constraints.
            var requiredPathsByRequirement = new Dictionary<CredentialPath, List<int>>();
            for(int i = 0; i < decisions.Count; i++)
            {
                foreach(var path in decisions[i].SelectedPaths)
                {
                    if(!requiredPathsByRequirement.TryGetValue(path, out var vars))
                    {
                        vars = [];
                        requiredPathsByRequirement[path] = vars;
                    }

                    vars.Add(variableMap[(i, path)]);
                }
            }

            var result = DpllSolver.Solve(clauses, nextVariable);

            if(!result.Satisfiable)
            {
                return Task.FromResult(decisions);
            }

            //Rebuild decisions from the solver's assignment.
            var optimized = new List<CredentialDisclosureDecision<string>>();
            for(int i = 0; i < decisions.Count; i++)
            {
                var keptPaths = new HashSet<CredentialPath>();
                foreach(var path in decisions[i].SelectedPaths)
                {
                    int variable = variableMap[(i, path)];
                    if(result.Assignment![variable])
                    {
                        keptPaths.Add(path);
                    }
                }

                //Always keep mandatory paths.
                if(decisions[i].Lattice is not null)
                {
                    keptPaths.UnionWith(decisions[i].Lattice!.Bottom);
                }

                optimized.Add(new CredentialDisclosureDecision<string>
                {
                    Credential = decisions[i].Credential,
                    QueryRequirementId = decisions[i].QueryRequirementId,
                    SelectedPaths = keptPaths,
                    SatisfiesRequirements = decisions[i].SatisfiesRequirements,
                    Format = decisions[i].Format,
                    Lattice = decisions[i].Lattice
                });
            }

            return Task.FromResult<IReadOnlyList<CredentialDisclosureDecision<string>>>(optimized);
        };
    }


    /// <summary>
    /// Creates a <see cref="DisclosureMatch{TCredential}"/> for testing. In production,
    /// a DCQL evaluator or presentation definition evaluator produces these from an actual
    /// query against the wallet's credential store. Here we construct them directly to
    /// isolate the disclosure computation from query evaluation.
    /// </summary>
    private static DisclosureMatch<string> CreateMatch(
        string credential,
        string requirementId,
        CredentialPath[] required,
        CredentialPath[] available,
        HashSet<CredentialPath>? mandatory = null)
    {
        return new DisclosureMatch<string>
        {
            Credential = credential,
            QueryRequirementId = requirementId,
            RequiredPaths = new HashSet<CredentialPath>(required),
            MatchedPaths = new HashSet<CredentialPath>(available),
            AllAvailablePaths = new HashSet<CredentialPath>(available),
            MandatoryPaths = mandatory
        };
    }
}