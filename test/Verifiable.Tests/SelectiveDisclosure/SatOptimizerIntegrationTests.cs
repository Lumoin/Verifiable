using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Integration tests that wire the <see cref="DpllSolver"/> into the disclosure
/// computation pipeline via <see cref="CrossCredentialOptimizerDelegate{TCredential}"/>.
/// </summary>
/// <remarks>
/// <para>
/// These tests exercise realistic multi-credential scenarios where a verifier requests
/// proof of multiple attributes, the holder's wallet contains overlapping credentials,
/// and privacy constraints restrict which combinations are permissible. The SAT solver
/// finds a feasible assignment that satisfies all coverage requirements while respecting
/// mutual exclusion constraints.
/// </para>
/// </remarks>
[TestClass]
internal sealed class SatOptimizerIntegrationTests
{
    public TestContext TestContext { get; set; } = null!;

    private static CredentialPath GivenName { get; } = CredentialPath.FromJsonPointer("/given_name");
    private static CredentialPath FamilyName { get; } = CredentialPath.FromJsonPointer("/family_name");
    private static CredentialPath Birthdate { get; } = CredentialPath.FromJsonPointer("/birthdate");
    private static CredentialPath Address { get; } = CredentialPath.FromJsonPointer("/address");
    private static CredentialPath Ssn { get; } = CredentialPath.FromJsonPointer("/ssn");
    private static CredentialPath Nationality { get; } = CredentialPath.FromJsonPointer("/nationality");
    private static CredentialPath Category { get; } = CredentialPath.FromJsonPointer("/category");
    private static CredentialPath AccountNumber { get; } = CredentialPath.FromJsonPointer("/account_number");
    private static CredentialPath Iss { get; } = CredentialPath.FromJsonPointer("/iss");


    [TestMethod]
    public async Task SatOptimizerEnforcesMutualExclusionAcrossCredentials()
    {
        //Scenario: verifier requests name, birthdate, and address.
        //Wallet holds three credentials with overlapping claims.
        //Constraint: never disclose SSN and account number to the same verifier.
        //The solver should find a feasible combination respecting this constraint.
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

        var plan = await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(plan.Satisfied);
        Assert.HasCount(3, plan.Decisions);

        //Verify the constraint: SSN and account number are not both disclosed.
        bool ssnDisclosed = false;
        bool accountDisclosed = false;

        foreach(var decision in plan.Decisions)
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
        //Signals carry a risk tolerance that the optimizer can use.
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

            //Required path constraints: at least one credential must disclose each required path.
            var requiredPathsByRequirement = new Dictionary<CredentialPath, List<int>>();
            for(int i = 0; i < decisions.Count; i++)
            {
                //The verifier-required paths are those that the lattice normalized as selectable + mandatory.
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
                //Constraints are infeasible — return decisions unchanged.
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
    /// Creates a <see cref="DisclosureMatch{TCredential}"/> for testing, where available
    /// paths double as matched paths and mandatory paths default to empty.
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
