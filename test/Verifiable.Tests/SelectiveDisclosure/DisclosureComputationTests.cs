using Verifiable.Core.SelectiveDisclosure;

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

        var plan = await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(plan.Satisfied);
        Assert.HasCount(1, plan.Decisions);
        Assert.IsTrue(plan.Decisions[0].SatisfiesRequirements);
        Assert.Contains(GivenName, plan.Decisions[0].SelectedPaths);
        Assert.Contains(FamilyName, plan.Decisions[0].SelectedPaths);
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

        var plan = await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(plan.Satisfied);
        var selected = plan.Decisions[0].SelectedPaths;

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

        var plan = await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(plan.Satisfied);
        var selected = plan.Decisions[0].SelectedPaths;

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

        var plan = await computation.ComputeAsync(matches, exclusions,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(plan.Satisfied);
        var decision = plan.Decisions[0];

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

        var plan = await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(plan.Satisfied);
        Assert.IsEmpty(plan.Decisions);
        Assert.IsNotNull(plan.UnsatisfiedRequirements);
        Assert.Contains("req-1", plan.UnsatisfiedRequirements!);
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

        var plan = await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(plan.Satisfied);
        var selected = plan.Decisions[0].SelectedPaths;

        Assert.Contains(GivenName, selected);
        Assert.DoesNotContain(FamilyName, selected);

        //Policy narrowed below verifier requirements.
        Assert.IsFalse(plan.Decisions[0].SatisfiesRequirements);
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

        var plan = await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var record = plan.DecisionRecord;

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

        var plan = await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var latticeRecord = plan.DecisionRecord.LatticeComputations[0];

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

        var plan = await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(plan.DecisionRecord.PolicyAssessments);
        Assert.HasCount(1, plan.DecisionRecord.PolicyAssessments!);

        var assessment = plan.DecisionRecord.PolicyAssessments[0];
        Assert.AreEqual("TestAssessor", assessment.AssessorName);
        Assert.IsTrue(assessment.Approved);
        Assert.AreEqual("Approved for testing.", assessment.Reason);
    }


    [TestMethod]
    public async Task EmptyMatchListProducesUnsatisfiedPlan()
    {
        var computation = new DisclosureComputation<string>();

        var plan = await computation.ComputeAsync([],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(plan.Satisfied);
        Assert.IsEmpty(plan.Decisions);
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

        var plan = await computation.ComputeAsync(matches,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(plan.Decisions[0].Lattice);
        Assert.Contains(GivenName, plan.Decisions[0].Lattice!.Top);
        Assert.Contains(FamilyName, plan.Decisions[0].Lattice!.Top);
    }

    
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