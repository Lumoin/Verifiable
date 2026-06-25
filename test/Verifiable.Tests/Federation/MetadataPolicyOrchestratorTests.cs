using Verifiable.Core.Assessment;
using Verifiable.OAuth.Federation;

namespace Verifiable.Tests.Federation;

/// <summary>
/// End-to-end tests for <see cref="MetadataPolicyOrchestrator"/> against
/// <see cref="FederationTestRing"/>-minted chains.
/// </summary>
[TestClass]
internal sealed class MetadataPolicyOrchestratorTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly EntityTypeIdentifier RpType =
        WellKnownEntityTypeIdentifiers.OpenIdRelyingParty;


    [TestMethod]
    public async Task ChainWithNoMetadataEmitsNoClaims()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));

        MintedChain chain = await FederationTestRing.BuildDirectChainAsync(
            subject, anchor, now, now.AddHours(1),
            TestContext.CancellationToken).ConfigureAwait(false);

        ClaimIssueResult result = await MetadataPolicyOrchestrator.RunAsync(
            chain.Chain,
            FederationDefaultHooks.EvaluateMetadataPolicy,
            FederationDefaultHooks.ApplyMetadataPolicy,
            TimeProvider.System,
            "test-correlation",
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, result.Claims,
            "No metadata declared, no crit claims → just the vacuously-Success crit check.");
        Claim critClaim = result.Claims.Single();
        Assert.AreEqual(WellKnownFederationClaimIds.MetadataPolicyCritOperatorsUnderstood.Code, critClaim.Id.Code);
        Assert.AreEqual(ClaimOutcome.Success, critClaim.Outcome);
        Assert.AreEqual(ClaimIssueCompletionStatus.Complete, result.CompletionStatus);
    }


    [TestMethod]
    public async Task SubjectMetadataPlusEmptyPolicyEmitsSuccessClaims()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));

        //Subject declares metadata for openid_relying_party but no statement carries
        //any metadata_policy — the merged policy is empty; evaluator returns Success;
        //applicator returns declared metadata unchanged.
        Dictionary<string, object> subjectMetadata = new()
        {
            [RpType.Value] = new Dictionary<string, object>
            {
                ["scope"] = "openid profile",
            },
        };

        MintedStatement subjectEc = await FederationTestRing.MintEntityConfigurationAsync(
            subject, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object>
            {
                [WellKnownFederationClaimNames.Metadata] = subjectMetadata,
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorAboutSubject = await FederationTestRing.MintSubordinateStatementAsync(
            anchor, subject, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorEc = await FederationTestRing.MintEntityConfigurationAsync(
            anchor, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustChain trustChain = new()
        {
            Statements = [subjectEc.Statement, anchorAboutSubject.Statement, anchorEc.Statement],
        };

        ClaimIssueResult result = await MetadataPolicyOrchestrator.RunAsync(
            trustChain,
            FederationDefaultHooks.EvaluateMetadataPolicy,
            FederationDefaultHooks.ApplyMetadataPolicy,
            TimeProvider.System,
            "test-correlation",
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(3, result.Claims,
            "One declared entity type → one 1140 + one 1141 + the standing 1143 crit check.");
        foreach(Claim claim in result.Claims)
        {
            Assert.AreEqual(ClaimOutcome.Success, claim.Outcome,
                $"Empty policy + declared metadata + no crit operators should produce success for {claim.Id}.");
        }
    }


    [TestMethod]
    public async Task AnchorPolicyConstrainsSubjectDeclaredMetadataSuccessfully()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));

        Dictionary<string, object> subjectMetadata = new()
        {
            [RpType.Value] = new Dictionary<string, object>
            {
                ["grant_types"] = new List<object> { "authorization_code" },
            },
        };

        //Subordinate statement carries a metadata_policy for openid_relying_party
        //that constrains grant_types to a subset that includes "authorization_code".
        Dictionary<string, object> anchorPolicy = new()
        {
            [RpType.Value] = new Dictionary<string, object>
            {
                ["grant_types"] = new Dictionary<string, object>
                {
                    ["subset_of"] = new List<object> { "authorization_code", "refresh_token" },
                },
            },
        };

        MintedStatement subjectEc = await FederationTestRing.MintEntityConfigurationAsync(
            subject, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object>
            {
                [WellKnownFederationClaimNames.Metadata] = subjectMetadata,
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorAboutSubject = await FederationTestRing.MintSubordinateStatementAsync(
            anchor, subject, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object>
            {
                [WellKnownFederationClaimNames.MetadataPolicy] = anchorPolicy,
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorEc = await FederationTestRing.MintEntityConfigurationAsync(
            anchor, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustChain trustChain = new()
        {
            Statements = [subjectEc.Statement, anchorAboutSubject.Statement, anchorEc.Statement],
        };

        ClaimIssueResult result = await MetadataPolicyOrchestrator.RunAsync(
            trustChain,
            FederationDefaultHooks.EvaluateMetadataPolicy,
            FederationDefaultHooks.ApplyMetadataPolicy,
            TimeProvider.System,
            "test-correlation",
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(3, result.Claims);
        Claim combinationClaim = result.Claims.Single(c =>
            c.Id.Code == WellKnownFederationClaimIds.MetadataPolicyOperatorCombinationLegal.Code);
        Claim applyClaim = result.Claims.Single(c =>
            c.Id.Code == WellKnownFederationClaimIds.MetadataPolicyAppliedCleanly.Code);
        Assert.AreEqual(ClaimOutcome.Success, combinationClaim.Outcome);
        Assert.AreEqual(ClaimOutcome.Success, applyClaim.Outcome);
    }


    [TestMethod]
    public async Task AnchorPolicyConstraintViolationFailsApplyClaim()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));

        //Subject declares grant_types=[authorization_code]; anchor's policy requires
        //superset_of [authorization_code, refresh_token], which the subject does not
        //satisfy. Apply fails (§6.1.3.1.6).
        Dictionary<string, object> subjectMetadata = new()
        {
            [RpType.Value] = new Dictionary<string, object>
            {
                ["grant_types"] = new List<object> { "authorization_code" },
            },
        };
        Dictionary<string, object> anchorPolicy = new()
        {
            [RpType.Value] = new Dictionary<string, object>
            {
                ["grant_types"] = new Dictionary<string, object>
                {
                    ["superset_of"] = new List<object> { "authorization_code", "refresh_token" },
                },
            },
        };

        MintedStatement subjectEc = await FederationTestRing.MintEntityConfigurationAsync(
            subject, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object>
            {
                [WellKnownFederationClaimNames.Metadata] = subjectMetadata,
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorAboutSubject = await FederationTestRing.MintSubordinateStatementAsync(
            anchor, subject, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object>
            {
                [WellKnownFederationClaimNames.MetadataPolicy] = anchorPolicy,
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorEc = await FederationTestRing.MintEntityConfigurationAsync(
            anchor, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustChain trustChain = new()
        {
            Statements = [subjectEc.Statement, anchorAboutSubject.Statement, anchorEc.Statement],
        };

        ClaimIssueResult result = await MetadataPolicyOrchestrator.RunAsync(
            trustChain,
            FederationDefaultHooks.EvaluateMetadataPolicy,
            FederationDefaultHooks.ApplyMetadataPolicy,
            TimeProvider.System,
            "test-correlation",
            TestContext.CancellationToken).ConfigureAwait(false);

        Claim applyClaim = result.Claims.Single(c =>
            c.Id.Code == WellKnownFederationClaimIds.MetadataPolicyAppliedCleanly.Code);
        Assert.AreEqual(ClaimOutcome.Failure, applyClaim.Outcome,
            "Subject's grant_types is missing a value the anchor's superset_of requires.");
    }


    [TestMethod]
    public async Task MergeConflictBetweenStatementsEmitsFailureAndNotApplicable()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode intermediate = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/intermediate"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));

        Dictionary<string, object> subjectMetadata = new()
        {
            [RpType.Value] = new Dictionary<string, object>
            {
                ["scope"] = "openid",
            },
        };

        //Anchor demands value='openid'; intermediate demands value='profile'. Merge conflicts.
        Dictionary<string, object> anchorPolicy = new()
        {
            [RpType.Value] = new Dictionary<string, object>
            {
                ["scope"] = new Dictionary<string, object> { ["value"] = "openid" },
            },
        };
        Dictionary<string, object> intermediatePolicy = new()
        {
            [RpType.Value] = new Dictionary<string, object>
            {
                ["scope"] = new Dictionary<string, object> { ["value"] = "profile" },
            },
        };

        MintedStatement subjectEc = await FederationTestRing.MintEntityConfigurationAsync(
            subject, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object>
            {
                [WellKnownFederationClaimNames.Metadata] = subjectMetadata,
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement intermediateAboutSubject = await FederationTestRing.MintSubordinateStatementAsync(
            intermediate, subject, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object>
            {
                [WellKnownFederationClaimNames.MetadataPolicy] = intermediatePolicy,
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorAboutIntermediate = await FederationTestRing.MintSubordinateStatementAsync(
            anchor, intermediate, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object>
            {
                [WellKnownFederationClaimNames.MetadataPolicy] = anchorPolicy,
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorEc = await FederationTestRing.MintEntityConfigurationAsync(
            anchor, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustChain trustChain = new()
        {
            Statements =
            [
                subjectEc.Statement,
                intermediateAboutSubject.Statement,
                anchorAboutIntermediate.Statement,
                anchorEc.Statement,
            ],
        };

        ClaimIssueResult result = await MetadataPolicyOrchestrator.RunAsync(
            trustChain,
            FederationDefaultHooks.EvaluateMetadataPolicy,
            FederationDefaultHooks.ApplyMetadataPolicy,
            TimeProvider.System,
            "test-correlation",
            TestContext.CancellationToken).ConfigureAwait(false);

        Claim combinationClaim = result.Claims.Single(c =>
            c.Id.Code == WellKnownFederationClaimIds.MetadataPolicyOperatorCombinationLegal.Code);
        Claim applyClaim = result.Claims.Single(c =>
            c.Id.Code == WellKnownFederationClaimIds.MetadataPolicyAppliedCleanly.Code);
        Assert.AreEqual(ClaimOutcome.Failure, combinationClaim.Outcome,
            "Conflicting value across statements should surface as 1140 Failure.");
        Assert.AreEqual(ClaimOutcome.NotApplicable, applyClaim.Outcome,
            "When merge fails, apply is NotApplicable.");
    }


    [TestMethod]
    public async Task KnownCriticalOperatorsPassCritCheck()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));

        //Anchor's SS lists 'subset_of' and 'one_of' in metadata_policy_crit — both
        //are library-known operators on WellKnownMetadataPolicyOperators. The crit
        //check succeeds.
        Dictionary<string, object> anchorCritList = new()
        {
            //metadata_policy_crit is a top-level claim; not nested under entity types.
        };

        MintedStatement subjectEc = await FederationTestRing.MintEntityConfigurationAsync(
            subject, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorAboutSubject = await FederationTestRing.MintSubordinateStatementAsync(
            anchor, subject, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object>
            {
                [WellKnownFederationClaimNames.MetadataPolicyCrit] = new List<object> { "subset_of", "one_of" },
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorEc = await FederationTestRing.MintEntityConfigurationAsync(
            anchor, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustChain trustChain = new()
        {
            Statements = [subjectEc.Statement, anchorAboutSubject.Statement, anchorEc.Statement],
        };

        ClaimIssueResult result = await MetadataPolicyOrchestrator.RunAsync(
            trustChain,
            FederationDefaultHooks.EvaluateMetadataPolicy,
            FederationDefaultHooks.ApplyMetadataPolicy,
            TimeProvider.System,
            "test-correlation",
            TestContext.CancellationToken).ConfigureAwait(false);

        Claim critClaim = result.Claims.Single(c =>
            c.Id.Code == WellKnownFederationClaimIds.MetadataPolicyCritOperatorsUnderstood.Code);
        Assert.AreEqual(ClaimOutcome.Success, critClaim.Outcome);
    }


    [TestMethod]
    public async Task UnknownCriticalOperatorFailsCritCheck()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));

        MintedStatement subjectEc = await FederationTestRing.MintEntityConfigurationAsync(
            subject, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorAboutSubject = await FederationTestRing.MintSubordinateStatementAsync(
            anchor, subject, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object>
            {
                //"urn:example:future_operator" isn't on WellKnownMetadataPolicyOperators
                //and the library has no registration channel for extensions yet, so it
                //surfaces as Unknown. "subset_of" is known and passes silently.
                [WellKnownFederationClaimNames.MetadataPolicyCrit] = new List<object>
                {
                    "subset_of",
                    "urn:example:future_operator",
                },
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorEc = await FederationTestRing.MintEntityConfigurationAsync(
            anchor, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustChain trustChain = new()
        {
            Statements = [subjectEc.Statement, anchorAboutSubject.Statement, anchorEc.Statement],
        };

        ClaimIssueResult result = await MetadataPolicyOrchestrator.RunAsync(
            trustChain,
            FederationDefaultHooks.EvaluateMetadataPolicy,
            FederationDefaultHooks.ApplyMetadataPolicy,
            TimeProvider.System,
            "test-correlation",
            TestContext.CancellationToken).ConfigureAwait(false);

        Claim critClaim = result.Claims.Single(c =>
            c.Id.Code == WellKnownFederationClaimIds.MetadataPolicyCritOperatorsUnderstood.Code);
        Assert.AreEqual(ClaimOutcome.Failure, critClaim.Outcome);

        MetadataPolicyCritFailureContext ctx = (MetadataPolicyCritFailureContext)critClaim.Context;
        Assert.HasCount(1, ctx.UnknownOperators,
            "Only the extension operator should surface as unknown.");
        Assert.AreEqual("urn:example:future_operator", ctx.UnknownOperators[0].Value);
    }
}
