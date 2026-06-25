using Verifiable.Core.Assessment;
using Verifiable.OAuth.Federation;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Opening invariants for <see cref="TrustChainValidator"/> against chains
/// minted by <see cref="FederationTestRing"/>.
/// </summary>
[TestClass]
internal sealed class TrustChainValidatorTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task HappyPathDirectChainEmitsAllSuccessClaims()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));

        MintedChain minted = await FederationTestRing.BuildDirectChainAsync(
            subject, anchor, now, now.AddHours(1),
            TestContext.CancellationToken).ConfigureAwait(false);

        IReadOnlyList<bool> linkVerified = await VerifyChainAsync(
            minted, subject, anchor, TestContext.CancellationToken).ConfigureAwait(false);

        TrustChainValidationContext context = new()
        {
            Chain = minted.Chain,
            TrustAnchors = [anchor.Identifier],
            LinkSignaturesVerified = linkVerified,
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        TrustChainValidator validator = TrustChainValidator.Default();
        ClaimIssueResult result = await validator.ValidateAsync(
            context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        foreach(bool isVerified in linkVerified)
        {
            Assert.IsTrue(isVerified, "All three chain signatures should verify under happy-path keys.");
        }

        Assert.HasCount(8, result.Claims, "Chain profile emits 8 claims for codes 1120-1127.");
        foreach(Claim claim in result.Claims)
        {
            Assert.AreEqual(ClaimOutcome.Success, claim.Outcome,
                $"Happy-path chain claim {claim.Id} should succeed, got {claim.Outcome}.");
        }
    }


    [TestMethod]
    public async Task WrongAnchorFailsChainTerminatesAtTrustAnchor()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));

        MintedChain minted = await FederationTestRing.BuildDirectChainAsync(
            subject, anchor, now, now.AddHours(1),
            TestContext.CancellationToken).ConfigureAwait(false);

        IReadOnlyList<bool> linkVerified = await VerifyChainAsync(
            minted, subject, anchor, TestContext.CancellationToken).ConfigureAwait(false);

        //The application's trust-anchor allow-list names a different entity.
        EntityIdentifier wrongAnchor = new("https://example.test/different-anchor");

        TrustChainValidationContext context = new()
        {
            Chain = minted.Chain,
            TrustAnchors = [wrongAnchor],
            LinkSignaturesVerified = linkVerified,
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        TrustChainValidator validator = TrustChainValidator.Default();
        ClaimIssueResult result = await validator.ValidateAsync(
            context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim anchorClaim = result.Claims.Single(c =>
            c.Id.Code == WellKnownFederationClaimIds.ChainTerminatesAtTrustAnchor.Code);
        Assert.AreEqual(ClaimOutcome.Failure, anchorClaim.Outcome,
            "ChainTerminatesAtTrustAnchor should fail when the chain's terminal issuer is not in the allow-list.");

        //All other chain claims should still succeed.
        int failures = result.Claims.Count(c => c.Outcome == ClaimOutcome.Failure);
        Assert.AreEqual(1, failures,
            "Only ChainTerminatesAtTrustAnchor should fail in the wrong-anchor case.");
    }


    [TestMethod]
    public async Task TamperedLinkFailsChainAllLinksVerified()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));

        MintedChain minted = await FederationTestRing.BuildDirectChainAsync(
            subject, anchor, now, now.AddHours(1),
            TestContext.CancellationToken).ConfigureAwait(false);

        //Simulate a tampered link by forcing position 1's verify outcome to false.
        bool[] linkVerified = [true, false, true];

        TrustChainValidationContext context = new()
        {
            Chain = minted.Chain,
            TrustAnchors = [anchor.Identifier],
            LinkSignaturesVerified = linkVerified,
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        TrustChainValidator validator = TrustChainValidator.Default();
        ClaimIssueResult result = await validator.ValidateAsync(
            context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim linksClaim = result.Claims.Single(c =>
            c.Id.Code == WellKnownFederationClaimIds.ChainAllLinksVerified.Code);
        Assert.AreEqual(ClaimOutcome.Failure, linksClaim.Outcome,
            "ChainAllLinksVerified should fail when any positional verify outcome is false.");
    }


    [TestMethod]
    public async Task ChainNotStartingWithSubjectEntityConfigurationFailsChainStartsAtSubject()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));

        MintedChain minted = await FederationTestRing.BuildDirectChainAsync(
            subject, anchor, now, now.AddHours(1), TestContext.CancellationToken).ConfigureAwait(false);

        //Reorder so position 0 is the anchor's Subordinate Statement (iss != sub) rather
        //than the subject's self-issued Entity Configuration. §10.1 requires the chain to
        //start at the subject's EC.
        TrustChain reordered = new()
        {
            Statements =
            [
                minted.Chain.Statements[1],
                minted.Chain.Statements[0],
                minted.Chain.Statements[2],
            ]
        };

        TrustChainValidationContext context = new()
        {
            Chain = reordered,
            TrustAnchors = [anchor.Identifier],
            LinkSignaturesVerified = [true, true, true],
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        ClaimIssueResult result = await TrustChainValidator.Default().ValidateAsync(
            context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim starts = result.Claims.Single(c => c.Id.Code == WellKnownFederationClaimIds.ChainStartsAtSubject.Code);
        Assert.AreEqual(ClaimOutcome.Failure, starts.Outcome,
            "A chain whose position 0 is not the subject's Entity Configuration must fail ChainStartsAtSubject.");
    }


    [TestMethod]
    public async Task ChainWithRepeatedSubordinateStatementFailsChainNoCycles()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));

        MintedChain minted = await FederationTestRing.BuildDirectChainAsync(
            subject, anchor, now, now.AddHours(1), TestContext.CancellationToken).ConfigureAwait(false);

        //Duplicate the anchor's Subordinate Statement: a non-self-issued statement whose
        //(iss, sub) pair repeats is a cycle per §10.2.
        TrustChain withCycle = new()
        {
            Statements =
            [
                minted.Chain.Statements[0],
                minted.Chain.Statements[1],
                minted.Chain.Statements[1],
                minted.Chain.Statements[2],
            ]
        };

        TrustChainValidationContext context = new()
        {
            Chain = withCycle,
            TrustAnchors = [anchor.Identifier],
            LinkSignaturesVerified = [true, true, true, true],
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        ClaimIssueResult result = await TrustChainValidator.Default().ValidateAsync(
            context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim noCycles = result.Claims.Single(c => c.Id.Code == WellKnownFederationClaimIds.ChainNoCycles.Code);
        Assert.AreEqual(ClaimOutcome.Failure, noCycles.Outcome,
            "A repeated non-self-issued (iss, sub) pair must fail ChainNoCycles.");
    }


    [TestMethod]
    public async Task ChainExceedingMaxPathLengthFailsChainWithinMaxPathLength()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode intermediate = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/intermediate"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));

        //The anchor's Subordinate Statement about the intermediate constrains
        //max_path_length=0 (no intermediates permitted below it), yet the chain carries an
        //intermediate — §6.2 violation.
        Dictionary<string, object> zeroPathLength = new()
        {
            [WellKnownFederationClaimNames.Constraints] = new Dictionary<string, object>
            {
                [WellKnownFederationClaimNames.MaxPathLength] = 0
            }
        };

        MintedChain minted = await FederationTestRing.BuildChainWithIntermediateAsync(
            subject, intermediate, anchor, now, now.AddHours(1),
            anchorAboutIntermediateExtraClaims: zeroPathLength,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustChainValidationContext context = new()
        {
            Chain = minted.Chain,
            TrustAnchors = [anchor.Identifier],
            LinkSignaturesVerified = [true, true, true, true, true],
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        ClaimIssueResult result = await TrustChainValidator.Default().ValidateAsync(
            context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim maxPath = result.Claims.Single(c => c.Id.Code == WellKnownFederationClaimIds.ChainWithinMaxPathLength.Code);
        Assert.AreEqual(ClaimOutcome.Failure, maxPath.Outcome,
            "An intermediate below a max_path_length=0 constraint must fail ChainWithinMaxPathLength.");
    }


    [TestMethod]
    public async Task ChainWithExpiredLinkFailsChainExpIsMinOfLinks()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));

        //The subject EC and anchor EC are fresh, but the anchor's Subordinate Statement
        //expired an hour ago. The chain's effective expiry is the minimum across links
        //(§10.4), so the whole chain is expired.
        MintedStatement subjectEc = await FederationTestRing.MintEntityConfigurationAsync(
            subject, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorAboutSubject = await FederationTestRing.MintSubordinateStatementAsync(
            anchor, subject, now.AddHours(-2), now.AddHours(-1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorEc = await FederationTestRing.MintEntityConfigurationAsync(
            anchor, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustChain chain = new()
        {
            Statements = [subjectEc.Statement, anchorAboutSubject.Statement, anchorEc.Statement]
        };

        TrustChainValidationContext context = new()
        {
            Chain = chain,
            TrustAnchors = [anchor.Identifier],
            LinkSignaturesVerified = [true, true, true],
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        ClaimIssueResult result = await TrustChainValidator.Default().ValidateAsync(
            context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim expMin = result.Claims.Single(c => c.Id.Code == WellKnownFederationClaimIds.ChainExpIsMinOfLinks.Code);
        Assert.AreEqual(ClaimOutcome.Failure, expMin.Outcome,
            "An expired link must drag the chain's effective (minimum) expiry into the past and fail ChainExpIsMinOfLinks.");
    }


    [TestMethod]
    public async Task SubordinateHostWithinPermittedSubtreeSatisfiesNamingConstraints()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        //Subject host leaf.example.test is within the permitted ".example.test" subtree.
        Dictionary<string, object> permittedSubtree = new()
        {
            ["permitted"] = new List<object> { ".example.test" }
        };

        (TrustChain chain, EntityIdentifier anchor) = await BuildChainWithSubjectNamingConstraintsAsync(
            "https://leaf.example.test/wallet", permittedSubtree, now).ConfigureAwait(false);

        Claim naming = await EvaluateNamingConstraintsAsync(chain, anchor, now).ConfigureAwait(false);
        Assert.AreEqual(ClaimOutcome.Success, naming.Outcome,
            "A subordinate host within the permitted subtree must satisfy ChainSatisfiesNamingConstraints.");
    }


    [TestMethod]
    public async Task ExcludedSubordinateHostFailsNamingConstraints()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        //Subject host leaf.example.test matches the excluded ".example.test" subtree —
        //invalid regardless of any permitted entry (§6.2.2).
        Dictionary<string, object> excludedSubtree = new()
        {
            ["excluded"] = new List<object> { ".example.test" }
        };

        (TrustChain chain, EntityIdentifier anchor) = await BuildChainWithSubjectNamingConstraintsAsync(
            "https://leaf.example.test/wallet", excludedSubtree, now).ConfigureAwait(false);

        Claim naming = await EvaluateNamingConstraintsAsync(chain, anchor, now).ConfigureAwait(false);
        Assert.AreEqual(ClaimOutcome.Failure, naming.Outcome,
            "A subordinate host matching an excluded subtree must fail ChainSatisfiesNamingConstraints.");
    }


    [TestMethod]
    public async Task SubordinateHostOutsidePermittedFailsNamingConstraints()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        //Subject host leaf.other.test is outside the only permitted subtree.
        Dictionary<string, object> permittedSubtree = new()
        {
            ["permitted"] = new List<object> { ".example.test" }
        };

        (TrustChain chain, EntityIdentifier anchor) = await BuildChainWithSubjectNamingConstraintsAsync(
            "https://leaf.other.test/wallet", permittedSubtree, now).ConfigureAwait(false);

        Claim naming = await EvaluateNamingConstraintsAsync(chain, anchor, now).ConfigureAwait(false);
        Assert.AreEqual(ClaimOutcome.Failure, naming.Outcome,
            "A subordinate host outside every permitted subtree must fail ChainSatisfiesNamingConstraints.");
    }


    /// <summary>
    /// Builds a direct chain [subject EC, anchor's SS-about-subject, anchor EC] where the
    /// Subordinate Statement carries the given <c>naming_constraints</c> value. Signatures
    /// are not re-verified by the naming-constraints check, so the minted statements suffice.
    /// </summary>
    private async ValueTask<(TrustChain Chain, EntityIdentifier Anchor)> BuildChainWithSubjectNamingConstraintsAsync(
        string subjectId, Dictionary<string, object> namingConstraintsValue, DateTimeOffset now)
    {
        using FederationTestRingNode subject = FederationTestRing.CreateNode(new EntityIdentifier(subjectId));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://anchor.example.org"));

        Dictionary<string, object> ssConstraints = new()
        {
            [WellKnownFederationClaimNames.Constraints] = new Dictionary<string, object>
            {
                [WellKnownFederationClaimNames.NamingConstraints] = namingConstraintsValue
            }
        };

        MintedStatement subjectEc = await FederationTestRing.MintEntityConfigurationAsync(
            subject, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorAboutSubject = await FederationTestRing.MintSubordinateStatementAsync(
            anchor, subject, now, now.AddHours(1), ssConstraints, TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorEc = await FederationTestRing.MintEntityConfigurationAsync(
            anchor, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustChain chain = new()
        {
            Statements = [subjectEc.Statement, anchorAboutSubject.Statement, anchorEc.Statement]
        };

        return (chain, anchor.Identifier);
    }


    /// <summary>
    /// Runs the trust-chain validator and returns the ChainSatisfiesNamingConstraints claim.
    /// </summary>
    private async ValueTask<Claim> EvaluateNamingConstraintsAsync(
        TrustChain chain, EntityIdentifier anchor, DateTimeOffset now)
    {
        TrustChainValidationContext context = new()
        {
            Chain = chain,
            TrustAnchors = [anchor],
            LinkSignaturesVerified = [true, true, true],
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        ClaimIssueResult result = await TrustChainValidator.Default().ValidateAsync(
            context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        return result.Claims.Single(c => c.Id.Code == WellKnownFederationClaimIds.ChainSatisfiesNamingConstraints.Code);
    }


    [TestMethod]
    public async Task ChainWithBrokenAdjacencyFailsChainProperlyLinked()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode other = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/other"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));

        //Position 1 is the anchor's Subordinate Statement about a DIFFERENT entity (other),
        //so Statements[0].iss (subject) != Statements[1].sub (other) — the chain does not
        //form a single path from subject to anchor (§10.2 step "ES[j].iss == ES[j+1].sub").
        MintedStatement subjectEc = await FederationTestRing.MintEntityConfigurationAsync(
            subject, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorAboutOther = await FederationTestRing.MintSubordinateStatementAsync(
            anchor, other, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorEc = await FederationTestRing.MintEntityConfigurationAsync(
            anchor, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustChain chain = new()
        {
            Statements = [subjectEc.Statement, anchorAboutOther.Statement, anchorEc.Statement]
        };

        TrustChainValidationContext context = new()
        {
            Chain = chain,
            TrustAnchors = [anchor.Identifier],
            LinkSignaturesVerified = [true, true, true],
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        ClaimIssueResult result = await TrustChainValidator.Default().ValidateAsync(
            context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim linked = result.Claims.Single(c => c.Id.Code == WellKnownFederationClaimIds.ChainProperlyLinked.Code);
        Assert.AreEqual(ClaimOutcome.Failure, linked.Outcome,
            "A chain whose adjacent iss/sub do not match must fail ChainProperlyLinked, even with all signatures verified.");
    }


    //Helper: re-verifies every position's signature against the node that
    //signed it. Position 0 (subject EC) self-signed by subject; positions
    //1 and 2 signed by anchor.
    private static async ValueTask<IReadOnlyList<bool>> VerifyChainAsync(
        MintedChain minted,
        FederationTestRingNode subject,
        FederationTestRingNode anchor,
        CancellationToken cancellationToken)
    {
        bool[] outcomes = new bool[minted.CompactJwsByPosition.Count];
        outcomes[0] = await FederationTestRing.VerifyAsync(
            subject, minted.CompactJwsByPosition[0], cancellationToken).ConfigureAwait(false);
        outcomes[1] = await FederationTestRing.VerifyAsync(
            anchor, minted.CompactJwsByPosition[1], cancellationToken).ConfigureAwait(false);
        outcomes[2] = await FederationTestRing.VerifyAsync(
            anchor, minted.CompactJwsByPosition[2], cancellationToken).ConfigureAwait(false);
        return outcomes;
    }
}
