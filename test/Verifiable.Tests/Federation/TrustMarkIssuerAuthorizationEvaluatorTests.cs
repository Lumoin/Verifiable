using Verifiable.Core.Assessment;
using Verifiable.OAuth.Federation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Tests for <see cref="TrustMarkIssuerAuthorizationEvaluator"/>.
/// </summary>
[TestClass]
internal sealed class TrustMarkIssuerAuthorizationEvaluatorTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string MarkId = "https://example.test/trust-mark/sirtfi";


    [TestMethod]
    public async Task AuthorizedIssuerEmitsSuccess()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));
        using FederationTestRingNode tmIssuer = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/tm-issuer"));

        //Trust Anchor declares trust_mark_issuers naming tmIssuer for MarkId.
        Dictionary<string, object> trustMarkIssuers = new(StringComparer.Ordinal)
        {
            [MarkId] = new List<object> { tmIssuer.Identifier.Value },
        };

        MintedStatement subjectEc = await FederationTestRing.MintEntityConfigurationAsync(
            subject, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorAboutSubject = await FederationTestRing.MintSubordinateStatementAsync(
            anchor, subject, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorEc = await FederationTestRing.MintEntityConfigurationAsync(
            anchor, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object>
            {
                [WellKnownFederationClaimNames.TrustMarkIssuers] = trustMarkIssuers,
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustChain chain = new()
        {
            Statements = [subjectEc.Statement, anchorAboutSubject.Statement, anchorEc.Statement],
        };

        MintedTrustMark mark = await FederationTestRing.MintTrustMarkAsync(
            tmIssuer, subject, MarkId, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Claim claim = TrustMarkIssuerAuthorizationEvaluator.Evaluate(mark.Mark, chain);

        Assert.AreEqual(ClaimOutcome.Success, claim.Outcome);
    }


    [TestMethod]
    public async Task UnauthorizedIssuerEmitsFailureWithIssuerNotInList()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));
        using FederationTestRingNode authorizedIssuer = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/authorized"));
        using FederationTestRingNode roguIssuer = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/rogue"));

        //TA lists only the authorized issuer.
        Dictionary<string, object> trustMarkIssuers = new(StringComparer.Ordinal)
        {
            [MarkId] = new List<object> { authorizedIssuer.Identifier.Value },
        };

        MintedStatement subjectEc = await FederationTestRing.MintEntityConfigurationAsync(
            subject, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorAboutSubject = await FederationTestRing.MintSubordinateStatementAsync(
            anchor, subject, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorEc = await FederationTestRing.MintEntityConfigurationAsync(
            anchor, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object>
            {
                [WellKnownFederationClaimNames.TrustMarkIssuers] = trustMarkIssuers,
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustChain chain = new()
        {
            Statements = [subjectEc.Statement, anchorAboutSubject.Statement, anchorEc.Statement],
        };

        //Mark issued by the rogue, not the authorized issuer.
        MintedTrustMark mark = await FederationTestRing.MintTrustMarkAsync(
            roguIssuer, subject, MarkId, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Claim claim = TrustMarkIssuerAuthorizationEvaluator.Evaluate(mark.Mark, chain);

        Assert.AreEqual(ClaimOutcome.Failure, claim.Outcome);
        TrustMarkIssuerAuthorizationContext ctx = (TrustMarkIssuerAuthorizationContext)claim.Context;
        Assert.AreEqual("IssuerNotInList", ctx.Reason);
    }


    [TestMethod]
    public async Task NoTrustMarkIssuersClaimOnAnchorEmitsFailure()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));
        using FederationTestRingNode tmIssuer = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/tm-issuer"));

        //TA has no trust_mark_issuers claim at all.
        MintedChain mintedChain = await FederationTestRing.BuildDirectChainAsync(
            subject, anchor, now, now.AddHours(1),
            TestContext.CancellationToken).ConfigureAwait(false);

        MintedTrustMark mark = await FederationTestRing.MintTrustMarkAsync(
            tmIssuer, subject, MarkId, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Claim claim = TrustMarkIssuerAuthorizationEvaluator.Evaluate(mark.Mark, mintedChain.Chain);

        Assert.AreEqual(ClaimOutcome.Failure, claim.Outcome);
        TrustMarkIssuerAuthorizationContext ctx = (TrustMarkIssuerAuthorizationContext)claim.Context;
        Assert.AreEqual("NoTrustMarkIssuersDeclared", ctx.Reason);
    }
}
