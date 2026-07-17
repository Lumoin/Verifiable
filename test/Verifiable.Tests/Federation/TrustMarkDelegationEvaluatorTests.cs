using Verifiable.Core.Assessment;
using Verifiable.JCose;
using Verifiable.OAuth.Federation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Tests for <see cref="TrustMarkDelegationEvaluator"/>.
/// </summary>
[TestClass]
internal sealed class TrustMarkDelegationEvaluatorTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string MarkId = "https://example.test/trust-mark/sirtfi";


    [TestMethod]
    public async Task HappyPathDelegationEmitsSuccess()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));
        using FederationTestRingNode tmOwner = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/tm-owner"));
        using FederationTestRingNode tmIssuer = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/tm-issuer"));

        //TA lists tmOwner in trust_mark_owners.
        Dictionary<string, object> trustMarkOwners = new(StringComparer.Ordinal)
        {
            [tmOwner.Identifier.Value] = new Dictionary<string, object>
            {
                ["jwks"] = tmOwner.JwksObject,
            },
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
                [WellKnownFederationClaimNames.TrustMarkOwners] = trustMarkOwners,
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustChain chain = new()
        {
            Statements = [subjectEc.Statement, anchorAboutSubject.Statement, anchorEc.Statement],
        };

        MintedTrustMarkDelegation delegation = await FederationTestRing.MintTrustMarkDelegationAsync(
            tmOwner, tmIssuer, MarkId, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedTrustMark mark = await FederationTestRing.MintTrustMarkAsync(
            tmIssuer, subject, MarkId, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Claim claim = TrustMarkDelegationEvaluator.Evaluate(
            mark.Mark,
            delegation.Delegation,
            chain,
            delegationSignatureVerified: true,
            now: now,
            clockSkew: TimeSpan.FromMinutes(5));

        Assert.AreEqual(ClaimOutcome.Success, claim.Outcome);
    }


    [TestMethod]
    public async Task DelegationSubjectMismatchFails()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));
        using FederationTestRingNode tmOwner = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/tm-owner"));
        using FederationTestRingNode tmIssuer = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/tm-issuer"));
        using FederationTestRingNode wrongIssuer = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/wrong-issuer"));

        Dictionary<string, object> trustMarkOwners = new(StringComparer.Ordinal)
        {
            [tmOwner.Identifier.Value] = new Dictionary<string, object> { ["jwks"] = tmOwner.JwksObject },
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
                [WellKnownFederationClaimNames.TrustMarkOwners] = trustMarkOwners,
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustChain chain = new()
        {
            Statements = [subjectEc.Statement, anchorAboutSubject.Statement, anchorEc.Statement],
        };

        //Delegation authorizes wrongIssuer; mark signed by tmIssuer.
        MintedTrustMarkDelegation delegation = await FederationTestRing.MintTrustMarkDelegationAsync(
            tmOwner, wrongIssuer, MarkId, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedTrustMark mark = await FederationTestRing.MintTrustMarkAsync(
            tmIssuer, subject, MarkId, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Claim claim = TrustMarkDelegationEvaluator.Evaluate(
            mark.Mark, delegation.Delegation, chain,
            delegationSignatureVerified: true, now: now, clockSkew: TimeSpan.FromMinutes(5));

        Assert.AreEqual(ClaimOutcome.Failure, claim.Outcome);
        TrustMarkDelegationFailureContext ctx = (TrustMarkDelegationFailureContext)claim.Context;
        Assert.AreEqual("DelegationSubjectMismatch", ctx.Reason);
    }


    [TestMethod]
    public async Task OwnerNotInTrustAnchorOwnersFails()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));
        using FederationTestRingNode unregisteredOwner = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/squatter"));
        using FederationTestRingNode tmIssuer = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/tm-issuer"));

        //TA has empty trust_mark_owners.
        Dictionary<string, object> trustMarkOwners = new(StringComparer.Ordinal);

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
                [WellKnownFederationClaimNames.TrustMarkOwners] = trustMarkOwners,
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustChain chain = new()
        {
            Statements = [subjectEc.Statement, anchorAboutSubject.Statement, anchorEc.Statement],
        };

        MintedTrustMarkDelegation delegation = await FederationTestRing.MintTrustMarkDelegationAsync(
            unregisteredOwner, tmIssuer, MarkId, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedTrustMark mark = await FederationTestRing.MintTrustMarkAsync(
            tmIssuer, subject, MarkId, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Claim claim = TrustMarkDelegationEvaluator.Evaluate(
            mark.Mark, delegation.Delegation, chain,
            delegationSignatureVerified: true, now: now, clockSkew: TimeSpan.FromMinutes(5));

        Assert.AreEqual(ClaimOutcome.Failure, claim.Outcome);
        TrustMarkDelegationFailureContext ctx = (TrustMarkDelegationFailureContext)claim.Context;
        Assert.AreEqual("OwnerNotRegistered", ctx.Reason);
    }


    [TestMethod]
    public async Task FutureIssuedDelegationFails()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));
        using FederationTestRingNode tmOwner = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/tm-owner"));
        using FederationTestRingNode tmIssuer = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/tm-issuer"));

        Dictionary<string, object> trustMarkOwners = new(StringComparer.Ordinal)
        {
            [tmOwner.Identifier.Value] = new Dictionary<string, object> { ["jwks"] = tmOwner.JwksObject },
        };

        MintedStatement subjectEc = await FederationTestRing.MintEntityConfigurationAsync(
            subject, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorAboutSubject = await FederationTestRing.MintSubordinateStatementAsync(
            anchor, subject, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorEc = await FederationTestRing.MintEntityConfigurationAsync(
            anchor, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object>
            {
                [WellKnownFederationClaimNames.TrustMarkOwners] = trustMarkOwners,
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustChain chain = new()
        {
            Statements = [subjectEc.Statement, anchorAboutSubject.Statement, anchorEc.Statement],
        };

        //Delegation issued two hours in the future, beyond the five-minute skew — §7.2.2
        //requires the current time to be after the delegation's iat.
        MintedTrustMarkDelegation delegation = await FederationTestRing.MintTrustMarkDelegationAsync(
            tmOwner, tmIssuer, MarkId, now.AddHours(2), now.AddHours(3),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedTrustMark mark = await FederationTestRing.MintTrustMarkAsync(
            tmIssuer, subject, MarkId, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Claim claim = TrustMarkDelegationEvaluator.Evaluate(
            mark.Mark, delegation.Delegation, chain,
            delegationSignatureVerified: true, now: now, clockSkew: TimeSpan.FromMinutes(5));

        Assert.AreEqual(ClaimOutcome.Failure, claim.Outcome);
        TrustMarkDelegationFailureContext ctx = (TrustMarkDelegationFailureContext)claim.Context;
        Assert.AreEqual("DelegationIssuedInFuture", ctx.Reason);
    }


    [TestMethod]
    public void AlgNoneDelegationHeaderIsRejectedByParser()
    {
        //§7.2.2: a delegation with alg=none must be rejected. The parser refuses it before
        //any payload inspection.
        UnverifiedJwtHeader header = new(new Dictionary<string, object>
        {
            [WellKnownJoseHeaderNames.Typ] = WellKnownFederationMediaTypes.TrustMarkDelegationJwt,
            [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.None
        });
        UnverifiedJwtPayload payload = new(new Dictionary<string, object>
        {
            [WellKnownJwtClaimNames.Iss] = "https://example.test/tm-owner",
            [WellKnownJwtClaimNames.Sub] = "https://example.test/tm-issuer",
            [WellKnownFederationClaimNames.TrustMarkType] = MarkId,
            [WellKnownJwtClaimNames.Iat] = 1_700_000_000L
        });

        TrustMarkDelegationParseResult result = TrustMarkDelegationParser.Parse(header, payload);
        Assert.IsNull(result.Delegation, "An alg=none delegation must not parse to a delegation.");
    }
}
