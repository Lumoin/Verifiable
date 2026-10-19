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

        //TA declares tmOwner the owner of the mark type in trust_mark_owners (Federation §3.1.2: keyed by the type, its sub and jwks).
        var trustMarkOwners = OwnersDeclaring(tmOwner);


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

        var trustMarkOwners = OwnersDeclaring(tmOwner);


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
        Assert.AreEqual(TrustMarkDelegationFailureReason.DelegationSubjectMismatch, ctx.Reason);
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
        Assert.AreEqual(TrustMarkDelegationFailureReason.OwnerNotRegistered, ctx.Reason);
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

        var trustMarkOwners = OwnersDeclaring(tmOwner);


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
        Assert.AreEqual(TrustMarkDelegationFailureReason.DelegationIssuedInFuture, ctx.Reason);
    }


    [TestMethod]
    public void AlgNoneDelegationHeaderIsRejectedByParser()
    {
        //§7.2.2: a delegation with alg=none must be rejected. The parser refuses it before
        //any payload inspection.
        UnverifiedJwtHeader header = new()
        {
            [WellKnownJoseHeaderNames.Typ] = WellKnownFederationMediaTypes.TrustMarkDelegationJwt,
            [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.None
        };
        UnverifiedJwtPayload payload = new()
        {
            [WellKnownJwtClaimNames.Iss] = "https://example.test/tm-owner",
            [WellKnownJwtClaimNames.Sub] = "https://example.test/tm-issuer",
            [WellKnownFederationClaimNames.TrustMarkType] = MarkId,
            [WellKnownJwtClaimNames.Iat] = 1_700_000_000L
        };

        TrustMarkDelegationParseResult result = TrustMarkDelegationParser.Parse(header, payload);
        Assert.IsNull(result.Delegation, "An alg=none delegation must not parse to a delegation.");
    }

    /// <summary>
    /// Federation §3.1.2: the Trust Anchor's <c>trust_mark_owners</c> claim is keyed by the Trust Mark type. A claim keyed by the
    /// owner's Entity Identifier declares no owner of the mark's type, and a claim declaring another owner of the type than the
    /// delegation's issuer refuses the delegation as signed by no declared owner.
    /// </summary>
    /// <param name="ownersCase">How the Trust Anchor declares the owners.</param>
    /// <param name="reason">The refusal's reason.</param>
    /// <returns>A task completing once the delegation is evaluated.</returns>
    [TestMethod]
    [DataRow("keyed-by-owner", TrustMarkDelegationFailureReason.OwnerNotRegistered, DisplayName = "Owners keyed by the owner's identifier")]
    [DataRow("another-owner", TrustMarkDelegationFailureReason.OwnerMismatch, DisplayName = "Another owner declared for the type")]
    public async Task TheOwnerIsTheOneDeclaredForTheMarksType(string ownersCase, TrustMarkDelegationFailureReason reason)
    {
        var now = TestClock.CanonicalEpoch;
        using var subject = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/subject"));
        using var anchor = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/anchor"));
        using var tmOwner = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/tm-owner"));
        using var declaredOwner = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/declared-owner"));
        using var tmIssuer = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/tm-issuer"));

        var trustMarkOwners = ownersCase is "keyed-by-owner"
            ? new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [tmOwner.Identifier.Value] = new Dictionary<string, object>(StringComparer.Ordinal) { ["sub"] = tmOwner.Identifier.Value, ["jwks"] = tmOwner.JwksObject }
            }
            : OwnersDeclaring(declaredOwner);

        var subjectEc = await FederationTestRing.MintEntityConfigurationAsync(subject, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        var anchorAboutSubject = await FederationTestRing.MintSubordinateStatementAsync(anchor, subject, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        var anchorEc = await FederationTestRing.MintEntityConfigurationAsync(
            anchor, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object> { [WellKnownFederationClaimNames.TrustMarkOwners] = trustMarkOwners },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var chain = new TrustChain { Statements = [subjectEc.Statement, anchorAboutSubject.Statement, anchorEc.Statement] };

        var delegation = await FederationTestRing.MintTrustMarkDelegationAsync(tmOwner, tmIssuer, MarkId, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        var mark = await FederationTestRing.MintTrustMarkAsync(tmIssuer, subject, MarkId, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var claim = TrustMarkDelegationEvaluator.Evaluate(mark.Mark, delegation.Delegation, chain, delegationSignatureVerified: true, now: now, clockSkew: TimeSpan.FromMinutes(5));

        Assert.AreEqual(ClaimOutcome.Failure, claim.Outcome, ownersCase);
        Assert.AreEqual(reason, ((TrustMarkDelegationFailureContext)claim.Context).Reason, ownersCase);
    }


    /// <summary>The Trust Anchor's <c>trust_mark_owners</c> value declaring the owner given of <see cref="MarkId"/> with its keys.</summary>
    /// <param name="owner">The owner.</param>
    /// <returns>The claim's value.</returns>
    private static Dictionary<string, object> OwnersDeclaring(FederationTestRingNode owner) => new(StringComparer.Ordinal)
    {
        [MarkId] = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["sub"] = owner.Identifier.Value,
            ["jwks"] = owner.JwksObject
        }
    };
}
