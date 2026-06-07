using Verifiable.Core.Assessment;
using Verifiable.OAuth.Federation;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Opening invariants for the standalone trust mark validator (1170 + 1172).
/// </summary>
[TestClass]
internal sealed class TrustMarkValidatorTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string MarkId = "https://example.test/trust-mark/sirtfi";


    [TestMethod]
    public async Task HappyPathTrustMarkEmitsBothSuccess()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode issuer = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/tm-issuer"));
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));

        MintedTrustMark minted = await FederationTestRing.MintTrustMarkAsync(
            issuer, subject, MarkId, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        bool signatureVerified = await FederationTestRing.VerifyAsync(
            issuer, minted.CompactJws, TestContext.CancellationToken).ConfigureAwait(false);

        TrustMarkValidationContext context = new()
        {
            Header = minted.Header,
            Mark = minted.Mark,
            SignatureVerified = signatureVerified,
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        ClaimIssueResult result = await TrustMarkValidator.Default()
            .ValidateAsync(context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(3, result.Claims);
        foreach(Claim claim in result.Claims)
        {
            Assert.AreEqual(ClaimOutcome.Success, claim.Outcome,
                $"Happy-path mark should succeed for {claim.Id}.");
        }
    }


    [TestMethod]
    public async Task ExpiredTrustMarkFailsExpInFuture()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode issuer = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/tm-issuer"));
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));

        MintedTrustMark minted = await FederationTestRing.MintTrustMarkAsync(
            issuer, subject, MarkId, now.AddHours(-2), now.AddHours(-1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        bool signatureVerified = await FederationTestRing.VerifyAsync(
            issuer, minted.CompactJws, TestContext.CancellationToken).ConfigureAwait(false);

        TrustMarkValidationContext context = new()
        {
            Header = minted.Header,
            Mark = minted.Mark,
            SignatureVerified = signatureVerified,
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        ClaimIssueResult result = await TrustMarkValidator.Default()
            .ValidateAsync(context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim expClaim = result.Claims.Single(c =>
            c.Id.Code == WellKnownFederationClaimIds.TrustMarkExpInFuture.Code);
        Assert.AreEqual(ClaimOutcome.Failure, expClaim.Outcome);
    }


    [TestMethod]
    public async Task TrustMarkWithExpiryAtOrBeforeIssuanceFailsExpAfterIat()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode issuer = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/tm-issuer"));
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));

        //exp one minute BEFORE iat — still in the future, so only the mutual-consistency
        //check (TrustMarkExpAfterIat) fails, not TrustMarkExpInFuture.
        MintedTrustMark minted = await FederationTestRing.MintTrustMarkAsync(
            issuer, subject, MarkId, now.AddMinutes(1), now,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        bool signatureVerified = await FederationTestRing.VerifyAsync(
            issuer, minted.CompactJws, TestContext.CancellationToken).ConfigureAwait(false);

        TrustMarkValidationContext context = new()
        {
            Header = minted.Header,
            Mark = minted.Mark,
            SignatureVerified = signatureVerified,
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        ClaimIssueResult result = await TrustMarkValidator.Default()
            .ValidateAsync(context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim expAfterIat = result.Claims.Single(c =>
            c.Id.Code == WellKnownFederationClaimIds.TrustMarkExpAfterIat.Code);
        Assert.AreEqual(ClaimOutcome.Failure, expAfterIat.Outcome,
            "exp at or before iat must fail TrustMarkExpAfterIat.");

        Claim expInFuture = result.Claims.Single(c =>
            c.Id.Code == WellKnownFederationClaimIds.TrustMarkExpInFuture.Code);
        Assert.AreEqual(ClaimOutcome.Success, expInFuture.Outcome,
            "exp is still in the future; only the mutual-consistency check should fail.");
    }


    [TestMethod]
    public async Task IndefiniteValidityMarkEmitsNotApplicableForExp()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode issuer = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/tm-issuer"));
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));

        //§7.1.1 permits trust marks without exp — indefinite validity.
        MintedTrustMark minted = await FederationTestRing.MintTrustMarkAsync(
            issuer, subject, MarkId, now, expiresAt: null,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustMarkValidationContext context = new()
        {
            Header = minted.Header,
            Mark = minted.Mark,
            SignatureVerified = true,
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        ClaimIssueResult result = await TrustMarkValidator.Default()
            .ValidateAsync(context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim expClaim = result.Claims.Single(c =>
            c.Id.Code == WellKnownFederationClaimIds.TrustMarkExpInFuture.Code);
        Assert.AreEqual(ClaimOutcome.NotApplicable, expClaim.Outcome);
    }


    [TestMethod]
    public async Task TamperedSignatureFailsSignatureVerifies()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode issuer = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/tm-issuer"));
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));

        MintedTrustMark minted = await FederationTestRing.MintTrustMarkAsync(
            issuer, subject, MarkId, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustMarkValidationContext context = new()
        {
            Header = minted.Header,
            Mark = minted.Mark,
            SignatureVerified = false,
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        ClaimIssueResult result = await TrustMarkValidator.Default()
            .ValidateAsync(context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim sigClaim = result.Claims.Single(c =>
            c.Id.Code == WellKnownFederationClaimIds.TrustMarkSignatureVerifies.Code);
        Assert.AreEqual(ClaimOutcome.Failure, sigClaim.Outcome);
    }
}
