using Verifiable.Core.Assessment;
using Verifiable.OAuth.Federation;
using Verifiable.OAuth.Trust;

namespace Verifiable.Tests.Federation;

/// <summary>
/// End-to-end wiring of the Federation provider behind <see cref="PartyTrustEngine"/>:
/// a real trust chain is validated by <see cref="TrustChainValidator"/>, the outcome is
/// lifted by <see cref="FederationTrustAdapter"/>, and the engine runs the Federation
/// assessors. A clean chain to a trusted anchor must be trusted (with a validity bound
/// + expiry trigger); a chain whose anchor is not trusted must be rejected.
/// </summary>
[TestClass]
internal sealed class FederationTrustAdapterTests
{
    public TestContext TestContext { get; set; } = null!;


    private static async ValueTask<(TrustChainValidationOutcome Outcome, DateTimeOffset Expiry)> ValidateChainAsync(
        EntityIdentifier anchorForValidation, DateTimeOffset now, CancellationToken cancellationToken)
    {
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/party"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));

        DateTimeOffset expiry = now.AddHours(1);
        MintedChain minted = await FederationTestRing.BuildDirectChainAsync(
            subject, anchor, now, expiry, cancellationToken).ConfigureAwait(false);

        //The adapter consumes the validation OUTCOME; signature verification is the
        //caller's contract (and is covered by TrustChainValidatorTests / the property
        //tests), so the links are marked verified here.
        IReadOnlyList<bool> linksVerified = [.. minted.Chain.Statements.Select(static _ => true)];

        TrustChainValidationContext context = new()
        {
            Chain = minted.Chain,
            TrustAnchors = [anchorForValidation],
            LinkSignaturesVerified = linksVerified,
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5)
        };

        ClaimIssueResult result = await TrustChainValidator.Default()
            .ValidateAsync(context, "federation-trust-adapter-test", cancellationToken)
            .ConfigureAwait(false);

        return (TrustChainValidationOutcome.Validated(minted.Chain, result), expiry);
    }


    [TestMethod]
    public async Task CleanChainToTrustedAnchorIsTrustedWithValidityAndExpiryTrigger()
    {
        DateTimeOffset now = new(2026, 6, 2, 12, 0, 0, TimeSpan.Zero);

        (TrustChainValidationOutcome outcome, DateTimeOffset expiry) = await ValidateChainAsync(
            new EntityIdentifier("https://example.test/anchor"), now, TestContext.CancellationToken)
            .ConfigureAwait(false);

        TrustEvidence<TrustChainValidationOutcome> evidence = FederationTrustAdapter.ToEvidence(outcome);

        TrustDecisionRecord<TrustChainValidationOutcome> record = await PartyTrustEngine.AssessAsync(
            evidence, TrustSignalSnapshot.Empty(now), FederationTrustAdapter.Assessors, now,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(record.Assessment.IsTrusted, "A clean chain to the trusted anchor must be trusted.");
        Assert.AreEqual("https://example.test/party", record.Assessment.PartyIdentifier);
        Assert.AreEqual(expiry, record.Assessment.ValidUntil, "Validity is bounded by the chain's earliest exp.");
        Assert.HasCount(1, record.Assessment.ReevaluationTriggers);
        Assert.AreEqual(TrustSignalKind.Expiry, record.Assessment.ReevaluationTriggers[0].Kind);
    }


    [TestMethod]
    public async Task ChainTerminatingAtAnUntrustedAnchorIsRejected()
    {
        DateTimeOffset now = new(2026, 6, 2, 12, 0, 0, TimeSpan.Zero);

        //Validate the chain against an anchor that is NOT the chain's terminal anchor —
        //ChainTerminatesAtTrustAnchor fails, so the Federation chain assessor rejects.
        (TrustChainValidationOutcome outcome, _) = await ValidateChainAsync(
            new EntityIdentifier("https://example.test/not-the-anchor"), now, TestContext.CancellationToken)
            .ConfigureAwait(false);

        TrustEvidence<TrustChainValidationOutcome> evidence = FederationTrustAdapter.ToEvidence(outcome);

        TrustDecisionRecord<TrustChainValidationOutcome> record = await PartyTrustEngine.AssessAsync(
            evidence, TrustSignalSnapshot.Empty(now), FederationTrustAdapter.Assessors, now,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(record.Assessment.IsTrusted, "A chain that does not reach a trusted anchor must be rejected.");
        Assert.IsNull(record.Assessment.ValidUntil, "An untrusted assessment carries no validity bound.");
        Assert.IsNotNull(record.Assessment.RejectionReason);
    }
}
