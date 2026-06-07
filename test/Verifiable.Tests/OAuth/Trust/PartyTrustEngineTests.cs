using Verifiable.OAuth.Trust;

namespace Verifiable.Tests.OAuth.Trust;

/// <summary>
/// Invariants of <see cref="PartyTrustEngine"/> exercised with fake assessors — no
/// mechanism adapter required. These pin the structural guarantees the whole design
/// rests on: fail-closed, monotone narrowing, reject-is-terminal, validity-is-the-meet.
/// </summary>
[TestClass]
internal sealed class PartyTrustEngineTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly DateTimeOffset Now = new(2026, 6, 2, 12, 0, 0, TimeSpan.Zero);


    private static TrustEvidence<string> Evidence() => new()
    {
        PartyIdentifier = "https://verifier.example",
        Mechanism = TrustMechanism.OpenIdFederation,
        MechanismEvidence = "federation-chain-proof"
    };


    private static TrustAssessorDelegate<string> Affirm(string id) =>
        (context, cancellationToken) => new ValueTask<TrustAssessorVerdict>(TrustAssessorVerdict.Affirm(id));


    private static TrustAssessorDelegate<string> Reject(string id, string reason) =>
        (context, cancellationToken) => new ValueTask<TrustAssessorVerdict>(TrustAssessorVerdict.Reject(id, reason));


    private static TrustAssessorDelegate<string> Constrain(
        string id,
        IReadOnlyDictionary<string, object>? metadata = null,
        DateTimeOffset? validUntil = null,
        IReadOnlyList<ReevaluationTrigger>? triggers = null) =>
        (context, cancellationToken) => new ValueTask<TrustAssessorVerdict>(new TrustAssessorVerdict
        {
            Outcome = TrustVerdictOutcome.Constrain,
            AssessorId = id,
            ConstrainedMetadata = metadata,
            ValidUntil = validUntil,
            ReevaluationTriggers = triggers ?? []
        });


    [TestMethod]
    public async Task EmptyAssessorPipelineIsFailClosed()
    {
        TrustDecisionRecord<string> record = await PartyTrustEngine.AssessAsync(
            Evidence(), TrustSignalSnapshot.Empty(Now), [], Now,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(record.Assessment.IsTrusted, "No assessors must fail closed — trust is never granted by default.");
        Assert.IsEmpty(record.Verdicts);
        Assert.IsNotNull(record.Assessment.RejectionReason);
    }


    [TestMethod]
    public async Task AllAssessorsAffirmYieldsTrusted()
    {
        TrustDecisionRecord<string> record = await PartyTrustEngine.AssessAsync(
            Evidence(), TrustSignalSnapshot.Empty(Now),
            [Affirm("a"), Affirm("b")], Now,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(record.Assessment.IsTrusted);
        Assert.HasCount(2, record.Verdicts);
    }


    [TestMethod]
    public async Task RejectIsTerminalAndLaterAssessorsDoNotRun()
    {
        TrustDecisionRecord<string> record = await PartyTrustEngine.AssessAsync(
            Evidence(), TrustSignalSnapshot.Empty(Now),
            [Affirm("first"), Reject("anchor-gate", "chain does not reach a trusted anchor"), Affirm("never-runs")], Now,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(record.Assessment.IsTrusted);
        Assert.AreEqual("chain does not reach a trusted anchor", record.Assessment.RejectionReason);
        Assert.HasCount(2, record.Verdicts, "The assessor after the reject must not run.");
    }


    [TestMethod]
    public async Task ConstrainAdoptsTheNarrowedMetadata()
    {
        Dictionary<string, object> narrowed = new() { ["organization_name"] = "Verifier Co." };

        TrustDecisionRecord<string> record = await PartyTrustEngine.AssessAsync(
            Evidence(), TrustSignalSnapshot.Empty(Now),
            [Constrain("policy", metadata: narrowed)], Now,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(record.Assessment.IsTrusted);
        Assert.AreEqual("Verifier Co.", record.Assessment.EffectiveMetadata["organization_name"]);
    }


    [TestMethod]
    public async Task ValidUntilIsTheEarliestBoundAcrossAssessors()
    {
        DateTimeOffset earlier = Now.AddHours(1);
        DateTimeOffset later = Now.AddHours(8);

        TrustDecisionRecord<string> record = await PartyTrustEngine.AssessAsync(
            Evidence(), TrustSignalSnapshot.Empty(Now),
            [Constrain("a", validUntil: later), Constrain("b", validUntil: earlier)], Now,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(earlier, record.Assessment.ValidUntil, "ValidUntil must be the earliest (meet) bound across assessors.");
    }


    [TestMethod]
    public async Task ReevaluationTriggersAreTheUnion()
    {
        ReevaluationTrigger statusTrigger = new() { Kind = TrustSignalKind.StatusListEntry, Subject = "cred-1" };
        ReevaluationTrigger revocationTrigger = new() { Kind = TrustSignalKind.Revocation, Subject = "https://verifier.example" };

        TrustDecisionRecord<string> record = await PartyTrustEngine.AssessAsync(
            Evidence(), TrustSignalSnapshot.Empty(Now),
            [Constrain("a", triggers: [statusTrigger]), Constrain("b", triggers: [revocationTrigger])], Now,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(2, record.Assessment.ReevaluationTriggers);
    }


    [TestMethod]
    public async Task UntrustedAssessmentCarriesNoMetadataOrValidity()
    {
        Dictionary<string, object> narrowed = new() { ["organization_name"] = "Verifier Co." };

        TrustDecisionRecord<string> record = await PartyTrustEngine.AssessAsync(
            Evidence(), TrustSignalSnapshot.Empty(Now),
            [
                Constrain("policy", metadata: narrowed, validUntil: Now.AddHours(1)),
                Reject("revocation", "verifier credential revoked")
            ],
            Now,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(record.Assessment.IsTrusted);
        Assert.IsEmpty(record.Assessment.EffectiveMetadata);
        Assert.IsNull(record.Assessment.ValidUntil);
    }
}
