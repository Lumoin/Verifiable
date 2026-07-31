using System;
using System.Collections.Generic;
using CsCheck;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for the augmentation-decision timing of clauses 7.14 and 7.15 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
/// ETSI TS 119 511 V1.2.1</see> — the one piece of that requirement pair the shipped machinery did not already
/// answer: not how to augment, but whether it is time to.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The properties are the point.</strong> A decision function of this shape fails silently: an
/// off-by-one on the lead, a comparison that treats an unlisted algorithm as reliable, or an ordering that lets
/// a later expiry produce a more urgent answer all look like ordinary behaviour on any single example. The three
/// properties below — monotonic in the trusted-until instants, deterministic, and never sound without a table —
/// are what an example cannot show. A failing sample is a defect, not noise: CsCheck shrinks it and prints the
/// seed that reproduces it.
/// </para>
/// <para>
/// <strong>Nothing here reads a clock</strong>, which is what the requirement's own reproducibility depends on:
/// a decision recorded beside an evidence has to be re-takeable years later against the table that was in force.
/// </para>
/// </remarks>
[TestClass]
internal sealed class PreservationAugmentationDecisionTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = default!;


    /// <summary>The algorithms the generated samples draw from — three the library computes plus one it does not, so a sample can be unlisted.</summary>
    private static AlgorithmIdentifier[] SampleAlgorithms { get; } =
    [
        AlgorithmIdentifier.Sha256,
        AlgorithmIdentifier.Sha384,
        AlgorithmIdentifier.Sha512,
        AlgorithmIdentifier.Sha1
    ];

    /// <summary>The instant the generated samples are decided at.</summary>
    private static DateTimeOffset SampleInstant { get; } = TestClock.CanonicalEpoch;

    /// <summary>
    /// Generates a trusted-until offset in days from the sample instant, or no asserted expiry at all, or a row
    /// pinned at the beginning of representable time — the three sentinels below the range stand for the row
    /// that asserts no expiry, which the table admits and the decision has to treat as an expiry that never
    /// comes, and for the two rows whose implied deadline falls before time begins, which the decision has to
    /// answer rather than throw on.
    /// </summary>
    /// <remarks>
    /// A table row is caller-supplied policy and is validated nowhere, so any representable instant is a legal
    /// row. Keeping the samples in a band around the decision instant left the whole representable edge outside
    /// the sample space, and subtracting a lead there is arithmetic <see cref="DateTimeOffset"/> refuses to
    /// perform. The edge is therefore generated rather than only exampled, so every property below — determinism,
    /// monotonicity, never-sound-without-a-table — is asserted over it too.
    /// </remarks>
    private static Gen<DateTimeOffset?> GenTrustedUntil { get; } =
        Gen.Int[-403, 400].Select<int, DateTimeOffset?>(days => days switch
        {
            -401 => null,
            -402 => DateTimeOffset.MinValue,
            -403 => DateTimeOffset.MinValue.AddDays(10),
            _ => SampleInstant.AddDays(days)
        });

    /// <summary>Generates a table of one to four rows over the sample algorithms.</summary>
    private static Gen<CryptographicConstraints> GenConstraints { get; } =
        Gen.Select(Gen.Int[0, SampleAlgorithms.Length - 1], GenTrustedUntil)
            .Array[1, 4]
            .Select(rows =>
            {
                var entries = new List<AlgorithmReliabilityEntry>(rows.Length);
                var seen = new HashSet<string>(StringComparer.Ordinal);
                for(int i = 0; i < rows.Length; ++i)
                {
                    AlgorithmIdentifier algorithm = SampleAlgorithms[rows[i].Item1];
                    if(seen.Add(algorithm.Oid))
                    {
                        entries.Add(new AlgorithmReliabilityEntry(algorithm, MinimumKeySizeBits: null, rows[i].Item2));
                    }
                }

                return new CryptographicConstraints { Entries = entries };
            });

    /// <summary>Generates one to four algorithm uses over the sample algorithms.</summary>
    private static Gen<List<AlgorithmUse>> GenUses { get; } =
        Gen.Int[0, SampleAlgorithms.Length - 1].Array[1, 4].Select(indices =>
        {
            var uses = new List<AlgorithmUse>(indices.Length);
            for(int i = 0; i < indices.Length; ++i)
            {
                uses.Add(new AlgorithmUse(SampleAlgorithms[indices[i]], KeySizeBits: null, $"material {i}"));
            }

            return uses;
        });

    /// <summary>Generates a lead of zero to one hundred and twenty days.</summary>
    private static Gen<TimeSpan> GenLeadTime { get; } = Gen.Int[0, 120].Select(TimeSpan.FromDays);


    /// <summary>
    /// A table listing every used algorithm well past the lead answers that nothing has to be done, and names
    /// the instant a scheduler has to come back by — <c>OVR-7.15-01</c>'s "can be used to achieve the
    /// corresponding preservation goal", read at the instant it is asked at.
    /// </summary>
    [TestMethod]
    public void AnEvidenceWhoseAlgorithmsAreReliablePastTheLeadIsSound()
    {
        DateTimeOffset expiry = PreservationCapabilitySource.DecisionInstant.AddDays(400);
        PreservationAugmentationDecision decision = PreservationAugmentation.Decide(
            PreservationCapabilitySource.DecisionContext(
                PreservationCapabilitySource.Constraints((AlgorithmIdentifier.Sha256, expiry), (AlgorithmIdentifier.Sha512, expiry.AddDays(100))),
                [
                    PreservationCapabilitySource.HashUse(AlgorithmIdentifier.Sha256, "the archive time-stamp's hash tree"),
                    PreservationCapabilitySource.HashUse(AlgorithmIdentifier.Sha512, "the time-stamp token's message imprint")
                ]));

        Assert.AreEqual(PreservationAugmentationDecisionKind.Sound, decision.Kind);
        Assert.AreEqual(PreservationAugmentationReason.ReliablePastTheStatedLead, decision.Reason);
        Assert.IsFalse(decision.IsAugmentationDue);
        Assert.AreEqual(expiry, decision.TrustedUntil);
        Assert.AreEqual(expiry - PreservationCapabilitySource.LeadTime, decision.AugmentBefore);

        //The earliest expiry is what decides, not the first use stated.
        Assert.AreEqual("the archive time-stamp's hash tree", decision.TriggeringUse?.MaterialIdentifier);
    }


    /// <summary>
    /// A table listing every used algorithm with no expiry at all schedules nothing, and says so with its own
    /// reason rather than by naming an instant it does not have.
    /// </summary>
    [TestMethod]
    public void AnEvidenceWhoseAlgorithmsHaveNoAssertedExpiryIsSoundWithNoDeadline()
    {
        PreservationAugmentationDecision decision = PreservationAugmentation.Decide(
            PreservationCapabilitySource.DecisionContext(
                PreservationCapabilitySource.Constraints((AlgorithmIdentifier.Sha512, null)),
                [PreservationCapabilitySource.HashUse(AlgorithmIdentifier.Sha512, "the archive time-stamp's hash tree")]));

        Assert.AreEqual(PreservationAugmentationDecisionKind.Sound, decision.Kind);
        Assert.AreEqual(PreservationAugmentationReason.NoExpiryAsserted, decision.Reason);
        Assert.IsNull(decision.TrustedUntil);
        Assert.IsNull(decision.AugmentBefore);
        Assert.IsNull(decision.TriggeringUse);
    }


    /// <summary>
    /// An algorithm whose asserted reliability has already run out answers that augmentation is due now, and
    /// names the algorithm and the instant — <c>OVR-7.14-02</c>'s trigger, made readable.
    /// </summary>
    [TestMethod]
    public void AnAlgorithmPastItsTrustedUntilInstantMakesAugmentationDue()
    {
        DateTimeOffset expiry = PreservationCapabilitySource.DecisionInstant.AddDays(-1);
        PreservationAugmentationDecision decision = PreservationAugmentation.Decide(
            PreservationCapabilitySource.DecisionContext(
                PreservationCapabilitySource.Constraints((AlgorithmIdentifier.Sha256, expiry)),
                [PreservationCapabilitySource.HashUse(AlgorithmIdentifier.Sha256, "the archive time-stamp's hash tree")]));

        Assert.AreEqual(PreservationAugmentationDecisionKind.AugmentNow, decision.Kind);
        Assert.AreEqual(PreservationAugmentationReason.AlgorithmNoLongerReliable, decision.Reason);
        Assert.IsTrue(decision.IsAugmentationDue);
        Assert.AreEqual(expiry, decision.TrustedUntil);
        Assert.AreEqual(AlgorithmIdentifier.Sha256.Oid, decision.TriggeringUse?.Algorithm.Oid);
    }


    /// <summary>
    /// An algorithm still reliable but expiring inside the stated lead makes augmentation due — which is the
    /// whole of <c>OVR-7.15-03</c>'s "before they cannot be used anymore", and the case a check that only asked
    /// "has it expired" would miss.
    /// </summary>
    [TestMethod]
    [DataRow(1, true, DisplayName = "expiring one day beyond the lead window, augmentation is not yet due")]
    [DataRow(0, false, DisplayName = "expiring exactly at the lead boundary, augmentation is due")]
    [DataRow(-1, false, DisplayName = "expiring one day inside the lead window, augmentation is due")]
    public void AnAlgorithmExpiringInsideTheStatedLeadMakesAugmentationDue(int daysFromTheBoundary, bool expectedSound)
    {
        //The boundary is the instant advanced by the lead: an expiry at or before it is inside the window.
        DateTimeOffset expiry = PreservationCapabilitySource.DecisionInstant + PreservationCapabilitySource.LeadTime + TimeSpan.FromDays(daysFromTheBoundary);
        PreservationAugmentationDecision decision = PreservationAugmentation.Decide(
            PreservationCapabilitySource.DecisionContext(
                PreservationCapabilitySource.Constraints((AlgorithmIdentifier.Sha256, expiry)),
                [PreservationCapabilitySource.HashUse(AlgorithmIdentifier.Sha256, "the archive time-stamp's hash tree")]));

        if(expectedSound)
        {
            Assert.AreEqual(PreservationAugmentationDecisionKind.Sound, decision.Kind);
            Assert.AreEqual(PreservationAugmentationReason.ReliablePastTheStatedLead, decision.Reason);
        }
        else
        {
            Assert.AreEqual(PreservationAugmentationDecisionKind.AugmentNow, decision.Kind);
            Assert.AreEqual(PreservationAugmentationReason.AlgorithmWeakensWithinTheStatedLead, decision.Reason);
        }

        Assert.AreEqual(expiry, decision.TrustedUntil);
        Assert.AreEqual(expiry - PreservationCapabilitySource.LeadTime, decision.AugmentBefore);
    }


    /// <summary>
    /// A key size below the row's floor makes augmentation due and states no deadline, because no instant
    /// repairs it — the parameter half of <c>OVR-7.14-01</c>'s "one of the used algorithms or parameters".
    /// </summary>
    [TestMethod]
    public void AKeySizeBelowTheRowsFloorMakesAugmentationDueWithNoDeadline()
    {
        PreservationAugmentationDecision decision = PreservationAugmentation.Decide(
            PreservationCapabilitySource.DecisionContext(
                PreservationCapabilitySource.ConstraintsWithKeySizeFloor(
                    AlgorithmIdentifier.Sha256,
                    minimumKeySizeBits: 3072,
                    trustedUntil: PreservationCapabilitySource.DecisionInstant.AddDays(400)),
                [PreservationCapabilitySource.KeyedUse(AlgorithmIdentifier.Sha256, keySizeBits: 2048, "the time-stamp token's signature")]));

        Assert.AreEqual(PreservationAugmentationDecisionKind.AugmentNow, decision.Kind);
        Assert.AreEqual(PreservationAugmentationReason.KeySizeBelowMinimum, decision.Reason);
        Assert.IsNull(decision.AugmentBefore);
        Assert.AreEqual("the time-stamp token's signature", decision.TriggeringUse?.MaterialIdentifier);
    }


    /// <summary>
    /// An empty table decides nothing and is never sound — the documented default, and the fail-closed reading
    /// the constraints machinery itself already takes of an unlisted algorithm.
    /// </summary>
    [TestMethod]
    public void AnEmptyTableDecidesNothingAndIsNeverSound()
    {
        PreservationAugmentationDecision decision = PreservationAugmentation.Decide(
            PreservationCapabilitySource.DecisionContext(
                CryptographicConstraints.Empty,
                [PreservationCapabilitySource.HashUse(AlgorithmIdentifier.Sha256, "the archive time-stamp's hash tree")]));

        Assert.AreEqual(PreservationAugmentationDecisionKind.Undecidable, decision.Kind);
        Assert.AreEqual(PreservationAugmentationReason.AlgorithmNotStatedInConstraints, decision.Reason);
        Assert.IsNull(decision.AugmentBefore);
        Assert.AreEqual(AlgorithmIdentifier.Sha256.Oid, decision.TriggeringUse?.Algorithm.Oid);
    }


    /// <summary>
    /// A table listing some of the used algorithms and not others is still undecidable, and names the unlisted
    /// one — a partial table must not read as a clean bill of health for the part it covers.
    /// </summary>
    [TestMethod]
    public void AnAlgorithmTheTableDoesNotListLeavesTheDecisionUndecidable()
    {
        PreservationAugmentationDecision decision = PreservationAugmentation.Decide(
            PreservationCapabilitySource.DecisionContext(
                PreservationCapabilitySource.Constraints((AlgorithmIdentifier.Sha256, PreservationCapabilitySource.DecisionInstant.AddDays(400))),
                [
                    PreservationCapabilitySource.HashUse(AlgorithmIdentifier.Sha256, "the archive time-stamp's hash tree"),
                    PreservationCapabilitySource.HashUse(AlgorithmIdentifier.Sha512, "the time-stamp token's message imprint")
                ]));

        Assert.AreEqual(PreservationAugmentationDecisionKind.Undecidable, decision.Kind);
        Assert.AreEqual(AlgorithmIdentifier.Sha512.Oid, decision.TriggeringUse?.Algorithm.Oid);
    }


    /// <summary>
    /// An expired algorithm beside an unlisted one answers that augmentation is due: the actionable answer wins
    /// over the one nobody can give, which is the precedence the function documents and the property below
    /// depends on.
    /// </summary>
    [TestMethod]
    public void AnExpiredAlgorithmOutranksAnUnlistedOne()
    {
        PreservationAugmentationDecision decision = PreservationAugmentation.Decide(
            PreservationCapabilitySource.DecisionContext(
                PreservationCapabilitySource.Constraints((AlgorithmIdentifier.Sha256, PreservationCapabilitySource.DecisionInstant.AddDays(-1))),
                [
                    PreservationCapabilitySource.HashUse(AlgorithmIdentifier.Sha512, "an algorithm no row mentions"),
                    PreservationCapabilitySource.HashUse(AlgorithmIdentifier.Sha256, "the archive time-stamp's hash tree")
                ]));

        Assert.AreEqual(PreservationAugmentationDecisionKind.AugmentNow, decision.Kind);
        Assert.AreEqual(PreservationAugmentationReason.AlgorithmNoLongerReliable, decision.Reason);
    }


    /// <summary>
    /// Stating no algorithm use at all is undecidable and never sound: an evidence nobody described has not been
    /// shown to be in good order.
    /// </summary>
    [TestMethod]
    public void StatingNoAlgorithmUseIsUndecidableRatherThanSound()
    {
        PreservationAugmentationDecision decision = PreservationAugmentation.Decide(
            PreservationCapabilitySource.DecisionContext(
                PreservationCapabilitySource.Constraints((AlgorithmIdentifier.Sha256, PreservationCapabilitySource.DecisionInstant.AddDays(400))),
                []));

        Assert.AreEqual(PreservationAugmentationDecisionKind.Undecidable, decision.Kind);
        Assert.AreEqual(PreservationAugmentationReason.NoAlgorithmUseStated, decision.Reason);
        Assert.IsNull(decision.TriggeringUse);
    }


    /// <summary>
    /// A default-initialised decision reads as neither sound nor due, and every enumeration this stage declares
    /// puts its zero on a value that means "not computed".
    /// </summary>
    [TestMethod]
    public void ADefaultInitialisedDecisionReadsAsNothingHavingBeenComputed()
    {
        Assert.AreEqual(nameof(PreservationAugmentationDecisionKind.NotEvaluated), Enum.GetName(default(PreservationAugmentationDecisionKind)));
        Assert.AreEqual(nameof(PreservationAugmentationReason.NotEvaluated), Enum.GetName(default(PreservationAugmentationReason)));
    }


    /// <summary>A negative lead would ask for an augmentation after the expiry it precedes, and is refused where it is stated.</summary>
    [TestMethod]
    public void ANegativeLeadIsRefused()
    {
        PreservationAugmentationContext context = PreservationCapabilitySource.DecisionContext(
            CryptographicConstraints.Empty,
            [PreservationCapabilitySource.HashUse(AlgorithmIdentifier.Sha256, "the archive time-stamp's hash tree")],
            leadTime: TimeSpan.FromDays(-1));

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => PreservationAugmentation.Decide(context));
        _ = Assert.ThrowsExactly<ArgumentNullException>(() => PreservationAugmentation.Decide(null!));
    }


    /// <summary>
    /// Moving a table row's trusted-until instant later never makes a decision more urgent. This is the property
    /// the requirement actually depends on — a service that learns an algorithm is good for longer must never be
    /// told to act sooner — and it is what the augment-now-beats-undecidable-beats-sound precedence buys.
    /// </summary>
    [TestMethod]
    public void MovingATrustedUntilInstantLaterNeverMakesADecisionMoreUrgent()
    {
        Gen.Select(GenConstraints, GenUses, GenLeadTime, Gen.Int[1, 500]).Sample(sample =>
        {
            (CryptographicConstraints constraints, List<AlgorithmUse> uses, TimeSpan leadTime, int extensionDays) = sample;

            var extended = new List<AlgorithmReliabilityEntry>(constraints.Entries.Count);
            for(int i = 0; i < constraints.Entries.Count; ++i)
            {
                AlgorithmReliabilityEntry entry = constraints.Entries[i];
                extended.Add(entry with
                {
                    TrustedUntil = entry.TrustedUntil is DateTimeOffset trustedUntil ? trustedUntil.AddDays(extensionDays) : null
                });
            }

            int before = UrgencyOf(PreservationAugmentation.Decide(Context(constraints, uses, leadTime)));
            int after = UrgencyOf(PreservationAugmentation.Decide(Context(new CryptographicConstraints { Entries = extended }, uses, leadTime)));

            return after <= before;
        });
    }


    /// <summary>
    /// The same table, uses, instant and lead always answer the same decision — the reproducibility a decision
    /// recorded beside an evidence and re-taken years later depends on.
    /// </summary>
    [TestMethod]
    public void TheSameQuestionAlwaysAnswersTheSameDecision()
    {
        Gen.Select(GenConstraints, GenUses, GenLeadTime).Sample(sample =>
        {
            (CryptographicConstraints constraints, List<AlgorithmUse> uses, TimeSpan leadTime) = sample;

            PreservationAugmentationDecision first = PreservationAugmentation.Decide(Context(constraints, uses, leadTime));
            PreservationAugmentationDecision second = PreservationAugmentation.Decide(Context(constraints, uses, leadTime));

            return first == second;
        });
    }


    /// <summary>
    /// A use whose algorithm no row mentions never reaches a sound decision, whatever else the table says — the
    /// documented table-absent default, stated as a property over every sample rather than over one example.
    /// </summary>
    [TestMethod]
    public void AUseNoRowMentionsNeverReachesASoundDecision()
    {
        Gen.Select(GenConstraints, GenUses, GenLeadTime).Sample(sample =>
        {
            (CryptographicConstraints constraints, List<AlgorithmUse> uses, TimeSpan leadTime) = sample;

            bool anyUnlisted = false;
            for(int i = 0; i < uses.Count; ++i)
            {
                anyUnlisted |= constraints.Find(uses[i].Algorithm) is null;
            }

            if(!anyUnlisted)
            {
                return true;
            }

            return PreservationAugmentation.Decide(Context(constraints, uses, leadTime)).Kind != PreservationAugmentationDecisionKind.Sound;
        });
    }


    /// <summary>
    /// A row whose trusted-until instant is nearer the beginning of representable time than the lead is long is
    /// answered with a decision, not with an exception. The deadline such a row implies falls before time
    /// begins, so no instant can name it — and the function already has the principled answer for a deadline
    /// that was never real, because the key-size arm states none either.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The table is caller-supplied declarative policy and it cannot say "never trusted" with a null, since a
    /// null says no expiry was asserted at all. A caller recording "broken since forever" therefore has to write
    /// a past instant, and the beginning of time is the natural one to write. Both arms that subtract the lead
    /// are exercised: the one an already-expired row reaches, and the lead-window guard a not-yet-expired row
    /// reaches.
    /// </para>
    /// <para>
    /// The documented exception set of <see cref="PreservationAugmentation.Decide"/> admits
    /// <see cref="ArgumentOutOfRangeException"/> for one cause only — a negative lead — so a caller catching it
    /// to report that cause must not be handed the same exception for a different one.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void ARowAtTheBeginningOfRepresentableTimeIsAnsweredRatherThanThrown()
    {
        //The already-expired arm: the row's instant is behind the decision instant, so the decision is the most
        //urgent one there is, and the deadline it would name is not representable and is therefore not named.
        PreservationAugmentationDecision expired = PreservationAugmentation.Decide(
            PreservationCapabilitySource.DecisionContext(
                PreservationCapabilitySource.Constraints((AlgorithmIdentifier.Sha1, DateTimeOffset.MinValue)),
                [PreservationCapabilitySource.HashUse(AlgorithmIdentifier.Sha1, "the archive time-stamp's hash tree")]));

        Assert.AreEqual(PreservationAugmentationDecisionKind.AugmentNow, expired.Kind);
        Assert.AreEqual(PreservationAugmentationReason.AlgorithmNoLongerReliable, expired.Reason);
        Assert.AreEqual(DateTimeOffset.MinValue, expired.TrustedUntil);
        Assert.IsNull(expired.AugmentBefore, "A deadline before the beginning of time was never real, so none is named.");

        //The lead-window arm: the row has not expired at the decision instant, but subtracting the lead from it
        //underflows, which means the window opened before any instant this type can express.
        PreservationAugmentationDecision withinTheLead = PreservationAugmentation.Decide(
            PreservationCapabilitySource.DecisionContext(
                PreservationCapabilitySource.Constraints((AlgorithmIdentifier.Sha256, DateTimeOffset.MinValue.AddDays(10))),
                [PreservationCapabilitySource.HashUse(AlgorithmIdentifier.Sha256, "the time-stamp token's message imprint")],
                instant: DateTimeOffset.MinValue));

        Assert.AreEqual(PreservationAugmentationDecisionKind.AugmentNow, withinTheLead.Kind);
        Assert.AreEqual(PreservationAugmentationReason.AlgorithmWeakensWithinTheStatedLead, withinTheLead.Reason);
        Assert.AreEqual(DateTimeOffset.MinValue.AddDays(10), withinTheLead.TrustedUntil);
        Assert.IsNull(withinTheLead.AugmentBefore);

        //The control the trigger condition is pinned by: with no lead at all the subtraction cannot underflow,
        //and the same row answers with the deadline named.
        PreservationAugmentationDecision withoutLead = PreservationAugmentation.Decide(
            PreservationCapabilitySource.DecisionContext(
                PreservationCapabilitySource.Constraints((AlgorithmIdentifier.Sha1, DateTimeOffset.MinValue)),
                [PreservationCapabilitySource.HashUse(AlgorithmIdentifier.Sha1, "the archive time-stamp's hash tree")],
                leadTime: TimeSpan.Zero));

        Assert.AreEqual(PreservationAugmentationDecisionKind.AugmentNow, withoutLead.Kind);
        Assert.AreEqual(DateTimeOffset.MinValue, withoutLead.AugmentBefore);

        //And the one cause the documented exception set really reserves that exception for still raises it.
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => PreservationAugmentation.Decide(
            PreservationCapabilitySource.DecisionContext(
                PreservationCapabilitySource.Constraints((AlgorithmIdentifier.Sha256, DateTimeOffset.MinValue.AddDays(10))),
                [PreservationCapabilitySource.HashUse(AlgorithmIdentifier.Sha256, "the time-stamp token's message imprint")],
                leadTime: TimeSpan.FromDays(-1))));
    }


    /// <summary>Builds the context a generated sample is decided from, at the one instant the samples share.</summary>
    /// <param name="constraints">The table.</param>
    /// <param name="uses">The uses.</param>
    /// <param name="leadTime">The lead.</param>
    /// <returns>The context.</returns>
    private static PreservationAugmentationContext Context(CryptographicConstraints constraints, IReadOnlyList<AlgorithmUse> uses, TimeSpan leadTime) =>
        new()
        {
            Constraints = constraints,
            AlgorithmUses = uses,
            Instant = SampleInstant,
            LeadTime = leadTime
        };


    /// <summary>
    /// Ranks a decision by how urgent it is, which is the order the monotonicity property is stated over:
    /// sound is the least urgent, an undecided one sits above it because it is not a pass, and augment-now is
    /// the most urgent.
    /// </summary>
    /// <param name="decision">The decision to rank.</param>
    /// <returns>The rank.</returns>
    private static int UrgencyOf(PreservationAugmentationDecision decision) => decision.Kind switch
    {
        PreservationAugmentationDecisionKind.Sound => 0,
        PreservationAugmentationDecisionKind.Undecidable => 1,
        PreservationAugmentationDecisionKind.AugmentNow => 2,
        _ => 3
    };
}
