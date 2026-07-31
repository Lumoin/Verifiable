using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// What a cryptographic constraints table, an evidence's algorithm uses and one instant say about whether a
/// preservation evidence has to be augmented — the decision <c>OVR-7.14-01</c>, <c>OVR-7.14-02</c> and
/// <c>OVR-7.15-03</c> of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
/// ETSI TS 119 511 V1.2.1</see> oblige a preservation service to keep taking.
/// </summary>
/// <remarks>
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised decision never reads as an evidence that was
/// found sound.
/// </remarks>
public enum PreservationAugmentationDecisionKind
{
    /// <summary>No decision has been taken. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>
    /// Every stated algorithm use is listed in the table and asserted reliable past the stated lead, so
    /// <c>OVR-7.15-01</c> and <c>OVR-7.15-02</c> hold without acting now.
    /// </summary>
    Sound = 1,

    /// <summary>
    /// At least one stated algorithm use is no longer reliable, or ceases to be reliable within the stated lead,
    /// so <c>OVR-7.15-03</c>'s "before they cannot be used anymore" instant has arrived.
    /// </summary>
    AugmentNow = 2,

    /// <summary>
    /// The table asserts nothing about at least one stated algorithm use, or no use was stated at all, so no
    /// answer can be given. Never a synonym for <see cref="Sound"/>: clause 5.1.4.1 of the signature-validation
    /// standard the constraints table belongs to forbids an unlisted algorithm from being treated as reliable,
    /// and this decision honours that.
    /// </summary>
    Undecidable = 3
}


/// <summary>
/// Why a <see cref="PreservationAugmentationDecision"/> reached the kind it did.
/// </summary>
/// <remarks>
/// <see cref="NotEvaluated"/> occupies zero for the same reason
/// <see cref="PreservationAugmentationDecisionKind.NotEvaluated"/> does.
/// </remarks>
public enum PreservationAugmentationReason
{
    /// <summary>No decision has been taken. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>Every stated use is reliable, and the earliest asserted expiry lies beyond the stated lead.</summary>
    ReliablePastTheStatedLead = 1,

    /// <summary>Every stated use is listed and no listed row asserts an expiry at all, so nothing schedules an augmentation.</summary>
    NoExpiryAsserted = 2,

    /// <summary>
    /// A stated use's algorithm is listed but the instant lies after the row's trusted-until instant — the
    /// <see cref="AlgorithmReliabilityVerdict.NoLongerReliable"/> verdict.
    /// </summary>
    AlgorithmNoLongerReliable = 3,

    /// <summary>
    /// A stated use's key size is below the floor its row states — the
    /// <see cref="AlgorithmReliabilityVerdict.KeySizeBelowMinimum"/> verdict, which no instant can repair.
    /// </summary>
    KeySizeBelowMinimum = 4,

    /// <summary>
    /// Every stated use is reliable at the instant, but the earliest asserted expiry falls at or before the
    /// instant advanced by the stated lead — <c>OVR-7.15-03</c>'s "before".
    /// </summary>
    AlgorithmWeakensWithinTheStatedLead = 5,

    /// <summary>The table lists no row for a stated use's algorithm — the <see cref="AlgorithmReliabilityVerdict.Unknown"/> verdict.</summary>
    AlgorithmNotStatedInConstraints = 6,

    /// <summary>No algorithm use was stated, so there is nothing to monitor and nothing that can be called sound.</summary>
    NoAlgorithmUseStated = 7
}


/// <summary>
/// Everything one <see cref="PreservationAugmentation.Decide"/> call reads: the constraints table, the algorithm
/// uses being monitored, the instant the question is asked at, and how far ahead of an expiry the answering
/// service augments.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Both scopes <c>OVR-7.14</c> distinguishes use this one record.</strong> <c>OVR-7.14-01</c> asks the
/// question per active preservation profile ("every cryptographic algorithm that was used in connection with this
/// profile") and <c>OVR-7.14-02</c> asks it per preservation evidence ("one of the algorithms or parameters which
/// were used in a preservation evidence"). The two differ only in which uses are stated in
/// <see cref="AlgorithmUses"/>, so one function answers both and the caller decides the scope.
/// </para>
/// <para>
/// <strong>The instant is stated, never read.</strong> A decision taken over an evidence has to be reproducible
/// — the same table, the same uses and the same instant answer the same thing on any machine on any day — which
/// is why nothing here consults a clock. A caller monitoring continuously passes its own scheduler's instant.
/// </para>
/// <para>
/// <strong>The lead has no default because the specification states no figure.</strong> <c>OVR-7.15-03</c>
/// obliges a service to augment "before" the evidence can no longer achieve its goal and leaves how far before to
/// the service; a defaulted zero would silently answer with the latest possible instant, and any non-zero default
/// would be a policy number this library invented. <see cref="LeadTime"/> is therefore required, and a caller
/// that really wants the last possible instant states <see cref="TimeSpan.Zero"/> itself.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservationAugmentationContext
{
    /// <summary>The dated algorithm-reliability table the decision is taken against; <see cref="CryptographicConstraints.Empty"/> asserts nothing about anything.</summary>
    public required CryptographicConstraints Constraints { get; init; }

    /// <summary>The algorithm uses being monitored — a profile's or one evidence's, per the remarks.</summary>
    public required IReadOnlyList<AlgorithmUse> AlgorithmUses { get; init; }

    /// <summary>The instant the question is asked at. Stated by the caller; nothing here reads a clock.</summary>
    public required DateTimeOffset Instant { get; init; }

    /// <summary>
    /// How far ahead of an asserted expiry the answering service augments. Required, per the remarks; must not be
    /// negative.
    /// </summary>
    public required TimeSpan LeadTime { get; init; }


    /// <summary>A short debugger string showing how many uses are monitored, against how many rows, at what instant.</summary>
    private string DebuggerDisplay =>
        $"PreservationAugmentationContext({AlgorithmUses.Count} uses, {Constraints.Entries.Count} rows, {Instant:O}, lead {LeadTime})";
}


/// <summary>
/// What <see cref="PreservationAugmentation.Decide"/> answered: whether a preservation evidence still achieves
/// its preservation goal, and if it does, by when it has to be augmented.
/// </summary>
/// <remarks>
/// <para>
/// The record carries only values, so two decisions taken over the same inputs are equal — which is what makes
/// "the same question answers the same thing twice" an assertion rather than a hope. A caller wanting the whole
/// per-use assessment list asks
/// <see cref="CryptographicConstraints.FindUnreliable(IReadOnlyList{AlgorithmUse}, DateTimeOffset)"/>, which
/// already produces exactly that; this type does not restate it.
/// </para>
/// <para>
/// <see cref="AugmentBefore"/> is the actionable half: on <see cref="PreservationAugmentationDecisionKind.Sound"/>
/// it is the instant a scheduler sets its next visit no later than, and on
/// <see cref="PreservationAugmentationDecisionKind.AugmentNow"/> it is the instant that has already passed.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservationAugmentationDecision
{
    /// <summary>The decision; <see cref="PreservationAugmentationDecisionKind.Sound"/> is the only "nothing to do".</summary>
    public required PreservationAugmentationDecisionKind Kind { get; init; }

    /// <summary>Why the decision came out as it did.</summary>
    public required PreservationAugmentationReason Reason { get; init; }

    /// <summary>
    /// The use the decision turns on — the weakening algorithm on
    /// <see cref="PreservationAugmentationDecisionKind.AugmentNow"/>, the unlisted one on
    /// <see cref="PreservationAugmentationDecisionKind.Undecidable"/>, and the one whose expiry comes first on
    /// <see cref="PreservationAugmentationDecisionKind.Sound"/>; <see langword="null"/> when no use decides
    /// anything, which is the case when no use was stated and the case when no listed row asserts an expiry.
    /// </summary>
    public AlgorithmUse? TriggeringUse { get; init; }

    /// <summary>The instant the table asserts <see cref="TriggeringUse"/>'s algorithm reliable until, or <see langword="null"/> when the row asserts none or there is no row.</summary>
    public DateTimeOffset? TrustedUntil { get; init; }

    /// <summary>
    /// The instant by which the evidence has to have been augmented — <see cref="TrustedUntil"/> brought forward
    /// by the context's lead — or <see langword="null"/> when nothing asserts an expiry or nothing can be decided.
    /// </summary>
    public DateTimeOffset? AugmentBefore { get; init; }


    /// <summary>Gets whether the decision obliges the caller to augment now.</summary>
    public bool IsAugmentationDue => Kind == PreservationAugmentationDecisionKind.AugmentNow;


    /// <summary>A short debugger string showing the decision, its reason and the instant it turns on.</summary>
    private string DebuggerDisplay =>
        $"PreservationAugmentationDecision({Kind}, {Reason}, before {(AugmentBefore is null ? "no instant" : AugmentBefore.Value.ToString("O"))})";
}


/// <summary>
/// The augmentation-decision timing of clause 7.14 and clause 7.15 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
/// ETSI TS 119 511 V1.2.1</see>: given a cryptographic constraints table, the algorithms an evidence or a profile
/// uses and an instant, whether and by when the evidence has to be augmented.
/// </summary>
/// <remarks>
/// <para>
/// <strong>What this decides and what it does not.</strong> <c>OVR-7.15-03</c> obliges a service to "augment the
/// preservation evidences before they cannot be used anymore to achieve the corresponding preservation goal";
/// NOTE 2 and NOTE 3 of that clause name the mechanisms — incorporating time-stamps and validation data into a
/// digital signature, and time-stamp renewal or hash-tree renewal of an evidence record — and every one of those
/// mechanisms is shipped (<see cref="CAdESSignatureAugmentation"/>, <see cref="EvidenceRecordRenewal"/>,
/// <see cref="AsicContainerAugmentation"/>). What was missing is the *timing*: the answer to "is it time yet".
/// This is that answer and nothing more; it performs no augmentation and contacts nothing.
/// </para>
/// <para>
/// <strong>It is pure over its inputs.</strong> No clock is read, no ambient state is consulted and no argument is
/// mutated, so the same context always answers the same decision. That is what lets a service record the decision
/// beside the evidence and lets an auditor re-take it years later against the table that was in force.
/// </para>
/// <para>
/// <strong>Precedence: augment-now beats undecidable beats sound.</strong> A use the table does not list can never
/// read as sound, and a use that is already unreliable is a more actionable answer than one that cannot be judged,
/// so a context mixing the two answers <see cref="PreservationAugmentationDecisionKind.AugmentNow"/>. The
/// consequence is the property that matters: moving a row's trusted-until instant later can only make a decision
/// less urgent, never more.
/// </para>
/// <para>
/// <strong>Certificate expiry is out of this function.</strong> <c>OVR-7.14-01</c> and <c>OVR-7.14-02</c> name two
/// triggers — an algorithm thought to weaken, and "the validity of a relevant certificate is going to expire". The
/// first is what a constraints table answers and is what this decides. The second is a fact about a certificate
/// chain, which the shipped chain and revocation machinery answers, and folding it in here would mean this
/// function reading material it was not given. A caller monitoring both takes the more urgent of the two answers.
/// </para>
/// </remarks>
public static class PreservationAugmentation
{
    /// <summary>
    /// Decides whether a preservation evidence still achieves its preservation goal at an instant, and by when it
    /// has to be augmented if it does.
    /// </summary>
    /// <param name="context">The table, the uses, the instant and the lead.</param>
    /// <returns>The decision.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="context"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The context's lead is negative, which would ask for an augmentation after the expiry it is meant to precede.</exception>
    /// <remarks>
    /// <strong>A deadline before the beginning of representable time is stated as no deadline.</strong> A table
    /// row is caller-supplied policy and any representable instant is a legal one, so a row whose trusted-until
    /// instant is nearer <see cref="DateTimeOffset.MinValue"/> than the lead is long implies an augment-before
    /// that cannot be expressed. The answer is the one the key-size arm already gives a deadline that was never
    /// real: the decision is returned with no <see cref="PreservationAugmentationDecision.AugmentBefore"/>, and
    /// where the same subtraction decides whether the lead window has opened, an unrepresentable window is one
    /// that opened before any instant and is therefore open. The exception this method documents stays reserved
    /// for the one cause it names.
    /// </remarks>
    public static PreservationAugmentationDecision Decide(PreservationAugmentationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if(context.LeadTime < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(context),
                context.LeadTime,
                "The lead time must not be negative: an augmentation is due before an expiry, never after it.");
        }

        if(context.AlgorithmUses.Count == 0)
        {
            return new PreservationAugmentationDecision
            {
                Kind = PreservationAugmentationDecisionKind.Undecidable,
                Reason = PreservationAugmentationReason.NoAlgorithmUseStated
            };
        }

        //An algorithm already outside what the table asserts is the most urgent answer there is, and the first
        //such use in the order the caller stated them is the one named — the order FindUnreliable reports in.
        AlgorithmUse? unlistedUse = null;
        for(int i = 0; i < context.AlgorithmUses.Count; ++i)
        {
            AlgorithmReliabilityAssessment assessment = context.Constraints.Assess(context.AlgorithmUses[i], context.Instant);
            switch(assessment.Verdict)
            {
                case AlgorithmReliabilityVerdict.NoLongerReliable:
                    return new PreservationAugmentationDecision
                    {
                        Kind = PreservationAugmentationDecisionKind.AugmentNow,
                        Reason = PreservationAugmentationReason.AlgorithmNoLongerReliable,
                        TriggeringUse = assessment.Use,
                        TrustedUntil = assessment.TrustedUntil,
                        AugmentBefore = assessment.TrustedUntil is DateTimeOffset expired ? DeadlineBefore(expired, context.LeadTime) : null
                    };

                case AlgorithmReliabilityVerdict.KeySizeBelowMinimum:
                    //No instant governs this one: the key size is below the row's floor at every instant, so an
                    //"augment before" would name a deadline that was never real.
                    return new PreservationAugmentationDecision
                    {
                        Kind = PreservationAugmentationDecisionKind.AugmentNow,
                        Reason = PreservationAugmentationReason.KeySizeBelowMinimum,
                        TriggeringUse = assessment.Use,
                        TrustedUntil = assessment.TrustedUntil
                    };

                case AlgorithmReliabilityVerdict.Unknown:
                    unlistedUse ??= context.AlgorithmUses[i];
                    break;

                default:
                    break;
            }
        }

        //Nothing has expired yet, so the question becomes when the first expiry falls. A use the table lists with
        //no expiry at all schedules nothing, which is why the earliest is sought rather than assumed to exist.
        AlgorithmUse? earliestUse = null;
        DateTimeOffset? earliest = null;
        for(int i = 0; i < context.AlgorithmUses.Count; ++i)
        {
            AlgorithmReliabilityEntry? entry = context.Constraints.Find(context.AlgorithmUses[i].Algorithm);
            if(entry?.TrustedUntil is DateTimeOffset trustedUntil && (earliest is null || trustedUntil < earliest))
            {
                earliest = trustedUntil;
                earliestUse = context.AlgorithmUses[i];
            }
        }

        //A window that cannot be expressed opened before every instant this type can express, so it is open.
        if(earliest is DateTimeOffset firstExpiry
            && (DeadlineBefore(firstExpiry, context.LeadTime) is not DateTimeOffset windowOpens || windowOpens <= context.Instant))
        {
            return new PreservationAugmentationDecision
            {
                Kind = PreservationAugmentationDecisionKind.AugmentNow,
                Reason = PreservationAugmentationReason.AlgorithmWeakensWithinTheStatedLead,
                TriggeringUse = earliestUse,
                TrustedUntil = firstExpiry,
                AugmentBefore = DeadlineBefore(firstExpiry, context.LeadTime)
            };
        }

        if(unlistedUse is not null)
        {
            return new PreservationAugmentationDecision
            {
                Kind = PreservationAugmentationDecisionKind.Undecidable,
                Reason = PreservationAugmentationReason.AlgorithmNotStatedInConstraints,
                TriggeringUse = unlistedUse
            };
        }

        return new PreservationAugmentationDecision
        {
            Kind = PreservationAugmentationDecisionKind.Sound,
            Reason = earliest is null ? PreservationAugmentationReason.NoExpiryAsserted : PreservationAugmentationReason.ReliablePastTheStatedLead,
            TriggeringUse = earliestUse,
            TrustedUntil = earliest,
            AugmentBefore = earliest is DateTimeOffset expiry ? DeadlineBefore(expiry, context.LeadTime) : null
        };

        //The instant a lead before an expiry, or nothing when that instant falls before the beginning of
        //representable time. DateTimeOffset's own subtraction throws there, and a throw is the one answer this
        //function does not otherwise give: every input it cannot judge is a value. The lead is known to be
        //non-negative by the guard above, so the only way out of range is downwards.
        static DateTimeOffset? DeadlineBefore(DateTimeOffset expiry, TimeSpan lead) =>
            expiry.DateTime.Ticks >= lead.Ticks ? expiry - lead : null;
    }
}
