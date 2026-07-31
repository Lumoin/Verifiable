using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// What a preservation profile does about one item of the content
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
/// ETSI TS 119 511 V1.2.1</see> clause 6.4 requires of it.
/// </summary>
/// <remarks>
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised outcome never reads as an item the profile
/// stated. <see cref="Undecidable"/> is deliberately not the same answer as <see cref="NotApplicable"/>: the
/// first says the condition governing an item is a fact about the service that no profile carries, the second
/// says the item's own tag excludes this profile. Reading the first as the second would report a profile as
/// conformant on a question nobody asked.
/// </remarks>
public enum PreservationProfileItemOutcome
{
    /// <summary>The item has not been looked at. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The profile states what the item requires.</summary>
    Stated = 1,

    /// <summary>The item applies to this profile and the profile does not state it.</summary>
    NotStated = 2,

    /// <summary>The item's storage-model or preservation-goal tag excludes this profile, so nothing is owed.</summary>
    NotApplicable = 3,

    /// <summary>The item is conditional on a fact no profile carries, so whether it is owed cannot be decided from the profile alone.</summary>
    Undecidable = 4,

    /// <summary>The profile states the item but with a value that cannot be used — a vocabulary value this library does not name, an inverted period, an empty text.</summary>
    Unusable = 5
}


/// <summary>
/// Whether a preservation profile carries the content clause 6.4 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
/// ETSI TS 119 511 V1.2.1</see> requires.
/// </summary>
/// <remarks>
/// <para>
/// Precedence, highest first: an unmet <em>shall</em> outranks an item nobody can decide, which outranks an unmet
/// <em>should</em>, which outranks conformance. The first is the specification's own semantics — only a failed
/// obligation is non-conformance — and the middle one is this library's fail-closed addition, the same one the
/// package assessors of this wave already make: an undecided item is not a pass.
/// </para>
/// <para>
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised status never reads as a conformant profile.
/// </para>
/// </remarks>
public enum PreservationProfileConformanceStatus
{
    /// <summary>No profile has been judged. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>Every applicable item is stated.</summary>
    Conformant = 1,

    /// <summary>Every applicable obligation is stated and at least one recommendation is not.</summary>
    RecommendationUnmet = 2,

    /// <summary>Every applicable obligation is stated and at least one item cannot be decided from the profile alone.</summary>
    Undecided = 3,

    /// <summary>At least one applicable obligation is not stated, or is stated with a value that cannot be used.</summary>
    RequirementUnmet = 4
}


/// <summary>
/// What one item of clause 6.4's content requirement says about one profile: the requirement, how strongly it is
/// owed, and what the profile did about it.
/// </summary>
/// <param name="Item">Which item of the content requirement this is.</param>
/// <param name="RequirementIdentifier">The identifier the document itself gives the item, per <see cref="PreservationProfileWellKnown.RequirementIdentifierOf"/>.</param>
/// <param name="Keyword">How strongly the item is owed.</param>
/// <param name="Outcome">What the profile did about it.</param>
/// <param name="Detail">What the outcome turns on, in terms a report can present, or <see langword="null"/>.</param>
[DebuggerDisplay("PreservationProfileItemReport: {RequirementIdentifier} is {Outcome}")]
public sealed record PreservationProfileItemReport(
    PreservationProfileContentItem Item,
    string RequirementIdentifier,
    PreservationRequirementKeyword Keyword,
    PreservationProfileItemOutcome Outcome,
    string? Detail);


/// <summary>
/// What <see cref="PreservationProfileConformance.State"/> answered about one profile: one row per item of clause
/// 6.4's content requirement, and the conclusion folded out of them.
/// </summary>
/// <remarks>
/// The conclusion is a fold over the rows and never a branch over the profile, so a caller that disagrees with the
/// fold can compute its own from <see cref="Items"/> without re-reading the profile.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservationProfileConformanceReport
{
    /// <summary>The conclusion; <see cref="PreservationProfileConformanceStatus.Conformant"/> is the only clean one.</summary>
    public required PreservationProfileConformanceStatus Status { get; init; }

    /// <summary>One row per item of <see cref="PreservationProfileContentItem"/> other than its unset value, in the order the document lists them.</summary>
    public required IReadOnlyList<PreservationProfileItemReport> Items { get; init; }


    /// <summary>
    /// Finds the row for one item.
    /// </summary>
    /// <param name="item">The item to look up.</param>
    /// <returns>The row, or <see langword="null"/> when no row was produced for it.</returns>
    public PreservationProfileItemReport? FindItem(PreservationProfileContentItem item)
    {
        for(int i = 0; i < Items.Count; ++i)
        {
            if(Items[i].Item == item)
            {
                return Items[i];
            }
        }

        return null;
    }


    /// <summary>A short debugger string showing the conclusion and how many rows it was folded from.</summary>
    private string DebuggerDisplay => $"PreservationProfileConformanceReport({Status}, {Items.Count} items)";
}


/// <summary>
/// Whether a preservation evidence describes itself, per <c>OVR-6.5-09</c>, <c>OVR-9.2-04</c> and
/// <c>OVR-9.2-05</c> of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
/// ETSI TS 119 511 V1.2.1</see>.
/// </summary>
/// <remarks>
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised status never reads as an evidence that
/// described itself.
/// </remarks>
public enum PreservationEvidenceSelfDescriptionStatus
{
    /// <summary>No evidence has been judged. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The evidence states all three items <c>OVR-6.5-09</c> lists, and any it can be checked against agrees.</summary>
    SelfDescribed = 1,

    /// <summary>The evidence states some but not all three items, and what it does state agrees.</summary>
    PartlySelfDescribed = 2,

    /// <summary>The evidence carries a self-description that states none of the three items.</summary>
    NotSelfDescribed = 3,

    /// <summary>The evidence states an item that contradicts the profile it was judged against.</summary>
    DisagreesWithProfile = 4,

    /// <summary>The artifact carries no self-description at all, which is a different fact from carrying an empty one.</summary>
    NotSupplied = 5
}


/// <summary>
/// What <see cref="PreservationProfileConformance.StateSelfDescription"/> answered about one evidence artifact.
/// </summary>
/// <remarks>
/// The three flags are <c>OVR-6.5-09</c>'s items a), b) and c) one for one;
/// <see cref="StatesEvidencePolicy"/> is also what <c>OVR-9.2-04</c> asks for, and
/// <see cref="IsCryptographicallyProtected"/> is <c>OVR-9.2-05</c>. Both of the latter are recommendations, so
/// their absence is visible here and is not a failure of anything.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservationEvidenceSelfDescriptionReport
{
    /// <summary>The conclusion.</summary>
    public required PreservationEvidenceSelfDescriptionStatus Status { get; init; }

    /// <summary><c>OVR-6.5-09</c> a) — whether the evidence names the applicable preservation service.</summary>
    public required bool StatesPreservationService { get; init; }

    /// <summary><c>OVR-6.5-09</c> b) and <c>OVR-9.2-04</c> — whether the evidence names the applicable preservation evidence policy.</summary>
    public required bool StatesEvidencePolicy { get; init; }

    /// <summary><c>OVR-6.5-09</c> c) — whether the evidence names the applicable preservation profile.</summary>
    public required bool StatesPreservationProfile { get; init; }

    /// <summary><c>OVR-9.2-05</c> — whether what the evidence states about itself is covered by a time assertion of the evidence.</summary>
    public required bool IsCryptographicallyProtected { get; init; }

    /// <summary>What the evidence and the profile disagree about, in terms a report can present, or <see langword="null"/> when they do not.</summary>
    public string? Disagreement { get; init; }


    /// <summary>A short debugger string showing the conclusion and which of the three items were stated.</summary>
    private string DebuggerDisplay =>
        $"PreservationEvidenceSelfDescriptionReport({Status}, service {StatesPreservationService}, policy {StatesEvidencePolicy}, profile {StatesPreservationProfile})";
}


/// <summary>
/// The profile-content and evidence-self-description capabilities of clauses 6.4, 6.5 and 9.2 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
/// ETSI TS 119 511 V1.2.1</see>, over the profile component and the self-description record this library already
/// ships.
/// </summary>
/// <remarks>
/// <para>
/// <strong>No second profile type exists, on purpose.</strong> Every item <c>OVR-6.4-04</c> a)–j) lists, and both
/// of <c>OVR-6.4-05</c>/<c>-06</c>, is carried by <see cref="PreservationProfile"/> — the component the companion
/// protocol standard defines and a service publishes. What this document adds is the requirement grammar over that
/// content, and this class applies it; minting a second record for one concept would put two spellings of a
/// profile in one library and leave a reader to guess which a service publishes.
/// </para>
/// <para>
/// <strong>Both entry points are pure over their inputs.</strong> Nothing here reads a clock, opens anything or
/// computes a digest: a profile is judged on what it carries and an evidence artifact on the facts a caller
/// already extracted for it. A caller wanting an artifact's facts gets them from
/// <see cref="EArkEvidencePlacement"/>, which is where reading an artifact lives.
/// </para>
/// <para>
/// <strong>Two halves are honestly unreachable and are reported, not claimed.</strong> Whether a profile
/// identifier is unique <em>across a service's profiles</em> (<c>OVR-6.4-03</c>) and whether a client provides the
/// validation data (<c>OVR-6.4-04</c> c)-b's condition) are facts about a service, not about a profile; the first
/// is noted on its row and the second is
/// <see cref="PreservationProfileItemOutcome.Undecidable"/>.
/// </para>
/// </remarks>
public static class PreservationProfileConformance
{
    /// <summary>
    /// The operations that carry content a submitter supplies, and therefore the ones <c>OVR-6.4-04</c> b)-a's
    /// "supported input formats" is about.
    /// </summary>
    /// <remarks>
    /// A documented interpretation. The sentence reads "for each operation", and the five remaining operations
    /// take identifiers, a version identifier or a filter — never a format-bearing payload — so requiring an input
    /// format of them would refuse every profile a conformant service can publish. The three named here are the
    /// ones whose requests carry a preservation object, a delta or an evidence.
    /// </remarks>
    private static string[] ContentAcceptingOperations { get; } =
    [
        PreservationWellKnown.PreservePreservationObjectOperation,
        PreservationWellKnown.UpdatePreservationObjectContainerOperation,
        PreservationWellKnown.ValidateEvidenceOperation
    ];


    /// <summary>
    /// Judges one preservation profile against the content clause 6.4 requires of it.
    /// </summary>
    /// <param name="profile">The profile to judge.</param>
    /// <returns>One row per item, and the conclusion folded out of them.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="profile"/> is <see langword="null"/>.</exception>
    public static PreservationProfileConformanceReport State(PreservationProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);

        List<PreservationProfileItemReport> items =
        [
            StateUniqueIdentification(profile),
            StateIdentifier(profile),
            StateSupportedOperations(profile),
            StateSupportedInputFormats(profile),
            StateAdditionalOutputFormats(profile),
            StateEvidencePolicyReference(profile),
            StateSignatureValidationPolicyReference(profile),
            StateValidityPeriod(profile),
            StateStorageModel(profile),
            StatePreservationGoals(profile),
            StateEvidenceFormats(profile),
            StateSpecification(profile),
            StateDescription(profile),
            StateSchemeIdentifier(profile),
            StateEvidenceRetentionPeriod(profile),
            StateExpectedEvidenceDuration(profile)
        ];

        return new PreservationProfileConformanceReport
        {
            Status = Conclude(items),
            Items = items
        };
    }


    /// <summary>
    /// States whether one evidence artifact describes itself, and whether what it says agrees with the profile it
    /// is judged against.
    /// </summary>
    /// <param name="artifact">The facts already extracted for the artifact, carrying its self-description and whether a time assertion covers it.</param>
    /// <param name="profile">The profile the evidence claims to have been produced under, or <see langword="null"/> to judge the self-description on its own.</param>
    /// <returns>The report.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="artifact"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// <para>
    /// This is where the one self-description convention this wave defined meets the requirement that asked for
    /// it. The convention has one content model reachable through three carriers — an archive time-stamp's
    /// attributes, a signer's unsigned attributes and a container extension — and one standardised spelling of the
    /// same three values as attributes of the companion protocol standard's Annex H; every one of them arrives
    /// here as the same <see cref="EArkEvidenceSelfDescription"/>, so this function is written once rather than
    /// four times.
    /// </para>
    /// <para>
    /// <strong>A disagreement outranks everything else.</strong> An evidence naming a profile other than the one
    /// it is being judged against is a stronger finding than an evidence naming none, because it asserts something
    /// that is not so; it is therefore reported as its own status rather than folded into the item flags.
    /// </para>
    /// <para>
    /// <strong>What cannot be checked is not claimed.</strong> A profile that references its evidence policy
    /// without a location gives nothing to compare a stated policy identifier against, so no disagreement can be
    /// found there and none is reported.
    /// </para>
    /// </remarks>
    public static PreservationEvidenceSelfDescriptionReport StateSelfDescription(
        EArkEvidenceArtifactFacts artifact,
        PreservationProfile? profile)
    {
        ArgumentNullException.ThrowIfNull(artifact);

        if(artifact.SelfDescription is not EArkEvidenceSelfDescription selfDescription)
        {
            return new PreservationEvidenceSelfDescriptionReport
            {
                Status = PreservationEvidenceSelfDescriptionStatus.NotSupplied,
                StatesPreservationService = false,
                StatesEvidencePolicy = false,
                StatesPreservationProfile = false,
                IsCryptographicallyProtected = false
            };
        }

        bool statesService = !string.IsNullOrWhiteSpace(selfDescription.PreservationServiceIdentifier);
        bool statesPolicy = !string.IsNullOrWhiteSpace(selfDescription.EvidencePolicyIdentifier);
        bool statesProfile = !string.IsNullOrWhiteSpace(selfDescription.PreservationProfileIdentifier);

        string? disagreement = null;
        if(profile is not null)
        {
            if(statesProfile && !string.Equals(selfDescription.PreservationProfileIdentifier, profile.ProfileIdentifier, StringComparison.Ordinal))
            {
                disagreement = string.Create(
                    CultureInfo.InvariantCulture,
                    $"The evidence names preservation profile '{selfDescription.PreservationProfileIdentifier}' and the profile it is judged against is '{profile.ProfileIdentifier}'.");
            }
            else if(statesPolicy && FindEvidencePolicyLocation(profile) is string policyLocation
                && !string.Equals(selfDescription.EvidencePolicyIdentifier, policyLocation, StringComparison.Ordinal))
            {
                disagreement = string.Create(
                    CultureInfo.InvariantCulture,
                    $"The evidence names preservation evidence policy '{selfDescription.EvidencePolicyIdentifier}' and the profile references '{policyLocation}'.");
            }
        }

        PreservationEvidenceSelfDescriptionStatus status = disagreement is not null
            ? PreservationEvidenceSelfDescriptionStatus.DisagreesWithProfile
            : (statesService, statesPolicy, statesProfile) switch
            {
                (true, true, true) => PreservationEvidenceSelfDescriptionStatus.SelfDescribed,
                (false, false, false) => PreservationEvidenceSelfDescriptionStatus.NotSelfDescribed,
                _ => PreservationEvidenceSelfDescriptionStatus.PartlySelfDescribed
            };

        return new PreservationEvidenceSelfDescriptionReport
        {
            Status = status,
            StatesPreservationService = statesService,
            StatesEvidencePolicy = statesPolicy,
            StatesPreservationProfile = statesProfile,
            IsCryptographicallyProtected = artifact.SelfDescriptionIsProtected,
            Disagreement = disagreement
        };


        //Finds where a profile says its preservation evidence policy is to be found, which is the one value a
        //stated policy identifier can be compared against. Kept beside its only caller.
        static string? FindEvidencePolicyLocation(PreservationProfile profile)
        {
            for(int i = 0; i < profile.Policies.Count; ++i)
            {
                PreservationPolicyReference policy = profile.Policies[i];
                if(string.Equals(policy.PolicyType, PreservationWellKnown.PreservationEvidencePolicyType, StringComparison.Ordinal)
                    && !string.IsNullOrWhiteSpace(policy.PolicyLocation))
                {
                    return policy.PolicyLocation;
                }
            }

            return null;
        }
    }


    /// <summary>Folds the item rows into the conclusion, per the precedence documented on <see cref="PreservationProfileConformanceStatus"/>.</summary>
    /// <param name="items">The rows.</param>
    /// <returns>The conclusion.</returns>
    private static PreservationProfileConformanceStatus Conclude(List<PreservationProfileItemReport> items)
    {
        bool undecided = false;
        bool recommendationUnmet = false;
        for(int i = 0; i < items.Count; ++i)
        {
            PreservationProfileItemReport item = items[i];
            bool missing = item.Outcome is PreservationProfileItemOutcome.NotStated or PreservationProfileItemOutcome.Unusable;
            if(missing && item.Keyword == PreservationRequirementKeyword.Shall)
            {
                return PreservationProfileConformanceStatus.RequirementUnmet;
            }

            undecided |= item.Outcome == PreservationProfileItemOutcome.Undecidable;
            recommendationUnmet |= missing && item.Keyword == PreservationRequirementKeyword.Should;
        }

        if(undecided)
        {
            return PreservationProfileConformanceStatus.Undecided;
        }

        return recommendationUnmet ? PreservationProfileConformanceStatus.RecommendationUnmet : PreservationProfileConformanceStatus.Conformant;
    }


    /// <summary>Builds one row, taking the requirement identifier and the keyword from the vocabulary rather than restating them.</summary>
    /// <param name="item">The item the row is about.</param>
    /// <param name="outcome">What the profile did about it.</param>
    /// <param name="detail">What the outcome turns on, or <see langword="null"/>.</param>
    /// <returns>The row.</returns>
    private static PreservationProfileItemReport Row(PreservationProfileContentItem item, PreservationProfileItemOutcome outcome, string? detail = null) =>
        new(item, PreservationProfileWellKnown.RequirementIdentifierOf(item), PreservationProfileWellKnown.KeywordOf(item), outcome, detail);


    /// <summary><c>OVR-6.4-03</c> — the profile is uniquely identified.</summary>
    /// <param name="profile">The profile.</param>
    /// <returns>The row.</returns>
    private static PreservationProfileItemReport StateUniqueIdentification(PreservationProfile profile) =>
        string.IsNullOrWhiteSpace(profile.ProfileIdentifier)
            ? Row(PreservationProfileContentItem.UniqueIdentification, PreservationProfileItemOutcome.NotStated, "The profile carries no identifier to be unique.")
            : Row(
                PreservationProfileContentItem.UniqueIdentification,
                PreservationProfileItemOutcome.Stated,
                "Uniqueness across the profiles one service publishes is a fact about the service and is not decidable from one profile.");


    /// <summary><c>OVR-6.4-04</c> a) — the profile contains its unique identifier.</summary>
    /// <param name="profile">The profile.</param>
    /// <returns>The row.</returns>
    private static PreservationProfileItemReport StateIdentifier(PreservationProfile profile) =>
        Row(
            PreservationProfileContentItem.Identifier,
            string.IsNullOrWhiteSpace(profile.ProfileIdentifier) ? PreservationProfileItemOutcome.NotStated : PreservationProfileItemOutcome.Stated);


    /// <summary><c>OVR-6.4-04</c> b) — the profile contains the supported operations of the preservation protocol.</summary>
    /// <param name="profile">The profile.</param>
    /// <returns>The row.</returns>
    private static PreservationProfileItemReport StateSupportedOperations(PreservationProfile profile)
    {
        if(profile.Operations.Count == 0)
        {
            return Row(PreservationProfileContentItem.SupportedOperations, PreservationProfileItemOutcome.NotStated);
        }

        for(int i = 0; i < profile.Operations.Count; ++i)
        {
            if(!PreservationWellKnown.IsOperationName(profile.Operations[i].Name))
            {
                return Row(
                    PreservationProfileContentItem.SupportedOperations,
                    PreservationProfileItemOutcome.Unusable,
                    string.Create(CultureInfo.InvariantCulture, $"Operation '{profile.Operations[i].Name}' is not one of the eight the preservation protocol defines."));
            }
        }

        return Row(PreservationProfileContentItem.SupportedOperations, PreservationProfileItemOutcome.Stated);
    }


    /// <summary><c>OVR-6.4-04</c> b)-a — each content-accepting operation states its supported input formats.</summary>
    /// <param name="profile">The profile.</param>
    /// <returns>The row.</returns>
    private static PreservationProfileItemReport StateSupportedInputFormats(PreservationProfile profile)
    {
        bool anyContentAccepting = false;
        for(int i = 0; i < profile.Operations.Count; ++i)
        {
            PreservationOperationDescriptor operation = profile.Operations[i];
            if(Array.IndexOf(ContentAcceptingOperations, operation.Name) < 0)
            {
                continue;
            }

            anyContentAccepting = true;
            if(operation.InputFormats.Count == 0)
            {
                return Row(
                    PreservationProfileContentItem.SupportedInputFormats,
                    PreservationProfileItemOutcome.NotStated,
                    string.Create(CultureInfo.InvariantCulture, $"Operation '{operation.Name}' accepts submitted content and states no input format."));
            }
        }

        return anyContentAccepting
            ? Row(PreservationProfileContentItem.SupportedInputFormats, PreservationProfileItemOutcome.Stated)
            : Row(
                PreservationProfileContentItem.SupportedInputFormats,
                PreservationProfileItemOutcome.NotApplicable,
                "The profile announces no operation that accepts submitted content.");
    }


    /// <summary><c>OVR-6.4-04</c> b)-b — additional output formats, where output differing from the input and evidence formats is supported.</summary>
    /// <param name="profile">The profile.</param>
    /// <returns>The row.</returns>
    private static PreservationProfileItemReport StateAdditionalOutputFormats(PreservationProfile profile)
    {
        for(int i = 0; i < profile.Operations.Count; ++i)
        {
            if(profile.Operations[i].OutputFormats.Count > 0)
            {
                return Row(PreservationProfileContentItem.AdditionalOutputFormats, PreservationProfileItemOutcome.Stated);
            }
        }

        return Row(
            PreservationProfileContentItem.AdditionalOutputFormats,
            PreservationProfileItemOutcome.NotApplicable,
            "No operation announces an output format, which is how a profile states that the condition does not hold.");
    }


    /// <summary><c>OVR-6.4-04</c> c)-a — the reference to the preservation evidence policy.</summary>
    /// <param name="profile">The profile.</param>
    /// <returns>The row.</returns>
    private static PreservationProfileItemReport StateEvidencePolicyReference(PreservationProfile profile) =>
        Row(
            PreservationProfileContentItem.EvidencePolicyReference,
            HasPolicyOfType(profile, PreservationWellKnown.PreservationEvidencePolicyType)
                ? PreservationProfileItemOutcome.Stated
                : PreservationProfileItemOutcome.NotStated);


    /// <summary><c>OVR-6.4-04</c> c)-b — the reference to the signature validation policy, where the client does not provide the validation data.</summary>
    /// <param name="profile">The profile.</param>
    /// <returns>The row.</returns>
    private static PreservationProfileItemReport StateSignatureValidationPolicyReference(PreservationProfile profile)
    {
        if(!StatesGoal(profile, PreservationWellKnown.DigitalSignatureGoal))
        {
            return Row(
                PreservationProfileContentItem.SignatureValidationPolicyReference,
                PreservationProfileItemOutcome.NotApplicable,
                "The item is tagged for the preservation of digital signatures and this profile announces no such goal.");
        }

        return HasPolicyOfType(profile, PreservationWellKnown.SignatureValidationPolicyType)
            ? Row(PreservationProfileContentItem.SignatureValidationPolicyReference, PreservationProfileItemOutcome.Stated)
            : Row(
                PreservationProfileContentItem.SignatureValidationPolicyReference,
                PreservationProfileItemOutcome.Undecidable,
                "Whether the client provides the validation data is a fact about the service, so a profile that references no signature validation policy cannot be judged from the profile alone.");
    }


    /// <summary><c>OVR-6.4-04</c> d) — the validity period with its activation instant.</summary>
    /// <param name="profile">The profile.</param>
    /// <returns>The row.</returns>
    private static PreservationProfileItemReport StateValidityPeriod(PreservationProfile profile) =>
        profile.ValidityPeriod.ValidUntil is DateTimeOffset validUntil && validUntil < profile.ValidityPeriod.ValidFrom
            ? Row(
                PreservationProfileContentItem.ValidityPeriod,
                PreservationProfileItemOutcome.Unusable,
                "The profile ceases to be active before it becomes active.")
            : Row(PreservationProfileContentItem.ValidityPeriod, PreservationProfileItemOutcome.Stated);


    /// <summary><c>OVR-6.4-04</c> e) — the preservation storage model.</summary>
    /// <param name="profile">The profile.</param>
    /// <returns>The row.</returns>
    private static PreservationProfileItemReport StateStorageModel(PreservationProfile profile) => profile.StorageModel switch
    {
        null or "" => Row(PreservationProfileContentItem.StorageModel, PreservationProfileItemOutcome.NotStated),
        string model when PreservationWellKnown.IsStorageModel(model) => Row(PreservationProfileContentItem.StorageModel, PreservationProfileItemOutcome.Stated),
        string model => Row(
            PreservationProfileContentItem.StorageModel,
            PreservationProfileItemOutcome.Unusable,
            string.Create(CultureInfo.InvariantCulture, $"'{model}' is not one of the three storage models clause 4.1 defines."))
    };


    /// <summary><c>OVR-6.4-04</c> f) — the preservation goals.</summary>
    /// <param name="profile">The profile.</param>
    /// <returns>The row.</returns>
    private static PreservationProfileItemReport StatePreservationGoals(PreservationProfile profile)
    {
        if(profile.PreservationGoals.Count == 0)
        {
            return Row(PreservationProfileContentItem.PreservationGoals, PreservationProfileItemOutcome.NotStated);
        }

        for(int i = 0; i < profile.PreservationGoals.Count; ++i)
        {
            if(!PreservationWellKnown.IsPreservationGoal(profile.PreservationGoals[i]))
            {
                return Row(
                    PreservationProfileContentItem.PreservationGoals,
                    PreservationProfileItemOutcome.Unusable,
                    string.Create(CultureInfo.InvariantCulture, $"'{profile.PreservationGoals[i]}' is not one of the goals clause 4.2 defines."));
            }
        }

        return Row(PreservationProfileContentItem.PreservationGoals, PreservationProfileItemOutcome.Stated);
    }


    /// <summary><c>OVR-6.4-04</c> g) — all supported evidence formats.</summary>
    /// <param name="profile">The profile.</param>
    /// <returns>The row.</returns>
    private static PreservationProfileItemReport StateEvidenceFormats(PreservationProfile profile)
    {
        if(profile.EvidenceFormats.Count == 0)
        {
            return Row(PreservationProfileContentItem.EvidenceFormats, PreservationProfileItemOutcome.NotStated);
        }

        for(int i = 0; i < profile.EvidenceFormats.Count; ++i)
        {
            //A format outside the registered ones is legal — the requirement asks for all supported formats, not
            //for formats from a closed list — so it is reported beside the row rather than refused.
            if(!PreservationFormatWellKnown.IsEvidenceFormat(profile.EvidenceFormats[i].FormatId))
            {
                return Row(
                    PreservationProfileContentItem.EvidenceFormats,
                    PreservationProfileItemOutcome.Stated,
                    string.Create(CultureInfo.InvariantCulture, $"Evidence format '{profile.EvidenceFormats[i].FormatId}' is not one the companion protocol standard's Annex A.2 registers."));
            }
        }

        return Row(PreservationProfileContentItem.EvidenceFormats, PreservationProfileItemOutcome.Stated);
    }


    /// <summary><c>OVR-6.4-04</c> h) — a specification referring to a publicly available description of the profile.</summary>
    /// <param name="profile">The profile.</param>
    /// <returns>The row.</returns>
    private static PreservationProfileItemReport StateSpecification(PreservationProfile profile) =>
        Row(
            PreservationProfileContentItem.Specification,
            profile.Specifications.Count > 0 ? PreservationProfileItemOutcome.Stated : PreservationProfileItemOutcome.NotApplicable);


    /// <summary><c>OVR-6.4-04</c> i) — a description in a human understandable language.</summary>
    /// <param name="profile">The profile.</param>
    /// <returns>The row.</returns>
    private static PreservationProfileItemReport StateDescription(PreservationProfile profile)
    {
        if(profile.Descriptions.Count == 0)
        {
            return Row(PreservationProfileContentItem.Description, PreservationProfileItemOutcome.NotStated);
        }

        for(int i = 0; i < profile.Descriptions.Count; ++i)
        {
            if(string.IsNullOrWhiteSpace(profile.Descriptions[i].Text))
            {
                return Row(
                    PreservationProfileContentItem.Description,
                    PreservationProfileItemOutcome.Unusable,
                    "A description carries no text.");
            }
        }

        return Row(PreservationProfileContentItem.Description, PreservationProfileItemOutcome.Stated);
    }


    /// <summary><c>OVR-6.4-04</c> j) — an identifier referring to the related preservation scheme's description.</summary>
    /// <param name="profile">The profile.</param>
    /// <returns>The row.</returns>
    private static PreservationProfileItemReport StateSchemeIdentifier(PreservationProfile profile) => profile.SchemeIdentifier switch
    {
        null or "" => Row(PreservationProfileContentItem.SchemeIdentifier, PreservationProfileItemOutcome.NotApplicable),
        string scheme when PreservationWellKnown.IsSchemeIdentifier(scheme) => Row(PreservationProfileContentItem.SchemeIdentifier, PreservationProfileItemOutcome.Stated),
        string scheme => Row(
            PreservationProfileContentItem.SchemeIdentifier,
            PreservationProfileItemOutcome.Stated,
            string.Create(CultureInfo.InvariantCulture, $"Scheme '{scheme}' is not one of the four the companion protocol standard's Annex F defines, which the item permits."))
    };


    /// <summary><c>OVR-6.4-05</c> — the preservation evidence retention period, for a service with temporary storage.</summary>
    /// <param name="profile">The profile.</param>
    /// <returns>The row.</returns>
    private static PreservationProfileItemReport StateEvidenceRetentionPeriod(PreservationProfile profile) =>
        !PreservationProfileWellKnown.AppliesUnderStorageModel(PreservationProfileContentItem.EvidenceRetentionPeriod, profile.StorageModel)
            ? Row(PreservationProfileContentItem.EvidenceRetentionPeriod, PreservationProfileItemOutcome.NotApplicable)
            : Row(
                PreservationProfileContentItem.EvidenceRetentionPeriod,
                string.IsNullOrWhiteSpace(profile.PreservationEvidenceRetentionPeriod) ? PreservationProfileItemOutcome.NotStated : PreservationProfileItemOutcome.Stated);


    /// <summary><c>OVR-6.4-06</c> — the expected evidence duration, for a service with temporary storage or without storage.</summary>
    /// <param name="profile">The profile.</param>
    /// <returns>The row.</returns>
    private static PreservationProfileItemReport StateExpectedEvidenceDuration(PreservationProfile profile) =>
        !PreservationProfileWellKnown.AppliesUnderStorageModel(PreservationProfileContentItem.ExpectedEvidenceDuration, profile.StorageModel)
            ? Row(PreservationProfileContentItem.ExpectedEvidenceDuration, PreservationProfileItemOutcome.NotApplicable)
            : Row(
                PreservationProfileContentItem.ExpectedEvidenceDuration,
                string.IsNullOrWhiteSpace(profile.ExpectedEvidenceDuration) ? PreservationProfileItemOutcome.NotStated : PreservationProfileItemOutcome.Stated);


    /// <summary>Determines whether a profile references a policy of one type.</summary>
    /// <param name="profile">The profile.</param>
    /// <param name="policyType">The type to look for.</param>
    /// <returns><see langword="true"/> when at least one policy reference states the type.</returns>
    private static bool HasPolicyOfType(PreservationProfile profile, string policyType)
    {
        for(int i = 0; i < profile.Policies.Count; ++i)
        {
            if(string.Equals(profile.Policies[i].PolicyType, policyType, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>Determines whether a profile announces one preservation goal.</summary>
    /// <param name="profile">The profile.</param>
    /// <param name="goal">The goal to look for.</param>
    /// <returns><see langword="true"/> when the profile announces the goal.</returns>
    private static bool StatesGoal(PreservationProfile profile, string goal)
    {
        for(int i = 0; i < profile.PreservationGoals.Count; ++i)
        {
            if(string.Equals(profile.PreservationGoals[i], goal, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
