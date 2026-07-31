using System;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The keyword a requirement of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
/// ETSI TS 119 511 V1.2.1</see> is stated with, which decides whether a departure from it is a failure or a
/// reported deviation.
/// </summary>
/// <remarks>
/// <see cref="NotStated"/> occupies zero so a default-initialised keyword never reads as an obligation that was
/// met or as one that may be skipped.
/// </remarks>
public enum PreservationRequirementKeyword
{
    /// <summary>No keyword has been stated. The value of an unset field, by design.</summary>
    NotStated = 0,

    /// <summary>The requirement is stated with <em>shall</em>: a profile that does not satisfy it is not conformant.</summary>
    Shall = 1,

    /// <summary>The requirement is stated with <em>should</em>: a profile that does not satisfy it is conformant and the departure is reported.</summary>
    Should = 2,

    /// <summary>The requirement is stated with <em>may</em>: nothing is owed either way, and the item's absence is not a departure.</summary>
    May = 3
}


/// <summary>
/// One item of the content a preservation profile is required to carry, per <c>OVR-6.4-03</c>, <c>OVR-6.4-04</c>
/// a)–j), <c>OVR-6.4-05</c> and <c>OVR-6.4-06</c> of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
/// ETSI TS 119 511 V1.2.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// The two sub-items of <c>OVR-6.4-04</c> b) and the two of c) are items of their own here, because each carries
/// its own obligation — one of the four is unconditional, two are conditional and one is tagged for the
/// preservation of digital signatures only. Their spelling follows the document's own: clauses 4.3.4 and 4.3.5
/// refer to the sub-items of c) as "<c>OVR-6.4-04</c> c)-a" and "<c>OVR-6.4-04</c> c)-b", and b)'s sub-items are
/// spelled by the same grammar.
/// </para>
/// <para>
/// <see cref="NotStated"/> occupies zero so a default-initialised item names no requirement.
/// </para>
/// </remarks>
public enum PreservationProfileContentItem
{
    /// <summary>No item has been stated. The value of an unset field, by design.</summary>
    NotStated = 0,

    /// <summary><c>OVR-6.4-03</c> — shall: the profile is uniquely identified.</summary>
    UniqueIdentification = 1,

    /// <summary><c>OVR-6.4-04</c> a) — shall: the profile contains the identifier which uniquely identifies it.</summary>
    Identifier = 2,

    /// <summary><c>OVR-6.4-04</c> b) — shall: the profile contains the supported operations of the preservation protocol.</summary>
    SupportedOperations = 3,

    /// <summary><c>OVR-6.4-04</c> b)-a — shall: each supported operation contains the supported input formats.</summary>
    SupportedInputFormats = 4,

    /// <summary><c>OVR-6.4-04</c> b)-b — conditional shall: additional output formats, where output differing from the input and evidence formats is supported.</summary>
    AdditionalOutputFormats = 5,

    /// <summary><c>OVR-6.4-04</c> c)-a — shall: the set of applicable technical policies contains the reference to the preservation evidence policy of clause 6.5.</summary>
    EvidencePolicyReference = 6,

    /// <summary><c>OVR-6.4-04</c> c)-b — conditional shall, tagged for the preservation of digital signatures: the reference to the signature validation policy of clause 6.6, where the client does not provide the validation data.</summary>
    SignatureValidationPolicyReference = 7,

    /// <summary><c>OVR-6.4-04</c> d) — shall: the validity period, containing the instant from which the profile is active and optionally the instant until which it is.</summary>
    ValidityPeriod = 8,

    /// <summary><c>OVR-6.4-04</c> e) — shall: the preservation storage model.</summary>
    StorageModel = 9,

    /// <summary><c>OVR-6.4-04</c> f) — shall: the preservation goals.</summary>
    PreservationGoals = 10,

    /// <summary><c>OVR-6.4-04</c> g) — shall: all supported evidence formats.</summary>
    EvidenceFormats = 11,

    /// <summary><c>OVR-6.4-04</c> h) — may: a specification referring to a publicly available description of the profile.</summary>
    Specification = 12,

    /// <summary><c>OVR-6.4-04</c> i) — shall: a description of the profile in a human understandable language, which may be in more than one.</summary>
    Description = 13,

    /// <summary><c>OVR-6.4-04</c> j) — may: an identifier referring to a publicly available description of the related preservation scheme.</summary>
    SchemeIdentifier = 14,

    /// <summary><c>OVR-6.4-05</c> — shall, tagged for temporary storage: the preservation evidence retention period.</summary>
    EvidenceRetentionPeriod = 15,

    /// <summary><c>OVR-6.4-06</c> — should, tagged for temporary storage and for no storage: the expected evidence duration.</summary>
    ExpectedEvidenceDuration = 16
}


/// <summary>
/// The identifiers and the requirement grammar
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
/// ETSI TS 119 511 V1.2.1</see> states about a preservation profile and about a preservation service's own
/// documentation.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why this is a vocabulary and not a second profile type.</strong> The content <c>OVR-6.4-04</c> lists is
/// carried by <see cref="PreservationProfile"/>, the component the companion protocol standard defines and a
/// service actually publishes; a second record for the same concept would put two spellings of one profile in one
/// library. What this document states that the companion does not is the requirement grammar over that content —
/// which item is owed with which keyword under which storage model — and its own documentation identifiers, and
/// those are what this class carries. <see cref="PreservationProfileConformance"/> is where the grammar is
/// applied.
/// </para>
/// <para>
/// <strong>Comparison is ordinal and case-sensitive</strong>, as everywhere else in this wave's vocabularies: an
/// object identifier differing in nothing but case is a different object identifier, and folding case would admit
/// a documentation claim a conforming reader does not recognise.
/// </para>
/// </remarks>
public static class PreservationProfileWellKnown
{
    /// <summary>
    /// The object identifier clause 4.3.2 states for a service conforming to this document's normative
    /// requirements <em>except</em> those of Annex A — <c>itu-t(0) identified-organization(4) etsi(0)
    /// pres-service-policies(19511) policy-identifiers(1) main(1)</c>.
    /// </summary>
    public static string ServicePolicyIdentifier { get; } = "0.4.0.19511.1.1";

    /// <summary>
    /// The object identifier clause 4.3.2 states for a service conforming to this document's normative
    /// requirements <em>including</em> those of Annex A, the qualified preservation service for qualified
    /// electronic signatures — <c>itu-t(0) identified-organization(4) etsi(0) pres-service-policies(19511)
    /// policy-identifiers(1) qualified(2)</c>.
    /// </summary>
    public static string QualifiedServicePolicyIdentifier { get; } = "0.4.0.19511.1.2";


    /// <summary>
    /// Determines whether an object identifier is one of the two this document reserves for a preservation
    /// service's documentation.
    /// </summary>
    /// <param name="objectIdentifier">The dotted-decimal identifier to test, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the identifier is either of the two clause 4.3.2 states.</returns>
    public static bool IsServicePolicyIdentifier(string? objectIdentifier) =>
        string.Equals(objectIdentifier, ServicePolicyIdentifier, StringComparison.Ordinal)
        || string.Equals(objectIdentifier, QualifiedServicePolicyIdentifier, StringComparison.Ordinal);


    /// <summary>
    /// Determines whether an object identifier is the one claiming conformance including Annex A.
    /// </summary>
    /// <param name="objectIdentifier">The dotted-decimal identifier to test, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the identifier is the qualified one of clause 4.3.2.</returns>
    public static bool IsQualifiedServicePolicyIdentifier(string? objectIdentifier) =>
        string.Equals(objectIdentifier, QualifiedServicePolicyIdentifier, StringComparison.Ordinal);


    /// <summary>
    /// States the requirement identifier the document itself gives one item of a profile's content — the value a
    /// requirements matrix keys its row on.
    /// </summary>
    /// <param name="item">The item.</param>
    /// <returns>The identifier text, verbatim in the document's own grammar; the empty string for <see cref="PreservationProfileContentItem.NotStated"/>.</returns>
    public static string RequirementIdentifierOf(PreservationProfileContentItem item) => item switch
    {
        PreservationProfileContentItem.UniqueIdentification => "OVR-6.4-03",
        PreservationProfileContentItem.Identifier => "OVR-6.4-04 a)",
        PreservationProfileContentItem.SupportedOperations => "OVR-6.4-04 b)",
        PreservationProfileContentItem.SupportedInputFormats => "OVR-6.4-04 b)-a",
        PreservationProfileContentItem.AdditionalOutputFormats => "OVR-6.4-04 b)-b",
        PreservationProfileContentItem.EvidencePolicyReference => "OVR-6.4-04 c)-a",
        PreservationProfileContentItem.SignatureValidationPolicyReference => "OVR-6.4-04 c)-b",
        PreservationProfileContentItem.ValidityPeriod => "OVR-6.4-04 d)",
        PreservationProfileContentItem.StorageModel => "OVR-6.4-04 e)",
        PreservationProfileContentItem.PreservationGoals => "OVR-6.4-04 f)",
        PreservationProfileContentItem.EvidenceFormats => "OVR-6.4-04 g)",
        PreservationProfileContentItem.Specification => "OVR-6.4-04 h)",
        PreservationProfileContentItem.Description => "OVR-6.4-04 i)",
        PreservationProfileContentItem.SchemeIdentifier => "OVR-6.4-04 j)",
        PreservationProfileContentItem.EvidenceRetentionPeriod => "OVR-6.4-05",
        PreservationProfileContentItem.ExpectedEvidenceDuration => "OVR-6.4-06",
        _ => string.Empty
    };


    /// <summary>
    /// States the keyword one item of a profile's content is required with.
    /// </summary>
    /// <param name="item">The item.</param>
    /// <returns>The keyword; <see cref="PreservationRequirementKeyword.NotStated"/> for <see cref="PreservationProfileContentItem.NotStated"/>.</returns>
    /// <remarks>
    /// A conditional obligation keeps the keyword its own sentence uses — the condition decides whether the item
    /// applies at all, which <see cref="IsConditional"/> and <see cref="AppliesUnderStorageModel"/> answer, not
    /// how strongly it is owed once it does.
    /// </remarks>
    public static PreservationRequirementKeyword KeywordOf(PreservationProfileContentItem item) => item switch
    {
        PreservationProfileContentItem.Specification => PreservationRequirementKeyword.May,
        PreservationProfileContentItem.SchemeIdentifier => PreservationRequirementKeyword.May,
        PreservationProfileContentItem.ExpectedEvidenceDuration => PreservationRequirementKeyword.Should,
        PreservationProfileContentItem.NotStated => PreservationRequirementKeyword.NotStated,
        _ => PreservationRequirementKeyword.Shall
    };


    /// <summary>
    /// Determines whether an item's obligation is stated with a condition, so that a profile not meeting the
    /// condition owes nothing.
    /// </summary>
    /// <param name="item">The item.</param>
    /// <returns><see langword="true"/> for the two sub-items whose sentences carry a condition.</returns>
    public static bool IsConditional(PreservationProfileContentItem item) =>
        item is PreservationProfileContentItem.AdditionalOutputFormats
            or PreservationProfileContentItem.SignatureValidationPolicyReference;


    /// <summary>
    /// Determines whether an item binds a profile announcing one storage model, per the
    /// <c>[WST]</c>/<c>[WTS]</c>/<c>[WOS]</c> tags clause 3.4 defines.
    /// </summary>
    /// <param name="item">The item.</param>
    /// <param name="storageModel">The storage model the profile announces, as <see cref="PreservationWellKnown.IsStorageModel"/> names it.</param>
    /// <returns><see langword="true"/> when the item's tags admit the storage model; <see langword="true"/> for every untagged item.</returns>
    /// <remarks>
    /// Only two of the sixteen items carry a storage-model tag: the retention period is tagged for temporary
    /// storage and the expected evidence duration for temporary storage and for no storage. A storage model this
    /// library does not name admits neither, which is the fail-closed reading — an unrecognised model is not
    /// evidence that a tagged requirement does not apply.
    /// </remarks>
    public static bool AppliesUnderStorageModel(PreservationProfileContentItem item, string? storageModel) => item switch
    {
        PreservationProfileContentItem.EvidenceRetentionPeriod =>
            string.Equals(storageModel, PreservationWellKnown.WithTemporaryStorageModel, StringComparison.Ordinal),
        PreservationProfileContentItem.ExpectedEvidenceDuration =>
            string.Equals(storageModel, PreservationWellKnown.WithTemporaryStorageModel, StringComparison.Ordinal)
            || string.Equals(storageModel, PreservationWellKnown.WithoutStorageModel, StringComparison.Ordinal),
        _ => true
    };
}
