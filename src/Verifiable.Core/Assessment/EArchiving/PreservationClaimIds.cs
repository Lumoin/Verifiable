namespace Verifiable.Core.Assessment.EArchiving;

/// <summary>
/// The <see cref="ClaimId"/> allocation for the two preservation-service specifications: the policy and
/// security requirements of ETSI TS 119 511 V1.2.1, stated with its own <c>OVR-</c> and <c>PRP-</c> identifier
/// grammar, and the protocol of ETSI TS 119 512 V1.2.1, whose own identifiers are its eight operation names and
/// its result codes.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The code ranges below are STABLE</strong> on the same terms as
/// <see cref="EArkClaimIds"/>, whose remarks carry the whole eArchiving band map: a code allocated here is
/// never reassigned, and a consuming system may key a requirements-to-code graph on the integer code alone.
/// </para>
/// <list type="table">
///   <item><description><c>2 400 000</c>–<c>2 499 999</c>: TS 119 511 <c>OVR-</c> requirements. A requirement
///     <c>OVR-&lt;major&gt;.&lt;minor&gt;-&lt;sequence&gt;</c> takes the code
///     <c>2 400 000 + major × 10 000 + minor × 100 + sequence</c>, a clause with no minor part counting as
///     minor zero (<c>OVR-5-01</c> is <c>2 450 001</c>). The Annex A requirements, whose clause is a letter,
///     take <c>2 499 000 + ordinal</c> in the order the annex states them.</description></item>
///   <item><description><c>2 500 000</c>–<c>2 599 999</c>: TS 119 511 <c>PRP-</c> requirements, by the same
///     clause arithmetic against the <c>2 500 000</c> start (<c>PRP-8.1-01</c> is <c>2 580 101</c>).</description></item>
///   <item><description><c>2 600 000</c>–<c>2 699 999</c>: TS 119 512 operations, <c>2 600 000 + ordinal</c> in
///     clause 5.3.2–5.3.9 order.</description></item>
///   <item><description><c>2 700 000</c>–<c>2 799 999</c>: TS 119 512 result codes, <c>2 700 000 + ordinal</c>,
///     the four codes common to the operations first and the operation-specific ones after.</description></item>
/// </list>
/// <para>
/// <strong>An allocation is not an implementation.</strong> TS 119 511 delegates roughly a third of its
/// identifiers to a general policy standard and states many others as obligations on a service organization
/// rather than on a computation. Every identifier is allocated a code all the same, so a requirements matrix
/// and a consuming graph can name every row; which of them a rule list issues is the business of the validation
/// profiles.
/// </para>
/// <para>
/// Sources:
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1</see>
/// and
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1</see>.
/// The bracketed tags in the summaries below are the specification's own storage-model and preservation-goal
/// tags — <c>[WST]</c> with storage of temporary or permanent objects, <c>[WTS]</c> with temporary storage,
/// <c>[WOS]</c> without storage, <c>[PGD]</c> preservation of general data, <c>[PDS]</c> preservation of
/// digital signatures, <c>[AUG]</c> augmentation of externally produced evidence — and <c>[CONDITIONAL]</c>
/// marks a requirement that only applies once its own precondition holds.
/// </para>
/// </remarks>
public static class PreservationClaimIds
{
    /// <summary>The first code of the band holding the TS 119 511 <c>OVR-</c> requirements, <c>2 400 000</c>.</summary>
    public static int OverallRequirementRangeStart { get; } = 2_400_000;

    /// <summary>The last code of the band holding the TS 119 511 <c>OVR-</c> requirements, <c>2 499 999</c>.</summary>
    public static int OverallRequirementRangeEnd { get; } = 2_499_999;

    /// <summary>The first code of the sub-band holding the TS 119 511 Annex A requirements, <c>2 499 000</c>.</summary>
    public static int OverallAnnexRangeStart { get; } = 2_499_000;

    /// <summary>The first code of the band holding the TS 119 511 <c>PRP-</c> requirements, <c>2 500 000</c>.</summary>
    public static int ProtocolRequirementRangeStart { get; } = 2_500_000;

    /// <summary>The last code of the band holding the TS 119 511 <c>PRP-</c> requirements, <c>2 599 999</c>.</summary>
    public static int ProtocolRequirementRangeEnd { get; } = 2_599_999;

    /// <summary>The first code of the band holding the TS 119 512 operations, <c>2 600 000</c>.</summary>
    public static int ProtocolOperationRangeStart { get; } = 2_600_000;

    /// <summary>The last code of the band holding the TS 119 512 operations, <c>2 699 999</c>.</summary>
    public static int ProtocolOperationRangeEnd { get; } = 2_699_999;

    /// <summary>The first code of the band holding the TS 119 512 result codes, <c>2 700 000</c>.</summary>
    public static int ProtocolResultRangeStart { get; } = 2_700_000;

    /// <summary>The last code of the band holding the TS 119 512 result codes, <c>2 799 999</c>.</summary>
    public static int ProtocolResultRangeEnd { get; } = 2_799_999;


    /// <summary><c>OVR-5-01</c> — shall: the risk-assessment requirements of the general policy standard apply. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 5</see>.</summary>
    public static ClaimId Ovr5Item01 { get; } = ClaimId.Create(2_450_001, "OVR-5-01");

    /// <summary><c>OVR-6.1-01</c> — shall: the general policy standard's clause 6.1 applies. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.1</see>.</summary>
    public static ClaimId Ovr61Item01 { get; } = ClaimId.Create(2_460_101, "OVR-6.1-01");

    /// <summary><c>OVR-6.1-02</c> — should: the practice statement lists and briefly describes the supported preservation service policies. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.1</see>.</summary>
    public static ClaimId Ovr61Item02 { get; } = ClaimId.Create(2_460_102, "OVR-6.1-02");

    /// <summary><c>OVR-6.1-03</c> — shall: the practice statement lists the supported preservation profiles. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.1</see>.</summary>
    public static ClaimId Ovr61Item03 { get; } = ClaimId.Create(2_460_103, "OVR-6.1-03");

    /// <summary><c>OVR-6.1-04</c> — shall: the practice statement states how the preservation goals are achieved. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.1</see>.</summary>
    public static ClaimId Ovr61Item04 { get; } = ClaimId.Create(2_460_104, "OVR-6.1-04");

    /// <summary><c>OVR-6.1-05</c> — shall: the practice statement defines how availability of submitted objects and evidences is achieved. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.1</see>.</summary>
    public static ClaimId Ovr61Item05 { get; } = ClaimId.Create(2_460_105, "OVR-6.1-05");

    /// <summary><c>OVR-6.1-06</c> — shall: the practice statement identifies the obligations of external organizations. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.1</see>.</summary>
    public static ClaimId Ovr61Item06 { get; } = ClaimId.Create(2_460_106, "OVR-6.1-06");

    /// <summary><c>OVR-6.1-07</c> <c>[WST]</c> — shall: the practice statement details the export-import package request process. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.1</see>.</summary>
    public static ClaimId Ovr61Item07 { get; } = ClaimId.Create(2_460_107, "OVR-6.1-07");

    /// <summary><c>OVR-6.1-08</c> <c>[WST]</c> — shall: the practice statement specifies how export-import packages are produced. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.1</see>.</summary>
    public static ClaimId Ovr61Item08 { get; } = ClaimId.Create(2_460_108, "OVR-6.1-08");

    /// <summary><c>OVR-6.1-09</c> <c>[WST]</c> — shall: the practice statement specifies what happens to the data at the end of the preservation period. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.1</see>.</summary>
    public static ClaimId Ovr61Item09 { get; } = ClaimId.Create(2_460_109, "OVR-6.1-09");

    /// <summary><c>OVR-6.2-01</c> — shall: the general policy standard's clause 6.2 applies. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.2</see>.</summary>
    public static ClaimId Ovr62Item01 { get; } = ClaimId.Create(2_460_201, "OVR-6.2-01");

    /// <summary><c>OVR-6.2-02</c> — shall: the terms and conditions list all supported preservation service policies. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.2</see>.</summary>
    public static ClaimId Ovr62Item02 { get; } = ClaimId.Create(2_460_202, "OVR-6.2-02");

    /// <summary><c>OVR-6.2-03</c> — shall: the terms and conditions state where the supported-profile information is found. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.2</see>.</summary>
    public static ClaimId Ovr62Item03 { get; } = ClaimId.Create(2_460_203, "OVR-6.2-03");

    /// <summary><c>OVR-6.2-04</c> <c>[CONDITIONAL]</c> — shall: when the submitter takes a role in the process, the terms and conditions state it. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.2</see>.</summary>
    public static ClaimId Ovr62Item04 { get; } = ClaimId.Create(2_460_204, "OVR-6.2-04");

    /// <summary><c>OVR-6.2-05</c> <c>[WST]</c> — shall: the terms and conditions state how an export-import package can be requested. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.2</see>.</summary>
    public static ClaimId Ovr62Item05 { get; } = ClaimId.Create(2_460_205, "OVR-6.2-05");

    /// <summary><c>OVR-6.2-06</c> <c>[PDS]</c> — shall: the terms and conditions state the strategy applied when not all validation data can be collected or verified. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.2</see>.</summary>
    public static ClaimId Ovr62Item06 { get; } = ClaimId.Create(2_460_206, "OVR-6.2-06");

    /// <summary><c>OVR-6.2-07</c> <c>[CONDITIONAL]</c> — shall: when hash-tree-renewal hash values may be submitted by the client, the terms and conditions state it. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.2</see>.</summary>
    public static ClaimId Ovr62Item07 { get; } = ClaimId.Create(2_460_207, "OVR-6.2-07");

    /// <summary><c>OVR-6.2-08</c> <c>[CONDITIONAL]</c> — shall: when only hashes of the objects may be submitted, the terms and conditions state it. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.2</see>.</summary>
    public static ClaimId Ovr62Item08 { get; } = ClaimId.Create(2_460_208, "OVR-6.2-08");

    /// <summary><c>OVR-6.3-01</c> — shall: the general policy standard's clause 6.3 applies. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.3</see>.</summary>
    public static ClaimId Ovr63Item01 { get; } = ClaimId.Create(2_460_301, "OVR-6.3-01");

    /// <summary><c>OVR-6.4-01</c> — shall: a preservation service supports at least one preservation profile. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.4</see>.</summary>
    public static ClaimId Ovr64Item01 { get; } = ClaimId.Create(2_460_401, "OVR-6.4-01");

    /// <summary><c>OVR-6.4-02</c> — may: a preservation service supports more than one profile. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.4</see>.</summary>
    public static ClaimId Ovr64Item02 { get; } = ClaimId.Create(2_460_402, "OVR-6.4-02");

    /// <summary><c>OVR-6.4-03</c> — shall: a preservation profile is uniquely identified. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.4</see>.</summary>
    public static ClaimId Ovr64Item03 { get; } = ClaimId.Create(2_460_403, "OVR-6.4-03");

    /// <summary><c>OVR-6.4-04</c> — shall, itemized a) to j): the content schema of a preservation profile, including its storage model, its goals and its supported evidence formats. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.4</see>.</summary>
    public static ClaimId Ovr64Item04 { get; } = ClaimId.Create(2_460_404, "OVR-6.4-04");

    /// <summary><c>OVR-6.4-05</c> <c>[WTS]</c> — shall: the profile contains the preservation evidence retention period. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.4</see>.</summary>
    public static ClaimId Ovr64Item05 { get; } = ClaimId.Create(2_460_405, "OVR-6.4-05");

    /// <summary><c>OVR-6.4-06</c> <c>[WTS][WOS]</c> — should: the profile contains the expected evidence duration. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.4</see>.</summary>
    public static ClaimId Ovr64Item06 { get; } = ClaimId.Create(2_460_406, "OVR-6.4-06");

    /// <summary><c>OVR-6.4-07</c> <c>[WTS][WOS]</c> — shall: the expected evidence duration is based on an estimate of cryptographic-algorithm strength. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.4</see>.</summary>
    public static ClaimId Ovr64Item07 { get; } = ClaimId.Create(2_460_407, "OVR-6.4-07");

    /// <summary><c>OVR-6.4-08</c> <c>[WTS][WOS]</c> — should: that estimate is based on the cryptographic-suites publication. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.4</see>.</summary>
    public static ClaimId Ovr64Item08 { get; } = ClaimId.Create(2_460_408, "OVR-6.4-08");

    /// <summary><c>OVR-6.4-09</c> — shall: the supported profiles are available online. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.4</see>.</summary>
    public static ClaimId Ovr64Item09 { get; } = ClaimId.Create(2_460_409, "OVR-6.4-09");

    /// <summary><c>OVR-6.4-10</c> — shall: the service publishes every profile it supports or has supported. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.4</see>.</summary>
    public static ClaimId Ovr64Item10 { get; } = ClaimId.Create(2_460_410, "OVR-6.4-10");

    /// <summary><c>OVR-6.4-11</c> <c>[WST]</c> — shall: the same profile applies for the whole preservation period. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.4</see>.</summary>
    public static ClaimId Ovr64Item11 { get; } = ClaimId.Create(2_460_411, "OVR-6.4-11");

    /// <summary><c>OVR-6.4-12</c> <c>[WTS]</c> — shall: the same profile applies for the whole retention period. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.4</see>.</summary>
    public static ClaimId Ovr64Item12 { get; } = ClaimId.Create(2_460_412, "OVR-6.4-12");

    /// <summary><c>OVR-6.4-13</c> — should: a profile does not change over time, its dynamic aspects living in the referenced policies. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.4</see>.</summary>
    public static ClaimId Ovr64Item13 { get; } = ClaimId.Create(2_460_413, "OVR-6.4-13");

    /// <summary><c>OVR-6.4-14</c> — shall: policies referenced by a profile may change over time, but every version stays retrievable. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.4</see>.</summary>
    public static ClaimId Ovr64Item14 { get; } = ClaimId.Create(2_460_414, "OVR-6.4-14");

    /// <summary><c>OVR-6.5-01</c> — may: the preservation evidence policy is in human-readable form. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.5</see>.</summary>
    public static ClaimId Ovr65Item01 { get; } = ClaimId.Create(2_460_501, "OVR-6.5-01");

    /// <summary><c>OVR-6.5-02</c> <c>[CONDITIONAL]</c> — shall: when several formats or languages exist, the policy states which one takes precedence. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.5</see>.</summary>
    public static ClaimId Ovr65Item02 { get; } = ClaimId.Create(2_460_502, "OVR-6.5-02");

    /// <summary><c>OVR-6.5-03</c> — shall: the evidence policy describes how evidence is created, including which algorithms are used. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.5</see>.</summary>
    public static ClaimId Ovr65Item03 { get; } = ClaimId.Create(2_460_503, "OVR-6.5-03");

    /// <summary><c>OVR-6.5-04</c> — should: those algorithms are chosen per the cryptographic-suites publication. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.5</see>.</summary>
    public static ClaimId Ovr65Item04 { get; } = ClaimId.Create(2_460_504, "OVR-6.5-04");

    /// <summary><c>OVR-6.5-05</c> — shall: the evidence policy describes which trust service providers may be used. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.5</see>.</summary>
    public static ClaimId Ovr65Item05 { get; } = ClaimId.Create(2_460_505, "OVR-6.5-05");

    /// <summary><c>OVR-6.5-06</c> — shall: the evidence policy describes how an evidence can be validated, including the trust anchors. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.5</see>.</summary>
    public static ClaimId Ovr65Item06 { get; } = ClaimId.Create(2_460_506, "OVR-6.5-06");

    /// <summary><c>OVR-6.5-07</c> <c>[WST][WTS]</c> — shall: the evidence policy states how evidences are augmented. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.5</see>.</summary>
    public static ClaimId Ovr65Item07 { get; } = ClaimId.Create(2_460_507, "OVR-6.5-07");

    /// <summary><c>OVR-6.5-08</c> — shall: the evidence policy describes the evidence format. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.5</see>.</summary>
    public static ClaimId Ovr65Item08 { get; } = ClaimId.Create(2_460_508, "OVR-6.5-08");

    /// <summary><c>OVR-6.5-09</c> — shall, itemized a) to c): the evidence policy states whether and how an evidence carries an explicit reference to the policy it was produced under. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.5</see>.</summary>
    public static ClaimId Ovr65Item09 { get; } = ClaimId.Create(2_460_509, "OVR-6.5-09");

    /// <summary><c>OVR-6.6-01</c> — may: the signature validation policy is in human-readable form. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.6</see>.</summary>
    public static ClaimId Ovr66Item01 { get; } = ClaimId.Create(2_460_601, "OVR-6.6-01");

    /// <summary><c>OVR-6.6-02</c> <c>[CONDITIONAL]</c> — shall: when several formats or languages exist, the policy states which one takes precedence. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.6</see>.</summary>
    public static ClaimId Ovr66Item02 { get; } = ClaimId.Create(2_460_602, "OVR-6.6-02");

    /// <summary><c>OVR-6.6-03</c> <c>[CONDITIONAL]</c> — shall: when present, the policy states the validation-material selection strategy. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.6</see>.</summary>
    public static ClaimId Ovr66Item03 { get; } = ClaimId.Create(2_460_603, "OVR-6.6-03");

    /// <summary><c>OVR-6.7-01</c> — shall: the service provides a subscriber agreement including acceptance of the terms and conditions. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.7</see>.</summary>
    public static ClaimId Ovr67Item01 { get; } = ClaimId.Create(2_460_701, "OVR-6.7-01");

    /// <summary><c>OVR-6.7-02</c> <c>[CONDITIONAL]</c> — shall: when a notification protocol exists, the agreement states whether and how it is used. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.7</see>.</summary>
    public static ClaimId Ovr67Item02 { get; } = ClaimId.Create(2_460_702, "OVR-6.7-02");

    /// <summary><c>OVR-6.7-03</c> <c>[CONDITIONAL]</c> — shall: the agreement is updated whenever a notification channel changes. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.7</see>.</summary>
    public static ClaimId Ovr67Item03 { get; } = ClaimId.Create(2_460_703, "OVR-6.7-03");

    /// <summary><c>OVR-6.7-04</c> <c>[WTS][WST]</c> — shall: the agreement states who may access the preservation objects. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.7</see>.</summary>
    public static ClaimId Ovr67Item04 { get; } = ClaimId.Create(2_460_704, "OVR-6.7-04");

    /// <summary><c>OVR-6.7-05</c> <c>[WTS][WST]</c> — shall: the agreement states who may request traces of the actions on a preservation object. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 6.7</see>.</summary>
    public static ClaimId Ovr67Item05 { get; } = ClaimId.Create(2_460_705, "OVR-6.7-05");

    /// <summary><c>OVR-7.1-01</c> — shall: the general policy standard's internal-organization clause applies. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.1</see>.</summary>
    public static ClaimId Ovr71Item01 { get; } = ClaimId.Create(2_470_101, "OVR-7.1-01");

    /// <summary><c>OVR-7.2-01</c> — shall: the general policy standard's human-resources clause applies. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.2</see>.</summary>
    public static ClaimId Ovr72Item01 { get; } = ClaimId.Create(2_470_201, "OVR-7.2-01");

    /// <summary><c>OVR-7.3-01</c> — shall: the general policy standard's asset-management clause applies. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.3</see>.</summary>
    public static ClaimId Ovr73Item01 { get; } = ClaimId.Create(2_470_301, "OVR-7.3-01");

    /// <summary><c>OVR-7.4-01</c> — shall: the general policy standard's access-control clause applies. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.4</see>.</summary>
    public static ClaimId Ovr74Item01 { get; } = ClaimId.Create(2_470_401, "OVR-7.4-01");

    /// <summary><c>OVR-7.5-01</c> — shall: the general policy standard's cryptographic-controls clause applies. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.5</see>.</summary>
    public static ClaimId Ovr75Item01 { get; } = ClaimId.Create(2_470_501, "OVR-7.5-01");

    /// <summary><c>OVR-7.5-02</c> — shall and should: preservation time-stamps come from a state-of-the-art time-stamping service. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.5</see>.</summary>
    public static ClaimId Ovr75Item02 { get; } = ClaimId.Create(2_470_502, "OVR-7.5-02");

    /// <summary><c>OVR-7.5-03</c> — should: only time-stamps verifiable through revocation information carrying a reason code are used. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.5</see>.</summary>
    public static ClaimId Ovr75Item03 { get; } = ClaimId.Create(2_470_503, "OVR-7.5-03");

    /// <summary><c>OVR-7.5-04</c> <c>[CONDITIONAL]</c> — should: when the service signs part of an evidence, its signing certificate is issued appropriately. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.5</see>.</summary>
    public static ClaimId Ovr75Item04 { get; } = ClaimId.Create(2_470_504, "OVR-7.5-04");

    /// <summary><c>OVR-7.5-05</c> <c>[CONDITIONAL]</c> — shall, itemized a) and b): the service's signing key is held in a secure cryptographic device. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.5</see>.</summary>
    public static ClaimId Ovr75Item05 { get; } = ClaimId.Create(2_470_505, "OVR-7.5-05");

    /// <summary><c>OVR-7.5-06</c> <c>[CONDITIONAL]</c> — should: the device meets item a) of the preceding requirement specifically. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.5</see>.</summary>
    public static ClaimId Ovr75Item06 { get; } = ClaimId.Create(2_470_506, "OVR-7.5-06");

    /// <summary><c>OVR-7.5-07</c> <c>[CONDITIONAL]</c> — shall: key backup copies are protected for integrity and confidentiality. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.5</see>.</summary>
    public static ClaimId Ovr75Item07 { get; } = ClaimId.Create(2_470_507, "OVR-7.5-07");

    /// <summary><c>OVR-7.6-01</c> — shall: the general policy standard's physical and environmental security clause applies. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.6</see>.</summary>
    public static ClaimId Ovr76Item01 { get; } = ClaimId.Create(2_470_601, "OVR-7.6-01");

    /// <summary><c>OVR-7.7-01</c> — shall: the general policy standard's operation-security clause applies. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.7</see>.</summary>
    public static ClaimId Ovr77Item01 { get; } = ClaimId.Create(2_470_701, "OVR-7.7-01");

    /// <summary><c>OVR-7.8-01</c> — shall: the general policy standard's network-security clause applies. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.8</see>.</summary>
    public static ClaimId Ovr78Item01 { get; } = ClaimId.Create(2_470_801, "OVR-7.8-01");

    /// <summary><c>OVR-7.8-02</c> <c>[WST]</c> — shall: storage access that changes content is routable only through the preservation service. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.8</see>.</summary>
    public static ClaimId Ovr78Item02 { get; } = ClaimId.Create(2_470_802, "OVR-7.8-02");

    /// <summary><c>OVR-7.9-01</c> — shall: the general policy standard's incident-management clause applies. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.9</see>.</summary>
    public static ClaimId Ovr79Item01 { get; } = ClaimId.Create(2_470_901, "OVR-7.9-01");

    /// <summary><c>OVR-7.10-01</c> — shall: the general policy standard's event-logging clause applies. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.10</see>.</summary>
    public static ClaimId Ovr710Item01 { get; } = ClaimId.Create(2_471_001, "OVR-7.10-01");

    /// <summary><c>OVR-7.10-02</c> — shall: the service implements event logs usable as later proofs. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.10</see>.</summary>
    public static ClaimId Ovr710Item02 { get; } = ClaimId.Create(2_471_002, "OVR-7.10-02");

    /// <summary><c>OVR-7.11-01</c> — shall: the general policy standard's business-continuity clause applies. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.11</see>.</summary>
    public static ClaimId Ovr711Item01 { get; } = ClaimId.Create(2_471_101, "OVR-7.11-01");

    /// <summary><c>OVR-7.12-01</c> — shall: the general policy standard's termination clause applies. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.12</see>.</summary>
    public static ClaimId Ovr712Item01 { get; } = ClaimId.Create(2_471_201, "OVR-7.12-01");

    /// <summary><c>OVR-7.12-02</c> <c>[WST]</c> — shall: the termination plan covers what happens to stored preservation objects. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.12</see>.</summary>
    public static ClaimId Ovr712Item02 { get; } = ClaimId.Create(2_471_202, "OVR-7.12-02");

    /// <summary><c>OVR-7.13-01</c> — shall: the general policy standard's compliance clause applies. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.13</see>.</summary>
    public static ClaimId Ovr713Item01 { get; } = ClaimId.Create(2_471_301, "OVR-7.13-01");

    /// <summary><c>OVR-7.14-01</c> — shall: for every active profile, the strength of every algorithm and parameter in use is monitored. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.14</see>.</summary>
    public static ClaimId Ovr714Item01 { get; } = ClaimId.Create(2_471_401, "OVR-7.14-01");

    /// <summary><c>OVR-7.14-02</c> <c>[WST][CONDITIONAL]</c> — shall: an algorithm or parameter used in an existing preservation object that ceases to be strong enough triggers the stated action. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.14</see>.</summary>
    public static ClaimId Ovr714Item02 { get; } = ClaimId.Create(2_471_402, "OVR-7.14-02");

    /// <summary><c>OVR-7.14-03</c> — should: the cryptographic-suites publication is considered for that evaluation. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.14</see>.</summary>
    public static ClaimId Ovr714Item03 { get; } = ClaimId.Create(2_471_403, "OVR-7.14-03");

    /// <summary><c>OVR-7.15-01</c> <c>[WST]</c> — shall: throughout the preservation period, the evidence can still achieve its preservation goal. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.15</see>.</summary>
    public static ClaimId Ovr715Item01 { get; } = ClaimId.Create(2_471_501, "OVR-7.15-01");

    /// <summary><c>OVR-7.15-02</c> <c>[WTS]</c> — shall: the same, scoped to the retention period. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.15</see>.</summary>
    public static ClaimId Ovr715Item02 { get; } = ClaimId.Create(2_471_502, "OVR-7.15-02");

    /// <summary><c>OVR-7.15-03</c> <c>[WST][WTS]</c> — shall: evidences are augmented before they can no longer achieve the goal. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.15</see>.</summary>
    public static ClaimId Ovr715Item03 { get; } = ClaimId.Create(2_471_503, "OVR-7.15-03");

    /// <summary><c>OVR-7.16-01</c> <c>[WST]</c> — shall: the client or another authorized preservation service can obtain an export-import package. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.16</see>.</summary>
    public static ClaimId Ovr716Item01 { get; } = ClaimId.Create(2_471_601, "OVR-7.16-01");

    /// <summary><c>OVR-7.16-02</c> <c>[WST]</c> — should: a standardized export-import package format is used. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.16</see>.</summary>
    public static ClaimId Ovr716Item02 { get; } = ClaimId.Create(2_471_602, "OVR-7.16-02");

    /// <summary><c>OVR-7.16-03</c> <c>[WST]</c> — shall: packages are delivered only to an authorized legal or natural person. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.16</see>.</summary>
    public static ClaimId Ovr716Item03 { get; } = ClaimId.Create(2_471_603, "OVR-7.16-03");

    /// <summary><c>OVR-7.16-04</c> <c>[WST]</c> — shall, two items: records are kept of every released package. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.16</see>.</summary>
    public static ClaimId Ovr716Item04 { get; } = ClaimId.Create(2_471_604, "OVR-7.16-04");

    /// <summary><c>OVR-7.17-01</c> — shall: the general policy standard's supply-chain clause applies. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 7.17</see>.</summary>
    public static ClaimId Ovr717Item01 { get; } = ClaimId.Create(2_471_701, "OVR-7.17-01");

    /// <summary><c>OVR-8.2-01</c> — may: the service defines a notification protocol to message subscribers. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 8.2</see>.</summary>
    public static ClaimId Ovr82Item01 { get; } = ClaimId.Create(2_480_201, "OVR-8.2-01");

    /// <summary><c>OVR-8.2-02</c> <c>[CONDITIONAL]</c> — shall: when a notification protocol exists, a referenced evidence change is notified. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 8.2</see>.</summary>
    public static ClaimId Ovr82Item02 { get; } = ClaimId.Create(2_480_202, "OVR-8.2-02");

    /// <summary><c>OVR-8.2-03</c> <c>[CONDITIONAL]</c> — shall: when a notification protocol exists, a referenced element change is notified. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 8.2</see>.</summary>
    public static ClaimId Ovr82Item03 { get; } = ClaimId.Create(2_480_203, "OVR-8.2-03");

    /// <summary><c>OVR-9.1-01</c> <c>[WOS][WTS]</c> — should not: a service without permanent storage keeps the data after the evidence has been produced. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 9.1</see>.</summary>
    public static ClaimId Ovr91Item01 { get; } = ClaimId.Create(2_490_101, "OVR-9.1-01");

    /// <summary><c>OVR-9.1-02</c> <c>[WOS][WTS][CONDITIONAL]</c> — should: when data is kept anyway, the retention is stated. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 9.1</see>.</summary>
    public static ClaimId Ovr91Item02 { get; } = ClaimId.Create(2_490_102, "OVR-9.1-02");

    /// <summary><c>OVR-9.1-03</c> <c>[WTS]</c> — shall not: an evidence is stored longer than the practice statement allows. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 9.1</see>.</summary>
    public static ClaimId Ovr91Item03 { get; } = ClaimId.Create(2_490_103, "OVR-9.1-03");

    /// <summary><c>OVR-9.2-01</c> <c>[CONDITIONAL]</c> — shall: a time-stamp token the service uses conforms to the time-stamp protocol. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 9.2</see>.</summary>
    public static ClaimId Ovr92Item01 { get; } = ClaimId.Create(2_490_201, "OVR-9.2-01");

    /// <summary><c>OVR-9.2-02</c> <c>[CONDITIONAL]</c> — should: a time-stamp token also conforms to the time-stamping profile standard. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 9.2</see>.</summary>
    public static ClaimId Ovr92Item02 { get; } = ClaimId.Create(2_490_202, "OVR-9.2-02");

    /// <summary><c>OVR-9.2-03</c> <c>[CONDITIONAL]</c> — shall: an evidence record the service uses conforms to the evidence-record specification. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 9.2</see>.</summary>
    public static ClaimId Ovr92Item03 { get; } = ClaimId.Create(2_490_203, "OVR-9.2-03");

    /// <summary><c>OVR-9.2-04</c> <c>[CONDITIONAL]</c> — should: when the evidence policy cannot be identified from the evidence itself, the evidence carries a reference to it. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 9.2</see>.</summary>
    public static ClaimId Ovr92Item04 { get; } = ClaimId.Create(2_490_204, "OVR-9.2-04");

    /// <summary><c>OVR-9.2-05</c> <c>[CONDITIONAL]</c> — should: an embedded evidence policy reference is cryptographically protected. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 9.2</see>.</summary>
    public static ClaimId Ovr92Item05 { get; } = ClaimId.Create(2_490_205, "OVR-9.2-05");

    /// <summary><c>OVR-9.3-01</c> <c>[PDS][PDS+PGD][CONDITIONAL]</c> — shall: when the client does not submit validation data, the service collects it. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 9.3</see>.</summary>
    public static ClaimId Ovr93Item01 { get; } = ClaimId.Create(2_490_301, "OVR-9.3-01");

    /// <summary><c>OVR-9.3-02</c> <c>[PDS][PDS+PGD][CONDITIONAL]</c> — should: submitted validation data is verified. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 9.3</see>.</summary>
    public static ClaimId Ovr93Item02 { get; } = ClaimId.Create(2_490_302, "OVR-9.3-02");

    /// <summary><c>OVR-9.3-03</c> <c>[PDS]</c> — shall: at minimum, a proof of existence of the signature and its validation data is provided. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 9.3</see>.</summary>
    public static ClaimId Ovr93Item03 { get; } = ClaimId.Create(2_490_303, "OVR-9.3-03");

    /// <summary><c>OVR-9.3-04</c> <c>[PDS+PGD]</c> — shall: a proof of existence of the signed data itself is provided as well. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 9.3</see>.</summary>
    public static ClaimId Ovr93Item04 { get; } = ClaimId.Create(2_490_304, "OVR-9.3-04");

    /// <summary><c>OVR-9.3-05</c> <c>[PDS][PDS+PGD][CONDITIONAL]</c> — may: for a detached signature, only the hash of the signed data is submitted. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 9.3</see>.</summary>
    public static ClaimId Ovr93Item05 { get; } = ClaimId.Create(2_490_305, "OVR-9.3-05");

    /// <summary><c>OVR-9.3-06</c> <c>[PDS][PDS+PGD][CONDITIONAL]</c> — shall: when hash-only submission is allowed, the service states the conditions. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 9.3</see>.</summary>
    public static ClaimId Ovr93Item06 { get; } = ClaimId.Create(2_490_306, "OVR-9.3-06");

    /// <summary><c>OVR-9.3-07</c> <c>[PDS][PDS+PGD][CONDITIONAL]</c> — shall: a submitted hash value is treated as the data object it stands for. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 9.3</see>.</summary>
    public static ClaimId Ovr93Item07 { get; } = ClaimId.Create(2_490_307, "OVR-9.3-07");

    /// <summary><c>OVR-9.3-08</c> <c>[PDS][PDS+PGD][CONDITIONAL]</c> — shall, two obligations: a hash-only submission is verified against the signature it belongs to. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 9.3</see>.</summary>
    public static ClaimId Ovr93Item08 { get; } = ClaimId.Create(2_490_308, "OVR-9.3-08");

    /// <summary><c>OVR-A-01</c> <c>[PDS][PDS+PGD]</c> — shall: every untagged and signature-preservation requirement of clauses 5 to 9 applies to a qualified service. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 Annex A</see>.</summary>
    public static ClaimId OvrAnnexAItem01 { get; } = ClaimId.Create(2_499_001, "OVR-A-01");

    /// <summary><c>OVR-A-02</c> <c>[PDS][PDS+PGD]</c> — shall: all information needed to check the signature is preserved. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 Annex A</see>.</summary>
    public static ClaimId OvrAnnexAItem02 { get; } = ClaimId.Create(2_499_002, "OVR-A-02");

    /// <summary><c>OVR-A-02A</c> <c>[PDS][PDS+PGD]</c> — shall: at any time during the preservation period, the signature's suitability determination holds. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 Annex A</see>.</summary>
    public static ClaimId OvrAnnexAItem02A { get; } = ClaimId.Create(2_499_003, "OVR-A-02A");

    /// <summary><c>OVR-A-03</c> <c>[PDS][PDS+PGD]</c> — should: time-stamps within the evidence come from a qualified time-stamping service. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 Annex A</see>.</summary>
    public static ClaimId OvrAnnexAItem03 { get; } = ClaimId.Create(2_499_004, "OVR-A-03");

    /// <summary><c>OVR-A-04</c> — shall: the service has one service digital identifier. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 Annex A</see>.</summary>
    public static ClaimId OvrAnnexAItem04 { get; } = ClaimId.Create(2_499_005, "OVR-A-04");


    /// <summary><c>PRP-8.1-01</c> — shall, two obligations: the client-to-service channel is secured and the service offers client authentication. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 8.1</see>.</summary>
    public static ClaimId Prp81Item01 { get; } = ClaimId.Create(2_580_101, "PRP-8.1-01");

    /// <summary><c>PRP-8.1-02</c> — should: the standardized preservation protocol is used. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 8.1</see>.</summary>
    public static ClaimId Prp81Item02 { get; } = ClaimId.Create(2_580_102, "PRP-8.1-02");

    /// <summary><c>PRP-8.1-03</c> — shall: the protocols are protected against unauthorized usage. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 8.1</see>.</summary>
    public static ClaimId Prp81Item03 { get; } = ClaimId.Create(2_580_103, "PRP-8.1-03");

    /// <summary><c>PRP-8.1-04</c> — shall: information about the currently and previously supported profiles can be retrieved. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 8.1</see>.</summary>
    public static ClaimId Prp81Item04 { get; } = ClaimId.Create(2_580_104, "PRP-8.1-04");

    /// <summary><c>PRP-8.1-05</c> — shall: one or more submitted data objects can be submitted under a named profile. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 8.1</see>.</summary>
    public static ClaimId Prp81Item05 { get; } = ClaimId.Create(2_580_105, "PRP-8.1-05");

    /// <summary><c>PRP-8.1-06</c> — may: traces of all operations on a preservation object identifier can be retrieved. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 8.1</see>.</summary>
    public static ClaimId Prp81Item06 { get; } = ClaimId.Create(2_580_106, "PRP-8.1-06");

    /// <summary><c>PRP-8.1-07</c> — may: preservation objects can be searched, returning a set of identifiers. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 8.1</see>.</summary>
    public static ClaimId Prp81Item07 { get; } = ClaimId.Create(2_580_107, "PRP-8.1-07");

    /// <summary><c>PRP-8.1-08</c> — may: an evidence and its preservation-object sequence can be submitted for validation. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 8.1</see>.</summary>
    public static ClaimId Prp81Item08 { get; } = ClaimId.Create(2_580_108, "PRP-8.1-08");

    /// <summary><c>PRP-8.1-09</c> <c>[CONDITIONAL]</c> — may: when search is supported, it includes a filter facility. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 8.1</see>.</summary>
    public static ClaimId Prp81Item09 { get; } = ClaimId.Create(2_580_109, "PRP-8.1-09");

    /// <summary><c>PRP-8.1-10</c> <c>[WST]</c> — shall: evidences and preservation objects can be retrieved. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 8.1</see>.</summary>
    public static ClaimId Prp81Item10 { get; } = ClaimId.Create(2_580_110, "PRP-8.1-10");

    /// <summary><c>PRP-8.1-11</c> <c>[WST]</c> — shall, two obligations: stored preservation objects can be deleted, and deleting the evidence follows. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 8.1</see>.</summary>
    public static ClaimId Prp81Item11 { get; } = ClaimId.Create(2_580_111, "PRP-8.1-11");

    /// <summary><c>PRP-8.1-12</c> <c>[WST]</c> — shall, two obligations: stored preservation objects may only be deleted before the end of the preservation period. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 8.1</see>.</summary>
    public static ClaimId Prp81Item12 { get; } = ClaimId.Create(2_580_112, "PRP-8.1-12");

    /// <summary><c>PRP-8.1-13</c> <c>[WST]</c> — should: a set of preservation object identifiers usable in the submission and trace operations can be requested. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 8.1</see>.</summary>
    public static ClaimId Prp81Item13 { get; } = ClaimId.Create(2_580_113, "PRP-8.1-13");

    /// <summary><c>PRP-8.1-14</c> <c>[WST]</c> — may, two permissions: a new version of a preservation object container can be submitted. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 8.1</see>.</summary>
    public static ClaimId Prp81Item14 { get; } = ClaimId.Create(2_580_114, "PRP-8.1-14");

    /// <summary><c>PRP-8.1-15</c> <c>[WTS]</c> — shall: asynchronously produced evidences can be retrieved. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">ETSI TS 119 511 V1.2.1 clause 8.1</see>.</summary>
    public static ClaimId Prp81Item15 { get; } = ClaimId.Create(2_580_115, "PRP-8.1-15");


    /// <summary>The <c>RetrieveInfo</c> operation of clause 5.3.2, the mandatory profile-discovery operation. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3.2</see>.</summary>
    public static ClaimId OperationRetrieveInfo { get; } = ClaimId.Create(2_600_001, "RetrieveInfo");

    /// <summary>The <c>PreservePO</c> operation of clause 5.3.3, the submission operation. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3.3</see>.</summary>
    public static ClaimId OperationPreservePo { get; } = ClaimId.Create(2_600_002, "PreservePO");

    /// <summary>The <c>RetrievePO</c> operation of clause 5.3.4, conditional on a storage-carrying scheme. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3.4</see>.</summary>
    public static ClaimId OperationRetrievePo { get; } = ClaimId.Create(2_600_003, "RetrievePO");

    /// <summary>The <c>DeletePO</c> operation of clause 5.3.5, conditional on the permanent-storage scheme. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3.5</see>.</summary>
    public static ClaimId OperationDeletePo { get; } = ClaimId.Create(2_600_004, "DeletePO");

    /// <summary>The <c>UpdatePOC</c> operation of clause 5.3.6, optional. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3.6</see>.</summary>
    public static ClaimId OperationUpdatePoc { get; } = ClaimId.Create(2_600_005, "UpdatePOC");

    /// <summary>The <c>RetrieveTrace</c> operation of clause 5.3.7, the audit-trail operation. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3.7</see>.</summary>
    public static ClaimId OperationRetrieveTrace { get; } = ClaimId.Create(2_600_006, "RetrieveTrace");

    /// <summary>The <c>ValidateEvidence</c> operation of clause 5.3.8, evidence validation as a service. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3.8</see>.</summary>
    public static ClaimId OperationValidateEvidence { get; } = ClaimId.Create(2_600_007, "ValidateEvidence");

    /// <summary>The <c>Search</c> operation of clause 5.3.9, query by filter. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3.9</see>.</summary>
    public static ClaimId OperationSearch { get; } = ClaimId.Create(2_600_008, "Search");


    /// <summary>The result code <c>noPermission</c>, common to the operations. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3</see>.</summary>
    public static ClaimId ResultNoPermission { get; } = ClaimId.Create(2_700_001, "http://uri.etsi.org/19512/error/noPermission");

    /// <summary>The result code <c>internalError</c>, common to the operations. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3</see>.</summary>
    public static ClaimId ResultInternalError { get; } = ClaimId.Create(2_700_002, "http://uri.etsi.org/19512/error/internalError");

    /// <summary>The result code <c>parameterError</c>, common to the operations. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3</see>.</summary>
    public static ClaimId ResultParameterError { get; } = ClaimId.Create(2_700_003, "http://uri.etsi.org/19512/error/parameterError");

    /// <summary>The result code <c>notSupported</c>, common to the operations. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3</see>.</summary>
    public static ClaimId ResultNotSupported { get; } = ClaimId.Create(2_700_004, "http://uri.etsi.org/19512/error/notSupported");

    /// <summary>The result code <c>transferError</c>, first stated for the submission operation. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3.3</see>.</summary>
    public static ClaimId ResultTransferError { get; } = ClaimId.Create(2_700_005, "http://uri.etsi.org/19512/error/transferError");

    /// <summary>The result code <c>noSpaceError</c>, first stated for the submission operation. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3.3</see>.</summary>
    public static ClaimId ResultNoSpaceError { get; } = ClaimId.Create(2_700_006, "http://uri.etsi.org/19512/error/noSpaceError");

    /// <summary>The result code <c>unknownPOFormat</c>, stated for the submission and retrieval operations. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3.3</see>.</summary>
    public static ClaimId ResultUnknownPoFormat { get; } = ClaimId.Create(2_700_007, "http://uri.etsi.org/19512/error/unknownPOFormat");

    /// <summary>The result code <c>POFormatError</c>, stated for the submission operation. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3.3</see>.</summary>
    public static ClaimId ResultPoFormatError { get; } = ClaimId.Create(2_700_008, "http://uri.etsi.org/19512/error/POFormatError");

    /// <summary>The result code <c>externalServiceUnavailable</c>, stated for the submission operation. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3.3</see>.</summary>
    public static ClaimId ResultExternalServiceUnavailable { get; } = ClaimId.Create(2_700_009, "http://uri.etsi.org/19512/error/externalServiceUnavailable");

    /// <summary>The warning code <c>lowSpace</c>, stated for the submission and update operations. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3.3</see>.</summary>
    public static ClaimId ResultLowSpace { get; } = ClaimId.Create(2_700_010, "http://uri.etsi.org/19512/warning/lowSpace");

    /// <summary>The result code <c>unknownEvidenceFormat</c>, stated for the retrieval operation. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3.4</see>.</summary>
    public static ClaimId ResultUnknownEvidenceFormat { get; } = ClaimId.Create(2_700_011, "http://uri.etsi.org/19512/error/unknownEvidenceFormat");

    /// <summary>The result code <c>unknownPOID</c>, stated for the retrieval, deletion, update and trace operations. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3.4</see>.</summary>
    public static ClaimId ResultUnknownPoId { get; } = ClaimId.Create(2_700_012, "http://uri.etsi.org/19512/error/unknownPOID");

    /// <summary>The result code <c>unknownVersionID</c>, stated for the retrieval operation. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3.4</see>.</summary>
    public static ClaimId ResultUnknownVersionId { get; } = ClaimId.Create(2_700_013, "http://uri.etsi.org/19512/error/unknownVersionID");

    /// <summary>The warning code <c>requestOnlyPartlySuccessful</c>, stated for the retrieval operation. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3.4</see>.</summary>
    public static ClaimId ResultRequestOnlyPartlySuccessful { get; } = ClaimId.Create(2_700_014, "http://uri.etsi.org/19512/warning/requestOnlyPartlySuccessful");

    /// <summary>The result code <c>unknownMode</c>, stated for the deletion operation. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3.5</see>.</summary>
    public static ClaimId ResultUnknownMode { get; } = ClaimId.Create(2_700_015, "http://uri.etsi.org/19512/error/unknownMode");

    /// <summary>The result code <c>unknownDeltaPOCType</c>, stated for the update operation. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3.6</see>.</summary>
    public static ClaimId ResultUnknownDeltaPocType { get; } = ClaimId.Create(2_700_016, "http://uri.etsi.org/19512/error/unknownDeltaPOCType");

    /// <summary>The result code <c>DeltaPOCInternalProblem</c>, stated for the update operation. <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">ETSI TS 119 512 V1.2.1 clause 5.3.6</see>.</summary>
    public static ClaimId ResultDeltaPocInternalProblem { get; } = ClaimId.Create(2_700_017, "http://uri.etsi.org/19512/error/DeltaPOCInternalProblem");


    /// <summary>Determines whether a claim identifier names a TS 119 511 <c>OVR-</c> requirement.</summary>
    /// <param name="claimId">The claim identifier to test.</param>
    /// <returns><see langword="true"/> when the code falls in the overall-requirement band.</returns>
    public static bool IsOverallRequirement(ClaimId claimId) =>
        claimId.Code >= OverallRequirementRangeStart && claimId.Code <= OverallRequirementRangeEnd;


    /// <summary>Determines whether a claim identifier names a TS 119 511 <c>PRP-</c> requirement.</summary>
    /// <param name="claimId">The claim identifier to test.</param>
    /// <returns><see langword="true"/> when the code falls in the protocol-requirement band.</returns>
    public static bool IsProtocolRequirement(ClaimId claimId) =>
        claimId.Code >= ProtocolRequirementRangeStart && claimId.Code <= ProtocolRequirementRangeEnd;


    /// <summary>Determines whether a claim identifier names a requirement of TS 119 511, of either grammar.</summary>
    /// <param name="claimId">The claim identifier to test.</param>
    /// <returns><see langword="true"/> when the code falls in either TS 119 511 band.</returns>
    public static bool IsPreservationServiceRequirement(ClaimId claimId) =>
        IsOverallRequirement(claimId) || IsProtocolRequirement(claimId);


    /// <summary>Determines whether a claim identifier names one of the eight TS 119 512 operations.</summary>
    /// <param name="claimId">The claim identifier to test.</param>
    /// <returns><see langword="true"/> when the code falls in the operation band.</returns>
    public static bool IsProtocolOperation(ClaimId claimId) =>
        claimId.Code >= ProtocolOperationRangeStart && claimId.Code <= ProtocolOperationRangeEnd;


    /// <summary>Determines whether a claim identifier names a TS 119 512 result or warning code.</summary>
    /// <param name="claimId">The claim identifier to test.</param>
    /// <returns><see langword="true"/> when the code falls in the result-code band.</returns>
    public static bool IsProtocolResult(ClaimId claimId) =>
        claimId.Code >= ProtocolResultRangeStart && claimId.Code <= ProtocolResultRangeEnd;


    /// <summary>Determines whether a claim identifier names an identifier of TS 119 512, an operation or a result code.</summary>
    /// <param name="claimId">The claim identifier to test.</param>
    /// <returns><see langword="true"/> when the code falls in either TS 119 512 band.</returns>
    public static bool IsPreservationProtocolIdentifier(ClaimId claimId) =>
        IsProtocolOperation(claimId) || IsProtocolResult(claimId);
}
