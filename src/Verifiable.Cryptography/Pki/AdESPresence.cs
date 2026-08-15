using System;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The presence vocabulary clause 6.2.2 defines for a baseline-level requirements table cell — every distinct
/// way an AdES family table states whether a header parameter, attribute, field, component, service, or Service
/// Provision Option (SPO) is (or must not be, or should not be) incorporated into a signature at a given
/// baseline level, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 6.2.2</see> (CB-6.2.2-03..08, CB-AdES Table 14),
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 6.2.2</see> (JA-6.2.2-16..21, JAdES Table 1), and
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
/// ETSI EN 319 142-1 V1.2.1, clause 6.2.2</see> (PA-6.2.2-11..16, PAdES Table 1). The six values and their
/// meanings map one-for-one across all three specifications; clause 6.2.2's own notation is restated near-
/// verbatim in the JAdES and PAdES documents from CB-AdES's original text.
/// </summary>
/// <remarks>
/// <see cref="ShouldNotBePresent"/> (each table's <c>"*"</c>) and <see cref="ShallNotBePresent"/> are
/// deliberately two distinct arms, never merged: <c>"*"</c> is a genuine soft-negative obligation with a
/// documented forward-compatibility hazard
/// (CB-6.2.2-08's own NOTE: incorporating a <c>"*"</c>-marked unsigned component can make a higher level
/// unreachable except by removing it), not silence or "not applicable". JA-6.2.2-21 and PA-6.2.2-16 restate the
/// identical hazard for their own tables.
/// </remarks>
public enum AdESPresence
{
    /// <summary>
    /// "shall be present" (CB-6.2.2-03, JA-6.2.2-16, PA-6.2.2-11): the item shall be incorporated into the
    /// signature, shall conform to the document referenced in the row's References column, further profiled by
    /// the row's Requirements-column references, with the row's cardinality.
    /// </summary>
    ShallBePresent,

    /// <summary>
    /// "shall not be present" (CB-6.2.2-04, JA-6.2.2-17, PA-6.2.2-12): the item shall not be incorporated into
    /// the signature — a hard exclusion a builder must refuse or strip. Distinct from
    /// <see cref="ShouldNotBePresent"/>.
    /// </summary>
    ShallNotBePresent,

    /// <summary>
    /// "may be present" (CB-6.2.2-05, JA-6.2.2-18, PA-6.2.2-13): the item may be incorporated, and, if it is,
    /// shall conform to the referenced document, further profiled by the Requirements-column references, with
    /// the row's cardinality — the same conformance/cardinality bundle as <see cref="ShallBePresent"/>, but
    /// inclusion itself is optional.
    /// </summary>
    MayBePresent,

    /// <summary>
    /// "shall be provided" (CB-6.2.2-06, JA-6.2.2-19, PA-6.2.2-14): the SERVICE named in column 1 shall be
    /// provided, as further specified by its SPO rows. Only appears on <see cref="AdESTableRowKind"/>
    /// <c>Service</c> rows; satisfaction is resolved by checking that at least one of the service's SPO rows is
    /// itself satisfied (CB-6.3-h — a logical OR, never a conjunction).
    /// </summary>
    ShallBeProvided,

    /// <summary>
    /// "conditioned presence" (CB-6.2.2-07, JA-6.2.2-20, PA-6.2.2-15): incorporation of the item is conditioned
    /// per the row's Requirements-column references and the specs/clauses in its References column, with the
    /// row's cardinality. The predicate itself is externally defined and evaluated at a later
    /// (creation/validation) stage — this value only records that a predicate gates the item, not the predicate
    /// itself.
    /// </summary>
    ConditionedPresence,

    /// <summary>
    /// "*" (CB-6.2.2-08, JA-6.2.2-21, PA-6.2.2-16): the item identified in column 1 SHOULD NOT be incorporated
    /// at this level; upper levels may specify other requirements. A genuine soft-negative obligation, not "not
    /// applicable" or silence — see the type remarks for the forward-compatibility hazard this value's own NOTE
    /// documents. Distinct from <see cref="ShallNotBePresent"/>.
    /// </summary>
    ShouldNotBePresent
}


/// <summary>
/// A requirements-table row's presence value at each of the four <see cref="AdESBaselineLevel"/> values — the
/// per-level convention CB-6.2.2-09/JA-6.2.2-22 states for cardinality, and clause 6.2.2's presence columns
/// mirror the same per-level shape for presence, as CB-AdES Table 14, JAdES Table 1, and PAdES Table 1 each
/// print it. Every row carries exactly one presence value per level (unlike cardinality, presence statements
/// never overlap or duplicate within a row).
/// </summary>
[DebuggerDisplay("AdESRowPresence(BB={BB}, BT={BT}, BLT={BLT}, BLTA={BLTA})")]
public sealed record AdESRowPresence
{
    /// <summary>Gets the presence value at <see cref="AdESBaselineLevel.BB"/>.</summary>
    public required AdESPresence BB { get; init; }

    /// <summary>Gets the presence value at <see cref="AdESBaselineLevel.BT"/>.</summary>
    public required AdESPresence BT { get; init; }

    /// <summary>Gets the presence value at <see cref="AdESBaselineLevel.BLT"/>.</summary>
    public required AdESPresence BLT { get; init; }

    /// <summary>Gets the presence value at <see cref="AdESBaselineLevel.BLTA"/>.</summary>
    public required AdESPresence BLTA { get; init; }


    /// <summary>Gets this row's presence value at <paramref name="level"/>.</summary>
    /// <param name="level">The baseline level to query.</param>
    /// <returns>The presence value the requirements table states for that level.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="level"/> is not one of the four declared values.</exception>
    public AdESPresence At(AdESBaselineLevel level) => level switch
    {
        AdESBaselineLevel.BB => BB,
        AdESBaselineLevel.BT => BT,
        AdESBaselineLevel.BLT => BLT,
        AdESBaselineLevel.BLTA => BLTA,
        _ => throw new ArgumentOutOfRangeException(nameof(level), level, "Unknown AdES baseline level (ETSI TS 119 152-1 V1.1.1 cl. 6.1 CB-6.1-01; ETSI TS 119 182-1 V1.2.1 cl. 6.1 JA-6.1-01..04; ETSI EN 319 142-1 V1.2.1 cl. 6.1 PA-6.1-DEF-a..d).")
    };


    /// <summary>
    /// Builds an <see cref="AdESRowPresence"/> whose value is identical at all four levels — the common,
    /// level-invariant case most requirements-table rows fall into.
    /// </summary>
    /// <param name="presence">The presence value to apply uniformly.</param>
    /// <returns>A new instance with <paramref name="presence"/> at every level.</returns>
    public static AdESRowPresence Uniform(AdESPresence presence) => new()
    {
        BB = presence,
        BT = presence,
        BLT = presence,
        BLTA = presence
    };
}
