using System;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The six presence values of clause 6.2.2 (CB-6.2.2-03..08) — every distinct way Table 14 (clause 6.3) states
/// whether a header parameter, component, service, or SPO is (or must not be, or should not be) incorporated
/// into a CB-AdES signature at a given <see cref="CBAdESBaselineLevel"/>, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 6.2.2</see>.
/// </summary>
/// <remarks>
/// <see cref="ShouldNotBePresent"/> (Table 14's <c>"*"</c>) and <see cref="ShallNotBePresent"/> are deliberately
/// two distinct arms, never merged: the leg-4 CB-AdES preflight report's Trap 4 identifies <c>"*"</c> as a
/// genuine soft-negative obligation with a documented forward-compatibility hazard (CB-6.2.2-08's own NOTE:
/// incorporating a <c>"*"</c>-marked unsigned <c>uHeaders</c> component can make a higher level unreachable
/// except by removing it), not silence or "not applicable".
/// </remarks>
public enum CBAdESPresence
{
    /// <summary>
    /// "shall be present" (CB-6.2.2-03): the item shall be incorporated into the signature, shall conform to
    /// the document referenced in the row's References column, further profiled by the row's
    /// Requirements-column references, with the row's cardinality.
    /// </summary>
    ShallBePresent,

    /// <summary>
    /// "shall not be present" (CB-6.2.2-04): the item shall not be incorporated into the signature — a hard
    /// exclusion a builder must refuse or strip. Distinct from <see cref="ShouldNotBePresent"/>.
    /// </summary>
    ShallNotBePresent,

    /// <summary>
    /// "may be present" (CB-6.2.2-05): the item may be incorporated, and, if it is, shall conform to the
    /// referenced document, further profiled by the Requirements-column references, with the row's
    /// cardinality — the same conformance/cardinality bundle as <see cref="ShallBePresent"/>, but inclusion
    /// itself is optional.
    /// </summary>
    MayBePresent,

    /// <summary>
    /// "shall be provided" (CB-6.2.2-06): the SERVICE named in column 1 shall be provided, as further
    /// specified by its SPO rows. Only appears on <see cref="CBAdESTableRowKind.Service"/> rows; satisfaction
    /// is resolved by checking that at least one of the service's SPO rows is itself satisfied (CB-6.3-h — a
    /// logical OR, never a conjunction).
    /// </summary>
    ShallBeProvided,

    /// <summary>
    /// "conditioned presence" (CB-6.2.2-07): incorporation of the item is conditioned per the row's
    /// Requirements-column references and the specs/clauses in its References column, with the row's
    /// cardinality. The predicate itself is externally defined and evaluated at a later (creation/validation)
    /// stage — this value only records that a predicate gates the item, not the predicate itself.
    /// </summary>
    ConditionedPresence,

    /// <summary>
    /// "*" (CB-6.2.2-08): the item identified in column 1 SHOULD NOT be incorporated at this level; upper
    /// levels may specify other requirements. A genuine soft-negative obligation, not "not applicable" or
    /// silence — see the type remarks for the forward-compatibility hazard this value's own NOTE documents.
    /// Distinct from <see cref="ShallNotBePresent"/>.
    /// </summary>
    ShouldNotBePresent
}


/// <summary>
/// A Table 14 row's presence value at each of the four <see cref="CBAdESBaselineLevel"/> values — the
/// per-level convention CB-6.2.2-09 states for cardinality, as it applies to presence. Every Table 14 row
/// carries exactly one presence value per level (unlike cardinality, presence statements never overlap or
/// duplicate within a row).
/// </summary>
[DebuggerDisplay("CBAdESRowPresence(BB={BB}, BT={BT}, BLT={BLT}, BLTA={BLTA})")]
public sealed record CBAdESRowPresence
{
    /// <summary>Gets the presence value at <see cref="CBAdESBaselineLevel.BB"/>.</summary>
    public required CBAdESPresence BB { get; init; }

    /// <summary>Gets the presence value at <see cref="CBAdESBaselineLevel.BT"/>.</summary>
    public required CBAdESPresence BT { get; init; }

    /// <summary>Gets the presence value at <see cref="CBAdESBaselineLevel.BLT"/>.</summary>
    public required CBAdESPresence BLT { get; init; }

    /// <summary>Gets the presence value at <see cref="CBAdESBaselineLevel.BLTA"/>.</summary>
    public required CBAdESPresence BLTA { get; init; }


    /// <summary>Gets this row's presence value at <paramref name="level"/>.</summary>
    /// <param name="level">The baseline level to query.</param>
    /// <returns>The presence value Table 14 states for that level.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="level"/> is not one of the four declared values.</exception>
    public CBAdESPresence At(CBAdESBaselineLevel level) => level switch
    {
        CBAdESBaselineLevel.BB => BB,
        CBAdESBaselineLevel.BT => BT,
        CBAdESBaselineLevel.BLT => BLT,
        CBAdESBaselineLevel.BLTA => BLTA,
        _ => throw new ArgumentOutOfRangeException(nameof(level), level, "Unknown CB-AdES baseline level (ETSI TS 119 152-1 V1.1.1, clause 6.1, CB-6.1-01).")
    };


    /// <summary>
    /// Builds a <see cref="CBAdESRowPresence"/> whose value is identical at all four levels — the common,
    /// level-invariant case most Table 14 rows fall into.
    /// </summary>
    /// <param name="presence">The presence value to apply uniformly.</param>
    /// <returns>A new instance with <paramref name="presence"/> at every level.</returns>
    public static CBAdESRowPresence Uniform(CBAdESPresence presence) => new()
    {
        BB = presence,
        BT = presence,
        BLT = presence,
        BLTA = presence
    };
}
