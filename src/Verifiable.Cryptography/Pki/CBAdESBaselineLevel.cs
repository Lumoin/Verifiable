using System;
using System.Collections.Generic;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The four CB-AdES baseline signature levels of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 6.1</see> (CB-6.1-01) — an ordered, closed set with an additive lifecycle
/// relationship: each higher level's requirements build on the level below's, and a level-upgrade operation
/// never removes content that was legal at a lower level.
/// </summary>
/// <remarks>
/// <para>
/// CB-6.1-01 defines the four levels as: a) <see cref="BB"/> — requirements for incorporating signed header
/// parameters and some unsigned <c>uHeaders</c> components at generation time; b) <see cref="BT"/> —
/// requirements for generating/including a trusted token proving the signature existed at a given date/time;
/// c) <see cref="BLT"/> — requirements for incorporating all material required to validate the signature
/// (long-term AVAILABILITY of validation material); d) <see cref="BLTA"/> — requirements for incorporating
/// electronic time-stamps enabling validation long after generation (long-term availability AND INTEGRITY).
/// </para>
/// <para>
/// Declared in ascending lifecycle order so the compiler-assigned ordinal already orders the levels
/// (<c>BB &lt; BT &lt; BLT &lt; BLTA</c>) — <see cref="CBAdESBaselineLevels.All"/> enumerates them in that
/// same order.
/// </para>
/// </remarks>
public enum CBAdESBaselineLevel
{
    /// <summary>
    /// CB-AdES-B-B: requirements for incorporating signed header parameters and some unsigned
    /// <c>uHeaders</c> components at generation time (CB-6.1-01 a)).
    /// </summary>
    BB = 0,

    /// <summary>
    /// CB-AdES-B-T: <see cref="BB"/> plus requirements for generating/including a trusted token proving the
    /// signature existed at a given date/time (CB-6.1-01 b)).
    /// </summary>
    BT = 1,

    /// <summary>
    /// CB-AdES-B-LT: <see cref="BT"/> plus requirements for incorporating all material required to validate
    /// the signature — long-term AVAILABILITY of validation material (CB-6.1-01 c)).
    /// </summary>
    BLT = 2,

    /// <summary>
    /// CB-AdES-B-LTA: <see cref="BLT"/> plus requirements for incorporating electronic time-stamps enabling
    /// validation long after generation — long-term availability AND INTEGRITY (CB-6.1-01 d)).
    /// </summary>
    BLTA = 3
}


/// <summary>
/// A closed set of <see cref="CBAdESBaselineLevel"/> values — the scope one <see cref="CBAdESCardinalityStatement"/>
/// or one arm of a <see cref="CBAdESRowPresence"/> applies to, mirroring Table 14's own "B-X, B-Y: ..."
/// sub-line convention (clause 6.2.2, CB-6.2.2-09; leg-4 preflight Trap 5) for the rows whose presence or
/// cardinality is not identical across every level.
/// </summary>
[Flags]
public enum CBAdESBaselineLevelSet
{
    /// <summary>No level.</summary>
    None = 0,

    /// <summary><see cref="CBAdESBaselineLevel.BB"/>.</summary>
    BB = 1 << 0,

    /// <summary><see cref="CBAdESBaselineLevel.BT"/>.</summary>
    BT = 1 << 1,

    /// <summary><see cref="CBAdESBaselineLevel.BLT"/>.</summary>
    BLT = 1 << 2,

    /// <summary><see cref="CBAdESBaselineLevel.BLTA"/>.</summary>
    BLTA = 1 << 3,

    /// <summary>Every level — the common, level-invariant case most Table 14 rows fall into.</summary>
    All = BB | BT | BLT | BLTA
}


/// <summary>
/// Conversions and membership queries between <see cref="CBAdESBaselineLevel"/> and its closed set type
/// <see cref="CBAdESBaselineLevelSet"/>.
/// </summary>
public static class CBAdESBaselineLevels
{
    /// <summary>Every baseline level, in ascending lifecycle order (CB-6.1-01).</summary>
    public static IReadOnlyList<CBAdESBaselineLevel> All { get; } =
    [
        CBAdESBaselineLevel.BB,
        CBAdESBaselineLevel.BT,
        CBAdESBaselineLevel.BLT,
        CBAdESBaselineLevel.BLTA
    ];


    /// <summary>Gets the single-level <see cref="CBAdESBaselineLevelSet"/> flag corresponding to <paramref name="level"/>.</summary>
    /// <param name="level">The level to convert.</param>
    /// <returns>The corresponding single-flag set.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="level"/> is not one of the four declared values.</exception>
    public static CBAdESBaselineLevelSet ToLevelSet(this CBAdESBaselineLevel level) => level switch
    {
        CBAdESBaselineLevel.BB => CBAdESBaselineLevelSet.BB,
        CBAdESBaselineLevel.BT => CBAdESBaselineLevelSet.BT,
        CBAdESBaselineLevel.BLT => CBAdESBaselineLevelSet.BLT,
        CBAdESBaselineLevel.BLTA => CBAdESBaselineLevelSet.BLTA,
        _ => throw new ArgumentOutOfRangeException(nameof(level), level, "Unknown CB-AdES baseline level (ETSI TS 119 152-1 V1.1.1, clause 6.1, CB-6.1-01).")
    };


    /// <summary>Gets whether <paramref name="set"/> includes <paramref name="level"/>.</summary>
    /// <param name="set">The level set to query.</param>
    /// <param name="level">The level to test for membership.</param>
    /// <returns><see langword="true"/> when <paramref name="level"/>'s flag is set in <paramref name="set"/>.</returns>
    public static bool Contains(this CBAdESBaselineLevelSet set, CBAdESBaselineLevel level) =>
        (set & level.ToLevelSet()) != CBAdESBaselineLevelSet.None;
}
