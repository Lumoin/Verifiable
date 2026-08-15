using System;
using System.Collections.Generic;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The four AdES baseline signature levels shared by CB-AdES, JAdES, and PAdES: an ordered, closed set with
/// an additive lifecycle relationship — each higher level's requirements build on the level below's, and a
/// level-upgrade operation never removes content that was legal at a lower level. Defined by
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 6.1</see> (CB-6.1-01),
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 6.1</see> (JA-6.1-01..04), and
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
/// ETSI EN 319 142-1 V1.2.1, clause 6.1</see> (PA-6.1-DEF-a..d).
/// </summary>
/// <remarks>
/// <para>
/// CB-6.1-01 / JA-6.1-01..04 / PA-6.1-DEF-a..d define the four levels as: a) <see cref="BB"/> — requirements
/// for incorporating signed header/attribute parameters and some unsigned components (CB-AdES's <c>uHeaders</c>,
/// JAdES's <c>etsiU</c>) at generation time; b) <see cref="BT"/> — requirements for generating/including a
/// trusted token proving the signature existed at a given date/time; c) <see cref="BLT"/> — requirements for
/// incorporating all material required to validate the signature (long-term AVAILABILITY of validation
/// material); d) <see cref="BLTA"/> — requirements for incorporating electronic time-stamps enabling validation
/// long after generation (long-term availability AND INTEGRITY).
/// </para>
/// <para>
/// The same four levels are also the CAdES/PAdES baseline levels of ETSI EN 319 122-1 that a signature
/// verification result reports: a verification that proves the baseline signed attributes reports
/// <see cref="BB"/>; one that additionally proves a signature timestamp reports <see cref="BT"/>.
/// </para>
/// <para>
/// Declared in ascending lifecycle order so the compiler-assigned ordinal already orders the levels
/// (<c>BB &lt; BT &lt; BLT &lt; BLTA</c>) — <see cref="AdESBaselineLevels.All"/> enumerates them in that same
/// order.
/// </para>
/// </remarks>
public enum AdESBaselineLevel
{
    /// <summary>
    /// AdES-B-B: requirements for incorporating signed header/attribute parameters and some unsigned
    /// components at generation time (CB-6.1-01 a); JA-6.1-01; PA-6.1-DEF-a).
    /// </summary>
    BB = 0,

    /// <summary>
    /// AdES-B-T: <see cref="BB"/> plus requirements for generating/including a trusted token proving the
    /// signature existed at a given date/time (CB-6.1-01 b); JA-6.1-02; PA-6.1-DEF-b).
    /// </summary>
    BT = 1,

    /// <summary>
    /// AdES-B-LT: <see cref="BT"/> plus requirements for incorporating all material required to validate
    /// the signature — long-term AVAILABILITY of validation material (CB-6.1-01 c); JA-6.1-03;
    /// PA-6.1-DEF-c).
    /// </summary>
    BLT = 2,

    /// <summary>
    /// AdES-B-LTA: <see cref="BLT"/> plus requirements for incorporating electronic time-stamps enabling
    /// validation long after generation — long-term availability AND INTEGRITY (CB-6.1-01 d); JA-6.1-04;
    /// PA-6.1-DEF-d).
    /// </summary>
    BLTA = 3
}


/// <summary>
/// A closed set of <see cref="AdESBaselineLevel"/> values — the scope one cardinality statement or one arm
/// of a row's per-level presence applies to, mirroring each format's Table's own "B-X, B-Y: ..." sub-line
/// convention (CB-AdES Table 14 clause 6.2.2, CB-6.2.2-09; JAdES Table 1 clause
/// 6.2.2, JA-6.2.2-22; PAdES Table 1 clause 6.2.2, PA-6.2.2-17, rows T27/T30) for the rows whose presence or
/// cardinality is not identical across every level.
/// </summary>
[Flags]
public enum AdESBaselineLevelSet
{
    /// <summary>No level.</summary>
    None = 0,

    /// <summary><see cref="AdESBaselineLevel.BB"/>.</summary>
    BB = 1 << 0,

    /// <summary><see cref="AdESBaselineLevel.BT"/>.</summary>
    BT = 1 << 1,

    /// <summary><see cref="AdESBaselineLevel.BLT"/>.</summary>
    BLT = 1 << 2,

    /// <summary><see cref="AdESBaselineLevel.BLTA"/>.</summary>
    BLTA = 1 << 3,

    /// <summary>Every level — the common, level-invariant case most table rows fall into.</summary>
    All = BB | BT | BLT | BLTA
}


/// <summary>
/// Conversions and membership queries between <see cref="AdESBaselineLevel"/> and its closed set type
/// <see cref="AdESBaselineLevelSet"/>.
/// </summary>
public static class AdESBaselineLevels
{
    /// <summary>Every baseline level, in ascending lifecycle order (CB-6.1-01; JA-6.1-01..04; PA-6.1-DEF-a..d).</summary>
    public static IReadOnlyList<AdESBaselineLevel> All { get; } =
    [
        AdESBaselineLevel.BB,
        AdESBaselineLevel.BT,
        AdESBaselineLevel.BLT,
        AdESBaselineLevel.BLTA
    ];


    /// <summary>Gets the single-level <see cref="AdESBaselineLevelSet"/> flag corresponding to <paramref name="level"/>.</summary>
    /// <param name="level">The level to convert.</param>
    /// <returns>The corresponding single-flag set.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="level"/> is not one of the four declared values.</exception>
    public static AdESBaselineLevelSet ToLevelSet(this AdESBaselineLevel level) => level switch
    {
        AdESBaselineLevel.BB => AdESBaselineLevelSet.BB,
        AdESBaselineLevel.BT => AdESBaselineLevelSet.BT,
        AdESBaselineLevel.BLT => AdESBaselineLevelSet.BLT,
        AdESBaselineLevel.BLTA => AdESBaselineLevelSet.BLTA,
        _ => throw new ArgumentOutOfRangeException(nameof(level), level, "Unknown AdES baseline level (ETSI TS 119 152-1 V1.1.1 clause 6.1 CB-6.1-01; ETSI TS 119 182-1 V1.2.1 clause 6.1 JA-6.1-01..04; ETSI EN 319 142-1 V1.2.1 clause 6.1 PA-6.1-DEF-a..d).")
    };


    /// <summary>Gets whether <paramref name="set"/> includes <paramref name="level"/>.</summary>
    /// <param name="set">The level set to query.</param>
    /// <param name="level">The level to test for membership.</param>
    /// <returns><see langword="true"/> when <paramref name="level"/>'s flag is set in <paramref name="set"/>.</returns>
    public static bool Contains(this AdESBaselineLevelSet set, AdESBaselineLevel level) =>
        (set & level.ToLevelSet()) != AdESBaselineLevelSet.None;
}
