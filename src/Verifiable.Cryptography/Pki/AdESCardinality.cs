using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The cardinality vocabulary clause 6.2.2 defines for a baseline-level requirements table's "Cardinality"
/// column — how many instances of a header parameter, attribute, field, component, service, or SPO a table row
/// allows or requires a signature to incorporate, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 6.2.2</see> (CB-6.2.2-09, CB-AdES Table 14),
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 6.2.2</see> (JA-6.2.2-22..27, JAdES Table 1),
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
/// ETSI EN 319 142-1 V1.2.1, clause 6.2.2</see> (PA-6.2.2-18..22, PAdES Table 1), and
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1, clause 6.2.2</see> (XA-6.2.2-23..27, XAdES Table 2). Five of the six tokens map
/// one-for-one across all four specifications; the sixth (<see cref="AtLeastTwo"/>) is XAdES-only.
/// </summary>
/// <remarks>
/// PAdES's own clause 6.2.2 additionally names a sixth, "not applicable" token (PA-6.2.2-17) for the "-" Table 1
/// prints on a service row, whose cardinality is stated by its SPO rows rather than by the service row itself.
/// That token is not carried here: CB-AdES, JAdES and PAdES service rows all already represent "this row has no
/// cardinality of its own" the same way, through the row's own <c>Cardinality</c> member being absent (see
/// <see cref="AdESTableRow.Cardinality"/>, a nullable reference), so a sixth enum member would duplicate a
/// distinction the row shape already makes. A PAdES service row's <c>Cardinality</c> is null, exactly like a
/// CB-AdES or JAdES service row's.
/// </remarks>
public enum AdESCardinality
{
    /// <summary>"0" (CB-6.2.2-09, JA-6.2.2-23, PA-6.2.2-18): shall not incorporate any instance.</summary>
    ExactlyZero,

    /// <summary>"1" (CB-6.2.2-09, JA-6.2.2-24, PA-6.2.2-19): shall incorporate exactly one instance.</summary>
    ExactlyOne,

    /// <summary>"0 or 1" (CB-6.2.2-09, JA-6.2.2-25, PA-6.2.2-20): shall incorporate zero or one instance.</summary>
    ZeroOrOne,

    /// <summary>"≥0" (CB-6.2.2-09, JA-6.2.2-26, PA-6.2.2-21): shall incorporate zero or more instances.</summary>
    ZeroOrMore,

    /// <summary>"≥1" (CB-6.2.2-09, JA-6.2.2-27, PA-6.2.2-22): shall incorporate one or more instances.</summary>
    OneOrMore,

    /// <summary>
    /// "≥2" (XA-6.3-t03, the <c>ds:Reference</c> row's own printed Table 2 cell): shall incorporate at least two
    /// instances. XAdES-only — no CB-AdES/JAdES/PAdES row states a minimum above one; this instance's own two
    /// mandatory references are the SignedProperties reference and at least one signed-content reference. Not
    /// silently narrowed to <see cref="OneOrMore"/>: the closed vocabulary gains a token rather than losing the
    /// distinction the printed cell states.
    /// </summary>
    AtLeastTwo
}


/// <summary>
/// One cardinality sub-line of a requirements-table cell, scoped to the levels named in <see cref="Levels"/> —
/// the unit <see cref="AdESRowCardinality.Statements"/> is built from, reproducing each table's own "B-X, B-Y:
/// N" convention (CB-6.2.2-09; JA-6.2.2-22; PA-6.2.2-17's own worked example, e.g. PAdES Table 1's T27 "B-B,
/// B-T: &gt;= 0 / B-LT, B-LTA: &gt;= 1" and T30's analogous split cell) in source order, including a duplicate
/// sub-line verbatim where a source repeats one (see the remarks on <see cref="AdESRowCardinality"/> and
/// <see cref="CBAdESBaselineLevelTable.SigTst"/>).
/// </summary>
/// <param name="Levels">The levels this sub-line's value applies to.</param>
/// <param name="Value">The cardinality token stated for those levels.</param>
[DebuggerDisplay("{Levels}: {Value}")]
public sealed record AdESCardinalityStatement(AdESBaselineLevelSet Levels, AdESCardinality Value);


/// <summary>
/// A requirements-table row's cardinality, as one or more level-scoped <see cref="AdESCardinalityStatement"/>s
/// in source order (CB-6.2.2-09; JA-6.2.2-22; PA-6.2.2-17). Most rows carry exactly one statement scoped to
/// <see cref="AdESBaselineLevelSet.All"/>; the level-split rows — CB-AdES's <c>sigTst</c>, <c>refs</c>,
/// <c>sigRTst</c>, <c>rfsTst</c>, JAdES's <c>sigTst</c>,
/// <c>xRefs</c>/<c>rRefs</c>/<c>axRefs</c>/<c>arRefs</c>, <c>sigRTst</c>/<c>rfsTst</c>,
/// and PAdES's T27/T30-shaped rows — carry more than one.
/// </summary>
/// <remarks>
/// CB-AdES's own <c>sigTst</c> row additionally reproduces a genuine source duplicate — this library reproduces
/// the duplicate line verbatim, with the semantics of zero new instances at B-LT/B-LTA (see the remarks
/// at its registry entry, <see cref="CBAdESBaselineLevelTable.SigTst"/>) — callers must never silently deduplicate
/// <see cref="Statements"/>. JAdES's Table 1 <c>sigTst</c> row (JA-6.3-26) states its level split as a single
/// two-part cell with no duplicated sub-line, so no JAdES row needs this duplicate-preserving discipline; PAdES's
/// Table 1 likewise states each of its split rows as a single, non-duplicated two-part cell.
/// </remarks>
[DebuggerDisplay("AdESRowCardinality({Statements.Count} statements)")]
public sealed record AdESRowCardinality
{
    /// <summary>
    /// Gets this row's cardinality statements, in the exact order the requirements table states them. Never
    /// empty. Reflects the source verbatim — including CB-AdES's <c>sigTst</c> row's duplicated "B-LT, B-LTA: 0"
    /// line — callers must never silently deduplicate the list.
    /// </summary>
    public required IReadOnlyList<AdESCardinalityStatement> Statements { get; init; }


    /// <summary>
    /// Gets every statement value that applies at <paramref name="level"/>, in source order. For most rows this
    /// returns exactly one value; for CB-AdES's <c>sigTst</c> row at <see cref="AdESBaselineLevel.BLT"/> or
    /// <see cref="AdESBaselineLevel.BLTA"/> it returns three — the cumulative "≥1" carried from B-T, plus the
    /// duplicated incremental "0" line, twice — reflecting the source verbatim rather than resolving it: the
    /// caller applies the ruled reading recorded at <see cref="CBAdESBaselineLevelTable.SigTst"/>. Returns an
    /// empty list for a level no statement names — the shape a service row's absent <see cref="AdESTableRow.Cardinality"/>
    /// already covers, so an empty result here is not expected on any row that carries an
    /// <see cref="AdESRowCardinality"/> at all.
    /// </summary>
    /// <param name="level">The baseline level to query.</param>
    /// <returns>Every applicable statement's value, in source order.</returns>
    public IReadOnlyList<AdESCardinality> ValuesAt(AdESBaselineLevel level)
    {
        List<AdESCardinality> matches = [];
        for(int i = 0; i < Statements.Count; ++i)
        {
            if(Statements[i].Levels.Contains(level))
            {
                matches.Add(Statements[i].Value);
            }
        }

        return matches;
    }


    /// <summary>
    /// Builds an <see cref="AdESRowCardinality"/> with a single statement scoped to
    /// <see cref="AdESBaselineLevelSet.All"/> — the common, level-invariant case most requirements-table rows
    /// fall into.
    /// </summary>
    /// <param name="cardinality">The cardinality to apply uniformly.</param>
    /// <returns>A new instance with one all-levels statement.</returns>
    public static AdESRowCardinality Uniform(AdESCardinality cardinality) => new()
    {
        Statements = [new AdESCardinalityStatement(AdESBaselineLevelSet.All, cardinality)]
    };
}
