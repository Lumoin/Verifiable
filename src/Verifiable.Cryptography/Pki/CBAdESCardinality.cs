using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The five cardinality tokens of clause 6.2.2 (CB-6.2.2-09) — how many instances of a header parameter,
/// component, service, or SPO Table 14 (clause 6.3) allows or requires a CB-AdES signature to incorporate, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 6.2.2</see>.
/// </summary>
public enum CBAdESCardinality
{
    /// <summary>"0": shall not incorporate any instance.</summary>
    ExactlyZero,

    /// <summary>"1": shall incorporate exactly one instance.</summary>
    ExactlyOne,

    /// <summary>"0 or 1": shall incorporate zero or one instance.</summary>
    ZeroOrOne,

    /// <summary>"≥0": shall incorporate zero or more instances.</summary>
    ZeroOrMore,

    /// <summary>"≥1": shall incorporate one or more instances.</summary>
    OneOrMore
}


/// <summary>
/// One cardinality sub-line of a Table 14 cell, scoped to the levels named in <see cref="Levels"/> — the unit
/// <see cref="CBAdESRowCardinality.Statements"/> is built from, reproducing the source table's own "B-X, B-Y:
/// N" convention (clause 6.2.2, CB-6.2.2-09; leg-4 CB-AdES preflight report Trap 5) in source order, including
/// a duplicate sub-line verbatim where the source repeats one (see the remarks on <see cref="CBAdESRowCardinality"/>
/// and <see cref="CBAdESBaselineLevelTable.SigTst"/>).
/// </summary>
/// <param name="Levels">The levels this sub-line's value applies to.</param>
/// <param name="Value">The cardinality token stated for those levels.</param>
[DebuggerDisplay("{Levels}: {Value}")]
public sealed record CBAdESCardinalityStatement(CBAdESBaselineLevelSet Levels, CBAdESCardinality Value);


/// <summary>
/// A Table 14 row's cardinality, as one or more level-scoped <see cref="CBAdESCardinalityStatement"/>s in
/// source order (CB-6.2.2-09). Most rows carry exactly one statement scoped to
/// <see cref="CBAdESBaselineLevelSet.All"/>; the four level-split rows — <c>sigTst</c>, <c>refs</c>,
/// <c>sigRTst</c>, <c>rfsTst</c> (leg-4 CB-AdES preflight report Trap 5) — carry more than one, and
/// <c>sigTst</c> additionally reproduces a genuine source duplicate (defect D2, wavecb-contract.md ruling R-6:
/// "reproduce the duplicate line ..., semantics = zero new instances at B-LT/B-LTA"; see the remarks at its
/// registry entry, <see cref="CBAdESBaselineLevelTable.SigTst"/>).
/// </summary>
[DebuggerDisplay("CBAdESRowCardinality({Statements.Count} statements)")]
public sealed record CBAdESRowCardinality
{
    /// <summary>
    /// Gets this row's cardinality statements, in the exact order Table 14 states them. Never empty. Reflects
    /// the source verbatim — including <c>sigTst</c>'s duplicated "B-LT, B-LTA: 0" line (D2) — callers must
    /// never silently deduplicate the list.
    /// </summary>
    public required IReadOnlyList<CBAdESCardinalityStatement> Statements { get; init; }


    /// <summary>
    /// Gets every statement value that applies at <paramref name="level"/>, in source order. For most rows
    /// this returns exactly one value; for <c>sigTst</c> at <see cref="CBAdESBaselineLevel.BLT"/> or
    /// <see cref="CBAdESBaselineLevel.BLTA"/> it returns three — the cumulative "≥1" carried from B-T, plus the
    /// duplicated incremental "0" line, twice — reflecting the source verbatim rather than resolving it: the
    /// caller applies the ruled reading recorded at <see cref="CBAdESBaselineLevelTable.SigTst"/>.
    /// </summary>
    /// <param name="level">The baseline level to query.</param>
    /// <returns>Every applicable statement's value, in source order.</returns>
    public IReadOnlyList<CBAdESCardinality> ValuesAt(CBAdESBaselineLevel level)
    {
        List<CBAdESCardinality> matches = [];
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
    /// Builds a <see cref="CBAdESRowCardinality"/> with a single statement scoped to
    /// <see cref="CBAdESBaselineLevelSet.All"/> — the common, level-invariant case most Table 14 rows fall
    /// into.
    /// </summary>
    /// <param name="cardinality">The cardinality to apply uniformly.</param>
    /// <returns>A new instance with one all-levels statement.</returns>
    public static CBAdESRowCardinality Uniform(CBAdESCardinality cardinality) => new()
    {
        Statements = [new CBAdESCardinalityStatement(CBAdESBaselineLevelSet.All, cardinality)]
    };
}
