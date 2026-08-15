using System;
using System.Collections.Generic;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The Table 14 (clause 6.3) row registry — all 26 rows CB-6.3-04..29 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 6.3</see>, exposed as static getters (the <c>CoseHeaderParameters</c>/
/// <c>WellKnownOids</c> exemplar shape) plus lookup helpers over <see cref="Rows"/>. COSE/CBOR-free: this
/// class carries only the presence/cardinality/reference/annotation DATA clause 6 states, never a wire encoding
/// or a rule-evaluation engine — those compose this registry from a later stage (JCose).
/// </summary>
/// <remarks>
/// <para>
/// Row-kind counts (see <see cref="AdESTableRowKind"/>): 10 <see cref="AdESTableRowKind.HeaderParameter"/>
/// rows (<see cref="Alg"/>, <see cref="ContentType"/>, <see cref="Kid"/>, <see cref="X5U"/>,
/// <see cref="X5Chain"/>, <see cref="Crit"/>, <see cref="CwtClaims"/>, <see cref="X5T"/>, <see cref="X5Ts"/>,
/// <see cref="CounterSignature"/>), 13 <see cref="AdESTableRowKind.Component"/> rows (<see cref="SigD"/>,
/// <see cref="SrAts"/>, <see cref="SrCms"/>, <see cref="SigPl"/>, <see cref="SigPId"/>, <see cref="AdoTst"/>,
/// <see cref="SigPSt"/>, <see cref="SigTst"/>, <see cref="ValData"/>, <see cref="Refs"/>, <see cref="SigRTst"/>,
/// <see cref="RfsTst"/>, <see cref="ArcTst"/>), 1 <see cref="AdESTableRowKind.Service"/> row
/// (<see cref="ValidationDataForTimestampsService"/>), and 2 <see cref="AdESTableRowKind.ServiceProvisionOption"/>
/// rows (<see cref="ValDataServiceProvisionOption"/>, <see cref="EmbeddedValidationDataServiceProvisionOption"/>)
/// — 26 rows total.
/// </para>
/// <para>
/// <strong>Duplicate line preserved.</strong> <see cref="SigTst"/>'s cardinality reproduces the
/// source table's genuine duplicate "B-LT, B-LTA: 0" sub-line verbatim rather than
/// silently deduplicating it — see the remarks at that member.
/// </para>
/// </remarks>
public static class CBAdESBaselineLevelTable
{
    /// <summary>
    /// <c>alg</c> (CB-6.3-04): shall be present at all 4 levels; cardinality 1; ref clause 5.1.2; no
    /// additional notes — the simplest presence class, mandatory and level-invariant.
    /// </summary>
    public static AdESTableRow Alg { get; } = new()
    {
        RequirementId = "CB-6.3-04",
        Name = "alg",
        Kind = AdESTableRowKind.HeaderParameter,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyOne),
        Reference = new AdESInternalClauseReference("5.1.2")
    };

    /// <summary>
    /// <c>content type</c> (CB-6.3-05): conditioned presence at all 4 levels; cardinality 0 or 1; ref clause
    /// 5.1.3; note 2 — the presence predicate lives outside clause 6, shared jointly with clause 5.2.8.1's
    /// <c>sigD</c>/<c>ctys</c> mechanism.
    /// </summary>
    public static AdESTableRow ContentType { get; } = new()
    {
        RequirementId = "CB-6.3-05",
        Name = "content type",
        Kind = AdESTableRowKind.HeaderParameter,
        Presence = AdESRowPresence.Uniform(AdESPresence.ConditionedPresence),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.1.3"),
        PresenceConditionClauses = ["5.1.3", "5.2.8.1"],
        Annotations = new AdESRowAnnotations { NoteNumbers = [2] }
    };

    /// <summary>
    /// <c>kid</c> (CB-6.3-06): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.1.4 — a
    /// simple optional singleton, level-invariant.
    /// </summary>
    public static AdESTableRow Kid { get; } = new()
    {
        RequirementId = "CB-6.3-06",
        Name = "kid",
        Kind = AdESTableRowKind.HeaderParameter,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.1.4")
    };

    /// <summary>
    /// <c>x5u</c> (CB-6.3-07): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.1.5 — a
    /// simple optional singleton, level-invariant.
    /// </summary>
    public static AdESTableRow X5U { get; } = new()
    {
        RequirementId = "CB-6.3-07",
        Name = "x5u",
        Kind = AdESTableRowKind.HeaderParameter,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.1.5")
    };

    /// <summary>
    /// <c>x5chain</c> (CB-6.3-08): conditioned presence at all 4 levels; cardinality 0 or 1; ref clause 5.1.8;
    /// note 3. The presence CONDITION for <c>x5chain</c>/<c>x5t</c>/<c>x5ts</c> lives
    /// in clause 5.2.2 (the <c>x5ts</c> row's own defining clause), not in this row's own References clause
    /// (5.1.8) — see <see cref="AdESTableRow.PresenceConditionClauses"/>.
    /// </summary>
    public static AdESTableRow X5Chain { get; } = new()
    {
        RequirementId = "CB-6.3-08",
        Name = "x5chain",
        Kind = AdESTableRowKind.HeaderParameter,
        Presence = AdESRowPresence.Uniform(AdESPresence.ConditionedPresence),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.1.8"),
        PresenceConditionClauses = ["5.2.2"],
        Annotations = new AdESRowAnnotations { NoteNumbers = [3] }
    };

    /// <summary>
    /// <c>crit</c> (CB-6.3-09): conditioned presence at all 4 levels; cardinality 0 or 1; ref clause 5.1.10;
    /// note 4 — the presence condition is co-located with this row's own defining clause (unlike
    /// <see cref="X5Chain"/>'s condition clause), so <see cref="AdESTableRow.PresenceConditionClauses"/> is left
    /// <see langword="null"/> here.
    /// </summary>
    public static AdESTableRow Crit { get; } = new()
    {
        RequirementId = "CB-6.3-09",
        Name = "crit",
        Kind = AdESTableRowKind.HeaderParameter,
        Presence = AdESRowPresence.Uniform(AdESPresence.ConditionedPresence),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.1.10"),
        Annotations = new AdESRowAnnotations { NoteNumbers = [4] }
    };

    /// <summary>
    /// <c>CWT Claims</c> (enclosing <c>iat</c>, CB-6.3-10): shall be present at all 4 levels; cardinality 1;
    /// ref clause 5.1.9; additional requirement (a) — mandatory singleton at every level, content further
    /// constrained by requirement (a) (CB-6.3-a: <c>iat</c> carries the generator-claimed UTC signing time).
    /// </summary>
    public static AdESTableRow CwtClaims { get; } = new()
    {
        RequirementId = "CB-6.3-10",
        Name = "CWT Claims",
        Kind = AdESTableRowKind.HeaderParameter,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyOne),
        Reference = new AdESInternalClauseReference("5.1.9"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["a"] }
    };

    /// <summary>
    /// <c>x5t</c> (CB-6.3-11): conditioned presence at all 4 levels; cardinality 0 or 1; ref clause 5.1.7;
    /// note 3 — part of the same tri-way condition group as <see cref="X5Chain"/>/<see cref="X5Ts"/>.
    /// </summary>
    public static AdESTableRow X5T { get; } = new()
    {
        RequirementId = "CB-6.3-11",
        Name = "x5t",
        Kind = AdESTableRowKind.HeaderParameter,
        Presence = AdESRowPresence.Uniform(AdESPresence.ConditionedPresence),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.1.7"),
        PresenceConditionClauses = ["5.2.2"],
        Annotations = new AdESRowAnnotations { NoteNumbers = [3] }
    };

    /// <summary>
    /// <c>x5ts</c> (CB-6.3-12): conditioned presence at all 4 levels; cardinality 0 or 1; ref clause 5.2.2;
    /// note 3 — this row's own defining clause (5.2.2) is ALSO the shared condition-logic clause for the
    /// whole <see cref="X5Chain"/>/<see cref="X5T"/>/<see cref="X5Ts"/> trio, resolving that shared defect in
    /// one place.
    /// </summary>
    public static AdESTableRow X5Ts { get; } = new()
    {
        RequirementId = "CB-6.3-12",
        Name = "x5ts",
        Kind = AdESTableRowKind.HeaderParameter,
        Presence = AdESRowPresence.Uniform(AdESPresence.ConditionedPresence),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.2.2"),
        PresenceConditionClauses = ["5.2.2"],
        Annotations = new AdESRowAnnotations { NoteNumbers = [3] }
    };

    /// <summary>
    /// <c>sigD</c> (CB-6.3-13): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.2.8 — a
    /// level-invariant optional singleton; interacts with <see cref="ContentType"/> via note 2.
    /// </summary>
    public static AdESTableRow SigD { get; } = new()
    {
        RequirementId = "CB-6.3-13",
        Name = "sigD",
        Kind = AdESTableRowKind.Component,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.2.8")
    };

    /// <summary>
    /// <c>srAts</c> (CB-6.3-14): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.2.5 — a
    /// level-invariant optional singleton.
    /// </summary>
    public static AdESTableRow SrAts { get; } = new()
    {
        RequirementId = "CB-6.3-14",
        Name = "srAts",
        Kind = AdESTableRowKind.Component,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.2.5")
    };

    /// <summary>
    /// <c>srCms</c> (CB-6.3-15): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.2.3; note 5
    /// — the cardinality is at the HEADER level: the value itself is a CBOR array that may hold several
    /// commitment types, which this row's cardinality does not count.
    /// </summary>
    public static AdESTableRow SrCms { get; } = new()
    {
        RequirementId = "CB-6.3-15",
        Name = "srCms",
        Kind = AdESTableRowKind.Component,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.2.3"),
        Annotations = new AdESRowAnnotations { NoteNumbers = [5] }
    };

    /// <summary>
    /// <c>sigPl</c> (CB-6.3-16): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.2.4 — a
    /// level-invariant optional singleton.
    /// </summary>
    public static AdESTableRow SigPl { get; } = new()
    {
        RequirementId = "CB-6.3-16",
        Name = "sigPl",
        Kind = AdESTableRowKind.Component,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.2.4")
    };

    /// <summary>
    /// <c>sigPId</c> (CB-6.3-17): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.2.7 — a
    /// level-invariant optional singleton; its own presence together with its <c>digVal</c> member gates
    /// <see cref="SigPSt"/>'s presence (requirement (b), CB-6.3-b).
    /// </summary>
    public static AdESTableRow SigPId { get; } = new()
    {
        RequirementId = "CB-6.3-17",
        Name = "sigPId",
        Kind = AdESTableRowKind.Component,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.2.7")
    };

    /// <summary>
    /// <c>counter signature</c> (CB-6.3-30): may be present at all 4 levels; cardinality ≥0; ref clause 5.1.6
    /// — unbounded repeatable, level-invariant. Table 14's own row order places this row where sequential
    /// numbering would yield CB-6.3-18; the identifier in use is CB-6.3-30, and CB-6.3-18 is permanently
    /// retired so neither identifier ever names two different rows.
    /// </summary>
    public static AdESTableRow CounterSignature { get; } = new()
    {
        RequirementId = "CB-6.3-30",
        Name = "counter signature",
        Kind = AdESTableRowKind.HeaderParameter,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrMore),
        Reference = new AdESInternalClauseReference("5.1.6")
    };

    /// <summary>
    /// <c>adoTst</c> (CB-6.3-19): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.3.2; note 6
    /// — the header-level cardinality of 0-or-1 is independent of how many electronic time-stamps (possibly
    /// from different TSAs) the internal <c>tstContainer</c> holds. It
    /// shares its References clause (5.3.2) verbatim with <see cref="SigPSt"/>.
    /// </summary>
    /// <remarks>
    /// <strong>Reference clause, corrected.</strong> Table 14's own printed
    /// References column for this row reads "Clause 5.3.2" — <see cref="SigPSt"/>'s own clause, the very
    /// next row, almost certainly the copy-paste origin — not "Clause 5.2.6," the clause whose own heading is
    /// "5.2.6 The <c>adoTst</c> (COSE payload time-stamp) header parameter." <see cref="Reference"/> below
    /// faithfully transcribes Table 14's printed cell ("5.3.2") per this registry's own transcription
    /// discipline; the ruled reading is "5.2.6" — a reading correction, not a change to the data recorded.
    /// </remarks>
    public static AdESTableRow AdoTst { get; } = new()
    {
        RequirementId = "CB-6.3-19",
        Name = "adoTst",
        Kind = AdESTableRowKind.Component,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.3.2"),
        Annotations = new AdESRowAnnotations { NoteNumbers = [6] }
    };

    /// <summary>
    /// <c>sigPSt</c> (CB-6.3-20): conditioned presence at all 4 levels; cardinality 0 or 1; ref clause 5.3.2;
    /// additional requirement (b) — CB-6.3-b: may be incorporated only if <see cref="SigPId"/> is also
    /// incorporated and carries its <c>digVal</c> member; otherwise shall not be incorporated. It
    /// shares its References clause (5.3.2) verbatim with <see cref="AdoTst"/>. The condition is the lettered
    /// requirement itself, not a distinct clause, so <see cref="AdESTableRow.PresenceConditionClauses"/> is
    /// left <see langword="null"/> here.
    /// </summary>
    public static AdESTableRow SigPSt { get; } = new()
    {
        RequirementId = "CB-6.3-20",
        Name = "sigPSt",
        Kind = AdESTableRowKind.Component,
        Presence = AdESRowPresence.Uniform(AdESPresence.ConditionedPresence),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.3.2"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["b"] }
    };

    /// <summary>
    /// <c>sigTst</c> (CB-6.3-21): presence <see cref="AdESBaselineLevel.BB"/> = <c>"*"</c> (should not be
    /// present); <see cref="AdESBaselineLevel.BT"/>/<see cref="AdESBaselineLevel.BLT"/>/
    /// <see cref="AdESBaselineLevel.BLTA"/> = shall be present. Ref clause 5.3.3; additional requirements
    /// (c)/(d); note 7.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>Duplicate line, reproduced.</strong>
    /// <see cref="AdESRowCardinality.Statements"/> carries FOUR statements, exactly as the source PDF's cell
    /// stacks them (confirmed by rendered-page visual inspection, not a
    /// markdown-conversion artifact): <c>{B-B: ≥0}</c>, <c>{B-T,B-LT,B-LTA: ≥1}</c>, <c>{B-LT,B-LTA: 0}</c>,
    /// <c>{B-LT,B-LTA: 0}</c> — the last two character-for-character identical. This model does NOT collapse
    /// the duplicate: <see cref="AdESRowCardinality.ValuesAt"/> at <see cref="AdESBaselineLevel.BLT"/> or
    /// <see cref="AdESBaselineLevel.BLTA"/> returns three values, <c>[OneOrMore, ExactlyZero, ExactlyZero]</c>.
    /// </para>
    /// <para>
    /// <strong>Ruled reading.</strong> The <c>≥1</c> statement is the CUMULATIVE total —
    /// once at B-T, at least one <c>sigTst</c> instance is present, and this stands unchanged through B-LT and
    /// B-LTA. The <c>0</c> statement (reproduced twice) is the INCREMENTAL reading: zero NEW <c>sigTst</c>
    /// instances are added specifically when transitioning into B-LT or B-LTA — an augmentation orchestrator
    /// must not mint a further <c>sigTst</c> at those two upgrade steps, even though multiple TSAs remain a
    /// legal way to satisfy the B-B→B-T transition's own <c>≥1</c> (note 7: "each <c>sigTst</c> shall contain
    /// only one electronic time-stamp" per requirement (c); redundancy across TSAs is achieved by repeating the
    /// B-T-transition's <c>sigTst</c> incorporation, never by adding instances later).
    /// </para>
    /// </remarks>
    public static AdESTableRow SigTst { get; } = new()
    {
        RequirementId = "CB-6.3-21",
        Name = "sigTst",
        Kind = AdESTableRowKind.Component,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShallBePresent,
            BLT = AdESPresence.ShallBePresent,
            BLTA = AdESPresence.ShallBePresent
        },
        Cardinality = new AdESRowCardinality
        {
            Statements =
            [
                new AdESCardinalityStatement(AdESBaselineLevelSet.BB, AdESCardinality.ZeroOrMore),
                new AdESCardinalityStatement(AdESBaselineLevelSet.BT | AdESBaselineLevelSet.BLT | AdESBaselineLevelSet.BLTA, AdESCardinality.OneOrMore),
                new AdESCardinalityStatement(AdESBaselineLevelSet.BLT | AdESBaselineLevelSet.BLTA, AdESCardinality.ExactlyZero),
                new AdESCardinalityStatement(AdESBaselineLevelSet.BLT | AdESBaselineLevelSet.BLTA, AdESCardinality.ExactlyZero)
            ]
        },
        Reference = new AdESInternalClauseReference("5.3.3"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["c", "d"], NoteNumbers = [7] }
    };

    /// <summary>
    /// <c>valData</c> (CB-6.3-22): presence <see cref="AdESBaselineLevel.BB"/>/<see cref="AdESBaselineLevel.BT"/>
    /// = <c>"*"</c>; <see cref="AdESBaselineLevel.BLT"/>/<see cref="AdESBaselineLevel.BLTA"/> = conditioned
    /// presence; cardinality ≥0, level-invariant (unlike the four level-split rows,
    /// <c>valData</c> carries a single row-wide cardinality despite its level-split presence); ref clause
    /// 5.3.4; additional requirements (e)/(f) — the presence condition from B-LT onward is resolved via
    /// <see cref="ValidationDataForTimestampsService"/>'s Service/SPO rows, not a clause, so
    /// <see cref="AdESTableRow.PresenceConditionClauses"/> is left <see langword="null"/> here.
    /// </summary>
    public static AdESTableRow ValData { get; } = new()
    {
        RequirementId = "CB-6.3-22",
        Name = "valData",
        Kind = AdESTableRowKind.Component,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ConditionedPresence,
            BLTA = AdESPresence.ConditionedPresence
        },
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrMore),
        Reference = new AdESInternalClauseReference("5.3.4"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["e", "f"] }
    };

    /// <summary>
    /// <c>refs</c> (Annex A.1.1, CB-6.3-23): presence <see cref="AdESBaselineLevel.BB"/>/<see cref="AdESBaselineLevel.BT"/>
    /// = <c>"*"</c>; <see cref="AdESBaselineLevel.BLT"/>/<see cref="AdESBaselineLevel.BLTA"/> = shall not
    /// be present; cardinality level-split: <c>{B-B,B-T: ≥0}</c>, <c>{B-LT,B-LTA: 0}</c>; ref clause A.1.1;
    /// additional requirement (g) — a B-B/B-T-only, soft-discouraged, then hard-forbidden-from-B-LT component;
    /// a level transition to B-LT/B-LTA must strip any pre-existing <c>refs</c> (part of the B-B/B-T-only
    /// reference-and-timestamp mechanism together with <see cref="SigRTst"/>/<see cref="RfsTst"/>).
    /// </summary>
    public static AdESTableRow Refs { get; } = new()
    {
        RequirementId = "CB-6.3-23",
        Name = "refs",
        Kind = AdESTableRowKind.Component,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ShallNotBePresent,
            BLTA = AdESPresence.ShallNotBePresent
        },
        Cardinality = new AdESRowCardinality
        {
            Statements =
            [
                new AdESCardinalityStatement(AdESBaselineLevelSet.BB | AdESBaselineLevelSet.BT, AdESCardinality.ZeroOrMore),
                new AdESCardinalityStatement(AdESBaselineLevelSet.BLT | AdESBaselineLevelSet.BLTA, AdESCardinality.ExactlyZero)
            ]
        },
        Reference = new AdESInternalClauseReference("A.1.1"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["g"] }
    };

    /// <summary>
    /// <c>sigRTst</c> (Annex A.1.2.1, CB-6.3-24): same presence/cardinality shape as <see cref="Refs"/> —
    /// presence <c>"*"</c> at B-B/B-T, shall-not-be-present at B-LT/B-LTA; cardinality level-split
    /// <c>{B-B,B-T: ≥0}</c>, <c>{B-LT,B-LTA: 0}</c>; ref clause A.1.2.1; no lettered requirement.
    /// </summary>
    public static AdESTableRow SigRTst { get; } = new()
    {
        RequirementId = "CB-6.3-24",
        Name = "sigRTst",
        Kind = AdESTableRowKind.Component,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ShallNotBePresent,
            BLTA = AdESPresence.ShallNotBePresent
        },
        Cardinality = new AdESRowCardinality
        {
            Statements =
            [
                new AdESCardinalityStatement(AdESBaselineLevelSet.BB | AdESBaselineLevelSet.BT, AdESCardinality.ZeroOrMore),
                new AdESCardinalityStatement(AdESBaselineLevelSet.BLT | AdESBaselineLevelSet.BLTA, AdESCardinality.ExactlyZero)
            ]
        },
        Reference = new AdESInternalClauseReference("A.1.2.1")
    };

    /// <summary>
    /// <c>rfsTst</c> (Annex A.1.2.2, CB-6.3-25): same presence/cardinality shape as <see cref="Refs"/>/
    /// <see cref="SigRTst"/> — presence <c>"*"</c> at B-B/B-T, shall-not-be-present at B-LT/B-LTA; cardinality
    /// level-split <c>{B-B,B-T: ≥0}</c>, <c>{B-LT,B-LTA: 0}</c>; ref clause A.1.2.2; no lettered requirement.
    /// </summary>
    public static AdESTableRow RfsTst { get; } = new()
    {
        RequirementId = "CB-6.3-25",
        Name = "rfsTst",
        Kind = AdESTableRowKind.Component,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ShallNotBePresent,
            BLTA = AdESPresence.ShallNotBePresent
        },
        Cardinality = new AdESRowCardinality
        {
            Statements =
            [
                new AdESCardinalityStatement(AdESBaselineLevelSet.BB | AdESBaselineLevelSet.BT, AdESCardinality.ZeroOrMore),
                new AdESCardinalityStatement(AdESBaselineLevelSet.BLT | AdESBaselineLevelSet.BLTA, AdESCardinality.ExactlyZero)
            ]
        },
        Reference = new AdESInternalClauseReference("A.1.2.2")
    };

    /// <summary>
    /// Service "Incorporation of validation data for electronic time-stamps" (CB-6.3-26): presence
    /// <see cref="AdESBaselineLevel.BB"/>/<see cref="AdESBaselineLevel.BT"/> = <c>"*"</c>;
    /// <see cref="AdESBaselineLevel.BLT"/>/<see cref="AdESBaselineLevel.BLTA"/> = shall be provided;
    /// cardinality "-" (n/a, service row); ref "-"; additional requirements (h)/(i); note 8.
    /// </summary>
    /// <remarks>
    /// A service-level obligation resolved by ≥1 satisfied SPO row — <see cref="ValDataServiceProvisionOption"/>
    /// (CB-6.3-27) or <see cref="EmbeddedValidationDataServiceProvisionOption"/> (CB-6.3-28) — never by a
    /// single header, and evaluated only from B-LT onward. CB-6.3-h: satisfaction is the logical OR of the two
    /// SPOs (<see cref="AdESTableRow.ServiceProvisionOptionRequirementIds"/>). CB-6.3-i: the generator
    /// SHOULD prefer <c>valData</c> over the embedded-in-TST SPO when both are available
    /// (<see cref="AdESTableRow.PreferredServiceProvisionOptionRequirementId"/> names CB-6.3-27).
    /// </remarks>
    public static AdESTableRow ValidationDataForTimestampsService { get; } = new()
    {
        RequirementId = "CB-6.3-26",
        Name = "Service: Incorporation of validation data for electronic time-stamps",
        Kind = AdESTableRowKind.Service,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ShallBeProvided,
            BLTA = AdESPresence.ShallBeProvided
        },
        Cardinality = null,
        Reference = null,
        Annotations = new AdESRowAnnotations { RequirementLetters = ["h", "i"], NoteNumbers = [8] },
        ServiceProvisionOptionRequirementIds = ["CB-6.3-27", "CB-6.3-28"],
        PreferredServiceProvisionOptionRequirementId = "CB-6.3-27"
    };

    /// <summary>
    /// SPO <c>valData</c> (CB-6.3-27): presence <c>"*"</c> at B-B/B-T; conditioned presence at B-LT/B-LTA;
    /// cardinality ≥0; ref clause 5.3.4; no separate lettered requirement (governed by
    /// <see cref="ValidationDataForTimestampsService"/>'s own (h)/(i)) — one of the two ways of satisfying the
    /// time-stamp-validation-data service; duplicates <see cref="ValData"/>'s own row under its
    /// service-provision framing.
    /// </summary>
    public static AdESTableRow ValDataServiceProvisionOption { get; } = new()
    {
        RequirementId = "CB-6.3-27",
        Name = "SPO: valData",
        Kind = AdESTableRowKind.ServiceProvisionOption,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ConditionedPresence,
            BLTA = AdESPresence.ConditionedPresence
        },
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrMore),
        Reference = new AdESInternalClauseReference("5.3.4")
    };

    /// <summary>
    /// SPO "certificate and revocation values embedded in the electronic time-stamp itself" (CB-6.3-28):
    /// presence <c>"*"</c> at B-B/B-T; conditioned presence at B-LT/B-LTA; cardinality ≥0; ref "-"; additional
    /// requirement (i) — the second SPO: the TST's own embedded cert/revocation data (e.g. a CMS
    /// <c>SignedData</c> in an RFC 3161 token) counts as satisfying the service in lieu of <c>valData</c>
    /// entries.
    /// </summary>
    public static AdESTableRow EmbeddedValidationDataServiceProvisionOption { get; } = new()
    {
        RequirementId = "CB-6.3-28",
        Name = "SPO: certificate and revocation values embedded in the electronic time-stamp itself",
        Kind = AdESTableRowKind.ServiceProvisionOption,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ConditionedPresence,
            BLTA = AdESPresence.ConditionedPresence
        },
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrMore),
        Reference = null,
        Annotations = new AdESRowAnnotations { RequirementLetters = ["i"] }
    };

    /// <summary>
    /// <c>arcTst</c> (CB-6.3-29): presence <see cref="AdESBaselineLevel.BB"/>/<see cref="AdESBaselineLevel.BT"/>/
    /// <see cref="AdESBaselineLevel.BLT"/> = <c>"*"</c>; <see cref="AdESBaselineLevel.BLTA"/> = shall be
    /// present; cardinality ≥1, level-invariant (a single row-wide value despite the
    /// level-split presence — see <see cref="ValData"/> for the same pattern); ref clause 5.3.5; additional
    /// requirements (j)/(k) — B-LTA-exclusive and mandatory once at that level; requirement (k) mandates a
    /// full validation-material refresh immediately before each new <c>arcTst</c> (not enforced by this data
    /// model; owned by the augmentation orchestrator).
    /// </summary>
    public static AdESTableRow ArcTst { get; } = new()
    {
        RequirementId = "CB-6.3-29",
        Name = "arcTst",
        Kind = AdESTableRowKind.Component,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ShouldNotBePresent,
            BLTA = AdESPresence.ShallBePresent
        },
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.OneOrMore),
        Reference = new AdESInternalClauseReference("5.3.5"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["j", "k"] }
    };


    /// <summary>Gets every Table 14 row, in the source table's own order (CB-6.3-04..29).</summary>
    public static IReadOnlyList<AdESTableRow> Rows { get; } =
    [
        Alg, ContentType, Kid, X5U, X5Chain, Crit, CwtClaims, X5T, X5Ts,
        SigD, SrAts, SrCms, SigPl, SigPId, CounterSignature, AdoTst, SigPSt,
        SigTst, ValData, Refs, SigRTst, RfsTst,
        ValidationDataForTimestampsService, ValDataServiceProvisionOption, EmbeddedValidationDataServiceProvisionOption,
        ArcTst
    ];


    /// <summary>Gets whether <paramref name="row"/> is a <see cref="AdESTableRowKind.Service"/> row.</summary>
    /// <param name="row">The row to test.</param>
    /// <returns><see langword="true"/> when <paramref name="row"/>'s kind is <see cref="AdESTableRowKind.Service"/>.</returns>
    public static bool IsServiceRow(AdESTableRow row)
    {
        ArgumentNullException.ThrowIfNull(row);

        return row.IsServiceRow;
    }


    /// <summary>Gets whether <paramref name="row"/> is a <see cref="AdESTableRowKind.ServiceProvisionOption"/> row.</summary>
    /// <param name="row">The row to test.</param>
    /// <returns><see langword="true"/> when <paramref name="row"/>'s kind is <see cref="AdESTableRowKind.ServiceProvisionOption"/>.</returns>
    public static bool IsServiceProvisionOptionRow(AdESTableRow row)
    {
        ArgumentNullException.ThrowIfNull(row);

        return row.IsServiceProvisionOptionRow;
    }


    /// <summary>Finds the registered row whose <see cref="AdESTableRow.RequirementId"/> matches <paramref name="requirementId"/>.</summary>
    /// <param name="requirementId">The requirement identifier to look up (e.g. <c>"CB-6.3-21"</c>).</param>
    /// <returns>The matching row, or <see langword="null"/> when no registered row carries that identifier.</returns>
    public static AdESTableRow? FindByRequirementId(string requirementId)
    {
        ArgumentNullException.ThrowIfNull(requirementId);

        return AdESBaselineLevelTables.FindByRequirementId(Rows, requirementId);
    }


    /// <summary>
    /// Resolves a <see cref="AdESTableRowKind.Service"/> row's SPO children to their registered
    /// <see cref="AdESTableRow"/> instances, in the order <see cref="AdESTableRow.ServiceProvisionOptionRequirementIds"/>
    /// lists them.
    /// </summary>
    /// <param name="serviceRow">The service row to resolve children for.</param>
    /// <returns>The service row's SPO rows, in declared order.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="serviceRow"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="serviceRow"/> is not a <see cref="AdESTableRowKind.Service"/> row.</exception>
    /// <exception cref="InvalidOperationException">
    /// <paramref name="serviceRow"/> names an SPO requirement identifier that is not registered in <see cref="Rows"/>.
    /// </exception>
    public static IReadOnlyList<AdESTableRow> ServiceProvisionOptionsFor(AdESTableRow serviceRow)
    {
        return AdESBaselineLevelTables.ServiceProvisionOptionsFor(Rows, serviceRow);
    }
}
