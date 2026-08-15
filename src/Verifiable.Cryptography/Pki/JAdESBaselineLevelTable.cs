using System;
using System.Collections.Generic;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The Table 1 (clause 6.3) row registry — all 38 rows JA-6.3-05..42 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 6.3</see> (zoom-verified pp. 46-47), exposed as static getters
/// (the <c>CBAdESBaselineLevelTable</c>/<c>CoseHeaderParameters</c> exemplar shape) plus lookup helpers over
/// <see cref="Rows"/>. JOSE/JSON-free: this class carries only the presence/cardinality/reference/annotation
/// DATA clause 6 states, never a wire encoding or a rule-evaluation engine — those compose this registry from
/// <see cref="JAdESLevelRules"/>.
/// </summary>
/// <remarks>
/// <para>
/// Row-kind counts (see <see cref="AdESTableRowKind"/>): 8 <see cref="AdESTableRowKind.HeaderParameter"/> rows
/// (<see cref="Alg"/>, <see cref="ContentType"/>, <see cref="Kid"/>, <see cref="X5U"/>, <see cref="X5Chain"/>,
/// <see cref="Crit"/>, <see cref="IssuedAt"/>, <see cref="SigT"/>), 21 <see cref="AdESTableRowKind.Component"/>
/// rows (<see cref="SigD"/>, <see cref="SrAts"/>, <see cref="SrCms"/>, <see cref="SigPl"/>, <see cref="SigPId"/>,
/// <see cref="CSig"/>, <see cref="AdoTst"/>, <see cref="SigPSt"/>, <see cref="SigTst"/>, <see cref="XVals"/>,
/// <see cref="AnyValData"/>, <see cref="XRefs"/>, <see cref="AxVals"/>, <see cref="AxRefs"/>, <see cref="RVals"/>,
/// <see cref="RRefs"/>, <see cref="ArVals"/>, <see cref="ArRefs"/>, <see cref="SigRTst"/>, <see cref="RfsTst"/>,
/// <see cref="ArcTst"/>), 3 <see cref="AdESTableRowKind.Service"/> rows (<see cref="SigningTimeService"/>,
/// <see cref="SigningCertificateReferenceService"/>, <see cref="ValidationDataForTimestampsService"/>), and 6
/// <see cref="AdESTableRowKind.ServiceProvisionOption"/> rows (<see cref="X5tHashS256Option"/>,
/// <see cref="X5tHashOOption"/>, <see cref="SigX5tsOption"/>, <see cref="TstVdOption"/>,
/// <see cref="EmbeddedValidationDataOption"/>, <see cref="AnyValDataOption"/>) — 38 rows total.
/// </para>
/// <para>
/// <strong>Ruled reading.</strong> Table 1's <c>crit</c> row (JA-6.3-10) prints a
/// blank Cardinality cell in the source PDF — verified twice independently (text-layer extraction and
/// 3× zoom render). The ruled reading is "0 or 1" (the uniform single-header-row pattern every other
/// "Conditioned presence" + single-header-parameter row in Table 1 states, and clause 5.1.9 offers no other
/// value) — see <see cref="Crit"/>'s own remarks.
/// </para>
/// <para>
/// <strong>Reference clause, corrected.</strong>
/// <see cref="AdoTst"/>'s row (JA-6.3-24) prints "Clause 5.3.3" in its References column — <see cref="SigPSt"/>'s
/// own defining clause (JA-6.3-25, the very next row), not "Clause 5.2.6," whose own heading is "The <c>adoTst</c>
/// (signed data time-stamp) header parameter" (<see cref="WellKnownJAdESHeaderNames.AdoTst"/>'s own remarks) —
/// the same copy-paste-from-<c>sigPSt</c> defect CB-AdES's own Table 14 carries, further evidence of
/// shared drafting lineage; the ruled reading is "5.2.6". <see cref="AdoTst"/>.<see cref="AdESTableRow.Reference"/> below
/// faithfully transcribes Table 1's printed cell ("5.3.3") per this registry's own transcription discipline,
/// mirroring the identical transcribe-the-printed-cell/document-the-ruled-reading-separately posture the
/// CB-AdES registry applies for the same defect — this remark carries the ruled reading (5.2.6).
/// </para>
/// <para>
/// <strong>iat/sigT (letter a) already enforced elsewhere.</strong> <see cref="IssuedAt"/>/<see cref="SigT"/>
/// (JA-6.3-12/-13, both letter <c>a</c>) are transcribed here exactly as Table 1 states them (uniform
/// "Conditioned presence", cardinality "0 or 1" — a static, pre/post-cutover-agnostic view); the temporal
/// SHALL-from-2025-07-15 obligation letter a)'s third sentence states is already a LIVE rule at
/// <see cref="JAdESHeaderRules.Check"/> (<see cref="JAdESIssuedAtMissingViolation"/>) and is not
/// re-implemented by <see cref="JAdESLevelRules"/> — see that rule surface's own remarks for the ruled reading
/// of letter a)'s SHOULD-NOT half (the "should not include the `iat`..." clause is read as <c>sigT</c>),
/// which is moot for any current-time evaluation now that the cutover date has passed.
/// </para>
/// </remarks>
public static class JAdESBaselineLevelTable
{
    /// <summary>
    /// <c>alg</c> (JA-6.3-05): shall be present at all 4 levels; cardinality 1; ref clause 5.1.2; no additional
    /// notes — the simplest presence class, mandatory and level-invariant.
    /// </summary>
    public static AdESTableRow Alg { get; } = new()
    {
        RequirementId = "JA-6.3-05",
        Name = "alg",
        Kind = AdESTableRowKind.HeaderParameter,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyOne),
        Reference = new AdESInternalClauseReference("5.1.2")
    };

    /// <summary>
    /// <c>cty</c> (JA-6.3-06): conditioned presence at all 4 levels; cardinality 0 or 1; ref clause 5.1.3; note 2
    /// — the presence predicate is jointly shared with clause 5.2.8.1's <c>sigD</c>/<c>ctys</c> mechanism.
    /// </summary>
    public static AdESTableRow ContentType { get; } = new()
    {
        RequirementId = "JA-6.3-06",
        Name = "cty",
        Kind = AdESTableRowKind.HeaderParameter,
        Presence = AdESRowPresence.Uniform(AdESPresence.ConditionedPresence),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.1.3"),
        Annotations = new AdESRowAnnotations { NoteNumbers = [2] }
    };

    /// <summary>
    /// <c>kid</c> (JA-6.3-07): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.1.4 — a simple
    /// optional singleton, level-invariant.
    /// </summary>
    public static AdESTableRow Kid { get; } = new()
    {
        RequirementId = "JA-6.3-07",
        Name = "kid",
        Kind = AdESTableRowKind.HeaderParameter,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.1.4")
    };

    /// <summary>
    /// <c>x5u</c> (JA-6.3-08): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.1.5 — a simple
    /// optional singleton, level-invariant.
    /// </summary>
    public static AdESTableRow X5U { get; } = new()
    {
        RequirementId = "JA-6.3-08",
        Name = "x5u",
        Kind = AdESTableRowKind.HeaderParameter,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.1.5")
    };

    /// <summary>
    /// <c>x5c</c> (JA-6.3-09): conditioned presence at all 4 levels; cardinality 0 or 1; ref clause 5.1.8;
    /// note 3 — part of the four-way signing-certificate-identification disjunction (JA-5.1.7-04) clause 5.1.7
    /// governs.
    /// </summary>
    public static AdESTableRow X5Chain { get; } = new()
    {
        RequirementId = "JA-6.3-09",
        Name = "x5c",
        Kind = AdESTableRowKind.HeaderParameter,
        Presence = AdESRowPresence.Uniform(AdESPresence.ConditionedPresence),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.1.8"),
        Annotations = new AdESRowAnnotations { NoteNumbers = [3] }
    };

    /// <summary>
    /// <c>crit</c> (JA-6.3-10): conditioned presence at all 4 levels; cardinality 0 or 1 (the
    /// source table's own Cardinality cell prints blank; see the type remarks); ref clause 5.1.9; note 4.
    /// </summary>
    public static AdESTableRow Crit { get; } = new()
    {
        RequirementId = "JA-6.3-10",
        Name = "crit",
        Kind = AdESTableRowKind.HeaderParameter,
        Presence = AdESRowPresence.Uniform(AdESPresence.ConditionedPresence),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.1.9"),
        Annotations = new AdESRowAnnotations { NoteNumbers = [4] }
    };

    /// <summary>
    /// Service "Incorporation of claimed signing time" (JA-6.3-11): shall be provided at all 4 levels;
    /// cardinality "-" (n/a, service row); ref "-"; no letter/note. Satisfied by <see cref="IssuedAt"/> or
    /// <see cref="SigT"/> (JA-6.3-12/-13) — Table 1's own column-1 cells for both print as plain header-
    /// parameter names, with no "SPO:" prefix (unlike <see cref="SigningCertificateReferenceService"/>'s three
    /// children), so <see cref="AdESTableRow.ServiceProvisionOptionRequirementIds"/> is left
    /// <see langword="null"/> here rather than naming rows the table's own column-1 convention (JA-6.2.2-10/-11)
    /// classifies as ordinary header parameters, not SPOs — a genuine document-structural fact, transcribed
    /// faithfully rather than normalized away.
    /// </summary>
    public static AdESTableRow SigningTimeService { get; } = new()
    {
        RequirementId = "JA-6.3-11",
        Name = "Service: Incorporation of claimed signing time",
        Kind = AdESTableRowKind.Service,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallBeProvided),
        Cardinality = null,
        Reference = null
    };

    /// <summary>
    /// <c>iat</c> (JA-6.3-12): conditioned presence at all 4 levels; cardinality 0 or 1; ref clause 5.1.11;
    /// letter a — see the type remarks for why letter a)'s live SHALL-from-2025-07-15 obligation is enforced at
    /// <see cref="JAdESHeaderRules"/>, not re-implemented here.
    /// </summary>
    public static AdESTableRow IssuedAt { get; } = new()
    {
        RequirementId = "JA-6.3-12",
        Name = "iat",
        Kind = AdESTableRowKind.HeaderParameter,
        Presence = AdESRowPresence.Uniform(AdESPresence.ConditionedPresence),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.1.11"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["a"] }
    };

    /// <summary>
    /// <c>sigT</c> (JA-6.3-13): conditioned presence at all 4 levels; cardinality 0 or 1; ref clause 5.2.1;
    /// letter a — the legacy claimed-signing-time header, superseded by <see cref="IssuedAt"/>.
    /// </summary>
    public static AdESTableRow SigT { get; } = new()
    {
        RequirementId = "JA-6.3-13",
        Name = "sigT",
        Kind = AdESTableRowKind.HeaderParameter,
        Presence = AdESRowPresence.Uniform(AdESPresence.ConditionedPresence),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.2.1"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["a"] }
    };

    /// <summary>
    /// Service "signing a reference of the signing certificate" (JA-6.3-14): conditioned presence at all 4
    /// levels; cardinality 1 (Table 1 states an actual value here, unlike CB-AdES's own "-" service-row
    /// convention); ref "-"; note 3. Satisfied by any of its three literally "SPO:"-prefixed children
    /// (<see cref="X5tHashS256Option"/>/<see cref="X5tHashOOption"/>/<see cref="SigX5tsOption"/>,
    /// JA-6.3-15..17) — note 3 additionally ties <c>x5c</c> (<see cref="X5Chain"/>) into the same four-way
    /// disjunction (JA-5.1.7-04) without <c>x5c</c>'s own row carrying the "SPO:" column-1 prefix.
    /// </summary>
    public static AdESTableRow SigningCertificateReferenceService { get; } = new()
    {
        RequirementId = "JA-6.3-14",
        Name = "Service: signing a reference of the signing certificate",
        Kind = AdESTableRowKind.Service,
        Presence = AdESRowPresence.Uniform(AdESPresence.ConditionedPresence),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyOne),
        Reference = null,
        Annotations = new AdESRowAnnotations { NoteNumbers = [3] },
        ServiceProvisionOptionRequirementIds = ["JA-6.3-15", "JA-6.3-16", "JA-6.3-17"]
    };

    /// <summary>
    /// SPO <c>x5t#256</c> (JA-6.3-15): conditioned presence at all 4 levels; cardinality 0 or 1; ref clause
    /// 5.1.7. Name transcribed exactly as Table 1 prints it — the wire header this row's own
    /// clause 5.1.7 profiles is <c>x5t#S256</c> (<see cref="WellKnownJwkMemberNames.X5tHashS256"/>); the printed
    /// cell omits the capital "S", not independently re-flagged here beyond this note.
    /// </summary>
    public static AdESTableRow X5tHashS256Option { get; } = new()
    {
        RequirementId = "JA-6.3-15",
        Name = "SPO: x5t#256",
        Kind = AdESTableRowKind.ServiceProvisionOption,
        Presence = AdESRowPresence.Uniform(AdESPresence.ConditionedPresence),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.1.7")
    };

    /// <summary>
    /// SPO <c>x5t#o</c> (JA-6.3-16): conditioned presence at all 4 levels; cardinality 0 or 1; ref clause 5.2.2.
    /// </summary>
    public static AdESTableRow X5tHashOOption { get; } = new()
    {
        RequirementId = "JA-6.3-16",
        Name = "SPO: x5t#o",
        Kind = AdESTableRowKind.ServiceProvisionOption,
        Presence = AdESRowPresence.Uniform(AdESPresence.ConditionedPresence),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.2.2")
    };

    /// <summary>
    /// SPO <c>sigX5ts</c> (JA-6.3-17): conditioned presence at all 4 levels; cardinality 0 or 1; ref clause
    /// 5.2.2.
    /// </summary>
    public static AdESTableRow SigX5tsOption { get; } = new()
    {
        RequirementId = "JA-6.3-17",
        Name = "SPO: sigX5ts",
        Kind = AdESTableRowKind.ServiceProvisionOption,
        Presence = AdESRowPresence.Uniform(AdESPresence.ConditionedPresence),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.2.2")
    };

    /// <summary>
    /// <c>sigD</c> (JA-6.3-18): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.2.8 — a
    /// level-invariant optional singleton.
    /// </summary>
    public static AdESTableRow SigD { get; } = new()
    {
        RequirementId = "JA-6.3-18",
        Name = "sigD",
        Kind = AdESTableRowKind.Component,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.2.8")
    };

    /// <summary>
    /// <c>srAts</c> (JA-6.3-19): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.2.5 — a
    /// level-invariant optional singleton.
    /// </summary>
    public static AdESTableRow SrAts { get; } = new()
    {
        RequirementId = "JA-6.3-19",
        Name = "srAts",
        Kind = AdESTableRowKind.Component,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.2.5")
    };

    /// <summary>
    /// <c>srCms</c> (JA-6.3-20): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.2.3; note 5 —
    /// the cardinality is at the HEADER level: the value itself is a JSON array that may hold several
    /// commitments, which this row's cardinality does not count.
    /// </summary>
    public static AdESTableRow SrCms { get; } = new()
    {
        RequirementId = "JA-6.3-20",
        Name = "srCms",
        Kind = AdESTableRowKind.Component,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.2.3"),
        Annotations = new AdESRowAnnotations { NoteNumbers = [5] }
    };

    /// <summary>
    /// <c>sigPl</c> (JA-6.3-21): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.2.4 — a
    /// level-invariant optional singleton.
    /// </summary>
    public static AdESTableRow SigPl { get; } = new()
    {
        RequirementId = "JA-6.3-21",
        Name = "sigPl",
        Kind = AdESTableRowKind.Component,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.2.4")
    };

    /// <summary>
    /// <c>sigPId</c> (JA-6.3-22): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.2.7 — a
    /// level-invariant optional singleton; its own presence together with its <c>digVal</c> member gates
    /// <see cref="SigPSt"/>'s presence (letter b).
    /// </summary>
    public static AdESTableRow SigPId { get; } = new()
    {
        RequirementId = "JA-6.3-22",
        Name = "sigPId",
        Kind = AdESTableRowKind.Component,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.2.7")
    };

    /// <summary>
    /// <c>cSig</c> (JA-6.3-23): may be present at all 4 levels; cardinality ≥ 0; ref clause 5.3.2 — unbounded
    /// repeatable, level-invariant.
    /// </summary>
    public static AdESTableRow CSig { get; } = new()
    {
        RequirementId = "JA-6.3-23",
        Name = "cSig",
        Kind = AdESTableRowKind.Component,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrMore),
        Reference = new AdESInternalClauseReference("5.3.2")
    };

    /// <summary>
    /// <c>adoTst</c> (JA-6.3-24): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.3.3 (printed
    /// verbatim — see the type remarks: <c>adoTst</c>'s own defining clause is 5.2.6); note 6 — the
    /// header-level cardinality of 0-or-1 is independent of how many electronic
    /// time-stamps (possibly from different TSAs) the internal <c>tstContainer</c> holds.
    /// </summary>
    public static AdESTableRow AdoTst { get; } = new()
    {
        RequirementId = "JA-6.3-24",
        Name = "adoTst",
        Kind = AdESTableRowKind.Component,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.3.3"),
        Annotations = new AdESRowAnnotations { NoteNumbers = [6] }
    };

    /// <summary>
    /// <c>sigPSt</c> (JA-6.3-25): conditioned presence at all 4 levels; cardinality 0 or 1; ref clause 5.3.3;
    /// letter b — JA-6.3-b1/-b2: may be incorporated only if <see cref="SigPId"/> is also incorporated and
    /// carries its <c>digVal</c> member; otherwise shall not be incorporated.
    /// </summary>
    public static AdESTableRow SigPSt { get; } = new()
    {
        RequirementId = "JA-6.3-25",
        Name = "sigPSt",
        Kind = AdESTableRowKind.Component,
        Presence = AdESRowPresence.Uniform(AdESPresence.ConditionedPresence),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.3.3"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["b"] }
    };

    /// <summary>
    /// <c>sigTst</c> (JA-6.3-26): presence <see cref="AdESBaselineLevel.BB"/> = <c>"*"</c> (should not be
    /// present); <see cref="AdESBaselineLevel.BT"/>/<see cref="AdESBaselineLevel.BLT"/>/
    /// <see cref="AdESBaselineLevel.BLTA"/> = shall be present. Cardinality level-split: B-B ≥ 0, B-T/B-LT/B-LTA
    /// ≥ 1 (a single two-part cell, not a duplicated sub-line — see the type remarks contrasting CB-AdES's own
    /// duplicated row). Ref clause 5.3.4; letters c, d; note 7.
    /// </summary>
    public static AdESTableRow SigTst { get; } = new()
    {
        RequirementId = "JA-6.3-26",
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
                new AdESCardinalityStatement(AdESBaselineLevelSet.BT | AdESBaselineLevelSet.BLT | AdESBaselineLevelSet.BLTA, AdESCardinality.OneOrMore)
            ]
        },
        Reference = new AdESInternalClauseReference("5.3.4"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["c", "d"], NoteNumbers = [7] }
    };

    /// <summary>
    /// <c>xVals</c> (JA-6.3-27): presence <c>"*"</c> at B-B/B-T; conditioned presence at B-LT/B-LTA; cardinality
    /// 0 or 1, level-invariant despite the level-split presence; ref clause 5.3.5.2; letter e.
    /// </summary>
    public static AdESTableRow XVals { get; } = new()
    {
        RequirementId = "JA-6.3-27",
        Name = "xVals",
        Kind = AdESTableRowKind.Component,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ConditionedPresence,
            BLTA = AdESPresence.ConditionedPresence
        },
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.3.5.2"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["e"] }
    };

    /// <summary>
    /// <c>anyValData</c> (JA-6.3-28): presence <c>"*"</c> at B-B/B-T; conditioned presence at B-LT/B-LTA;
    /// cardinality ≥ 0; ref clause 5.3.5.6; letters e, i.
    /// </summary>
    public static AdESTableRow AnyValData { get; } = new()
    {
        RequirementId = "JA-6.3-28",
        Name = "anyValData",
        Kind = AdESTableRowKind.Component,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ConditionedPresence,
            BLTA = AdESPresence.ConditionedPresence
        },
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrMore),
        Reference = new AdESInternalClauseReference("5.3.5.6"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["e", "i"] }
    };

    /// <summary>
    /// <c>xRefs</c> (JA-6.3-29): presence <c>"*"</c> at B-B/B-T; shall not be present at B-LT/B-LTA; cardinality
    /// level-split: B-B/B-T 0 or 1, B-LT/B-LTA 0; ref clause A.1.1; letters f, g — a B-B/B-T-only,
    /// soft-discouraged, then hard-forbidden-from-B-LT component.
    /// </summary>
    public static AdESTableRow XRefs { get; } = new()
    {
        RequirementId = "JA-6.3-29",
        Name = "xRefs",
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
                new AdESCardinalityStatement(AdESBaselineLevelSet.BB | AdESBaselineLevelSet.BT, AdESCardinality.ZeroOrOne),
                new AdESCardinalityStatement(AdESBaselineLevelSet.BLT | AdESBaselineLevelSet.BLTA, AdESCardinality.ExactlyZero)
            ]
        },
        Reference = new AdESInternalClauseReference("A.1.1"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["f", "g"] }
    };

    /// <summary>
    /// <c>axVals</c> (JA-6.3-30): presence <c>"*"</c> at B-B/B-T; conditioned presence at B-LT/B-LTA; cardinality
    /// 0 or 1; ref clause 5.3.5.4; letter e.
    /// </summary>
    public static AdESTableRow AxVals { get; } = new()
    {
        RequirementId = "JA-6.3-30",
        Name = "axVals",
        Kind = AdESTableRowKind.Component,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ConditionedPresence,
            BLTA = AdESPresence.ConditionedPresence
        },
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.3.5.4"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["e"] }
    };

    /// <summary>
    /// <c>axRefs</c> (JA-6.3-31): presence <c>"*"</c> at B-B/B-T; shall not be present at B-LT/B-LTA; cardinality
    /// level-split: B-B/B-T 0 or 1, B-LT/B-LTA 0; ref clause A.1.3; letters f, g, h.
    /// </summary>
    public static AdESTableRow AxRefs { get; } = new()
    {
        RequirementId = "JA-6.3-31",
        Name = "axRefs",
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
                new AdESCardinalityStatement(AdESBaselineLevelSet.BB | AdESBaselineLevelSet.BT, AdESCardinality.ZeroOrOne),
                new AdESCardinalityStatement(AdESBaselineLevelSet.BLT | AdESBaselineLevelSet.BLTA, AdESCardinality.ExactlyZero)
            ]
        },
        Reference = new AdESInternalClauseReference("A.1.3"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["f", "g", "h"] }
    };

    /// <summary>
    /// <c>rVals</c> (JA-6.3-32): presence <c>"*"</c> at B-B/B-T; conditioned presence at B-LT/B-LTA; cardinality
    /// 0 or 1; ref clause 5.3.5.3; letter i.
    /// </summary>
    public static AdESTableRow RVals { get; } = new()
    {
        RequirementId = "JA-6.3-32",
        Name = "rVals",
        Kind = AdESTableRowKind.Component,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ConditionedPresence,
            BLTA = AdESPresence.ConditionedPresence
        },
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.3.5.3"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["i"] }
    };

    /// <summary>
    /// <c>rRefs</c> (JA-6.3-33): presence <c>"*"</c> at B-B/B-T; shall not be present at B-LT/B-LTA; cardinality
    /// level-split: B-B/B-T 0 or 1, B-LT/B-LTA 0; ref clause A.1.2; no lettered requirement.
    /// </summary>
    public static AdESTableRow RRefs { get; } = new()
    {
        RequirementId = "JA-6.3-33",
        Name = "rRefs",
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
                new AdESCardinalityStatement(AdESBaselineLevelSet.BB | AdESBaselineLevelSet.BT, AdESCardinality.ZeroOrOne),
                new AdESCardinalityStatement(AdESBaselineLevelSet.BLT | AdESBaselineLevelSet.BLTA, AdESCardinality.ExactlyZero)
            ]
        },
        Reference = new AdESInternalClauseReference("A.1.2")
    };

    /// <summary>
    /// <c>arVals</c> (JA-6.3-34): presence <c>"*"</c> at B-B/B-T; conditioned presence at B-LT/B-LTA; cardinality
    /// 0 or 1; ref clause 5.3.5.5; letter i.
    /// </summary>
    public static AdESTableRow ArVals { get; } = new()
    {
        RequirementId = "JA-6.3-34",
        Name = "arVals",
        Kind = AdESTableRowKind.Component,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ConditionedPresence,
            BLTA = AdESPresence.ConditionedPresence
        },
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.3.5.5"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["i"] }
    };

    /// <summary>
    /// <c>arRefs</c> (JA-6.3-35): presence <c>"*"</c> at B-B/B-T; shall not be present at B-LT/B-LTA; cardinality
    /// level-split: B-B/B-T 0 or 1, B-LT/B-LTA 0; ref clause A.1.4; letter h.
    /// </summary>
    public static AdESTableRow ArRefs { get; } = new()
    {
        RequirementId = "JA-6.3-35",
        Name = "arRefs",
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
                new AdESCardinalityStatement(AdESBaselineLevelSet.BB | AdESBaselineLevelSet.BT, AdESCardinality.ZeroOrOne),
                new AdESCardinalityStatement(AdESBaselineLevelSet.BLT | AdESBaselineLevelSet.BLTA, AdESCardinality.ExactlyZero)
            ]
        },
        Reference = new AdESInternalClauseReference("A.1.4"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["h"] }
    };

    /// <summary>
    /// <c>sigRTst</c> (JA-6.3-36): presence <c>"*"</c> at B-B/B-T; shall not be present at B-LT/B-LTA;
    /// cardinality level-split: B-B/B-T ≥ 0, B-LT/B-LTA 0; ref clause A.1.5.1; no lettered requirement.
    /// </summary>
    public static AdESTableRow SigRTst { get; } = new()
    {
        RequirementId = "JA-6.3-36",
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
        Reference = new AdESInternalClauseReference("A.1.5.1")
    };

    /// <summary>
    /// <c>rfsTst</c> (JA-6.3-37): same presence/cardinality shape as <see cref="SigRTst"/> — presence <c>"*"</c>
    /// at B-B/B-T, shall not be present at B-LT/B-LTA; cardinality level-split B-B/B-T ≥ 0, B-LT/B-LTA 0; ref
    /// clause A.1.5.2; no lettered requirement.
    /// </summary>
    public static AdESTableRow RfsTst { get; } = new()
    {
        RequirementId = "JA-6.3-37",
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
        Reference = new AdESInternalClauseReference("A.1.5.2")
    };

    /// <summary>
    /// Service "Incorporation of validation data for electronic time-stamps" (JA-6.3-38): presence <c>"*"</c> at
    /// B-B/B-T; shall be provided at B-LT/B-LTA; cardinality "-" (n/a, service row); ref "-"; letters j, k;
    /// note 8. Satisfied by any of its three literally "SPO:"-prefixed children
    /// (<see cref="TstVdOption"/>/<see cref="EmbeddedValidationDataOption"/>/<see cref="AnyValDataOption"/>,
    /// JA-6.3-39..41) — letter j's three-way disjunction. Letter k's SHOULD-NOT preference against the
    /// embedded-in-token option has no single-preferred-SPO field to populate here (unlike CB-AdES's own
    /// service row, whose (i) requirement names exactly one preferred SPO) — <see cref="JAdESLevelRules"/>
    /// documents, but does not enforce, letter k's soft preference.
    /// </summary>
    public static AdESTableRow ValidationDataForTimestampsService { get; } = new()
    {
        RequirementId = "JA-6.3-38",
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
        Annotations = new AdESRowAnnotations { RequirementLetters = ["j", "k"], NoteNumbers = [8] },
        ServiceProvisionOptionRequirementIds = ["JA-6.3-39", "JA-6.3-40", "JA-6.3-41"]
    };

    /// <summary>
    /// SPO <c>tstVD</c> (JA-6.3-39): presence <c>"*"</c> at B-B/B-T; conditioned presence at B-LT/B-LTA;
    /// cardinality ≥ 0; ref clause 5.3.6.1; no lettered requirement.
    /// </summary>
    public static AdESTableRow TstVdOption { get; } = new()
    {
        RequirementId = "JA-6.3-39",
        Name = "SPO: tstVD",
        Kind = AdESTableRowKind.ServiceProvisionOption,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ConditionedPresence,
            BLTA = AdESPresence.ConditionedPresence
        },
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrMore),
        Reference = new AdESInternalClauseReference("5.3.6.1")
    };

    /// <summary>
    /// SPO "certificate and revocation values embedded in the electronic time-stamp itself" (JA-6.3-40):
    /// presence <c>"*"</c> at B-B/B-T; conditioned presence at B-LT/B-LTA; cardinality ≥ 0; ref "-"; no lettered
    /// requirement — the TST's own embedded cert/revocation data counts as satisfying the service in lieu of
    /// <see cref="TstVdOption"/>/<see cref="AnyValDataOption"/> entries (letter k disfavors this option).
    /// </summary>
    public static AdESTableRow EmbeddedValidationDataOption { get; } = new()
    {
        RequirementId = "JA-6.3-40",
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
        Reference = null
    };

    /// <summary>
    /// SPO <c>anyValData</c> (JA-6.3-41): presence <c>"*"</c> at B-B/B-T; conditioned presence at B-LT/B-LTA;
    /// cardinality ≥ 0; ref clause 5.3.5.6; letters j, k — the same wire element as <see cref="AnyValData"/>
    /// under its service-provision framing.
    /// </summary>
    public static AdESTableRow AnyValDataOption { get; } = new()
    {
        RequirementId = "JA-6.3-41",
        Name = "SPO: anyValData",
        Kind = AdESTableRowKind.ServiceProvisionOption,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ConditionedPresence,
            BLTA = AdESPresence.ConditionedPresence
        },
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrMore),
        Reference = new AdESInternalClauseReference("5.3.5.6"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["j", "k"] }
    };

    /// <summary>
    /// <c>arcTst</c> (JA-6.3-42): presence <c>"*"</c> at B-B/B-T/B-LT; shall be present at B-LTA; cardinality
    /// ≥ 1, level-invariant; ref clause 5.3.6.2; letters l, m — B-LTA-exclusive and mandatory once at that
    /// level; letter m mandates a full validation-material refresh immediately before each new <c>arcTst</c>
    /// (not enforced by this data model; owned by the augmentation orchestrator).
    /// </summary>
    public static AdESTableRow ArcTst { get; } = new()
    {
        RequirementId = "JA-6.3-42",
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
        Reference = new AdESInternalClauseReference("5.3.6.2"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["l", "m"] }
    };


    /// <summary>Gets every Table 1 row, in the source table's own order (JA-6.3-05..42).</summary>
    public static IReadOnlyList<AdESTableRow> Rows { get; } =
    [
        Alg, ContentType, Kid, X5U, X5Chain, Crit,
        SigningTimeService, IssuedAt, SigT,
        SigningCertificateReferenceService, X5tHashS256Option, X5tHashOOption, SigX5tsOption,
        SigD, SrAts, SrCms, SigPl, SigPId, CSig, AdoTst, SigPSt,
        SigTst, XVals, AnyValData, XRefs, AxVals, AxRefs, RVals, RRefs, ArVals, ArRefs,
        SigRTst, RfsTst,
        ValidationDataForTimestampsService, TstVdOption, EmbeddedValidationDataOption, AnyValDataOption,
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
    /// <param name="requirementId">The requirement identifier to look up (e.g. <c>"JA-6.3-26"</c>).</param>
    /// <returns>The matching row, or <see langword="null"/> when no registered row carries that identifier.</returns>
    public static AdESTableRow? FindByRequirementId(string requirementId)
    {
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
    /// <exception cref="ArgumentException">
    /// <paramref name="serviceRow"/> is not a <see cref="AdESTableRowKind.Service"/> row, or names no SPO
    /// children (<see cref="SigningTimeService"/> — see that member's own remarks).
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// <paramref name="serviceRow"/> names an SPO requirement identifier that is not registered in <see cref="Rows"/>.
    /// </exception>
    public static IReadOnlyList<AdESTableRow> ServiceProvisionOptionsFor(AdESTableRow serviceRow)
    {
        return AdESBaselineLevelTables.ServiceProvisionOptionsFor(Rows, serviceRow);
    }
}
