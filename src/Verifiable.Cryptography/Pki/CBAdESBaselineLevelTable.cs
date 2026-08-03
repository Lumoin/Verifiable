using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The kind of thing a Table 14 row describes (CB-6.2.2-01/02): a plain header parameter or CB-AdES-specific
/// component, a service (satisfied by ≥1 of its SPO rows), or one of a service's SPO (service-provision-option)
/// rows, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 6.2.2</see>.
/// </summary>
/// <remarks>
/// Clause 6.2.2's own row-kind discrimination (CB-6.2.2-02) is a two-way string-prefix convention on column 1
/// ("Service"/"SPO"/anything else); this enum additionally splits the "anything else" bucket into
/// <see cref="HeaderParameter"/> (the plain IANA/RFC 9052/RFC 9360/CWT header fields profiled by clause 5.1)
/// and <see cref="Component"/> (the CB-AdES-specific structured CBOR objects of clauses 5.2/5.3/Annex A) — a
/// judgment call this model makes for a more informative row-kind than the source's own binary
/// service/non-service split; the source text itself does not name this second split explicitly (flagged for
/// review).
/// </remarks>
public enum CBAdESTableRowKind
{
    /// <summary>A plain header parameter profiled by clause 5.1 (e.g. <c>alg</c>, <c>x5chain</c>, <c>crit</c>).</summary>
    HeaderParameter,

    /// <summary>A CB-AdES-specific structured component (clauses 5.2/5.3/Annex A, e.g. <c>sigD</c>, <c>valData</c>, <c>arcTst</c>).</summary>
    Component,

    /// <summary>A service row (CB-6.2.2-01/06): satisfied by the logical OR of its SPO rows (CB-6.3-h).</summary>
    Service,

    /// <summary>A service-provision-option (SPO) row: one way of satisfying its owning service row.</summary>
    ServiceProvisionOption
}


/// <summary>
/// The References-column tagged union of clause 6.2.2 (CB-6.2.2-10): either a clause of this document itself
/// (<see cref="CBAdESInternalClauseReference"/>) or another document's own clause
/// (<see cref="CBAdESExternalReference"/>). A DU-ready closed sum: no external type may derive from it.
/// </summary>
/// <remarks>
/// Every one of Table 14's 26 rows that carries a reference at all cites a clause of THIS document (clauses
/// 5.1-5.4 or Annex A) — <see cref="CBAdESExternalReference"/> is modelled for CB-6.2.2-10's own completeness
/// (a future row citing an IETF RFC or another ETSI deliverable directly in its References column) but is not
/// exercised by any row currently registered in <see cref="CBAdESBaselineLevelTable"/>.
/// </remarks>
public abstract record CBAdESRowReference
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected CBAdESRowReference()
    {
    }
}


/// <summary>
/// The internal arm of <see cref="CBAdESRowReference"/> (CB-6.2.2-10): a clause of this document itself —
/// either the main body (e.g. <c>"5.1.2"</c>) or an annex (e.g. <c>"A.1.1"</c>).
/// </summary>
/// <param name="Clause">The clause identifier, exactly as Table 14's References column states it.</param>
[DebuggerDisplay("CBAdESInternalClauseReference: {Clause}")]
public sealed record CBAdESInternalClauseReference(string Clause) : CBAdESRowReference;


/// <summary>
/// The external arm of <see cref="CBAdESRowReference"/> (CB-6.2.2-10): a clause of a document other than this
/// one. Not exercised by any row currently registered in <see cref="CBAdESBaselineLevelTable"/> — see the
/// remarks on <see cref="CBAdESRowReference"/>.
/// </summary>
/// <param name="Document">The external document's identifying name.</param>
/// <param name="Clause">The clause identifier within <paramref name="Document"/>, or <see langword="null"/> when the row cites the whole document.</param>
[DebuggerDisplay("CBAdESExternalReference: {Document} {Clause}")]
public sealed record CBAdESExternalReference(string Document, string? Clause) : CBAdESRowReference;


/// <summary>
/// The Requirements-column annotations of clause 6.2.2 (CB-6.2.2-11): the lettered additional requirements
/// (a)-(k) and/or numbered notes a Table 14 row carries, listed below the table.
/// </summary>
[DebuggerDisplay("CBAdESRowAnnotations(Letters={RequirementLetters.Count}, Notes={NoteNumbers.Count})")]
public sealed record CBAdESRowAnnotations
{
    /// <summary>Gets the lettered additional requirements (e.g. <c>'a'</c>, <c>'k'</c>) this row carries, or empty when none.</summary>
    public IReadOnlyList<char> RequirementLetters { get; init; } = [];

    /// <summary>Gets the numbered notes this row carries, or empty when none.</summary>
    public IReadOnlyList<int> NoteNumbers { get; init; } = [];


    /// <summary>The shared instance for rows that carry no annotation of either kind.</summary>
    public static CBAdESRowAnnotations None { get; } = new();
}


/// <summary>
/// One row of Table 14 (clause 6.3) — the presence, cardinality, reference, and annotation requirements a
/// single header parameter, component, service, or SPO carries at each CB-AdES baseline level, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 6.3</see>.
/// </summary>
[DebuggerDisplay("CBAdESTableRow({RequirementId}, {Name})")]
public sealed record CBAdESTableRow
{
    /// <summary>Gets this row's requirement identifier (e.g. <c>"CB-6.3-04"</c>).</summary>
    public required string RequirementId { get; init; }

    /// <summary>Gets this row's column-1 name, exactly as Table 14 prints it (e.g. <c>"alg"</c>, <c>"x5chain"</c>).</summary>
    public required string Name { get; init; }

    /// <summary>Gets the kind of thing this row describes (CB-6.2.2-01/02).</summary>
    public required CBAdESTableRowKind Kind { get; init; }

    /// <summary>Gets this row's presence value at each baseline level (CB-6.2.2-03..08).</summary>
    public required CBAdESRowPresence Presence { get; init; }

    /// <summary>
    /// Gets this row's cardinality, or <see langword="null"/> for the <see cref="CBAdESTableRowKind.Service"/>
    /// row (Table 14 states "-" in the Cardinality column for a service row — CB-6.3-26).
    /// </summary>
    public CBAdESRowCardinality? Cardinality { get; init; }

    /// <summary>
    /// Gets the References-column citation, or <see langword="null"/> when Table 14 states "-" (the service
    /// row CB-6.3-26 and the embedded-in-TST SPO row CB-6.3-28).
    /// </summary>
    public CBAdESRowReference? Reference { get; init; }

    /// <summary>
    /// Gets the clause(s) that actually govern this row's <see cref="CBAdESPresence.ConditionedPresence"/>
    /// predicate, when the leg-4 CB-AdES preflight report identifies them as distinct from (or additional to)
    /// <see cref="Reference"/>'s own clause — populated only for <c>content type</c> (note 2: jointly with
    /// <c>sigD</c>'s <c>ctys</c>, clauses 5.1.3 and 5.2.8.1) and the <c>x5chain</c>/<c>x5t</c>/<c>x5ts</c> trio
    /// (note 3, Trap 2: the shared condition lives in clause 5.2.2, not each row's own References clause).
    /// <see langword="null"/> for every other row, including conditioned-presence rows whose condition is a
    /// lettered requirement rather than a clause (<c>sigPSt</c>, requirement (b)) or a service resolution
    /// (<c>valData</c> and both SPO rows, requirements (h)/(i)).
    /// </summary>
    public IReadOnlyList<string>? PresenceConditionClauses { get; init; }

    /// <summary>Gets this row's lettered-requirement and note annotations (CB-6.2.2-11).</summary>
    public CBAdESRowAnnotations Annotations { get; init; } = CBAdESRowAnnotations.None;

    /// <summary>
    /// Gets the requirement identifiers of this <see cref="CBAdESTableRowKind.Service"/> row's SPO children
    /// (CB-6.2.2-01: "one row for the service's own requirement, followed by ≥2 rows for its SPOs"), or
    /// <see langword="null"/> for every non-service row. Satisfaction of the service is the logical OR of
    /// these SPOs (CB-6.3-h) — never their conjunction.
    /// </summary>
    public IReadOnlyList<string>? ServiceProvisionOptionRequirementIds { get; init; }

    /// <summary>
    /// Gets the requirement identifier of the SPO this service row's own additional requirement (i) prefers
    /// when more than one SPO is available to the generator (e.g. CB-6.3-i: "should be included within
    /// <c>valData</c>"), or <see langword="null"/> for every non-service row and for a service row with no
    /// recorded preference.
    /// </summary>
    public string? PreferredServiceProvisionOptionRequirementId { get; init; }
}


/// <summary>
/// The Table 14 (clause 6.3) row registry — all 26 rows CB-6.3-04..29 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 6.3</see>, exposed as static getters (the <c>CoseHeaderParameters</c>/
/// <c>WellKnownOids</c> exemplar shape) plus lookup helpers over <see cref="Rows"/>. COSE/CBOR-free: this
/// class carries only the presence/cardinality/reference/annotation DATA clause 6 states, never a wire encoding
/// or a rule-evaluation engine — those compose this registry from a later stage (JCose), per wavecb-contract.md
/// R-1(a)/R-3.
/// </summary>
/// <remarks>
/// <para>
/// Row-kind counts (see <see cref="CBAdESTableRowKind"/>): 10 <see cref="CBAdESTableRowKind.HeaderParameter"/>
/// rows (<see cref="Alg"/>, <see cref="ContentType"/>, <see cref="Kid"/>, <see cref="X5U"/>,
/// <see cref="X5Chain"/>, <see cref="Crit"/>, <see cref="CwtClaims"/>, <see cref="X5T"/>, <see cref="X5Ts"/>,
/// <see cref="CounterSignature"/>), 13 <see cref="CBAdESTableRowKind.Component"/> rows (<see cref="SigD"/>,
/// <see cref="SrAts"/>, <see cref="SrCms"/>, <see cref="SigPl"/>, <see cref="SigPId"/>, <see cref="AdoTst"/>,
/// <see cref="SigPSt"/>, <see cref="SigTst"/>, <see cref="ValData"/>, <see cref="Refs"/>, <see cref="SigRTst"/>,
/// <see cref="RfsTst"/>, <see cref="ArcTst"/>), 1 <see cref="CBAdESTableRowKind.Service"/> row
/// (<see cref="ValidationDataForTimestampsService"/>), and 2 <see cref="CBAdESTableRowKind.ServiceProvisionOption"/>
/// rows (<see cref="ValDataServiceProvisionOption"/>, <see cref="EmbeddedValidationDataServiceProvisionOption"/>)
/// — 26 rows total, matching the leg-4 CB-AdES preflight report's row count.
/// </para>
/// <para>
/// <strong>D2 (wavecb-contract.md ruling R-6).</strong> <see cref="SigTst"/>'s cardinality reproduces the
/// source table's genuine duplicate "B-LT, B-LTA: 0" sub-line verbatim (leg-4 preflight Trap 5) rather than
/// silently deduplicating it — see the remarks at that member.
/// </para>
/// </remarks>
public static class CBAdESBaselineLevelTable
{
    /// <summary>
    /// <c>alg</c> (CB-6.3-04): shall be present at all 4 levels; cardinality 1; ref clause 5.1.2; no
    /// additional notes — the simplest presence class, mandatory and level-invariant.
    /// </summary>
    public static CBAdESTableRow Alg { get; } = new()
    {
        RequirementId = "CB-6.3-04",
        Name = "alg",
        Kind = CBAdESTableRowKind.HeaderParameter,
        Presence = CBAdESRowPresence.Uniform(CBAdESPresence.ShallBePresent),
        Cardinality = CBAdESRowCardinality.Uniform(CBAdESCardinality.ExactlyOne),
        Reference = new CBAdESInternalClauseReference("5.1.2")
    };

    /// <summary>
    /// <c>content type</c> (CB-6.3-05): conditioned presence at all 4 levels; cardinality 0 or 1; ref clause
    /// 5.1.3; note 2 — the presence predicate lives outside clause 6, shared jointly with clause 5.2.8.1's
    /// <c>sigD</c>/<c>ctys</c> mechanism (leg-4 preflight report).
    /// </summary>
    public static CBAdESTableRow ContentType { get; } = new()
    {
        RequirementId = "CB-6.3-05",
        Name = "content type",
        Kind = CBAdESTableRowKind.HeaderParameter,
        Presence = CBAdESRowPresence.Uniform(CBAdESPresence.ConditionedPresence),
        Cardinality = CBAdESRowCardinality.Uniform(CBAdESCardinality.ZeroOrOne),
        Reference = new CBAdESInternalClauseReference("5.1.3"),
        PresenceConditionClauses = ["5.1.3", "5.2.8.1"],
        Annotations = new CBAdESRowAnnotations { NoteNumbers = [2] }
    };

    /// <summary>
    /// <c>kid</c> (CB-6.3-06): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.1.4 — a
    /// simple optional singleton, level-invariant.
    /// </summary>
    public static CBAdESTableRow Kid { get; } = new()
    {
        RequirementId = "CB-6.3-06",
        Name = "kid",
        Kind = CBAdESTableRowKind.HeaderParameter,
        Presence = CBAdESRowPresence.Uniform(CBAdESPresence.MayBePresent),
        Cardinality = CBAdESRowCardinality.Uniform(CBAdESCardinality.ZeroOrOne),
        Reference = new CBAdESInternalClauseReference("5.1.4")
    };

    /// <summary>
    /// <c>x5u</c> (CB-6.3-07): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.1.5 — a
    /// simple optional singleton, level-invariant.
    /// </summary>
    public static CBAdESTableRow X5U { get; } = new()
    {
        RequirementId = "CB-6.3-07",
        Name = "x5u",
        Kind = CBAdESTableRowKind.HeaderParameter,
        Presence = CBAdESRowPresence.Uniform(CBAdESPresence.MayBePresent),
        Cardinality = CBAdESRowCardinality.Uniform(CBAdESCardinality.ZeroOrOne),
        Reference = new CBAdESInternalClauseReference("5.1.5")
    };

    /// <summary>
    /// <c>x5chain</c> (CB-6.3-08): conditioned presence at all 4 levels; cardinality 0 or 1; ref clause 5.1.8;
    /// note 3. Leg-4 preflight Trap 2: the presence CONDITION for <c>x5chain</c>/<c>x5t</c>/<c>x5ts</c> lives
    /// in clause 5.2.2 (the <c>x5ts</c> row's own defining clause), not in this row's own References clause
    /// (5.1.8) — see <see cref="CBAdESTableRow.PresenceConditionClauses"/>.
    /// </summary>
    public static CBAdESTableRow X5Chain { get; } = new()
    {
        RequirementId = "CB-6.3-08",
        Name = "x5chain",
        Kind = CBAdESTableRowKind.HeaderParameter,
        Presence = CBAdESRowPresence.Uniform(CBAdESPresence.ConditionedPresence),
        Cardinality = CBAdESRowCardinality.Uniform(CBAdESCardinality.ZeroOrOne),
        Reference = new CBAdESInternalClauseReference("5.1.8"),
        PresenceConditionClauses = ["5.2.2"],
        Annotations = new CBAdESRowAnnotations { NoteNumbers = [3] }
    };

    /// <summary>
    /// <c>crit</c> (CB-6.3-09): conditioned presence at all 4 levels; cardinality 0 or 1; ref clause 5.1.10;
    /// note 4 — the presence condition is co-located with this row's own defining clause (unlike
    /// <see cref="X5Chain"/>'s Trap 2), so <see cref="CBAdESTableRow.PresenceConditionClauses"/> is left
    /// <see langword="null"/> here.
    /// </summary>
    public static CBAdESTableRow Crit { get; } = new()
    {
        RequirementId = "CB-6.3-09",
        Name = "crit",
        Kind = CBAdESTableRowKind.HeaderParameter,
        Presence = CBAdESRowPresence.Uniform(CBAdESPresence.ConditionedPresence),
        Cardinality = CBAdESRowCardinality.Uniform(CBAdESCardinality.ZeroOrOne),
        Reference = new CBAdESInternalClauseReference("5.1.10"),
        Annotations = new CBAdESRowAnnotations { NoteNumbers = [4] }
    };

    /// <summary>
    /// <c>CWT Claims</c> (enclosing <c>iat</c>, CB-6.3-10): shall be present at all 4 levels; cardinality 1;
    /// ref clause 5.1.9; additional requirement (a) — mandatory singleton at every level, content further
    /// constrained by requirement (a) (CB-6.3-a: <c>iat</c> carries the generator-claimed UTC signing time).
    /// </summary>
    public static CBAdESTableRow CwtClaims { get; } = new()
    {
        RequirementId = "CB-6.3-10",
        Name = "CWT Claims",
        Kind = CBAdESTableRowKind.HeaderParameter,
        Presence = CBAdESRowPresence.Uniform(CBAdESPresence.ShallBePresent),
        Cardinality = CBAdESRowCardinality.Uniform(CBAdESCardinality.ExactlyOne),
        Reference = new CBAdESInternalClauseReference("5.1.9"),
        Annotations = new CBAdESRowAnnotations { RequirementLetters = ['a'] }
    };

    /// <summary>
    /// <c>x5t</c> (CB-6.3-11): conditioned presence at all 4 levels; cardinality 0 or 1; ref clause 5.1.7;
    /// note 3 — part of the same tri-way condition group as <see cref="X5Chain"/>/<see cref="X5Ts"/> (Trap 2).
    /// </summary>
    public static CBAdESTableRow X5T { get; } = new()
    {
        RequirementId = "CB-6.3-11",
        Name = "x5t",
        Kind = CBAdESTableRowKind.HeaderParameter,
        Presence = CBAdESRowPresence.Uniform(CBAdESPresence.ConditionedPresence),
        Cardinality = CBAdESRowCardinality.Uniform(CBAdESCardinality.ZeroOrOne),
        Reference = new CBAdESInternalClauseReference("5.1.7"),
        PresenceConditionClauses = ["5.2.2"],
        Annotations = new CBAdESRowAnnotations { NoteNumbers = [3] }
    };

    /// <summary>
    /// <c>x5ts</c> (CB-6.3-12): conditioned presence at all 4 levels; cardinality 0 or 1; ref clause 5.2.2;
    /// note 3 — this row's own defining clause (5.2.2) is ALSO the shared condition-logic clause for the
    /// whole <see cref="X5Chain"/>/<see cref="X5T"/>/<see cref="X5Ts"/> trio (CB-AdES preflight leg-4 report,
    /// resolving defect D9 in one place per wavecb-contract.md R-6).
    /// </summary>
    public static CBAdESTableRow X5Ts { get; } = new()
    {
        RequirementId = "CB-6.3-12",
        Name = "x5ts",
        Kind = CBAdESTableRowKind.HeaderParameter,
        Presence = CBAdESRowPresence.Uniform(CBAdESPresence.ConditionedPresence),
        Cardinality = CBAdESRowCardinality.Uniform(CBAdESCardinality.ZeroOrOne),
        Reference = new CBAdESInternalClauseReference("5.2.2"),
        PresenceConditionClauses = ["5.2.2"],
        Annotations = new CBAdESRowAnnotations { NoteNumbers = [3] }
    };

    /// <summary>
    /// <c>sigD</c> (CB-6.3-13): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.2.8 — a
    /// level-invariant optional singleton; interacts with <see cref="ContentType"/> via note 2.
    /// </summary>
    public static CBAdESTableRow SigD { get; } = new()
    {
        RequirementId = "CB-6.3-13",
        Name = "sigD",
        Kind = CBAdESTableRowKind.Component,
        Presence = CBAdESRowPresence.Uniform(CBAdESPresence.MayBePresent),
        Cardinality = CBAdESRowCardinality.Uniform(CBAdESCardinality.ZeroOrOne),
        Reference = new CBAdESInternalClauseReference("5.2.8")
    };

    /// <summary>
    /// <c>srAts</c> (CB-6.3-14): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.2.5 — a
    /// level-invariant optional singleton.
    /// </summary>
    public static CBAdESTableRow SrAts { get; } = new()
    {
        RequirementId = "CB-6.3-14",
        Name = "srAts",
        Kind = CBAdESTableRowKind.Component,
        Presence = CBAdESRowPresence.Uniform(CBAdESPresence.MayBePresent),
        Cardinality = CBAdESRowCardinality.Uniform(CBAdESCardinality.ZeroOrOne),
        Reference = new CBAdESInternalClauseReference("5.2.5")
    };

    /// <summary>
    /// <c>srCms</c> (CB-6.3-15): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.2.3; note 5
    /// — the cardinality is at the HEADER level: the value itself is a CBOR array that may hold several
    /// commitment types (leg-4 preflight report), which this row's cardinality does not count.
    /// </summary>
    public static CBAdESTableRow SrCms { get; } = new()
    {
        RequirementId = "CB-6.3-15",
        Name = "srCms",
        Kind = CBAdESTableRowKind.Component,
        Presence = CBAdESRowPresence.Uniform(CBAdESPresence.MayBePresent),
        Cardinality = CBAdESRowCardinality.Uniform(CBAdESCardinality.ZeroOrOne),
        Reference = new CBAdESInternalClauseReference("5.2.3"),
        Annotations = new CBAdESRowAnnotations { NoteNumbers = [5] }
    };

    /// <summary>
    /// <c>sigPl</c> (CB-6.3-16): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.2.4 — a
    /// level-invariant optional singleton.
    /// </summary>
    public static CBAdESTableRow SigPl { get; } = new()
    {
        RequirementId = "CB-6.3-16",
        Name = "sigPl",
        Kind = CBAdESTableRowKind.Component,
        Presence = CBAdESRowPresence.Uniform(CBAdESPresence.MayBePresent),
        Cardinality = CBAdESRowCardinality.Uniform(CBAdESCardinality.ZeroOrOne),
        Reference = new CBAdESInternalClauseReference("5.2.4")
    };

    /// <summary>
    /// <c>sigPId</c> (CB-6.3-17): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.2.7 — a
    /// level-invariant optional singleton; its own presence together with its <c>digVal</c> member gates
    /// <see cref="SigPSt"/>'s presence (requirement (b), CB-6.3-b).
    /// </summary>
    public static CBAdESTableRow SigPId { get; } = new()
    {
        RequirementId = "CB-6.3-17",
        Name = "sigPId",
        Kind = CBAdESTableRowKind.Component,
        Presence = CBAdESRowPresence.Uniform(CBAdESPresence.MayBePresent),
        Cardinality = CBAdESRowCardinality.Uniform(CBAdESCardinality.ZeroOrOne),
        Reference = new CBAdESInternalClauseReference("5.2.7")
    };

    /// <summary>
    /// <c>counter signature</c> (CB-6.3-18): may be present at all 4 levels; cardinality ≥0; ref clause 5.1.6
    /// — unbounded repeatable, level-invariant.
    /// </summary>
    public static CBAdESTableRow CounterSignature { get; } = new()
    {
        RequirementId = "CB-6.3-18",
        Name = "counter signature",
        Kind = CBAdESTableRowKind.HeaderParameter,
        Presence = CBAdESRowPresence.Uniform(CBAdESPresence.MayBePresent),
        Cardinality = CBAdESRowCardinality.Uniform(CBAdESCardinality.ZeroOrMore),
        Reference = new CBAdESInternalClauseReference("5.1.6")
    };

    /// <summary>
    /// <c>adoTst</c> (CB-6.3-19): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.3.2; note 6
    /// — the header-level cardinality of 0-or-1 is independent of how many electronic time-stamps (possibly
    /// from different TSAs) the internal <c>tstContainer</c> holds (leg-4 preflight report). Leg-4 Trap 3:
    /// shares its References clause (5.3.2) verbatim with <see cref="SigPSt"/>.
    /// </summary>
    public static CBAdESTableRow AdoTst { get; } = new()
    {
        RequirementId = "CB-6.3-19",
        Name = "adoTst",
        Kind = CBAdESTableRowKind.Component,
        Presence = CBAdESRowPresence.Uniform(CBAdESPresence.MayBePresent),
        Cardinality = CBAdESRowCardinality.Uniform(CBAdESCardinality.ZeroOrOne),
        Reference = new CBAdESInternalClauseReference("5.3.2"),
        Annotations = new CBAdESRowAnnotations { NoteNumbers = [6] }
    };

    /// <summary>
    /// <c>sigPSt</c> (CB-6.3-20): conditioned presence at all 4 levels; cardinality 0 or 1; ref clause 5.3.2;
    /// additional requirement (b) — CB-6.3-b: may be incorporated only if <see cref="SigPId"/> is also
    /// incorporated and carries its <c>digVal</c> member; otherwise shall not be incorporated. Leg-4 Trap 3:
    /// shares its References clause (5.3.2) verbatim with <see cref="AdoTst"/>. The condition is the lettered
    /// requirement itself, not a distinct clause, so <see cref="CBAdESTableRow.PresenceConditionClauses"/> is
    /// left <see langword="null"/> here.
    /// </summary>
    public static CBAdESTableRow SigPSt { get; } = new()
    {
        RequirementId = "CB-6.3-20",
        Name = "sigPSt",
        Kind = CBAdESTableRowKind.Component,
        Presence = CBAdESRowPresence.Uniform(CBAdESPresence.ConditionedPresence),
        Cardinality = CBAdESRowCardinality.Uniform(CBAdESCardinality.ZeroOrOne),
        Reference = new CBAdESInternalClauseReference("5.3.2"),
        Annotations = new CBAdESRowAnnotations { RequirementLetters = ['b'] }
    };

    /// <summary>
    /// <c>sigTst</c> (CB-6.3-21): presence <see cref="CBAdESBaselineLevel.BB"/> = <c>"*"</c> (should not be
    /// present); <see cref="CBAdESBaselineLevel.BT"/>/<see cref="CBAdESBaselineLevel.BLT"/>/
    /// <see cref="CBAdESBaselineLevel.BLTA"/> = shall be present. Ref clause 5.3.3; additional requirements
    /// (c)/(d); note 7.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>D2 (wavecb-contract.md ruling R-6) — the source table's genuine duplicate line, reproduced.</strong>
    /// <see cref="CBAdESRowCardinality.Statements"/> carries FOUR statements, exactly as the source PDF's cell
    /// stacks them (leg-4 CB-AdES preflight report Trap 5, confirmed by rendered-page visual inspection, not a
    /// markdown-conversion artifact): <c>{B-B: ≥0}</c>, <c>{B-T,B-LT,B-LTA: ≥1}</c>, <c>{B-LT,B-LTA: 0}</c>,
    /// <c>{B-LT,B-LTA: 0}</c> — the last two character-for-character identical. This model does NOT collapse
    /// the duplicate: <see cref="CBAdESRowCardinality.ValuesAt"/> at <see cref="CBAdESBaselineLevel.BLT"/> or
    /// <see cref="CBAdESBaselineLevel.BLTA"/> returns three values, <c>[OneOrMore, ExactlyZero, ExactlyZero]</c>.
    /// </para>
    /// <para>
    /// <strong>Ruled reading (contract R-6, D2).</strong> The <c>≥1</c> statement is the CUMULATIVE total —
    /// once at B-T, at least one <c>sigTst</c> instance is present, and this stands unchanged through B-LT and
    /// B-LTA. The <c>0</c> statement (reproduced twice) is the INCREMENTAL reading: zero NEW <c>sigTst</c>
    /// instances are added specifically when transitioning into B-LT or B-LTA — an augmentation orchestrator
    /// must not mint a further <c>sigTst</c> at those two upgrade steps, even though multiple TSAs remain a
    /// legal way to satisfy the B-B→B-T transition's own <c>≥1</c> (note 7: "each <c>sigTst</c> shall contain
    /// only one electronic time-stamp" per requirement (c); redundancy across TSAs is achieved by repeating the
    /// B-T-transition's <c>sigTst</c> incorporation, never by adding instances later).
    /// </para>
    /// </remarks>
    public static CBAdESTableRow SigTst { get; } = new()
    {
        RequirementId = "CB-6.3-21",
        Name = "sigTst",
        Kind = CBAdESTableRowKind.Component,
        Presence = new CBAdESRowPresence
        {
            BB = CBAdESPresence.ShouldNotBePresent,
            BT = CBAdESPresence.ShallBePresent,
            BLT = CBAdESPresence.ShallBePresent,
            BLTA = CBAdESPresence.ShallBePresent
        },
        Cardinality = new CBAdESRowCardinality
        {
            Statements =
            [
                new CBAdESCardinalityStatement(CBAdESBaselineLevelSet.BB, CBAdESCardinality.ZeroOrMore),
                new CBAdESCardinalityStatement(CBAdESBaselineLevelSet.BT | CBAdESBaselineLevelSet.BLT | CBAdESBaselineLevelSet.BLTA, CBAdESCardinality.OneOrMore),
                new CBAdESCardinalityStatement(CBAdESBaselineLevelSet.BLT | CBAdESBaselineLevelSet.BLTA, CBAdESCardinality.ExactlyZero),
                new CBAdESCardinalityStatement(CBAdESBaselineLevelSet.BLT | CBAdESBaselineLevelSet.BLTA, CBAdESCardinality.ExactlyZero)
            ]
        },
        Reference = new CBAdESInternalClauseReference("5.3.3"),
        Annotations = new CBAdESRowAnnotations { RequirementLetters = ['c', 'd'], NoteNumbers = [7] }
    };

    /// <summary>
    /// <c>valData</c> (CB-6.3-22): presence <see cref="CBAdESBaselineLevel.BB"/>/<see cref="CBAdESBaselineLevel.BT"/>
    /// = <c>"*"</c>; <see cref="CBAdESBaselineLevel.BLT"/>/<see cref="CBAdESBaselineLevel.BLTA"/> = conditioned
    /// presence; cardinality ≥0, level-invariant (leg-4 preflight report: unlike the four level-split rows,
    /// <c>valData</c> carries a single row-wide cardinality despite its level-split presence); ref clause
    /// 5.3.4; additional requirements (e)/(f) — the presence condition from B-LT onward is resolved via
    /// <see cref="ValidationDataForTimestampsService"/>'s Service/SPO rows, not a clause, so
    /// <see cref="CBAdESTableRow.PresenceConditionClauses"/> is left <see langword="null"/> here.
    /// </summary>
    public static CBAdESTableRow ValData { get; } = new()
    {
        RequirementId = "CB-6.3-22",
        Name = "valData",
        Kind = CBAdESTableRowKind.Component,
        Presence = new CBAdESRowPresence
        {
            BB = CBAdESPresence.ShouldNotBePresent,
            BT = CBAdESPresence.ShouldNotBePresent,
            BLT = CBAdESPresence.ConditionedPresence,
            BLTA = CBAdESPresence.ConditionedPresence
        },
        Cardinality = CBAdESRowCardinality.Uniform(CBAdESCardinality.ZeroOrMore),
        Reference = new CBAdESInternalClauseReference("5.3.4"),
        Annotations = new CBAdESRowAnnotations { RequirementLetters = ['e', 'f'] }
    };

    /// <summary>
    /// <c>refs</c> (Annex A.1.1, CB-6.3-23): presence <see cref="CBAdESBaselineLevel.BB"/>/<see cref="CBAdESBaselineLevel.BT"/>
    /// = <c>"*"</c>; <see cref="CBAdESBaselineLevel.BLT"/>/<see cref="CBAdESBaselineLevel.BLTA"/> = shall not
    /// be present; cardinality level-split: <c>{B-B,B-T: ≥0}</c>, <c>{B-LT,B-LTA: 0}</c>; ref clause A.1.1;
    /// additional requirement (g) — a B-B/B-T-only, soft-discouraged, then hard-forbidden-from-B-LT component;
    /// a level transition to B-LT/B-LTA must strip any pre-existing <c>refs</c> (part of the B-B/B-T-only
    /// reference-and-timestamp mechanism together with <see cref="SigRTst"/>/<see cref="RfsTst"/>).
    /// </summary>
    public static CBAdESTableRow Refs { get; } = new()
    {
        RequirementId = "CB-6.3-23",
        Name = "refs",
        Kind = CBAdESTableRowKind.Component,
        Presence = new CBAdESRowPresence
        {
            BB = CBAdESPresence.ShouldNotBePresent,
            BT = CBAdESPresence.ShouldNotBePresent,
            BLT = CBAdESPresence.ShallNotBePresent,
            BLTA = CBAdESPresence.ShallNotBePresent
        },
        Cardinality = new CBAdESRowCardinality
        {
            Statements =
            [
                new CBAdESCardinalityStatement(CBAdESBaselineLevelSet.BB | CBAdESBaselineLevelSet.BT, CBAdESCardinality.ZeroOrMore),
                new CBAdESCardinalityStatement(CBAdESBaselineLevelSet.BLT | CBAdESBaselineLevelSet.BLTA, CBAdESCardinality.ExactlyZero)
            ]
        },
        Reference = new CBAdESInternalClauseReference("A.1.1"),
        Annotations = new CBAdESRowAnnotations { RequirementLetters = ['g'] }
    };

    /// <summary>
    /// <c>sigRTst</c> (Annex A.1.2.1, CB-6.3-24): same presence/cardinality shape as <see cref="Refs"/> —
    /// presence <c>"*"</c> at B-B/B-T, shall-not-be-present at B-LT/B-LTA; cardinality level-split
    /// <c>{B-B,B-T: ≥0}</c>, <c>{B-LT,B-LTA: 0}</c>; ref clause A.1.2.1; no lettered requirement.
    /// </summary>
    public static CBAdESTableRow SigRTst { get; } = new()
    {
        RequirementId = "CB-6.3-24",
        Name = "sigRTst",
        Kind = CBAdESTableRowKind.Component,
        Presence = new CBAdESRowPresence
        {
            BB = CBAdESPresence.ShouldNotBePresent,
            BT = CBAdESPresence.ShouldNotBePresent,
            BLT = CBAdESPresence.ShallNotBePresent,
            BLTA = CBAdESPresence.ShallNotBePresent
        },
        Cardinality = new CBAdESRowCardinality
        {
            Statements =
            [
                new CBAdESCardinalityStatement(CBAdESBaselineLevelSet.BB | CBAdESBaselineLevelSet.BT, CBAdESCardinality.ZeroOrMore),
                new CBAdESCardinalityStatement(CBAdESBaselineLevelSet.BLT | CBAdESBaselineLevelSet.BLTA, CBAdESCardinality.ExactlyZero)
            ]
        },
        Reference = new CBAdESInternalClauseReference("A.1.2.1")
    };

    /// <summary>
    /// <c>rfsTst</c> (Annex A.1.2.2, CB-6.3-25): same presence/cardinality shape as <see cref="Refs"/>/
    /// <see cref="SigRTst"/> — presence <c>"*"</c> at B-B/B-T, shall-not-be-present at B-LT/B-LTA; cardinality
    /// level-split <c>{B-B,B-T: ≥0}</c>, <c>{B-LT,B-LTA: 0}</c>; ref clause A.1.2.2; no lettered requirement.
    /// </summary>
    public static CBAdESTableRow RfsTst { get; } = new()
    {
        RequirementId = "CB-6.3-25",
        Name = "rfsTst",
        Kind = CBAdESTableRowKind.Component,
        Presence = new CBAdESRowPresence
        {
            BB = CBAdESPresence.ShouldNotBePresent,
            BT = CBAdESPresence.ShouldNotBePresent,
            BLT = CBAdESPresence.ShallNotBePresent,
            BLTA = CBAdESPresence.ShallNotBePresent
        },
        Cardinality = new CBAdESRowCardinality
        {
            Statements =
            [
                new CBAdESCardinalityStatement(CBAdESBaselineLevelSet.BB | CBAdESBaselineLevelSet.BT, CBAdESCardinality.ZeroOrMore),
                new CBAdESCardinalityStatement(CBAdESBaselineLevelSet.BLT | CBAdESBaselineLevelSet.BLTA, CBAdESCardinality.ExactlyZero)
            ]
        },
        Reference = new CBAdESInternalClauseReference("A.1.2.2")
    };

    /// <summary>
    /// Service "Incorporation of validation data for electronic time-stamps" (CB-6.3-26): presence
    /// <see cref="CBAdESBaselineLevel.BB"/>/<see cref="CBAdESBaselineLevel.BT"/> = <c>"*"</c>;
    /// <see cref="CBAdESBaselineLevel.BLT"/>/<see cref="CBAdESBaselineLevel.BLTA"/> = shall be provided;
    /// cardinality "-" (n/a, service row); ref "-"; additional requirements (h)/(i); note 8.
    /// </summary>
    /// <remarks>
    /// A service-level obligation resolved by ≥1 satisfied SPO row — <see cref="ValDataServiceProvisionOption"/>
    /// (CB-6.3-27) or <see cref="EmbeddedValidationDataServiceProvisionOption"/> (CB-6.3-28) — never by a
    /// single header, and evaluated only from B-LT onward. CB-6.3-h: satisfaction is the logical OR of the two
    /// SPOs (<see cref="CBAdESTableRow.ServiceProvisionOptionRequirementIds"/>). CB-6.3-i: the generator
    /// SHOULD prefer <c>valData</c> over the embedded-in-TST SPO when both are available
    /// (<see cref="CBAdESTableRow.PreferredServiceProvisionOptionRequirementId"/> names CB-6.3-27).
    /// </remarks>
    public static CBAdESTableRow ValidationDataForTimestampsService { get; } = new()
    {
        RequirementId = "CB-6.3-26",
        Name = "Service: Incorporation of validation data for electronic time-stamps",
        Kind = CBAdESTableRowKind.Service,
        Presence = new CBAdESRowPresence
        {
            BB = CBAdESPresence.ShouldNotBePresent,
            BT = CBAdESPresence.ShouldNotBePresent,
            BLT = CBAdESPresence.ShallBeProvided,
            BLTA = CBAdESPresence.ShallBeProvided
        },
        Cardinality = null,
        Reference = null,
        Annotations = new CBAdESRowAnnotations { RequirementLetters = ['h', 'i'], NoteNumbers = [8] },
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
    public static CBAdESTableRow ValDataServiceProvisionOption { get; } = new()
    {
        RequirementId = "CB-6.3-27",
        Name = "SPO: valData",
        Kind = CBAdESTableRowKind.ServiceProvisionOption,
        Presence = new CBAdESRowPresence
        {
            BB = CBAdESPresence.ShouldNotBePresent,
            BT = CBAdESPresence.ShouldNotBePresent,
            BLT = CBAdESPresence.ConditionedPresence,
            BLTA = CBAdESPresence.ConditionedPresence
        },
        Cardinality = CBAdESRowCardinality.Uniform(CBAdESCardinality.ZeroOrMore),
        Reference = new CBAdESInternalClauseReference("5.3.4")
    };

    /// <summary>
    /// SPO "certificate and revocation values embedded in the electronic time-stamp itself" (CB-6.3-28):
    /// presence <c>"*"</c> at B-B/B-T; conditioned presence at B-LT/B-LTA; cardinality ≥0; ref "-"; additional
    /// requirement (i) — the second SPO: the TST's own embedded cert/revocation data (e.g. a CMS
    /// <c>SignedData</c> in an RFC 3161 token) counts as satisfying the service in lieu of <c>valData</c>
    /// entries.
    /// </summary>
    public static CBAdESTableRow EmbeddedValidationDataServiceProvisionOption { get; } = new()
    {
        RequirementId = "CB-6.3-28",
        Name = "SPO: certificate and revocation values embedded in the electronic time-stamp itself",
        Kind = CBAdESTableRowKind.ServiceProvisionOption,
        Presence = new CBAdESRowPresence
        {
            BB = CBAdESPresence.ShouldNotBePresent,
            BT = CBAdESPresence.ShouldNotBePresent,
            BLT = CBAdESPresence.ConditionedPresence,
            BLTA = CBAdESPresence.ConditionedPresence
        },
        Cardinality = CBAdESRowCardinality.Uniform(CBAdESCardinality.ZeroOrMore),
        Reference = null,
        Annotations = new CBAdESRowAnnotations { RequirementLetters = ['i'] }
    };

    /// <summary>
    /// <c>arcTst</c> (CB-6.3-29): presence <see cref="CBAdESBaselineLevel.BB"/>/<see cref="CBAdESBaselineLevel.BT"/>/
    /// <see cref="CBAdESBaselineLevel.BLT"/> = <c>"*"</c>; <see cref="CBAdESBaselineLevel.BLTA"/> = shall be
    /// present; cardinality ≥1, level-invariant (leg-4 preflight report: a single row-wide value despite the
    /// level-split presence — see <see cref="ValData"/> for the same pattern); ref clause 5.3.5; additional
    /// requirements (j)/(k) — B-LTA-exclusive and mandatory once at that level; requirement (k) mandates a
    /// full validation-material refresh immediately before each new <c>arcTst</c> (not enforced by this data
    /// model; owned by the augmentation orchestrator).
    /// </summary>
    public static CBAdESTableRow ArcTst { get; } = new()
    {
        RequirementId = "CB-6.3-29",
        Name = "arcTst",
        Kind = CBAdESTableRowKind.Component,
        Presence = new CBAdESRowPresence
        {
            BB = CBAdESPresence.ShouldNotBePresent,
            BT = CBAdESPresence.ShouldNotBePresent,
            BLT = CBAdESPresence.ShouldNotBePresent,
            BLTA = CBAdESPresence.ShallBePresent
        },
        Cardinality = CBAdESRowCardinality.Uniform(CBAdESCardinality.OneOrMore),
        Reference = new CBAdESInternalClauseReference("5.3.5"),
        Annotations = new CBAdESRowAnnotations { RequirementLetters = ['j', 'k'] }
    };


    /// <summary>Gets every Table 14 row, in the source table's own order (CB-6.3-04..29).</summary>
    public static IReadOnlyList<CBAdESTableRow> Rows { get; } =
    [
        Alg, ContentType, Kid, X5U, X5Chain, Crit, CwtClaims, X5T, X5Ts,
        SigD, SrAts, SrCms, SigPl, SigPId, CounterSignature, AdoTst, SigPSt,
        SigTst, ValData, Refs, SigRTst, RfsTst,
        ValidationDataForTimestampsService, ValDataServiceProvisionOption, EmbeddedValidationDataServiceProvisionOption,
        ArcTst
    ];


    /// <summary>Gets whether <paramref name="row"/> is a <see cref="CBAdESTableRowKind.Service"/> row.</summary>
    /// <param name="row">The row to test.</param>
    /// <returns><see langword="true"/> when <paramref name="row"/>'s kind is <see cref="CBAdESTableRowKind.Service"/>.</returns>
    public static bool IsServiceRow(CBAdESTableRow row)
    {
        ArgumentNullException.ThrowIfNull(row);

        return row.Kind == CBAdESTableRowKind.Service;
    }


    /// <summary>Gets whether <paramref name="row"/> is a <see cref="CBAdESTableRowKind.ServiceProvisionOption"/> row.</summary>
    /// <param name="row">The row to test.</param>
    /// <returns><see langword="true"/> when <paramref name="row"/>'s kind is <see cref="CBAdESTableRowKind.ServiceProvisionOption"/>.</returns>
    public static bool IsServiceProvisionOptionRow(CBAdESTableRow row)
    {
        ArgumentNullException.ThrowIfNull(row);

        return row.Kind == CBAdESTableRowKind.ServiceProvisionOption;
    }


    /// <summary>Finds the registered row whose <see cref="CBAdESTableRow.RequirementId"/> matches <paramref name="requirementId"/>.</summary>
    /// <param name="requirementId">The requirement identifier to look up (e.g. <c>"CB-6.3-21"</c>).</param>
    /// <returns>The matching row, or <see langword="null"/> when no registered row carries that identifier.</returns>
    public static CBAdESTableRow? FindByRequirementId(string requirementId)
    {
        ArgumentNullException.ThrowIfNull(requirementId);

        for(int i = 0; i < Rows.Count; ++i)
        {
            if(string.Equals(Rows[i].RequirementId, requirementId, StringComparison.Ordinal))
            {
                return Rows[i];
            }
        }

        return null;
    }


    /// <summary>
    /// Resolves a <see cref="CBAdESTableRowKind.Service"/> row's SPO children to their registered
    /// <see cref="CBAdESTableRow"/> instances, in the order <see cref="CBAdESTableRow.ServiceProvisionOptionRequirementIds"/>
    /// lists them.
    /// </summary>
    /// <param name="serviceRow">The service row to resolve children for.</param>
    /// <returns>The service row's SPO rows, in declared order.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="serviceRow"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="serviceRow"/> is not a <see cref="CBAdESTableRowKind.Service"/> row.</exception>
    /// <exception cref="InvalidOperationException">
    /// <paramref name="serviceRow"/> names an SPO requirement identifier that is not registered in <see cref="Rows"/>.
    /// </exception>
    public static IReadOnlyList<CBAdESTableRow> ServiceProvisionOptionsFor(CBAdESTableRow serviceRow)
    {
        ArgumentNullException.ThrowIfNull(serviceRow);

        if(serviceRow.Kind != CBAdESTableRowKind.Service || serviceRow.ServiceProvisionOptionRequirementIds is null)
        {
            throw new ArgumentException(
                $"'{serviceRow.RequirementId}' is not a service row (ETSI TS 119 152-1 V1.1.1, clause 6.2.2, CB-6.2.2-01/02).",
                nameof(serviceRow));
        }

        var options = new List<CBAdESTableRow>(serviceRow.ServiceProvisionOptionRequirementIds.Count);
        for(int i = 0; i < serviceRow.ServiceProvisionOptionRequirementIds.Count; ++i)
        {
            string optionId = serviceRow.ServiceProvisionOptionRequirementIds[i];
            CBAdESTableRow? option = FindByRequirementId(optionId);
            if(option is null)
            {
                throw new InvalidOperationException(
                    $"Service row '{serviceRow.RequirementId}' names an unregistered SPO requirement identifier '{optionId}'.");
            }

            options.Add(option);
        }

        return options;
    }
}
