using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The kind of thing a baseline-level table row describes: a plain header/field parameter, a format-specific
/// structured component, a service (satisfied by ≥1 of its SPO rows), or one of a service's SPO
/// (service-provision-option) rows. The union of <c>AdESTableRowKind</c> (CB-6.2.2-01/02), <c>AdESTableRowKind</c>
/// (JA-6.2.2-09/-10/-11), and <c>AdESTableRowKind</c> (PA-6.2.2-02..05), per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 6.2.2</see>,
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 6.2.2</see>, and
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
/// ETSI EN 319 142-1 V1.2.1, clause 6.2.2</see>.
/// </summary>
/// <remarks>
/// CB-AdES and JAdES both split their own "anything else" (non-service, non-SPO) row bucket into
/// <see cref="HeaderParameter"/> (the plain COSE/JOSE header fields clause 5.1 profiles) and
/// <see cref="Component"/> (the format-specific structured CBOR/JSON objects of clauses 5.2/5.3/Annex A) — under
/// IDENTICAL arm names in both sources, so this union carries the pair unchanged. PAdES's own row kinds name a
/// different pair for the same "anything else" bucket, reflecting its different container substrate:
/// <see cref="SignatureDictionaryField"/> (an ISO 32000-1 Signature Dictionary key) and <see cref="CmsAttribute"/>
/// (a signed/unsigned CMS attribute of the enclosing <c>SignerInfo</c>, most of them PAdES's own [CAdES-deferred]
/// by-reference reuse of ETSI EN 319 122-1 clause 5, RP-3). XAdES names a third pair for the same bucket,
/// reflecting XML's own by-reference/native split (EN 319 132-1 Table 2, clause 6.3): <see cref="XmlDsigElement"/>
/// (an XMLDSIG core element or attribute Table 2 profiles by reference — the XAdES analogue of PAdES's
/// <see cref="CmsAttribute"/>) and <see cref="QualifyingProperty"/> (an <c>xades:</c>-namespaced element or
/// attribute EN 319 132-1 itself defines — the analogue of PAdES's <see cref="SignatureDictionaryField"/>).
/// <see cref="Service"/> and <see cref="ServiceProvisionOption"/> are common to all four sources under identical
/// names.
/// </remarks>
public enum AdESTableRowKind
{
    /// <summary>A plain header parameter profiled by clause 5.1 (CB-AdES <c>alg</c>/<c>x5chain</c>/<c>crit</c>; JAdES <c>alg</c>/<c>cty</c>/<c>iat</c>/<c>sigT</c>). CB-AdES and JAdES only.</summary>
    HeaderParameter,

    /// <summary>A format-specific structured component of clauses 5.2/5.3/Annex A (e.g. <c>sigD</c>, <c>valData</c>/<c>xVals</c>, <c>arcTst</c>). CB-AdES and JAdES only.</summary>
    Component,

    /// <summary>An ISO 32000-1 Signature Dictionary field (e.g. <c>M</c>, <c>Contents</c>, <c>ByteRange</c>). PAdES only.</summary>
    SignatureDictionaryField,

    /// <summary>A CMS/CAdES signed or unsigned attribute of the enclosing <c>SignerInfo</c> (PAdES's own [CAdES-deferred] rows). PAdES only.</summary>
    CmsAttribute,

    /// <summary>An XMLDSIG core element or attribute a XAdES baseline-level table row profiles by reference, not itself defined by EN 319 132-1 (e.g. <c>ds:KeyInfo/X509Data</c>, <c>ds:SignedInfo/ds:CanonicalizationMethod</c>). XAdES only.</summary>
    XmlDsigElement,

    /// <summary>An <c>xades:</c>-namespaced qualifying property, or one of its child elements/attributes, that EN 319 132-1 itself defines (e.g. <c>SigningTime</c>, <c>DataObjectFormat/MimeType</c>). XAdES only.</summary>
    QualifyingProperty,

    /// <summary>A service row: satisfied by the logical OR of its SPO rows (CB-6.3-h and its JAdES/PAdES/XAdES analogues).</summary>
    Service,

    /// <summary>A service-provision-option (SPO) row: one way of satisfying its owning service row.</summary>
    ServiceProvisionOption
}


/// <summary>
/// The References-column tagged union a baseline-level table row's citation takes: either a clause of the
/// citing document itself (<see cref="AdESInternalClauseReference"/>) or another document's own clause
/// (<see cref="AdESExternalReference"/>). The union of <c>AdESRowReference</c> (CB-6.2.2-10) and
/// <c>AdESRowReference</c> (JA-6.2.2-29) — a DU-ready closed sum: no external type may derive from it.
/// </summary>
/// <remarks>
/// Both sources name their external arm <c>*ExternalReference</c>, not <c>*ExternalClauseReference</c>:
/// <c>AdESExternalReference</c> and <c>AdESExternalReference</c> agree exactly, so this union carries the pair
/// unchanged under those same two arm names. PAdES's own <c>AdESTableRow.Reference</c> is a plain
/// <see cref="string"/>? transcribing Table 1's References-column cell verbatim (e.g. <c>"IETF RFC 5652, clause 5.1"</c>,
/// <c>"clause 5.4.3"</c>) rather than this internal/external tagged union — flagged in the fidelity report rather
/// than parsed into one arm or the other, since PAdES's own source carries no discriminated internal/external
/// distinction to transcribe faithfully.
/// </remarks>
public abstract record AdESRowReference
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected AdESRowReference()
    {
    }
}


/// <summary>
/// The internal arm of <see cref="AdESRowReference"/>: a clause of the citing document itself — either the main
/// body (e.g. <c>"5.1.2"</c>) or an annex (e.g. <c>"A.1.1"</c>).
/// </summary>
/// <param name="Clause">The clause identifier, exactly as the table's References column states it.</param>
[DebuggerDisplay("AdESInternalClauseReference: {Clause}")]
public sealed record AdESInternalClauseReference(string Clause) : AdESRowReference;


/// <summary>
/// The external arm of <see cref="AdESRowReference"/>: a clause of a document other than the citing one.
/// </summary>
/// <param name="Document">The external document's identifying name.</param>
/// <param name="Clause">The clause identifier within <paramref name="Document"/>, or <see langword="null"/> when the row cites the whole document.</param>
[DebuggerDisplay("AdESExternalReference: {Document} {Clause}")]
public sealed record AdESExternalReference(string Document, string? Clause) : AdESRowReference;


/// <summary>
/// The Requirements/Additional-requirements-and-notes-column annotations a baseline-level table row carries: the
/// lettered additional requirements and/or numbered notes listed below the table. The union of
/// <c>AdESRowAnnotations</c> (CB-6.2.2-11), <c>AdESRowAnnotations</c> (JA-6.2.2-29), and PAdES's own flat
/// <c>AdESTableRow.AdditionalRequirementLetters</c>/<c>NoteNumbers</c> pair.
/// </summary>
/// <remarks>
/// <see cref="RequirementLetters"/> carries <see cref="string"/> elements, not <see cref="char"/>: CB-AdES's and
/// JAdES's own <c>RequirementLetters</c> are declared as <c>IReadOnlyList&lt;char&gt;</c> (every registered value
/// today is a single character, <c>'a'</c>..<c>'k'</c>/<c>'m'</c>), but PAdES's own
/// <c>AdditionalRequirementLetters</c> is declared as <c>IReadOnlyList&lt;string&gt;</c> — the wider element type
/// this record's member name (kept from CB/J) inherits, per union-model rule 1. Every currently registered
/// PAdES letter happens to be single-character too, but the source's own declared type does not guarantee that.
/// </remarks>
[DebuggerDisplay("AdESRowAnnotations(Letters={RequirementLetters.Count}, Notes={NoteNumbers.Count})")]
public sealed record AdESRowAnnotations
{
    /// <summary>Gets the lettered additional requirements (e.g. <c>"a"</c>, <c>"k"</c>) this row carries, or empty when none.</summary>
    public IReadOnlyList<string> RequirementLetters { get; init; } = [];

    /// <summary>Gets the numbered notes this row carries, or empty when none.</summary>
    public IReadOnlyList<int> NoteNumbers { get; init; } = [];


    /// <summary>The shared instance for rows that carry no annotation of either kind.</summary>
    public static AdESRowAnnotations None { get; } = new();
}


/// <summary>
/// One row of a baseline-level table — the presence, cardinality, reference, and annotation requirements a
/// single header parameter, component, service, dictionary field, or CMS attribute carries at each AdES
/// baseline level. The superset union of <c>AdESTableRow</c> (Table 14, clause 6.3,
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>), <c>AdESTableRow</c> (Table 1, clause 6.3,
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>), and <c>AdESTableRow</c> (Table 1, clauses 6.2/6.3,
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
/// ETSI EN 319 142-1 V1.2.1</see>).
/// </summary>
[DebuggerDisplay("AdESTableRow({RequirementId}, {Name})")]
public sealed record AdESTableRow
{
    /// <summary>Gets this row's requirement identifier (e.g. <c>"CB-6.3-04"</c>, <c>"JA-6.3-26"</c>, <c>"PA-6.3-T27"</c>).</summary>
    public required string RequirementId { get; init; }

    /// <summary>Gets this row's column-1 name, exactly as the source table prints it (e.g. <c>"alg"</c>, <c>"sigTst"</c>, <c>"SPO: DSS"</c>).</summary>
    public required string Name { get; init; }

    /// <summary>Gets the kind of thing this row describes.</summary>
    public required AdESTableRowKind Kind { get; init; }

    /// <summary>Gets this row's presence value at each baseline level.</summary>
    public required AdESRowPresence Presence { get; init; }

    /// <summary>
    /// Gets this row's cardinality, or <see langword="null"/> for most <see cref="AdESTableRowKind.Service"/>
    /// rows (every source states "-" in the Cardinality column for a service row whose own SPO rows carry the
    /// cardinality instead — JAdES's own <c>SigningCertificateReferenceService</c> is the one exception, printing
    /// an actual cardinality of its own).
    /// </summary>
    public AdESRowCardinality? Cardinality { get; init; }

    /// <summary>
    /// Gets the References-column citation, or <see langword="null"/> when the source table states "-" (a
    /// service row, or an SPO row whose References cell is itself "-").
    /// </summary>
    public AdESRowReference? Reference { get; init; }

    /// <summary>
    /// Gets the clause(s) that actually govern this row's <c>ConditionedPresence</c> predicate, when they are
    /// distinct from (or additional to) <see cref="Reference"/>'s own
    /// clause. CB-AdES-only today (<c>content type</c>'s note 2 and the <c>x5chain</c>/<c>x5t</c>/<c>x5ts</c>
    /// trio's note 3) — <see langword="null"/> for every JAdES/PAdES row transcribed so far.
    /// </summary>
    public IReadOnlyList<string>? PresenceConditionClauses { get; init; }

    /// <summary>Gets this row's lettered-requirement and note annotations.</summary>
    public AdESRowAnnotations Annotations { get; init; } = AdESRowAnnotations.None;

    /// <summary>
    /// Gets whether this row is one of PAdES's own [CAdES-deferred] rows: its own attribute is pure by-reference
    /// reuse of a signed/unsigned CMS attribute ETSI EN 319 122-1 clause 5 already defines and the shipped CAdES
    /// surface already models/tests (RP-3). PAdES-only today — <see langword="false"/> for every CB-AdES/JAdES row.
    /// </summary>
    public bool IsCAdESDeferred { get; init; }

    /// <summary>
    /// Gets the requirement identifiers of this <see cref="AdESTableRowKind.Service"/> row's SPO children, or
    /// <see langword="null"/> for a non-service row, or for a service row whose satisfying rows print with no
    /// "SPO:" column-1 prefix (JAdES's own <c>SigningTimeService</c>). Satisfaction of a populated service is the
    /// logical OR of these SPOs (CB-6.3-h and its JAdES/PAdES analogues), never their conjunction.
    /// </summary>
    public IReadOnlyList<string>? ServiceProvisionOptionRequirementIds { get; init; }

    /// <summary>
    /// Gets the requirement identifier of the SPO this service row's own additional requirement prefers when
    /// more than one SPO is available to the generator (CB-6.3-i: "should be included within <c>valData</c>"),
    /// or <see langword="null"/> for every non-service row and for a service row with no recorded preference.
    /// CB-AdES-only today — JAdES's own letter k) states an analogous SHOULD-NOT preference in prose with no
    /// single-preferred-SPO field to populate (documented, not enforced, by the JAdES level-rules surface), and
    /// PAdES's own Table 1 records no comparable preference.
    /// </summary>
    public string? PreferredServiceProvisionOptionRequirementId { get; init; }

    /// <summary>
    /// Gets the requirement identifiers of every SPO this service row's own additional requirement prefers when
    /// more than one SPO is available to the generator, for a source whose preference names MORE THAN ONE SPO
    /// out of a larger set (XA-6.3-t40 letter y: "should be included either in the <c>TimeStampValidationData</c>
    /// [...] or the <c>AnyValidationData</c> [...]" — two of the row's three SPOs, disfavoring only the
    /// embedded-in-time-stamp option) — <see langword="null"/> for every row whose own preference (if any) names
    /// exactly one SPO, which stays on <see cref="PreferredServiceProvisionOptionRequirementId"/> unchanged. XAdES
    /// widens the shared apparatus with this ADDITIVE member rather than narrowing a two-SPO preference onto the
    /// singular field (the "not silently narrowed" precedent, one clause over) — XAdES-only today.
    /// </summary>
    public IReadOnlyList<string>? PreferredServiceProvisionOptionRequirementIds { get; init; }

    /// <summary>Gets whether this row's <see cref="Kind"/> is <see cref="AdESTableRowKind.Service"/>.</summary>
    public bool IsServiceRow => Kind == AdESTableRowKind.Service;

    /// <summary>Gets whether this row's <see cref="Kind"/> is <see cref="AdESTableRowKind.ServiceProvisionOption"/>.</summary>
    public bool IsServiceProvisionOptionRow => Kind == AdESTableRowKind.ServiceProvisionOption;
}


/// <summary>
/// Lookup helpers shared by every format's baseline-level table row registry — the merger of
/// <c>CBAdESBaselineLevelTable</c>/<c>JAdESBaselineLevelTable</c>/<c>PAdESBaselineLevelTable</c>'s three
/// duplicated <c>FindByRequirementId</c>/<c>ServiceProvisionOptionsFor</c> statics into one implementation, taking
/// the caller's own row list rather than a fixed <c>Rows</c> field so each format's own registry can call it
/// against its own rows, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 6.3</see> (Table 14),
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 6.3</see> (Table 1), and
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
/// ETSI EN 319 142-1 V1.2.1, clauses 6.2/6.3</see> (Table 1).
/// </summary>
public static class AdESBaselineLevelTables
{
    /// <summary>Finds the row in <paramref name="rows"/> whose <see cref="AdESTableRow.RequirementId"/> matches <paramref name="requirementId"/>.</summary>
    /// <param name="rows">The table's own row registry to search.</param>
    /// <param name="requirementId">The requirement identifier to look up (e.g. <c>"CB-6.3-21"</c>).</param>
    /// <returns>The matching row, or <see langword="null"/> when no row in <paramref name="rows"/> carries that identifier.</returns>
    public static AdESTableRow? FindByRequirementId(IReadOnlyList<AdESTableRow> rows, string requirementId)
    {
        ArgumentNullException.ThrowIfNull(rows);
        ArgumentNullException.ThrowIfNull(requirementId);

        for(int i = 0; i < rows.Count; ++i)
        {
            if(string.Equals(rows[i].RequirementId, requirementId, StringComparison.Ordinal))
            {
                return rows[i];
            }
        }

        return null;
    }


    /// <summary>
    /// Resolves a <see cref="AdESTableRowKind.Service"/> row's SPO children to their registered
    /// <see cref="AdESTableRow"/> instances, in the order
    /// <see cref="AdESTableRow.ServiceProvisionOptionRequirementIds"/> lists them.
    /// </summary>
    /// <param name="rows">The table's own row registry to resolve children against.</param>
    /// <param name="serviceRow">The service row to resolve children for.</param>
    /// <returns>The service row's SPO rows, in declared order.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="rows"/> or <paramref name="serviceRow"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="serviceRow"/> is not a <see cref="AdESTableRowKind.Service"/> row, or names no SPO children
    /// (e.g. JAdES's own <c>SigningTimeService</c> — see <see cref="AdESTableRow.ServiceProvisionOptionRequirementIds"/>).
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// <paramref name="serviceRow"/> names an SPO requirement identifier that is not registered in <paramref name="rows"/>.
    /// </exception>
    public static IReadOnlyList<AdESTableRow> ServiceProvisionOptionsFor(IReadOnlyList<AdESTableRow> rows, AdESTableRow serviceRow)
    {
        ArgumentNullException.ThrowIfNull(rows);
        ArgumentNullException.ThrowIfNull(serviceRow);

        if(!serviceRow.IsServiceRow || serviceRow.ServiceProvisionOptionRequirementIds is null)
        {
            throw new ArgumentException(
                $"'{serviceRow.RequirementId}' is not a service row with registered SPO children (ETSI TS 119 152-1 V1.1.1 clause 6.2.2 CB-6.2.2-01/02; ETSI TS 119 182-1 V1.2.1 clause 6.2.2 JA-6.2.2-09/-10; ETSI EN 319 142-1 V1.2.1 clause 6.2.2 PA-6.2.2-02..05).",
                nameof(serviceRow));
        }

        var options = new List<AdESTableRow>(serviceRow.ServiceProvisionOptionRequirementIds.Count);
        for(int i = 0; i < serviceRow.ServiceProvisionOptionRequirementIds.Count; ++i)
        {
            string optionId = serviceRow.ServiceProvisionOptionRequirementIds[i];
            AdESTableRow? option = FindByRequirementId(rows, optionId);
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
