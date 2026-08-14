using System;
using System.Collections.Generic;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The Table 2 (clause 6.3) row registry — all 46 rows XA-6.3-t01..t46 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see> (zoom-verified cell-for-cell), exposed as static getters (the
/// <c>JAdESBaselineLevelTable</c>/<c>CBAdESBaselineLevelTable</c> exemplar shape) plus lookup helpers over
/// <see cref="Rows"/>. XML-decoder-free: this class carries only the presence/cardinality/reference/annotation
/// DATA clause 6 states, never a wire reader or a rule-evaluation engine — those compose this registry above
/// it: <see cref="XAdESLevelRules"/> evaluates a signature's classification facts (built by
/// <see cref="XAdESSignatureFacts"/>'s seam) against <see cref="Rows"/>.
/// </summary>
/// <remarks>
/// <para>
/// Row-kind counts (see <see cref="AdESTableRowKind"/>): 4 <see cref="AdESTableRowKind.XmlDsigElement"/> rows
/// (<see cref="DsX509Data"/>, <see cref="DsCanonicalizationMethod"/>, <see cref="DsReference"/>,
/// <see cref="DsReferenceTransforms"/> — the XMLDSIG core elements Table 2 profiles by reference, never XAdES's
/// own), 38 <see cref="AdESTableRowKind.QualifyingProperty"/> rows (every <c>xades:</c>-namespaced row, including
/// the eight always-<c>ExactlyZero</c> deprecated-V1 rows and <see cref="DataObjectFormatDescription"/>'s sibling
/// sub-attribute rows), 1 <see cref="AdESTableRowKind.Service"/> row
/// (<see cref="ValidationDataForTimestampsService"/>), and 3 <see cref="AdESTableRowKind.ServiceProvisionOption"/>
/// rows (<see cref="TimeStampValidationDataOption"/>, <see cref="EmbeddedValidationDataOption"/>,
/// <see cref="AnyValidationDataOption"/>) — 46 rows total (the document's own clause 6.3 lead sentence says
/// "44 rows" — an unverified rough estimate, not a spec artifact — every row the raster shows is
/// transcribed here, none omitted).
/// </para>
/// <para>
/// <strong>XA-6.3-t03's <c>ds:Reference</c> row states "&#8805; 2" — a sixth cardinality token minted for XAdES's own Table 2.</strong>
/// <see cref="AdESCardinality.AtLeastTwo"/> is new: CB-AdES's/JAdES's/PAdES's own Table 14/1/1 cells never state a
/// minimum above one. Table 2's own cell is transcribed as printed (at least the SignedProperties reference plus
/// at least one signed-content reference), not silently narrowed to the closest existing token
/// (<see cref="AdESCardinality.OneOrMore"/>) — see that member's own remarks.
/// </para>
/// <para>
/// <strong>Cell-verified.</strong> <see cref="DsCanonicalizationMethod"/>'s
/// own References cell prints "XMLDSIG [1], clause 4.4.1" (clause 4.4.1 of the XML Signature Syntax and
/// Processing recommendation defines <c>KeyName</c>, not <c>CanonicalizationMethod</c>, whose true defining
/// clause is 4.3.1) — transcribed here exactly as printed (<see cref="DsCanonicalizationMethod"/>'s own remarks
/// carry the true clause), mirroring the house's honor-never-correct discipline for a printed-cell defect
/// (the JAdES <c>adoTst</c>/CB-AdES precedent).
/// </para>
/// <para>
/// <strong><see cref="CompleteRevocationRefs"/>/<see cref="AttributeRevocationRefs"/> carry no deprecated-V1
/// twin.</strong> Unlike <see cref="CompleteCertificateRefsV2"/>/<see cref="AttributeCertificateRefsV2"/> (each
/// paired with an always-<c>ExactlyZero</c> V1 row, <see cref="CompleteCertificateRefs"/>/
/// <see cref="AttributeCertificateRefs"/>), Table 2 prints <c>CompleteRevocationRefs</c>/
/// <c>AttributeRevocationRefs</c> with no "V2" suffix and no separate deprecated twin — revocation references
/// never carried the <c>IssuerSerialV2</c>-shaped content that motivated the certificate/attribute-certificate
/// refs' V1-to-V2 split. A genuine document structural asymmetry, transcribed faithfully rather than assumed
/// symmetric with the cert-refs family.
/// </para>
/// <para>
/// <strong>Eight deprecated-V1 rows, always <see cref="AdESPresence.ShallNotBePresent"/>/
/// <see cref="AdESCardinality.ExactlyZero"/>, References "-".</strong> <see cref="SigningCertificate"/>,
/// <see cref="SignerRole"/>, <see cref="SignatureProductionPlace"/>, <see cref="CompleteCertificateRefs"/>,
/// <see cref="AttributeCertificateRefs"/>, <see cref="SigAndRefsTimeStamp"/>, <see cref="RefsOnlyTimeStamp"/>, and
/// <see cref="ArchiveTimeStampV132"/> (the v1.3.2-namespace <c>ArchiveTimeStamp</c>, superseded by the v1.4.1
/// namespace's own <see cref="ArchiveTimeStamp"/> — this library's namespace-is-identity ruling) — each recognized and
/// refused by the leaf's own <c>XAdESReadFailure.DeprecatedQualifyingProperty</c>.
/// </para>
/// <para>
/// <strong>Word-order defect, no row-level effect.</strong> Clause 6.2.2 item 8's own prose names
/// Table 2's eighth column "Additional notes and requirements"; the table's own printed header reads "Additional
/// requirements and notes" — a word-order transposition with no normative effect, recorded once here rather than
/// per row, since it names the COLUMN, not any one row's content.
/// </para>
/// <para>
/// <strong>Letters honored verbatim, never corrected (the r/s/w grammar echo).</strong>
/// <see cref="SignatureTimeStamp"/>'s letter o) reads "the electronic time-stamps encapsulated within the
/// signature-time-stamp attributes" — CAdES-flavoured "attributes" wording in a XAdES document;
/// <see cref="AttrAuthoritiesCertValues"/>'s letter r), <see cref="AttributeCertificateRefsV2"/>'s and
/// <see cref="AttributeRevocationRefs"/>'s shared letter s), and <see cref="AttributeRevocationValues"/>'s
/// letter w) each read "...may be used when a at least an attribute certificate or a signed assertion is
/// incorporated..." — the source's own grammar, reproduced verbatim in the register, not corrected here.
/// </para>
/// <para>
/// <strong><see cref="AdESRowAnnotations.RequirementLetters"/>'s <see cref="string"/> element type is load-bearing
/// here.</strong> Letters <c>aa</c>, <c>bb</c>, <c>cc</c> (<see cref="ArchiveTimeStamp"/>,
/// <see cref="RenewedDigestsV2"/>) are two-character identifiers — the first family member to actually exercise
/// the wider-than-<see cref="char"/> element type that record's own remarks anticipated.
/// </para>
/// <para>
/// <strong>Rule evaluation lives beside this registry, not inside it.</strong> This registry is DATA only —
/// no facts-to-rows classification engine lives in this file, mirroring how <c>CBAdESBaselineLevelTable</c>/
/// <c>JAdESBaselineLevelTable</c> stay pure data while <c>CBAdESLevelRules</c>/<c>JAdESLevelRules</c>
/// (<c>src/Verifiable.JCose</c>, one layer above <c>Verifiable.Cryptography.Pki</c>) evaluate a decoded
/// signature's facts against those registries' rows. <see cref="XAdESSignatureFacts.CreateSeam"/>
/// is where a decoded XAdES signature's format-neutral presence/cardinality inventory is built;
/// <see cref="XAdESLevelRules.Check"/>/<see cref="XAdESLevelRules.EnsureConformant"/>, in this same folder,
/// are the level-rule evaluation surface that consumes both that inventory and <see cref="Rows"/> — the
/// XAdES analogue of <c>JAdESLevelRules.Check</c>/<c>EnsureConformant</c>.
/// </para>
/// <para>
/// <strong>Annex B record (XA-B-01, XA-B-02, XA-B-02.3, XA-B-02.4) — out of implementation scope, by the
/// clause's own address.</strong> Annex B (normative) does not impose an obligation this implementation itself
/// must satisfy: its four "shall be specified" items address whoever DEFINES a NEW, non-clause-5.5 mechanism
/// for long-term availability/integrity of validation data ("[i]f such a mechanism is incorporated into the
/// signature using an unsigned property, then for this mechanism shall be specified: ..."), not a verifier or
/// generator consuming the mechanisms clause 5.5 and clause 6.3 (this file) already cover. This
/// implementation defines no such alternative mechanism, so Annex B has no reader, no check, and no proving
/// test — the correct disposition for a clause whose obligation never triggers. Clause 6.1 NOTE 4 cites
/// "Annex C" for this content (XP-1, this library's own defect register); this registry's own row data
/// carries no Annex B material to misattribute, since none of Table 2's 46 rows reference Annex B.
/// </para>
/// </remarks>
public static class XAdESBaselineLevelTable
{
    /// <summary>
    /// <c>ds:KeyInfo/X509Data</c> (XA-6.3-t01): shall be present at all 4 levels; cardinality 1; ref XMLDSIG
    /// clause 4.5.4 (as Table 2 itself prints it); letters a, b, c; notes 3, 4, 5 — the signing certificate
    /// (and, per letters b/c, path-building material) the generator embeds directly in <c>ds:KeyInfo</c>.
    /// </summary>
    public static AdESTableRow DsX509Data { get; } = new()
    {
        RequirementId = "XA-6.3-t01",
        Name = "ds:KeyInfo/X509Data",
        Kind = AdESTableRowKind.XmlDsigElement,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyOne),
        Reference = new AdESExternalReference("XMLDSIG", "4.5.4"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["a", "b", "c"], NoteNumbers = [3, 4, 5] }
    };

    /// <summary>
    /// <c>ds:SignedInfo/ds:CanonicalizationMethod</c> (XA-6.3-t02): shall be present at all 4 levels; cardinality
    /// 1; letters d, e; note 6. Table 2's own References cell prints "XMLDSIG [1], clause 4.4.1" — clause
    /// 4.4.1 of the XML Signature Syntax and Processing recommendation defines <c>KeyName</c>; this element's
    /// true defining clause is
    /// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-CanonicalizationMethod">4.3.1</see>.
    /// <see cref="AdESTableRow.Reference"/> below transcribes the printed cell verbatim (4.4.1), per this
    /// registry's own print-what's-printed discipline; this remark carries the true clause.
    /// </summary>
    public static AdESTableRow DsCanonicalizationMethod { get; } = new()
    {
        RequirementId = "XA-6.3-t02",
        Name = "ds:SignedInfo/ds:CanonicalizationMethod",
        Kind = AdESTableRowKind.XmlDsigElement,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyOne),
        Reference = new AdESExternalReference("XMLDSIG", "4.4.1"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["d", "e"], NoteNumbers = [6] }
    };

    /// <summary>
    /// <c>ds:Reference</c> (XA-6.3-t03): shall be present at all 4 levels; cardinality "&#8805; 2" — modeled as
    /// <see cref="AdESCardinality.AtLeastTwo"/>, minted for XAdES's own Table 2 (see the type remarks); ref
    /// XMLDSIG clause 4.4.3; no letters/notes — at least the SignedProperties reference plus at least one
    /// signed-content reference.
    /// </summary>
    public static AdESTableRow DsReference { get; } = new()
    {
        RequirementId = "XA-6.3-t03",
        Name = "ds:Reference",
        Kind = AdESTableRowKind.XmlDsigElement,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.AtLeastTwo),
        Reference = new AdESExternalReference("XMLDSIG", "4.4.3")
    };

    /// <summary>
    /// <c>ds:Reference/ds:Transforms</c> (XA-6.3-t04): may be present at all 4 levels; cardinality 0 or 1; ref
    /// XMLDSIG clause 4.4.3.4; letters f, g — the transform-chain requirements (canonicalization-algorithm
    /// closure for a canonicalizing transform, letter f; the allowed non-canonicalizing transform list, letter
    /// g).
    /// </summary>
    public static AdESTableRow DsReferenceTransforms { get; } = new()
    {
        RequirementId = "XA-6.3-t04",
        Name = "ds:Reference/ds:Transforms",
        Kind = AdESTableRowKind.XmlDsigElement,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESExternalReference("XMLDSIG", "4.4.3.4"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["f", "g"] }
    };

    /// <summary>
    /// <c>SigningTime</c> (XA-6.3-t05): shall be present at all 4 levels; cardinality 1; ref clause 5.2.1; letter
    /// h — the generator-claimed UTC signing time.
    /// </summary>
    public static AdESTableRow SigningTime { get; } = new()
    {
        RequirementId = "XA-6.3-t05",
        Name = "SigningTime",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyOne),
        Reference = new AdESInternalClauseReference("5.2.1"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["h"] }
    };

    /// <summary>
    /// <c>SigningCertificateV2</c> (XA-6.3-t06): shall be present at all 4 levels; cardinality 1; ref clause
    /// 5.2.2; letters i, j; note 7 — the mandatory signing-certificate binding property (letter i: no <c>URI</c>
    /// attribute on generated <c>Cert</c> children; letter j: the referenced-certificates SHOULD-NOT preference
    /// against <c>IssuerSerialV2</c>, shared with <see cref="CompleteCertificateRefsV2"/>/
    /// <see cref="AttributeCertificateRefsV2"/>).
    /// </summary>
    public static AdESTableRow SigningCertificateV2 { get; } = new()
    {
        RequirementId = "XA-6.3-t06",
        Name = "SigningCertificateV2",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyOne),
        Reference = new AdESInternalClauseReference("5.2.2"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["i", "j"], NoteNumbers = [7] }
    };

    /// <summary>
    /// <c>SigningCertificate</c> [deprecated V1] (XA-6.3-t07): shall not be present at any level; cardinality 0;
    /// References "-"; no letters — superseded by <see cref="SigningCertificateV2"/>.
    /// </summary>
    public static AdESTableRow SigningCertificate { get; } = new()
    {
        RequirementId = "XA-6.3-t07",
        Name = "SigningCertificate",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallNotBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyZero),
        Reference = null
    };

    /// <summary>
    /// <c>DataObjectFormat</c> (XA-6.3-t08): conditioned presence at all 4 levels; cardinality &#8805; 0; ref
    /// clause 5.2.4; letter k — one instance per signed data object except <c>SignedProperties</c> and (per
    /// letter k's countersignature carve-out) the countersigned signature reference.
    /// </summary>
    public static AdESTableRow DataObjectFormat { get; } = new()
    {
        RequirementId = "XA-6.3-t08",
        Name = "DataObjectFormat",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.ConditionedPresence),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrMore),
        Reference = new AdESInternalClauseReference("5.2.4"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["k"] }
    };

    /// <summary>
    /// <c>DataObjectFormat/Description</c> (XA-6.3-t09): may be present at all 4 levels; cardinality 0 or 1; ref
    /// clause 5.2.4; letter l; note 8.
    /// </summary>
    public static AdESTableRow DataObjectFormatDescription { get; } = new()
    {
        RequirementId = "XA-6.3-t09",
        Name = "DataObjectFormat/Description",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.2.4"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["l"], NoteNumbers = [8] }
    };

    /// <summary>
    /// <c>DataObjectFormat/ObjectIdentifier</c> (XA-6.3-t10): may be present at all 4 levels; cardinality 0 or 1;
    /// ref clause 5.2.4; letter l.
    /// </summary>
    public static AdESTableRow DataObjectFormatObjectIdentifier { get; } = new()
    {
        RequirementId = "XA-6.3-t10",
        Name = "DataObjectFormat/ObjectIdentifier",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.2.4"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["l"] }
    };

    /// <summary>
    /// <c>DataObjectFormat/MimeType</c> (XA-6.3-t11): shall be present at all 4 levels; cardinality 1; ref clause
    /// 5.2.4; letter l — the only mandatory child of <see cref="DataObjectFormat"/>.
    /// </summary>
    public static AdESTableRow DataObjectFormatMimeType { get; } = new()
    {
        RequirementId = "XA-6.3-t11",
        Name = "DataObjectFormat/MimeType",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyOne),
        Reference = new AdESInternalClauseReference("5.2.4"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["l"] }
    };

    /// <summary>
    /// <c>DataObjectFormat/Encoding</c> (XA-6.3-t12): may be present at all 4 levels; cardinality 0 or 1; ref
    /// clause 5.2.4; letter l.
    /// </summary>
    public static AdESTableRow DataObjectFormatEncoding { get; } = new()
    {
        RequirementId = "XA-6.3-t12",
        Name = "DataObjectFormat/Encoding",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.2.4"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["l"] }
    };

    /// <summary>
    /// <c>DataObjectFormat</c>'s <c>ObjectReference</c> attribute (XA-6.3-t13): shall be present at all 4
    /// levels; cardinality 1; ref clause 5.2.4; letter l — the attribute binding one <c>DataObjectFormat</c> to
    /// its <c>ds:Reference</c>.
    /// </summary>
    public static AdESTableRow DataObjectFormatObjectReference { get; } = new()
    {
        RequirementId = "XA-6.3-t13",
        Name = "DataObjectFormat's ObjectReference attribute",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyOne),
        Reference = new AdESInternalClauseReference("5.2.4"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["l"] }
    };

    /// <summary>
    /// <c>SignerRole</c> [deprecated V1] (XA-6.3-t14): shall not be present at any level; cardinality 0;
    /// References "-"; no letters — superseded by <see cref="SignerRoleV2"/>.
    /// </summary>
    public static AdESTableRow SignerRole { get; } = new()
    {
        RequirementId = "XA-6.3-t14",
        Name = "SignerRole",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallNotBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyZero),
        Reference = null
    };

    /// <summary>
    /// <c>SignerRoleV2</c> (XA-6.3-t15): may be present at all 4 levels; cardinality 0 or 1; ref clause 5.2.6; no
    /// letters/notes.
    /// </summary>
    public static AdESTableRow SignerRoleV2 { get; } = new()
    {
        RequirementId = "XA-6.3-t15",
        Name = "SignerRoleV2",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.2.6")
    };

    /// <summary>
    /// <c>CommitmentTypeIndication</c> (XA-6.3-t16): may be present at all 4 levels; cardinality &#8805; 0; ref
    /// clause 5.2.3; no letters.
    /// </summary>
    public static AdESTableRow CommitmentTypeIndication { get; } = new()
    {
        RequirementId = "XA-6.3-t16",
        Name = "CommitmentTypeIndication",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrMore),
        Reference = new AdESInternalClauseReference("5.2.3")
    };

    /// <summary>
    /// <c>SignatureProductionPlaceV2</c> (XA-6.3-t17): may be present at all 4 levels; cardinality 0 or 1; ref
    /// clause 5.2.5; no letters.
    /// </summary>
    public static AdESTableRow SignatureProductionPlaceV2 { get; } = new()
    {
        RequirementId = "XA-6.3-t17",
        Name = "SignatureProductionPlaceV2",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.2.5")
    };

    /// <summary>
    /// <c>SignatureProductionPlace</c> [deprecated V1] (XA-6.3-t18): shall not be present at any level;
    /// cardinality 0; References "-"; no letters — superseded by <see cref="SignatureProductionPlaceV2"/>.
    /// </summary>
    public static AdESTableRow SignatureProductionPlace { get; } = new()
    {
        RequirementId = "XA-6.3-t18",
        Name = "SignatureProductionPlace",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallNotBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyZero),
        Reference = null
    };

    /// <summary>
    /// <c>CounterSignature</c> (XA-6.3-t19): may be present at all 4 levels; cardinality &#8805; 0; ref clause
    /// 5.2.7.2; no letters.
    /// </summary>
    public static AdESTableRow CounterSignature { get; } = new()
    {
        RequirementId = "XA-6.3-t19",
        Name = "CounterSignature",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrMore),
        Reference = new AdESInternalClauseReference("5.2.7.2")
    };

    /// <summary>
    /// <c>AllDataObjectsTimeStamp</c> (XA-6.3-t20): may be present at all 4 levels; cardinality &#8805; 0; ref
    /// clause 5.2.8.1; note 10 (several instances, possibly from different TSAs).
    /// </summary>
    public static AdESTableRow AllDataObjectsTimeStamp { get; } = new()
    {
        RequirementId = "XA-6.3-t20",
        Name = "AllDataObjectsTimeStamp",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrMore),
        Reference = new AdESInternalClauseReference("5.2.8.1"),
        Annotations = new AdESRowAnnotations { NoteNumbers = [10] }
    };

    /// <summary>
    /// <c>IndividualDataObjectsTimeStamp</c> (XA-6.3-t21): may be present at all 4 levels; cardinality &#8805; 0;
    /// ref clause 5.2.8.2; note 10.
    /// </summary>
    public static AdESTableRow IndividualDataObjectsTimeStamp { get; } = new()
    {
        RequirementId = "XA-6.3-t21",
        Name = "IndividualDataObjectsTimeStamp",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrMore),
        Reference = new AdESInternalClauseReference("5.2.8.2"),
        Annotations = new AdESRowAnnotations { NoteNumbers = [10] }
    };

    /// <summary>
    /// <c>SignaturePolicyIdentifier</c> (XA-6.3-t22): may be present at all 4 levels; cardinality 0 or 1; ref
    /// clause 5.2.9; no letters.
    /// </summary>
    public static AdESTableRow SignaturePolicyIdentifier { get; } = new()
    {
        RequirementId = "XA-6.3-t22",
        Name = "SignaturePolicyIdentifier",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.2.9")
    };

    /// <summary>
    /// <c>SignaturePolicyStore</c> (XA-6.3-t23): conditioned presence at all 4 levels; cardinality 0 or 1; ref
    /// clause 5.2.10; letter m — may be incorporated only alongside a <see cref="SignaturePolicyIdentifier"/>
    /// carrying <c>SigPolicyHash</c>.
    /// </summary>
    public static AdESTableRow SignaturePolicyStore { get; } = new()
    {
        RequirementId = "XA-6.3-t23",
        Name = "SignaturePolicyStore",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.ConditionedPresence),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.2.10"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["m"] }
    };

    /// <summary>
    /// <c>SignatureTimeStamp</c> (XA-6.3-t24): presence <see cref="AdESBaselineLevel.BB"/> = "*" (should not be
    /// present); <see cref="AdESBaselineLevel.BT"/>/<see cref="AdESBaselineLevel.BLT"/>/
    /// <see cref="AdESBaselineLevel.BLTA"/> = shall be present. Cardinality level-split: B-B &#8805; 0, B-T/B-LT/
    /// B-LTA &#8805; 1 (a single two-part cell, mirroring JAdES's own <c>sigTst</c> row shape). Ref clause 5.3;
    /// letters n, o; note 10. Letter o): "the electronic time-stamps encapsulated within the
    /// signature-time-stamp attributes shall be created before the signing certificate has been revoked or has
    /// expired" — CAdES-flavoured "attributes" wording, honored verbatim.
    /// </summary>
    public static AdESTableRow SignatureTimeStamp { get; } = new()
    {
        RequirementId = "XA-6.3-t24",
        Name = "SignatureTimeStamp",
        Kind = AdESTableRowKind.QualifyingProperty,
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
        Reference = new AdESInternalClauseReference("5.3"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["n", "o"], NoteNumbers = [10] }
    };

    /// <summary>
    /// <c>CertificateValues</c> (XA-6.3-t25): presence "*" at B-B/B-T; conditioned presence at B-LT/B-LTA;
    /// cardinality 0 or 1, level-invariant despite the level-split presence; ref clause 5.4.2; letters p, q.
    /// </summary>
    public static AdESTableRow CertificateValues { get; } = new()
    {
        RequirementId = "XA-6.3-t25",
        Name = "CertificateValues",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ConditionedPresence,
            BLTA = AdESPresence.ConditionedPresence
        },
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.4.2"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["p", "q"] }
    };

    /// <summary>
    /// <c>AnyValidationData</c> (XA-6.3-t26): presence "*" at B-B/B-T; conditioned presence at B-LT/B-LTA;
    /// cardinality &#8805; 0; ref clause 5.4.6; letters q, u, v, cc.
    /// </summary>
    public static AdESTableRow AnyValidationData { get; } = new()
    {
        RequirementId = "XA-6.3-t26",
        Name = "AnyValidationData",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ConditionedPresence,
            BLTA = AdESPresence.ConditionedPresence
        },
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrMore),
        Reference = new AdESInternalClauseReference("5.4.6"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["q", "u", "v", "cc"] }
    };

    /// <summary>
    /// <c>CompleteCertificateRefsV2</c> (XA-6.3-t27): presence "*" at B-B/B-T; shall not be present at B-LT/
    /// B-LTA; cardinality level-split: B-B/B-T 0 or 1, B-LT/B-LTA 0; ref clause A.1.1; letter j.
    /// </summary>
    public static AdESTableRow CompleteCertificateRefsV2 { get; } = new()
    {
        RequirementId = "XA-6.3-t27",
        Name = "CompleteCertificateRefsV2",
        Kind = AdESTableRowKind.QualifyingProperty,
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
        Annotations = new AdESRowAnnotations { RequirementLetters = ["j"] }
    };

    /// <summary>
    /// <c>CompleteCertificateRefs</c> [deprecated V1] (XA-6.3-t28): shall not be present at any level;
    /// cardinality 0; References "-"; no letters — superseded by <see cref="CompleteCertificateRefsV2"/>.
    /// </summary>
    public static AdESTableRow CompleteCertificateRefs { get; } = new()
    {
        RequirementId = "XA-6.3-t28",
        Name = "CompleteCertificateRefs",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallNotBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyZero),
        Reference = null
    };

    /// <summary>
    /// <c>AttrAuthoritiesCertValues</c> (XA-6.3-t29): presence "*" at B-B/B-T; conditioned presence at B-LT/
    /// B-LTA; cardinality 0 or 1; ref clause 5.4.4; letters q, r. Letter r) reads "...may be used when a at
    /// least an attribute certificate or a signed assertion is incorporated..." — the source's own grammar,
    /// honored verbatim (un-numbered, shared with letters s/w).
    /// </summary>
    public static AdESTableRow AttrAuthoritiesCertValues { get; } = new()
    {
        RequirementId = "XA-6.3-t29",
        Name = "AttrAuthoritiesCertValues",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ConditionedPresence,
            BLTA = AdESPresence.ConditionedPresence
        },
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.4.4"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["q", "r"] }
    };

    /// <summary>
    /// <c>AttributeCertificateRefsV2</c> (XA-6.3-t30): presence "*" at B-B/B-T; shall not be present at B-LT/
    /// B-LTA; cardinality level-split: B-B/B-T 0 or 1, B-LT/B-LTA 0; ref clause A.1.3; letters j, s.
    /// </summary>
    public static AdESTableRow AttributeCertificateRefsV2 { get; } = new()
    {
        RequirementId = "XA-6.3-t30",
        Name = "AttributeCertificateRefsV2",
        Kind = AdESTableRowKind.QualifyingProperty,
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
        Annotations = new AdESRowAnnotations { RequirementLetters = ["j", "s"] }
    };

    /// <summary>
    /// <c>AttributeCertificateRefs</c> [deprecated V1] (XA-6.3-t31): shall not be present at any level;
    /// cardinality 0; References "-"; no letters — superseded by <see cref="AttributeCertificateRefsV2"/>.
    /// </summary>
    public static AdESTableRow AttributeCertificateRefs { get; } = new()
    {
        RequirementId = "XA-6.3-t31",
        Name = "AttributeCertificateRefs",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallNotBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyZero),
        Reference = null
    };

    /// <summary>
    /// <c>RevocationValues</c> (XA-6.3-t32): presence "*" at B-B/B-T; conditioned presence at B-LT/B-LTA;
    /// cardinality 0 or 1; ref clause 5.4.3; letters t, u, v.
    /// </summary>
    public static AdESTableRow RevocationValues { get; } = new()
    {
        RequirementId = "XA-6.3-t32",
        Name = "RevocationValues",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ConditionedPresence,
            BLTA = AdESPresence.ConditionedPresence
        },
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.4.3"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["t", "u", "v"] }
    };

    /// <summary>
    /// <c>CompleteRevocationRefs</c> (XA-6.3-t33): presence "*" at B-B/B-T; shall not be present at B-LT/B-LTA;
    /// cardinality level-split: B-B/B-T 0 or 1, B-LT/B-LTA 0; ref clause A.1.2; no letters — printed with no "V2"
    /// suffix and no deprecated twin (see the type remarks).
    /// </summary>
    public static AdESTableRow CompleteRevocationRefs { get; } = new()
    {
        RequirementId = "XA-6.3-t33",
        Name = "CompleteRevocationRefs",
        Kind = AdESTableRowKind.QualifyingProperty,
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
    /// <c>AttributeRevocationValues</c> (XA-6.3-t34): presence "*" at B-B/B-T; conditioned presence at B-LT/
    /// B-LTA; cardinality 0 or 1; ref clause 5.4.5; letters v, w.
    /// </summary>
    public static AdESTableRow AttributeRevocationValues { get; } = new()
    {
        RequirementId = "XA-6.3-t34",
        Name = "AttributeRevocationValues",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ConditionedPresence,
            BLTA = AdESPresence.ConditionedPresence
        },
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne),
        Reference = new AdESInternalClauseReference("5.4.5"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["v", "w"] }
    };

    /// <summary>
    /// <c>AttributeRevocationRefs</c> (XA-6.3-t35): presence "*" at B-B/B-T; shall not be present at B-LT/B-LTA;
    /// cardinality level-split: B-B/B-T 0 or 1, B-LT/B-LTA 0; ref clause A.1.4; letter s — printed with no "V2"
    /// suffix and no deprecated twin (see the type remarks).
    /// </summary>
    public static AdESTableRow AttributeRevocationRefs { get; } = new()
    {
        RequirementId = "XA-6.3-t35",
        Name = "AttributeRevocationRefs",
        Kind = AdESTableRowKind.QualifyingProperty,
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
        Annotations = new AdESRowAnnotations { RequirementLetters = ["s"] }
    };

    /// <summary>
    /// <c>SigAndRefsTimeStampV2</c> (XA-6.3-t36): presence "*" at B-B/B-T; shall not be present at B-LT/B-LTA;
    /// cardinality level-split: B-B/B-T &#8805; 0, B-LT/B-LTA 0; ref clause A.1.5.1; no letters.
    /// </summary>
    public static AdESTableRow SigAndRefsTimeStampV2 { get; } = new()
    {
        RequirementId = "XA-6.3-t36",
        Name = "SigAndRefsTimeStampV2",
        Kind = AdESTableRowKind.QualifyingProperty,
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
    /// <c>SigAndRefsTimeStamp</c> [deprecated V1] (XA-6.3-t37): shall not be present at any level; cardinality
    /// 0; References "-"; no letters — superseded by <see cref="SigAndRefsTimeStampV2"/>.
    /// </summary>
    public static AdESTableRow SigAndRefsTimeStamp { get; } = new()
    {
        RequirementId = "XA-6.3-t37",
        Name = "SigAndRefsTimeStamp",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallNotBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyZero),
        Reference = null
    };

    /// <summary>
    /// <c>RefsOnlyTimeStampV2</c> (XA-6.3-t38): presence "*" at B-B/B-T; shall not be present at B-LT/B-LTA;
    /// cardinality level-split: B-B/B-T &#8805; 0, B-LT/B-LTA 0; ref clause A.1.5.2; no letters.
    /// </summary>
    public static AdESTableRow RefsOnlyTimeStampV2 { get; } = new()
    {
        RequirementId = "XA-6.3-t38",
        Name = "RefsOnlyTimeStampV2",
        Kind = AdESTableRowKind.QualifyingProperty,
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
    /// <c>RefsOnlyTimeStamp</c> [deprecated V1] (XA-6.3-t39): shall not be present at any level; cardinality 0;
    /// References "-"; no letters — superseded by <see cref="RefsOnlyTimeStampV2"/>.
    /// </summary>
    public static AdESTableRow RefsOnlyTimeStamp { get; } = new()
    {
        RequirementId = "XA-6.3-t39",
        Name = "RefsOnlyTimeStamp",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallNotBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyZero),
        Reference = null
    };

    /// <summary>
    /// Service "Incorporation of validation data for electronic time-stamps" (XA-6.3-t40): presence "*" at B-B/
    /// B-T; shall be provided at B-LT/B-LTA; cardinality "-" (n/a, service row); References "-"; letters x, y;
    /// note 9. Satisfied by any of its three "SPO:"-prefixed children
    /// (<see cref="TimeStampValidationDataOption"/>/<see cref="EmbeddedValidationDataOption"/>/
    /// <see cref="AnyValidationDataOption"/>, XA-6.3-t41..43) — letter x's three-way disjunction. Letter y's own
    /// SHOULD ("the validation data for electronic time-stamps should be included either in the
    /// <c>TimeStampValidationData</c> [...] or the <c>AnyValidationData</c> [...]") prefers
    /// <see cref="TimeStampValidationDataOption"/>/<see cref="AnyValidationDataOption"/> over
    /// <see cref="EmbeddedValidationDataOption"/>, surfaced as an <see cref="XAdESRuleObservation"/> by
    /// <see cref="XAdESLevelRules.CheckValidationDataServicePreference"/> — never a
    /// <see cref="XAdESRuleViolation"/>, the standing SHOULD-level vocabulary.
    /// </summary>
    public static AdESTableRow ValidationDataForTimestampsService { get; } = new()
    {
        RequirementId = "XA-6.3-t40",
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
        Annotations = new AdESRowAnnotations { RequirementLetters = ["x", "y"], NoteNumbers = [9] },
        ServiceProvisionOptionRequirementIds = ["XA-6.3-t41", "XA-6.3-t42", "XA-6.3-t43"],
        PreferredServiceProvisionOptionRequirementIds = ["XA-6.3-t41", "XA-6.3-t43"]
    };

    /// <summary>
    /// SPO <c>TimeStampValidationData</c> (XA-6.3-t41): presence "*" at B-B/B-T; conditioned presence at B-LT/
    /// B-LTA; cardinality &#8805; 0; ref clause 5.5.1; letter y.
    /// </summary>
    public static AdESTableRow TimeStampValidationDataOption { get; } = new()
    {
        RequirementId = "XA-6.3-t41",
        Name = "SPO: TimeStampValidationData",
        Kind = AdESTableRowKind.ServiceProvisionOption,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ConditionedPresence,
            BLTA = AdESPresence.ConditionedPresence
        },
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrMore),
        Reference = new AdESInternalClauseReference("5.5.1"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["y"] }
    };

    /// <summary>
    /// SPO "certificate and revocation values embedded in the electronic time-stamp itself" (XA-6.3-t42):
    /// presence "*" at B-B/B-T; conditioned presence at B-LT/B-LTA; cardinality &#8805; 0; References "-"; letter
    /// y — the TST's own embedded validation data counts as satisfying the service (letter y disfavors this
    /// option against <see cref="TimeStampValidationDataOption"/>/<see cref="AnyValidationDataOption"/>).
    /// </summary>
    public static AdESTableRow EmbeddedValidationDataOption { get; } = new()
    {
        RequirementId = "XA-6.3-t42",
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
        Annotations = new AdESRowAnnotations { RequirementLetters = ["y"] }
    };

    /// <summary>
    /// SPO <c>AnyValidationData</c> (XA-6.3-t43): presence "*" at B-B/B-T; conditioned presence at B-LT/B-LTA;
    /// cardinality &#8805; 0; ref clause 5.4.6; letter y — the same wire element as
    /// <see cref="AnyValidationData"/> under its service-provision framing.
    /// </summary>
    public static AdESTableRow AnyValidationDataOption { get; } = new()
    {
        RequirementId = "XA-6.3-t43",
        Name = "SPO: AnyValidationData",
        Kind = AdESTableRowKind.ServiceProvisionOption,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ConditionedPresence,
            BLTA = AdESPresence.ConditionedPresence
        },
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrMore),
        Reference = new AdESInternalClauseReference("5.4.6"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["y"] }
    };

    /// <summary>
    /// <c>ArchiveTimeStamp</c>, namespace <c>http://uri.etsi.org/01903/v1.4.1#</c> (XA-6.3-t44): presence "*" at
    /// B-B/B-T/B-LT; shall be present at B-LTA; cardinality &#8805; 1, level-invariant; ref clause 5.5.2; letters
    /// z, aa — B-LTA-exclusive and mandatory once reached. Namespace is part of this row's own identity, not a
    /// modeled member: the leaf's own <c>XAdESIdentifiers.XAdESNamespaceV141</c> carries the URI (this Pki-side
    /// registry stays XML-decoder-free).
    /// </summary>
    public static AdESTableRow ArchiveTimeStamp { get; } = new()
    {
        RequirementId = "XA-6.3-t44",
        Name = "ArchiveTimeStamp (namespace http://uri.etsi.org/01903/v1.4.1#)",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ShouldNotBePresent,
            BLTA = AdESPresence.ShallBePresent
        },
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.OneOrMore),
        Reference = new AdESInternalClauseReference("5.5.2"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["z", "aa"] }
    };

    /// <summary>
    /// <c>ArchiveTimeStamp</c> [deprecated V1 namespace], namespace <c>http://uri.etsi.org/01903/v1.3.2#</c>
    /// (XA-6.3-t45): shall not be present at any level; cardinality 0; References "-"; no letters — superseded
    /// by the v1.4.1-namespace <see cref="ArchiveTimeStamp"/> (this library's namespace-is-identity ruling).
    /// </summary>
    public static AdESTableRow ArchiveTimeStampV132 { get; } = new()
    {
        RequirementId = "XA-6.3-t45",
        Name = "ArchiveTimeStamp (namespace http://uri.etsi.org/01903/v1.3.2#)",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = AdESRowPresence.Uniform(AdESPresence.ShallNotBePresent),
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ExactlyZero),
        Reference = null
    };

    /// <summary>
    /// <c>RenewedDigestsV2</c> (XA-6.3-t46): presence "*" at B-B/B-T/B-LT; conditioned presence at B-LTA;
    /// cardinality &#8805; 0; ref clause 5.5.3; letter bb.
    /// </summary>
    public static AdESTableRow RenewedDigestsV2 { get; } = new()
    {
        RequirementId = "XA-6.3-t46",
        Name = "RenewedDigestsV2",
        Kind = AdESTableRowKind.QualifyingProperty,
        Presence = new AdESRowPresence
        {
            BB = AdESPresence.ShouldNotBePresent,
            BT = AdESPresence.ShouldNotBePresent,
            BLT = AdESPresence.ShouldNotBePresent,
            BLTA = AdESPresence.ConditionedPresence
        },
        Cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrMore),
        Reference = new AdESInternalClauseReference("5.5.3"),
        Annotations = new AdESRowAnnotations { RequirementLetters = ["bb"] }
    };


    /// <summary>Gets every Table 2 row, in the source table's own printed order (XA-6.3-t01..t46).</summary>
    public static IReadOnlyList<AdESTableRow> Rows { get; } =
    [
        DsX509Data, DsCanonicalizationMethod, DsReference, DsReferenceTransforms,
        SigningTime, SigningCertificateV2, SigningCertificate,
        DataObjectFormat, DataObjectFormatDescription, DataObjectFormatObjectIdentifier,
        DataObjectFormatMimeType, DataObjectFormatEncoding, DataObjectFormatObjectReference,
        SignerRole, SignerRoleV2, CommitmentTypeIndication,
        SignatureProductionPlaceV2, SignatureProductionPlace, CounterSignature,
        AllDataObjectsTimeStamp, IndividualDataObjectsTimeStamp,
        SignaturePolicyIdentifier, SignaturePolicyStore, SignatureTimeStamp,
        CertificateValues, AnyValidationData,
        CompleteCertificateRefsV2, CompleteCertificateRefs,
        AttrAuthoritiesCertValues, AttributeCertificateRefsV2, AttributeCertificateRefs,
        RevocationValues, CompleteRevocationRefs,
        AttributeRevocationValues, AttributeRevocationRefs,
        SigAndRefsTimeStampV2, SigAndRefsTimeStamp,
        RefsOnlyTimeStampV2, RefsOnlyTimeStamp,
        ValidationDataForTimestampsService, TimeStampValidationDataOption, EmbeddedValidationDataOption, AnyValidationDataOption,
        ArchiveTimeStamp, ArchiveTimeStampV132,
        RenewedDigestsV2
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
    /// <param name="requirementId">The requirement identifier to look up (e.g. <c>"XA-6.3-t24"</c>).</param>
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
    /// children.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// <paramref name="serviceRow"/> names an SPO requirement identifier that is not registered in <see cref="Rows"/>.
    /// </exception>
    public static IReadOnlyList<AdESTableRow> ServiceProvisionOptionsFor(AdESTableRow serviceRow)
    {
        return AdESBaselineLevelTables.ServiceProvisionOptionsFor(Rows, serviceRow);
    }
}
