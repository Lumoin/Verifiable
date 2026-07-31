using System;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One wire name of the preservation protocol of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>, in both of the syntaxes the document makes normative: the XML element name and
/// the JSON member name that implements it.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The two halves travel together because neither derives from the other.</strong> Every component's
/// clause carries a table mapping its element names to "implementing JSON member names", and no rule reproduces
/// them: <c>ClaimedRequestorName</c> becomes <c>crn</c>, <c>PreservationEvidenceRetentionPeriod</c> becomes
/// <c>perp</c>, <c>ExpectedEvidenceDuration</c> becomes <c>eed</c>, and the very same element name maps to
/// different member names in different components — <c>VersionID</c> is <c>versionId</c> on a retrieval request
/// and <c>verId</c> on an evidence, and <c>value</c> is <c>Value</c> on a deletion mode and <c>value</c> on a
/// subject of retrieval. A binding that derived one name from the other would diverge from the specification
/// silently, which is why every pair in this namespace is transcribed from its own table and carried as a unit.
/// </para>
/// <para>
/// <strong>Comparison is ordinal and case-sensitive</strong>, in both syntaxes: an XML element name is matched by
/// exact character sequence, and a JSON member name is a string the same way.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct PreservationName
{
    /// <summary>Initializes a name pair from the two spellings one component's table states.</summary>
    /// <param name="xmlElementName">The XML element name, exactly as the component's clause writes it.</param>
    /// <param name="jsonMemberName">The JSON member name the same clause's table gives for it.</param>
    /// <exception cref="ArgumentException">Thrown when either spelling is absent or empty; a name pair with a half missing is not a name.</exception>
    public PreservationName(string xmlElementName, string jsonMemberName)
    {
        ArgumentException.ThrowIfNullOrEmpty(xmlElementName);
        ArgumentException.ThrowIfNullOrEmpty(jsonMemberName);

        XmlElementName = xmlElementName;
        JsonMemberName = jsonMemberName;
    }


    /// <summary>The XML element name, as the component's own clause writes it.</summary>
    public string XmlElementName { get; }

    /// <summary>The JSON member name the component's mapping table gives for <see cref="XmlElementName"/>.</summary>
    public string JsonMemberName { get; }


    /// <summary>Determines whether a name read off an XML document is this element.</summary>
    /// <param name="name">The local name of the element, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the name is ordinally equal to <see cref="XmlElementName"/>.</returns>
    public bool IsXmlElementName(string? name) =>
        XmlElementName is not null && string.Equals(name, XmlElementName, StringComparison.Ordinal);


    /// <summary>Determines whether a name read off a JSON object is this member.</summary>
    /// <param name="name">The member name, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the name is ordinally equal to <see cref="JsonMemberName"/>.</returns>
    public bool IsJsonMemberName(string? name) =>
        JsonMemberName is not null && string.Equals(name, JsonMemberName, StringComparison.Ordinal);


    /// <summary>A short debugger string showing both spellings.</summary>
    private string DebuggerDisplay => $"PreservationName({XmlElementName ?? "unstated"} / {JsonMemberName ?? "unstated"})";
}


/// <summary>
/// The names of the <c>Request</c> base component, which every one of the eight operation requests extends and
/// inherits (clause 5.3.1.1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
/// <remarks>
/// The base component is "used as a base type only, not as a JSON instance", so it has no mapping table of its
/// own; the two names below are the ones the operations' own tables restate. Tables 3, 5, 7, 8, 10 and 12 list
/// them beside the operation's own elements, while Tables 1 and 14 list only the operation's own — an
/// inconsistency in the document that changes nothing about the names themselves.
/// </remarks>
public static class PreservationRequestParameterNames
{
    /// <summary>The <c>OptionalInputs</c> element, JSON <c>optIn</c> — a sub-component of the external base specification, carried verbatim by this library.</summary>
    public static PreservationName OptionalInputs { get; } = new("OptionalInputs", "optIn");

    /// <summary>The <c>RequestID</c> attribute, JSON <c>reqId</c> — the identifier a service echoes back in its response.</summary>
    public static PreservationName RequestId { get; } = new("RequestID", "reqId");
}


/// <summary>
/// The names of the <c>Response</c> base component, which every one of the eight operation responses extends and
/// inherits (clause 5.3.1.2 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
/// <remarks>
/// <strong>The <c>Result</c> element has no pair here, and that is deliberate.</strong> Clause 5.3.1.2 requires
/// it and defines it by reference to the external base specification, and no table of this document gives it a
/// JSON member name. Stating one would put a name on the wire that no cached normative text supports, so the
/// element is modelled (see <see cref="PreservationResult"/>) and its JSON spelling is left to the binding that
/// has the base specification in hand.
/// </remarks>
public static class PreservationResponseParameterNames
{
    /// <summary>The <c>OptionalOutputs</c> element, JSON <c>optOut</c> — a sub-component of the external base specification, carried verbatim by this library.</summary>
    public static PreservationName OptionalOutputs { get; } = new("OptionalOutputs", "optOut");

    /// <summary>The <c>RequestID</c> attribute, JSON <c>reqId</c> — echoed from the request that produced this response.</summary>
    public static PreservationName RequestId { get; } = new("RequestID", "reqId");

    /// <summary>The <c>Result</c> element's XML name. It has no stated JSON member name; see the class remarks.</summary>
    public static string ResultElementName { get; } = "Result";
}


/// <summary>
/// The name of the <c>DeletionMode</c> component (clause 5.4.2, Table 17 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
/// <remarks>
/// <strong>Two documented oddities ride on this single row.</strong> The table maps the element <c>value</c> to
/// the member name <c>Value</c>, with a capital, while the sibling <c>SubjectOfRetrieval</c> component's Table 22
/// maps its identically named element to <c>value</c> — the same element name, two member names, in two
/// components of one clause. And the JSON type the same clause reproduces is a bare string enumeration with no
/// properties at all, so the member the table names cannot occur in it. Both are transcribed rather than
/// normalised: a binding that "corrected" either would stop implementing what the document states.
/// </remarks>
public static class PreservationDeletionModeParameterNames
{
    /// <summary>The <c>value</c> element, JSON <c>Value</c> — the deletion mode itself.</summary>
    public static PreservationName Value { get; } = new("value", "Value");
}


/// <summary>
/// The names of the <c>Event</c> component (clause 5.4.3, Table 18 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>), the payload of a trace.
/// </summary>
public static class PreservationEventParameterNames
{
    /// <summary>The mandatory <c>Time</c> element, JSON <c>time</c> — an XML date and time, and an integer of milliseconds since the epoch in the JSON binding.</summary>
    public static PreservationName Time { get; } = new("Time", "time");

    /// <summary>The mandatory <c>Subject</c> element, JSON <c>sub</c> — who or what triggered the event.</summary>
    public static PreservationName Subject { get; } = new("Subject", "sub");

    /// <summary>The mandatory <c>Operation</c> element, JSON <c>op</c> — the characteristic of the event, such as the operation it belongs to.</summary>
    public static PreservationName Operation { get; } = new("Operation", "op");

    /// <summary>The optional <c>Object</c> element, JSON <c>obj</c> — the object the event addressed.</summary>
    public static PreservationName Object { get; } = new("Object", "obj");

    /// <summary>The optional <c>Detail</c> element, JSON <c>det</c> — free text.</summary>
    public static PreservationName Detail { get; } = new("Detail", "det");
}


/// <summary>
/// The names of the <c>PO</c> component (clause 5.4.5, Table 20 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>), the payload container every operation that carries data uses.
/// </summary>
/// <remarks>
/// The value itself is an XML <c>choice</c> of two elements and the JSON binding keeps only the first, so
/// <see cref="BinaryData"/> is a pair and <see cref="XmlDataElementName"/> is an XML name with no JSON member of
/// its own.
/// </remarks>
public static class PreservationObjectParameterNames
{
    /// <summary>The <c>binaryData</c> alternative of the value choice, JSON <c>binaryData</c> — base64-encoded octets.</summary>
    public static PreservationName BinaryData { get; } = new("binaryData", "binaryData");

    /// <summary>
    /// The <c>xmlData</c> alternative of the value choice. The reproduced JSON schema omits this alternative
    /// altogether, so the document states no member name for it: over the JSON binding an XML-native payload has
    /// no representation of its own.
    /// </summary>
    public static string XmlDataElementName { get; } = "xmlData";

    /// <summary>The optional <c>FormatId</c> attribute, JSON <c>formatId</c> — mandatory whenever the object needs treatment beyond base64 decoding.</summary>
    public static PreservationName FormatId { get; } = new("FormatId", "formatId");

    /// <summary>The optional <c>MimeType</c> attribute, JSON <c>mimeType</c> — mandatory when <see cref="FormatId"/> is omitted.</summary>
    public static PreservationName MimeType { get; } = new("MimeType", "mimeType");

    /// <summary>The optional <c>PronomId</c> attribute, JSON <c>pronomId</c> — a persistent unique identifier of the file format.</summary>
    public static PreservationName PronomId { get; } = new("PronomId", "pronomId");

    /// <summary>The optional <c>ID</c> attribute, JSON <c>id</c> — unique within the document that carries it.</summary>
    public static PreservationName Id { get; } = new("ID", "id");

    /// <summary>The optional <c>RelatedObjects</c> attribute, JSON <c>relObj</c> — a list of identifier references, not a single one.</summary>
    public static PreservationName RelatedObjects { get; } = new("RelatedObjects", "relObj");
}


/// <summary>
/// The names of the <c>Evidence</c> component (clause 5.4.4, Table 19 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>), which extends <c>PO</c> with two names of its own.
/// </summary>
/// <remarks>
/// The six inherited names are restated here rather than reached through
/// <see cref="PreservationObjectParameterNames"/>, because Table 19 restates them — and because one of them does
/// not survive the extension unchanged in spirit: clause 5.4.4.1 makes <see cref="FormatId"/> mandatory on an
/// evidence although it is optional on the object the evidence extends. The pair itself is identical; the
/// obligation is not.
/// </remarks>
public static class PreservationEvidenceParameterNames
{
    /// <summary>The <c>binaryData</c> alternative of the inherited value choice, JSON <c>binaryData</c>.</summary>
    public static PreservationName BinaryData { get; } = new("binaryData", "binaryData");

    /// <summary>The inherited <c>FormatId</c> attribute, JSON <c>formatId</c> — mandatory on an evidence (clause 5.4.4.1).</summary>
    public static PreservationName FormatId { get; } = new("FormatId", "formatId");

    /// <summary>The inherited <c>MimeType</c> attribute, JSON <c>mimeType</c>.</summary>
    public static PreservationName MimeType { get; } = new("MimeType", "mimeType");

    /// <summary>The inherited <c>PronomId</c> attribute, JSON <c>pronomId</c>.</summary>
    public static PreservationName PronomId { get; } = new("PronomId", "pronomId");

    /// <summary>The inherited <c>ID</c> attribute, JSON <c>id</c>.</summary>
    public static PreservationName Id { get; } = new("ID", "id");

    /// <summary>The inherited <c>RelatedObjects</c> attribute, JSON <c>relObj</c>.</summary>
    public static PreservationName RelatedObjects { get; } = new("RelatedObjects", "relObj");

    /// <summary>The <c>POID</c> attribute this component adds, JSON <c>poId</c> — which preservation object the evidence belongs to.</summary>
    public static PreservationName PreservationObjectId { get; } = new("POID", "poId");

    /// <summary>
    /// The <c>VersionID</c> attribute this component adds, JSON <c>verId</c> — <strong>not</strong>
    /// <c>versionId</c>, which is what the same element name maps to on a retrieval request and an update
    /// response (Tables 5 and 9).
    /// </summary>
    public static PreservationName VersionId { get; } = new("VersionID", "verId");
}


/// <summary>
/// The name of the <c>SubjectOfRetrieval</c> component (clause 5.4.9, Table 22 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
public static class PreservationSubjectOfRetrievalParameterNames
{
    /// <summary>The <c>value</c> element, JSON <c>value</c> — lower case here, unlike the identically named element of the deletion-mode component.</summary>
    public static PreservationName Value { get; } = new("value", "value");
}


/// <summary>
/// The name of the <c>Trace</c> component (clause 5.4.10, Table 23 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
public static class PreservationTraceParameterNames
{
    /// <summary>The repeatable <c>Event</c> element, JSON <c>event</c> — an array in the JSON binding.</summary>
    public static PreservationName Event { get; } = new("Event", "event");
}


/// <summary>
/// The names of the <c>Profile</c> component (clause 5.4.7, Table 21 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>), the discovery payload a service publishes.
/// </summary>
/// <remarks>
/// <para>
/// Table 21 is the one place this document promises traceability into its companion specification: beside each
/// JSON member name it states the requirement of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
/// ETSI TS 119 511 V1.2.1</see> clause 6.4 that the sub-component satisfies. Each correspondence is written on
/// the member below exactly as the table gives it.
/// </para>
/// <para>
/// <strong>A cross-document defect, recorded rather than corrected.</strong> Table 21's last two correspondences
/// appear to be interchanged: it maps <c>ExpectedEvidenceDuration</c> to <c>OVR-6.4-05</c> and
/// <c>PreservationEvidenceRetentionPeriod</c> to <c>OVR-6.4-06</c>, while clause 6.4 of the companion
/// specification states <c>OVR-6.4-05</c> as the requirement that a profile contain the preservation evidence
/// retention period and <c>OVR-6.4-06</c> as the recommendation that it contain the expected evidence duration —
/// the other way round. The table's own text is transcribed on the members; the requirements matrix owns the row.
/// </para>
/// </remarks>
public static class PreservationProfileParameterNames
{
    /// <summary>The <c>ProfileIdentifier</c> element, JSON <c>pid</c>; Table 21 states the correspondence <c>OVR-6.4-04a)</c>.</summary>
    public static PreservationName ProfileIdentifier { get; } = new("ProfileIdentifier", "pid");

    /// <summary>The <c>Operation</c> element, JSON <c>op</c>; Table 21 states the correspondence <c>OVR-6.4-04 b)</c>.</summary>
    public static PreservationName Operation { get; } = new("Operation", "op");

    /// <summary>The <c>Policy</c> element, JSON <c>pol</c>; Table 21 states the correspondence <c>OVR-6.4-04 c)</c>.</summary>
    public static PreservationName Policy { get; } = new("Policy", "pol");

    /// <summary>The <c>ProfileValidityPeriod</c> element, JSON <c>pvp</c>; Table 21 states the correspondence <c>OVR-6.4-04 d)</c>.</summary>
    public static PreservationName ProfileValidityPeriod { get; } = new("ProfileValidityPeriod", "pvp");

    /// <summary>The <c>PreservationStorageModel</c> element, JSON <c>psm</c>; Table 21 states the correspondence <c>OVR-6.4-04 e)</c>.</summary>
    public static PreservationName PreservationStorageModel { get; } = new("PreservationStorageModel", "psm");

    /// <summary>The <c>PreservationGoal</c> element, JSON <c>pg</c>; Table 21 states the correspondence <c>OVR-6.4-04 f)</c>.</summary>
    public static PreservationName PreservationGoal { get; } = new("PreservationGoal", "pg");

    /// <summary>The <c>EvidenceFormat</c> element, JSON <c>ef</c>; Table 21 states the correspondence <c>OVR-6.4-04 g)</c>.</summary>
    public static PreservationName EvidenceFormat { get; } = new("EvidenceFormat", "ef");

    /// <summary>The <c>Specification</c> element, JSON <c>spec</c>; Table 21 states the correspondence <c>OVR-6.4-04 h)</c>.</summary>
    public static PreservationName Specification { get; } = new("Specification", "spec");

    /// <summary>
    /// The <c>Description</c> element, JSON <c>desc</c>; Table 21 states the correspondence <c>OVR-6.4-04 i)</c>.
    /// The reproduced JSON schema fragment of clause 5.4.7.3 spells the property <c>description</c> instead; the
    /// table is the mapping the clause makes normative and is what is stated here.
    /// </summary>
    public static PreservationName Description { get; } = new("Description", "desc");

    /// <summary>The <c>SchemeIdentifier</c> element, JSON <c>sid</c>; Table 21 states the correspondence <c>OVR-6.4-04 j)</c>.</summary>
    public static PreservationName SchemeIdentifier { get; } = new("SchemeIdentifier", "sid");

    /// <summary>The <c>ExpectedEvidenceDuration</c> element, JSON <c>eed</c>; Table 21 states the correspondence <c>OVR-6.4-05</c> — see the class remarks on that correspondence.</summary>
    public static PreservationName ExpectedEvidenceDuration { get; } = new("ExpectedEvidenceDuration", "eed");

    /// <summary>The <c>PreservationEvidenceRetentionPeriod</c> element, JSON <c>perp</c>; Table 21 states the correspondence <c>OVR-6.4-06</c> — see the class remarks on that correspondence.</summary>
    public static PreservationName PreservationEvidenceRetentionPeriod { get; } = new("PreservationEvidenceRetentionPeriod", "perp");

    /// <summary>The <c>Extension</c> element, JSON <c>ext</c>; Table 21 states no requirement correspondence for it.</summary>
    public static PreservationName Extension { get; } = new("Extension", "ext");
}
