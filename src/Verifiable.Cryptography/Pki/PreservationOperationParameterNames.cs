namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The names of the <c>RetrieveInfo</c> request (clause 5.3.2.1, Table 1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
/// <remarks>
/// Table 1 lists only the operation's own elements; the two inherited names are
/// <see cref="PreservationRequestParameterNames"/>'s.
/// </remarks>
public static class RetrieveInfoRequestParameterNames
{
    /// <summary>The optional <c>Profile</c> element, JSON <c>pro</c> — the one profile information is wanted about.</summary>
    public static PreservationName Profile { get; } = new("Profile", "pro");

    /// <summary>The optional <c>Status</c> element, JSON <c>stat</c> — which profiles are wanted; omitting it means the active ones.</summary>
    public static PreservationName Status { get; } = new("Status", "stat");
}


/// <summary>
/// The names of the <c>RetrieveInfoResponse</c> (clause 5.3.2.2, Table 2 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
/// <remarks>
/// Table 2 lists only the operation's own element; the inherited names are
/// <see cref="PreservationResponseParameterNames"/>'s.
/// </remarks>
public static class RetrieveInfoResponseParameterNames
{
    /// <summary>The repeatable <c>Profile</c> element, JSON <c>pro</c> — the profiles the service publishes.</summary>
    public static PreservationName Profile { get; } = new("Profile", "pro");
}


/// <summary>
/// The names of the <c>PreservePO</c> request (clause 5.3.3.1, Table 3 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
/// <remarks>Table 3 restates the two inherited names beside the operation's own.</remarks>
public static class PreservePreservationObjectRequestParameterNames
{
    /// <summary>The inherited <c>OptionalInputs</c> element, JSON <c>optIn</c>.</summary>
    public static PreservationName OptionalInputs { get; } = new("OptionalInputs", "optIn");

    /// <summary>The inherited <c>RequestID</c> attribute, JSON <c>reqId</c>.</summary>
    public static PreservationName RequestId { get; } = new("RequestID", "reqId");

    /// <summary>The mandatory <c>Profile</c> element, JSON <c>pro</c> — which operational profile the submission is preserved under.</summary>
    public static PreservationName Profile { get; } = new("Profile", "pro");

    /// <summary>The repeatable <c>PO</c> element, JSON <c>po</c> — the preservation objects submitted, of which there may be none.</summary>
    public static PreservationName PreservationObject { get; } = new("PO", "po");
}


/// <summary>
/// The names of the <c>PreservePOResponse</c> (clause 5.3.3.2, Table 4 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
public static class PreservePreservationObjectResponseParameterNames
{
    /// <summary>The inherited <c>OptionalOutputs</c> element, JSON <c>optOut</c>.</summary>
    public static PreservationName OptionalOutputs { get; } = new("OptionalOutputs", "optOut");

    /// <summary>The inherited <c>RequestID</c> attribute, JSON <c>reqId</c>.</summary>
    public static PreservationName RequestId { get; } = new("RequestID", "reqId");

    /// <summary>The optional <c>POID</c> element, JSON <c>poId</c> — which a successful call returns whenever the service stores anything or supports the trace operation.</summary>
    public static PreservationName PreservationObjectId { get; } = new("POID", "poId");

    /// <summary>The repeatable <c>PO</c> element, JSON <c>po</c> — one per submitted object when the service stores nothing and produces the evidence synchronously.</summary>
    public static PreservationName PreservationObject { get; } = new("PO", "po");
}


/// <summary>
/// The names of the <c>RetrievePO</c> request (clause 5.3.4.1, Table 5 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
public static class RetrievePreservationObjectRequestParameterNames
{
    /// <summary>The inherited <c>OptionalInputs</c> element, JSON <c>optIn</c>.</summary>
    public static PreservationName OptionalInputs { get; } = new("OptionalInputs", "optIn");

    /// <summary>The inherited <c>RequestID</c> attribute, JSON <c>reqId</c>.</summary>
    public static PreservationName RequestId { get; } = new("RequestID", "reqId");

    /// <summary>The mandatory <c>POID</c> element, JSON <c>poId</c> — which preservation object is wanted.</summary>
    public static PreservationName PreservationObjectId { get; } = new("POID", "poId");

    /// <summary>
    /// The repeatable <c>VersionID</c> element, JSON <c>versionId</c> — <strong>not</strong> <c>verId</c>, which
    /// is what the same element name maps to on an evidence (Table 19).
    /// </summary>
    public static PreservationName VersionId { get; } = new("VersionID", "versionId");

    /// <summary>The optional <c>SubjectOfRetrieval</c> element, JSON <c>sor</c> — what is to be returned; omitting it means the object with its evidence embedded.</summary>
    public static PreservationName SubjectOfRetrieval { get; } = new("SubjectOfRetrieval", "sor");

    /// <summary>
    /// The optional <c>POFormat</c> element, JSON <c>poFormat</c>. The reproduced JSON schema fragment of clause
    /// 5.3.4.1.3 also shows an all-lower-case <c>poformat</c> property beside it; Table 5 states one member name
    /// and that is the one stated here.
    /// </summary>
    public static PreservationName PreservationObjectFormat { get; } = new("POFormat", "poFormat");

    /// <summary>The optional <c>EvidenceFormat</c> element, JSON <c>evFormat</c> — which evidence format is wanted back.</summary>
    public static PreservationName EvidenceFormat { get; } = new("EvidenceFormat", "evFormat");
}


/// <summary>
/// The names of the <c>RetrievePOResponse</c> (clause 5.3.4.2, Table 6 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
public static class RetrievePreservationObjectResponseParameterNames
{
    /// <summary>The inherited <c>OptionalOutputs</c> element, JSON <c>optOut</c>.</summary>
    public static PreservationName OptionalOutputs { get; } = new("OptionalOutputs", "optOut");

    /// <summary>The inherited <c>RequestID</c> attribute, JSON <c>reqId</c>.</summary>
    public static PreservationName RequestId { get; } = new("RequestID", "reqId");

    /// <summary>The repeatable <c>PO</c> element, JSON <c>po</c> — the objects and evidences the request asked for.</summary>
    public static PreservationName PreservationObject { get; } = new("PO", "po");
}


/// <summary>
/// The names of the <c>DeletePO</c> request (clause 5.3.5.1, Table 7 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
public static class DeletePreservationObjectRequestParameterNames
{
    /// <summary>The inherited <c>OptionalInputs</c> element, JSON <c>optIn</c>.</summary>
    public static PreservationName OptionalInputs { get; } = new("OptionalInputs", "optIn");

    /// <summary>The inherited <c>RequestID</c> attribute, JSON <c>reqId</c>.</summary>
    public static PreservationName RequestId { get; } = new("RequestID", "reqId");

    /// <summary>The mandatory <c>POID</c> element, JSON <c>poId</c> — which preservation object is to be deleted.</summary>
    public static PreservationName PreservationObjectId { get; } = new("POID", "poId");

    /// <summary>The optional <c>Mode</c> element, JSON <c>mod</c> — what is deleted; omitting it means the objects and the evidences over them.</summary>
    public static PreservationName Mode { get; } = new("Mode", "mod");

    /// <summary>The optional <c>ClaimedRequestorName</c> element, JSON <c>crn</c> — the pair no derivation rule reproduces.</summary>
    public static PreservationName ClaimedRequestorName { get; } = new("ClaimedRequestorName", "crn");

    /// <summary>The optional <c>Reason</c> element, JSON <c>reason</c> — free text.</summary>
    public static PreservationName Reason { get; } = new("Reason", "reason");
}


/// <summary>
/// The names of the <c>UpdatePOC</c> request (clause 5.3.6.1, Table 8 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
public static class UpdatePreservationObjectContainerRequestParameterNames
{
    /// <summary>The inherited <c>OptionalInputs</c> element, JSON <c>optIn</c>.</summary>
    public static PreservationName OptionalInputs { get; } = new("OptionalInputs", "optIn");

    /// <summary>The inherited <c>RequestID</c> attribute, JSON <c>reqId</c>.</summary>
    public static PreservationName RequestId { get; } = new("RequestID", "reqId");

    /// <summary>The mandatory <c>POID</c> element, JSON <c>poId</c> — which container is to be updated.</summary>
    public static PreservationName PreservationObjectId { get; } = new("POID", "poId");

    /// <summary>
    /// The repeatable, mandatory <c>DeltaPOC</c> element, JSON <c>deltaPoc</c> — which carries no type of its
    /// own: both syntaxes resolve it to the <c>PO</c> component, so a delta is a preservation object under
    /// another element name.
    /// </summary>
    public static PreservationName DeltaContainer { get; } = new("DeltaPOC", "deltaPoc");
}


/// <summary>
/// The names of the <c>UpdatePOCResponse</c> (clause 5.3.6.2, Table 9 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
public static class UpdatePreservationObjectContainerResponseParameterNames
{
    /// <summary>The inherited <c>OptionalOutputs</c> element, JSON <c>optOut</c>.</summary>
    public static PreservationName OptionalOutputs { get; } = new("OptionalOutputs", "optOut");

    /// <summary>The inherited <c>RequestID</c> attribute, JSON <c>reqId</c>.</summary>
    public static PreservationName RequestId { get; } = new("RequestID", "reqId");

    /// <summary>
    /// The optional <c>VersionID</c> element, JSON <c>versionId</c> — the version the update produced. Clause
    /// 5.3.6.2.1 recommends a sequential scheme such as <c>v1</c>, <c>v2</c>, <c>v3</c>, which is a
    /// recommendation and not a format a reader may assume.
    /// </summary>
    public static PreservationName VersionId { get; } = new("VersionID", "versionId");
}


/// <summary>
/// The names of the <c>RetrieveTrace</c> request (clause 5.3.7.1, Table 10 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
public static class RetrieveTraceRequestParameterNames
{
    /// <summary>The inherited <c>OptionalInputs</c> element, JSON <c>optIn</c>.</summary>
    public static PreservationName OptionalInputs { get; } = new("OptionalInputs", "optIn");

    /// <summary>The inherited <c>RequestID</c> attribute, JSON <c>reqId</c>.</summary>
    public static PreservationName RequestId { get; } = new("RequestID", "reqId");

    /// <summary>The mandatory <c>POID</c> element, JSON <c>poId</c> — which preservation object's audit trail is wanted.</summary>
    public static PreservationName PreservationObjectId { get; } = new("POID", "poId");
}


/// <summary>
/// The names of the <c>RetrieveTraceResponse</c> (clause 5.3.7.2, Table 11 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
public static class RetrieveTraceResponseParameterNames
{
    /// <summary>The inherited <c>OptionalOutputs</c> element, JSON <c>optOut</c>.</summary>
    public static PreservationName OptionalOutputs { get; } = new("OptionalOutputs", "optOut");

    /// <summary>The inherited <c>RequestID</c> attribute, JSON <c>reqId</c>.</summary>
    public static PreservationName RequestId { get; } = new("RequestID", "reqId");

    /// <summary>The mandatory <c>Trace</c> element, JSON <c>trace</c> — the sequence of events.</summary>
    public static PreservationName Trace { get; } = new("Trace", "trace");
}


/// <summary>
/// The names of the <c>ValidateEvidence</c> request (clause 5.3.8.1, Table 12 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
public static class ValidateEvidenceRequestParameterNames
{
    /// <summary>The inherited <c>OptionalInputs</c> element, JSON <c>optIn</c>.</summary>
    public static PreservationName OptionalInputs { get; } = new("OptionalInputs", "optIn");

    /// <summary>The inherited <c>RequestID</c> attribute, JSON <c>reqId</c>.</summary>
    public static PreservationName RequestId { get; } = new("RequestID", "reqId");

    /// <summary>The <c>Evidence</c> element, JSON <c>ev</c> — the evidence to be validated.</summary>
    public static PreservationName Evidence { get; } = new("Evidence", "ev");

    /// <summary>The repeatable <c>PO</c> element, JSON <c>po</c> — the objects the evidence protects, if the caller supplies them.</summary>
    public static PreservationName PreservationObject { get; } = new("PO", "po");
}


/// <summary>
/// The names of the <c>ValidateEvidenceResponse</c> (clause 5.3.8.2, Table 13 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
/// <remarks>
/// Clause 5.3.8.2 names its own XML type and JSON schema key after an operation called <c>ValidatePOC</c> —
/// <c>ValidatePOCResponseType</c> and <c>pres-ValidatePOCResponseType</c> — although every other clause calls
/// this operation <c>ValidateEvidence</c>, and the reproduced JSON fragment carries a further property
/// <c>pocreport</c> that the semantics prose never mentions. Both read as residue of an earlier name. The names
/// below are the two the table states; nothing is invented for the third.
/// </remarks>
public static class ValidateEvidenceResponseParameterNames
{
    /// <summary>The inherited <c>OptionalOutputs</c> element, JSON <c>optOut</c>.</summary>
    public static PreservationName OptionalOutputs { get; } = new("OptionalOutputs", "optOut");

    /// <summary>The inherited <c>RequestID</c> attribute, JSON <c>reqId</c>.</summary>
    public static PreservationName RequestId { get; } = new("RequestID", "reqId");

    /// <summary>The optional <c>ValidationReport</c> element, JSON <c>valRep</c> — carried as a preservation object, per clause 5.4.5.</summary>
    public static PreservationName ValidationReport { get; } = new("ValidationReport", "valRep");

    /// <summary>
    /// The optional <c>ProofOfExistence</c> element, JSON <c>poe</c> — a date and time in the XML binding and an
    /// integer of milliseconds since the epoch in the JSON one.
    /// </summary>
    public static PreservationName ProofOfExistence { get; } = new("ProofOfExistence", "poe");
}


/// <summary>
/// The names of the <c>Search</c> request (clause 5.3.9.1, Table 14 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
/// <remarks>
/// Table 14 lists only the operation's own element; the two inherited names are
/// <see cref="PreservationRequestParameterNames"/>'s.
/// </remarks>
public static class SearchRequestParameterNames
{
    /// <summary>
    /// The optional <c>Filter</c> element, JSON <c>fi</c> — a query string whose language the profile defines and
    /// this document does not, so it is opaque to the vocabulary.
    /// </summary>
    public static PreservationName Filter { get; } = new("Filter", "fi");
}


/// <summary>
/// The names of the <c>SearchResponse</c> (clause 5.3.9.2, Table 15 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>).
/// </summary>
public static class SearchResponseParameterNames
{
    /// <summary>The repeatable <c>POID</c> element, JSON <c>poId</c> — the identifiers matching the filter.</summary>
    public static PreservationName PreservationObjectId { get; } = new("POID", "poId");
}
