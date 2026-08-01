using System;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The format identifiers Annex A of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> registers — the submission data object formats of clause A.1, the preservation
/// evidence formats of clause A.2 and the preservation object container format of clause A.3.1 — together with
/// the recognition helpers a <c>FormatId</c>, <c>POFormat</c> or <c>EvidenceFormat</c> value is judged by.
/// </summary>
/// <remarks>
/// <para>
/// <strong>What each identifier names in this library.</strong> Four of the six evidence formats name machinery
/// this library already ships — the time-stamp token, the evidence record and its two renewal procedures, the
/// XML-syntax evidence record on the validation side, and the archive time-stamp attribute of a CAdES signature.
/// The remaining two name signature formats no module of this repository implements; they are stated all the
/// same, because a client has to recognise what a service announces even when it cannot process it, and a
/// vocabulary that omitted them would silently turn "I cannot handle this" into "I do not know what this is".
/// </para>
/// <para>
/// <strong>One identifier of clause A.1 is deliberately absent.</strong> Clause A.1.5 registers an XML-based
/// archival package format defined by a national technical guideline outside this specification's own series,
/// and its own clause A.3.2 makes it a second container format. That format is out of this wave's scope: no
/// object model for it exists here, its defining text is not among this repository's normative sources, and
/// stating an identifier for a format nothing can read would announce a capability that does not exist.
/// </para>
/// <para>
/// <strong>Comparison is ordinal and case-sensitive</strong>, as for every other wire value of this protocol.
/// Two identifiers below differ only in their last segment's case-sensitive suffix
/// (<see cref="ExtendedContainerFormat"/> and <see cref="EvidenceRecordContainerFormat"/>), so a case-folding
/// comparison would read a preservation object container as a plain one.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "A format identifier is compared and written as an exact character sequence; System.Uri normalises case and escaping, which would make two identifiers naming different formats compare equal. Nothing here is dereferenced.")]
[SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
    Justification = "The recognition helpers compare an identifier read off the wire against an exact character sequence, for the reason given on the properties.")]
public static class PreservationFormatWellKnown
{
    /// <summary>
    /// The submission format identifier of a CAdES digital signature, <c>http://uri.etsi.org/ades/CAdES</c>
    /// (clause A.1.1) — the Signed Data Object this library creates, augments and verifies.
    /// </summary>
    public static string CadesSignatureFormat { get; } = "http://uri.etsi.org/ades/CAdES";

    /// <summary>
    /// The submission format identifier of a XAdES digital signature, <c>http://uri.etsi.org/ades/XAdES</c>
    /// (clause A.1.2). Stated for recognition; this repository implements no XML-signature module.
    /// </summary>
    public static string XadesSignatureFormat { get; } = "http://uri.etsi.org/ades/XAdES";

    /// <summary>
    /// The submission format identifier of a PAdES digital signature, <c>http://uri.etsi.org/ades/PAdES</c>
    /// (clause A.1.3). Stated for recognition; this repository implements no document-format module.
    /// </summary>
    public static string PadesSignatureFormat { get; } = "http://uri.etsi.org/ades/PAdES";

    /// <summary>
    /// The submission format identifier of an extended Associated Signature Container,
    /// <c>http://uri.etsi.org/ades/ASiC/type/ASiC-E</c> (clause A.1.4) — the container this library authors,
    /// reads, validates and augments.
    /// </summary>
    public static string ExtendedContainerFormat { get; } = "http://uri.etsi.org/ades/ASiC/type/ASiC-E";

    /// <summary>
    /// The submission format identifier of the hash-only submission payload,
    /// <c>http://uri.etsi.org/19512/format/DigestList</c> (clause A.1.6), which a preservation object states in
    /// its <c>FormatId</c> when it carries digest values instead of the data objects themselves.
    /// </summary>
    /// <remarks>
    /// The payload's own shape is the <c>DigestList</c> component of clause 5.6.1. The identifier is stated here
    /// because it is a format identifier like the others; the component is modelled beside the container profile
    /// it belongs to.
    /// </remarks>
    public static string DigestListFormat { get; } = "http://uri.etsi.org/19512/format/DigestList";

    /// <summary>
    /// The container format identifier of an extended Associated Signature Container carrying evidence record
    /// manifests, <c>http://uri.etsi.org/ades/ASiC/type/ASiC-ERS</c> (clause A.3.1.1) — the preservation-specific
    /// profile of <see cref="ExtendedContainerFormat"/> whose structural element this library already ships.
    /// </summary>
    public static string EvidenceRecordContainerFormat { get; } = "http://uri.etsi.org/ades/ASiC/type/ASiC-ERS";


    /// <summary>
    /// The evidence format identifier of a time-stamp token, <c>urn:ietf:rfc:3161:TimeStampToken</c> (clause
    /// A.2.1) — the token this library requests, reads and verifies.
    /// </summary>
    public static string TimeStampTokenEvidenceFormat { get; } = "urn:ietf:rfc:3161:TimeStampToken";

    /// <summary>
    /// The evidence format identifier of an evidence record, <c>urn:ietf:rfc:4998:EvidenceRecord</c> (clause
    /// A.2.2) — the record this library creates, verifies and renews by both procedures.
    /// </summary>
    public static string EvidenceRecordEvidenceFormat { get; } = "urn:ietf:rfc:4998:EvidenceRecord";

    /// <summary>
    /// The evidence format identifier of an XML-syntax evidence record,
    /// <c>urn:ietf:rfc:6283:EvidenceRecord</c> (clause A.2.3) — verified through the parse and canonicalisation
    /// seams and created through <see cref="XmlEvidenceRecords.CreateInitialAsync"/> with the write seam.
    /// </summary>
    public static string XmlEvidenceRecordEvidenceFormat { get; } = "urn:ietf:rfc:6283:EvidenceRecord";

    /// <summary>
    /// The evidence format identifier of a CAdES archive time-stamp,
    /// <c>http://uri.etsi.org/ades/CAdES/archive-time-stamp-v3</c> (clause A.2.4) — the unsigned attribute this
    /// library builds, attaches and verifies.
    /// </summary>
    public static string CadesArchiveTimeStampEvidenceFormat { get; } = "http://uri.etsi.org/ades/CAdES/archive-time-stamp-v3";

    /// <summary>
    /// The evidence format identifier of a XAdES archive time-stamp,
    /// <c>http://uri.etsi.org/ades/XAdES/ArchiveTimeStamp</c> (clause A.2.5). Stated for recognition; this
    /// repository implements no XML-signature module.
    /// </summary>
    public static string XadesArchiveTimeStampEvidenceFormat { get; } = "http://uri.etsi.org/ades/XAdES/ArchiveTimeStamp";

    /// <summary>
    /// The evidence format identifier of a PAdES document time-stamp,
    /// <c>http://uri.etsi.org/ades/PAdES/document-time-stamp</c> (clause A.2.6). Stated for recognition; this
    /// repository implements no document-format module.
    /// </summary>
    public static string PadesDocumentTimeStampEvidenceFormat { get; } = "http://uri.etsi.org/ades/PAdES/document-time-stamp";


    /// <summary>Determines whether a value is one of the six preservation evidence formats of clause A.2.</summary>
    /// <param name="formatIdentifier">The <c>EvidenceFormat</c> or <c>FormatId</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value names an evidence format the annex registers.</returns>
    public static bool IsEvidenceFormat(string? formatIdentifier) =>
        IsOneOf(
            formatIdentifier,
            TimeStampTokenEvidenceFormat,
            EvidenceRecordEvidenceFormat,
            XmlEvidenceRecordEvidenceFormat,
            CadesArchiveTimeStampEvidenceFormat,
            XadesArchiveTimeStampEvidenceFormat,
            PadesDocumentTimeStampEvidenceFormat);


    /// <summary>
    /// Determines whether a value is one of the submission data object formats of clause A.1 this class states.
    /// </summary>
    /// <param name="formatIdentifier">The <c>FormatId</c> or <c>POFormat</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value names a submission format stated here.</returns>
    /// <remarks>
    /// The archival package format of clause A.1.5 is out of scope and therefore not stated, so a value naming it
    /// answers <see langword="false"/> — "not a format this library states" rather than "not a format the
    /// specification registers". The distinction is documented at the class.
    /// </remarks>
    public static bool IsSubmissionFormat(string? formatIdentifier) =>
        IsOneOf(
            formatIdentifier,
            CadesSignatureFormat,
            XadesSignatureFormat,
            PadesSignatureFormat,
            ExtendedContainerFormat,
            DigestListFormat);


    /// <summary>Determines whether a value names the preservation object container format of clause A.3.1.</summary>
    /// <param name="formatIdentifier">The <c>FormatId</c> or <c>POFormat</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is exactly <see cref="EvidenceRecordContainerFormat"/>.</returns>
    public static bool IsContainerFormat(string? formatIdentifier) =>
        string.Equals(formatIdentifier, EvidenceRecordContainerFormat, StringComparison.Ordinal);


    /// <summary>Compares a value against a set of exact character sequences.</summary>
    /// <param name="value">The value read off the wire, or <see langword="null"/>.</param>
    /// <param name="candidates">The identifiers the annex registers.</param>
    /// <returns><see langword="true"/> when the value is ordinally equal to one of the candidates.</returns>
    private static bool IsOneOf(string? value, params string[] candidates)
    {
        if(value is null)
        {
            return false;
        }

        foreach(string candidate in candidates)
        {
            if(string.Equals(value, candidate, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
