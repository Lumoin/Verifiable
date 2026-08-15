using System;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The wire names of the XML Evidence Record Syntax of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283">IETF RFC 6283</see>: the namespace its schema declares,
/// every element and attribute name clause 8's schema states, and the two closed enumerations clause 3.1.2 and
/// clause 3.1.3 place on <c>TimeStampToken/@Type</c> and <c>CryptographicInformation/@Type</c>.
/// </summary>
/// <remarks>
/// <para>
/// The names live here rather than as constants inside a parser because the parser is a seam this library does
/// not ship: a caller writing a binding needs the same names the library's own conformance statements are
/// written against, and a name that exists twice is a name that can differ.
/// </para>
/// <para>
/// <strong>Comparison is ordinal.</strong> XML element and attribute names are case-sensitive by definition
/// (<see href="https://www.w3.org/TR/xml/#sec-common-syn">Extensible Markup Language clause 2.3</see>), and the
/// <c>Type</c> values of clauses 3.1.2 and 3.1.3 are <c>xs:NMTOKEN</c> values registered verbatim with IANA
/// under clause 10, so <c>"rfc3161"</c> is not <c>"RFC3161"</c>.
/// </para>
/// <para>
/// <strong>What is recognised and what is verified are different sets.</strong>
/// <see cref="Rfc3161TimeStampTokenType"/> names the only time-stamp format this library reads;
/// <see cref="XmlEntrustTimeStampTokenType"/> is named so a document using it is refused for its format rather
/// than for being unreadable, exactly as <see cref="XmlSignatureWellKnown.Sha1DigestUri"/> is named for the
/// digest it will not compute.
/// </para>
/// </remarks>
public static class XmlEvidenceRecordWellKnown
{
    /// <summary>
    /// The namespace clause 8's schema declares as its target, <c>urn:ietf:params:xml:ns:ers</c>. Its
    /// <c>elementFormDefault="qualified"</c> puts every element of an Evidence Record in it.
    /// </summary>
    public static string EvidenceRecordNamespace { get; } = "urn:ietf:params:xml:ns:ers";

    /// <summary>The root element's local name, <c>EvidenceRecord</c> (clause 2.1).</summary>
    public static string EvidenceRecordElementName { get; } = "EvidenceRecord";

    /// <summary>The <c>EncryptionInformation</c> element's local name (clause 5), optional and never produced here.</summary>
    public static string EncryptionInformationElementName { get; } = "EncryptionInformation";

    /// <summary>The <c>SupportingInformationList</c> element's local name (clause 2.1), optional.</summary>
    public static string SupportingInformationListElementName { get; } = "SupportingInformationList";

    /// <summary>The <c>SupportingInformation</c> element's local name (clause 2.1).</summary>
    public static string SupportingInformationElementName { get; } = "SupportingInformation";

    /// <summary>The <c>ArchiveTimeStampSequence</c> element's local name (clause 4.1), required.</summary>
    public static string ArchiveTimeStampSequenceElementName { get; } = "ArchiveTimeStampSequence";

    /// <summary>The <c>ArchiveTimeStampChain</c> element's local name (clause 4.1), one or more.</summary>
    public static string ArchiveTimeStampChainElementName { get; } = "ArchiveTimeStampChain";

    /// <summary>The <c>ArchiveTimeStamp</c> element's local name (clause 3.1), one or more per chain.</summary>
    public static string ArchiveTimeStampElementName { get; } = "ArchiveTimeStamp";

    /// <summary>The <c>DigestMethod</c> element's local name (clause 4.1.1), required per chain.</summary>
    public static string DigestMethodElementName { get; } = "DigestMethod";

    /// <summary>The <c>CanonicalizationMethod</c> element's local name (clause 4.1.2), required per chain.</summary>
    public static string CanonicalizationMethodElementName { get; } = "CanonicalizationMethod";

    /// <summary>The <c>HashTree</c> element's local name (clause 3.1.1), optional per Archive Time-Stamp.</summary>
    public static string HashTreeElementName { get; } = "HashTree";

    /// <summary>The <c>Sequence</c> element's local name (clause 3.1.1), one or more per hash tree.</summary>
    public static string SequenceElementName { get; } = "Sequence";

    /// <summary>The <c>DigestValue</c> element's local name (clause 3.1.1), one or more per sequence, base64 content.</summary>
    public static string DigestValueElementName { get; } = "DigestValue";

    /// <summary>The <c>TimeStamp</c> element's local name (clause 3.1.2), required per Archive Time-Stamp.</summary>
    public static string TimeStampElementName { get; } = "TimeStamp";

    /// <summary>The <c>TimeStampToken</c> element's local name (clause 3.1.2), required per time-stamp.</summary>
    public static string TimeStampTokenElementName { get; } = "TimeStampToken";

    /// <summary>The <c>CryptographicInformationList</c> element's local name (clause 3.1.3), optional.</summary>
    public static string CryptographicInformationListElementName { get; } = "CryptographicInformationList";

    /// <summary>The <c>CryptographicInformation</c> element's local name (clause 3.1.3).</summary>
    public static string CryptographicInformationElementName { get; } = "CryptographicInformation";

    /// <summary>The <c>Attributes</c> element's local name (clause 2.1), optional per Archive Time-Stamp.</summary>
    public static string AttributesElementName { get; } = "Attributes";

    /// <summary>The <c>Attribute</c> element's local name (clause 2.1).</summary>
    public static string AttributeElementName { get; } = "Attribute";

    /// <summary>
    /// The <c>Version</c> attribute's name, carried by the root element and required by clause 2.1. Clause 8's
    /// schema fixes it to <c>1.0</c>, so clause 6's major/minor comparison never applies to a schema-valid
    /// document; the value is nevertheless read and reported rather than assumed.
    /// </summary>
    public static string VersionAttributeName { get; } = "Version";

    /// <summary>The value clause 8's schema fixes <c>Version</c> to, <c>1.0</c>.</summary>
    public static string Version10 { get; } = "1.0";

    /// <summary>
    /// The <c>Order</c> attribute's name, required "in every case where sibling elements of the same name occur
    /// at the same level" (clause 2.1) and constrained by clause 8's <c>OrderType</c> to integers of at least 1.
    /// </summary>
    public static string OrderAttributeName { get; } = "Order";

    /// <summary>The <c>Type</c> attribute's name, carried by <c>TimeStampToken</c>, <c>CryptographicInformation</c>, <c>Attribute</c> and <c>SupportingInformation</c>.</summary>
    public static string TypeAttributeName { get; } = "Type";

    /// <summary>The <c>Algorithm</c> attribute's name, carried by <c>DigestMethod</c> and <c>CanonicalizationMethod</c>.</summary>
    public static string AlgorithmAttributeName { get; } = XmlSignatureWellKnown.AlgorithmAttributeName;

    /// <summary>
    /// The time-stamp format clause 3.1.2 names for a base64-encoded DER ASN.1 <c>TimeStampToken</c>,
    /// <c>RFC3161</c> — the very token the RFC 3161 acquisition surface of this library produces and verifies.
    /// </summary>
    public static string Rfc3161TimeStampTokenType { get; } = "RFC3161";

    /// <summary>
    /// The other time-stamp format clause 3.1.2 names, <c>XMLENTRUST</c> — an XML-signature-shaped token.
    /// Recognised so a document using it is refused for its format rather than for being unreadable; this
    /// library reads no XML time-stamp.
    /// </summary>
    public static string XmlEntrustTimeStampTokenType { get; } = "XMLENTRUST";

    /// <summary>The <c>CryptographicInformation</c> type clause 3.1.3 gives a DER X.509 <c>CertificateList</c>, <c>CRL</c>.</summary>
    public static string CertificateRevocationListInformationType { get; } = "CRL";

    /// <summary>The <c>CryptographicInformation</c> type clause 3.1.3 gives a DER <c>OCSPResponse</c>, <c>OCSP</c>.</summary>
    public static string OcspResponseInformationType { get; } = "OCSP";

    /// <summary>
    /// The <c>CryptographicInformation</c> type clause 3.1.3 gives a DER <c>CVResponse</c>, <c>SCVP</c>.
    /// Recognised as one of the four the registry of clause 10 admits; this library interprets no certificate
    /// validation response, so an entry of this type is carried and reported, never read.
    /// </summary>
    public static string CertificateValidationResponseInformationType { get; } = "SCVP";

    /// <summary>The <c>CryptographicInformation</c> type clause 3.1.3 gives a DER X.509 certificate, <c>CERT</c>.</summary>
    public static string CertificateInformationType { get; } = "CERT";


    /// <summary>Determines whether a <c>TimeStampToken/@Type</c> value names the RFC 3161 format.</summary>
    /// <param name="tokenType">The <c>Type</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="Rfc3161TimeStampTokenType"/>.</returns>
    public static bool IsRfc3161TimeStampTokenType(string? tokenType) =>
        string.Equals(tokenType, Rfc3161TimeStampTokenType, StringComparison.Ordinal);


    /// <summary>Determines whether a <c>TimeStampToken/@Type</c> value names the XML time-stamp format.</summary>
    /// <param name="tokenType">The <c>Type</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="XmlEntrustTimeStampTokenType"/>.</returns>
    public static bool IsXmlTimeStampTokenType(string? tokenType) =>
        string.Equals(tokenType, XmlEntrustTimeStampTokenType, StringComparison.Ordinal);


    /// <summary>
    /// Determines whether a <c>TimeStampToken/@Type</c> value names one of the two formats clause 3.1.2 admits.
    /// </summary>
    /// <param name="tokenType">The <c>Type</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is either registered format.</returns>
    /// <remarks>
    /// Clause 10 makes the set extensible only by IANA registration under a "Specification Required" policy, so
    /// a value outside it is not an unknown extension a validator may pass over — it is a document naming a
    /// format no specification defines.
    /// </remarks>
    public static bool IsRegisteredTimeStampTokenType(string? tokenType) =>
        IsRfc3161TimeStampTokenType(tokenType) || IsXmlTimeStampTokenType(tokenType);


    /// <summary>
    /// Determines whether a <c>CryptographicInformation/@Type</c> value is one of the four clause 3.1.3 admits.
    /// </summary>
    /// <param name="informationType">The <c>Type</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <c>CRL</c>, <c>OCSP</c>, <c>SCVP</c> or <c>CERT</c>.</returns>
    public static bool IsRegisteredCryptographicInformationType(string? informationType) =>
        string.Equals(informationType, CertificateRevocationListInformationType, StringComparison.Ordinal)
        || string.Equals(informationType, OcspResponseInformationType, StringComparison.Ordinal)
        || string.Equals(informationType, CertificateValidationResponseInformationType, StringComparison.Ordinal)
        || string.Equals(informationType, CertificateInformationType, StringComparison.Ordinal);
}
