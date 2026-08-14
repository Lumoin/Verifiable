using System;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The object identifiers the Evidence Record Syntax of
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#appendix-B">IETF RFC 4998 Appendix B</see> defines, as
/// dotted-decimal strings, together with the recognition helpers a dispatch site uses instead of comparing
/// string literals at the call site.
/// </summary>
/// <remarks>
/// <para>
/// Appendix B is the authoritative module: clause 2.1 of RFC 4998 states "If there is a conflict between both
/// modules, the 1988-ASN.1 module precedes", and Appendix B is that module. The 1997-syntax module of
/// Appendix C declares the same two attribute identifiers with the same arcs, so nothing here depends on which
/// module a producer compiled against.
/// </para>
/// <para>
/// The two attribute identifiers are the placements
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#appendix-A">RFC 4998 Appendix A</see> defines for carrying
/// an <c>EvidenceRecord</c> inside a CMS object. Which of the appendix's two selection methods each identifier
/// names is never stated in the RFC's prose; the mapping this library applies is recorded on
/// <see cref="IsInternalEvidenceRecordAttribute"/> and
/// <see cref="IsExternalEvidenceRecordAttribute"/>.
/// </para>
/// </remarks>
public static class EvidenceRecordWellKnown
{
    /// <summary>
    /// The Long-Term Archive and Notary Services arc <c>1.3.6.1.5.5.11</c> that RFC 4998 Appendix B declares as
    /// <c>ltans</c> and roots its module identifiers under.
    /// </summary>
    public static string LtansArc { get; } = "1.3.6.1.5.5.11";

    /// <summary>
    /// The identifier of the 1988-syntax ASN.1 module of
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#appendix-B">RFC 4998 Appendix B</see>,
    /// <c>1.3.6.1.5.5.11.0.2.1</c> — the module this library encodes and decodes against.
    /// </summary>
    public static string EvidenceRecordSyntax1988Module { get; } = "1.3.6.1.5.5.11.0.2.1";

    /// <summary>
    /// The identifier of the 1997-syntax ASN.1 module of
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#appendix-C">RFC 4998 Appendix C</see>,
    /// <c>1.3.6.1.5.5.11.0.1.1</c>. Named for completeness; clause 2.1 makes the 1988 module precede it.
    /// </summary>
    public static string EvidenceRecordSyntax1997Module { get; } = "1.3.6.1.5.5.11.0.1.1";

    /// <summary>
    /// <c>id-aa-er-internal</c> (<c>1.2.840.113549.1.9.16.2.49</c>) — the unsigned attribute
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#appendix-A">RFC 4998 Appendix A</see> defines for an
    /// <c>EvidenceRecord</c> whose archived data object is the CMS object itself.
    /// </summary>
    public static string InternalEvidenceRecordAttributeOid { get; } = "1.2.840.113549.1.9.16.2.49";

    /// <summary>
    /// <c>id-aa-er-external</c> (<c>1.2.840.113549.1.9.16.2.50</c>) — the unsigned attribute
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#appendix-A">RFC 4998 Appendix A</see> defines for an
    /// <c>EvidenceRecord</c> whose archived data object group holds the CMS object and its detached content.
    /// </summary>
    public static string ExternalEvidenceRecordAttributeOid { get; } = "1.2.840.113549.1.9.16.2.50";


    /// <summary>
    /// Determines whether an attribute type names <c>id-aa-er-internal</c>: the attribute-covering selection
    /// method of Appendix A, where the archived data object is the CMS object with the Evidence Record attribute
    /// itself absent ("the hash value must be generated over the CMS object without the one EvidenceRecord").
    /// </summary>
    /// <param name="attributeType">The dotted-decimal <c>attrType</c> object identifier.</param>
    /// <returns><see langword="true"/> when the type is <see cref="InternalEvidenceRecordAttributeOid"/>.</returns>
    /// <remarks>
    /// <para>
    /// RFC 4998 Appendix A never states which of its two selection methods each identifier names. This library
    /// reads the pair structurally: the "internal" identifier is the one whose archived data object is the CMS
    /// object alone — Appendix A's first selection method, "a hash value of the CMS object MUST be located in
    /// the first list of hash values of Archive Timestamps" — which is the shape a CMS object carrying its own
    /// content takes, since there is nothing outside it to group with.
    /// </para>
    /// <para>
    /// <strong>The reading was checked against third-party CMS objects carrying these attributes.</strong> Every
    /// one whose signed content is encapsulated in the object carries this identifier and an Evidence Record
    /// whose first list of hash values names one data object; every one whose signed content is detached carries
    /// <see cref="ExternalEvidenceRecordAttributeOid"/> and an Evidence Record whose first list names two, one of
    /// them the hash of the detached content itself. The artifacts that break the pattern are the ones named for
    /// being wrong — one attaching the external identifier to an object with encapsulated content, one whose
    /// external-identifier record leaves the detached content's hash out of the group.
    /// </para>
    /// </remarks>
    public static bool IsInternalEvidenceRecordAttribute(string attributeType) =>
        string.Equals(attributeType, InternalEvidenceRecordAttributeOid, StringComparison.Ordinal);


    /// <summary>
    /// Determines whether an attribute type names <c>id-aa-er-external</c>: the second selection method of
    /// Appendix A, where "the hash value of the CMS Object as well as the hash value of the content have to be
    /// stored in the first list of hash values as a group of data objects" — the shape a CMS object with
    /// detached content takes, since the content it signs is a data object of its own.
    /// </summary>
    /// <param name="attributeType">The dotted-decimal <c>attrType</c> object identifier.</param>
    /// <returns><see langword="true"/> when the type is <see cref="ExternalEvidenceRecordAttributeOid"/>.</returns>
    /// <remarks>See <see cref="IsInternalEvidenceRecordAttribute"/> for how the mapping was arrived at and what it was checked against.</remarks>
    public static bool IsExternalEvidenceRecordAttribute(string attributeType) =>
        string.Equals(attributeType, ExternalEvidenceRecordAttributeOid, StringComparison.Ordinal);


    /// <summary>
    /// Determines whether an attribute type is either of the two Evidence Record placements of Appendix A.
    /// </summary>
    /// <param name="attributeType">The dotted-decimal <c>attrType</c> object identifier.</param>
    /// <returns><see langword="true"/> when the type names an Evidence Record attribute.</returns>
    public static bool IsEvidenceRecordAttribute(string attributeType) =>
        IsInternalEvidenceRecordAttribute(attributeType) || IsExternalEvidenceRecordAttribute(attributeType);
}
