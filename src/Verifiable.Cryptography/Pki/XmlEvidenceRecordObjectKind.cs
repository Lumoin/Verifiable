namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Discriminates what a pooled carrier holding octets of an
/// <see href="https://www.rfc-editor.org/rfc/rfc6283">IETF RFC 6283</see> Evidence Record holds.
/// </summary>
/// <remarks>
/// <para>
/// Used as a <see cref="Tag"/> component so a block of Evidence Record octets can be routed and reported on
/// without re-parsing it, the same job <see cref="AsicObjectKind"/> does for container octets and
/// <see cref="PkiObjectKind"/> for DER objects. It is a separate enumeration for the same reason
/// <see cref="AsicObjectKind"/> is: an XML Evidence Record is neither a DER PKI object nor a container entry,
/// and widening either of those would make its own documentation false.
/// </para>
/// <para>
/// <see cref="None"/> occupies zero so a default-initialised tag component never reads as an Evidence Record.
/// </para>
/// </remarks>
public enum XmlEvidenceRecordObjectKind
{
    /// <summary>No Evidence Record object kind specified. The value of an unset component, by design.</summary>
    None = 0,

    /// <summary>The serialised octets of one whole <c>EvidenceRecord</c> document (clause 2.1).</summary>
    EvidenceRecord = 1,

    /// <summary>
    /// The canonical binary representation of one XML element, produced by the canonicalization seam — the
    /// "proper binary representation ... determined by UTF-8 encoding and canonicalization" of clause 4.1.2.
    /// This is the only form of an Evidence Record's own elements that is ever hashed.
    /// </summary>
    CanonicalizedElement = 2,

    /// <summary>
    /// The octets of one <c>CryptographicInformation</c> element's content (clause 3.1.3) — a certificate
    /// revocation list, an online certificate status response, a certificate validation response or a
    /// certificate, carried verbatim rather than interpreted.
    /// </summary>
    CryptographicInformation = 3,

    /// <summary>
    /// The serialised octets of one <c>Attribute</c> or <c>SupportingInformation</c> element (clause 2.1), whose
    /// content clause 8's schema types as lax-processed any content and which this library therefore carries
    /// verbatim rather than interpreting.
    /// </summary>
    OpaqueInformation = 4
}
