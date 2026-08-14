using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// The XAdES namespace and version-less URI identifiers of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see> clauses 4.2, 4.4.2, 5.1.3, 5.2.7.1 and 5.2.9.1: exactly the identifiers this
/// leaf itself dispatches or classifies on, mirroring <see cref="XmlSignatureIdentifiers"/>'s posture for the
/// XMLDSIG core.
/// </summary>
/// <remarks>
/// <para>
/// Every identifier is given twice: as a <see cref="string"/>, for callers that carry identifiers as text,
/// and as a UTF-8 <see cref="ReadOnlySpan{T}"/> under the <c>Utf8</c> suffix, for allocation-free comparison
/// against the octets an <see cref="XmlNodeTable"/> attribute or element value already is. Comparison of
/// every identifier is exact-character: none of these values are ever routed through <see cref="System.Uri"/>,
/// which normalizes case, escaping and default ports and so could make two identifiers that name different
/// things compare equal.
/// </para>
/// <para>
/// The two namespace URIs (clause 4.2) are separate, first-class values, never conflated: <c>v1.3.2#</c>
/// holds most qualifying properties, <c>v1.4.1#</c> holds <c>SPDocSpecification</c>,
/// <c>SignaturePolicyStore</c>, <c>AnyValidationData</c>, <c>TimeStampValidationData</c>, the current
/// <c>ArchiveTimeStamp</c> form and every <c>V2</c>-suffixed obsoleting property clause 4.3.6 names — the
/// choice of namespace is part of a qualifying property's identity, never an interchangeable prefix.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "These are registered namespace/type/transform/encoding identifiers compared as strings or as UTF-8 octets, never dereferenced; nothing here fetches a URI. Clause 4.2 identifies a namespace by the URI string as written, and System.Uri normalizes case, escaping and default ports, which would make two identifiers that name different things compare equal.")]
public static class XAdESIdentifiers
{
    /// <summary>
    /// The XAdES v1.3.2 namespace, <c>http://uri.etsi.org/01903/v1.3.2#</c>, holding most qualifying
    /// properties (clause 4.2).
    /// </summary>
    public static string XAdESNamespaceV132 { get; } = "http://uri.etsi.org/01903/v1.3.2#";

    /// <summary><see cref="XAdESNamespaceV132"/> as UTF-8 octets.</summary>
    public static ReadOnlySpan<byte> XAdESNamespaceV132Utf8 => "http://uri.etsi.org/01903/v1.3.2#"u8;

    /// <summary>
    /// The XAdES v1.4.1 namespace, <c>http://uri.etsi.org/01903/v1.4.1#</c> (clause 4.2). Its schema imports
    /// <see cref="XAdESNamespaceV132"/> under the fixed prefix <c>xades</c> (clause 4.2's XA-4.2-3 preamble).
    /// </summary>
    public static string XAdESNamespaceV141 { get; } = "http://uri.etsi.org/01903/v1.4.1#";

    /// <summary><see cref="XAdESNamespaceV141"/> as UTF-8 octets.</summary>
    public static ReadOnlySpan<byte> XAdESNamespaceV141Utf8 => "http://uri.etsi.org/01903/v1.4.1#"u8;


    /// <summary>
    /// The <c>Type</c> attribute value the <c>ds:Reference</c> to a XAdES signature's <c>SignedProperties</c>
    /// element carries, <c>http://uri.etsi.org/01903#SignedProperties</c> (clause 4.4.2) — the discovery key
    /// for locating the signed qualifying properties of a XAdES signature conforming to this specification.
    /// The version-less <c>01903#</c> URI space is distinct from the versioned <c>01903/v1.3.2#</c>/
    /// <c>01903/v1.4.1#</c> namespaces above.
    /// </summary>
    public static string SignedPropertiesTypeUri { get; } = "http://uri.etsi.org/01903#SignedProperties";

    /// <summary><see cref="SignedPropertiesTypeUri"/> as UTF-8 octets.</summary>
    public static ReadOnlySpan<byte> SignedPropertiesTypeUriUtf8 => "http://uri.etsi.org/01903#SignedProperties"u8;

    /// <summary>
    /// The <c>Type</c> attribute value a countersignature's <c>ds:Reference</c> to the countersigned
    /// signature carries, <c>http://uri.etsi.org/01903#CountersignedSignature</c> (clause 5.2.7.1).
    /// </summary>
    public static string CountersignedSignatureTypeUri { get; } = "http://uri.etsi.org/01903#CountersignedSignature";

    /// <summary><see cref="CountersignedSignatureTypeUri"/> as UTF-8 octets.</summary>
    public static ReadOnlySpan<byte> CountersignedSignatureTypeUriUtf8 => "http://uri.etsi.org/01903#CountersignedSignature"u8;


    /// <summary>
    /// The <c>SPDocDigestAsInSpecification</c> transform algorithm identifier,
    /// <c>http://uri.etsi.org/01903/v1.3.2/SignaturePolicy/SPDocDigestAsInSpecification</c> (clause 5.2.9.1):
    /// indicates the hash value of a signature policy document was computed as specified in a named
    /// technical specification, rather than by canonicalizing then digesting XML.
    /// </summary>
    public static string SPDocDigestAsInSpecificationTransformUri { get; } = "http://uri.etsi.org/01903/v1.3.2/SignaturePolicy/SPDocDigestAsInSpecification";

    /// <summary><see cref="SPDocDigestAsInSpecificationTransformUri"/> as UTF-8 octets.</summary>
    public static ReadOnlySpan<byte> SPDocDigestAsInSpecificationTransformUriUtf8 => "http://uri.etsi.org/01903/v1.3.2/SignaturePolicy/SPDocDigestAsInSpecification"u8;


    /// <summary>
    /// The <c>EncapsulatedPKIDataType</c> <c>Encoding</c> attribute value denoting ASN.1 data encoded in DER,
    /// <c>http://uri.etsi.org/01903/v1.2.2#DER</c> (clause 5.1.3) — the encoding an
    /// <c>EncapsulatedPKIDataType</c>-typed element's content is in when the attribute is absent altogether.
    /// </summary>
    public static string DerEncodingUri { get; } = "http://uri.etsi.org/01903/v1.2.2#DER";

    /// <summary><see cref="DerEncodingUri"/> as UTF-8 octets.</summary>
    public static ReadOnlySpan<byte> DerEncodingUriUtf8 => "http://uri.etsi.org/01903/v1.2.2#DER"u8;

    /// <summary>
    /// The <c>EncapsulatedPKIDataType</c> <c>Encoding</c> attribute value denoting ASN.1 data encoded in BER,
    /// <c>http://uri.etsi.org/01903/v1.2.2#BER</c> (clause 5.1.3).
    /// </summary>
    public static string BerEncodingUri { get; } = "http://uri.etsi.org/01903/v1.2.2#BER";

    /// <summary><see cref="BerEncodingUri"/> as UTF-8 octets.</summary>
    public static ReadOnlySpan<byte> BerEncodingUriUtf8 => "http://uri.etsi.org/01903/v1.2.2#BER"u8;

    /// <summary>
    /// The <c>EncapsulatedPKIDataType</c> <c>Encoding</c> attribute value denoting ASN.1 data encoded in CER,
    /// <c>http://uri.etsi.org/01903/v1.2.2#CER</c> (clause 5.1.3).
    /// </summary>
    public static string CerEncodingUri { get; } = "http://uri.etsi.org/01903/v1.2.2#CER";

    /// <summary><see cref="CerEncodingUri"/> as UTF-8 octets.</summary>
    public static ReadOnlySpan<byte> CerEncodingUriUtf8 => "http://uri.etsi.org/01903/v1.2.2#CER"u8;

    /// <summary>
    /// The <c>EncapsulatedPKIDataType</c> <c>Encoding</c> attribute value denoting ASN.1 data encoded in PER,
    /// <c>http://uri.etsi.org/01903/v1.2.2#PER</c> (clause 5.1.3).
    /// </summary>
    public static string PerEncodingUri { get; } = "http://uri.etsi.org/01903/v1.2.2#PER";

    /// <summary><see cref="PerEncodingUri"/> as UTF-8 octets.</summary>
    public static ReadOnlySpan<byte> PerEncodingUriUtf8 => "http://uri.etsi.org/01903/v1.2.2#PER"u8;

    /// <summary>
    /// The <c>EncapsulatedPKIDataType</c> <c>Encoding</c> attribute value denoting ASN.1 data encoded in XER,
    /// <c>http://uri.etsi.org/01903/v1.2.2#XER</c> (clause 5.1.3).
    /// </summary>
    public static string XerEncodingUri { get; } = "http://uri.etsi.org/01903/v1.2.2#XER";

    /// <summary><see cref="XerEncodingUri"/> as UTF-8 octets.</summary>
    public static ReadOnlySpan<byte> XerEncodingUriUtf8 => "http://uri.etsi.org/01903/v1.2.2#XER"u8;
}
