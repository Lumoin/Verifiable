using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// The <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
/// Processing (Second Edition)</see> core namespace, the six canonicalization algorithm identifiers of
/// <see cref="XmlCanonicalizationAlgorithm"/>, and the transform identifiers the reference-processing chain
/// recognizes: exactly the identifiers this leaf itself dispatches or classifies on.
/// </summary>
/// <remarks>
/// <para>
/// Digest-method and signature-method identifiers are deliberately absent here: this leaf never dispatches
/// on them. Recognition of those stays one layer up, with
/// <c>Verifiable.Cryptography.Pki.XmlSignatureWellKnown</c>. That type's six canonicalization identifiers
/// and this type's <see cref="CanonicalXml10Uri"/> through <see cref="ExclusiveCanonicalXml10WithCommentsUri"/>
/// name the same six algorithms with the same literal text — a bijection test proves the restatement
/// byte-identical in both directions.
/// </para>
/// <para>
/// Every identifier is given twice: as a <see cref="string"/>, for callers that carry algorithm identifiers
/// as text, and as a UTF-8 <see cref="ReadOnlySpan{T}"/> under the <c>Utf8</c> suffix, for allocation-free
/// comparison against the octets an <see cref="XmlNodeTable"/> attribute value already is — this leaf's own
/// span-first idiom, the one <see cref="XmlCharacters"/> uses for the character-level vocabulary.
/// Comparison of every identifier is exact-character: <see href="https://www.w3.org/TR/xmldsig-core1/#sec-AlgID">
/// XML Signature clause 6.1</see> identifies an algorithm by the URI as written, and none of these values are
/// ever routed through <see cref="System.Uri"/>, which normalizes case, escaping and default ports and so
/// could make two identifiers that name different algorithms compare equal.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "These are registered algorithm identifiers compared as strings or as UTF-8 octets, never dereferenced; nothing here fetches a URI. XML Signature clause 6.1 identifies an algorithm by the URI string as written, and System.Uri normalizes case, escaping and default ports, which would make two identifiers that name different algorithms compare equal.")]
public static class XmlSignatureIdentifiers
{
    /// <summary>
    /// The XML Signature core namespace, <c>http://www.w3.org/2000/09/xmldsig#</c>
    /// (<see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> Appendix A).
    /// </summary>
    public static string XmlSignatureNamespace { get; } = "http://www.w3.org/2000/09/xmldsig#";

    /// <summary><see cref="XmlSignatureNamespace"/> as UTF-8 octets.</summary>
    public static ReadOnlySpan<byte> XmlSignatureNamespaceUtf8 => "http://www.w3.org/2000/09/xmldsig#"u8;


    /// <summary>
    /// <see cref="XmlCanonicalizationAlgorithm.CanonicalXml10"/>, <c>http://www.w3.org/TR/2001/REC-xml-c14n-20010315</c>
    /// (<see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see>).
    /// </summary>
    public static string CanonicalXml10Uri { get; } = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

    /// <summary><see cref="CanonicalXml10Uri"/> as UTF-8 octets.</summary>
    public static ReadOnlySpan<byte> CanonicalXml10UriUtf8 => "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"u8;

    /// <summary>
    /// <see cref="XmlCanonicalizationAlgorithm.CanonicalXml10WithComments"/>,
    /// <c>http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments</c>
    /// (<see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see>).
    /// </summary>
    public static string CanonicalXml10WithCommentsUri { get; } = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";

    /// <summary><see cref="CanonicalXml10WithCommentsUri"/> as UTF-8 octets.</summary>
    public static ReadOnlySpan<byte> CanonicalXml10WithCommentsUriUtf8 => "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"u8;

    /// <summary>
    /// <see cref="XmlCanonicalizationAlgorithm.CanonicalXml11"/>, <c>http://www.w3.org/2006/12/xml-c14n11</c>
    /// (<see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see>).
    /// </summary>
    public static string CanonicalXml11Uri { get; } = "http://www.w3.org/2006/12/xml-c14n11";

    /// <summary><see cref="CanonicalXml11Uri"/> as UTF-8 octets.</summary>
    public static ReadOnlySpan<byte> CanonicalXml11UriUtf8 => "http://www.w3.org/2006/12/xml-c14n11"u8;

    /// <summary>
    /// <see cref="XmlCanonicalizationAlgorithm.CanonicalXml11WithComments"/>,
    /// <c>http://www.w3.org/2006/12/xml-c14n11#WithComments</c>
    /// (<see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see>).
    /// </summary>
    public static string CanonicalXml11WithCommentsUri { get; } = "http://www.w3.org/2006/12/xml-c14n11#WithComments";

    /// <summary><see cref="CanonicalXml11WithCommentsUri"/> as UTF-8 octets.</summary>
    public static ReadOnlySpan<byte> CanonicalXml11WithCommentsUriUtf8 => "http://www.w3.org/2006/12/xml-c14n11#WithComments"u8;

    /// <summary>
    /// <see cref="XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10"/>, <c>http://www.w3.org/2001/10/xml-exc-c14n#</c>
    /// (<see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see>).
    /// </summary>
    public static string ExclusiveCanonicalXml10Uri { get; } = "http://www.w3.org/2001/10/xml-exc-c14n#";

    /// <summary><see cref="ExclusiveCanonicalXml10Uri"/> as UTF-8 octets.</summary>
    public static ReadOnlySpan<byte> ExclusiveCanonicalXml10UriUtf8 => "http://www.w3.org/2001/10/xml-exc-c14n#"u8;

    /// <summary>
    /// <see cref="XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10WithComments"/>,
    /// <c>http://www.w3.org/2001/10/xml-exc-c14n#WithComments</c>
    /// (<see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see>).
    /// </summary>
    public static string ExclusiveCanonicalXml10WithCommentsUri { get; } = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

    /// <summary><see cref="ExclusiveCanonicalXml10WithCommentsUri"/> as UTF-8 octets.</summary>
    public static ReadOnlySpan<byte> ExclusiveCanonicalXml10WithCommentsUriUtf8 => "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"u8;


    /// <summary>
    /// The enveloped-signature transform, <c>http://www.w3.org/2000/09/xmldsig#enveloped-signature</c>
    /// (<see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 6.6.4, "Required*" — required unless the application knows
    /// the signature is not enveloped).
    /// </summary>
    public static string EnvelopedSignatureTransformUri { get; } = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

    /// <summary><see cref="EnvelopedSignatureTransformUri"/> as UTF-8 octets.</summary>
    public static ReadOnlySpan<byte> EnvelopedSignatureTransformUriUtf8 => "http://www.w3.org/2000/09/xmldsig#enveloped-signature"u8;

    /// <summary>
    /// The base64 decoding transform, <c>http://www.w3.org/2000/09/xmldsig#base64</c>
    /// (<see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 6.6.2, "Required").
    /// </summary>
    public static string Base64TransformUri { get; } = "http://www.w3.org/2000/09/xmldsig#base64";

    /// <summary><see cref="Base64TransformUri"/> as UTF-8 octets.</summary>
    public static ReadOnlySpan<byte> Base64TransformUriUtf8 => "http://www.w3.org/2000/09/xmldsig#base64"u8;

    /// <summary>
    /// The XPath filtering transform, <c>http://www.w3.org/TR/1999/REC-xpath-19991116</c> — the identifier
    /// IS the <see href="https://www.w3.org/TR/1999/REC-xpath-19991116">XML Path Language (XPath) Version
    /// 1.0</see> namespace-free recommendation URI, per
    /// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 6.6.3 ("Recommended"). Recognized so a document naming it
    /// refuses for a named reason rather than for an unrecognized algorithm; this leaf does not execute it.
    /// </summary>
    public static string XPathTransformUri { get; } = "http://www.w3.org/TR/1999/REC-xpath-19991116";

    /// <summary><see cref="XPathTransformUri"/> as UTF-8 octets.</summary>
    public static ReadOnlySpan<byte> XPathTransformUriUtf8 => "http://www.w3.org/TR/1999/REC-xpath-19991116"u8;

    /// <summary>
    /// The XSLT transform, <c>http://www.w3.org/TR/1999/REC-xslt-19991116</c> — the identifier IS the
    /// XSL Transformations (XSLT) Version 1.0 recommendation URI, per
    /// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 6.6.5 ("Optional"). Recognized so a document naming it
    /// refuses for a named reason rather than for an unrecognized algorithm; this leaf does not execute it.
    /// </summary>
    public static string XsltTransformUri { get; } = "http://www.w3.org/TR/1999/REC-xslt-19991116";

    /// <summary><see cref="XsltTransformUri"/> as UTF-8 octets.</summary>
    public static ReadOnlySpan<byte> XsltTransformUriUtf8 => "http://www.w3.org/TR/1999/REC-xslt-19991116"u8;

    /// <summary>
    /// The XML-Signature XPath Filter 2.0 transform, <c>http://www.w3.org/2002/06/xmldsig-filter2</c>, which
    /// clause 6.3(g) of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> requires a XAdES signature validator to support. Recognized so a
    /// document naming it refuses for a named reason rather than for an unrecognized algorithm; this leaf
    /// does not execute it.
    /// </summary>
    public static string XPathFilter2TransformUri { get; } = "http://www.w3.org/2002/06/xmldsig-filter2";

    /// <summary><see cref="XPathFilter2TransformUri"/> as UTF-8 octets.</summary>
    public static ReadOnlySpan<byte> XPathFilter2TransformUriUtf8 => "http://www.w3.org/2002/06/xmldsig-filter2"u8;

    /// <summary>
    /// The OOXML package Relationships transform, <c>http://schemas.openxmlformats.org/package/2006/RelationshipTransform</c>
    /// (ECMA-376), which clause 6.3(g) of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> requires a XAdES signature validator to support. Recognized so a
    /// document naming it refuses for a named reason rather than for an unrecognized algorithm; this leaf
    /// does not execute it.
    /// </summary>
    public static string RelationshipTransformUri { get; } = "http://schemas.openxmlformats.org/package/2006/RelationshipTransform";

    /// <summary><see cref="RelationshipTransformUri"/> as UTF-8 octets.</summary>
    public static ReadOnlySpan<byte> RelationshipTransformUriUtf8 => "http://schemas.openxmlformats.org/package/2006/RelationshipTransform"u8;
}
