namespace Verifiable.Xml;

/// <summary>
/// The canonicalization algorithm applied to an XML node-set.
/// </summary>
/// <remarks>
/// <para>
/// The six members are the canonicalization forms
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see>
/// clause 6.3(d) requires a XAdES signature validator to support:
/// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see>,
/// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see> and
/// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization 1.0</see>,
/// each in its comment-omitting and comment-preserving form.
/// </para>
/// <para>
/// The algorithm identifier URIs are not restated in this leaf: recognition of the
/// <c>ds:CanonicalizationMethod</c> identifiers stays with the PKI layer's <c>XmlSignatureWellKnown</c>,
/// whose six recognized canonicalization identifiers map one-to-one onto these members.
/// </para>
/// </remarks>
public enum XmlCanonicalizationAlgorithm
{
    /// <summary>
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> omitting comments.
    /// </summary>
    CanonicalXml10,

    /// <summary>
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> preserving comments.
    /// </summary>
    CanonicalXml10WithComments,

    /// <summary>
    /// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see> omitting comments.
    /// </summary>
    CanonicalXml11,

    /// <summary>
    /// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see> preserving comments.
    /// </summary>
    CanonicalXml11WithComments,

    /// <summary>
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization 1.0</see>
    /// omitting comments.
    /// </summary>
    ExclusiveCanonicalXml10,

    /// <summary>
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization 1.0</see>
    /// preserving comments.
    /// </summary>
    ExclusiveCanonicalXml10WithComments
}
