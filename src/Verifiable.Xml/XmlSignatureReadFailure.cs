namespace Verifiable.Xml;

/// <summary>
/// The reason a <c>ds:Signature</c> structural read was refused, per the <c>ds</c>-namespace element and
/// attribute grammar of <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature
/// Syntax and Processing (Second Edition)</see> sections 4 and 5.
/// </summary>
/// <remarks>
/// Reading is result-shaped: a structural refusal is reported as an <see cref="XmlSignatureReadError"/>
/// carrying one of these reasons and the byte offset at which it was determined, never as an exception.
/// This validator reads fail-closed: the "laxly schema valid" generation-side allowance of section 4.1 is a
/// generator's obligation, not a reading tolerance. Every member is produced by the structural model reader
/// of the XAdES XMLDSIG core arc except <see cref="InvalidBase64Content"/>, which the base64
/// content decoder every base64-typed element field shares already produces.
/// </remarks>
public enum XmlSignatureReadFailure
{
    /// <summary>
    /// The mandatory <c>SignedInfo</c> child of <c>Signature</c> is absent. The section 4.1 schema declares
    /// <c>SignedInfo</c> first among <c>SignedInfo, SignatureValue, KeyInfo?, Object*</c> and required.
    /// </summary>
    MissingSignedInfo,

    /// <summary>
    /// A core element's children appear in an order the section 4 or 5 schema does not declare for it, such
    /// as a <c>SignatureValue</c> preceding <c>SignedInfo</c>.
    /// </summary>
    InvalidChildOrder,

    /// <summary>
    /// A core element carries more occurrences of a <c>ds</c>-namespace child than its content model
    /// permits, such as a second <c>SignedInfo</c> under one <c>Signature</c>.
    /// </summary>
    DuplicateCoreChild,

    /// <summary>
    /// A <c>ds</c>-namespace element name appears at a position the section 4 or 5 schema does not declare
    /// it for.
    /// </summary>
    UnknownCoreElement,

    /// <summary>
    /// An attribute in no namespace or the <c>ds</c> namespace appears on a core element whose content
    /// model does not declare it, outside the schema's <c>##other</c> extension points.
    /// </summary>
    UnknownCoreAttribute,

    /// <summary>
    /// Element content typed <c>base64Binary</c> or <c>ds:CryptoBinary</c> — <c>DigestValue</c>,
    /// <c>SignatureValue</c>, <c>X509Certificate</c>, <c>SPKISexp</c> and every <c>ds:CryptoBinary</c>
    /// key-material field — does not match the lexical space
    /// <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#base64Binary">XML Schema Part 2:
    /// Datatypes</see> section 3.2.16 defines for <c>base64Binary</c>: once XML white space is stripped,
    /// the remaining characters are not all drawn from the 64-character base64 alphabet, their count is not
    /// a multiple of four, or the trailing padding does not match the <c>Base64Binary</c> production's
    /// quantum rule.
    /// </summary>
    InvalidBase64Content,

    /// <summary>
    /// An <c>HMACOutputLength</c> element's content is not the non-negative integer the section 6.3.1
    /// schema (a restriction of <c>xsd:integer</c>) requires. Parsed structurally only — the truncation
    /// attack the value parameterizes is recorded, never acted on, because MAC verification is out of
    /// scope here.
    /// </summary>
    InvalidHmacOutputLength,

    /// <summary>
    /// A mandatory child element the section 4 or 5 schema declares with a minimum occurrence of one is
    /// absent where a differently-named or absent sibling already ruled out
    /// <see cref="InvalidChildOrder"/> and <see cref="DuplicateCoreChild"/> — for example
    /// <c>SignedInfo</c>'s first <c>Reference</c>, <c>DSAKeyValue</c>'s <c>Y</c>, or <c>Manifest</c>'s
    /// first <c>Reference</c>.
    /// </summary>
    MissingRequiredChild,

    /// <summary>
    /// A core element's mandatory attribute — such as <c>CanonicalizationMethod</c>, <c>SignatureMethod</c>,
    /// <c>DigestMethod</c> or <c>Transform</c>'s <c>Algorithm</c> — is absent. The section 4/5 DTD and
    /// schema declare these <c>#REQUIRED</c>/<c>use="required"</c>; per the terminology framing of section
    /// 1.1, that cardinality is XML-grammar syntax rather than an RFC 2119 keyword, but this reader still
    /// refuses its absence structurally.
    /// </summary>
    MissingRequiredAttribute,

    /// <summary>
    /// An element's actual content does not match the shape its own content model declares: a
    /// simple-content element (declared <c>string</c> or <c>base64Binary</c> content, such as
    /// <c>DigestValue</c> or <c>KeyName</c>) contains an element child, or a comment or processing
    /// instruction splits its character data into more than one text node; or an element-only content
    /// model (such as <c>KeyInfo</c> or <c>X509Data</c>) contains non-whitespace character data between
    /// its element children. Whitespace-only text between element children is never this failure — the
    /// section 7.1 "laxly schema valid" allowance means every fixture the reader accepts may be
    /// pretty-printed.
    /// </summary>
    UnexpectedElementContent
}
