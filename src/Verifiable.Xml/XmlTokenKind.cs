namespace Verifiable.Xml;

/// <summary>
/// The kind of markup or character data an <see cref="XmlToken"/> represents.
/// </summary>
/// <remarks>
/// The kinds follow the document grammar of
/// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">Extensible Markup Language (XML) 1.0 (Fifth
/// Edition)</see>: the XML declaration (section 2.8), start-tags, end-tags and empty-element tags with
/// their attributes (section 3.1), character data (section 2.4), CDATA sections (section 2.7), comments
/// (section 2.5), processing instructions (section 2.6) and the white space permitted outside the document
/// element by the <c>Misc</c> production (section 2.8). A start-tag is delivered as an
/// <see cref="ElementStart"/> token, zero or more <see cref="Attribute"/> tokens and exactly one closing
/// token that tells whether the tag was a start-tag (<see cref="ElementStartClose"/>) or an empty-element
/// tag (<see cref="ElementEmptyClose"/>).
/// </remarks>
public enum XmlTokenKind
{
    /// <summary>
    /// No token. The kind of a default-constructed <see cref="XmlToken"/>.
    /// </summary>
    None = 0,

    /// <summary>
    /// The XML declaration, production <c>XMLDecl</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.8.
    /// Occurs only at the very beginning of the document.
    /// </summary>
    XmlDeclaration,

    /// <summary>
    /// The opening of a start-tag or empty-element tag: the <c>&lt;</c> and the element's qualified name.
    /// The token's name carries the <c>QName</c>. Followed by <see cref="Attribute"/> tokens and one of
    /// <see cref="ElementStartClose"/> or <see cref="ElementEmptyClose"/>.
    /// </summary>
    ElementStart,

    /// <summary>
    /// One attribute specification inside a start-tag or empty-element tag, production <c>Attribute</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 3.1.
    /// The value is the raw literal between the quotes: references are not resolved and no normalization is
    /// applied at this layer.
    /// </summary>
    Attribute,

    /// <summary>
    /// The <c>&gt;</c> completing a start-tag: the element has content and a matching end-tag must follow.
    /// </summary>
    ElementStartClose,

    /// <summary>
    /// The <c>/&gt;</c> completing an empty-element tag, production <c>EmptyElemTag</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 3.1.
    /// </summary>
    ElementEmptyClose,

    /// <summary>
    /// An end-tag, production <c>ETag</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 3.1.
    /// The token's name carries the <c>QName</c>.
    /// </summary>
    ElementEnd,

    /// <summary>
    /// A run of character data inside the document element, production <c>CharData</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.4.
    /// The value is raw: character and entity references are not resolved and line ends are not normalized
    /// at this layer.
    /// </summary>
    Text,

    /// <summary>
    /// The character content of a CDATA section, production <c>CDSect</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.7,
    /// without the <c>&lt;![CDATA[</c> and <c>]]&gt;</c> delimiters.
    /// </summary>
    CDataSection,

    /// <summary>
    /// The content of a comment, production <c>Comment</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.5,
    /// without the <c>&lt;!--</c> and <c>--&gt;</c> delimiters.
    /// </summary>
    Comment,

    /// <summary>
    /// A processing instruction, production <c>PI</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.6.
    /// The token's name carries the target and its value the instruction content after the white space that
    /// separates it from the target.
    /// </summary>
    ProcessingInstruction,

    /// <summary>
    /// White space outside the document element, permitted by the <c>Misc</c> production of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.8.
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.1
    /// requires it to be discarded from the data model, which is why it is delivered as its own kind.
    /// </summary>
    WhitespaceOutsideRoot
}
