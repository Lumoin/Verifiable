namespace Verifiable.Xml;

/// <summary>
/// The kind of a node in an <see cref="XmlNodeTable"/>, following the XPath data model that
/// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.1
/// canonicalization is defined over: a single root node whose children represent information outside the
/// document element, and element, text, comment and processing instruction nodes beneath it. Attributes
/// and namespace declarations are not children; they are associated with their element and read through
/// the per-element accessors of <see cref="XmlNodeTable"/>.
/// </summary>
public enum XmlNodeKind
{
    /// <summary>
    /// The root node, parent of the document element and of any comments and processing instructions
    /// outside it. Always at index zero.
    /// </summary>
    Root = 0,

    /// <summary>
    /// An element node.
    /// </summary>
    Element,

    /// <summary>
    /// A text node: one maximal run of character data with CDATA sections replaced by their content and
    /// character and entity references resolved, per
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.1,
    /// which requires all consecutive characters to be placed into a single text node.
    /// </summary>
    Text,

    /// <summary>
    /// A comment node.
    /// </summary>
    Comment,

    /// <summary>
    /// A processing instruction node.
    /// </summary>
    ProcessingInstruction
}
