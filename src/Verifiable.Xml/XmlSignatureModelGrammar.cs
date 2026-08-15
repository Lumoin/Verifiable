using System.Collections.Generic;
using System.Runtime.CompilerServices;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// What <see cref="XmlSignatureModelGrammar.TryFindFirstElementChild"/> and
/// <see cref="XmlSignatureModelGrammar.TryFindNextElementSibling"/> found while skipping the insignificant
/// whitespace text, comment and processing-instruction nodes an element-only content model of
/// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
/// (Second Edition)</see> sections 4 and 5 permits between its element children.
/// </summary>
internal enum ElementScanResult
{
    /// <summary>An element node was found.</summary>
    Found,

    /// <summary>No further nodes remain; every remaining sibling, if any, was insignificant whitespace, a comment or a processing instruction.</summary>
    EndOfChildren,

    /// <summary>A text node carrying non-whitespace character data was found where only elements are permitted.</summary>
    UnexpectedContent
}


/// <summary>
/// The core-grammar reading primitives every <c>ds</c>-namespace element reader of the XAdES
/// structural model (<see cref="XmlSignature"/> and its constituent types) shares: exact-name element
/// recognition, unprefixed-attribute lookup, the "at most the known attributes" cardinality check, the
/// simple-content single-text-node rule, and skip-whitespace element-child navigation — one place these
/// rules live so every reader applies them identically.
/// </summary>
/// <remarks>
/// Every navigation helper here tolerates the insignificant whitespace text nodes, comments and processing
/// instructions a pretty-printed, "laxly schema valid" (section 4.1) document carries between element
/// children — real XML Signature documents, including this specification's own section 2.1–2.3 examples,
/// are indented. Only <em>non-whitespace</em> character data between element children, or non-text content
/// where a simple-content element declares only text, is a structural refusal
/// (<see cref="XmlSignatureReadFailure.UnexpectedElementContent"/>).
/// </remarks>
internal static class XmlSignatureModelGrammar
{
    /// <summary>
    /// Tells whether an element carries the <c>ds</c> namespace of
    /// <see cref="XmlSignatureIdentifiers.XmlSignatureNamespace"/> and the given local name.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The element to test.</param>
    /// <param name="localName">The expected local name.</param>
    /// <returns><see langword="true"/> when both the namespace and the local name match.</returns>
    public static bool IsDsElement(XmlNodeTable table, int elementIndex, ReadOnlySpan<byte> localName)
    {
        return table.NamespaceUriOf(elementIndex).SequenceEqual(XmlSignatureIdentifiers.XmlSignatureNamespaceUtf8)
            && table.LocalNameOf(elementIndex).SequenceEqual(localName);
    }


    /// <summary>
    /// Tells whether an element carries the given namespace and local name.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The element to test.</param>
    /// <param name="namespaceUri">The expected namespace URI.</param>
    /// <param name="localName">The expected local name.</param>
    /// <returns><see langword="true"/> when both the namespace and the local name match.</returns>
    public static bool IsElement(XmlNodeTable table, int elementIndex, ReadOnlySpan<byte> namespaceUri, ReadOnlySpan<byte> localName)
    {
        return table.NamespaceUriOf(elementIndex).SequenceEqual(namespaceUri) && table.LocalNameOf(elementIndex).SequenceEqual(localName);
    }


    /// <summary>
    /// Finds the ordinal of an un-prefixed attribute by exact local name — every attribute the section 4/5
    /// schema declares on a core element (<c>Id</c>, <c>URI</c>, <c>Type</c>, <c>Algorithm</c>,
    /// <c>MimeType</c>, <c>Encoding</c>, <c>Target</c>, <c>PrefixList</c>) is un-prefixed.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The element to search.</param>
    /// <param name="localName">The attribute's local name.</param>
    /// <param name="ordinal">The found ordinal, or -1.</param>
    /// <returns><see langword="true"/> when the attribute is present.</returns>
    public static bool TryFindAttribute(XmlNodeTable table, int elementIndex, ReadOnlySpan<byte> localName, out int ordinal)
    {
        int count = table.AttributeCountOf(elementIndex);
        for(int i = 0; i < count; ++i)
        {
            if(table.AttributePrefixOf(elementIndex, i).IsEmpty && table.AttributeLocalNameOf(elementIndex, i).SequenceEqual(localName))
            {
                ordinal = i;

                return true;
            }
        }

        ordinal = -1;

        return false;
    }


    /// <summary>
    /// Refuses an element that carries an un-prefixed attribute beyond the ones this reader already
    /// recognized for it. Prefixed attributes — whether in the <c>xml</c> namespace such as <c>xml:id</c>
    /// or in a foreign namespace — are always tolerated, since the section 4/5 schema declares no core
    /// attribute with a prefix and a foreign-namespace attribute is not a <c>ds</c>-namespace attribute
    /// this reader requires refusing.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The element to validate.</param>
    /// <param name="knownUnprefixedCount">
    /// How many of the element's un-prefixed attributes this reader already looked up and recognized —
    /// duplicate attribute names cannot occur in a parsed <see cref="XmlNodeTable"/>, so a count above this
    /// number can only be an attribute this reader never looked for.
    /// </param>
    /// <param name="error">The refusal when an unrecognized un-prefixed attribute is present.</param>
    /// <returns><see langword="true"/> when no unrecognized un-prefixed attribute is present.</returns>
    public static bool TryValidateAttributeCount(XmlNodeTable table, int elementIndex, int knownUnprefixedCount, out XmlSignatureReadError error)
    {
        int unprefixedCount = 0;
        int count = table.AttributeCountOf(elementIndex);
        for(int i = 0; i < count; ++i)
        {
            if(table.AttributePrefixOf(elementIndex, i).IsEmpty)
            {
                ++unprefixedCount;
            }
        }

        if(unprefixedCount > knownUnprefixedCount)
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.UnknownCoreAttribute, 0);

            return false;
        }

        error = default;

        return true;
    }


    /// <summary>
    /// Tells whether every octet of a value is XML white space per production <c>S</c>.
    /// </summary>
    /// <param name="value">The value to test.</param>
    /// <returns><see langword="true"/> when the value is empty or entirely white space.</returns>
    public static bool IsAllWhitespace(ReadOnlySpan<byte> value)
    {
        foreach(byte octet in value)
        {
            if(!XmlCharacters.IsWhitespace(octet))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Finds the first element child of a node, skipping leading insignificant whitespace text, comments
    /// and processing instructions.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="parentIndex">The parent node.</param>
    /// <param name="elementIndex">The found element index on <see cref="ElementScanResult.Found"/>; -1 otherwise.</param>
    /// <returns>What the scan found.</returns>
    public static ElementScanResult TryFindFirstElementChild(XmlNodeTable table, int parentIndex, out int elementIndex)
    {
        int child = table.FirstChildOf(parentIndex);
        if(child < 0)
        {
            elementIndex = -1;

            return ElementScanResult.EndOfChildren;
        }

        return ClassifyFromNode(table, child, out elementIndex);
    }


    /// <summary>
    /// Finds the next element sibling after a node, skipping insignificant whitespace text, comments and
    /// processing instructions.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="nodeIndex">The node to search onward from.</param>
    /// <param name="elementIndex">The found element index on <see cref="ElementScanResult.Found"/>; -1 otherwise.</param>
    /// <returns>What the scan found.</returns>
    public static ElementScanResult TryFindNextElementSibling(XmlNodeTable table, int nodeIndex, out int elementIndex)
    {
        int sibling = table.NextSiblingOf(nodeIndex);
        if(sibling < 0)
        {
            elementIndex = -1;

            return ElementScanResult.EndOfChildren;
        }

        return ClassifyFromNode(table, sibling, out elementIndex);
    }


    /// <summary>
    /// Classifies a node and every following sibling until an element is found or the siblings are
    /// exhausted.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="startIndex">The node to start classifying from.</param>
    /// <param name="elementIndex">The found element index on <see cref="ElementScanResult.Found"/>; -1 otherwise.</param>
    /// <returns>What the scan found.</returns>
    private static ElementScanResult ClassifyFromNode(XmlNodeTable table, int startIndex, out int elementIndex)
    {
        for(int current = startIndex; current >= 0; current = table.NextSiblingOf(current))
        {
            XmlNodeKind kind = table.KindOf(current);
            if(kind == XmlNodeKind.Element)
            {
                elementIndex = current;

                return ElementScanResult.Found;
            }

            if(kind == XmlNodeKind.Text && !IsAllWhitespace(table.ValueOf(current)))
            {
                elementIndex = -1;

                return ElementScanResult.UnexpectedContent;
            }
        }

        elementIndex = -1;

        return ElementScanResult.EndOfChildren;
    }


    /// <summary>
    /// Gathers every element child of a node in document order, refusing non-whitespace character data
    /// between them — the element-only content model shared by <c>KeyInfo</c>, <c>X509Data</c>,
    /// <c>Manifest</c> and <c>SignatureProperties</c>.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="parentIndex">The parent element.</param>
    /// <param name="children">The element children found, in document order.</param>
    /// <param name="error">The refusal when non-whitespace text is found between elements.</param>
    /// <returns><see langword="true"/> when every non-element child was insignificant.</returns>
    public static bool TryReadElementChildren(XmlNodeTable table, int parentIndex, out List<int> children, out XmlSignatureReadError error)
    {
        children = [];
        for(int child = table.FirstChildOf(parentIndex); child >= 0; child = table.NextSiblingOf(child))
        {
            XmlNodeKind kind = table.KindOf(child);
            if(kind == XmlNodeKind.Element)
            {
                children.Add(child);

                continue;
            }

            if(kind == XmlNodeKind.Text && !IsAllWhitespace(table.ValueOf(child)))
            {
                error = new XmlSignatureReadError(XmlSignatureReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        error = default;

        return true;
    }


    /// <summary>
    /// Gathers every element child of a node in document order without validating what lies between them —
    /// for the mixed-content extensibility points of <c>CanonicalizationMethod</c>, <c>SignatureMethod</c>
    /// and <c>DigestMethod</c>, whose content models are <c>##any</c>/<c>##other</c> and mixed by design.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="parentIndex">The parent element.</param>
    /// <returns>The element children found, in document order.</returns>
    public static List<int> GatherElementChildrenLoosely(XmlNodeTable table, int parentIndex)
    {
        var children = new List<int>();
        for(int child = table.FirstChildOf(parentIndex); child >= 0; child = table.NextSiblingOf(child))
        {
            if(table.KindOf(child) == XmlNodeKind.Element)
            {
                children.Add(child);
            }
        }

        return children;
    }


    /// <summary>
    /// Finds the single coalesced text node of a simple-content element, per the <c>base64Binary</c>/
    /// <c>string</c> simple content every <c>DigestValue</c>-, <c>KeyName</c>-, <c>MgmtData</c>-shaped
    /// element declares: zero children is empty content, exactly one <see cref="XmlNodeKind.Text"/> child
    /// with no further siblings is its text, anything else — an element child, or a comment or processing
    /// instruction splitting the text into more than one node — refuses.
    /// </summary>
    /// <remarks>
    /// RECORDED DEVIATION: XSD's Element Locally Valid (Type) rule permits comment and
    /// processing-instruction information items among a simple-typed element's children without them
    /// affecting the element's simple-content value — a document such as
    /// <c>&lt;DigestValue&gt;QQ&lt;!--x--&gt;==&lt;/DigestValue&gt;</c> is schema-valid with value
    /// <c>QQ==</c>. This reader refuses it (<see cref="XmlSignatureReadFailure.UnexpectedElementContent"/>)
    /// rather than skip the comment/PI and coalesce the surrounding text. Grounds: a comment or processing
    /// instruction splitting base64/CryptoBinary content is exactly the shape comment-smuggling and
    /// parser-differential attacks use to hide bytes a lax reader would drop and a stricter one would keep —
    /// this leaf's fail-closed reading posture (section 4.1's "laxly schema valid" is a GENERATION
    /// obligation, never a reading tolerance, per <see cref="XmlSignature"/>'s own remarks) refuses the
    /// whole class rather than special-case which split shapes are "safe."
    /// </remarks>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The simple-content element.</param>
    /// <param name="textNodeIndex">The text node index, or -1 for empty content.</param>
    /// <param name="error">The refusal when the content does not match the simple-content shape.</param>
    /// <returns><see langword="true"/> when the content matched.</returns>
    public static bool TryGetSimpleContentTextNodeIndex(XmlNodeTable table, int elementIndex, out int textNodeIndex, out XmlSignatureReadError error)
    {
        int child = table.FirstChildOf(elementIndex);
        if(child < 0)
        {
            textNodeIndex = -1;
            error = default;

            return true;
        }

        if(table.KindOf(child) != XmlNodeKind.Text || table.NextSiblingOf(child) >= 0)
        {
            textNodeIndex = -1;
            error = new XmlSignatureReadError(XmlSignatureReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        textNodeIndex = child;
        error = default;

        return true;
    }


    /// <summary>
    /// Decodes the base64 content of a simple-content element per <see cref="TryGetSimpleContentTextNodeIndex"/>
    /// then <see cref="XmlBase64Content.TryDecode"/>, registering the decoded octets with the reading
    /// operation's custody list on success.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The simple-content element.</param>
    /// <param name="pool">The pool the decoded octets are rented from.</param>
    /// <param name="owned">The custody list the decoded octets are added to on success.</param>
    /// <param name="decoded">The decoded octets on success.</param>
    /// <param name="error">The refusal on failure.</param>
    /// <returns><see langword="true"/> when the content decoded.</returns>
    public static bool TryDecodeSimpleBase64Content(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out PooledMemory? decoded, out XmlSignatureReadError error)
    {
        if(!TryGetSimpleContentTextNodeIndex(table, elementIndex, out int textNodeIndex, out error))
        {
            decoded = null;

            return false;
        }

        ReadOnlySpan<byte> content = textNodeIndex >= 0 ? table.ValueOf(textNodeIndex) : ReadOnlySpan<byte>.Empty;
        if(!XmlBase64Content.TryDecode(content, pool, out decoded, out error))
        {
            return false;
        }

        owned.Add(decoded!);

        return true;
    }
}


/// <summary>
/// The one hash-combination rule every read-model type of this leaf shares for its <c>Equals</c>/
/// <c>GetHashCode</c> override: two values are equal exactly when they were read from the same
/// <see cref="XmlNodeTable"/> instance at the same element index, regardless of any other structural state
/// they carry — these types are read-models over a table position, not independent value objects, so
/// identity of the position they read is the whole of their equality.
/// </summary>
internal static class XmlModelEquality
{
    /// <summary>
    /// Combines a table reference and an element index into one hash code, consistent with the
    /// (table-reference, element-index) equality every read-model type applies.
    /// </summary>
    /// <param name="table">The table the model was read from, or <see langword="null"/> for a default value.</param>
    /// <param name="elementIndex">The element index the model was read at.</param>
    /// <returns>The combined hash code.</returns>
    public static int CombineHash(XmlNodeTable? table, int elementIndex)
    {
        return HashCode.Combine(table is null ? 0 : RuntimeHelpers.GetHashCode(table), elementIndex);
    }
}
