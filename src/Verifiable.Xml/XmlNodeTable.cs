using Lumoin.Base;

namespace Verifiable.Xml;

/// <summary>
/// An immutable, pooled, index-based table of the nodes of one XML document, in the XPath data model shape
/// that <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.1
/// defines canonicalization over: a root node at index zero whose children are the document element and
/// any comments and processing instructions outside it; element, text, comment and processing instruction
/// nodes beneath; and attribute and namespace declaration axes associated with each element rather than
/// among its children. Node indices ascend in document order.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="TryParse"/> is the only way to obtain a table. Its front end accepts UTF-8 with or without a
/// byte order mark and UTF-16 discriminated by byte order mark, or without one only when the document
/// begins with the unambiguous 16-bit <c>&lt;?xml</c> pattern; UTF-16 is transcoded once into a pooled
/// UTF-8 buffer and every other encoding is refused. This is conformant:
/// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.1 makes
/// UTF-8 and UTF-16 required, ISO-8859-1 recommended and all others optional — and because no non-UCS
/// encoding is ever transcoded, its Unicode Normalization Form C requirement for non-UCS source encodings
/// is vacuously met. Ill-formed sequences are refused, never replaced.
/// </para>
/// <para>
/// The table holds the processed data model: line ends normalized per
/// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.11,
/// attribute values normalized per the CDATA rule of section 3.3.3, CDATA sections replaced with their
/// character content, character and predefined entity references resolved, and consecutive character data
/// coalesced into single text nodes. Every element and attribute name is resolved to its (namespace URI,
/// prefix, local name) triple per
/// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
/// Edition)</see>; the in-scope namespace axis of any element is reconstructable from
/// <see cref="NamespaceDeclarationCountOf"/> along the ancestor chain plus the implicit <c>xml</c>
/// binding, which <see cref="TryResolvePrefix"/> performs.
/// </para>
/// <para>
/// All storage is rented from the pool given to <see cref="TryParse"/> and returned by
/// <see cref="Dispose"/>; the table keeps no reference to the input octets. Refusal offsets locate the
/// position in the document octets for UTF-8 input; for UTF-16 input, refusals determined after the
/// transcoding step locate the position in the document's once-transcoded UTF-8 form.
/// </para>
/// </remarks>
public sealed class XmlNodeTable: IDisposable
{
    /// <summary>The document tree nodes, in document order.</summary>
    private PooledStructList<NodeRecord> Nodes { get; }

    /// <summary>The attribute records, contiguous per element in document order.</summary>
    private PooledStructList<AttributeRecord> Attributes { get; }

    /// <summary>The namespace declaration records, contiguous per element in document order.</summary>
    private PooledStructList<NamespaceDeclarationRecord> NamespaceDeclarations { get; }

    /// <summary>The string heap all records reference into.</summary>
    private PooledStructList<byte> StringHeap { get; }

    /// <summary>Heap offset of the interned <c>xml</c> namespace URI.</summary>
    private int XmlNamespaceUriOffset { get; }

    /// <summary>Heap length of the interned <c>xml</c> namespace URI.</summary>
    private int XmlNamespaceUriLength { get; }

    /// <summary>Whether the table has been disposed.</summary>
    private bool isDisposed;


    /// <summary>
    /// The index of the root node.
    /// </summary>
    public int RootIndex
    {
        get
        {
            ObjectDisposedException.ThrowIf(isDisposed, this);

            return 0;
        }
    }

    /// <summary>
    /// The number of nodes in the table. Indices from zero to one less than this are valid, in document
    /// order.
    /// </summary>
    public int Count
    {
        get
        {
            ObjectDisposedException.ThrowIf(isDisposed, this);

            return Nodes.Count;
        }
    }

    /// <summary>
    /// The index of the document element, the single element child of the root.
    /// </summary>
    public int DocumentElementIndex
    {
        get
        {
            ObjectDisposedException.ThrowIf(isDisposed, this);
            for(int child = Nodes[0].FirstChild; child >= 0; child = Nodes[child].NextSibling)
            {
                if(Nodes[child].Kind == (int)XmlNodeKind.Element)
                {
                    return child;
                }
            }

            return -1;
        }
    }


    /// <summary>
    /// Creates the table over lists built by <see cref="XmlNodeTableBuilder"/>, taking their ownership.
    /// </summary>
    /// <param name="nodes">The node records.</param>
    /// <param name="attributes">The attribute records.</param>
    /// <param name="namespaceDeclarations">The namespace declaration records.</param>
    /// <param name="stringHeap">The string heap.</param>
    /// <param name="xmlNamespaceUriOffset">Heap offset of the interned <c>xml</c> namespace URI.</param>
    /// <param name="xmlNamespaceUriLength">Heap length of the interned <c>xml</c> namespace URI.</param>
    internal XmlNodeTable(
        PooledStructList<NodeRecord> nodes,
        PooledStructList<AttributeRecord> attributes,
        PooledStructList<NamespaceDeclarationRecord> namespaceDeclarations,
        PooledStructList<byte> stringHeap,
        int xmlNamespaceUriOffset,
        int xmlNamespaceUriLength)
    {
        Nodes = nodes;
        Attributes = attributes;
        NamespaceDeclarations = namespaceDeclarations;
        StringHeap = stringHeap;
        XmlNamespaceUriOffset = xmlNamespaceUriOffset;
        XmlNamespaceUriLength = xmlNamespaceUriLength;
    }


    /// <summary>
    /// Parses document octets into a node table.
    /// </summary>
    /// <param name="documentOctets">The document octets in any accepted encoding.</param>
    /// <param name="pool">The pool every buffer of the parse and of the table is rented from.</param>
    /// <param name="table">The table on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal reason and byte offset on failure.</param>
    /// <returns><see langword="true"/> when the document was accepted.</returns>
    public static bool TryParse(ReadOnlyMemory<byte> documentOctets, BaseMemoryPool pool, out XmlNodeTable? table, out XmlReadError error)
    {
        ArgumentNullException.ThrowIfNull(pool);
        table = null;
        ReadOnlySpan<byte> octets = documentOctets.Span;
        if(!XmlDocumentDecoder.TryDetectEncoding(octets, out DetectedXmlEncoding detected, out int bomLength, out error))
        {
            return false;
        }

        var builder = new XmlNodeTableBuilder(pool, octets.Length);
        try
        {
            bool isBuilt;
            if(detected == DetectedXmlEncoding.Utf8)
            {
                ReadOnlySpan<byte> working = octets[bomLength..];
                if(!XmlDocumentDecoder.TryValidateUtf8(working, bomLength, out error))
                {
                    builder.Dispose();

                    return false;
                }

                isBuilt = builder.TryBuild(working, bomLength, detected, out error);
            }
            else
            {
                using var transcoded = new PooledStructList<byte>(pool, Math.Max(64, octets.Length + (octets.Length / 2)));
                bool isTranscoded = XmlDocumentDecoder.TryTranscodeUtf16(octets, bomLength, detected == DetectedXmlEncoding.Utf16BigEndian, transcoded, out error);
                isBuilt = isTranscoded && builder.TryBuild(transcoded.AsSpan(), 0, detected, out error);
            }

            if(!isBuilt)
            {
                builder.Dispose();

                return false;
            }

            table = builder.TransferToTable();
            builder.Dispose();
            error = default;

            return true;
        }
        catch
        {
            builder.Dispose();

            throw;
        }
    }


    /// <summary>
    /// The kind of a node.
    /// </summary>
    /// <param name="nodeIndex">The node index.</param>
    /// <returns>The node kind.</returns>
    public XmlNodeKind KindOf(int nodeIndex)
    {
        ValidateNodeIndex(nodeIndex);

        return (XmlNodeKind)Nodes[nodeIndex].Kind;
    }


    /// <summary>
    /// The parent of a node, or -1 for the root.
    /// </summary>
    /// <param name="nodeIndex">The node index.</param>
    /// <returns>The parent node index, or -1.</returns>
    public int ParentOf(int nodeIndex)
    {
        ValidateNodeIndex(nodeIndex);

        return Nodes[nodeIndex].Parent;
    }


    /// <summary>
    /// The first child of a node, or -1 when it has none. Attributes and namespace declarations are not
    /// children; they are read through the per-element accessors.
    /// </summary>
    /// <param name="nodeIndex">The node index.</param>
    /// <returns>The first child node index, or -1.</returns>
    public int FirstChildOf(int nodeIndex)
    {
        ValidateNodeIndex(nodeIndex);

        return Nodes[nodeIndex].FirstChild;
    }


    /// <summary>
    /// The next sibling of a node, or -1 when it is the last child.
    /// </summary>
    /// <param name="nodeIndex">The node index.</param>
    /// <returns>The next sibling node index, or -1.</returns>
    public int NextSiblingOf(int nodeIndex)
    {
        ValidateNodeIndex(nodeIndex);

        return Nodes[nodeIndex].NextSibling;
    }


    /// <summary>
    /// The namespace prefix of an element as it appeared in the document, empty for an unprefixed name.
    /// The original prefix is retained because canonical XML renders the QName with the prefix from the
    /// input document per <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML
    /// 1.0</see> section 2.3.
    /// </summary>
    /// <param name="nodeIndex">The element node index.</param>
    /// <returns>The prefix octets.</returns>
    public ReadOnlySpan<byte> PrefixOf(int nodeIndex)
    {
        ValidateNodeIndex(nodeIndex);
        NodeRecord record = Nodes[nodeIndex];

        return StringHeap.AsSpan().Slice(record.PrefixOffset, record.PrefixLength);
    }


    /// <summary>
    /// The local name of an element, or the target of a processing instruction.
    /// </summary>
    /// <param name="nodeIndex">The node index.</param>
    /// <returns>The local name octets.</returns>
    public ReadOnlySpan<byte> LocalNameOf(int nodeIndex)
    {
        ValidateNodeIndex(nodeIndex);
        NodeRecord record = Nodes[nodeIndex];

        return StringHeap.AsSpan().Slice(record.LocalOffset, record.LocalLength);
    }


    /// <summary>
    /// The resolved namespace URI of an element, empty when the element is in no namespace.
    /// </summary>
    /// <param name="nodeIndex">The element node index.</param>
    /// <returns>The namespace URI octets.</returns>
    public ReadOnlySpan<byte> NamespaceUriOf(int nodeIndex)
    {
        ValidateNodeIndex(nodeIndex);
        NodeRecord record = Nodes[nodeIndex];

        return StringHeap.AsSpan().Slice(record.NamespaceOffset, record.NamespaceLength);
    }


    /// <summary>
    /// The value of a text, comment or processing instruction node, fully normalized and resolved.
    /// </summary>
    /// <param name="nodeIndex">The node index.</param>
    /// <returns>The value octets.</returns>
    public ReadOnlySpan<byte> ValueOf(int nodeIndex)
    {
        ValidateNodeIndex(nodeIndex);
        NodeRecord record = Nodes[nodeIndex];

        return StringHeap.AsSpan().Slice(record.ValueOffset, record.ValueLength);
    }


    /// <summary>
    /// The number of attributes of an element, namespace declarations excluded. Attributes are stored in
    /// document order; sorting them is the canonicalizer's concern.
    /// </summary>
    /// <param name="elementIndex">The element node index.</param>
    /// <returns>The attribute count.</returns>
    public int AttributeCountOf(int elementIndex)
    {
        ValidateNodeIndex(elementIndex);

        return Nodes[elementIndex].AttributeCount;
    }


    /// <summary>
    /// The namespace prefix of an attribute, empty for an unprefixed name.
    /// </summary>
    /// <param name="elementIndex">The element node index.</param>
    /// <param name="attributeOrdinal">The attribute's position in document order.</param>
    /// <returns>The prefix octets.</returns>
    public ReadOnlySpan<byte> AttributePrefixOf(int elementIndex, int attributeOrdinal)
    {
        AttributeRecord record = AttributeAt(elementIndex, attributeOrdinal);

        return StringHeap.AsSpan().Slice(record.PrefixOffset, record.PrefixLength);
    }


    /// <summary>
    /// The local name of an attribute.
    /// </summary>
    /// <param name="elementIndex">The element node index.</param>
    /// <param name="attributeOrdinal">The attribute's position in document order.</param>
    /// <returns>The local name octets.</returns>
    public ReadOnlySpan<byte> AttributeLocalNameOf(int elementIndex, int attributeOrdinal)
    {
        AttributeRecord record = AttributeAt(elementIndex, attributeOrdinal);

        return StringHeap.AsSpan().Slice(record.LocalOffset, record.LocalLength);
    }


    /// <summary>
    /// The resolved namespace URI of an attribute, empty when the attribute is in no namespace. An
    /// unprefixed attribute is always in no namespace per
    /// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 6.2.
    /// </summary>
    /// <param name="elementIndex">The element node index.</param>
    /// <param name="attributeOrdinal">The attribute's position in document order.</param>
    /// <returns>The namespace URI octets.</returns>
    public ReadOnlySpan<byte> AttributeNamespaceUriOf(int elementIndex, int attributeOrdinal)
    {
        AttributeRecord record = AttributeAt(elementIndex, attributeOrdinal);

        return StringHeap.AsSpan().Slice(record.NamespaceOffset, record.NamespaceLength);
    }


    /// <summary>
    /// The value of an attribute, normalized per the CDATA rule of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 3.3.3 with references resolved.
    /// </summary>
    /// <param name="elementIndex">The element node index.</param>
    /// <param name="attributeOrdinal">The attribute's position in document order.</param>
    /// <returns>The normalized value octets.</returns>
    public ReadOnlySpan<byte> AttributeValueOf(int elementIndex, int attributeOrdinal)
    {
        AttributeRecord record = AttributeAt(elementIndex, attributeOrdinal);

        return StringHeap.AsSpan().Slice(record.ValueOffset, record.ValueLength);
    }


    /// <summary>
    /// The number of namespace declarations an element carries itself. Declarations inherited from
    /// ancestors are reconstructed by walking <see cref="ParentOf"/>, which
    /// <see cref="TryResolvePrefix"/> does.
    /// </summary>
    /// <param name="elementIndex">The element node index.</param>
    /// <returns>The declaration count.</returns>
    public int NamespaceDeclarationCountOf(int elementIndex)
    {
        ValidateNodeIndex(elementIndex);

        return Nodes[elementIndex].NamespaceDeclarationCount;
    }


    /// <summary>
    /// The prefix a namespace declaration declares, empty for the default namespace declaration.
    /// </summary>
    /// <param name="elementIndex">The element node index.</param>
    /// <param name="declarationOrdinal">The declaration's position in document order.</param>
    /// <returns>The declared prefix octets.</returns>
    public ReadOnlySpan<byte> NamespaceDeclarationPrefixOf(int elementIndex, int declarationOrdinal)
    {
        NamespaceDeclarationRecord record = NamespaceDeclarationAt(elementIndex, declarationOrdinal);

        return StringHeap.AsSpan().Slice(record.PrefixOffset, record.PrefixLength);
    }


    /// <summary>
    /// The namespace URI a namespace declaration binds, empty for the <c>xmlns=""</c> un-declaration of
    /// the default namespace.
    /// </summary>
    /// <param name="elementIndex">The element node index.</param>
    /// <param name="declarationOrdinal">The declaration's position in document order.</param>
    /// <returns>The declared URI octets.</returns>
    public ReadOnlySpan<byte> NamespaceDeclarationUriOf(int elementIndex, int declarationOrdinal)
    {
        NamespaceDeclarationRecord record = NamespaceDeclarationAt(elementIndex, declarationOrdinal);

        return StringHeap.AsSpan().Slice(record.UriOffset, record.UriLength);
    }


    /// <summary>
    /// Resolves a prefix against the namespace declarations in scope at an element: the element's own
    /// declarations, those inherited along the ancestor chain, and the implicit <c>xml</c> binding of
    /// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 3. This reconstructs the namespace axis of the XPath data model, under which
    /// an element has namespace nodes for its own declarations as well as any made by its ancestors that
    /// it has not overridden, per <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical
    /// XML 1.0</see> section 2.1.
    /// </summary>
    /// <param name="elementIndex">The element node index.</param>
    /// <param name="prefix">The prefix to resolve; empty for the default namespace.</param>
    /// <param name="namespaceUri">
    /// The bound URI; empty when the innermost binding is the <c>xmlns=""</c> un-declaration, meaning no
    /// namespace.
    /// </param>
    /// <returns><see langword="true"/> when a binding is in scope.</returns>
    public bool TryResolvePrefix(int elementIndex, ReadOnlySpan<byte> prefix, out ReadOnlySpan<byte> namespaceUri)
    {
        ValidateNodeIndex(elementIndex);
        if(prefix.SequenceEqual(XmlCharacters.XmlPrefix))
        {
            namespaceUri = StringHeap.AsSpan().Slice(XmlNamespaceUriOffset, XmlNamespaceUriLength);

            return true;
        }

        for(int current = elementIndex; current > 0; current = Nodes[current].Parent)
        {
            NodeRecord record = Nodes[current];
            if(record.Kind != (int)XmlNodeKind.Element)
            {
                continue;
            }

            for(int i = 0; i < record.NamespaceDeclarationCount; ++i)
            {
                NamespaceDeclarationRecord declaration = NamespaceDeclarations[record.NamespaceDeclarationFirst + i];
                if(StringHeap.AsSpan().Slice(declaration.PrefixOffset, declaration.PrefixLength).SequenceEqual(prefix))
                {
                    namespaceUri = StringHeap.AsSpan().Slice(declaration.UriOffset, declaration.UriLength);

                    return true;
                }
            }
        }

        namespaceUri = default;

        return false;
    }


    /// <summary>
    /// Finds the element identified by a recognized <c>ID</c>-typed attribute value: an un-prefixed
    /// attribute with local name exactly <c>Id</c> — the
    /// XMLDSIG schema's own typed attribute name at every attribute-definition site — or the <c>xml:id</c>
    /// attribute of <see href="https://www.w3.org/TR/2005/REC-xml-id-20050909/">xml:id Version 1.0</see>,
    /// which is an ID independently of any DTD. No document type declaration ever reaches this table
    /// (<see cref="XmlReadFailure.DoctypeProhibited"/>), so no attribute is "of type ID" by schema
    /// declaration; recognition is by exact name instead. Case variants <c>ID</c>/<c>id</c> un-prefixed are
    /// deliberately not recognized: promiscuous case matching is a known signature-wrapping surface.
    /// </summary>
    /// <param name="idValue">The identifier value to find an element by.</param>
    /// <param name="elementIndex">The found element's index on success; -1 otherwise.</param>
    /// <param name="error">The refusal when no unique element carries the value:
    /// <see cref="XmlSignatureProcessingFailure.IdNotFound"/> when no recognized attribute carries it,
    /// <see cref="XmlSignatureProcessingFailure.DuplicateId"/> when more than one distinct ELEMENT carries
    /// it anywhere in the document — ambiguous targets are how signature-wrapping attacks work, so a
    /// duplicate refuses rather than resolving to the first match. One element
    /// carrying the value on BOTH recognized spellings at once (its own <c>Id</c> and its own <c>xml:id</c>
    /// both equal to <paramref name="idValue"/>) is a single unambiguous target, not a duplicate: only
    /// distinct elements are counted, never distinct matching attributes.</param>
    /// <returns><see langword="true"/> when exactly one element carries the value on a recognized attribute.</returns>
    public bool TryFindElementById(ReadOnlySpan<byte> idValue, out int elementIndex, out XmlSignatureProcessingError error)
    {
        ObjectDisposedException.ThrowIf(isDisposed, this);
        int matchIndex = -1;
        int matchCount = 0;
        for(int node = 0; node < Nodes.Count; ++node)
        {
            if(KindOf(node) != XmlNodeKind.Element || !ElementCarriesRecognizedIdValue(node, idValue))
            {
                continue;
            }

            if(matchCount == 0)
            {
                matchIndex = node;
            }

            ++matchCount;
        }

        if(matchCount == 1)
        {
            elementIndex = matchIndex;
            error = default;

            return true;
        }

        elementIndex = -1;
        error = new XmlSignatureProcessingError(matchCount == 0 ? XmlSignatureProcessingFailure.IdNotFound : XmlSignatureProcessingFailure.DuplicateId, 0);

        return false;
    }


    /// <summary>
    /// Tells whether an element carries <paramref name="idValue"/> on at least one of its recognized
    /// <c>ID</c>-typed attributes (<see cref="IsRecognizedIdAttribute"/>) — the per-ELEMENT membership test
    /// <see cref="TryFindElementById"/> counts, so an element carrying the same value on both its <c>Id</c>
    /// and its <c>xml:id</c> contributes exactly once.
    /// </summary>
    /// <param name="elementIndex">The element node index.</param>
    /// <param name="idValue">The identifier value to look for.</param>
    /// <returns><see langword="true"/> when at least one recognized attribute carries the value.</returns>
    private bool ElementCarriesRecognizedIdValue(int elementIndex, ReadOnlySpan<byte> idValue)
    {
        int attributeCount = AttributeCountOf(elementIndex);
        for(int ordinal = 0; ordinal < attributeCount; ++ordinal)
        {
            if(IsRecognizedIdAttribute(elementIndex, ordinal) && AttributeValueOf(elementIndex, ordinal).SequenceEqual(idValue))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Returns every pooled buffer the table holds.
    /// </summary>
    public void Dispose()
    {
        if(isDisposed)
        {
            return;
        }

        isDisposed = true;
        Nodes.Dispose();
        Attributes.Dispose();
        NamespaceDeclarations.Dispose();
        StringHeap.Dispose();
    }


    /// <summary>
    /// Validates a node index against the table.
    /// </summary>
    /// <param name="nodeIndex">The node index.</param>
    private void ValidateNodeIndex(int nodeIndex)
    {
        ObjectDisposedException.ThrowIf(isDisposed, this);
        ArgumentOutOfRangeException.ThrowIfNegative(nodeIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(nodeIndex, Nodes.Count);
    }


    /// <summary>
    /// Fetches an attribute record by element and ordinal.
    /// </summary>
    /// <param name="elementIndex">The element node index.</param>
    /// <param name="attributeOrdinal">The attribute's position in document order.</param>
    /// <returns>The attribute record.</returns>
    private AttributeRecord AttributeAt(int elementIndex, int attributeOrdinal)
    {
        ValidateNodeIndex(elementIndex);
        NodeRecord element = Nodes[elementIndex];
        ArgumentOutOfRangeException.ThrowIfNegative(attributeOrdinal);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(attributeOrdinal, element.AttributeCount);

        return Attributes[element.AttributeFirst + attributeOrdinal];
    }


    /// <summary>
    /// Tells whether an attribute is a recognized <c>ID</c>-typed attribute: an un-prefixed
    /// attribute with local name exactly <c>Id</c>, or the <c>xml:id</c> attribute (namespace
    /// <c>http://www.w3.org/XML/1998/namespace</c>, local name <c>id</c>). Case variants <c>ID</c>/<c>id</c>
    /// un-prefixed are deliberately not matched.
    /// </summary>
    /// <param name="elementIndex">The element node index.</param>
    /// <param name="attributeOrdinal">The attribute's position in document order.</param>
    /// <returns><see langword="true"/> when the attribute is a recognized <c>ID</c>-typed attribute.</returns>
    private bool IsRecognizedIdAttribute(int elementIndex, int attributeOrdinal)
    {
        ReadOnlySpan<byte> localName = AttributeLocalNameOf(elementIndex, attributeOrdinal);

        return AttributePrefixOf(elementIndex, attributeOrdinal).IsEmpty
            ? localName.SequenceEqual("Id"u8)
            : AttributeNamespaceUriOf(elementIndex, attributeOrdinal).SequenceEqual(XmlCharacters.XmlNamespaceUri) && localName.SequenceEqual("id"u8);
    }


    /// <summary>
    /// Fetches a namespace declaration record by element and ordinal.
    /// </summary>
    /// <param name="elementIndex">The element node index.</param>
    /// <param name="declarationOrdinal">The declaration's position in document order.</param>
    /// <returns>The namespace declaration record.</returns>
    private NamespaceDeclarationRecord NamespaceDeclarationAt(int elementIndex, int declarationOrdinal)
    {
        ValidateNodeIndex(elementIndex);
        NodeRecord element = Nodes[elementIndex];
        ArgumentOutOfRangeException.ThrowIfNegative(declarationOrdinal);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(declarationOrdinal, element.NamespaceDeclarationCount);

        return NamespaceDeclarations[element.NamespaceDeclarationFirst + declarationOrdinal];
    }
}
