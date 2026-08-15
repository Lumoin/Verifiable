namespace Verifiable.Xml;

/// <summary>
/// One node of an <see cref="XmlNodeTable"/>: kind, tree links and ranges into the table's string heap.
/// A range of length zero means the field is absent. Fields are plain integers so the records live in a
/// pooled buffer.
/// </summary>
internal struct NodeRecord
{
    /// <summary>The <see cref="XmlNodeKind"/> of the node.</summary>
    public int Kind;

    /// <summary>The parent node index, or -1 for the root.</summary>
    public int Parent;

    /// <summary>The first child node index, or -1.</summary>
    public int FirstChild;

    /// <summary>The last child node index, or -1; used while building to append siblings.</summary>
    public int LastChild;

    /// <summary>The next sibling node index, or -1.</summary>
    public int NextSibling;

    /// <summary>Heap offset of the namespace prefix of an element.</summary>
    public int PrefixOffset;

    /// <summary>Heap length of the namespace prefix of an element.</summary>
    public int PrefixLength;

    /// <summary>Heap offset of the local name of an element or the target of a processing instruction.</summary>
    public int LocalOffset;

    /// <summary>Heap length of the local name of an element or the target of a processing instruction.</summary>
    public int LocalLength;

    /// <summary>Heap offset of the resolved namespace URI of an element.</summary>
    public int NamespaceOffset;

    /// <summary>Heap length of the resolved namespace URI of an element; zero means no namespace.</summary>
    public int NamespaceLength;

    /// <summary>Heap offset of the value of a text, comment or processing instruction node.</summary>
    public int ValueOffset;

    /// <summary>Heap length of the value of a text, comment or processing instruction node.</summary>
    public int ValueLength;

    /// <summary>Index of the element's first attribute record.</summary>
    public int AttributeFirst;

    /// <summary>Number of attribute records the element owns.</summary>
    public int AttributeCount;

    /// <summary>Index of the element's first namespace declaration record.</summary>
    public int NamespaceDeclarationFirst;

    /// <summary>Number of namespace declaration records the element owns.</summary>
    public int NamespaceDeclarationCount;
}


/// <summary>
/// One attribute of an element in an <see cref="XmlNodeTable"/>, stored in document order with its
/// namespace-resolved qualified name and its value normalized per the CDATA rule of
/// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 3.3.3.
/// Namespace declarations are not attribute records; they live in
/// <see cref="NamespaceDeclarationRecord"/>s per the XPath data model.
/// </summary>
internal struct AttributeRecord
{
    /// <summary>The owning element's node index.</summary>
    public int Parent;

    /// <summary>Heap offset of the namespace prefix.</summary>
    public int PrefixOffset;

    /// <summary>Heap length of the namespace prefix; zero for an unprefixed attribute.</summary>
    public int PrefixLength;

    /// <summary>Heap offset of the local name.</summary>
    public int LocalOffset;

    /// <summary>Heap length of the local name.</summary>
    public int LocalLength;

    /// <summary>Heap offset of the resolved namespace URI.</summary>
    public int NamespaceOffset;

    /// <summary>Heap length of the resolved namespace URI; zero means no namespace.</summary>
    public int NamespaceLength;

    /// <summary>Heap offset of the normalized value.</summary>
    public int ValueOffset;

    /// <summary>Heap length of the normalized value.</summary>
    public int ValueLength;
}


/// <summary>
/// One namespace declaration attribute (<c>xmlns</c> or <c>xmlns:prefix</c>) of an element in an
/// <see cref="XmlNodeTable"/>, stored in document order. The in-scope namespace axis of any element is
/// reconstructed from these records along the ancestor chain plus the implicit <c>xml</c> binding.
/// </summary>
internal struct NamespaceDeclarationRecord
{
    /// <summary>The owning element's node index.</summary>
    public int Parent;

    /// <summary>Heap offset of the declared prefix.</summary>
    public int PrefixOffset;

    /// <summary>Heap length of the declared prefix; zero for the default namespace declaration.</summary>
    public int PrefixLength;

    /// <summary>Heap offset of the declared namespace URI.</summary>
    public int UriOffset;

    /// <summary>Heap length of the declared namespace URI; zero for the <c>xmlns=""</c> un-declaration.</summary>
    public int UriLength;
}


/// <summary>
/// One entry of the namespace scope stack used while building: the heap ranges of a declared prefix and
/// its URI. Entries are pushed per element and truncated back when the element closes, and each entry is
/// threaded on a hash-bucket chain keyed by its prefix, so the innermost in-scope declaration of a prefix
/// is found by one bucket walk instead of a scan of the whole stack. A chain runs from the most recently
/// pushed entry outward, and the stack's last-in first-out discipline keeps every popped entry at its
/// chain head when it pops.
/// </summary>
internal struct NamespaceScopeEntry
{
    /// <summary>Heap offset of the prefix.</summary>
    public int PrefixOffset;

    /// <summary>Heap length of the prefix.</summary>
    public int PrefixLength;

    /// <summary>Heap offset of the URI.</summary>
    public int UriOffset;

    /// <summary>Heap length of the URI.</summary>
    public int UriLength;

    /// <summary>The hash bucket the entry is threaded on.</summary>
    public int Bucket;

    /// <summary>The stack index of the previous entry on the same bucket chain, or -1.</summary>
    public int PreviousInBucket;
}


/// <summary>
/// One entry of the open-element stack used while building.
/// </summary>
internal struct ElementStackEntry
{
    /// <summary>The element's node index.</summary>
    public int NodeIndex;

    /// <summary>The namespace scope depth to truncate back to when the element closes.</summary>
    public int NamespaceScopeMark;

    /// <summary>Offset of the element's qualified name in the working document span.</summary>
    public int QNameOffset;

    /// <summary>Length of the element's qualified name in the working document span.</summary>
    public int QNameLength;
}


/// <summary>
/// One attribute specification staged while a start-tag is being read, as ranges into the working document
/// span; processed once the whole tag has been read so declarations on the tag are in scope for every name
/// on it.
/// </summary>
internal struct StagedAttribute
{
    /// <summary>Offset of the qualified name in the working span.</summary>
    public int NameOffset;

    /// <summary>Length of the qualified name in the working span.</summary>
    public int NameLength;

    /// <summary>Offset of the raw value literal in the working span.</summary>
    public int ValueOffset;

    /// <summary>Length of the raw value literal in the working span.</summary>
    public int ValueLength;
}
