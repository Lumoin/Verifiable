namespace Verifiable.Xml;

/// <summary>
/// Finds every <c>ds:Signature</c> element of a parsed document.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
/// (Second Edition)</see> does not cap the number of <c>Signature</c> elements a document carries, and an
/// <c>Object</c> may itself contain a whole nested <c>Signature</c> (section 4.5's schema permits
/// <c>Object</c> content of <c>##any</c> namespace, which includes the <c>ds</c> namespace itself; the
/// worked example of section 6.6.4 depends on exactly this shape for two sibling enveloped signatures).
/// <see cref="XmlNodeTable"/> node indices ascend in document order (a pre-order walk: a parent's index is
/// always less than any of its descendants'), so one linear scan over every node already visits an outer
/// <c>Signature</c> before any <c>Signature</c> nested inside it, in document order, with no separate
/// recursive descent required.
/// </remarks>
public static class XmlSignatureLocator
{
    /// <summary>
    /// Finds every <c>ds:Signature</c> element index, in document order, nested signatures included.
    /// </summary>
    /// <param name="table">The parsed document to search.</param>
    /// <returns>
    /// The element indices, in document order. An array is returned rather than a pooled buffer: the result
    /// carries no byte payload — only small structural integers — and its size is bounded by the number of
    /// <c>Signature</c> elements a caller-supplied document actually contains, the same index-array shape
    /// <see cref="XmlNodeTable.TryFindElementById"/>'s single-index result and <see cref="XmlNodeSet"/>'s
    /// own exclusion/ancestor-context arrays already use for structural index lists in this leaf.
    /// </returns>
    public static int[] FindSignatures(XmlNodeTable table)
    {
        ArgumentNullException.ThrowIfNull(table);

        var found = new List<int>();
        int count = table.Count;
        for(int node = 0; node < count; ++node)
        {
            if(table.KindOf(node) == XmlNodeKind.Element && XmlSignatureModelGrammar.IsDsElement(table, node, "Signature"u8))
            {
                found.Add(node);
            }
        }

        return [.. found];
    }
}
