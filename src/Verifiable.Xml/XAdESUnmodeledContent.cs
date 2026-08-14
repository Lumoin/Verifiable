using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// The unmodeled-content carriage this leaf applies to every <c>AnyType</c>-typed position (clause 5.1.1):
/// the ordered run of an element's immediate child nodes — text, comment, processing-instruction and element
/// nodes alike — carried as index positions into the owning <see cref="XmlNodeTable"/>, never interpreted or
/// decoded. Backs the <c>Any</c> element clause 5.1.1 itself declares, and every other <c>AnyType</c>-typed
/// position this leaf reads (<c>UnsignedDataObjectProperty</c>, <c>XMLTimeStamp</c>,
/// <c>SigPolicyQualifier</c>, <c>SignedAssertion</c>, <c>OtherAttributeCertificate</c> and others) — this
/// library's posture for content this specification leaves open by design: clause 4.3.7's own words
/// about one such position, "the schema definition leaves open the definition of the contents of this
/// type," apply uniformly to every <c>AnyType</c> position, not just that one.
/// </summary>
/// <remarks>
/// <c>AnyType</c>'s content model is <c>mixed="true"</c> with <c>xsd:any namespace="##any" processContents="lax"</c>
/// and <c>xsd:anyAttribute namespace="##any"</c> (clause 5.1.1's three <c>shall</c>s: a content model allowing
/// an unrestricted-length sequence of arbitrary elements mixed with text, allowing text-only content, and
/// allowing an unrestricted number of arbitrary attributes). <see cref="ContentNodeIndices"/> lists every
/// immediate child exactly as the document carries it — with no whitespace filtering and no refusal of any
/// shape, since this content model permits everything <see cref="Read"/> could ever see. A caller inspecting
/// the element's own attributes reads them directly from its own <see cref="XmlNodeTable"/> reference via
/// <see cref="ParentElementIndex"/>, using <see cref="XmlNodeTable.AttributeCountOf"/> and its siblings; this
/// type does not restate that surface, keeping to the one thing an <c>AnyType</c> position needs beyond what
/// the table already exposes — the ordered list of child positions.
/// </remarks>
public readonly struct XAdESUnmodeledContent: IEquatable<XAdESUnmodeledContent>
{
    /// <summary>The table the content's indices read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>AnyType</c>-typed element's own index.</summary>
    public int ParentElementIndex { get; }

    /// <summary>Every immediate child node index, in document order, unfiltered, unvalidated.</summary>
    public IReadOnlyList<int> ContentNodeIndices { get; }


    private XAdESUnmodeledContent(XmlNodeTable table, int parentElementIndex, IReadOnlyList<int> contentNodeIndices)
    {
        Table = table;
        ParentElementIndex = parentElementIndex;
        ContentNodeIndices = contentNodeIndices;
    }


    /// <summary>
    /// Reads an <c>AnyType</c>-typed element's content: every immediate child node index, unfiltered. This
    /// can never refuse — <c>AnyType</c>'s content model (clause 5.1.1) permits any sequence of elements,
    /// text, or both, in any mixture, so there is no shape for this method to reject.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="parentElementIndex">The <c>AnyType</c>-typed element.</param>
    /// <returns>The unmodeled content.</returns>
    public static XAdESUnmodeledContent Read(XmlNodeTable table, int parentElementIndex)
    {
        ArgumentNullException.ThrowIfNull(table);

        var contentNodeIndices = new List<int>();
        for(int child = table.FirstChildOf(parentElementIndex); child >= 0; child = table.NextSiblingOf(child))
        {
            contentNodeIndices.Add(child);
        }

        return new XAdESUnmodeledContent(table, parentElementIndex, contentNodeIndices);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESUnmodeledContent other) => ReferenceEquals(Table, other.Table) && ParentElementIndex == other.ParentElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESUnmodeledContent other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ParentElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESUnmodeledContent left, XAdESUnmodeledContent right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESUnmodeledContent left, XAdESUnmodeledContent right) => !left.Equals(right);
}
