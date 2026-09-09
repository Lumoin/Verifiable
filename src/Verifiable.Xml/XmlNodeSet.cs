using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace Verifiable.Xml;

/// <summary>
/// A node-set over an <see cref="XmlNodeTable"/> in the document-subset shapes XML Signature same-document
/// references, the enveloped-signature transform and the canonicalization specifications' own conformance
/// examples produce: the whole document, an element subtree with its ancestor namespace context, either of
/// those minus excluded subtrees, or a subtree wrapped by included ancestor elements. Membership follows the
/// XPath node-set semantics of <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML
/// 1.0</see> section 2.1: the attribute and namespace axes of every included element are included with it,
/// and an omitted node may still influence the rendering of its descendants. Whether comment nodes render
/// belongs to the algorithm variant of <see cref="XmlCanonicalizationAlgorithm"/>, not to the set.
/// </summary>
/// <remarks>
/// <see cref="WholeDocument"/> is the octet-stream input shape of Canonical XML section 2.1.
/// <see cref="ElementSubtree"/> is the shape a same-document <c>#id</c> reference dereferences to: the
/// identified element, its descendants and their attribute and namespace axes, with every ancestor
/// omitted. <see cref="Excluding"/> removes one element and its whole subtree, the shape the
/// enveloped-signature transform produces, and composes once per excluded subtree without bound.
/// <see cref="IncludingAncestor"/> adds one ancestor element as rendered context, the document-subset
/// shape of the specifications' conformance examples. <see cref="WithoutComments"/> marks the set to
/// exclude every comment node regardless of the canonicalization algorithm variant rendered afterwards —
/// the document-subset comment deletion of XML Signature section 4.3.3.3 step 4, which a same-document
/// dereference applies at dereference time, independently of the algorithm. Compositions grow immutable
/// index arrays — structural allocation over node indices, not byte payload — normalized at composition:
/// each array is held sorted ascending without duplicates, so two compositions denoting the same node-set
/// are equal regardless of composition order or repetition.
/// </remarks>
public readonly struct XmlNodeSet: IEquatable<XmlNodeSet>
{
    /// <summary>The table the set marks nodes of; <see langword="null"/> for a default-constructed set.</summary>
    internal XmlNodeTable? Table { get; }

    /// <summary>Whether the set is the whole-document shape.</summary>
    internal bool IsWholeDocument { get; }

    /// <summary>The subtree apex element index, or -1 for the whole-document shape.</summary>
    internal int ApexElementIndex { get; }

    /// <summary>Whether the set excludes every comment node regardless of canonicalization variant, per <see cref="WithoutComments"/>.</summary>
    internal bool ExcludesComments { get; }

    /// <summary>The excluded subtree apex indices; <see langword="null"/> when the set excludes nothing.</summary>
    private int[]? ExclusionIndices { get; }

    /// <summary>The ancestor-context element indices; <see langword="null"/> when the set includes no ancestor context.</summary>
    private int[]? AncestorContextIndices { get; }


    /// <summary>
    /// Creates the set over its parts.
    /// </summary>
    /// <param name="table">The table the set marks nodes of.</param>
    /// <param name="isWholeDocument">Whether the set is the whole-document shape.</param>
    /// <param name="apexElementIndex">The subtree apex element index, or -1.</param>
    /// <param name="exclusionIndices">The excluded subtree apex indices, or <see langword="null"/>.</param>
    /// <param name="ancestorContextIndices">The ancestor-context element indices, or <see langword="null"/>.</param>
    /// <param name="excludesComments">Whether the set excludes every comment node.</param>
    private XmlNodeSet(XmlNodeTable table, bool isWholeDocument, int apexElementIndex, int[]? exclusionIndices, int[]? ancestorContextIndices, bool excludesComments)
    {
        Table = table;
        IsWholeDocument = isWholeDocument;
        ApexElementIndex = apexElementIndex;
        ExclusionIndices = exclusionIndices;
        AncestorContextIndices = ancestorContextIndices;
        ExcludesComments = excludesComments;
    }


    /// <summary>
    /// The set containing every node of the document: the root node, all elements with their attribute and
    /// namespace axes, and all text, comment and processing instruction nodes — the node-set the default
    /// XPath expressions of <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML
    /// 1.0</see> section 2.1 generate over octet-stream input.
    /// </summary>
    /// <param name="table">The table whose nodes the set marks.</param>
    /// <returns>The whole-document set.</returns>
    public static XmlNodeSet WholeDocument(XmlNodeTable table)
    {
        ArgumentNullException.ThrowIfNull(table);

        return new XmlNodeSet(table, isWholeDocument: true, apexElementIndex: -1, exclusionIndices: null, ancestorContextIndices: null, excludesComments: false);
    }


    /// <summary>
    /// The set containing one element, its descendants and the attribute and namespace axes of each, with
    /// every ancestor omitted — the shape a same-document <c>#id</c> reference of XML Signature
    /// dereferences to. Omitted ancestors still supply namespace context and the <c>xml:*</c> inheritance
    /// the document-subsets sections of the canonicalization specifications define.
    /// </summary>
    /// <param name="table">The table whose nodes the set marks.</param>
    /// <param name="elementIndex">The subtree apex element index.</param>
    /// <returns>The element-subtree set.</returns>
    public static XmlNodeSet ElementSubtree(XmlNodeTable table, int elementIndex)
    {
        ArgumentNullException.ThrowIfNull(table);

        return new XmlNodeSet(table, isWholeDocument: false, elementIndex, exclusionIndices: null, ancestorContextIndices: null, excludesComments: false);
    }


    /// <summary>
    /// A copy of the set with one element and its whole subtree, including its attribute and namespace
    /// axes, removed — the shape the enveloped-signature transform of XML Signature produces. The
    /// composition is unbounded: a document carrying several signatures excludes one subtree per
    /// signature. The exclusion indices are held sorted ascending without duplicates, so compositions
    /// denoting the same node-set are equal regardless of composition order or repetition.
    /// </summary>
    /// <param name="elementIndex">The apex element index of the subtree to exclude.</param>
    /// <returns>The composed set.</returns>
    public XmlNodeSet Excluding(int elementIndex)
    {
        return new XmlNodeSet(Table!, IsWholeDocument, ApexElementIndex, InsertIndexSorted(ExclusionIndices, elementIndex), AncestorContextIndices, ExcludesComments);
    }


    /// <summary>
    /// A copy of an element-subtree set with one ancestor element added as rendered context: the element
    /// and its attribute and namespace axes join the set while its other content stays omitted. This is
    /// the document-subset shape the conformance examples of
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 3.7
    /// and <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see>
    /// sections 3.7 and 3.8 define with their document-subset expressions — an included ancestor wrapping
    /// an identified subtree across omitted intermediate elements — which a conformant implementation of
    /// the section 2.4 document-subsets processing renders. The ancestor-context indices are held sorted
    /// ascending without duplicates, so compositions denoting the same node-set are equal regardless of
    /// composition order or repetition.
    /// </summary>
    /// <param name="elementIndex">The ancestor element index to include as rendered context.</param>
    /// <returns>The composed set.</returns>
    public XmlNodeSet IncludingAncestor(int elementIndex)
    {
        return new XmlNodeSet(Table!, IsWholeDocument, ApexElementIndex, ExclusionIndices, InsertIndexSorted(AncestorContextIndices, elementIndex), ExcludesComments);
    }


    /// <summary>
    /// A copy of the set marked to exclude every comment node, regardless of whichever
    /// <see cref="XmlCanonicalizationAlgorithm"/> variant renders it afterwards — the effect
    /// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.3 step 4 requires of a same-document dereference
    /// whose fragment identifier is absent or is a bare-name (shortname) XPointer: "if the URI has no
    /// fragment identifier or the fragment identifier is a shortname XPointer, then delete all comment
    /// nodes." The mark operates at dereference time, before and independently of the algorithm variant
    /// applied afterwards: a with-comments algorithm rendering a comment-excluding set still renders no
    /// comments, while the same algorithm rendering a set built without this mark — for instance the
    /// scheme-based <c>#xpointer(/)</c> and <c>#xpointer(id(...))</c> forms section 4.3.3.2 names, which
    /// retain comments precisely so a with-comments algorithm can render them — renders them. Sets composed
    /// without this mark keep the rendering semantics unchanged: a comment renders exactly when the
    /// algorithm variant is with-comments.
    /// </summary>
    /// <returns>The composed set, excluding every comment node.</returns>
    public XmlNodeSet WithoutComments()
    {
        return new XmlNodeSet(Table!, IsWholeDocument, ApexElementIndex, ExclusionIndices, AncestorContextIndices, excludesComments: true);
    }


    /// <summary>The number of excluded subtrees.</summary>
    internal int ExclusionCount => ExclusionIndices?.Length ?? 0;

    /// <summary>The number of ancestor-context elements.</summary>
    internal int AncestorContextCount => AncestorContextIndices?.Length ?? 0;


    /// <summary>
    /// The excluded subtree apex index at the given ordinal.
    /// </summary>
    /// <param name="ordinal">The ordinal, less than <see cref="ExclusionCount"/>.</param>
    /// <returns>The excluded element index.</returns>
    internal int ExclusionAt(int ordinal)
    {
        return ExclusionIndices![ordinal];
    }


    /// <summary>
    /// The ancestor-context element index at the given ordinal.
    /// </summary>
    /// <param name="ordinal">The ordinal, less than <see cref="AncestorContextCount"/>.</param>
    /// <returns>The ancestor-context element index.</returns>
    internal int AncestorContextAt(int ordinal)
    {
        return AncestorContextIndices![ordinal];
    }


    /// <summary>
    /// Tells whether the set marks nodes of the given table instance.
    /// </summary>
    /// <param name="table">The table to check against.</param>
    /// <returns><see langword="true"/> when the set was constructed over the same table.</returns>
    internal bool IsOver(XmlNodeTable table)
    {
        return ReferenceEquals(Table, table);
    }


    /// <summary>
    /// Tells whether an element is the apex of one of the set's excluded subtrees — the same membership
    /// question <see cref="XmlCanonicalRenderer"/> asks while walking the set, exposed here for other
    /// set-membership-aware consumers such as the reference-processing/transform-chain engine's base64
    /// text-node selection, which must skip an excluded subtree exactly as rendering does.
    /// </summary>
    /// <param name="elementIndex">The element to test.</param>
    /// <returns><see langword="true"/> when the element is an exclusion apex.</returns>
    internal bool IsExcludedElement(int elementIndex)
    {
        for(int i = 0; i < ExclusionCount; ++i)
        {
            if(ExclusionAt(i) == elementIndex)
            {
                return true;
            }
        }

        return false;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XmlNodeSet other) =>
        ReferenceEquals(Table, other.Table)
        && IsWholeDocument == other.IsWholeDocument
        && ApexElementIndex == other.ApexElementIndex
        && ExcludesComments == other.ExcludesComments
        && AreIndexArraysEqual(ExclusionIndices, other.ExclusionIndices)
        && AreIndexArraysEqual(AncestorContextIndices, other.AncestorContextIndices);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XmlNodeSet other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Table is null ? 0 : RuntimeHelpers.GetHashCode(Table));
        hash.Add(IsWholeDocument);
        hash.Add(ApexElementIndex);
        hash.Add(ExcludesComments);
        AddIndexArray(ref hash, ExclusionIndices);
        AddIndexArray(ref hash, AncestorContextIndices);

        return hash.ToHashCode();
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XmlNodeSet left, XmlNodeSet right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XmlNodeSet left, XmlNodeSet right) => !left.Equals(right);


    /// <summary>
    /// A copy of an index array with one more index in its sorted position, or the array unchanged when
    /// the index is already present — the normalized representation the set's value equality relies on:
    /// ascending order without duplicates makes sequence equality set equality. Insertions copy because
    /// the arrays are shared between the set and its copies.
    /// </summary>
    /// <param name="indices">The existing sorted indices, or <see langword="null"/> for none.</param>
    /// <param name="index">The index to insert.</param>
    /// <returns>The array holding the index in sorted position.</returns>
    private static int[] InsertIndexSorted(int[]? indices, int index)
    {
        if(indices is null)
        {
            return [index];
        }

        int position = indices.AsSpan().BinarySearch(index);
        if(position >= 0)
        {
            return indices;
        }

        int insertion = ~position;
        int[] inserted = new int[indices.Length + 1];
        indices.AsSpan(0, insertion).CopyTo(inserted);
        inserted[insertion] = index;
        indices.AsSpan(insertion).CopyTo(inserted.AsSpan(insertion + 1));

        return inserted;
    }


    /// <summary>
    /// Tells whether two index arrays hold the same indices in the same order, a missing array equal to an
    /// empty one.
    /// </summary>
    /// <param name="left">The left array, or <see langword="null"/>.</param>
    /// <param name="right">The right array, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the sequences match.</returns>
    private static bool AreIndexArraysEqual(int[]? left, int[]? right)
    {
        ReadOnlySpan<int> leftIndices = left ?? [];
        ReadOnlySpan<int> rightIndices = right ?? [];

        return leftIndices.SequenceEqual(rightIndices);
    }


    /// <summary>
    /// Accumulates the indices of an array into a hash, a missing array contributing nothing.
    /// </summary>
    /// <param name="hash">The hash accumulator.</param>
    /// <param name="indices">The indices, or <see langword="null"/>.</param>
    private static void AddIndexArray(ref HashCode hash, int[]? indices)
    {
        foreach(int index in indices ?? [])
        {
            hash.Add(index);
        }
    }
}
