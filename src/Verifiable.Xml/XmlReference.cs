using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The <c>InclusiveNamespaces</c> child and <c>XPath</c> child a <c>Transform</c> or
/// <c>CanonicalizationMethod</c> element carries structurally, and the <c>Transform</c>'s own algorithm —
/// section 4.3.3.4 of
/// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
/// (Second Edition)</see> together with section 4.2 of
/// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
/// 1.0</see>.
/// </summary>
/// <remarks>
/// Reading captures the parameters structurally without interpreting them: the <c>InclusiveNamespaces
/// PrefixList</c> attribute value is exposed as written, un-tokenized (the reference-processing engine
/// tokenizes it when the exclusive canonicalization algorithm actually runs), and the <c>XPath</c> child's
/// character content is exposed as the coalesced text of its single text node. Every other <c>##other</c>
/// child a <c>Transform</c> carries — an algorithm parameter this leaf does not recognize — is tolerated
/// and left unmodeled, per the choice content model section 4.3.3.4 declares.
/// </remarks>
public readonly struct XmlTransform: IEquatable<XmlTransform>
{
    /// <summary>The table the transform's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>Transform</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>The attribute ordinal of the mandatory <c>Algorithm</c> attribute.</summary>
    private int AlgorithmAttributeOrdinal { get; }

    /// <summary>The transform's <c>Algorithm</c> URI, exact-character.</summary>
    public ReadOnlySpan<byte> Algorithm => Table.AttributeValueOf(ElementIndex, AlgorithmAttributeOrdinal);

    /// <summary>
    /// Whether an <c>ec:InclusiveNamespaces</c> child (namespace
    /// <see cref="XmlSignatureIdentifiers.ExclusiveCanonicalXml10Uri"/>) is present, per section 4.2 of
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see>.
    /// </summary>
    public bool HasInclusiveNamespaces { get; }

    /// <summary>The <c>InclusiveNamespaces</c> element's own index, or -1 when absent.</summary>
    public int InclusiveNamespacesElementIndex { get; }

    /// <summary>The attribute ordinal of <c>InclusiveNamespaces</c>'s optional <c>PrefixList</c> attribute, or -1 when absent.</summary>
    private int PrefixListAttributeOrdinal { get; }

    /// <summary>
    /// The <c>PrefixList</c> attribute value as written, a white-space-separated list of namespace prefixes
    /// and/or the <c>#default</c> token — un-tokenized; empty when <see cref="HasInclusiveNamespaces"/> is
    /// <see langword="false"/> or the attribute itself is absent.
    /// </summary>
    public ReadOnlySpan<byte> PrefixList => HasInclusiveNamespaces && PrefixListAttributeOrdinal >= 0
        ? Table.AttributeValueOf(InclusiveNamespacesElementIndex, PrefixListAttributeOrdinal)
        : ReadOnlySpan<byte>.Empty;

    /// <summary>
    /// Whether a <c>ds:XPath</c> child is present — the character-content parameter of the section 6.6.3
    /// XPath filtering transform.
    /// </summary>
    public bool HasXPath { get; }

    /// <summary>The <c>XPath</c> element's own index, or -1 when absent.</summary>
    public int XPathElementIndex { get; }

    /// <summary>The <c>XPath</c> child's single text node index, or -1 for empty/absent content.</summary>
    private int XPathTextNodeIndex { get; }

    /// <summary>The <c>XPath</c> child's character content.</summary>
    public ReadOnlySpan<byte> XPathContent => XPathTextNodeIndex >= 0 ? Table.ValueOf(XPathTextNodeIndex) : ReadOnlySpan<byte>.Empty;


    /// <summary>
    /// Creates the transform model over its read parts.
    /// </summary>
    internal XmlTransform(
        XmlNodeTable table,
        int elementIndex,
        int algorithmAttributeOrdinal,
        bool hasInclusiveNamespaces,
        int inclusiveNamespacesElementIndex,
        int prefixListAttributeOrdinal,
        bool hasXPath,
        int xPathElementIndex,
        int xPathTextNodeIndex)
    {
        Table = table;
        ElementIndex = elementIndex;
        AlgorithmAttributeOrdinal = algorithmAttributeOrdinal;
        HasInclusiveNamespaces = hasInclusiveNamespaces;
        InclusiveNamespacesElementIndex = inclusiveNamespacesElementIndex;
        PrefixListAttributeOrdinal = prefixListAttributeOrdinal;
        HasXPath = hasXPath;
        XPathElementIndex = xPathElementIndex;
        XPathTextNodeIndex = xPathTextNodeIndex;
    }


    /// <summary>
    /// Reads one <c>Transform</c> element: its mandatory <c>Algorithm</c> attribute and its optional
    /// <c>InclusiveNamespaces</c>/<c>XPath</c> children.
    /// </summary>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, out XmlTransform transform, out XmlSignatureReadError error)
    {
        if(!XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Algorithm"u8, out int algorithmOrdinal))
        {
            transform = default;
            error = new XmlSignatureReadError(XmlSignatureReadFailure.MissingRequiredAttribute, 0);

            return false;
        }

        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 1, out error))
        {
            transform = default;

            return false;
        }

        bool hasInclusiveNamespaces = false;
        int inclusiveNamespacesElementIndex = -1;
        int prefixListOrdinal = -1;
        bool hasXPath = false;
        int xPathElementIndex = -1;
        int xPathTextNodeIndex = -1;

        List<int> children = XmlSignatureModelGrammar.GatherElementChildrenLoosely(table, elementIndex);
        foreach(int child in children)
        {
            if(XmlSignatureModelGrammar.IsDsElement(table, child, "XPath"u8))
            {
                if(hasXPath)
                {
                    transform = default;
                    error = new XmlSignatureReadError(XmlSignatureReadFailure.DuplicateCoreChild, 0);

                    return false;
                }

                if(!XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, child, out xPathTextNodeIndex, out error))
                {
                    transform = default;

                    return false;
                }

                hasXPath = true;
                xPathElementIndex = child;

                continue;
            }

            if(XmlSignatureModelGrammar.IsElement(table, child, XmlSignatureIdentifiers.ExclusiveCanonicalXml10UriUtf8, "InclusiveNamespaces"u8))
            {
                if(hasInclusiveNamespaces)
                {
                    transform = default;
                    error = new XmlSignatureReadError(XmlSignatureReadFailure.DuplicateCoreChild, 0);

                    return false;
                }

                hasInclusiveNamespaces = true;
                inclusiveNamespacesElementIndex = child;
                _ = XmlSignatureModelGrammar.TryFindAttribute(table, child, "PrefixList"u8, out prefixListOrdinal);
            }
        }

        transform = new XmlTransform(table, elementIndex, algorithmOrdinal, hasInclusiveNamespaces, inclusiveNamespacesElementIndex, prefixListOrdinal, hasXPath, xPathElementIndex, xPathTextNodeIndex);
        error = default;

        return true;
    }


    /// <summary>
    /// Reads one <c>Transforms</c> element's <c>Transform+</c> children, per section 4.3.3.4.
    /// </summary>
    internal static bool TryReadList(XmlNodeTable table, int transformsElementIndex, out List<XmlTransform> transforms, out XmlSignatureReadError error)
    {
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, transformsElementIndex, 0, out error))
        {
            transforms = [];

            return false;
        }

        if(!XmlSignatureModelGrammar.TryReadElementChildren(table, transformsElementIndex, out List<int> children, out error))
        {
            transforms = [];

            return false;
        }

        if(children.Count == 0)
        {
            transforms = [];
            error = new XmlSignatureReadError(XmlSignatureReadFailure.MissingRequiredChild, 0);

            return false;
        }

        transforms = new List<XmlTransform>(children.Count);
        foreach(int child in children)
        {
            if(!XmlSignatureModelGrammar.IsDsElement(table, child, "Transform"u8))
            {
                error = new XmlSignatureReadError(XmlSignatureReadFailure.UnknownCoreElement, 0);

                return false;
            }

            if(!TryRead(table, child, out XmlTransform transform, out error))
            {
                return false;
            }

            transforms.Add(transform);
        }

        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XmlTransform other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XmlTransform other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XmlTransform left, XmlTransform right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XmlTransform left, XmlTransform right) => !left.Equals(right);
}


/// <summary>
/// One <c>ds:Reference</c> element: its <c>Id</c>/<c>URI</c>/<c>Type</c> attributes, its optional
/// <c>Transforms</c> chain, its <c>DigestMethod</c> algorithm and its decoded <c>DigestValue</c> octets —
/// section 4.3.3 of
/// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
/// (Second Edition)</see>.
/// </summary>
public readonly struct XmlReference: IEquatable<XmlReference>
{
    /// <summary>The table the reference's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>Reference</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>
    /// Whether the optional <c>URI</c> attribute is present. Its absence is the section 4.3.3.1
    /// "application context" case this library refuses during reference processing
    /// (<see cref="XmlSignatureProcessingFailure.UriOmitted"/>); the structural reader still models it.
    /// </summary>
    public bool HasUri { get; }

    private int UriAttributeOrdinal { get; }

    /// <summary>The <c>URI</c> attribute value.</summary>
    public ReadOnlySpan<byte> Uri => HasUri ? Table.AttributeValueOf(ElementIndex, UriAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>Whether the optional, advisory <c>Type</c> attribute is present.</summary>
    public bool HasType { get; }

    private int TypeAttributeOrdinal { get; }

    /// <summary>The <c>Type</c> attribute value.</summary>
    public ReadOnlySpan<byte> Type => HasType ? Table.AttributeValueOf(ElementIndex, TypeAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>The reference's transform chain, in document order; empty when no <c>Transforms</c> element is present.</summary>
    public IReadOnlyList<XmlTransform> Transforms { get; }

    /// <summary>The <c>DigestMethod</c> element's own index.</summary>
    public int DigestMethodElementIndex { get; }

    private int DigestMethodAlgorithmAttributeOrdinal { get; }

    /// <summary>The <c>DigestMethod</c>'s <c>Algorithm</c> URI, exact-character.</summary>
    public ReadOnlySpan<byte> DigestMethodAlgorithm => Table.AttributeValueOf(DigestMethodElementIndex, DigestMethodAlgorithmAttributeOrdinal);

    /// <summary>The <c>DigestValue</c> element's own index.</summary>
    public int DigestValueElementIndex { get; }

    /// <summary>
    /// The decoded <c>DigestValue</c> octets, tagged <see cref="BufferTags.XmlDecodedContent"/>. Owned by
    /// the enclosing <see cref="XmlSignature"/> or <see cref="XmlManifest"/> and released on its
    /// <see cref="IDisposable.Dispose"/>.
    /// </summary>
    public PooledMemory DigestValueOctets { get; }


    /// <summary>
    /// Creates the reference model over its read parts.
    /// </summary>
    private XmlReference(
        XmlNodeTable table,
        int elementIndex,
        bool hasId,
        int idAttributeOrdinal,
        bool hasUri,
        int uriAttributeOrdinal,
        bool hasType,
        int typeAttributeOrdinal,
        IReadOnlyList<XmlTransform> transforms,
        int digestMethodElementIndex,
        int digestMethodAlgorithmAttributeOrdinal,
        int digestValueElementIndex,
        PooledMemory digestValueOctets)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        HasUri = hasUri;
        UriAttributeOrdinal = uriAttributeOrdinal;
        HasType = hasType;
        TypeAttributeOrdinal = typeAttributeOrdinal;
        Transforms = transforms;
        DigestMethodElementIndex = digestMethodElementIndex;
        DigestMethodAlgorithmAttributeOrdinal = digestMethodAlgorithmAttributeOrdinal;
        DigestValueElementIndex = digestValueElementIndex;
        DigestValueOctets = digestValueOctets;
    }


    /// <summary>
    /// Reads one <c>Reference</c> element: its attributes, its optional <c>Transforms</c> child, its
    /// mandatory <c>DigestMethod</c> and <c>DigestValue</c> children, in that order.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>Reference</c> element.</param>
    /// <param name="pool">The pool the decoded <c>DigestValue</c> octets are rented from.</param>
    /// <param name="owned">The custody list the decoded octets are added to.</param>
    /// <param name="reference">The read reference on success.</param>
    /// <param name="error">The refusal on failure.</param>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out XmlReference reference, out XmlSignatureReadError error)
    {
        reference = default;
        bool hasId = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Id"u8, out int idOrdinal);
        bool hasUri = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "URI"u8, out int uriOrdinal);
        bool hasType = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Type"u8, out int typeOrdinal);
        int knownAttributeCount = (hasId ? 1 : 0) + (hasUri ? 1 : 0) + (hasType ? 1 : 0);
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, knownAttributeCount, out error))
        {
            return false;
        }

        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
        if(scan == ElementScanResult.UnexpectedContent)
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        if(scan != ElementScanResult.Found)
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.MissingRequiredChild, 0);

            return false;
        }

        List<XmlTransform> transforms = [];
        if(XmlSignatureModelGrammar.IsDsElement(table, child, "Transforms"u8))
        {
            if(!XmlTransform.TryReadList(table, child, out transforms, out error))
            {
                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XmlSignatureReadError(XmlSignatureReadFailure.UnexpectedElementContent, 0);

                return false;
            }

            if(scan != ElementScanResult.Found)
            {
                error = new XmlSignatureReadError(XmlSignatureReadFailure.MissingRequiredChild, 0);

                return false;
            }
        }

        if(!XmlSignatureModelGrammar.IsDsElement(table, child, "DigestMethod"u8))
        {
            //A second Transforms child lands here too (it is never DigestMethod): section 4.3.3's content
            //model permits Transforms? at most once, so a repeat is DuplicateCoreChild, not an unrelated
            //unknown element.
            error = new XmlSignatureReadError(
                XmlSignatureModelGrammar.IsDsElement(table, child, "Transforms"u8) ? XmlSignatureReadFailure.DuplicateCoreChild : XmlSignatureReadFailure.UnknownCoreElement, 0);

            return false;
        }

        int digestMethodElementIndex = child;
        if(!XmlSignatureModelGrammar.TryFindAttribute(table, digestMethodElementIndex, "Algorithm"u8, out int digestAlgorithmOrdinal))
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.MissingRequiredAttribute, 0);

            return false;
        }

        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, digestMethodElementIndex, 1, out error))
        {
            return false;
        }

        scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, digestMethodElementIndex, out int digestValueElementIndex);
        if(scan == ElementScanResult.UnexpectedContent)
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsDsElement(table, digestValueElementIndex, "DigestValue"u8))
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.MissingRequiredChild, 0);

            return false;
        }

        if(!XmlSignatureModelGrammar.TryDecodeSimpleBase64Content(table, digestValueElementIndex, pool, owned, out PooledMemory? digestValueOctets, out error))
        {
            return false;
        }

        scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, digestValueElementIndex, out int trailing);
        if(scan != ElementScanResult.EndOfChildren)
        {
            error = new XmlSignatureReadError(
                scan == ElementScanResult.UnexpectedContent ? XmlSignatureReadFailure.UnexpectedElementContent : XmlSignatureReadFailure.UnknownCoreElement, 0);
            _ = trailing;

            return false;
        }

        reference = new XmlReference(table, elementIndex, hasId, idOrdinal, hasUri, uriOrdinal, hasType, typeOrdinal, transforms, digestMethodElementIndex, digestAlgorithmOrdinal, digestValueElementIndex, digestValueOctets!);
        error = default;

        return true;
    }


    /// <summary>
    /// Reads a <c>Reference+</c> sequence starting from an already-located first <c>Reference</c> element —
    /// <c>SignedInfo</c>'s trailing children after <c>CanonicalizationMethod</c> and <c>SignatureMethod</c>,
    /// or <c>Manifest</c>'s whole child list, per section 4.3 and section 5.1.
    /// </summary>
    internal static bool TryReadSequence(XmlNodeTable table, int firstReferenceElementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out List<XmlReference> references, out XmlSignatureReadError error)
    {
        references = [];
        int current = firstReferenceElementIndex;
        while(current >= 0)
        {
            if(!XmlSignatureModelGrammar.IsDsElement(table, current, "Reference"u8))
            {
                error = new XmlSignatureReadError(XmlSignatureReadFailure.UnknownCoreElement, 0);

                return false;
            }

            if(!TryRead(table, current, pool, owned, out XmlReference reference, out error))
            {
                return false;
            }

            references.Add(reference);
            ElementScanResult scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, current, out int next);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XmlSignatureReadError(XmlSignatureReadFailure.UnexpectedElementContent, 0);

                return false;
            }

            current = scan == ElementScanResult.Found ? next : -1;
        }

        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XmlReference other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XmlReference other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XmlReference left, XmlReference right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XmlReference left, XmlReference right) => !left.Equals(right);
}
