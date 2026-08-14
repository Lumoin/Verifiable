using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The <c>OtherTimeStampType</c> data type of clause 5.1.4.5: a restriction of the abstract
/// <c>GenericTimeStampType</c> (clause 5.1.4.3) fixing its content to one-or-more <c>ReferenceInfo</c>
/// elements, an optional <c>ds:CanonicalizationMethod</c>, then EXACTLY ONE
/// <c>EncapsulatedTimeStamp</c>/<c>XMLTimeStamp</c> entry — a schema-only cardinality asymmetry with
/// <c>XAdESTimeStampType</c>'s own one-or-more choice, confirmed against the acquired v132 XSD (the
/// trailing choice here carries neither an explicit <c>minOccurs</c> nor <c>maxOccurs</c>, so
/// both default to one, unlike <c>XAdESTimeStampType</c>'s own <c>maxOccurs="unbounded"</c>).
/// </summary>
/// <remarks>
/// Modeled at GRAMMAR level only: clause 5.1.4.2's container list — the
/// enumeration of every time-stamp qualifying property this specification defines — names only
/// <c>XAdESTimeStampType</c> instances (<c>AllDataObjectsTimeStamp</c>, <c>IndividualDataObjectsTimeStamp</c>,
/// <c>SignatureTimeStamp</c>, <c>ArchiveTimeStamp</c>, <c>SigAndRefsTimeStampV2</c>,
/// <c>RefsOnlyTimeStampV2</c>); no Part-1 qualifying property instantiates <c>OtherTimeStampType</c>. This
/// type therefore has no message-imprint-input processing engine of its own — <see cref="TryRead"/> exists
/// to prove the grammar shape against the schema and to let a future property that DOES instantiate it read
/// structurally without further reader work, should one ever be found.
/// </remarks>
public readonly struct XAdESOtherTimeStamp: IEquatable<XAdESOtherTimeStamp>
{
    /// <summary>The table the value's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The wrapping element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>The one-or-more <c>ReferenceInfo</c> children, in document order.</summary>
    public IReadOnlyList<XAdESReferenceInfo> ReferenceInfos { get; }

    /// <summary>Whether the optional <c>ds:CanonicalizationMethod</c> child is present.</summary>
    public bool HasCanonicalizationMethod { get; }

    /// <summary>The <c>ds:CanonicalizationMethod</c> child, meaningful only when <see cref="HasCanonicalizationMethod"/> is <see langword="true"/>.</summary>
    public XmlCanonicalizationMethodInfo CanonicalizationMethod { get; }

    /// <summary>The exactly-one <c>EncapsulatedTimeStamp</c>/<c>XMLTimeStamp</c> entry.</summary>
    public XAdESTimeStampEntry TimeStamp { get; }


    private XAdESOtherTimeStamp(
        XmlNodeTable table,
        int elementIndex,
        bool hasId,
        int idAttributeOrdinal,
        IReadOnlyList<XAdESReferenceInfo> referenceInfos,
        bool hasCanonicalizationMethod,
        XmlCanonicalizationMethodInfo canonicalizationMethod,
        XAdESTimeStampEntry timeStamp)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        ReferenceInfos = referenceInfos;
        HasCanonicalizationMethod = hasCanonicalizationMethod;
        CanonicalizationMethod = canonicalizationMethod;
        TimeStamp = timeStamp;
    }


    /// <summary>
    /// Reads an <c>OtherTimeStampType</c>-shaped element: one-or-more <c>ReferenceInfo</c>, an optional
    /// <c>ds:CanonicalizationMethod</c>, then exactly one <c>EncapsulatedTimeStamp</c>/<c>XMLTimeStamp</c>
    /// entry, in that fixed order.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>OtherTimeStampType</c>-typed element.</param>
    /// <param name="pool">The pool a decoded digest value or <c>EncapsulatedTimeStamp</c> content is rented from.</param>
    /// <param name="owned">The caller's custody list. Decoded content is appended as it is read, including
    /// on paths that subsequently refuse — the caller must dispose the list when this method returns
    /// <see langword="false"/>.</param>
    /// <param name="value">The read model on success.</param>
    /// <param name="error">The refusal on failure.</param>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out XAdESOtherTimeStamp value, out XAdESReadError error)
    {
        value = default;
        bool hasId = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Id"u8, out int idOrdinal);
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, hasId ? 1 : 0, out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        var referenceInfos = new List<XAdESReferenceInfo>();
        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
        if(scan == ElementScanResult.UnexpectedContent)
        {
            error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        while(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "ReferenceInfo"u8))
        {
            if(!XAdESReferenceInfo.TryRead(table, child, pool, owned, out XAdESReferenceInfo referenceInfo, out error))
            {
                return false;
            }

            referenceInfos.Add(referenceInfo);
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        if(referenceInfos.Count == 0)
        {
            //ReferenceInfo is the type's first required position, with no optional phase preceding it —
            //the same "wrong element in the mandatory-first slot" shape XAdESObjectIdentifier's Identifier
            //and XAdESDigestAlgAndValue's DigestMethod classify as MissingRequiredChild, whether the scan
            //found a differently-named element or nothing at all (UnexpectedContent already returned above).
            error = new XAdESReadError(XAdESReadFailure.MissingRequiredChild, 0);

            return false;
        }

        bool hasCanonicalizationMethod = false;
        XmlCanonicalizationMethodInfo canonicalizationMethod = default;
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsDsElement(table, child, "CanonicalizationMethod"u8))
        {
            if(!XmlCanonicalizationMethodInfo.TryRead(table, child, out canonicalizationMethod, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            hasCanonicalizationMethod = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        if(scan != ElementScanResult.Found || !XAdESGenericTimeStamp.IsChoiceMember(table, child))
        {
            error = new XAdESReadError(
                scan != ElementScanResult.Found
                    ? XAdESReadFailure.MissingRequiredChild
                    : hasCanonicalizationMethod && XmlSignatureModelGrammar.IsDsElement(table, child, "CanonicalizationMethod"u8)
                        ? XAdESReadFailure.DuplicateCoreChild
                        : XAdESReadFailure.UnknownCoreElement,
                0);

            return false;
        }

        if(!XAdESGenericTimeStamp.TryReadChoiceMember(table, child, pool, owned, out XAdESTimeStampEntry timeStamp, out error))
        {
            return false;
        }

        //Exactly one: a further choice member (or any other trailing element) exceeds OtherTimeStampType's
        //own cardinality, unlike XAdESTimeStampType's unbounded repetition of the same choice.
        scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out int trailing);
        if(scan != ElementScanResult.EndOfChildren)
        {
            error = new XAdESReadError(scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.UnknownCoreElement, 0);
            _ = trailing;

            return false;
        }

        value = new XAdESOtherTimeStamp(table, elementIndex, hasId, idOrdinal, referenceInfos, hasCanonicalizationMethod, canonicalizationMethod, timeStamp);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESOtherTimeStamp other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESOtherTimeStamp other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESOtherTimeStamp left, XAdESOtherTimeStamp right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESOtherTimeStamp left, XAdESOtherTimeStamp right) => !left.Equals(right);
}
