using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The <c>XAdESTimeStampType</c> data type of clause 5.1.4.4.1: a restriction of the abstract
/// <c>GenericTimeStampType</c> (clause 5.1.4.3) fixing its content to zero-or-more <c>Include</c> elements
/// (XA-5.1.4.4.2.1-1/-2, in document order — <see cref="Includes"/> preserves it, since that order fixes the
/// message-imprint concatenation order, XA-5.1.4.4.2.3-4), an optional <c>ds:CanonicalizationMethod</c>, then
/// one-or-more <c>EncapsulatedTimeStamp</c>/<c>XMLTimeStamp</c> entries in any combination — verified against
/// the acquired v132 XSD's <c>xsd:restriction</c> (XA-5.1.4.4.1-2): the trailing
/// choice carries no explicit <c>minOccurs</c>, so it defaults to the XSD rule of exactly one, applied
/// <c>maxOccurs="unbounded"</c> times — one-or-more, not zero-or-more. Backs every concrete time-stamp
/// qualifying property this leaf declares of this type (<c>SignatureTimeStamp</c>,
/// <c>AllDataObjectsTimeStamp</c>, <c>IndividualDataObjectsTimeStamp</c>, <c>ArchiveTimeStamp</c> and others),
/// so <see cref="TryRead"/> does not itself check the wrapping element's local name — the caller has already
/// recognized it, the posture every other multiply-instantiated auxiliary type in this leaf takes.
/// </summary>
public readonly struct XAdESTimeStamp: IEquatable<XAdESTimeStamp>
{
    /// <summary>
    /// The maximum number of <c>Include</c> children <see cref="TryRead"/> accepts under one time-stamp
    /// container before refusing with <see cref="XAdESReadFailure.EntryCountLimitExceeded"/> — a documented
    /// hardening bound: clause 5.1.4.4.2.1's <c>maxOccurs="unbounded"</c> sets no numeric limit, and every
    /// <c>Include</c> both feeds the message-imprint reconstruction engines and, in the
    /// <c>referencedData="true"</c> case, drives a full nested reference-processing pass. Chosen generously
    /// above the number of signed data objects any legitimate signature would explicitly select;
    /// <c>XAdESGrowthBoundsCostTests.IncludeFloodIsRefusedWithNoPooledRent</c> measures a flood one entry past
    /// this bound refusing with no pooled rent, since an <c>Include</c> entry carries no pooled content on any path.
    /// </summary>
    public const int MaximumIncludeCount = 4096;

    /// <summary>The table the value's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The wrapping element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>The <c>Include</c> children, in document order; empty when the implicit mechanism applies (XA-5.1.4.4.1-4).</summary>
    public IReadOnlyList<XAdESInclude> Includes { get; }

    /// <summary>Whether the optional <c>ds:CanonicalizationMethod</c> child is present.</summary>
    public bool HasCanonicalizationMethod { get; }

    /// <summary>The <c>ds:CanonicalizationMethod</c> child, meaningful only when <see cref="HasCanonicalizationMethod"/> is <see langword="true"/>.</summary>
    public XmlCanonicalizationMethodInfo CanonicalizationMethod { get; }

    /// <summary>The one-or-more <c>EncapsulatedTimeStamp</c>/<c>XMLTimeStamp</c> entries, in document order.</summary>
    public IReadOnlyList<XAdESTimeStampEntry> TimeStamps { get; }


    private XAdESTimeStamp(
        XmlNodeTable table,
        int elementIndex,
        bool hasId,
        int idAttributeOrdinal,
        IReadOnlyList<XAdESInclude> includes,
        bool hasCanonicalizationMethod,
        XmlCanonicalizationMethodInfo canonicalizationMethod,
        IReadOnlyList<XAdESTimeStampEntry> timeStamps)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        Includes = includes;
        HasCanonicalizationMethod = hasCanonicalizationMethod;
        CanonicalizationMethod = canonicalizationMethod;
        TimeStamps = timeStamps;
    }


    /// <summary>
    /// Reads an <c>XAdESTimeStampType</c>-shaped element: zero-or-more <c>Include</c>, an optional
    /// <c>ds:CanonicalizationMethod</c>, then one-or-more <c>EncapsulatedTimeStamp</c>/<c>XMLTimeStamp</c>
    /// entries, in that fixed order.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>XAdESTimeStampType</c>-typed element.</param>
    /// <param name="pool">The pool an <c>EncapsulatedTimeStamp</c>'s decoded content is rented from.</param>
    /// <param name="owned">The caller's custody list. An <c>EncapsulatedTimeStamp</c>'s decoded content is
    /// appended as it is read, including on paths that subsequently refuse — the caller must dispose the
    /// list when this method returns <see langword="false"/>.</param>
    /// <param name="value">The read model on success.</param>
    /// <param name="error">The refusal on failure.</param>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out XAdESTimeStamp value, out XAdESReadError error)
    {
        value = default;
        bool hasId = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Id"u8, out int idOrdinal);
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, hasId ? 1 : 0, out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        var includes = new List<XAdESInclude>();
        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
        if(scan == ElementScanResult.UnexpectedContent)
        {
            error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        while(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "Include"u8))
        {
            if(!XAdESInclude.TryRead(table, child, out XAdESInclude include, out error))
            {
                return false;
            }

            includes.Add(include);
            if(includes.Count > MaximumIncludeCount)
            {
                error = new XAdESReadError(XAdESReadFailure.EntryCountLimitExceeded, 0);

                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
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

        var timeStamps = new List<XAdESTimeStampEntry>();
        while(scan == ElementScanResult.Found && XAdESGenericTimeStamp.IsChoiceMember(table, child))
        {
            if(!XAdESGenericTimeStamp.TryReadChoiceMember(table, child, pool, owned, out XAdESTimeStampEntry entry, out error))
            {
                return false;
            }

            timeStamps.Add(entry);
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        if(timeStamps.Count == 0)
        {
            //Nothing matched the mandatory one-or-more choice: EndOfChildren means it is genuinely absent
            //(MissingRequiredChild); scan==Found means some other named element — including an out-of-order
            //Include or a second CanonicalizationMethod — sits where the content model requires a choice
            //member instead.
            error = new XAdESReadError(
                scan != ElementScanResult.Found ? XAdESReadFailure.MissingRequiredChild : DetermineExcessElementFailure(table, child, hasCanonicalizationMethod), 0);

            return false;
        }

        if(scan == ElementScanResult.Found)
        {
            error = new XAdESReadError(DetermineExcessElementFailure(table, child, hasCanonicalizationMethod), 0);

            return false;
        }

        value = new XAdESTimeStamp(table, elementIndex, hasId, idOrdinal, includes, hasCanonicalizationMethod, canonicalizationMethod, timeStamps);
        error = default;

        return true;
    }


    /// <summary>
    /// Chooses the reason an element sits at a position the content model does not declare it for: a repeat
    /// of the already-consumed singular <c>ds:CanonicalizationMethod</c> slot is a duplicate; anything else —
    /// including an out-of-order <c>Include</c> — is unknown at this position.
    /// </summary>
    private static XAdESReadFailure DetermineExcessElementFailure(XmlNodeTable table, int elementIndex, bool hasCanonicalizationMethod)
    {
        return hasCanonicalizationMethod && XmlSignatureModelGrammar.IsDsElement(table, elementIndex, "CanonicalizationMethod"u8)
            ? XAdESReadFailure.DuplicateCoreChild
            : XAdESReadFailure.UnknownCoreElement;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESTimeStamp other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESTimeStamp other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESTimeStamp left, XAdESTimeStamp right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESTimeStamp left, XAdESTimeStamp right) => !left.Equals(right);
}
