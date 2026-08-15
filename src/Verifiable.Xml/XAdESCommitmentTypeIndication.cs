using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// Which arm of <c>CommitmentTypeIndicationType</c>'s <c>ObjectReference</c>/<c>AllSignedDataObjects</c>
/// choice (clause 5.2.3) a <see cref="XAdESCommitmentTypeIndication"/> holds.
/// </summary>
public enum XAdESCommitmentTypeIndicationChoice
{
    /// <summary>One-or-more <c>ObjectReference</c> elements name the signed data object subset the commitment applies to.</summary>
    ObjectReferences,

    /// <summary>The empty <c>AllSignedDataObjects</c> marker: the commitment applies to the complete set of signed data objects.</summary>
    AllSignedDataObjects
}


/// <summary>
/// The <c>CommitmentTypeIndication</c> qualifying property of clause 5.2.3: a signed qualifying property that
/// qualifies signed data object(s), indicating one commitment the signer made — a <c>CommitmentTypeId</c>
/// (the shared <c>ObjectIdentifierType</c> reader, narrowed by two extra prose rules this reader enforces:
/// the identifier is a bare URI, and its <c>Identifier</c> child shall not carry a <c>Qualifier</c> attribute),
/// then the <see cref="XAdESCommitmentTypeIndicationChoice"/> choice, then optional
/// <c>CommitmentTypeQualifiers</c>.
/// </summary>
/// <remarks>
/// Carries no owned pooled content of its own — every field is either a span computed from
/// <see cref="Table"/>, a nested <see cref="XAdESObjectIdentifier"/>, or an <see cref="XAdESUnmodeledContent"/>
/// list — so no <see cref="IDisposable"/> surface is needed.
/// </remarks>
public readonly struct XAdESCommitmentTypeIndication: IEquatable<XAdESCommitmentTypeIndication>
{
    /// <summary>The table the property's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>CommitmentTypeIndication</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>The <c>CommitmentTypeId</c> child, a URI-valued object identifier never carrying a <c>Qualifier</c>.</summary>
    public XAdESObjectIdentifier CommitmentTypeId { get; }

    /// <summary>Which arm of the <c>ObjectReference</c>/<c>AllSignedDataObjects</c> choice is present.</summary>
    public XAdESCommitmentTypeIndicationChoice Choice { get; }

    private IReadOnlyList<int> ObjectReferenceTextNodeIndices { get; }

    /// <summary>
    /// How many <c>ObjectReference</c> elements are present; at least one when <see cref="Choice"/> is
    /// <see cref="XAdESCommitmentTypeIndicationChoice.ObjectReferences"/>, zero otherwise.
    /// </summary>
    public int ObjectReferenceCount => ObjectReferenceTextNodeIndices.Count;

    /// <summary>The <c>anyURI</c> content of the <c>ObjectReference</c> at the given position, in document order.</summary>
    /// <param name="index">The zero-based position, less than <see cref="ObjectReferenceCount"/>.</param>
    public ReadOnlySpan<byte> ObjectReferenceAt(int index)
    {
        int textNodeIndex = ObjectReferenceTextNodeIndices[index];

        return textNodeIndex >= 0 ? Table.ValueOf(textNodeIndex) : ReadOnlySpan<byte>.Empty;
    }

    /// <summary>Whether the optional <c>CommitmentTypeQualifiers</c> child is present.</summary>
    public bool HasCommitmentTypeQualifiers { get; }

    /// <summary>
    /// The <c>CommitmentTypeQualifier</c> entries <c>CommitmentTypeQualifiers</c> carries (each <c>AnyType</c>),
    /// in document order; meaningful only when <see cref="HasCommitmentTypeQualifiers"/> is
    /// <see langword="true"/>, and possibly empty even then — the schema's own <c>CommitmentTypeQualifier</c>
    /// declares <c>minOccurs="0"</c>, unlike <c>SigPolicyQualifier</c> (clause 5.2.9.1).
    /// </summary>
    public IReadOnlyList<XAdESUnmodeledContent> CommitmentTypeQualifiers { get; }


    private XAdESCommitmentTypeIndication(
        XmlNodeTable table,
        int elementIndex,
        XAdESObjectIdentifier commitmentTypeId,
        XAdESCommitmentTypeIndicationChoice choice,
        IReadOnlyList<int> objectReferenceTextNodeIndices,
        bool hasCommitmentTypeQualifiers,
        IReadOnlyList<XAdESUnmodeledContent> commitmentTypeQualifiers)
    {
        Table = table;
        ElementIndex = elementIndex;
        CommitmentTypeId = commitmentTypeId;
        Choice = choice;
        ObjectReferenceTextNodeIndices = objectReferenceTextNodeIndices;
        HasCommitmentTypeQualifiers = hasCommitmentTypeQualifiers;
        CommitmentTypeQualifiers = commitmentTypeQualifiers;
    }


    /// <summary>
    /// Reads a <c>CommitmentTypeIndication</c> element: no attributes of its own, then <c>CommitmentTypeId</c>,
    /// the <c>ObjectReference</c>/<c>AllSignedDataObjects</c> choice, and optional
    /// <c>CommitmentTypeQualifiers</c>, in that fixed order.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>CommitmentTypeIndication</c> element — typically obtained from a
    /// <see cref="XAdESSignedDataObjectPropertyEntry"/> whose
    /// <see cref="XAdESSignedDataObjectPropertyEntry.Name"/> is
    /// <see cref="XAdESSignedDataObjectPropertyName.CommitmentTypeIndication"/>.</param>
    /// <param name="value">The read model on success.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESReadFailure.CommitmentTypeIdQualifierNotPermitted"/> when <c>CommitmentTypeId</c>'s
    /// <c>Identifier</c> carries a <c>Qualifier</c> attribute (clause 5.2.3's own restriction, narrower than
    /// <c>ObjectIdentifierType</c>'s general schema).</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryRead(XmlNodeTable table, int elementIndex, out XAdESCommitmentTypeIndication value, out XAdESReadError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        value = default;
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 0, out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
        if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "CommitmentTypeId"u8))
        {
            error = new XAdESReadError(
                scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

            return false;
        }

        if(!XAdESObjectIdentifier.TryRead(table, child, out XAdESObjectIdentifier commitmentTypeId, out error))
        {
            return false;
        }

        if(commitmentTypeId.HasQualifier)
        {
            error = new XAdESReadError(XAdESReadFailure.CommitmentTypeIdQualifierNotPermitted, 0);

            return false;
        }

        scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
        if(scan == ElementScanResult.UnexpectedContent)
        {
            error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        var objectReferenceTextNodeIndices = new List<int>();
        XAdESCommitmentTypeIndicationChoice choice;
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "ObjectReference"u8))
        {
            choice = XAdESCommitmentTypeIndicationChoice.ObjectReferences;
            while(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "ObjectReference"u8))
            {
                if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, child, 0, out grammarError)
                    || !XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, child, out int objectReferenceTextNodeIndex, out grammarError))
                {
                    error = XAdESGrammar.FromGrammarFailure(grammarError);

                    return false;
                }

                objectReferenceTextNodeIndices.Add(objectReferenceTextNodeIndex);
                scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
                if(scan == ElementScanResult.UnexpectedContent)
                {
                    error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                    return false;
                }
            }
        }
        else if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "AllSignedDataObjects"u8))
        {
            choice = XAdESCommitmentTypeIndicationChoice.AllSignedDataObjects;
            int markerElementIndex = child;
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, markerElementIndex, 0, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            //AllSignedDataObjects is the empty marker XA-5.2.3's schema names via a type-less element
            //declaration; only an actual element or non-whitespace text child makes it non-empty —
            //insignificant whitespace, comments and processing instructions are tolerated like everywhere
            //else in this leaf's grammar.
            ElementScanResult markerScan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, markerElementIndex, out _);
            if(markerScan != ElementScanResult.EndOfChildren)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, markerElementIndex, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }
        else
        {
            error = new XAdESReadError(
                scan == ElementScanResult.Found ? XAdESReadFailure.UnknownCoreElement : XAdESReadFailure.MissingRequiredChild, 0);

            return false;
        }

        bool hasCommitmentTypeQualifiers = false;
        var commitmentTypeQualifiers = new List<XAdESUnmodeledContent>();
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "CommitmentTypeQualifiers"u8))
        {
            int qualifiersElementIndex = child;
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, qualifiersElementIndex, 0, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            if(!XmlSignatureModelGrammar.TryReadElementChildren(table, qualifiersElementIndex, out List<int> qualifierElements, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            foreach(int qualifierElement in qualifierElements)
            {
                if(!XmlSignatureModelGrammar.IsElement(table, qualifierElement, XAdESIdentifiers.XAdESNamespaceV132Utf8, "CommitmentTypeQualifier"u8))
                {
                    error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

                    return false;
                }

                commitmentTypeQualifiers.Add(XAdESUnmodeledContent.Read(table, qualifierElement));
            }

            hasCommitmentTypeQualifiers = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, qualifiersElementIndex, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        if(scan == ElementScanResult.Found)
        {
            error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        value = new XAdESCommitmentTypeIndication(table, elementIndex, commitmentTypeId, choice, objectReferenceTextNodeIndices, hasCommitmentTypeQualifiers, commitmentTypeQualifiers);
        error = default;

        return true;
    }


    /// <summary>
    /// Verifies clause 5.2.3's cross-artifact rule that "each <c>ObjectReference</c> shall reference one
    /// <c>ds:Reference</c> element within the <c>ds:SignedInfo</c> element or within a signed
    /// <c>ds:Manifest</c> element": resolves every <see cref="ObjectReferenceAt"/> value against
    /// <paramref name="signature"/>. A <see cref="Choice"/> of
    /// <see cref="XAdESCommitmentTypeIndicationChoice.AllSignedDataObjects"/> has no <c>ObjectReference</c> to
    /// verify and always succeeds.
    /// </summary>
    /// <param name="table">The document both <paramref name="signature"/> and <paramref name="commitmentTypeIndication"/> were read from.</param>
    /// <param name="signature">The signature whose <c>ds:SignedInfo</c>/signed <c>ds:Manifest</c>s every <c>ObjectReference</c> must resolve within.</param>
    /// <param name="commitmentTypeIndication">The property whose <c>ObjectReference</c> values are verified.</param>
    /// <param name="error">The refusal on failure — see <see cref="XAdESObjectReferenceResolution.TryResolve"/> — or
    /// <see cref="XAdESProcessingFailure.TableMismatch"/> when <paramref name="table"/> does not match both arguments' own table.</param>
    /// <returns><see langword="true"/> when every <c>ObjectReference</c> resolved.</returns>
    public static bool TryVerifyObjectReferences(XmlNodeTable table, XmlSignature signature, XAdESCommitmentTypeIndication commitmentTypeIndication, out XAdESProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(signature);
        if(!signature.IsOver(table) || !ReferenceEquals(commitmentTypeIndication.Table, table))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.TableMismatch, 0);

            return false;
        }

        if(commitmentTypeIndication.Choice != XAdESCommitmentTypeIndicationChoice.ObjectReferences)
        {
            error = default;

            return true;
        }

        for(int i = 0; i < commitmentTypeIndication.ObjectReferenceCount; ++i)
        {
            if(!XAdESObjectReferenceResolution.TryResolve(table, signature, commitmentTypeIndication.ObjectReferenceAt(i), out _, out error))
            {
                return false;
            }
        }

        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESCommitmentTypeIndication other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESCommitmentTypeIndication other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESCommitmentTypeIndication left, XAdESCommitmentTypeIndication right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESCommitmentTypeIndication left, XAdESCommitmentTypeIndication right) => !left.Equals(right);
}
