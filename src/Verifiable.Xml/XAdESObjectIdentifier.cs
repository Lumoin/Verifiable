using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// Which of the two mechanisms <c>IdentifierType</c>'s optional <c>Qualifier</c> attribute (clause 5.1.2)
/// names for encoding an Object Identifier (OID) as the value of an <c>Identifier</c> element.
/// </summary>
public enum XAdESObjectIdentifierQualifier
{
    /// <summary><c>Qualifier="OIDAsURI"</c>: the OID is encoded as a URI that is not a URN.</summary>
    OIDAsURI,

    /// <summary>
    /// <c>Qualifier="OIDAsURN"</c>: the OID is encoded as a URN per
    /// <see href="https://www.rfc-editor.org/rfc/rfc3061">IETF RFC 3061</see>. The schema's enumeration
    /// spells this value with a lower-case <c>s</c>; the specification's own prose restates it as
    /// <c>"OIDASURN"</c> at one site — clause 4.2's schema-precedence rule makes the schema's
    /// casing, the one this member names, authoritative.
    /// </summary>
    OIDAsURN
}


/// <summary>
/// The <c>ObjectIdentifierType</c> data type of clause 5.1.2: a unique, permanent <c>Identifier</c> (an
/// <c>anyURI</c> value, optionally qualified as an encoded Object Identifier), an optional textual
/// <c>Description</c>, and an optional <c>DocumentationReferences</c> list of further explanatory documents.
/// Backs every named element the schema declares this type for — <c>ObjectIdentifier</c>, <c>SigPolicyId</c>,
/// <c>CommitmentTypeId</c> and others — so <see cref="TryRead"/> does not itself check
/// the wrapping element's local name; the caller has already recognized it, the same posture
/// <see cref="XAdESEncapsulatedPkiData"/> and <see cref="XAdESDigestAlgAndValue"/> take for their own
/// multiply-instantiated types.
/// </summary>
/// <remarks>
/// Two normative statements this type cannot enforce from a single document instance, recorded rather than
/// silently dropped: the <c>Identifier</c> element's permanence once assigned (an issuer-side obligation with
/// no structural trace in one instance to check against); and the directional "a URI-identified object's
/// <c>Qualifier</c> shall not be present; an OID-identified object's shall" rule — <c>Qualifier</c>'s own
/// presence IS how a reader distinguishes the two cases, so there is no independent check to perform beyond
/// restricting a present value to the schema's two enumerated literals, which <see cref="TryRead"/> does.
/// Likewise the <c>should</c> preferring a URI over an OID when both exist (clause 5.1.2) is a generation-side
/// recommendation about which mechanism an issuer chooses, not a shape one instance's wire content could ever
/// violate.
/// </remarks>
public readonly struct XAdESObjectIdentifier: IEquatable<XAdESObjectIdentifier>
{
    /// <summary>The table the identifier's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>ObjectIdentifierType</c>-typed element's own index (e.g. <c>ObjectIdentifier</c>, <c>SigPolicyId</c>).</summary>
    public int ElementIndex { get; }

    /// <summary>The <c>Identifier</c> element's own index.</summary>
    public int IdentifierElementIndex { get; }

    private int IdentifierTextNodeIndex { get; }

    /// <summary>The <c>Identifier</c> element's <c>anyURI</c> content.</summary>
    public ReadOnlySpan<byte> Identifier => IdentifierTextNodeIndex >= 0 ? Table.ValueOf(IdentifierTextNodeIndex) : ReadOnlySpan<byte>.Empty;

    /// <summary>Whether the <c>Identifier</c> element's optional <c>Qualifier</c> attribute is present.</summary>
    public bool HasQualifier { get; }

    /// <summary>The <c>Qualifier</c> value, valid when <see cref="HasQualifier"/> is <see langword="true"/>.</summary>
    public XAdESObjectIdentifierQualifier Qualifier { get; }

    /// <summary>Whether the optional <c>Description</c> element is present.</summary>
    public bool HasDescription { get; }

    private int DescriptionTextNodeIndex { get; }

    /// <summary>The <c>Description</c> element's <c>string</c> content, valid when <see cref="HasDescription"/> is <see langword="true"/>.</summary>
    public ReadOnlySpan<byte> Description => HasDescription && DescriptionTextNodeIndex >= 0 ? Table.ValueOf(DescriptionTextNodeIndex) : ReadOnlySpan<byte>.Empty;

    /// <summary>Whether the optional <c>DocumentationReferences</c> element is present.</summary>
    public bool HasDocumentationReferences { get; }

    private IReadOnlyList<int> DocumentationReferenceTextNodeIndices { get; }

    /// <summary>
    /// How many <c>DocumentationReference</c> children <c>DocumentationReferences</c> carries; zero when
    /// <see cref="HasDocumentationReferences"/> is <see langword="false"/>. At least one whenever
    /// <see cref="HasDocumentationReferences"/> is <see langword="true"/> — <see cref="TryRead"/> refuses an
    /// empty <c>DocumentationReferences</c> element.
    /// </summary>
    public int DocumentationReferenceCount => DocumentationReferenceTextNodeIndices.Count;

    /// <summary>The <c>anyURI</c> content of the <c>DocumentationReference</c> at the given position, in document order.</summary>
    /// <param name="index">The zero-based position, less than <see cref="DocumentationReferenceCount"/>.</param>
    public ReadOnlySpan<byte> DocumentationReferenceAt(int index)
    {
        int textNodeIndex = DocumentationReferenceTextNodeIndices[index];

        return textNodeIndex >= 0 ? Table.ValueOf(textNodeIndex) : ReadOnlySpan<byte>.Empty;
    }


    private XAdESObjectIdentifier(
        XmlNodeTable table,
        int elementIndex,
        int identifierElementIndex,
        int identifierTextNodeIndex,
        bool hasQualifier,
        XAdESObjectIdentifierQualifier qualifier,
        bool hasDescription,
        int descriptionTextNodeIndex,
        bool hasDocumentationReferences,
        IReadOnlyList<int> documentationReferenceTextNodeIndices)
    {
        Table = table;
        ElementIndex = elementIndex;
        IdentifierElementIndex = identifierElementIndex;
        IdentifierTextNodeIndex = identifierTextNodeIndex;
        HasQualifier = hasQualifier;
        Qualifier = qualifier;
        HasDescription = hasDescription;
        DescriptionTextNodeIndex = descriptionTextNodeIndex;
        HasDocumentationReferences = hasDocumentationReferences;
        DocumentationReferenceTextNodeIndices = documentationReferenceTextNodeIndices;
    }


    /// <summary>
    /// Reads an <c>ObjectIdentifierType</c>-shaped element: its mandatory <c>Identifier</c> (with its
    /// optional <c>Qualifier</c> attribute), optional <c>Description</c> and optional
    /// <c>DocumentationReferences</c>, in that fixed order.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>ObjectIdentifierType</c>-typed element.</param>
    /// <param name="value">The read model on success.</param>
    /// <param name="error">The refusal on failure.</param>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, out XAdESObjectIdentifier value, out XAdESReadError error)
    {
        value = default;
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 0, out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
        if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "Identifier"u8))
        {
            error = new XAdESReadError(
                scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

            return false;
        }

        int identifierElementIndex = child;
        bool hasQualifier = XmlSignatureModelGrammar.TryFindAttribute(table, identifierElementIndex, "Qualifier"u8, out int qualifierOrdinal);
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, identifierElementIndex, hasQualifier ? 1 : 0, out grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        XAdESObjectIdentifierQualifier qualifier = default;
        if(hasQualifier)
        {
            ReadOnlySpan<byte> qualifierValue = table.AttributeValueOf(identifierElementIndex, qualifierOrdinal);
            if(qualifierValue.SequenceEqual("OIDAsURI"u8))
            {
                qualifier = XAdESObjectIdentifierQualifier.OIDAsURI;
            }
            else if(qualifierValue.SequenceEqual("OIDAsURN"u8))
            {
                qualifier = XAdESObjectIdentifierQualifier.OIDAsURN;
            }
            else
            {
                error = new XAdESReadError(XAdESReadFailure.UnrecognizedObjectIdentifierQualifier, 0);

                return false;
            }
        }

        if(!XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, identifierElementIndex, out int identifierTextNodeIndex, out grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, identifierElementIndex, out child);
        if(scan == ElementScanResult.UnexpectedContent)
        {
            error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        bool hasDescription = false;
        int descriptionTextNodeIndex = -1;
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "Description"u8))
        {
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, child, 0, out grammarError)
                || !XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, child, out descriptionTextNodeIndex, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            hasDescription = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        bool hasDocumentationReferences = false;
        List<int> documentationReferenceTextNodeIndices = [];
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "DocumentationReferences"u8))
        {
            int documentationReferencesElementIndex = child;
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, documentationReferencesElementIndex, 0, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            if(!XmlSignatureModelGrammar.TryReadElementChildren(table, documentationReferencesElementIndex, out List<int> referenceElements, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            if(referenceElements.Count == 0)
            {
                error = new XAdESReadError(XAdESReadFailure.MissingRequiredChild, 0);

                return false;
            }

            foreach(int referenceElement in referenceElements)
            {
                if(!XmlSignatureModelGrammar.IsElement(table, referenceElement, XAdESIdentifiers.XAdESNamespaceV132Utf8, "DocumentationReference"u8))
                {
                    error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

                    return false;
                }

                if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, referenceElement, 0, out grammarError)
                    || !XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, referenceElement, out int referenceTextNodeIndex, out grammarError))
                {
                    error = XAdESGrammar.FromGrammarFailure(grammarError);

                    return false;
                }

                documentationReferenceTextNodeIndices.Add(referenceTextNodeIndex);
            }

            hasDocumentationReferences = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, documentationReferencesElementIndex, out child);
        }

        if(scan == ElementScanResult.Found || scan == ElementScanResult.UnexpectedContent)
        {
            //A repeat of an element already consumed is a duplicate; anything else — including an
            //out-of-order element this reader has not consumed yet, such as Description appearing after
            //DocumentationReferences — is simply not valid at this position, per the fixed xsd:sequence.
            //Identifier is unconditionally consumed exactly once before this point is ever reached, so a
            //repeat of it is always a duplicate, unlike Description/DocumentationReferences which need the
            //hasX flag to tell "already consumed" apart from "not yet reached."
            bool isRepeat = scan == ElementScanResult.Found
                && (XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "Identifier"u8)
                    || (hasDescription && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "Description"u8))
                    || (hasDocumentationReferences && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "DocumentationReferences"u8)));
            error = new XAdESReadError(
                scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent
                : isRepeat ? XAdESReadFailure.DuplicateCoreChild
                : XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        value = new XAdESObjectIdentifier(
            table, elementIndex, identifierElementIndex, identifierTextNodeIndex, hasQualifier, qualifier,
            hasDescription, descriptionTextNodeIndex, hasDocumentationReferences, documentationReferenceTextNodeIndices);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESObjectIdentifier other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESObjectIdentifier other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESObjectIdentifier left, XAdESObjectIdentifier right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESObjectIdentifier left, XAdESObjectIdentifier right) => !left.Equals(right);
}
