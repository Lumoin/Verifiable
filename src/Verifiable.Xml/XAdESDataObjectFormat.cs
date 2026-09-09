using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// The <c>DataObjectFormat</c> qualifying property of clause 5.2.4: a signed qualifying property that
/// qualifies one specific signed data object, describing its format through optional <c>Description</c>/
/// <c>ObjectIdentifier</c>/<c>MimeType</c>/<c>Encoding</c> children (fixed order, each individually
/// schema-optional) and a mandatory <c>ObjectReference</c> attribute naming the data object described. Clause
/// 5.2.4 narrows the schema's "each independently optional" shape with a cross-child floor the schema itself
/// cannot express: "this qualifying property shall contain at least one of the following elements:
/// Description, ObjectIdentifier and MimeType" — <c>Encoding</c> is excluded from that floor, and
/// <see cref="TryRead"/> enforces it explicitly.
/// </summary>
/// <remarks>
/// Carries no owned pooled content of its own — every field is either a span computed from
/// <see cref="Table"/> or a nested <see cref="XAdESObjectIdentifier"/> — so no <see cref="IDisposable"/>
/// surface is needed.
/// </remarks>
public readonly struct XAdESDataObjectFormat: IEquatable<XAdESDataObjectFormat>
{
    /// <summary>The table the property's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>DataObjectFormat</c> element's own index.</summary>
    public int ElementIndex { get; }

    private int ObjectReferenceAttributeOrdinal { get; }

    /// <summary>
    /// The mandatory <c>ObjectReference</c> attribute: an <c>anyURI</c> naming the <c>ds:Reference</c> child of
    /// <c>ds:SignedInfo</c> or a signed <c>ds:Manifest</c> that references the signed data object this
    /// property describes.
    /// </summary>
    public ReadOnlySpan<byte> ObjectReference => Table.AttributeValueOf(ElementIndex, ObjectReferenceAttributeOrdinal);

    /// <summary>Whether the optional <c>Description</c> child is present.</summary>
    public bool HasDescription { get; }

    private int DescriptionTextNodeIndex { get; }

    /// <summary>The <c>Description</c> element's <c>string</c> content, valid when <see cref="HasDescription"/> is <see langword="true"/>.</summary>
    public ReadOnlySpan<byte> Description => HasDescription && DescriptionTextNodeIndex >= 0 ? Table.ValueOf(DescriptionTextNodeIndex) : ReadOnlySpan<byte>.Empty;

    /// <summary>Whether the optional <c>ObjectIdentifier</c> child is present.</summary>
    public bool HasObjectIdentifier { get; }

    /// <summary>The <c>ObjectIdentifier</c> child, valid when <see cref="HasObjectIdentifier"/> is <see langword="true"/>.</summary>
    public XAdESObjectIdentifier ObjectIdentifier { get; }

    /// <summary>Whether the optional <c>MimeType</c> child is present.</summary>
    public bool HasMimeType { get; }

    private int MimeTypeTextNodeIndex { get; }

    /// <summary>The <c>MimeType</c> element's <see href="https://www.rfc-editor.org/rfc/rfc2045">IETF RFC 2045</see>-valued content, valid when <see cref="HasMimeType"/> is <see langword="true"/>.</summary>
    public ReadOnlySpan<byte> MimeType => HasMimeType && MimeTypeTextNodeIndex >= 0 ? Table.ValueOf(MimeTypeTextNodeIndex) : ReadOnlySpan<byte>.Empty;

    /// <summary>Whether the optional <c>Encoding</c> child is present.</summary>
    public bool HasEncoding { get; }

    private int EncodingTextNodeIndex { get; }

    /// <summary>The <c>Encoding</c> element's <c>anyURI</c> content, valid when <see cref="HasEncoding"/> is <see langword="true"/>.</summary>
    public ReadOnlySpan<byte> Encoding => HasEncoding && EncodingTextNodeIndex >= 0 ? Table.ValueOf(EncodingTextNodeIndex) : ReadOnlySpan<byte>.Empty;


    private XAdESDataObjectFormat(
        XmlNodeTable table,
        int elementIndex,
        int objectReferenceAttributeOrdinal,
        bool hasDescription,
        int descriptionTextNodeIndex,
        bool hasObjectIdentifier,
        XAdESObjectIdentifier objectIdentifier,
        bool hasMimeType,
        int mimeTypeTextNodeIndex,
        bool hasEncoding,
        int encodingTextNodeIndex)
    {
        Table = table;
        ElementIndex = elementIndex;
        ObjectReferenceAttributeOrdinal = objectReferenceAttributeOrdinal;
        HasDescription = hasDescription;
        DescriptionTextNodeIndex = descriptionTextNodeIndex;
        HasObjectIdentifier = hasObjectIdentifier;
        ObjectIdentifier = objectIdentifier;
        HasMimeType = hasMimeType;
        MimeTypeTextNodeIndex = mimeTypeTextNodeIndex;
        HasEncoding = hasEncoding;
        EncodingTextNodeIndex = encodingTextNodeIndex;
    }


    /// <summary>
    /// Reads a <c>DataObjectFormat</c> element: its mandatory <c>ObjectReference</c> attribute, then its
    /// optional <c>Description</c>/<c>ObjectIdentifier</c>/<c>MimeType</c>/<c>Encoding</c> children in that
    /// fixed order, refusing an element with none of the three descriptive children present.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>DataObjectFormat</c> element — typically obtained from a
    /// <see cref="XAdESSignedDataObjectPropertyEntry"/> whose
    /// <see cref="XAdESSignedDataObjectPropertyEntry.Name"/> is
    /// <see cref="XAdESSignedDataObjectPropertyName.DataObjectFormat"/>.</param>
    /// <param name="value">The read model on success.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESReadFailure.MissingRequiredAttribute"/> when <c>ObjectReference</c> is absent;
    /// <see cref="XAdESReadFailure.DataObjectFormatMissingDescriptiveChild"/> when none of
    /// <c>Description</c>/<c>ObjectIdentifier</c>/<c>MimeType</c> is present (clause 5.2.4's cross-child
    /// floor).</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryRead(XmlNodeTable table, int elementIndex, out XAdESDataObjectFormat value, out XAdESReadError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        value = default;
        if(!XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "ObjectReference"u8, out int objectReferenceOrdinal))
        {
            error = new XAdESReadError(XAdESReadFailure.MissingRequiredAttribute, 0);

            return false;
        }

        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 1, out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
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

        bool hasObjectIdentifier = false;
        XAdESObjectIdentifier objectIdentifier = default;
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "ObjectIdentifier"u8))
        {
            if(!XAdESObjectIdentifier.TryRead(table, child, out objectIdentifier, out error))
            {
                return false;
            }

            hasObjectIdentifier = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        bool hasMimeType = false;
        int mimeTypeTextNodeIndex = -1;
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "MimeType"u8))
        {
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, child, 0, out grammarError)
                || !XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, child, out mimeTypeTextNodeIndex, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            hasMimeType = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        bool hasEncoding = false;
        int encodingTextNodeIndex = -1;
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "Encoding"u8))
        {
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, child, 0, out grammarError)
                || !XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, child, out encodingTextNodeIndex, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            hasEncoding = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        if(scan == ElementScanResult.Found)
        {
            //One disjunct per xsd:sequence child this element can repeat; a named predicate per child
            //would only rename the grammar, not simplify it.
            bool isRepeat = (hasDescription && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "Description"u8))
                || (hasObjectIdentifier && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "ObjectIdentifier"u8))
                || (hasMimeType && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "MimeType"u8))
                || (hasEncoding && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "Encoding"u8));
            error = new XAdESReadError(isRepeat ? XAdESReadFailure.DuplicateCoreChild : XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        if(!hasDescription && !hasObjectIdentifier && !hasMimeType)
        {
            error = new XAdESReadError(XAdESReadFailure.DataObjectFormatMissingDescriptiveChild, 0);

            return false;
        }

        value = new XAdESDataObjectFormat(
            table, elementIndex, objectReferenceOrdinal,
            hasDescription, descriptionTextNodeIndex,
            hasObjectIdentifier, objectIdentifier,
            hasMimeType, mimeTypeTextNodeIndex,
            hasEncoding, encodingTextNodeIndex);
        error = default;

        return true;
    }


    /// <summary>
    /// Verifies clause 5.2.4's cross-artifact consistency rule: "If the <c>DataObjectFormat</c> qualifying
    /// property references a <c>ds:Reference</c> that in turn references a <c>ds:Object</c> within the XAdES
    /// signature, and if this <c>ds:Object</c> element has the <c>MimeType</c> or (and) the <c>Encoding</c>
    /// attribute(s), then <c>DataObjectFormat</c>'s children <c>MimeType</c> and <c>Encoding</c> shall have
    /// exactly the same values, if they are present." Resolves <see cref="ObjectReference"/> the same way
    /// <see cref="XAdESCommitmentTypeIndication.TryVerifyObjectReferences"/> resolves an <c>ObjectReference</c>
    /// value; when the resolved <c>ds:Reference</c>'s own <c>URI</c> is absent, is not a same-document
    /// bare-name form, or does not identify one of <paramref name="signature"/>'s own <c>ds:Object</c>
    /// children, the consistency rule simply does not apply and this method succeeds (NOTE 8 clarifies the
    /// referenced <c>ds:Reference</c> need not even be a direct <c>ds:SignedInfo</c> child, let alone name a
    /// <c>ds:Object</c> at all).
    /// </summary>
    /// <param name="table">The document both <paramref name="signature"/> and <paramref name="dataObjectFormat"/> were read from.</param>
    /// <param name="signature">The signature whose <c>ds:SignedInfo</c>/signed <c>ds:Manifest</c>s and <c>ds:Object</c> children are consulted.</param>
    /// <param name="dataObjectFormat">The property whose consistency with the referenced <c>ds:Object</c> is verified.</param>
    /// <param name="error">The refusal on failure — see <see cref="XAdESObjectReferenceResolution.TryResolve"/>,
    /// <see cref="XAdESProcessingFailure.DataObjectFormatMimeTypeMismatch"/>,
    /// <see cref="XAdESProcessingFailure.DataObjectFormatEncodingMismatch"/> — or
    /// <see cref="XAdESProcessingFailure.TableMismatch"/> when <paramref name="table"/> does not match both
    /// arguments' own table.</param>
    /// <returns><see langword="true"/> when <see cref="ObjectReference"/> resolved and any applicable
    /// <c>MimeType</c>/<c>Encoding</c> values matched.</returns>
    public static bool TryVerifyConsistency(XmlNodeTable table, XmlSignature signature, XAdESDataObjectFormat dataObjectFormat, out XAdESProcessingError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(signature);
        if(!signature.IsOver(table) || !ReferenceEquals(dataObjectFormat.Table, table))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.TableMismatch, 0);

            return false;
        }

        if(!XAdESObjectReferenceResolution.TryResolve(table, signature, dataObjectFormat.ObjectReference, out int referenceElementIndex, out error))
        {
            return false;
        }

        if(!XmlSignatureModelGrammar.TryFindAttribute(table, referenceElementIndex, "URI"u8, out int dataUriOrdinal))
        {
            error = default;

            return true;
        }

        ReadOnlySpan<byte> dataUri = table.AttributeValueOf(referenceElementIndex, dataUriOrdinal);
        if(dataUri.IsEmpty || dataUri[0] != (byte)'#')
        {
            error = default;

            return true;
        }

        ReadOnlySpan<byte> fragment = dataUri[1..];
        if(!XmlReferenceDereferencer.IsNcNameFragment(fragment) || !table.TryFindElementById(fragment, out int dataObjectElementIndex, out _))
        {
            error = default;

            return true;
        }

        if(!XmlSignatureModelGrammar.IsDsElement(table, dataObjectElementIndex, "Object"u8))
        {
            error = default;

            return true;
        }

        XmlSignatureObject? matchedObject = null;
        foreach(XmlSignatureObject candidate in signature.Objects)
        {
            if(candidate.ElementIndex == dataObjectElementIndex)
            {
                matchedObject = candidate;

                break;
            }
        }

        if(matchedObject is null)
        {
            error = default;

            return true;
        }

        XmlSignatureObject dataObject = matchedObject.Value;
        if(dataObjectFormat.HasMimeType && dataObject.HasMimeType && !dataObjectFormat.MimeType.SequenceEqual(dataObject.MimeType))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.DataObjectFormatMimeTypeMismatch, 0);

            return false;
        }

        if(dataObjectFormat.HasEncoding && dataObject.HasEncoding && !dataObjectFormat.Encoding.SequenceEqual(dataObject.Encoding))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.DataObjectFormatEncodingMismatch, 0);

            return false;
        }

        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESDataObjectFormat other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESDataObjectFormat other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESDataObjectFormat left, XAdESDataObjectFormat right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESDataObjectFormat left, XAdESDataObjectFormat right) => !left.Equals(right);
}
