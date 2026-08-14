using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// The <c>SignedProperties</c> container of clause 4.3.2: the qualifying properties collectively signed by
/// the XML signature, split into an optional <see cref="SignedSignatureProperties"/> and an optional
/// <see cref="SignedDataObjectProperties"/>, in that fixed order (XA-4.3.2-4's <c>SignedPropertiesType</c>
/// sequence), plus the optional <see cref="Id"/> attribute clause 4.4.2's <c>ds:Reference</c> targets.
/// </summary>
/// <remarks>
/// Carries no owned pooled content of its own — every field is either a span computed from <see cref="Table"/>
/// or a nested read-model struct over the same table — so no <see cref="IDisposable"/> surface is needed,
/// mirroring <see cref="XmlSignatureProperties"/>'s own posture.
/// </remarks>
public readonly struct XAdESSignedProperties: IEquatable<XAdESSignedProperties>
{
    /// <summary>The table the properties' spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>SignedProperties</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>Whether the optional <c>SignedSignatureProperties</c> child is present.</summary>
    public bool HasSignedSignatureProperties { get; }

    /// <summary>The <c>SignedSignatureProperties</c> child, meaningful only when <see cref="HasSignedSignatureProperties"/> is <see langword="true"/>.</summary>
    public XAdESSignedSignatureProperties SignedSignatureProperties { get; }

    /// <summary>Whether the optional <c>SignedDataObjectProperties</c> child is present.</summary>
    public bool HasSignedDataObjectProperties { get; }

    /// <summary>The <c>SignedDataObjectProperties</c> child, meaningful only when <see cref="HasSignedDataObjectProperties"/> is <see langword="true"/>.</summary>
    public XAdESSignedDataObjectProperties SignedDataObjectProperties { get; }


    private XAdESSignedProperties(
        XmlNodeTable table,
        int elementIndex,
        bool hasId,
        int idAttributeOrdinal,
        bool hasSignedSignatureProperties,
        XAdESSignedSignatureProperties signedSignatureProperties,
        bool hasSignedDataObjectProperties,
        XAdESSignedDataObjectProperties signedDataObjectProperties)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        HasSignedSignatureProperties = hasSignedSignatureProperties;
        SignedSignatureProperties = signedSignatureProperties;
        HasSignedDataObjectProperties = hasSignedDataObjectProperties;
        SignedDataObjectProperties = signedDataObjectProperties;
    }


    /// <summary>
    /// Reads a <c>SignedProperties</c> element: its optional <c>Id</c> attribute, then its optional
    /// <c>SignedSignatureProperties</c>/<c>SignedDataObjectProperties</c> children in that fixed order,
    /// refusing an element with neither child present (XA-4.3.2-8: "A XAdES signature shall not incorporate
    /// empty <c>SignedProperties</c> element").
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>SignedProperties</c> element.</param>
    /// <param name="value">The read model on success.</param>
    /// <param name="error">The refusal on failure.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, out XAdESSignedProperties value, out XAdESReadError error)
    {
        value = default;
        if(!XmlSignatureModelGrammar.IsElement(table, elementIndex, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SignedProperties"u8))
        {
            error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        bool hasId = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Id"u8, out int idOrdinal);
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, hasId ? 1 : 0, out XmlSignatureReadError grammarError))
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

        bool hasSignedSignatureProperties = false;
        XAdESSignedSignatureProperties signedSignatureProperties = default;
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SignedSignatureProperties"u8))
        {
            if(!XAdESSignedSignatureProperties.TryRead(table, child, out signedSignatureProperties, out error))
            {
                return false;
            }

            hasSignedSignatureProperties = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        bool hasSignedDataObjectProperties = false;
        XAdESSignedDataObjectProperties signedDataObjectProperties = default;
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SignedDataObjectProperties"u8))
        {
            if(!XAdESSignedDataObjectProperties.TryRead(table, child, out signedDataObjectProperties, out error))
            {
                return false;
            }

            hasSignedDataObjectProperties = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        if(scan == ElementScanResult.Found)
        {
            bool isRepeat = (hasSignedSignatureProperties && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SignedSignatureProperties"u8))
                || (hasSignedDataObjectProperties && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SignedDataObjectProperties"u8));
            error = new XAdESReadError(isRepeat ? XAdESReadFailure.DuplicateCoreChild : XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        if(!hasSignedSignatureProperties && !hasSignedDataObjectProperties)
        {
            error = new XAdESReadError(XAdESReadFailure.EmptyQualifyingPropertiesContainer, 0);

            return false;
        }

        value = new XAdESSignedProperties(table, elementIndex, hasId, idOrdinal, hasSignedSignatureProperties, signedSignatureProperties, hasSignedDataObjectProperties, signedDataObjectProperties);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESSignedProperties other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESSignedProperties other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESSignedProperties left, XAdESSignedProperties right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESSignedProperties left, XAdESSignedProperties right) => !left.Equals(right);
}
