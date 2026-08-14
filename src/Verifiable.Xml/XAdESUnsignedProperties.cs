using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// The <c>UnsignedProperties</c> container of clause 4.3.3: the qualifying properties NOT signed by the XML
/// signature, split into an optional <see cref="UnsignedSignatureProperties"/> and an optional
/// <see cref="UnsignedDataObjectProperties"/>, in that fixed order (XA-4.3.3-3's <c>UnsignedPropertiesType</c>
/// sequence), plus the optional <see cref="Id"/> attribute.
/// </summary>
/// <remarks>
/// Carries no owned pooled content of its own — every field is either a span computed from <see cref="Table"/>
/// or a nested read-model struct over the same table — so no <see cref="IDisposable"/> surface is needed,
/// mirroring <see cref="XmlSignatureProperties"/>'s own posture.
/// </remarks>
public readonly struct XAdESUnsignedProperties: IEquatable<XAdESUnsignedProperties>
{
    /// <summary>The table the properties' spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>UnsignedProperties</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>Whether the optional <c>UnsignedSignatureProperties</c> child is present.</summary>
    public bool HasUnsignedSignatureProperties { get; }

    /// <summary>The <c>UnsignedSignatureProperties</c> child, meaningful only when <see cref="HasUnsignedSignatureProperties"/> is <see langword="true"/>.</summary>
    public XAdESUnsignedSignatureProperties UnsignedSignatureProperties { get; }

    /// <summary>Whether the optional <c>UnsignedDataObjectProperties</c> child is present.</summary>
    public bool HasUnsignedDataObjectProperties { get; }

    /// <summary>The <c>UnsignedDataObjectProperties</c> child, meaningful only when <see cref="HasUnsignedDataObjectProperties"/> is <see langword="true"/>.</summary>
    public XAdESUnsignedDataObjectProperties UnsignedDataObjectProperties { get; }


    private XAdESUnsignedProperties(
        XmlNodeTable table,
        int elementIndex,
        bool hasId,
        int idAttributeOrdinal,
        bool hasUnsignedSignatureProperties,
        XAdESUnsignedSignatureProperties unsignedSignatureProperties,
        bool hasUnsignedDataObjectProperties,
        XAdESUnsignedDataObjectProperties unsignedDataObjectProperties)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        HasUnsignedSignatureProperties = hasUnsignedSignatureProperties;
        UnsignedSignatureProperties = unsignedSignatureProperties;
        HasUnsignedDataObjectProperties = hasUnsignedDataObjectProperties;
        UnsignedDataObjectProperties = unsignedDataObjectProperties;
    }


    /// <summary>
    /// Reads an <c>UnsignedProperties</c> element: its optional <c>Id</c> attribute, then its optional
    /// <c>UnsignedSignatureProperties</c>/<c>UnsignedDataObjectProperties</c> children in that fixed order,
    /// refusing an element with neither child present (XA-4.3.3-7: "A XAdES signature shall not incorporate
    /// empty <c>UnsignedProperties</c> elements").
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>UnsignedProperties</c> element.</param>
    /// <param name="value">The read model on success.</param>
    /// <param name="error">The refusal on failure.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, out XAdESUnsignedProperties value, out XAdESReadError error)
    {
        value = default;
        if(!XmlSignatureModelGrammar.IsElement(table, elementIndex, XAdESIdentifiers.XAdESNamespaceV132Utf8, "UnsignedProperties"u8))
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

        bool hasUnsignedSignatureProperties = false;
        XAdESUnsignedSignatureProperties unsignedSignatureProperties = default;
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "UnsignedSignatureProperties"u8))
        {
            if(!XAdESUnsignedSignatureProperties.TryRead(table, child, out unsignedSignatureProperties, out error))
            {
                return false;
            }

            hasUnsignedSignatureProperties = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        bool hasUnsignedDataObjectProperties = false;
        XAdESUnsignedDataObjectProperties unsignedDataObjectProperties = default;
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "UnsignedDataObjectProperties"u8))
        {
            if(!XAdESUnsignedDataObjectProperties.TryRead(table, child, out unsignedDataObjectProperties, out error))
            {
                return false;
            }

            hasUnsignedDataObjectProperties = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        if(scan == ElementScanResult.Found)
        {
            bool isRepeat = (hasUnsignedSignatureProperties && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "UnsignedSignatureProperties"u8))
                || (hasUnsignedDataObjectProperties && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "UnsignedDataObjectProperties"u8));
            error = new XAdESReadError(isRepeat ? XAdESReadFailure.DuplicateCoreChild : XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        if(!hasUnsignedSignatureProperties && !hasUnsignedDataObjectProperties)
        {
            error = new XAdESReadError(XAdESReadFailure.EmptyQualifyingPropertiesContainer, 0);

            return false;
        }

        value = new XAdESUnsignedProperties(table, elementIndex, hasId, idOrdinal, hasUnsignedSignatureProperties, unsignedSignatureProperties, hasUnsignedDataObjectProperties, unsignedDataObjectProperties);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESUnsignedProperties other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESUnsignedProperties other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESUnsignedProperties left, XAdESUnsignedProperties right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESUnsignedProperties left, XAdESUnsignedProperties right) => !left.Equals(right);
}
