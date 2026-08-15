using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// The <c>QualifyingProperties</c> container of clause 4.3.1: the top-level wrapper for every qualifying
/// property a XAdES signature carries, split into an optional <see cref="SignedProperties"/> and an optional
/// <see cref="UnsignedProperties"/>, in that fixed order (XA-4.3.1-3's <c>QualifyingPropertiesType</c>
/// sequence), plus the mandatory <see cref="Target"/> and optional <see cref="Id"/> attributes.
/// </summary>
/// <remarks>
/// <see cref="Target"/> is captured as the raw <c>xsd:anyURI</c> span, exact-character, with no shape
/// validation performed here — the bare-name-XPointer shape rules and the binding to the enclosing
/// <c>ds:Signature</c>'s own <c>Id</c> (clause 4.3.1) are <see cref="XAdESQualifyingPropertiesDiscovery.TryVerifyTargetBinding"/>'s
/// concern, since validating them needs the <c>ds:Signature</c> this structural read does not have. Carries
/// no owned pooled content of its own — every field is either a span computed from <see cref="Table"/> or a
/// nested read-model struct over the same table — so no <see cref="IDisposable"/> surface is needed, mirroring
/// <see cref="XmlSignatureProperties"/>'s own posture.
/// </remarks>
public readonly struct XAdESQualifyingProperties: IEquatable<XAdESQualifyingProperties>
{
    /// <summary>The table the properties' spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>QualifyingProperties</c> element's own index.</summary>
    public int ElementIndex { get; }

    private int TargetAttributeOrdinal { get; }

    /// <summary>The mandatory <c>Target</c> attribute's raw value, exact-character, unvalidated.</summary>
    public ReadOnlySpan<byte> Target => Table.AttributeValueOf(ElementIndex, TargetAttributeOrdinal);

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>Whether the optional <c>SignedProperties</c> child is present.</summary>
    public bool HasSignedProperties { get; }

    /// <summary>The <c>SignedProperties</c> child, meaningful only when <see cref="HasSignedProperties"/> is <see langword="true"/>.</summary>
    public XAdESSignedProperties SignedProperties { get; }

    /// <summary>Whether the optional <c>UnsignedProperties</c> child is present.</summary>
    public bool HasUnsignedProperties { get; }

    /// <summary>The <c>UnsignedProperties</c> child, meaningful only when <see cref="HasUnsignedProperties"/> is <see langword="true"/>.</summary>
    public XAdESUnsignedProperties UnsignedProperties { get; }


    private XAdESQualifyingProperties(
        XmlNodeTable table,
        int elementIndex,
        int targetAttributeOrdinal,
        bool hasId,
        int idAttributeOrdinal,
        bool hasSignedProperties,
        XAdESSignedProperties signedProperties,
        bool hasUnsignedProperties,
        XAdESUnsignedProperties unsignedProperties)
    {
        Table = table;
        ElementIndex = elementIndex;
        TargetAttributeOrdinal = targetAttributeOrdinal;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        HasSignedProperties = hasSignedProperties;
        SignedProperties = signedProperties;
        HasUnsignedProperties = hasUnsignedProperties;
        UnsignedProperties = unsignedProperties;
    }


    /// <summary>
    /// Reads a <c>QualifyingProperties</c> element: its mandatory <c>Target</c> and optional <c>Id</c>
    /// attributes, then its optional <c>SignedProperties</c>/<c>UnsignedProperties</c> children in that fixed
    /// order, refusing an element with neither child present (XA-4.3.1-9: "A XAdES signature shall not
    /// incorporate empty <c>QualifyingProperties</c> elements").
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>QualifyingProperties</c> element.</param>
    /// <param name="value">The read model on success.</param>
    /// <param name="error">The refusal on failure.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryRead(XmlNodeTable table, int elementIndex, out XAdESQualifyingProperties value, out XAdESReadError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        value = default;
        if(!XmlSignatureModelGrammar.IsElement(table, elementIndex, XAdESIdentifiers.XAdESNamespaceV132Utf8, "QualifyingProperties"u8))
        {
            error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        if(!XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Target"u8, out int targetOrdinal))
        {
            error = new XAdESReadError(XAdESReadFailure.MissingRequiredAttribute, 0);

            return false;
        }

        bool hasId = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Id"u8, out int idOrdinal);
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 1 + (hasId ? 1 : 0), out XmlSignatureReadError grammarError))
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

        bool hasSignedProperties = false;
        XAdESSignedProperties signedProperties = default;
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SignedProperties"u8))
        {
            if(!XAdESSignedProperties.TryRead(table, child, out signedProperties, out error))
            {
                return false;
            }

            hasSignedProperties = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        bool hasUnsignedProperties = false;
        XAdESUnsignedProperties unsignedProperties = default;
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "UnsignedProperties"u8))
        {
            if(!XAdESUnsignedProperties.TryRead(table, child, out unsignedProperties, out error))
            {
                return false;
            }

            hasUnsignedProperties = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        if(scan == ElementScanResult.Found)
        {
            bool isRepeat = (hasSignedProperties && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SignedProperties"u8))
                || (hasUnsignedProperties && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "UnsignedProperties"u8));
            error = new XAdESReadError(isRepeat ? XAdESReadFailure.DuplicateCoreChild : XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        if(!hasSignedProperties && !hasUnsignedProperties)
        {
            error = new XAdESReadError(XAdESReadFailure.EmptyQualifyingPropertiesContainer, 0);

            return false;
        }

        value = new XAdESQualifyingProperties(table, elementIndex, targetOrdinal, hasId, idOrdinal, hasSignedProperties, signedProperties, hasUnsignedProperties, unsignedProperties);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESQualifyingProperties other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESQualifyingProperties other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESQualifyingProperties left, XAdESQualifyingProperties right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESQualifyingProperties left, XAdESQualifyingProperties right) => !left.Equals(right);
}
