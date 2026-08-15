using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// One <c>ds:SignatureProperty</c> element: its mandatory <c>Target</c> attribute, optional <c>Id</c>
/// attribute, and immediate child node indices, per section 5.2 of
/// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
/// (Second Edition)</see>. <see cref="ContentNodeIndices"/> is unvalidated, unfiltered — the same "caller
/// reads what it recognizes" shape <see cref="XmlSignatureObject.ContentNodeIndices"/> uses, appropriate to
/// this element's own <c>##other</c> extension-point content model.
/// </summary>
public readonly struct XmlSignatureProperty: IEquatable<XmlSignatureProperty>
{
    /// <summary>The table the property's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>SignatureProperty</c> element's own index.</summary>
    public int ElementIndex { get; }

    private int TargetAttributeOrdinal { get; }

    /// <summary>The mandatory <c>Target</c> attribute value — references the <c>Signature</c> element the property applies to.</summary>
    public ReadOnlySpan<byte> Target => Table.AttributeValueOf(ElementIndex, TargetAttributeOrdinal);

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>Every immediate child node index, in document order, unvalidated.</summary>
    public IReadOnlyList<int> ContentNodeIndices { get; }


    private XmlSignatureProperty(XmlNodeTable table, int elementIndex, int targetAttributeOrdinal, bool hasId, int idAttributeOrdinal, IReadOnlyList<int> contentNodeIndices)
    {
        Table = table;
        ElementIndex = elementIndex;
        TargetAttributeOrdinal = targetAttributeOrdinal;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        ContentNodeIndices = contentNodeIndices;
    }


    /// <summary>
    /// Reads a <c>SignatureProperty</c> element: its mandatory <c>Target</c>, its optional <c>Id</c>, and
    /// every immediate child index, unvalidated.
    /// </summary>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, out XmlSignatureProperty property, out XmlSignatureReadError error)
    {
        property = default;
        if(!XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Target"u8, out int targetOrdinal))
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.MissingRequiredAttribute, 0);

            return false;
        }

        bool hasId = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Id"u8, out int idOrdinal);
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 1 + (hasId ? 1 : 0), out error))
        {
            return false;
        }

        var contentNodeIndices = new List<int>();
        for(int child = table.FirstChildOf(elementIndex); child >= 0; child = table.NextSiblingOf(child))
        {
            contentNodeIndices.Add(child);
        }

        property = new XmlSignatureProperty(table, elementIndex, targetOrdinal, hasId, idOrdinal, contentNodeIndices);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XmlSignatureProperty other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XmlSignatureProperty other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XmlSignatureProperty left, XmlSignatureProperty right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XmlSignatureProperty left, XmlSignatureProperty right) => !left.Equals(right);
}


/// <summary>
/// One <c>ds:SignatureProperties</c> element: its optional <c>Id</c> attribute and its one-or-more
/// <c>SignatureProperty</c> children, per section 5.2.
/// </summary>
public readonly struct XmlSignatureProperties: IEquatable<XmlSignatureProperties>
{
    /// <summary>The table the properties' spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>SignatureProperties</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>The <c>SignatureProperty</c> children, in document order; at least one.</summary>
    public IReadOnlyList<XmlSignatureProperty> Properties { get; }


    private XmlSignatureProperties(XmlNodeTable table, int elementIndex, bool hasId, int idAttributeOrdinal, IReadOnlyList<XmlSignatureProperty> properties)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        Properties = properties;
    }


    /// <summary>
    /// Reads a <c>SignatureProperties</c> element: its <c>Id</c> attribute and its <c>SignatureProperty+</c>
    /// children. Carries no owned pooled content of its own — every field it exposes is either a span
    /// computed from <paramref name="table"/> or an unvalidated child node index — so no
    /// <see cref="IDisposable"/> surface is needed; <paramref name="table"/> stays the caller's to dispose.
    /// </summary>
    /// <param name="table">The parsed document.</param>
    /// <param name="elementIndex">The <c>SignatureProperties</c> element.</param>
    /// <param name="properties">The read model on success.</param>
    /// <param name="error">The refusal on failure.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryRead(XmlNodeTable table, int elementIndex, out XmlSignatureProperties? properties, out XmlSignatureReadError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        properties = null;
        if(!XmlSignatureModelGrammar.IsDsElement(table, elementIndex, "SignatureProperties"u8))
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.UnknownCoreElement, 0);

            return false;
        }

        bool hasId = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Id"u8, out int idOrdinal);
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, hasId ? 1 : 0, out error))
        {
            return false;
        }

        if(!XmlSignatureModelGrammar.TryReadElementChildren(table, elementIndex, out List<int> childIndices, out error))
        {
            return false;
        }

        if(childIndices.Count == 0)
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.MissingRequiredChild, 0);

            return false;
        }

        var propertyList = new List<XmlSignatureProperty>(childIndices.Count);
        foreach(int childIndex in childIndices)
        {
            if(!XmlSignatureModelGrammar.IsDsElement(table, childIndex, "SignatureProperty"u8))
            {
                error = new XmlSignatureReadError(XmlSignatureReadFailure.UnknownCoreElement, 0);

                return false;
            }

            if(!XmlSignatureProperty.TryRead(table, childIndex, out XmlSignatureProperty property, out error))
            {
                return false;
            }

            propertyList.Add(property);
        }

        properties = new XmlSignatureProperties(table, elementIndex, hasId, idOrdinal, propertyList);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XmlSignatureProperties other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XmlSignatureProperties other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XmlSignatureProperties left, XmlSignatureProperties right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XmlSignatureProperties left, XmlSignatureProperties right) => !left.Equals(right);
}
