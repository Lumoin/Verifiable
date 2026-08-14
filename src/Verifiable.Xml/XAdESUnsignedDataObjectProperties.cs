using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// The <c>UnsignedDataObjectProperties</c> container of clause 4.3.7: one-or-more <c>UnsignedDataObjectProperty</c>
/// elements of type <c>AnyType</c> (XA-4.3.7-3), each carried unmodeled through <see cref="XAdESUnmodeledContent"/>
/// — clause 4.3.7's own NOTE states plainly that "the present document does not
/// specify the usage of any unsigned qualifying property qualifying the signed data objects... The schema
/// definition leaves open the definition of the contents of this type," and no
/// Part-1 clause targets this container as its home. Unlike <see cref="XAdESUnsignedSignatureProperties"/>,
/// the wrapping element name here IS closed (only <c>UnsignedDataObjectProperty</c> is schema-legal, with no
/// <c>##other</c> extension point on the container itself) — a differently-named child is a plain grammar
/// violation, <see cref="XAdESReadFailure.UnknownCoreElement"/>, not the signed-container allowlist concept.
/// </summary>
/// <remarks>
/// Carries no owned pooled content of its own — every entry is a plain node-index list over
/// <see cref="Table"/> — so no <see cref="IDisposable"/> surface is needed.
/// </remarks>
public readonly struct XAdESUnsignedDataObjectProperties: IEquatable<XAdESUnsignedDataObjectProperties>
{
    /// <summary>The table the properties' spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>UnsignedDataObjectProperties</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>The <c>UnsignedDataObjectProperty</c> children's unmodeled content, in document order; at least one.</summary>
    public IReadOnlyList<XAdESUnmodeledContent> Properties { get; }


    private XAdESUnsignedDataObjectProperties(XmlNodeTable table, int elementIndex, bool hasId, int idAttributeOrdinal, IReadOnlyList<XAdESUnmodeledContent> properties)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        Properties = properties;
    }


    /// <summary>
    /// Reads an <c>UnsignedDataObjectProperties</c> element: its optional <c>Id</c> attribute, then its
    /// one-or-more <c>UnsignedDataObjectProperty</c> children, each carried unmodeled — refusing a
    /// differently-named child or an empty element (XA-4.3.7-5).
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>UnsignedDataObjectProperties</c> element.</param>
    /// <param name="value">The read model on success.</param>
    /// <param name="error">The refusal on failure.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, out XAdESUnsignedDataObjectProperties value, out XAdESReadError error)
    {
        value = default;
        if(!XmlSignatureModelGrammar.IsElement(table, elementIndex, XAdESIdentifiers.XAdESNamespaceV132Utf8, "UnsignedDataObjectProperties"u8))
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

        var entries = new List<XAdESUnmodeledContent>();
        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
        if(scan == ElementScanResult.UnexpectedContent)
        {
            error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        while(scan == ElementScanResult.Found)
        {
            if(!XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "UnsignedDataObjectProperty"u8))
            {
                error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

                return false;
            }

            entries.Add(XAdESUnmodeledContent.Read(table, child));

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        if(entries.Count == 0)
        {
            error = new XAdESReadError(XAdESReadFailure.EmptyQualifyingPropertiesContainer, 0);

            return false;
        }

        value = new XAdESUnsignedDataObjectProperties(table, elementIndex, hasId, idOrdinal, entries);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESUnsignedDataObjectProperties other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESUnsignedDataObjectProperties other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESUnsignedDataObjectProperties left, XAdESUnsignedDataObjectProperties right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESUnsignedDataObjectProperties left, XAdESUnsignedDataObjectProperties right) => !left.Equals(right);
}
