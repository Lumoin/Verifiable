using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// The <c>IncludeType</c> data type of clause 5.1.4.4.2.1: an attribute-only element — no children of any
/// kind — carrying a mandatory <c>URI</c> (XA-5.1.4.4.2.1-3/-4, the bare-name-XPointer rules
/// <see cref="XAdESIncludeUriProcessing"/> processes) and an optional <c>referencedData</c> boolean
/// (XA-5.1.4.4.2.1-5, gating whether the referenced data object is itself processed as a <c>ds:Reference</c>
/// once retrieved). Document order among the <c>Include</c> elements of one time-stamp container is
/// semantically load-bearing (XA-5.1.4.4.2.1-2: it fixes the order the referenced data objects contribute to
/// the message-imprint input, XA-5.1.4.4.2.3-4) — this reader models one <c>Include</c> at a time, so
/// preserving that order is <see cref="XAdESTimeStamp"/>'s own list-building responsibility, not this type's.
/// </summary>
public readonly struct XAdESInclude: IEquatable<XAdESInclude>
{
    /// <summary>The table the value's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>Include</c> element's own index.</summary>
    public int ElementIndex { get; }

    private int UriAttributeOrdinal { get; }

    /// <summary>The mandatory <c>URI</c> attribute value, exact-character.</summary>
    public ReadOnlySpan<byte> Uri => Table.AttributeValueOf(ElementIndex, UriAttributeOrdinal);

    /// <summary>Whether the optional <c>referencedData</c> attribute is present.</summary>
    public bool HasReferencedData { get; }

    /// <summary>The parsed <c>referencedData</c> value, meaningful only when <see cref="HasReferencedData"/> is <see langword="true"/>.</summary>
    public bool ReferencedData { get; }


    private XAdESInclude(XmlNodeTable table, int elementIndex, int uriAttributeOrdinal, bool hasReferencedData, bool referencedData)
    {
        Table = table;
        ElementIndex = elementIndex;
        UriAttributeOrdinal = uriAttributeOrdinal;
        HasReferencedData = hasReferencedData;
        ReferencedData = referencedData;
    }


    /// <summary>
    /// Reads an <c>Include</c> element: its mandatory <c>URI</c> and optional <c>referencedData</c>
    /// attributes, refusing any element or non-whitespace text content — <c>IncludeType</c> declares none.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>Include</c> element.</param>
    /// <param name="value">The read model on success.</param>
    /// <param name="error">The refusal on failure.</param>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, out XAdESInclude value, out XAdESReadError error)
    {
        value = default;
        if(!XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "URI"u8, out int uriOrdinal))
        {
            error = new XAdESReadError(XAdESReadFailure.MissingRequiredAttribute, 0);

            return false;
        }

        bool hasReferencedData = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "referencedData"u8, out int referencedDataOrdinal);
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 1 + (hasReferencedData ? 1 : 0), out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        bool referencedData = false;
        if(hasReferencedData && !XAdESGrammar.TryParseXsdBoolean(table.AttributeValueOf(elementIndex, referencedDataOrdinal), out referencedData))
        {
            error = new XAdESReadError(XAdESReadFailure.InvalidBooleanAttributeValue, 0);

            return false;
        }

        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out _);
        if(scan == ElementScanResult.Found)
        {
            error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        if(scan == ElementScanResult.UnexpectedContent)
        {
            error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        value = new XAdESInclude(table, elementIndex, uriOrdinal, hasReferencedData, referencedData);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESInclude other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESInclude other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESInclude left, XAdESInclude right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESInclude left, XAdESInclude right) => !left.Equals(right);
}
