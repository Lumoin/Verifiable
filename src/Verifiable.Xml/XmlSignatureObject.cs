using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// One <c>ds:Object</c> element: its optional <c>Id</c>/<c>MimeType</c>/<c>Encoding</c> attributes and its
/// immediate child node indices, per section 4.5 of
/// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
/// (Second Edition)</see>.
/// </summary>
/// <remarks>
/// <c>Object</c>'s content model is <c>##any</c> namespace, mixed, unbounded — genuinely arbitrary content
/// this leaf does not interpret. <see cref="ContentNodeIndices"/> lists every immediate child exactly as
/// the document carries it (text, comments and processing instructions included, with no whitespace
/// filtering), so a caller who recognizes what an <c>Object</c> holds — a nested <c>Manifest</c> via
/// <see cref="XmlManifest.TryRead"/>, a <c>SignatureProperties</c> via
/// <see cref="XmlSignatureProperties.TryRead"/>, or a whole nested <c>ds:Signature</c> via
/// <see cref="XmlSignature.TryRead"/> — reads that content itself, over one of these indices.
/// </remarks>
public readonly struct XmlSignatureObject: IEquatable<XmlSignatureObject>
{
    /// <summary>The table the object's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>Object</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>Whether the optional, advisory <c>MimeType</c> attribute is present.</summary>
    public bool HasMimeType { get; }

    private int MimeTypeAttributeOrdinal { get; }

    /// <summary>The <c>MimeType</c> attribute value.</summary>
    public ReadOnlySpan<byte> MimeType => HasMimeType ? Table.AttributeValueOf(ElementIndex, MimeTypeAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>Whether the optional, advisory <c>Encoding</c> attribute is present.</summary>
    public bool HasEncoding { get; }

    private int EncodingAttributeOrdinal { get; }

    /// <summary>The <c>Encoding</c> attribute value.</summary>
    public ReadOnlySpan<byte> Encoding => HasEncoding ? Table.AttributeValueOf(ElementIndex, EncodingAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>Every immediate child node index, in document order, unvalidated.</summary>
    public IReadOnlyList<int> ContentNodeIndices { get; }


    private XmlSignatureObject(
        XmlNodeTable table,
        int elementIndex,
        bool hasId,
        int idAttributeOrdinal,
        bool hasMimeType,
        int mimeTypeAttributeOrdinal,
        bool hasEncoding,
        int encodingAttributeOrdinal,
        IReadOnlyList<int> contentNodeIndices)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        HasMimeType = hasMimeType;
        MimeTypeAttributeOrdinal = mimeTypeAttributeOrdinal;
        HasEncoding = hasEncoding;
        EncodingAttributeOrdinal = encodingAttributeOrdinal;
        ContentNodeIndices = contentNodeIndices;
    }


    /// <summary>
    /// Reads an <c>Object</c> element: its attributes and the index of every immediate child, unvalidated.
    /// </summary>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, out XmlSignatureObject signatureObject, out XmlSignatureReadError error)
    {
        bool hasId = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Id"u8, out int idOrdinal);
        bool hasMimeType = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "MimeType"u8, out int mimeTypeOrdinal);
        bool hasEncoding = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Encoding"u8, out int encodingOrdinal);
        int knownCount = (hasId ? 1 : 0) + (hasMimeType ? 1 : 0) + (hasEncoding ? 1 : 0);
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, knownCount, out error))
        {
            signatureObject = default;

            return false;
        }

        var contentNodeIndices = new List<int>();
        for(int child = table.FirstChildOf(elementIndex); child >= 0; child = table.NextSiblingOf(child))
        {
            contentNodeIndices.Add(child);
        }

        signatureObject = new XmlSignatureObject(table, elementIndex, hasId, idOrdinal, hasMimeType, mimeTypeOrdinal, hasEncoding, encodingOrdinal, contentNodeIndices);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XmlSignatureObject other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XmlSignatureObject other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XmlSignatureObject left, XmlSignatureObject right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XmlSignatureObject left, XmlSignatureObject right) => !left.Equals(right);
}
