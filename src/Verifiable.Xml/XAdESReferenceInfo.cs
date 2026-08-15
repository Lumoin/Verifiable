using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The <c>ReferenceInfoType</c> data type of clause 5.1.4.3: a <c>ds:DigestMethod</c> then <c>ds:DigestValue</c>
/// pair — the same fixed child sequence <see cref="XAdESDigestAlgAndValue"/> reads, via the shared
/// <see cref="XAdESDigestAlgAndValue.TryReadDigestMethodAndValue"/> core — together with the wrapping
/// element's own optional <c>Id</c> and <c>URI</c> attributes, which <c>ReferenceInfoType</c> declares on
/// itself unlike <c>DigestAlgAndValueType</c>. Backs the <c>ReferenceInfo</c> element
/// <see cref="XAdESOtherTimeStamp"/>'s <c>OtherTimeStampType</c> (clause 5.1.4.5) carries one-or-more of, each
/// identifying one external data object's digest by reference (XA-5.1.4.5-4).
/// </summary>
public readonly struct XAdESReferenceInfo: IEquatable<XAdESReferenceInfo>
{
    /// <summary>The table the info's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>ReferenceInfo</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>
    /// Whether the optional <c>URI</c> attribute is present. When absent, XA-5.1.4.5-5 makes the referenced
    /// object's identity a matter of the deployment context, mirroring XMLDSIG's own <c>ds:Reference URI</c>-
    /// omitted convention — this reader still models presence structurally, taking no position on that
    /// context.
    /// </summary>
    public bool HasUri { get; }

    private int UriAttributeOrdinal { get; }

    /// <summary>The <c>URI</c> attribute value.</summary>
    public ReadOnlySpan<byte> Uri => HasUri ? Table.AttributeValueOf(ElementIndex, UriAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>The <c>ds:DigestMethod</c>/<c>ds:DigestValue</c> pair identifying the external data object's digest.</summary>
    public XAdESDigestAlgAndValue Digest { get; }


    private XAdESReferenceInfo(XmlNodeTable table, int elementIndex, bool hasId, int idAttributeOrdinal, bool hasUri, int uriAttributeOrdinal, XAdESDigestAlgAndValue digest)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        HasUri = hasUri;
        UriAttributeOrdinal = uriAttributeOrdinal;
        Digest = digest;
    }


    /// <summary>
    /// Reads a <c>ReferenceInfo</c> element: its optional <c>Id</c>/<c>URI</c> attributes, then its
    /// <c>ds:DigestMethod</c>/<c>ds:DigestValue</c> children in that fixed order.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>ReferenceInfo</c> element.</param>
    /// <param name="pool">The pool <see cref="XAdESDigestAlgAndValue.DigestValueOctets"/> is rented from.</param>
    /// <param name="owned">The caller's custody list. The decoded digest value is appended as it is read,
    /// including on paths that subsequently refuse — the caller must dispose the list when this method
    /// returns <see langword="false"/>.</param>
    /// <param name="value">The read model on success.</param>
    /// <param name="error">The refusal on failure.</param>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out XAdESReferenceInfo value, out XAdESReadError error)
    {
        value = default;
        bool hasId = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Id"u8, out int idOrdinal);
        bool hasUri = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "URI"u8, out int uriOrdinal);
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, (hasId ? 1 : 0) + (hasUri ? 1 : 0), out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        if(!XAdESDigestAlgAndValue.TryReadDigestMethodAndValue(table, elementIndex, pool, owned, out XAdESDigestAlgAndValue digest, out error))
        {
            return false;
        }

        value = new XAdESReferenceInfo(table, elementIndex, hasId, idOrdinal, hasUri, uriOrdinal, digest);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESReferenceInfo other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESReferenceInfo other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESReferenceInfo left, XAdESReferenceInfo right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESReferenceInfo left, XAdESReferenceInfo right) => !left.Equals(right);
}
