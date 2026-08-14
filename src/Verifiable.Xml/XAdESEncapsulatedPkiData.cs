using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// Which ASN.1 encoding an <c>EncapsulatedPKIDataType</c>-typed element's content was written in before
/// being base64-encoded, per clause 5.1.3's <c>Encoding</c> attribute. Resolving an encoding to actual
/// decoding behaviour (X.509/CRL/OCSP/CMS parsing) is
/// <c>Verifiable.Cryptography.Pki.AdESPkiObjectEncoding</c>'s own concern, above this leaf;
/// this enum only carries the closed five-value fact clause 5.1.3 states.
/// </summary>
public enum XAdESPkiDataEncoding
{
    /// <summary>
    /// Distinguished Encoding Rules, <see cref="XAdESIdentifiers.DerEncodingUri"/> — the value this leaf
    /// reports when the <c>Encoding</c> attribute is absent altogether, per clause 5.1.3's default rule.
    /// </summary>
    Der,

    /// <summary>Basic Encoding Rules, <see cref="XAdESIdentifiers.BerEncodingUri"/>.</summary>
    Ber,

    /// <summary>Canonical Encoding Rules, <see cref="XAdESIdentifiers.CerEncodingUri"/>.</summary>
    Cer,

    /// <summary>Packed Encoding Rules, <see cref="XAdESIdentifiers.PerEncodingUri"/>.</summary>
    Per,

    /// <summary>XML Encoding Rules, <see cref="XAdESIdentifiers.XerEncodingUri"/>.</summary>
    Xer
}


/// <summary>
/// The <c>EncapsulatedPKIDataType</c> data type of clause 5.1.3: a base64-encoded, potentially non-XML PKI
/// object (an X.509 certificate, a CRL, an OCSP response, an attribute certificate, an electronic
/// time-stamp) with an optional <c>Id</c> and an optional <c>Encoding</c>. Backs every named element the
/// schema declares this type for — <c>EncapsulatedX509Certificate</c>, <c>EncapsulatedCRLValue</c>,
/// <c>EncapsulatedOCSPValue</c>, <c>EncapsulatedTimeStamp</c> and others — so
/// <see cref="TryRead"/> does not itself check the wrapping element's local name; the caller has already
/// recognized it.
/// </summary>
public readonly struct XAdESEncapsulatedPkiData: IEquatable<XAdESEncapsulatedPkiData>
{
    /// <summary>The table the value's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>
    /// The PKI object's encoding: the <c>Encoding</c> attribute's value when present, or
    /// <see cref="XAdESPkiDataEncoding.Der"/> when the attribute is absent, per clause 5.1.3's default rule.
    /// </summary>
    public XAdESPkiDataEncoding Encoding { get; }

    /// <summary>
    /// The decoded PKI object octets, tagged <see cref="BufferTags.XmlDecodedContent"/>. Owned by the
    /// caller's custody list and released by whichever aggregate ultimately owns it, per the shipped
    /// substrate's custody convention — this type is not itself <see cref="IDisposable"/>.
    /// </summary>
    public PooledMemory Content { get; }


    private XAdESEncapsulatedPkiData(XmlNodeTable table, int elementIndex, bool hasId, int idAttributeOrdinal, XAdESPkiDataEncoding encoding, PooledMemory content)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        Encoding = encoding;
        Content = content;
    }


    /// <summary>
    /// Reads an <c>EncapsulatedPKIDataType</c>-shaped element: its optional <c>Id</c>/<c>Encoding</c>
    /// attributes and its base64-encoded simple content, decoded through the same strict
    /// <c>base64Binary</c> lexical decoder every base64-typed field of this leaf shares.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The element to read.</param>
    /// <param name="pool">The pool <see cref="Content"/> is rented from.</param>
    /// <param name="owned">The caller's custody list. <see cref="Content"/> is appended as it is read,
    /// including on paths that subsequently refuse — the caller must dispose the list when this method
    /// returns <see langword="false"/>.</param>
    /// <param name="value">The read model on success.</param>
    /// <param name="error">The refusal on failure.</param>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out XAdESEncapsulatedPkiData value, out XAdESReadError error)
    {
        value = default;
        bool hasId = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Id"u8, out int idOrdinal);
        bool hasEncodingAttribute = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Encoding"u8, out int encodingOrdinal);
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, (hasId ? 1 : 0) + (hasEncodingAttribute ? 1 : 0), out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        XAdESPkiDataEncoding encoding = XAdESPkiDataEncoding.Der;
        if(hasEncodingAttribute)
        {
            ReadOnlySpan<byte> encodingValue = table.AttributeValueOf(elementIndex, encodingOrdinal);
            if(encodingValue.SequenceEqual(XAdESIdentifiers.DerEncodingUriUtf8))
            {
                encoding = XAdESPkiDataEncoding.Der;
            }
            else if(encodingValue.SequenceEqual(XAdESIdentifiers.BerEncodingUriUtf8))
            {
                encoding = XAdESPkiDataEncoding.Ber;
            }
            else if(encodingValue.SequenceEqual(XAdESIdentifiers.CerEncodingUriUtf8))
            {
                encoding = XAdESPkiDataEncoding.Cer;
            }
            else if(encodingValue.SequenceEqual(XAdESIdentifiers.PerEncodingUriUtf8))
            {
                encoding = XAdESPkiDataEncoding.Per;
            }
            else if(encodingValue.SequenceEqual(XAdESIdentifiers.XerEncodingUriUtf8))
            {
                encoding = XAdESPkiDataEncoding.Xer;
            }
            else
            {
                error = new XAdESReadError(XAdESReadFailure.UnrecognizedPkiDataEncoding, 0);

                return false;
            }
        }

        if(!XmlSignatureModelGrammar.TryDecodeSimpleBase64Content(table, elementIndex, pool, owned, out PooledMemory? content, out grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        value = new XAdESEncapsulatedPkiData(table, elementIndex, hasId, idOrdinal, encoding, content!);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESEncapsulatedPkiData other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESEncapsulatedPkiData other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESEncapsulatedPkiData left, XAdESEncapsulatedPkiData right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESEncapsulatedPkiData left, XAdESEncapsulatedPkiData right) => !left.Equals(right);
}
