using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// Which arm of <c>CertificateValuesType</c>'s <c>EncapsulatedX509Certificate</c>/<c>OtherCertificate</c>
/// choice (clause 5.4.2) a <see cref="XAdESCertificateValueEntry"/> holds.
/// </summary>
public enum XAdESCertificateValueKind
{
    /// <summary>The base-64 encoding of a DER-encoded X.509 certificate, within <c>EncapsulatedX509Certificate</c>.</summary>
    EncapsulatedX509Certificate,

    /// <summary>A placeholder for a potential future certificate format, within <c>OtherCertificate</c>.</summary>
    OtherCertificate
}


/// <summary>
/// One entry of a <see cref="XAdESCertificateValues"/> list: exactly one of
/// <see cref="EncapsulatedX509Certificate"/> or <see cref="OtherCertificate"/> is meaningful, selected by
/// <see cref="Kind"/> — the same two-arm-entry shape <see cref="XAdESCertifiedRole"/> takes for
/// <c>CertifiedRoleTypeV2</c>'s own choice.
/// </summary>
public readonly struct XAdESCertificateValueEntry: IEquatable<XAdESCertificateValueEntry>
{
    /// <summary>Which arm of the choice this entry holds.</summary>
    public XAdESCertificateValueKind Kind { get; }

    /// <summary>The <c>EncapsulatedX509Certificate</c> payload; meaningful only when <see cref="Kind"/> is <see cref="XAdESCertificateValueKind.EncapsulatedX509Certificate"/>.</summary>
    public XAdESEncapsulatedPkiData EncapsulatedX509Certificate { get; }

    /// <summary>The <c>OtherCertificate</c> payload; meaningful only when <see cref="Kind"/> is <see cref="XAdESCertificateValueKind.OtherCertificate"/>.</summary>
    public XAdESUnmodeledContent OtherCertificate { get; }


    private XAdESCertificateValueEntry(XAdESCertificateValueKind kind, XAdESEncapsulatedPkiData encapsulatedX509Certificate, XAdESUnmodeledContent otherCertificate)
    {
        Kind = kind;
        EncapsulatedX509Certificate = encapsulatedX509Certificate;
        OtherCertificate = otherCertificate;
    }


    /// <summary>Wraps an <c>EncapsulatedX509Certificate</c> payload.</summary>
    /// <param name="value">The read <c>EncapsulatedX509Certificate</c>, already narrowed to DER.</param>
    /// <returns>The wrapped entry.</returns>
    internal static XAdESCertificateValueEntry FromEncapsulatedX509Certificate(XAdESEncapsulatedPkiData value) => new(XAdESCertificateValueKind.EncapsulatedX509Certificate, value, default);


    /// <summary>Wraps an <c>OtherCertificate</c> payload.</summary>
    /// <param name="value">The unmodeled <c>OtherCertificate</c> content.</param>
    /// <returns>The wrapped entry.</returns>
    internal static XAdESCertificateValueEntry FromOtherCertificate(XAdESUnmodeledContent value) => new(XAdESCertificateValueKind.OtherCertificate, default, value);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESCertificateValueEntry other) =>
        Kind == other.Kind
        && (Kind == XAdESCertificateValueKind.EncapsulatedX509Certificate ? EncapsulatedX509Certificate.Equals(other.EncapsulatedX509Certificate) : OtherCertificate.Equals(other.OtherCertificate));


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESCertificateValueEntry other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Kind == XAdESCertificateValueKind.EncapsulatedX509Certificate ? HashCode.Combine(Kind, EncapsulatedX509Certificate) : HashCode.Combine(Kind, OtherCertificate);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESCertificateValueEntry left, XAdESCertificateValueEntry right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESCertificateValueEntry left, XAdESCertificateValueEntry right) => !left.Equals(right);
}


/// <summary>
/// The <c>CertificateValuesType</c> data type: an unbounded, individually-optional
/// (<c>xsd:choice minOccurs="0" maxOccurs="unbounded"</c>) sequence of <c>EncapsulatedX509Certificate</c>/
/// <c>OtherCertificate</c> entries plus an optional <c>Id</c>. This is the ONE shared reader backing BOTH the
/// <c>CertificateValues</c> qualifying property (clause 5.4.2) and the <c>AttrAuthoritiesCertValues</c>
/// qualifying property (clause 5.4.4, "shall be defined as in XML Schema file ...
/// <c>&lt;xsd:element name="AttrAuthoritiesCertValues" type="CertificateValuesType"/&gt;</c>" — no new complex
/// type of its own) — <see cref="TryRead"/> does not itself check the wrapping element's local name, the same
/// posture <see cref="XAdESDigestAlgAndValue"/> and <see cref="XAdESEncapsulatedPkiData"/> already take for
/// their own multiply-reused types.
/// </summary>
/// <remarks>
/// <para>
/// Zero entries is a legal read, not a refusal: the schema's own <c>minOccurs="0"</c> on the choice permits an
/// entirely empty <c>CertificateValues</c>/<c>AttrAuthoritiesCertValues</c> element (only the optional
/// <c>Id</c> attribute, no children), and clause 5.4 states no matching "empty ... shall not be generated"
/// floor the way clauses 5.2.5/5.2.6 do for <c>SignatureProductionPlaceV2</c>/<c>SignerRoleV2</c> — clause
/// 5.4.1's own framing ("A XAdES signature may contain certificates and/or revocation data within any of the
/// XAdES qualifying properties specified in this clause 5.4 as long as the specific requirements defined for
/// each qualifying property are met") leaves presence optional per-property with no cross-child count floor.
/// Annex A corroborates emptiness is contemplated by the specification itself for this exact construct: its
/// <c>CompleteCertificateRefsV2</c>/<c>AttributeCertificateRefsV2</c> clauses distinguish "<c>AnyValidationData</c>
/// with a <em>non empty</em> <c>CertificateValues</c> child element" from the general case, a qualifier that
/// would be redundant if an empty <c>CertificateValues</c> child were already impossible.
/// </para>
/// <para>
/// This is a clause-5.4 reader that decodes pooled content of its own (any <c>EncapsulatedX509Certificate</c>
/// entry, via <see cref="XAdESEncapsulatedPkiData"/>), so — like <see cref="XAdESSignerRoleV2"/> — it is itself
/// <see cref="IDisposable"/>, owning one flat custody list across every <see cref="Entries"/> entry's decoded
/// fields.
/// </para>
/// </remarks>
public sealed class XAdESCertificateValues: IDisposable
{
    /// <summary>
    /// The maximum number of <c>EncapsulatedX509Certificate</c>/<c>OtherCertificate</c> entries <see cref="TryRead"/>
    /// accepts under one <c>CertificateValues</c>/<c>AttrAuthoritiesCertValues</c> element before refusing with
    /// <see cref="XAdESReadFailure.EntryCountLimitExceeded"/> — a documented hardening bound, since each
    /// <c>EncapsulatedX509Certificate</c> entry base64-decodes a full certificate and the schema's own
    /// <c>xsd:choice maxOccurs="unbounded"</c> content model sets no numeric limit. Chosen generously above any
    /// legitimate certificate-chain-plus-cross-certificates set;
    /// <c>XAdESGrowthBoundsCostTests.CertificateValuesFloodIsRefusedWithNoPooledRent</c> measures a flood one
    /// entry past this bound refusing with no pooled rent, since an <c>OtherCertificate</c> entry carries no pooled content.
    /// </summary>
    public const int MaximumEntryCount = 4096;

    /// <summary>The document the property was read from. Not owned; the caller disposes it separately.</summary>
    public XmlNodeTable Table { get; }

    /// <summary>The <c>CertificateValues</c>/<c>AttrAuthoritiesCertValues</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>Every choice entry, in document order; possibly empty.</summary>
    public IReadOnlyList<XAdESCertificateValueEntry> Entries { get; }

    private List<PooledMemory> OwnedContent { get; }

    private bool isDisposed;


    private XAdESCertificateValues(XmlNodeTable table, int elementIndex, bool hasId, int idAttributeOrdinal, IReadOnlyList<XAdESCertificateValueEntry> entries, List<PooledMemory> ownedContent)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        Entries = entries;
        OwnedContent = ownedContent;
    }


    /// <summary>
    /// Reads a <c>CertificateValuesType</c>-shaped element: its optional <c>Id</c> attribute, then every
    /// <c>EncapsulatedX509Certificate</c>/<c>OtherCertificate</c> choice member in document order. Every
    /// <c>EncapsulatedX509Certificate</c> entry is narrowed to DER — "The <c>EncapsulatedX509Certificate</c>
    /// element shall contain the base-64 encoding of a DER-encoded X.509 certificate" (clause 5.4.2) — a
    /// per-usage-site restriction of <see cref="XAdESEncapsulatedPkiData"/>'s general five-encoding
    /// enumeration, per clause 5.1.3 NOTE 2. <c>OtherCertificate</c> entries carry no such restriction: their
    /// content is <c>AnyType</c>, not <c>EncapsulatedPKIDataType</c>.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>CertificateValues</c> or <c>AttrAuthoritiesCertValues</c> element —
    /// typically obtained from a <see cref="XAdESUnsignedSignaturePropertyEntry"/> whose
    /// <see cref="XAdESUnsignedSignaturePropertyEntry.Name"/> is
    /// <see cref="XAdESUnsignedSignaturePropertyName.CertificateValues"/> or
    /// <see cref="XAdESUnsignedSignaturePropertyName.AttrAuthoritiesCertValues"/>.</param>
    /// <param name="pool">The pool every decoded field is rented from.</param>
    /// <param name="value">The read model on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESReadFailure.EncapsulatedPkiDataNotDerEncoded"/> when an <c>EncapsulatedX509Certificate</c>
    /// carries a non-DER <c>Encoding</c>; <see cref="XAdESReadFailure.UnknownCoreElement"/> for a child that is
    /// neither choice member.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, out XAdESCertificateValues? value, out XAdESReadError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(pool);
        value = null;
        var owned = new List<PooledMemory>();
        try
        {
            bool hasId = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Id"u8, out int idOrdinal);
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, hasId ? 1 : 0, out XmlSignatureReadError grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            var entries = new List<XAdESCertificateValueEntry>();
            ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }

            while(scan == ElementScanResult.Found)
            {
                bool isX509 = XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "EncapsulatedX509Certificate"u8);
                bool isOther = !isX509 && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "OtherCertificate"u8);
                if(!isX509 && !isOther)
                {
                    error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

                    return false;
                }

                if(isX509)
                {
                    if(!XAdESEncapsulatedPkiData.TryRead(table, child, pool, owned, out XAdESEncapsulatedPkiData pkiData, out error))
                    {
                        return false;
                    }

                    if(pkiData.Encoding != XAdESPkiDataEncoding.Der)
                    {
                        error = new XAdESReadError(XAdESReadFailure.EncapsulatedPkiDataNotDerEncoded, 0);

                        return false;
                    }

                    entries.Add(XAdESCertificateValueEntry.FromEncapsulatedX509Certificate(pkiData));
                }
                else
                {
                    entries.Add(XAdESCertificateValueEntry.FromOtherCertificate(XAdESUnmodeledContent.Read(table, child)));
                }

                if(entries.Count > MaximumEntryCount)
                {
                    error = new XAdESReadError(XAdESReadFailure.EntryCountLimitExceeded, 0);

                    return false;
                }

                scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
                if(scan == ElementScanResult.UnexpectedContent)
                {
                    error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                    return false;
                }
            }

            value = new XAdESCertificateValues(table, elementIndex, hasId, idOrdinal, entries, owned);
            error = default;

            return true;
        }
        finally
        {
            if(value is null)
            {
                for(int i = 0; i < owned.Count; ++i)
                {
                    owned[i].Dispose();
                }
            }
        }
    }


    /// <summary>
    /// Tells whether this value was read over the given table instance — the identity guard this library
    /// requires before any processing that combines this value with another table-scoped argument.
    /// </summary>
    /// <param name="table">The table to check against.</param>
    /// <returns><see langword="true"/> when this value was read from the same table instance.</returns>
    public bool IsOver(XmlNodeTable table)
    {
        return ReferenceEquals(Table, table);
    }


    /// <summary>
    /// Releases every decoded field every <see cref="Entries"/> entry owns. <see cref="Table"/> is not owned
    /// and is not disposed here. Idempotent.
    /// </summary>
    public void Dispose()
    {
        if(isDisposed)
        {
            return;
        }

        isDisposed = true;
        for(int i = 0; i < OwnedContent.Count; ++i)
        {
            OwnedContent[i].Dispose();
        }
    }
}
