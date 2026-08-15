using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The <c>RevocationValuesType</c> data type: three individually-optional lists in fixed sequence order —
/// <c>CRLValues</c> (one-or-more <c>EncapsulatedCRLValue</c> entries, each narrowed to DER), <c>OCSPValues</c>
/// (one-or-more <c>EncapsulatedOCSPValue</c> entries, each narrowed to DER), <c>OtherValues</c> (one-or-more
/// unmodeled <c>OtherValue</c> entries) — plus an optional <c>Id</c>. This is the ONE shared reader backing
/// BOTH the <c>RevocationValues</c> qualifying property (clause 5.4.3) and the
/// <c>AttributeRevocationValues</c> qualifying property (clause 5.4.5, "shall be defined as in XML Schema file
/// ... <c>&lt;xsd:element name="AttributeRevocationValues" type="RevocationValuesType"/&gt;</c>" — no new
/// complex type of its own) — <see cref="TryRead"/> does not itself check the wrapping element's local name,
/// the same posture <see cref="XAdESCertificateValues"/> takes for its own multiply-reused type.
/// </summary>
/// <remarks>
/// <para>
/// A completely empty <c>RevocationValues</c>/<c>AttributeRevocationValues</c> element (none of the three
/// lists present, only the optional <c>Id</c> attribute) is a legal read: every child of
/// <c>RevocationValuesType</c>'s <c>xsd:sequence</c> is individually <c>minOccurs="0"</c> and clause 5.4
/// states no cross-child count floor for this property (clause 5.4.1's framing, restated at
/// <see cref="XAdESCertificateValues"/>'s own remarks). Once present, though, each of the three lists must
/// carry at least one entry — the schema's own <c>maxOccurs="unbounded"</c> children of <c>CRLValuesType</c>/
/// <c>OCSPValuesType</c>/<c>OtherCertStatusValuesType</c> default to <c>minOccurs="1"</c> — enforced here as
/// <see cref="XAdESReadFailure.MissingRequiredChild"/>, the same "present list carries zero entries" posture
/// <see cref="XAdESSignerRoleV2"/> already applies to its own three optional lists.
/// </para>
/// <para>
/// This document does not implement the Delta-CRL completeness rules of clause 5.4.3 ("If the validation data
/// contain one or more Delta CRLs, the <c>CRLValues</c> element shall contain the set of CRLs required to
/// provide complete revocation lists") — determining whether an encapsulated CRL is a Delta CRL requires
/// parsing its DER content, which this crypto-free leaf never does; the DER bytes
/// stay opaque pooled content and this rule is a recorded, verification-side disposition.
/// </para>
/// <para>
/// This is a clause-5.4 reader that decodes pooled content of its own (any <c>EncapsulatedCRLValue</c>/
/// <c>EncapsulatedOCSPValue</c> entry, via <see cref="XAdESEncapsulatedPkiData"/>), so — like
/// <see cref="XAdESCertificateValues"/> — it is itself <see cref="IDisposable"/>, owning one flat custody list
/// across every decoded field.
/// </para>
/// </remarks>
public sealed class XAdESRevocationValues: IDisposable
{
    /// <summary>
    /// The maximum number of <c>EncapsulatedCRLValue</c>/<c>EncapsulatedOCSPValue</c> entries
    /// <see cref="TryReadNonEmptyEncapsulatedList"/> accepts under one <c>CRLValues</c>/<c>OCSPValues</c> list
    /// element before refusing with <see cref="XAdESReadFailure.EntryCountLimitExceeded"/> — a documented
    /// hardening bound, since each entry base64-decodes a full CRL/OCSP response and the schema's own
    /// <c>maxOccurs="unbounded"</c> content model sets no numeric limit. Chosen generously above any legitimate
    /// validation-data set's own size; <c>XAdESGrowthBoundsCostTests.RevocationValuesEncapsulatedFloodIsRefusedWithinTheCeiling</c>
    /// measures a flood one entry past this bound refusing well inside its own loose ceiling.
    /// </summary>
    public const int MaximumEncapsulatedEntryCount = 4096;

    /// <summary>
    /// The maximum number of entries <see cref="TryReadNonEmptyUnmodeledList"/> accepts under one unmodeled
    /// list element before refusing with <see cref="XAdESReadFailure.EntryCountLimitExceeded"/> — shared by
    /// this type's own <c>OtherValues</c> and <see cref="XAdESCompleteRevocationRefs"/>'s <c>OtherRefs</c>
    /// (the method's own remarks). A documented hardening bound; the schema's own <c>maxOccurs="unbounded"</c>
    /// content model sets no numeric limit; <c>XAdESGrowthBoundsCostTests.RevocationValuesUnmodeledFloodIsRefusedWithinTheCeiling</c>
    /// measures a flood one entry past this bound refusing well inside its own loose ceiling.
    /// </summary>
    public const int MaximumUnmodeledEntryCount = 4096;

    /// <summary>The document the property was read from. Not owned; the caller disposes it separately.</summary>
    public XmlNodeTable Table { get; }

    /// <summary>The <c>RevocationValues</c>/<c>AttributeRevocationValues</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>Whether the optional <c>CRLValues</c> child is present.</summary>
    public bool HasCrlValues { get; }

    /// <summary>The <c>EncapsulatedCRLValue</c> entries, in document order, each DER-narrowed; non-empty when <see cref="HasCrlValues"/> is <see langword="true"/>, empty otherwise.</summary>
    public IReadOnlyList<XAdESEncapsulatedPkiData> CrlValues { get; }

    /// <summary>Whether the optional <c>OCSPValues</c> child is present.</summary>
    public bool HasOcspValues { get; }

    /// <summary>The <c>EncapsulatedOCSPValue</c> entries, in document order, each DER-narrowed; non-empty when <see cref="HasOcspValues"/> is <see langword="true"/>, empty otherwise.</summary>
    public IReadOnlyList<XAdESEncapsulatedPkiData> OcspValues { get; }

    /// <summary>Whether the optional <c>OtherValues</c> child is present.</summary>
    public bool HasOtherValues { get; }

    /// <summary>The <c>OtherValue</c> entries' unmodeled content, in document order; non-empty when <see cref="HasOtherValues"/> is <see langword="true"/>, empty otherwise.</summary>
    public IReadOnlyList<XAdESUnmodeledContent> OtherValues { get; }

    private List<PooledMemory> OwnedContent { get; }

    private bool isDisposed;


    private XAdESRevocationValues(
        XmlNodeTable table,
        int elementIndex,
        bool hasId,
        int idAttributeOrdinal,
        bool hasCrlValues,
        IReadOnlyList<XAdESEncapsulatedPkiData> crlValues,
        bool hasOcspValues,
        IReadOnlyList<XAdESEncapsulatedPkiData> ocspValues,
        bool hasOtherValues,
        IReadOnlyList<XAdESUnmodeledContent> otherValues,
        List<PooledMemory> ownedContent)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        HasCrlValues = hasCrlValues;
        CrlValues = crlValues;
        HasOcspValues = hasOcspValues;
        OcspValues = ocspValues;
        HasOtherValues = hasOtherValues;
        OtherValues = otherValues;
        OwnedContent = ownedContent;
    }


    /// <summary>
    /// Reads a <c>RevocationValuesType</c>-shaped element: its optional <c>Id</c> attribute, then its optional
    /// <c>CRLValues</c>, <c>OCSPValues</c> and <c>OtherValues</c> children, in that fixed order.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>RevocationValues</c> or <c>AttributeRevocationValues</c> element —
    /// typically obtained from a <see cref="XAdESUnsignedSignaturePropertyEntry"/> whose
    /// <see cref="XAdESUnsignedSignaturePropertyEntry.Name"/> is
    /// <see cref="XAdESUnsignedSignaturePropertyName.RevocationValues"/> or
    /// <see cref="XAdESUnsignedSignaturePropertyName.AttributeRevocationValues"/>.</param>
    /// <param name="pool">The pool every decoded field is rented from.</param>
    /// <param name="value">The read model on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESReadFailure.MissingRequiredChild"/> when a present list carries zero entries;
    /// <see cref="XAdESReadFailure.EncapsulatedPkiDataNotDerEncoded"/> when an <c>EncapsulatedCRLValue</c>/
    /// <c>EncapsulatedOCSPValue</c> carries a non-DER <c>Encoding</c>.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, out XAdESRevocationValues? value, out XAdESReadError error)
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

            ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }

            bool hasCrlValues = false;
            var crlValues = new List<XAdESEncapsulatedPkiData>();
            if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "CRLValues"u8))
            {
                int listElementIndex = child;
                if(!TryReadNonEmptyEncapsulatedList(table, listElementIndex, "EncapsulatedCRLValue"u8, pool, owned, crlValues, out error))
                {
                    return false;
                }

                hasCrlValues = true;
                scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, listElementIndex, out child);
                if(scan == ElementScanResult.UnexpectedContent)
                {
                    error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                    return false;
                }
            }

            bool hasOcspValues = false;
            var ocspValues = new List<XAdESEncapsulatedPkiData>();
            if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "OCSPValues"u8))
            {
                int listElementIndex = child;
                if(!TryReadNonEmptyEncapsulatedList(table, listElementIndex, "EncapsulatedOCSPValue"u8, pool, owned, ocspValues, out error))
                {
                    return false;
                }

                hasOcspValues = true;
                scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, listElementIndex, out child);
                if(scan == ElementScanResult.UnexpectedContent)
                {
                    error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                    return false;
                }
            }

            bool hasOtherValues = false;
            var otherValues = new List<XAdESUnmodeledContent>();
            if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "OtherValues"u8))
            {
                int listElementIndex = child;
                if(!TryReadNonEmptyUnmodeledList(table, listElementIndex, "OtherValue"u8, otherValues, out error))
                {
                    return false;
                }

                hasOtherValues = true;
                scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, listElementIndex, out child);
                if(scan == ElementScanResult.UnexpectedContent)
                {
                    error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                    return false;
                }
            }

            if(scan == ElementScanResult.Found)
            {
                bool isRepeat = (hasCrlValues && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "CRLValues"u8))
                    || (hasOcspValues && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "OCSPValues"u8))
                    || (hasOtherValues && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "OtherValues"u8));
                error = new XAdESReadError(isRepeat ? XAdESReadFailure.DuplicateCoreChild : XAdESReadFailure.UnknownCoreElement, 0);

                return false;
            }

            value = new XAdESRevocationValues(table, elementIndex, hasId, idOrdinal, hasCrlValues, crlValues, hasOcspValues, ocspValues, hasOtherValues, otherValues, owned);
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
    /// Reads a <c>CRLValues</c>/<c>OCSPValues</c>-shaped list element: no attributes of its own, then a
    /// non-empty sequence of same-named <c>EncapsulatedPKIDataType</c> children, each narrowed to DER.
    /// </summary>
    private static bool TryReadNonEmptyEncapsulatedList(
        XmlNodeTable table,
        int listElementIndex,
        ReadOnlySpan<byte> memberLocalName,
        BaseMemoryPool pool,
        List<PooledMemory> owned,
        List<XAdESEncapsulatedPkiData> entries,
        out XAdESReadError error)
    {
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, listElementIndex, 0, out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        if(!XmlSignatureModelGrammar.TryReadElementChildren(table, listElementIndex, out List<int> memberElements, out grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        if(memberElements.Count == 0)
        {
            error = new XAdESReadError(XAdESReadFailure.MissingRequiredChild, 0);

            return false;
        }

        if(memberElements.Count > MaximumEncapsulatedEntryCount)
        {
            error = new XAdESReadError(XAdESReadFailure.EntryCountLimitExceeded, 0);

            return false;
        }

        foreach(int memberElement in memberElements)
        {
            if(!XmlSignatureModelGrammar.IsElement(table, memberElement, XAdESIdentifiers.XAdESNamespaceV132Utf8, memberLocalName))
            {
                error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

                return false;
            }

            if(!XAdESEncapsulatedPkiData.TryRead(table, memberElement, pool, owned, out XAdESEncapsulatedPkiData pkiData, out error))
            {
                return false;
            }

            if(pkiData.Encoding != XAdESPkiDataEncoding.Der)
            {
                error = new XAdESReadError(XAdESReadFailure.EncapsulatedPkiDataNotDerEncoded, 0);

                return false;
            }

            entries.Add(pkiData);
        }

        error = default;

        return true;
    }


    /// <summary>
    /// Reads an <c>OtherValues</c>-shaped list element: no attributes of its own, then a non-empty sequence of
    /// same-named <c>AnyType</c> children, each carried unmodeled. Shared beyond this type's own
    /// <c>OtherValues</c>/<c>OtherValue</c> use: <see cref="XAdESCompleteRevocationRefs"/>'s Annex A.1.2/A.1.4
    /// <c>OtherRefs</c>/<c>OtherRef</c> list is the identical shape (a non-empty sequence of same-named
    /// <c>AnyType</c> children), so it calls this method directly with its own member local name rather than
    /// re-implementing the loop, the same additive-reuse posture <see cref="XAdESDigestAlgAndValue"/> and
    /// <see cref="XAdESSigningCertificateV2.TryReadCertIdListV2"/> already establish for their own shared cores.
    /// </summary>
    internal static bool TryReadNonEmptyUnmodeledList(XmlNodeTable table, int listElementIndex, ReadOnlySpan<byte> memberLocalName, List<XAdESUnmodeledContent> entries, out XAdESReadError error)
    {
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, listElementIndex, 0, out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        if(!XmlSignatureModelGrammar.TryReadElementChildren(table, listElementIndex, out List<int> memberElements, out grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        if(memberElements.Count == 0)
        {
            error = new XAdESReadError(XAdESReadFailure.MissingRequiredChild, 0);

            return false;
        }

        if(memberElements.Count > MaximumUnmodeledEntryCount)
        {
            error = new XAdESReadError(XAdESReadFailure.EntryCountLimitExceeded, 0);

            return false;
        }

        foreach(int memberElement in memberElements)
        {
            if(!XmlSignatureModelGrammar.IsElement(table, memberElement, XAdESIdentifiers.XAdESNamespaceV132Utf8, memberLocalName))
            {
                error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

                return false;
            }

            entries.Add(XAdESUnmodeledContent.Read(table, memberElement));
        }

        error = default;

        return true;
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
    /// Releases every decoded <see cref="CrlValues"/>/<see cref="OcspValues"/> field. <see cref="Table"/> is
    /// not owned and is not disposed here. Idempotent.
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
