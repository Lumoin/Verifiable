using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// One <c>RecomputedDigestValue</c> entry of a <see cref="XAdESRenewedDigestsV2"/>: <c>NewSDODigestValue</c>
/// then <c>OriginalRefDigest</c>, each a base64Binary-typed <c>ds:DigestValueType</c> value decoded to pooled
/// octets (clause 5.5.3, <c>RecomputedDigestValueType</c>). Neither child carries an attribute of its own — the
/// schema types both as the bare <c>ds:DigestValueType</c> simple type.
/// </summary>
public readonly struct XAdESRecomputedDigestValue: IEquatable<XAdESRecomputedDigestValue>
{
    /// <summary>The table the value's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>RecomputedDigestValue</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>
    /// The decoded <c>NewSDODigestValue</c> octets, tagged <see cref="BufferTags.XmlDecodedContent"/> — "the
    /// digest value, computed using the algorithm indicated in the [sibling] <c>ds:DigestMethod</c> element, of
    /// one of the signed detached objects" (XA-5.5.3-10).
    /// </summary>
    public PooledMemory NewSDODigestValueOctets { get; }

    /// <summary>
    /// The decoded <c>OriginalRefDigest</c> octets, tagged <see cref="BufferTags.XmlDecodedContent"/> — the
    /// digest, computed with the same <c>ds:DigestMethod</c>, of the CANONICALIZED <c>ds:Reference</c> element
    /// (not the referenced object) that names the detached object <see cref="NewSDODigestValueOctets"/> is about
    /// (XA-5.5.3-11/-12).
    /// </summary>
    public PooledMemory OriginalRefDigestOctets { get; }


    internal XAdESRecomputedDigestValue(XmlNodeTable table, int elementIndex, PooledMemory newSDODigestValueOctets, PooledMemory originalRefDigestOctets)
    {
        Table = table;
        ElementIndex = elementIndex;
        NewSDODigestValueOctets = newSDODigestValueOctets;
        OriginalRefDigestOctets = originalRefDigestOctets;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESRecomputedDigestValue other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESRecomputedDigestValue other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESRecomputedDigestValue left, XAdESRecomputedDigestValue right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESRecomputedDigestValue left, XAdESRecomputedDigestValue right) => !left.Equals(right);
}


/// <summary>
/// The <c>RenewedDigestsV2</c> qualifying property of clause 5.5.3: <c>ds:CanonicalizationMethod</c> then
/// <c>ds:DigestMethod</c> — BOTH MANDATORY here, unlike every optional <c>ds:CanonicalizationMethod</c>
/// elsewhere in this leg (contrast <see cref="XAdESTimeStamp.HasCanonicalizationMethod"/>) — then one-or-more
/// <c>RecomputedDigestValue</c> entries, plus an optional <c>Id</c>. Honors a spec defect: clause 5.5.3's own
/// basic classification sentence uses non-modal "is" ("The <c>RenewedDigestsV2</c> qualifying property IS an
/// unsigned qualifying property...") where every sibling property in this leg says "shall be" — this leaf treats
/// it as the shall it plainly states, an unsigned qualifying property qualifying the signature. Honors another
/// spec defect: the clause's own prose misspells the child element name <c>ds:CanonicalizationMehtod</c> at exactly
/// one sentence (the <c>OriginalRefDigest</c> definition); the element itself, the schema, and every other prose
/// occurrence spell it correctly, and this reader matches that correct spelling — the one-off typo has no
/// normative-force impact.
/// </summary>
/// <remarks>
/// <para>
/// The one property in this whole leg whose schema embeds XMLDSIG-namespace element refs directly
/// (<c>ds:CanonicalizationMethod</c>, <c>ds:DigestMethod</c>) rather than going through a XAdES-defined
/// digest-carrier wrapper — <see cref="XAdESDigestAlgAndValue"/> does not apply here, since this type's
/// <c>ds:DigestMethod</c> has no sibling <c>ds:DigestValue</c> (the digest VALUES live one level down, inside
/// each <see cref="XAdESRecomputedDigestValue"/> entry, under XAdES-named — not <c>ds</c>-named —
/// <c>NewSDODigestValue</c>/<c>OriginalRefDigest</c> children).
/// </para>
/// <para>
/// The XA-5.5.3-3 "shall not be used if the signature contains no [...] signed <c>ds:Manifest</c> [...]
/// referencing detached data objects" precondition and the six-step validation procedure (XA-5.5.3-13) are
/// <see cref="XAdESRenewedDigestsV2Processing"/>'s concern, layered above this structural read.
/// </para>
/// <para>
/// Owns every decoded field (the <c>ds:DigestMethod Algorithm</c> attribute is a plain span, never decoded, but
/// every <see cref="XAdESRecomputedDigestValue"/> entry's two base64 fields are), so is itself
/// <see cref="IDisposable"/>.
/// </para>
/// </remarks>
public sealed class XAdESRenewedDigestsV2: IDisposable
{
    /// <summary>The document the property was read from. Not owned; the caller disposes it separately.</summary>
    public XmlNodeTable Table { get; }

    /// <summary>The <c>RenewedDigestsV2</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>
    /// The mandatory <c>ds:CanonicalizationMethod</c> child — "shall identify a canonicalization algorithm"
    /// (clause 5.5.3), the algorithm every <see cref="XAdESRecomputedDigestValue.OriginalRefDigestOctets"/>
    /// computation canonicalizes its candidate <c>ds:Reference</c> with.
    /// </summary>
    public XmlCanonicalizationMethodInfo CanonicalizationMethod { get; }

    /// <summary>The <c>ds:DigestMethod</c> element's own index.</summary>
    public int DigestMethodElementIndex { get; }

    private int DigestMethodAlgorithmAttributeOrdinal { get; }

    /// <summary>
    /// The mandatory <c>ds:DigestMethod</c>'s <c>Algorithm</c> URI, exact-character — "shall identify the digest
    /// algorithm used for recomputing digest values of the [...] detached signed data objects" (clause 5.5.3),
    /// the algorithm every <see cref="XAdESRecomputedDigestValue"/> entry's two digest fields were computed with.
    /// </summary>
    public ReadOnlySpan<byte> DigestMethodAlgorithm => Table.AttributeValueOf(DigestMethodElementIndex, DigestMethodAlgorithmAttributeOrdinal);

    /// <summary>Every <c>RecomputedDigestValue</c> entry, in document order; at least one.</summary>
    public IReadOnlyList<XAdESRecomputedDigestValue> RecomputedDigestValues { get; }

    private List<PooledMemory> OwnedContent { get; }

    private bool isDisposed;


    private XAdESRenewedDigestsV2(
        XmlNodeTable table,
        int elementIndex,
        bool hasId,
        int idAttributeOrdinal,
        XmlCanonicalizationMethodInfo canonicalizationMethod,
        int digestMethodElementIndex,
        int digestMethodAlgorithmAttributeOrdinal,
        IReadOnlyList<XAdESRecomputedDigestValue> recomputedDigestValues,
        List<PooledMemory> ownedContent)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        CanonicalizationMethod = canonicalizationMethod;
        DigestMethodElementIndex = digestMethodElementIndex;
        DigestMethodAlgorithmAttributeOrdinal = digestMethodAlgorithmAttributeOrdinal;
        RecomputedDigestValues = recomputedDigestValues;
        OwnedContent = ownedContent;
    }


    /// <summary>
    /// Reads a <c>RenewedDigestsV2</c> element: its optional <c>Id</c> attribute, then its mandatory
    /// <c>ds:CanonicalizationMethod</c>, mandatory <c>ds:DigestMethod</c>, and one-or-more
    /// <c>RecomputedDigestValue</c> children, in that fixed order.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>RenewedDigestsV2</c> element — typically obtained from an
    /// <see cref="XAdESUnsignedSignaturePropertyEntry"/> whose
    /// <see cref="XAdESUnsignedSignaturePropertyEntry.Name"/> is
    /// <see cref="XAdESUnsignedSignaturePropertyName.Unrecognized"/> and whose element identity is separately
    /// confirmed to be this v1.4.1-namespace element.</param>
    /// <param name="pool">The pool every decoded field is rented from.</param>
    /// <param name="value">The read model on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESReadFailure.UnknownCoreElement"/> when the element is not the v1.4.1-namespace
    /// <c>RenewedDigestsV2</c>;
    /// <see cref="XAdESReadFailure.MissingRequiredChild"/> when <c>ds:CanonicalizationMethod</c>,
    /// <c>ds:DigestMethod</c> or every <c>RecomputedDigestValue</c> is absent;
    /// <see cref="XAdESReadFailure.MissingRequiredAttribute"/> when <c>ds:DigestMethod</c>'s own <c>Algorithm</c>
    /// is absent.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, out XAdESRenewedDigestsV2? value, out XAdESReadError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(pool);
        value = null;
        if(!XmlSignatureModelGrammar.IsElement(table, elementIndex, XAdESIdentifiers.XAdESNamespaceV141Utf8, "RenewedDigestsV2"u8))
        {
            error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

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
            if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsDsElement(table, child, "CanonicalizationMethod"u8))
            {
                error = new XAdESReadError(
                    scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

                return false;
            }

            if(!XmlCanonicalizationMethodInfo.TryRead(table, child, out XmlCanonicalizationMethodInfo canonicalizationMethod, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out int digestMethodElementIndex);
            if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsDsElement(table, digestMethodElementIndex, "DigestMethod"u8))
            {
                error = new XAdESReadError(
                    scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

                return false;
            }

            if(!XmlSignatureModelGrammar.TryFindAttribute(table, digestMethodElementIndex, "Algorithm"u8, out int digestAlgorithmOrdinal))
            {
                error = new XAdESReadError(XAdESReadFailure.MissingRequiredAttribute, 0);

                return false;
            }

            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, digestMethodElementIndex, 1, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, digestMethodElementIndex, out int current);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }

            var recomputedDigestValues = new List<XAdESRecomputedDigestValue>();
            while(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, current, XAdESIdentifiers.XAdESNamespaceV141Utf8, "RecomputedDigestValue"u8))
            {
                if(!TryReadRecomputedDigestValue(table, current, pool, owned, out XAdESRecomputedDigestValue recomputedDigestValue, out error))
                {
                    return false;
                }

                recomputedDigestValues.Add(recomputedDigestValue);
                scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, current, out current);
                if(scan == ElementScanResult.UnexpectedContent)
                {
                    error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                    return false;
                }
            }

            if(recomputedDigestValues.Count == 0)
            {
                error = new XAdESReadError(XAdESReadFailure.MissingRequiredChild, 0);

                return false;
            }

            if(scan == ElementScanResult.Found)
            {
                error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

                return false;
            }

            value = new XAdESRenewedDigestsV2(table, elementIndex, hasId, idOrdinal, canonicalizationMethod, digestMethodElementIndex, digestAlgorithmOrdinal, recomputedDigestValues, owned);
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
    /// Reads one <c>RecomputedDigestValue</c> element: its <c>NewSDODigestValue</c> then <c>OriginalRefDigest</c>
    /// children, in that fixed order, no attributes on the wrapping element or either child.
    /// </summary>
    private static bool TryReadRecomputedDigestValue(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out XAdESRecomputedDigestValue value, out XAdESReadError error)
    {
        value = default;
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 0, out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
        if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV141Utf8, "NewSDODigestValue"u8))
        {
            error = new XAdESReadError(
                scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

            return false;
        }

        if(!XmlSignatureModelGrammar.TryDecodeSimpleBase64Content(table, child, pool, owned, out PooledMemory? newSDODigestValueOctets, out grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out int originalRefDigestElementIndex);
        if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsElement(table, originalRefDigestElementIndex, XAdESIdentifiers.XAdESNamespaceV141Utf8, "OriginalRefDigest"u8))
        {
            error = new XAdESReadError(
                scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

            return false;
        }

        if(!XmlSignatureModelGrammar.TryDecodeSimpleBase64Content(table, originalRefDigestElementIndex, pool, owned, out PooledMemory? originalRefDigestOctets, out grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, originalRefDigestElementIndex, out int trailing);
        if(scan != ElementScanResult.EndOfChildren)
        {
            error = new XAdESReadError(
                scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.UnknownCoreElement, 0);
            _ = trailing;

            return false;
        }

        value = new XAdESRecomputedDigestValue(table, elementIndex, newSDODigestValueOctets!, originalRefDigestOctets!);
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
    /// Releases every decoded <see cref="XAdESRecomputedDigestValue"/> field. <see cref="Table"/> is not owned
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
