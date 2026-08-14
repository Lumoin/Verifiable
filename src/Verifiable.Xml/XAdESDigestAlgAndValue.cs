using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The <c>DigestAlgAndValueType</c> data type — a <c>ds:DigestMethod</c> then <c>ds:DigestValue</c> pair with
/// no attribute of its own — first declared in clause 5.2.2 as <c>CertDigest</c>'s content, and reused
/// unchanged for <c>SigPolicyHash</c> (clause 5.2.9.1) and the CRL/OCSP reference types' own
/// <c>DigestAlgAndValue</c> element (Annex A). This is the ONE shared digest-carrier reader used everywhere:
/// <see cref="TryRead"/> does not itself check the wrapping element's local name, so
/// every one of those differently-named elements reads through this single type rather than a per-property
/// copy — a leaf-local grammar primitive equally shared by the clause 5.1 auxiliary-type readers
/// (<c>ObjectIdentifierType</c>'s own <c>SigPolicyHash</c> sibling field) rather than a concern any single
/// property owns alone.
/// </summary>
/// <remarks>
/// The fixed <c>ds:DigestMethod</c> then <c>ds:DigestValue</c> child sequence this type reads is itself
/// shared one level deeper, through <see cref="TryReadDigestMethodAndValue"/>, with clause 5.1.4.3's
/// <c>ReferenceInfoType</c> (<see cref="XAdESReferenceInfo"/>): the two types agree on this child shape but
/// differ on which attributes the wrapping element itself may carry — none for
/// <c>DigestAlgAndValueType</c>, optional <c>Id</c>/<c>URI</c> for <c>ReferenceInfoType</c> — so the shared
/// core skips the wrapping element's own attribute validation, leaving that to each caller.
/// </remarks>
public readonly struct XAdESDigestAlgAndValue: IEquatable<XAdESDigestAlgAndValue>
{
    /// <summary>The table the value's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The wrapping element's own index (e.g. <c>CertDigest</c>, <c>SigPolicyHash</c>).</summary>
    public int ElementIndex { get; }

    /// <summary>The <c>ds:DigestMethod</c> element's own index.</summary>
    public int DigestMethodElementIndex { get; }

    private int DigestMethodAlgorithmAttributeOrdinal { get; }

    /// <summary>The <c>ds:DigestMethod</c>'s <c>Algorithm</c> URI, exact-character.</summary>
    public ReadOnlySpan<byte> DigestMethodAlgorithm => Table.AttributeValueOf(DigestMethodElementIndex, DigestMethodAlgorithmAttributeOrdinal);

    /// <summary>The <c>ds:DigestValue</c> element's own index.</summary>
    public int DigestValueElementIndex { get; }

    /// <summary>The decoded <c>ds:DigestValue</c> octets, tagged <see cref="BufferTags.XmlDecodedContent"/>.</summary>
    public PooledMemory DigestValueOctets { get; }


    private XAdESDigestAlgAndValue(
        XmlNodeTable table,
        int elementIndex,
        int digestMethodElementIndex,
        int digestMethodAlgorithmAttributeOrdinal,
        int digestValueElementIndex,
        PooledMemory digestValueOctets)
    {
        Table = table;
        ElementIndex = elementIndex;
        DigestMethodElementIndex = digestMethodElementIndex;
        DigestMethodAlgorithmAttributeOrdinal = digestMethodAlgorithmAttributeOrdinal;
        DigestValueElementIndex = digestValueElementIndex;
        DigestValueOctets = digestValueOctets;
    }


    /// <summary>
    /// Reads a <c>DigestAlgAndValueType</c>-shaped element: its <c>ds:DigestMethod</c> then
    /// <c>ds:DigestValue</c> children, in that fixed order, and nothing else — the type declares no
    /// attribute of its own.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>DigestAlgAndValueType</c>-typed element.</param>
    /// <param name="pool">The pool <see cref="DigestValueOctets"/> is rented from.</param>
    /// <param name="owned">The caller's custody list. <see cref="DigestValueOctets"/> is appended as it is
    /// read, including on paths that subsequently refuse — the caller must dispose the list when this method
    /// returns <see langword="false"/>.</param>
    /// <param name="value">The read model on success.</param>
    /// <param name="error">The refusal on failure.</param>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out XAdESDigestAlgAndValue value, out XAdESReadError error)
    {
        value = default;
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 0, out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        return TryReadDigestMethodAndValue(table, elementIndex, pool, owned, out value, out error);
    }


    /// <summary>
    /// Reads the <c>ds:DigestMethod</c> then <c>ds:DigestValue</c> child sequence alone, without validating
    /// the wrapping element's own attribute count — the core <see cref="TryRead"/> and
    /// <see cref="XAdESReferenceInfo.TryRead"/> both delegate to, each having already validated the
    /// attributes its own type declares.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The wrapping element whose <c>ds:DigestMethod</c>/<c>ds:DigestValue</c>
    /// children are read.</param>
    /// <param name="pool">The pool <see cref="DigestValueOctets"/> is rented from.</param>
    /// <param name="owned">The caller's custody list. <see cref="DigestValueOctets"/> is appended as it is
    /// read, including on paths that subsequently refuse — the caller must dispose the list when this method
    /// returns <see langword="false"/>.</param>
    /// <param name="value">The read model on success.</param>
    /// <param name="error">The refusal on failure.</param>
    internal static bool TryReadDigestMethodAndValue(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out XAdESDigestAlgAndValue value, out XAdESReadError error)
    {
        value = default;
        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
        if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsDsElement(table, child, "DigestMethod"u8))
        {
            error = new XAdESReadError(
                scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

            return false;
        }

        int digestMethodElementIndex = child;
        if(!XmlSignatureModelGrammar.TryFindAttribute(table, digestMethodElementIndex, "Algorithm"u8, out int digestAlgorithmOrdinal))
        {
            error = new XAdESReadError(XAdESReadFailure.MissingRequiredAttribute, 0);

            return false;
        }

        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, digestMethodElementIndex, 1, out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, digestMethodElementIndex, out int digestValueElementIndex);
        if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsDsElement(table, digestValueElementIndex, "DigestValue"u8))
        {
            error = new XAdESReadError(
                scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

            return false;
        }

        if(!XmlSignatureModelGrammar.TryDecodeSimpleBase64Content(table, digestValueElementIndex, pool, owned, out PooledMemory? digestValueOctets, out grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, digestValueElementIndex, out int trailing);
        if(scan != ElementScanResult.EndOfChildren)
        {
            error = new XAdESReadError(
                scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.UnknownCoreElement, 0);
            _ = trailing;

            return false;
        }

        value = new XAdESDigestAlgAndValue(table, elementIndex, digestMethodElementIndex, digestAlgorithmOrdinal, digestValueElementIndex, digestValueOctets!);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESDigestAlgAndValue other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESDigestAlgAndValue other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESDigestAlgAndValue left, XAdESDigestAlgAndValue right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESDigestAlgAndValue left, XAdESDigestAlgAndValue right) => !left.Equals(right);
}
