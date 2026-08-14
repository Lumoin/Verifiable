using System.Collections.Generic;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// One <c>ds:Manifest</c> element: its optional <c>Id</c> attribute and its one-or-more <c>Reference</c>
/// children, read through the same reference machinery <see cref="XmlSignature.SignedInfo"/> uses, per
/// section 5.1 of
/// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
/// (Second Edition)</see>.
/// </summary>
/// <remarks>
/// A <c>Manifest</c> pointed to from <c>SignedInfo</c> has its own digest checked by core signature
/// validation, but "the digests within such a <c>Manifest</c> are checked at the application's discretion"
/// (section 5.1) — this type reads the structure only; which references get dereferenced and digest-checked,
/// and what happens when one fails or is inaccessible, is the caller's policy. A <c>Manifest</c> may be
/// found as the document root, as one of an <c>Object</c>'s <see cref="XmlSignatureObject.ContentNodeIndices"/>,
/// or nested arbitrarily deep the same way — <see cref="TryRead"/> is usable standalone over any element
/// index a caller already knows names a <c>Manifest</c>.
/// </remarks>
public sealed class XmlManifest: IDisposable
{
    /// <summary>The document the manifest was read from. Not owned; the caller disposes it separately.</summary>
    public XmlNodeTable Table { get; }

    /// <summary>The <c>Manifest</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>The <c>Reference</c> children, in document order; at least one.</summary>
    public IReadOnlyList<XmlReference> References { get; }

    private List<PooledMemory> OwnedContent { get; }

    private bool isDisposed;


    private XmlManifest(XmlNodeTable table, int elementIndex, bool hasId, int idAttributeOrdinal, IReadOnlyList<XmlReference> references, List<PooledMemory> ownedContent)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        References = references;
        OwnedContent = ownedContent;
    }


    /// <summary>
    /// Reads a <c>Manifest</c> element: its <c>Id</c> attribute and its <c>Reference+</c> children, decoding
    /// every <c>DigestValue</c> along the way.
    /// </summary>
    /// <param name="table">The parsed document.</param>
    /// <param name="manifestElementIndex">The <c>Manifest</c> element.</param>
    /// <param name="pool">The pool every decoded <c>DigestValue</c> is rented from.</param>
    /// <param name="manifest">The read model on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal on failure.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryRead(XmlNodeTable table, int manifestElementIndex, BaseMemoryPool pool, out XmlManifest? manifest, out XmlSignatureReadError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(pool);
        manifest = null;
        if(!XmlSignatureModelGrammar.IsDsElement(table, manifestElementIndex, "Manifest"u8))
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.UnknownCoreElement, 0);

            return false;
        }

        var owned = new List<PooledMemory>();
        try
        {
            bool hasId = XmlSignatureModelGrammar.TryFindAttribute(table, manifestElementIndex, "Id"u8, out int idOrdinal);
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, manifestElementIndex, hasId ? 1 : 0, out error))
            {
                return false;
            }

            ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, manifestElementIndex, out int firstReference);
            if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsDsElement(table, firstReference, "Reference"u8))
            {
                error = new XmlSignatureReadError(
                    scan == ElementScanResult.UnexpectedContent ? XmlSignatureReadFailure.UnexpectedElementContent : XmlSignatureReadFailure.MissingRequiredChild, 0);

                return false;
            }

            if(!XmlReference.TryReadSequence(table, firstReference, pool, owned, out List<XmlReference> references, out error))
            {
                return false;
            }

            manifest = new XmlManifest(table, manifestElementIndex, hasId, idOrdinal, references, owned);
            error = default;

            return true;
        }
        finally
        {
            if(manifest is null)
            {
                for(int i = 0; i < owned.Count; ++i)
                {
                    owned[i].Dispose();
                }
            }
        }
    }


    /// <summary>
    /// Tells whether this manifest was read over the given table instance — the identity guard
    /// <see cref="XmlReferenceProcessing"/>'s entry points require before processing a
    /// <c>table</c> argument against a <c>Manifest</c> read from a different document, mirroring the
    /// <see cref="XmlNodeSet.IsOver"/> precedent.
    /// </summary>
    /// <param name="table">The table to check against.</param>
    /// <returns><see langword="true"/> when this manifest was read from the same table instance.</returns>
    public bool IsOver(XmlNodeTable table)
    {
        return ReferenceEquals(Table, table);
    }


    /// <summary>
    /// Releases every decoded <c>DigestValue</c> the manifest's references own. <see cref="Table"/> is not
    /// owned and is not disposed here.
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
