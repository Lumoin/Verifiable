using System.Collections.Generic;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// Which arm of <c>SignaturePolicyStoreType</c>'s <c>SignaturePolicyDocument</c>/<c>SigPolDocLocalURI</c>
/// choice (clause 5.2.10) an <see cref="XAdESSignaturePolicyStore"/> holds.
/// </summary>
public enum XAdESSignaturePolicyStoreChoice
{
    /// <summary>The signature policy document itself, base64-encoded, carried by <see cref="XAdESSignaturePolicyStore.SignaturePolicyDocumentOctets"/>.</summary>
    SignaturePolicyDocument,

    /// <summary>A URI referencing a local store where the signature policy document can be retrieved, carried by <see cref="XAdESSignaturePolicyStore.SigPolDocLocalURI"/>.</summary>
    SigPolDocLocalURI
}


/// <summary>
/// The <c>SignaturePolicyStore</c> qualifying property of clause 5.2.10 (namespace
/// <see cref="XAdESIdentifiers.XAdESNamespaceV141"/>): an unsigned qualifying property qualifying the
/// signature, carrying a mandatory <c>SPDocSpecification</c> (the shared reader of clause 5.2.9.2, also
/// used by <see cref="XAdESSigPolicyQualifierEntry"/>) then a choice between the signature policy document
/// itself, base64-encoded, or a URI to a local store holding it — so that the policy document referenced by
/// the signed <c>SignaturePolicyIdentifier</c> qualifying property (clause 5.2.9.1) is available for offline
/// and long-term validation.
/// </summary>
/// <remarks>
/// <para>
/// Being unsigned, this property is not itself integrity-protected: NOTE 3 of clause 5.2.10 states its
/// security rationale explicitly — the stored document's integrity is assured indirectly, by comparing its
/// digest against the SIGNED <c>SignaturePolicyIdentifier</c>'s own <c>SigPolicyHash</c> (clause 5.2.9.1).
/// Reconciling <see cref="XAdESSignaturePolicyStore"/> against a discovered <c>SignaturePolicyId</c> is
/// <see cref="XAdESSignaturePolicyStoreLegality"/>'s own job, not this reader's.
/// </para>
/// <para>
/// Table 2's letter m) conditions this property's legality on a <c>SignaturePolicyIdentifier</c> being
/// present and carrying <c>SigPolicyHash</c> — a baseline-level presence rule
/// <see cref="XAdESSignaturePolicyStoreLegality"/> and the Pki-side Table 2 registry (clause 6) own; this
/// reader implements clause 5.2.10's own syntax only, not that conditioning.
/// </para>
/// </remarks>
public sealed class XAdESSignaturePolicyStore: IDisposable
{
    /// <summary>The document the property was read from. Not owned; the caller disposes it separately.</summary>
    public XmlNodeTable Table { get; }

    /// <summary>The <c>SignaturePolicyStore</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>The mandatory <c>SPDocSpecification</c> child, identifying the policy document's own syntax.</summary>
    public XAdESObjectIdentifier SPDocSpecification { get; }

    /// <summary>Which arm of the choice is present.</summary>
    public XAdESSignaturePolicyStoreChoice Choice { get; }

    /// <summary>
    /// The decoded signature policy document octets, tagged <see cref="BufferTags.XmlDecodedContent"/>; valid
    /// when <see cref="Choice"/> is <see cref="XAdESSignaturePolicyStoreChoice.SignaturePolicyDocument"/>.
    /// </summary>
    public PooledMemory? SignaturePolicyDocumentOctets { get; }

    private int SigPolDocLocalURITextNodeIndex { get; }

    /// <summary>
    /// The local-store URI; valid when <see cref="Choice"/> is
    /// <see cref="XAdESSignaturePolicyStoreChoice.SigPolDocLocalURI"/>.
    /// </summary>
    public ReadOnlySpan<byte> SigPolDocLocalURI => Choice == XAdESSignaturePolicyStoreChoice.SigPolDocLocalURI && SigPolDocLocalURITextNodeIndex >= 0
        ? Table.ValueOf(SigPolDocLocalURITextNodeIndex)
        : ReadOnlySpan<byte>.Empty;

    private List<PooledMemory> OwnedContent { get; }

    private bool isDisposed;


    private XAdESSignaturePolicyStore(
        XmlNodeTable table,
        int elementIndex,
        bool hasId,
        int idAttributeOrdinal,
        XAdESObjectIdentifier spDocSpecification,
        XAdESSignaturePolicyStoreChoice choice,
        PooledMemory? signaturePolicyDocumentOctets,
        int sigPolDocLocalURITextNodeIndex,
        List<PooledMemory> ownedContent)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        SPDocSpecification = spDocSpecification;
        Choice = choice;
        SignaturePolicyDocumentOctets = signaturePolicyDocumentOctets;
        SigPolDocLocalURITextNodeIndex = sigPolDocLocalURITextNodeIndex;
        OwnedContent = ownedContent;
    }


    /// <summary>
    /// Reads a <c>SignaturePolicyStore</c> element: its optional <c>Id</c> attribute, then the mandatory
    /// <c>SPDocSpecification</c> child and the <c>SignaturePolicyDocument</c>/<c>SigPolDocLocalURI</c>
    /// choice, in that fixed order.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>SignaturePolicyStore</c> element — typically obtained from an
    /// <see cref="XAdESUnsignedSignaturePropertyEntry"/> whose <see cref="XAdESUnsignedSignaturePropertyEntry.Name"/>
    /// is <see cref="XAdESUnsignedSignaturePropertyName.Unrecognized"/> and whose own element identity the
    /// caller has confirmed as namespace <see cref="XAdESIdentifiers.XAdESNamespaceV141"/>, local name
    /// <c>SignaturePolicyStore</c> — the same v1.4.1-namespace fall-through
    /// <see cref="XAdESUnsignedSignatureProperties"/>'s own remarks describe for <c>ArchiveTimeStamp</c> and
    /// every Annex A V2 property.</param>
    /// <param name="pool">The pool every decoded field is rented from.</param>
    /// <param name="value">The read model on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESReadFailure.MissingRequiredChild"/> when <c>SPDocSpecification</c> or the
    /// <c>SignaturePolicyDocument</c>/<c>SigPolDocLocalURI</c> choice is absent;
    /// <see cref="XAdESReadFailure.SPDocSpecificationQualifierNotOIDAsURN"/> per
    /// <see cref="XAdESSPDocSpecification.TryRead"/>.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, out XAdESSignaturePolicyStore? value, out XAdESReadError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(pool);
        value = null;
        var owned = new List<PooledMemory>();
        try
        {
            if(!XmlSignatureModelGrammar.IsElement(table, elementIndex, XAdESIdentifiers.XAdESNamespaceV141Utf8, "SignaturePolicyStore"u8))
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

            ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
            if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV141Utf8, "SPDocSpecification"u8))
            {
                error = new XAdESReadError(
                    scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

                return false;
            }

            if(!XAdESSPDocSpecification.TryRead(table, child, out XAdESObjectIdentifier spDocSpecification, out error))
            {
                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }

            if(scan != ElementScanResult.Found)
            {
                error = new XAdESReadError(XAdESReadFailure.MissingRequiredChild, 0);

                return false;
            }

            bool isSignaturePolicyDocument = XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV141Utf8, "SignaturePolicyDocument"u8);
            bool isSigPolDocLocalURI = !isSignaturePolicyDocument && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV141Utf8, "SigPolDocLocalURI"u8);
            if(!isSignaturePolicyDocument && !isSigPolDocLocalURI)
            {
                error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

                return false;
            }

            XAdESSignaturePolicyStoreChoice choice;
            PooledMemory? signaturePolicyDocumentOctets = null;
            int sigPolDocLocalURITextNodeIndex = -1;
            if(isSignaturePolicyDocument)
            {
                choice = XAdESSignaturePolicyStoreChoice.SignaturePolicyDocument;
                if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, child, 0, out grammarError)
                    || !XmlSignatureModelGrammar.TryDecodeSimpleBase64Content(table, child, pool, owned, out signaturePolicyDocumentOctets, out grammarError))
                {
                    error = XAdESGrammar.FromGrammarFailure(grammarError);

                    return false;
                }
            }
            else
            {
                choice = XAdESSignaturePolicyStoreChoice.SigPolDocLocalURI;
                if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, child, 0, out grammarError)
                    || !XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, child, out sigPolDocLocalURITextNodeIndex, out grammarError))
                {
                    error = XAdESGrammar.FromGrammarFailure(grammarError);

                    return false;
                }
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out int trailing);
            if(scan != ElementScanResult.EndOfChildren)
            {
                bool isRepeat = scan == ElementScanResult.Found
                    && ((isSignaturePolicyDocument && XmlSignatureModelGrammar.IsElement(table, trailing, XAdESIdentifiers.XAdESNamespaceV141Utf8, "SignaturePolicyDocument"u8))
                        || (isSigPolDocLocalURI && XmlSignatureModelGrammar.IsElement(table, trailing, XAdESIdentifiers.XAdESNamespaceV141Utf8, "SigPolDocLocalURI"u8)));
                error = new XAdESReadError(
                    scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent
                    : isRepeat ? XAdESReadFailure.DuplicateCoreChild
                    : XAdESReadFailure.UnknownCoreElement, 0);

                return false;
            }

            value = new XAdESSignaturePolicyStore(table, elementIndex, hasId, idOrdinal, spDocSpecification, choice, signaturePolicyDocumentOctets, sigPolDocLocalURITextNodeIndex, owned);
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
    /// Releases <see cref="SignaturePolicyDocumentOctets"/> when present. <see cref="Table"/> is not owned
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
