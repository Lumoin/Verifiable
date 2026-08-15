using Lumoin.Base;

namespace Verifiable.Xml;

/// <summary>
/// The <c>CounterSignature</c> qualifying property of clause 5.2.7.2: an unsigned qualifying property that
/// qualifies the signature, containing one countersignature of the XAdES signature where it is incorporated —
/// "The content of this qualifying property shall be a XMLDSIG [1] or XAdES signature," per the acquired v132
/// XSD's <c>CounterSignatureType</c> (a single <c>ds:Signature</c> child plus an optional <c>Id</c> attribute).
/// The embedded <c>ds:Signature</c> is read through the SHIPPED <see cref="XmlSignature.TryRead"/> machinery
/// rooted at the child element's own index — <see cref="XmlSignature.TryRead"/> already accepts an arbitrary
/// interior <c>ds:Signature</c> element index (it checks only that the given index IS a <c>ds:Signature</c>
/// element and reads structurally from there, with no assumption the element is the document's outermost
/// signature), so no additive extension to the shipped reader was needed to root this read.
/// </summary>
/// <remarks>
/// <para>
/// This type provides the STRUCTURAL surface only: the embedded <see cref="Signature"/> and, through its own
/// <see cref="XmlSignature.SignedInfo"/>, its <c>ds:Reference</c> children. Clause 5.2.7.2's digest rule over
/// the countersigned signature's <c>ds:SignatureValue</c> — "The content of the <c>ds:DigestValue</c> in the
/// aforementioned <c>ds:Reference</c> element ... shall be the base-64 encoded digest of the complete (and
/// canonicalized) <c>ds:SignatureValue</c> element ... of the embedding and countersigned XAdES signature" —
/// is verification-side (digesting and comparison happen above this crypto-free leaf)
/// and is NOT computed or checked here.
/// </para>
/// <para>
/// Owns the embedded <see cref="Signature"/>'s pooled content and is therefore itself
/// <see cref="IDisposable"/>, mirroring <see cref="XAdESSigningCertificateV2"/>'s and
/// <see cref="XAdESSignerRoleV2"/>'s posture for the first clause-5.2 readers that own pooled content of
/// their own.
/// </para>
/// </remarks>
public sealed class XAdESCounterSignature: IDisposable
{
    /// <summary>The document the property was read from. Not owned; the caller disposes it separately.</summary>
    public XmlNodeTable Table { get; }

    /// <summary>The <c>CounterSignature</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>
    /// The <c>Id</c> attribute value — NOTE 1's rationale: it lets this unsigned property be referenced by
    /// URI when the enclosing signature uses indirect property incorporation and a time-stamp container's
    /// <c>Include</c> element needs to point at the countersignature.
    /// </summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>The embedded countersignature — a XMLDSIG or XAdES <c>ds:Signature</c>. Owned by this instance.</summary>
    public XmlSignature Signature { get; }

    private bool isDisposed;


    private XAdESCounterSignature(XmlNodeTable table, int elementIndex, bool hasId, int idAttributeOrdinal, XmlSignature signature)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        Signature = signature;
    }


    /// <summary>
    /// Reads a <c>CounterSignature</c> element: its optional <c>Id</c> attribute, then its mandatory single
    /// <c>ds:Signature</c> child, read fully through <see cref="XmlSignature.TryRead"/>.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>CounterSignature</c> element — typically obtained from a
    /// <see cref="XAdESUnsignedSignaturePropertyEntry"/> whose
    /// <see cref="XAdESUnsignedSignaturePropertyEntry.Name"/> is
    /// <see cref="XAdESUnsignedSignaturePropertyName.CounterSignature"/>.</param>
    /// <param name="pool">The pool every decoded field of the embedded signature is rented from.</param>
    /// <param name="value">The read model on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESReadFailure.MissingRequiredChild"/> when no <c>ds:Signature</c> child is present, or
    /// the single child present is not a <c>ds:Signature</c> element;
    /// <see cref="XAdESReadFailure.UnknownCoreElement"/>/<see cref="XAdESReadFailure.UnexpectedElementContent"/>
    /// for trailing content after the <c>ds:Signature</c> child;
    /// <see cref="XAdESReadFailure.MalformedEmbeddedSignature"/> when the <c>ds:Signature</c> child does not
    /// itself read as a well-formed XMLDSIG signature — the byte offset is the embedded read's own offset.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, out XAdESCounterSignature? value, out XAdESReadError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(pool);
        value = null;
        XmlSignature? signature = null;
        try
        {
            bool hasId = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Id"u8, out int idOrdinal);
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, hasId ? 1 : 0, out XmlSignatureReadError grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
            if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsDsElement(table, child, "Signature"u8))
            {
                error = new XAdESReadError(
                    scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

                return false;
            }

            int signatureElementIndex = child;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, signatureElementIndex, out int trailing);
            if(scan != ElementScanResult.EndOfChildren)
            {
                bool isRepeat = scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsDsElement(table, trailing, "Signature"u8);
                error = new XAdESReadError(
                    scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent
                    : isRepeat ? XAdESReadFailure.DuplicateCoreChild
                    : XAdESReadFailure.UnknownCoreElement, 0);

                return false;
            }

            if(!XmlSignature.TryRead(table, signatureElementIndex, pool, out signature, out XmlSignatureReadError signatureError))
            {
                error = new XAdESReadError(XAdESReadFailure.MalformedEmbeddedSignature, signatureError.ByteOffset);

                return false;
            }

            value = new XAdESCounterSignature(table, elementIndex, hasId, idOrdinal, signature!);
            signature = null;
            error = default;

            return true;
        }
        finally
        {
            signature?.Dispose();
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
    /// Releases the embedded <see cref="Signature"/>'s decoded content. <see cref="Table"/> is not owned and
    /// is not disposed here. Idempotent.
    /// </summary>
    public void Dispose()
    {
        if(isDisposed)
        {
            return;
        }

        isDisposed = true;
        Signature.Dispose();
    }
}
