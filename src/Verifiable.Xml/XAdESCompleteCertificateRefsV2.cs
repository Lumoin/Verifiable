using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The <c>CompleteCertificateRefsTypeV2</c> data type (Annex A.1.1, v1.4.1 namespace): a mandatory
/// <c>CertRefs</c> child of type <c>xades:CertIDListV2Type</c> — "already defined in clause 5.2.2," reused
/// exactly through <see cref="XAdESSigningCertificateV2.TryReadCertIdListV2"/> — and
/// an optional <c>Id</c>. This is the ONE shared reader backing BOTH the <c>CompleteCertificateRefsV2</c>
/// qualifying property (A.1.1) and the <c>AttributeCertificateRefsV2</c> qualifying property (A.1.3, "shall be
/// defined as in XML Schema file ... <c>&lt;xsd:element name="AttributeCertificateRefsV2"
/// type="CompleteCertificateRefsTypeV2"/&gt;</c>" — no new complex type of its own): <see cref="TryRead"/> does
/// not itself check the wrapping element's local name, the same posture <see cref="XAdESCertificateValues"/>
/// and <see cref="XAdESRevocationValues"/> already take for their own multiply-reused types.
/// </summary>
/// <remarks>
/// <para>
/// A.1.1's closing conditional-<c>shall</c> paragraph — "if at least one of <c>CertificateValues</c>,
/// <c>AttrAuthoritiesCertValues</c>, <c>AnyValidationData</c> with a non empty <c>CertificateValues</c> child
/// element, or the <c>ArchiveTimeStamp</c> defined in the namespace whose URI is [v1.4.1] is incorporated ...
/// all the certificates referenced in <c>CompleteCertificateRefsV2</c> shall be present elsewhere in the
/// signature" (A.1.3 restates it verbatim for <c>AttributeCertificateRefsV2</c>) — is split across the
/// leaf/Pki boundary: <see cref="XAdESValidationDataTrigger.TryDetermine"/> delivers the structural half
/// (which trigger properties are present); matching each referenced certificate to its actual DER value
/// elsewhere in the signature needs digest computation, crypto this leaf never performs —
/// <c>Verifiable.Cryptography.Pki.XAdESLevelRules.CheckReferencesResolveToValidationDataAsync</c>
/// performs it above the leaf.
/// </para>
/// <para>
/// A.1.1's own five-item content-selection list (trust-anchor/CA-path references, the signing-certificate
/// exclusion, the attribute-certificate-path exclusion) and A.1.3's own three-item list (the "if not already
/// present within <c>CompleteCertificateRefsV2</c>/<c>SigningCertificateV2</c>" gate plus its three
/// <c>should not</c>-duplicate clauses) are both chain-dependent — determining which certificate a reference
/// names, and whether it lies on a signing, time-stamping, or attribute-certificate path, needs X.509 chain
/// building this crypto-free leaf never performs — a permanent delegate-seam obligation, the same family as
/// clause 5.4's own content-selection lists.
/// </para>
/// <para>
/// This is an Annex A reader that decodes pooled content of its own (via <see cref="XAdESCertIdV2"/>'s
/// <c>CertDigest</c>/<c>IssuerSerialV2</c>), so — like <see cref="XAdESSigningCertificateV2"/> — it is itself
/// <see cref="IDisposable"/>, owning one flat custody list across every <see cref="CertRefs"/> entry's decoded
/// fields.
/// </para>
/// </remarks>
public sealed class XAdESCompleteCertificateRefsV2: IDisposable
{
    /// <summary>The document the property was read from. Not owned; the caller disposes it separately.</summary>
    public XmlNodeTable Table { get; }

    /// <summary>The <c>CompleteCertificateRefsV2</c>/<c>AttributeCertificateRefsV2</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>The mandatory <c>CertRefs</c> child's own element index.</summary>
    public int CertRefsElementIndex { get; }

    /// <summary>The <c>CertRefs</c> child's <c>Cert</c> entries, in document order; at least one.</summary>
    public IReadOnlyList<XAdESCertIdV2> CertRefs { get; }

    private List<PooledMemory> OwnedContent { get; }

    private bool isDisposed;


    private XAdESCompleteCertificateRefsV2(
        XmlNodeTable table,
        int elementIndex,
        bool hasId,
        int idAttributeOrdinal,
        int certRefsElementIndex,
        IReadOnlyList<XAdESCertIdV2> certRefs,
        List<PooledMemory> ownedContent)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        CertRefsElementIndex = certRefsElementIndex;
        CertRefs = certRefs;
        OwnedContent = ownedContent;
    }


    /// <summary>
    /// Reads a <c>CompleteCertificateRefsTypeV2</c>-shaped element: its optional <c>Id</c> attribute, then its
    /// mandatory <c>CertRefs</c> child and nothing else.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>CompleteCertificateRefsV2</c> or <c>AttributeCertificateRefsV2</c>
    /// element — typically obtained from an <see cref="XAdESUnsignedSignaturePropertyEntry"/> whose
    /// <see cref="XAdESUnsignedSignaturePropertyEntry.Name"/> is
    /// <see cref="XAdESUnsignedSignaturePropertyName.Unrecognized"/> and whose element identity is separately
    /// confirmed to be one of these two v1.4.1-namespace elements (both share this exact reader).</param>
    /// <param name="pool">The pool every decoded field is rented from.</param>
    /// <param name="value">The read model on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESReadFailure.MissingRequiredChild"/> when <c>CertRefs</c> is absent, or present but
    /// carrying zero <c>Cert</c> entries.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, out XAdESCompleteCertificateRefsV2? value, out XAdESReadError error)
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
            if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV141Utf8, "CertRefs"u8))
            {
                error = new XAdESReadError(
                    scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

                return false;
            }

            int certRefsElementIndex = child;
            if(!XAdESSigningCertificateV2.TryReadCertIdListV2(table, certRefsElementIndex, pool, owned, out List<XAdESCertIdV2> certs, out error))
            {
                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, certRefsElementIndex, out child);
            if(scan == ElementScanResult.Found)
            {
                bool isRepeat = XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV141Utf8, "CertRefs"u8);
                error = new XAdESReadError(isRepeat ? XAdESReadFailure.DuplicateCoreChild : XAdESReadFailure.UnknownCoreElement, 0);

                return false;
            }

            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }

            value = new XAdESCompleteCertificateRefsV2(table, elementIndex, hasId, idOrdinal, certRefsElementIndex, certs, owned);
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
    /// Releases every decoded field every <see cref="CertRefs"/> entry owns. <see cref="Table"/> is not owned
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
