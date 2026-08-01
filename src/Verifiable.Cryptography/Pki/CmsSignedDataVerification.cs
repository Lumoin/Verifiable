using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Verifies the signature on a CMS SignedData structure (RFC 5652) and returns its encapsulated
/// content together with the certificates it carries. Signature verification only — establishing
/// trust in the signer's certificate is a separate step performed through
/// <see cref="ValidateCertificateChainAsyncDelegate"/>.
/// </summary>
/// <remarks>
/// <para>
/// CMS SignedData is the shared substrate of several signature formats this library targets: the
/// eMRTD Document Security Object (EF.SOD) that Passive Authentication verifies (ICAO Doc 9303
/// Part 11), and the CAdES family of EU advanced electronic signatures (ETSI EN 319 122), which is
/// CMS SignedData with additional signed attributes. This seam factors the common core — decode,
/// verify the signer's signature over the encapsulated content, and surface the content and the
/// embedded certificates — so each format layers its own rules on top: eMRTD matches the data-group
/// hashes and chains to a CSCA; CAdES validates its signed attributes. Neither concern lives here.
/// </para>
/// <para>
/// The seam is asynchronous because a backend may verify at a hardware or service boundary. The
/// implementation verifies the signature only (it does not build or trust a certificate chain); a
/// failed signature throws rather than returning, matching the fail-closed shape of the other
/// verification seams.
/// </para>
/// </remarks>
/// <param name="signedData">The CMS SignedData carrier (with encapsulated content).</param>
/// <param name="pool">Memory pool for the content and certificate allocations.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The verified content and the embedded certificates. The caller disposes it.</returns>
public delegate ValueTask<CmsVerifiedContent> VerifyCmsSignedDataDelegate(
    CmsSignedData signedData,
    BaseMemoryPool pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Verifies the signature on a CMS SignedData structure that encapsulates no content of its own
/// (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.2">RFC 5652 §5.2</see>: "the content
/// is not present ... it is supplied by other means") against content the caller carries beside it —
/// the detached form. The optional counterpart of <see cref="VerifyCmsSignedDataDelegate"/>: a host
/// that registers one of these chooses the backend detached verification runs on, and a host that
/// registers none keeps the library's own managed backend.
/// </summary>
/// <remarks>
/// <para>
/// Detached is the only form an Associated Signature Container carries — clause 4.4.4.2 item 3 a) and
/// clause 4.3.3.2 item 4 b) of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> both place a detached CAdES object in the container's signature file — so
/// without this seam the container path would be the one cryptographic operation of this library a host cannot
/// choose the backend for. The signed data items travel beside the structure there (Table 8 of clause 5.2.2.2
/// of ETSI EN 319 102-1: the Driving Application supplies the Signer's Document), which is why this takes them
/// as a parameter while <see cref="VerifyCmsSignedDataDelegate"/> does not.
/// </para>
/// <para>
/// The contract is otherwise that of <see cref="VerifyCmsSignedDataDelegate"/>: the signature only (never the
/// certificate chain), fail-closed by throwing rather than returning, and the returned
/// <see cref="CmsVerifiedContent"/> carries the content that was verified — here the octets the caller
/// supplied. An implementation is expected to refuse a structure that <em>does</em> encapsulate content of its
/// own rather than check it against the supplied octets: two contents with only one of them checked is the
/// shape a substitution attack takes.
/// </para>
/// </remarks>
/// <param name="signedData">The CMS SignedData carrier, encapsulating no content of its own.</param>
/// <param name="detachedContent">The octets the signature is detached over — the Signer's Document.</param>
/// <param name="pool">Memory pool for the content and certificate allocations.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The verified content and the embedded certificates. The caller disposes it.</returns>
public delegate ValueTask<CmsVerifiedContent> VerifyDetachedCmsSignedDataDelegate(
    CmsSignedData signedData,
    SignedContentMemory detachedContent,
    BaseMemoryPool pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// The result of verifying a CMS SignedData signature: the encapsulated content, its content-type
/// identifier, and the certificates the structure carried — including the signer's, ready to feed
/// <see cref="ValidateCertificateChainAsyncDelegate"/> for the separate trust step.
/// </summary>
public sealed class CmsVerifiedContent: IDisposable
{
    private IMemoryOwner<byte> ContentOwner { get; }
    private int ContentLength { get; }
    private int SignerIndex { get; }
    private bool disposed;


    /// <summary>
    /// Initialises a new <see cref="CmsVerifiedContent"/>. Ownership of the content buffer and every
    /// certificate transfers to this instance.
    /// </summary>
    /// <param name="contentType">The encapsulated content type OID (for example the eMRTD LDS security object OID).</param>
    /// <param name="content">The encapsulated content bytes, owned. The length is taken from the owner's memory.</param>
    /// <param name="contentLength">The number of valid bytes in <paramref name="content"/>.</param>
    /// <param name="certificates">The embedded certificates in chain order, the signer first.</param>
    /// <param name="signerIndex">The index of the signer's certificate within <paramref name="certificates"/>.</param>
    /// <param name="signedAttributes">The signer's signed attributes (RFC 5652 §5.3), which the signature covers; empty when the SignerInfo carries none.</param>
    public CmsVerifiedContent(
        string contentType,
        IMemoryOwner<byte> content,
        int contentLength,
        IReadOnlyList<PkiCertificateMemory> certificates,
        int signerIndex,
        IReadOnlyList<CmsSignedAttribute> signedAttributes)
    {
        ArgumentNullException.ThrowIfNull(contentType);
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(certificates);
        ArgumentNullException.ThrowIfNull(signedAttributes);
        ArgumentOutOfRangeException.ThrowIfNegative(signerIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(signerIndex, certificates.Count);

        ContentType = contentType;
        ContentOwner = content;
        ContentLength = contentLength;
        Certificates = certificates;
        SignerIndex = signerIndex;
        SignedAttributes = signedAttributes;
    }


    /// <summary>Gets the encapsulated content type OID.</summary>
    public string ContentType { get; }

    /// <summary>Gets the encapsulated (signed) content bytes.</summary>
    public ReadOnlyMemory<byte> Content => ContentOwner.Memory[..ContentLength];

    /// <summary>Gets the embedded certificates in chain order, the signer first.</summary>
    public IReadOnlyList<PkiCertificateMemory> Certificates { get; }

    /// <summary>Gets the signer's certificate.</summary>
    public PkiCertificateMemory SignerCertificate => Certificates[SignerIndex];

    /// <summary>Gets the signer's signed attributes (RFC 5652 §5.3); empty when the SignerInfo carries none. Owned by this instance.</summary>
    public IReadOnlyList<CmsSignedAttribute> SignedAttributes { get; }


    /// <summary>
    /// Finds the signed attribute with the given type object identifier.
    /// </summary>
    /// <param name="attributeType">The attribute type object identifier (dotted form).</param>
    /// <param name="attribute">The matching attribute when present; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when an attribute of that type is present.</returns>
    public bool TryGetSignedAttribute(string attributeType, [NotNullWhen(true)] out CmsSignedAttribute? attribute)
    {
        ArgumentNullException.ThrowIfNull(attributeType);

        foreach(CmsSignedAttribute candidate in SignedAttributes)
        {
            if(string.Equals(candidate.AttributeType, attributeType, StringComparison.Ordinal))
            {
                attribute = candidate;

                return true;
            }
        }

        attribute = null;

        return false;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            ContentOwner.Dispose();
            foreach(PkiCertificateMemory certificate in Certificates)
            {
                certificate.Dispose();
            }

            foreach(CmsSignedAttribute attribute in SignedAttributes)
            {
                attribute.Dispose();
            }

            disposed = true;
        }
    }
}
