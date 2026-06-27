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
    MemoryPool<byte> pool,
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
