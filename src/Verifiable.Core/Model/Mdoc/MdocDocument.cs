namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// A single mdoc document per ISO/IEC 18013-5 §8.3.2.1 — one credential's
/// worth of claims, MSO commitment, and (on presentation) the holder-side
/// device authentication.
/// </summary>
/// <remarks>
/// <para>
/// On issuance only <see cref="DocType"/> and <see cref="IssuerSigned"/> are
/// present. <see cref="DeviceSigned"/> is attached by the wallet at
/// presentation time per ISO/IEC 18013-5 §8.3.2.1.2.3; M.3b lands the
/// signer and verifier for the COSE_Sign1 path.
/// </para>
/// <para>
/// Disposal cascades through <see cref="IssuerSigned"/> into every item
/// under every namespace. <see cref="DeviceSigned"/> holds no owned
/// sensitive memory of its own (no per-item randoms in the device path),
/// so no disposal step is needed for it today.
/// </para>
/// </remarks>
public sealed class MdocDocument: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a document from caller-supplied parts. Ownership of
    /// <paramref name="issuerSigned"/> transfers to the new document.
    /// </summary>
    public MdocDocument(
        string docType,
        MdocIssuerSigned issuerSigned,
        MdocDeviceSigned? deviceSigned = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(docType);
        ArgumentNullException.ThrowIfNull(issuerSigned);

        DocType = docType;
        IssuerSigned = issuerSigned;
        DeviceSigned = deviceSigned;
    }


    /// <summary>
    /// The document type URI, e.g. <c>org.iso.18013.5.1.mDL</c> for the ISO
    /// mobile driving licence or <c>eu.europa.ec.eudi.pid.1</c> for the EUDI PID.
    /// </summary>
    public string DocType { get; }

    /// <summary>The issuer-side half: the namespaced claims and the COSE_Sign1 MSO.</summary>
    public MdocIssuerSigned IssuerSigned { get; }

    /// <summary>
    /// The device-side half: claim assertions and the COSE_Sign1 / COSE_Mac0
    /// over <c>DeviceAuthentication</c> per ISO/IEC 18013-5 §8.3.2.1.2.3.
    /// <see langword="null"/> on issuance; the wallet attaches it before
    /// presentation.
    /// </summary>
    public MdocDeviceSigned? DeviceSigned { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        IssuerSigned.Dispose();
        disposed = true;
    }
}
