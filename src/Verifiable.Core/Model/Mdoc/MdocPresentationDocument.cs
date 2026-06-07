namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Presentation-side document — wraps an <see cref="MdocIssuerSignedView"/>
/// (borrowed from an owned <see cref="MdocDocument"/>) plus the wallet's
/// <see cref="MdocDeviceSigned"/> for the <c>DeviceResponse</c> wire
/// envelope per ISO/IEC 18013-5 §8.3.2.1.
/// </summary>
/// <remarks>
/// <para>
/// The split mirrors the
/// <see cref="Verifiable.Core.Model.DataIntegrity.BaseProofResult"/> /
/// <see cref="Verifiable.Core.Model.DataIntegrity.EcdsaSdDerivedProof"/>
/// separation: <see cref="MdocDocument"/> is the owned issuance shape;
/// this type is the presentation shape that gets assembled at
/// presentation time.
/// </para>
/// <para>
/// <strong>Ownership.</strong> Mixed by design — <see cref="IssuerSigned"/>
/// is a borrowed view (the originating
/// <see cref="MdocDocument"/>'s lifetime brackets the presentation's),
/// but <see cref="DeviceSigned"/> is OWNED (it carries pool-routed
/// COSE_Sign1 / COSE_Mac0 wire bytes the wallet produced at presentation
/// time). Disposing the presentation cascades into
/// <see cref="DeviceSigned"/> when present; it does not touch
/// <see cref="IssuerSigned"/>.
/// </para>
/// </remarks>
public sealed class MdocPresentationDocument: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a presentation document from caller-supplied parts.
    /// <see cref="IssuerSigned"/> is borrowed; ownership of
    /// <paramref name="deviceSigned"/> (when non-null) transfers to the
    /// new instance.
    /// </summary>
    public MdocPresentationDocument(
        string docType,
        MdocIssuerSignedView issuerSigned,
        MdocDeviceSigned? deviceSigned = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(docType);
        ArgumentNullException.ThrowIfNull(issuerSigned);

        DocType = docType;
        IssuerSigned = issuerSigned;
        DeviceSigned = deviceSigned;
    }


    /// <summary>
    /// The document type URI carried verbatim from the originating
    /// <see cref="MdocDocument.DocType"/>.
    /// </summary>
    public string DocType { get; }

    /// <summary>The borrowed issuer-signed view — namespaces plus IssuerAuth ref.</summary>
    public MdocIssuerSignedView IssuerSigned { get; }

    /// <summary>
    /// The device-side half assembled by the wallet at presentation time.
    /// Owned by this instance when populated. <see langword="null"/> in
    /// pre-device-signing intermediate states; the wire encoder treats
    /// null as "omit the deviceSigned slot."
    /// </summary>
    public MdocDeviceSigned? DeviceSigned { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        DeviceSigned?.Dispose();
        disposed = true;
    }
}
