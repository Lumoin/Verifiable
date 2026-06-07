namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// A single mdoc <c>Document</c> per ISO/IEC 18013-5 §8.3.2.1 as reconstructed
/// by a verifier from received <c>DeviceResponse</c> wire bytes — the
/// verifier-side counterpart to the issuance-side <see cref="MdocDocument"/>
/// and the wallet-side <see cref="MdocPresentationDocument"/>.
/// </summary>
/// <remarks>
/// <para>
/// The three document shapes correspond to the three lifecycle phases, each
/// with its own ownership contract:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <see cref="MdocDocument"/> — issuance: owns <see cref="IssuerSigned"/>,
///     carries no device half (it is attached later).
///   </description></item>
///   <item><description>
///     <see cref="MdocPresentationDocument"/> — wallet presentation: borrows a
///     <see cref="MdocIssuerSignedView"/> into an owned
///     <see cref="MdocDocument"/> and owns only the device half it produced.
///   </description></item>
///   <item><description>
///     <see cref="MdocParsedDocument"/> (this type) — verifier parse: owns
///     <strong>both</strong> halves, because both were materialised fresh from
///     the wire and have no other owner.
///   </description></item>
/// </list>
/// <para>
/// <strong>Ownership.</strong> Disposing this document disposes
/// <see cref="IssuerSigned"/> (cascading into every item's
/// <see cref="MdocIssuerSignedItem.Random"/> salt and the
/// <see cref="MdocIssuerAuth"/> COSE_Sign1 wire-bytes carrier) and, when
/// present, <see cref="DeviceSigned"/> (releasing the device-side COSE_Sign1 /
/// COSE_Mac0 carrier). Neither <see cref="MdocDocument"/> nor
/// <see cref="MdocPresentationDocument"/> cascades into both halves, which is
/// why a verifier parse that owns both needs this distinct shape.
/// </para>
/// </remarks>
public sealed class MdocParsedDocument: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a parsed document from caller-supplied parts. Ownership of
    /// <paramref name="issuerSigned"/> and (when non-null)
    /// <paramref name="deviceSigned"/> transfers to the new document.
    /// </summary>
    /// <param name="docType">The document type URI carried in the wire <c>docType</c> slot.</param>
    /// <param name="issuerSigned">The owned issuer-signed half parsed from the wire.</param>
    /// <param name="deviceSigned">
    /// The owned device-signed half parsed from the wire. <see langword="null"/>
    /// only when the received document carried no <c>deviceSigned</c> slot — a
    /// presentation DeviceResponse always carries one.
    /// </param>
    public MdocParsedDocument(
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


    /// <summary>The document type URI carried verbatim from the wire <c>docType</c> slot.</summary>
    public string DocType { get; }

    /// <summary>The owned issuer-side half: the namespaced claims and the COSE_Sign1 MSO.</summary>
    public MdocIssuerSigned IssuerSigned { get; }

    /// <summary>
    /// The owned device-side half: the device namespaces plus the COSE_Sign1 /
    /// COSE_Mac0 over <c>DeviceAuthentication</c>. <see langword="null"/> when
    /// the received document carried no <c>deviceSigned</c> slot.
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
        DeviceSigned?.Dispose();
        disposed = true;
    }
}
