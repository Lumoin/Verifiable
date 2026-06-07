namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// The top-level <c>DeviceResponse</c> per ISO/IEC 18013-5 §8.3.2.1.1 — the
/// wire envelope a wallet returns to a reader. Holds
/// <see cref="MdocPresentationDocument"/>s.
/// </summary>
/// <remarks>
/// <para>
/// The protocol pins <see cref="Version"/> to <c>"1.0"</c> at the time of
/// writing; future versions will broaden the constant set in
/// <see cref="MdocWellKnownKeys"/> rather than here.
/// </para>
/// <para>
/// Each <see cref="MdocPresentationDocument"/> borrows
/// <see cref="MdocPresentationDocument.IssuerSigned"/> references back into
/// an owned <see cref="MdocDocument"/> the wallet hydrated from storage
/// and owns its own <see cref="MdocPresentationDocument.DeviceSigned"/>
/// (which carries pool-routed COSE wire bytes). Disposing the response
/// cascades into every document, releasing the device-side carriers.
/// </para>
/// </remarks>
public sealed class MdocDeviceResponse: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a device response from caller-supplied parts. Ownership
    /// of the documents in <paramref name="documents"/> transfers to the
    /// new instance; disposing the response disposes each document.
    /// </summary>
    public MdocDeviceResponse(
        string version,
        IReadOnlyList<MdocPresentationDocument> documents,
        uint status,
        ReadOnlyMemory<byte>? encodedDocumentErrors = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(version);
        ArgumentNullException.ThrowIfNull(documents);

        Version = version;
        Documents = documents;
        Status = status;
        EncodedDocumentErrors = encodedDocumentErrors;
    }


    /// <summary>The protocol version string, currently always <c>"1.0"</c>.</summary>
    public string Version { get; }

    /// <summary>
    /// The presentation documents carried in this response. May be empty
    /// when only <see cref="EncodedDocumentErrors"/> are returned, but the
    /// wire CDDL requires at least one of <c>documents</c> or
    /// <c>documentErrors</c> in practice — this layer leaves that policy
    /// decision to callers.
    /// </summary>
    public IReadOnlyList<MdocPresentationDocument> Documents { get; }

    /// <summary>
    /// Opaque encoding of the optional <c>documentErrors</c> structure
    /// (per-document error info). Kept as bytes; structured parsing can
    /// land later if a consumer needs it.
    /// </summary>
    public ReadOnlyMemory<byte>? EncodedDocumentErrors { get; }

    /// <summary>
    /// The status code (per §8.3.2.1.1.2 Table 8).
    /// <see cref="MdocWellKnownKeys.StatusOk"/> = 0 indicates success;
    /// non-zero values report decoder or validator failures.
    /// </summary>
    public uint Status { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        foreach(MdocPresentationDocument document in Documents)
        {
            document.Dispose();
        }

        disposed = true;
    }
}
