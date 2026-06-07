namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// The top-level <c>DeviceResponse</c> per ISO/IEC 18013-5 §8.3.2.1.1 as
/// reconstructed by a verifier from received wire bytes — the read-path
/// counterpart to the wallet-side <see cref="MdocDeviceResponse"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="MdocDeviceResponse"/> holds <see cref="MdocPresentationDocument"/>s
/// whose issuer-signed halves are borrowed views into owned
/// <see cref="MdocDocument"/>s the wallet hydrated from storage. A verifier has
/// no such backing store — it materialises every part fresh from the wire — so
/// the parsed envelope holds <see cref="MdocParsedDocument"/>s that own both
/// halves. Disposing the response cascades into every document, releasing the
/// issuer-side salts / COSE_Sign1 carriers and the device-side COSE carriers.
/// </para>
/// </remarks>
public sealed class MdocParsedDeviceResponse: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a parsed device response from caller-supplied parts.
    /// Ownership of the documents in <paramref name="documents"/> transfers to
    /// the new instance; disposing the response disposes each document.
    /// </summary>
    public MdocParsedDeviceResponse(
        string version,
        IReadOnlyList<MdocParsedDocument> documents,
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
    /// The parsed presentation documents carried in this response. May be empty
    /// when only <see cref="EncodedDocumentErrors"/> were returned.
    /// </summary>
    public IReadOnlyList<MdocParsedDocument> Documents { get; }

    /// <summary>
    /// Opaque encoding of the optional <c>documentErrors</c> structure
    /// (per-document error info), preserved verbatim. <see langword="null"/>
    /// when the response carried no <c>documentErrors</c> slot.
    /// </summary>
    public ReadOnlyMemory<byte>? EncodedDocumentErrors { get; }

    /// <summary>
    /// The status code (per §8.3.2.1.1.2 Table 8).
    /// <see cref="MdocWellKnownKeys.StatusOk"/> = 0 indicates success;
    /// non-zero values report decoder or validator failures the wallet signalled.
    /// </summary>
    public uint Status { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        foreach(MdocParsedDocument document in Documents)
        {
            document.Dispose();
        }

        disposed = true;
    }
}
