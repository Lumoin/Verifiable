using System;
using Verifiable.JCose;

namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Intermediate state from mdoc device-signature verification, exposed by the
/// <c>VerifyDeviceSignedVerboseAsync</c> sibling for spec-vector validation and debugging.
/// Production callers use <c>VerifyDeviceSignedAsync</c>, which discards this.
/// </summary>
/// <remarks>
/// <para>
/// Owns the parsed COSE_Sign1 the verification ran against — with the reconstructed
/// <c>DeviceAuthenticationBytes</c> re-attached as its payload (the wire form carries a nil
/// payload per ISO/IEC 18013-5 §9.1.3.4). The caller disposes this context, which disposes the
/// message; <see cref="Message"/> is valid only until disposal.
/// </para>
/// <para>
/// The context is non-null only when the signature verified, mirroring the
/// <see cref="MdocIssuerAuthVerificationContext"/> and SD-* convention that a context exists only
/// past the signature check. Callers diagnosing a session-transcript mismatch — the common
/// device-signature failure — reconstruct the bytes themselves via the
/// <see cref="EncodeDeviceAuthenticationBytesDelegate"/> seam, the same value this context's
/// <see cref="DeviceAuthenticationBytes"/> carries on success.
/// </para>
/// </remarks>
public sealed class MdocDeviceSignedVerificationContext: IDisposable
{
    private bool disposed;

    internal MdocDeviceSignedVerificationContext(
        CoseSign1Message message,
        ReadOnlyMemory<byte> deviceAuthenticationBytes)
    {
        Message = message;
        DeviceAuthenticationBytes = deviceAuthenticationBytes;
    }

    /// <summary>
    /// The parsed COSE_Sign1 message the signature check ran against, with the reconstructed
    /// <c>DeviceAuthenticationBytes</c> as its payload. Owned by this context; valid until
    /// <see cref="Dispose"/>.
    /// </summary>
    public CoseSign1Message Message { get; }

    /// <summary>
    /// The Tag 24-wrapped <c>DeviceAuthentication</c> array the signature was verified against —
    /// reconstructed from the session transcript, doctype, and the device-signed half's preserved
    /// namespace bytes. A standalone buffer; the same value as <see cref="Message"/>'s payload.
    /// </summary>
    public ReadOnlyMemory<byte> DeviceAuthenticationBytes { get; }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        Message.Dispose();
        disposed = true;
    }
}
