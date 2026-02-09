using System.Diagnostics;

namespace Verifiable.Tpm;

/// <summary>
/// Diagnostic information about a transport-level failure communicating with the TPM.
/// </summary>
/// <remarks>
/// <para>
/// This record captures the details of why a <see cref="TpmDevice"/> transport broke.
/// Once a transport failure occurs, the device is permanently failed — all subsequent
/// <see cref="TpmDevice.Submit"/> calls return the same error immediately.
/// </para>
/// <para>
/// <b>Linux failures:</b> The <see cref="ErrorCode"/> is an <c>errno</c> value from the
/// kernel. Common values include <c>EIO</c> (5) for I/O errors and <c>ENODEV</c> (19)
/// when the device is removed.
/// </para>
/// <para>
/// <b>Windows failures:</b> The <see cref="ErrorCode"/> is a TBS HRESULT. Common values
/// include <c>TBS_E_INVALID_CONTEXT</c> when the context is no longer valid.
/// </para>
/// <para>
/// <b>Recovery:</b> There is no reconnect mechanism. When the transport fails, the kernel
/// resource manager has already flushed all transient objects, sessions, and their associated
/// nonce state for this client. The caller must dispose the failed device, create a new
/// <see cref="TpmDevice"/>, and rebuild all sessions and object handles from scratch.
/// Primary keys created via <c>TPM2_CreatePrimary</c> with the same template will produce
/// the same cryptographic material on the new device (the handle value will differ).
/// </para>
/// </remarks>
/// <param name="ErrorCode">The platform-specific error code (<c>errno</c> on Linux, TBS HRESULT on Windows).</param>
/// <param name="Platform">The platform on which the failure occurred.</param>
/// <param name="Reason">A human-readable description of the failure.</param>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record TpmTransportFailure(uint ErrorCode, TpmPlatform Platform, string Reason)
{
    private string DebuggerDisplay
    {
        //Shows platform, error code, and reason at a glance.
        get => $"TransportFailure({Platform}, 0x{ErrorCode:X8}, {Reason})";
    }
}