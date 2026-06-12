using System.Diagnostics;

namespace Verifiable.Apdu;

/// <summary>
/// Diagnostic information about a transport-level failure during APDU communication.
/// </summary>
/// <remarks>
/// <para>
/// Transport failures occur when communication with the card is lost before a valid
/// response is received. This includes NFC tag loss on mobile platforms, PC/SC reader
/// disconnect, and USB communication errors.
/// </para>
/// </remarks>
/// <param name="ErrorCode">
/// A platform-specific error code. On PC/SC this is an <c>SCARD_*</c> value.
/// On Android this is an <c>IOException</c> HResult. On iOS this is an
/// <c>NSError</c> code.
/// </param>
/// <param name="Platform">The platform on which the failure occurred.</param>
/// <param name="Reason">A human-readable description of the failure.</param>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record ApduTransportFailure(
    uint ErrorCode,
    ApduPlatform Platform,
    string Reason)
{
    private string DebuggerDisplay =>
        $"ApduTransportFailure({Platform}, 0x{ErrorCode:X8}, {Reason})";
}
