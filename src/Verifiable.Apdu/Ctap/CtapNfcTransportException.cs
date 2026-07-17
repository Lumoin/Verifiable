using System;
using System.Diagnostics;

namespace Verifiable.Apdu.Ctap;

/// <summary>
/// Thrown by <see cref="CtapNfcTransport"/> when the NFC exchange did not resolve to a CTAP2 response
/// envelope: the authenticator returned a card-level error status word, or the transport itself
/// failed.
/// </summary>
/// <remarks>
/// <see cref="CtapPayloadTransceiveDelegate"/> and the identically-shaped transceive delegate it binds
/// to by method-group conversion on the CTAP2 authenticator-API side carry no error channel of their
/// own — a <see cref="ValueTask{T}"/> either produces a response envelope or faults. This exception is
/// the fault this transport raises for anything <see cref="ApduExecutor"/> did not already resolve to a
/// successful CTAP status word.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class CtapNfcTransportException: Exception
{
    /// <summary>
    /// Gets the card-level status word that caused the failure, or <see langword="null"/> if the
    /// failure was a transport error rather than a card response.
    /// </summary>
    public StatusWord? StatusWord { get; }

    /// <summary>
    /// Gets the platform-specific transport error code, or <see langword="null"/> if the failure was
    /// a card-level status word rather than a transport error.
    /// </summary>
    public uint? TransportErrorCode { get; }


    /// <summary>
    /// Initializes a new instance for a card-level error status word.
    /// </summary>
    /// <param name="statusWord">The status word the authenticator returned.</param>
    public CtapNfcTransportException(StatusWord statusWord)
        : base($"The authenticator returned status word {statusWord} instead of a CTAP2 response.")
    {
        StatusWord = statusWord;
    }

    /// <summary>
    /// Initializes a new instance for a transport-level failure.
    /// </summary>
    /// <param name="transportErrorCode">The platform-specific transport error code.</param>
    public CtapNfcTransportException(uint transportErrorCode)
        : base($"The NFC transport failed with error code 0x{transportErrorCode:X8}.")
    {
        TransportErrorCode = transportErrorCode;
    }

    /// <summary>
    /// Initializes a new instance with no message, satisfying the standard exception constructor
    /// pattern. Prefer <see cref="CtapNfcTransportException(StatusWord)"/> or
    /// <see cref="CtapNfcTransportException(uint)"/>, which carry the failure detail.
    /// </summary>
    public CtapNfcTransportException()
    {
    }

    /// <summary>
    /// Initializes a new instance with the specified message, satisfying the standard exception
    /// constructor pattern. Prefer <see cref="CtapNfcTransportException(StatusWord)"/> or
    /// <see cref="CtapNfcTransportException(uint)"/>, which carry the failure detail.
    /// </summary>
    /// <param name="message">The exception message.</param>
    public CtapNfcTransportException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance with the specified message and inner exception, satisfying the
    /// standard exception constructor pattern. Prefer <see cref="CtapNfcTransportException(StatusWord)"/>
    /// or <see cref="CtapNfcTransportException(uint)"/>, which carry the failure detail.
    /// </summary>
    /// <param name="message">The exception message.</param>
    /// <param name="innerException">The inner exception.</param>
    public CtapNfcTransportException(string message, Exception innerException)
        : base(message, innerException)
    {
    }


    private string DebuggerDisplay => StatusWord is StatusWord sw
        ? $"CtapNfcTransportException(SW={sw})"
        : $"CtapNfcTransportException(transport=0x{TransportErrorCode:X8})";
}
