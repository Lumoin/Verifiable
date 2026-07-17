using System;
using System.Diagnostics;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Thrown when a CTAP2 authenticator returns a non-success status code for a command.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
/// CTAP 2.3, section 8.2: Status codes</see>. This is distinct from
/// <c>Verifiable.Apdu.Ctap.CtapNfcTransportException</c>: that type reports a failure of the NFC
/// transport binding itself (a transport error, or a card-level status word that never resolved to a
/// CTAP2 response envelope at all); this type reports a CTAP2 response envelope that arrived
/// successfully but carries a non-<c>CTAP2_OK</c> status byte, so it is raised at the
/// authenticator-API layer rather than the transport layer.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class CtapCommandException: Exception
{
    /// <summary>
    /// Gets the CTAP2 status code the authenticator returned.
    /// </summary>
    public byte StatusCode { get; }


    /// <summary>
    /// Initializes a new instance for a non-success CTAP2 status code.
    /// </summary>
    /// <param name="statusCode">The CTAP2 status code the authenticator returned.</param>
    public CtapCommandException(byte statusCode)
        : base($"The authenticator returned CTAP2 status code 0x{statusCode:X2} instead of CTAP2_OK.")
    {
        StatusCode = statusCode;
    }

    /// <summary>
    /// Initializes a new instance with no message, satisfying the standard exception constructor
    /// pattern. Prefer <see cref="CtapCommandException(byte)"/>, which carries the status code.
    /// </summary>
    public CtapCommandException()
    {
    }

    /// <summary>
    /// Initializes a new instance with the specified message, satisfying the standard exception
    /// constructor pattern. Prefer <see cref="CtapCommandException(byte)"/>, which carries the
    /// status code.
    /// </summary>
    /// <param name="message">The exception message.</param>
    public CtapCommandException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance with the specified message and inner exception, satisfying the
    /// standard exception constructor pattern. Prefer <see cref="CtapCommandException(byte)"/>,
    /// which carries the status code.
    /// </summary>
    /// <param name="message">The exception message.</param>
    /// <param name="innerException">The inner exception.</param>
    public CtapCommandException(string message, Exception innerException)
        : base(message, innerException)
    {
    }


    private string DebuggerDisplay => $"CtapCommandException(status=0x{StatusCode:X2})";
}
