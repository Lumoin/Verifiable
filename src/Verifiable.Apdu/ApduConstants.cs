namespace Verifiable.Apdu;

/// <summary>
/// ISO/IEC 7816-4 APDU protocol constants.
/// </summary>
public static class ApduConstants
{
    /// <summary>
    /// Size of the mandatory command APDU header in bytes (CLA, INS, P1, P2).
    /// </summary>
    public const int CommandHeaderSize = 4;

    /// <summary>
    /// Size of the status word trailer in every response APDU (SW1, SW2).
    /// </summary>
    public const int StatusWordSize = 2;

    /// <summary>
    /// Maximum response data length for short-length encoding.
    /// </summary>
    /// <remarks>
    /// When Le is <c>0x00</c> in short encoding, the card returns up to 256 bytes.
    /// </remarks>
    public const int MaxShortResponseData = 256;

    /// <summary>
    /// Maximum response data length for extended-length encoding.
    /// </summary>
    /// <remarks>
    /// When Le is <c>0x000000</c> in extended encoding, the card returns up to 65536 bytes.
    /// </remarks>
    public const int MaxExtendedResponseData = 65536;

    /// <summary>
    /// Maximum allowed response size in bytes including data and status word.
    /// </summary>
    /// <remarks>
    /// This is a safety limit to prevent allocating excessive memory if the
    /// response contains garbage data. 64 KiB plus the status word is sufficient
    /// for all standard APDU responses including extended-length certificate reads.
    /// </remarks>
    public const int MaxResponseSize = MaxExtendedResponseData + StatusWordSize;

    /// <summary>
    /// Transport error code the executor reports when a transceive that the transport marked
    /// successful nevertheless returns a frame shorter than the mandatory two-byte status word.
    /// </summary>
    /// <remarks>
    /// A conformant response always carries SW1-SW2, so a sub-status-word frame is a protocol
    /// integrity failure (e.g. a truncated NFC frame). The value sits in a high sentinel range
    /// to distinguish library-detected protocol errors from platform transport codes. A richer
    /// transport-error taxonomy (timeout, tag-lost, cancelled, I/O) is planned to subsume it.
    /// </remarks>
    public const uint MalformedResponseTransportError = 0xFFFF_FF01;
}
