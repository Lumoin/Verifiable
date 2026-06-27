namespace Verifiable.Apdu;

/// <summary>
/// Platform on which the card is accessed.
/// </summary>
public enum ApduPlatform
{
    /// <summary>
    /// Platform could not be determined.
    /// </summary>
    Unknown,

    /// <summary>
    /// Android NFC via IsoDep.
    /// </summary>
    Android,

    /// <summary>
    /// iOS NFC via Core NFC NFCISO7816Tag.
    /// </summary>
    Ios,

    /// <summary>
    /// PC/SC reader on Windows, Linux, or macOS.
    /// </summary>
    PcSc,

    /// <summary>
    /// Virtual card using delegate-based handler for testing and replay.
    /// </summary>
    /// <remarks>
    /// Used when <see cref="ApduDevice"/> is created via <see cref="ApduDevice.Create"/>
    /// with a custom <see cref="TransceiveDelegate"/>.
    /// </remarks>
    Virtual
}
