namespace Verifiable.Apdu.Ctap;

/// <summary>
/// The one-byte "Response Status Code" a keep-alive wrapper carries in its data field while a CTAP2
/// request is still being processed.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-ctap-response">
/// CTAP 2.3, section 11.3.7.2: NFCCTAP_GETRESPONSE (0x11)</see>, lines 10651-10661: "STATUS_PROCESSING =
/// 1. The authenticator is still processing the current request. ... STATUS_UPNEEDED = 2. The
/// authenticator is waiting for user presence." The identical two values also carry the HID keep-alive
/// command's own status byte (lines 10400-10410), so this vocabulary is transport-neutral even though
/// only <see cref="CtapNfcResponder"/> exercises it in this codebase — the data field of a
/// <see cref="WellKnownCtapStatusWords.ResponseStatus"/> (<c>0x9100</c>) response.
/// </remarks>
public static class WellKnownCtapKeepaliveStatusCodes
{
    /// <summary>
    /// <c>STATUS_PROCESSING</c> (<c>0x01</c>): the authenticator is still processing the current
    /// request, with no user action pending.
    /// </summary>
    public const byte Processing = 0x01;

    /// <summary>
    /// <c>STATUS_UPNEEDED</c> (<c>0x02</c>): the authenticator is waiting for user presence.
    /// </summary>
    public const byte UpNeeded = 0x02;


    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="Processing"/>.
    /// </summary>
    /// <param name="statusCode">The keep-alive status byte to check.</param>
    /// <returns><see langword="true"/> if the authenticator is still processing with no user action pending.</returns>
    public static bool IsProcessing(byte statusCode) => statusCode == Processing;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="UpNeeded"/>.
    /// </summary>
    /// <param name="statusCode">The keep-alive status byte to check.</param>
    /// <returns><see langword="true"/> if the authenticator is waiting for user presence.</returns>
    public static bool IsUpNeeded(byte statusCode) => statusCode == UpNeeded;
}
