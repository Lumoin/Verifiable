namespace Verifiable.Apdu.Ctap;

/// <summary>
/// ISO/IEC 7816-4 status words for the CTAP2-over-NFC binding.
/// </summary>
/// <remarks>
/// Registered via <see cref="StatusWord.Create"/> — the documented vendor-registration seam
/// <see cref="StatusWord"/> already exposes — since <c>0x9100</c> is not a generic ISO/IEC 7816-4
/// code but CTAP's own "keep-alive" wrapper.
/// </remarks>
public static class WellKnownCtapStatusWords
{
    /// <summary>
    /// NFCCTAP response status (0x9100): the authenticator has not finished processing the request
    /// and the client must poll with <see cref="WellKnownCtapInstructionCodes.NfcCtapGetResponse"/>.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-response-framing">
    /// CTAP 2.3, section 11.3.5.2: Response framing</see> — a <c>9100</c> response carries a
    /// one-byte "Response Status Code" in the data field (<c>STATUS_PROCESSING = 1</c>,
    /// <c>STATUS_UPNEEDED = 2</c>), distinct from a final <c>9000</c> success. Unlike <c>61xx</c>,
    /// where the byte count rides in SW2, the sub-code here is a data-field byte the response
    /// framing/poll-loop layer decodes, not <see cref="StatusWord"/> itself.
    /// </remarks>
    public static readonly StatusWord ResponseStatus =
        StatusWord.Create(0x9100, "NFCCTAP response status: still processing, issue NFCCTAP_GETRESPONSE.");


    /// <summary>
    /// Gets a value indicating whether <paramref name="statusWord"/> is
    /// <see cref="ResponseStatus"/> (<c>9100</c>) — the authenticator has deferred its response and
    /// the client must poll with <see cref="WellKnownCtapInstructionCodes.NfcCtapGetResponse"/>.
    /// </summary>
    /// <param name="statusWord">The status word to check.</param>
    /// <returns><see langword="true"/> if <paramref name="statusWord"/> is the CTAP response-status wrapper.</returns>
    public static bool IsResponseStatus(StatusWord statusWord) => statusWord == ResponseStatus;
}
