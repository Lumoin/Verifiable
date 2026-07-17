namespace Verifiable.Apdu.Ctap;

/// <summary>
/// ISO/IEC 7816-4 instruction codes for the CTAP2-over-NFC binding.
/// </summary>
/// <remarks>
/// <para>
/// These three instructions are registered via <see cref="InstructionCode.Create"/> — the documented
/// vendor-registration seam <see cref="InstructionCode"/> already exposes — rather than being added
/// to <see cref="InstructionCode"/> itself, since they are specific to the CTAP2 NFC profile, not
/// generic ISO/IEC 7816-4.
/// </para>
/// <para>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-command-framing">
/// CTAP 2.3, section 11.3.5.1: Command framing</see> defines <see cref="NfcCtapMsg"/> as the sole
/// carrier for CTAP2 command/response envelopes over NFC; <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-ctap-response">
/// section 11.3.7.2</see> defines <see cref="NfcCtapGetResponse"/> for polling a deferred response;
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-applet-deselect">
/// section 11.3.4</see> defines <see cref="NfcCtapControl"/> for applet deselection.
/// </para>
/// </remarks>
public static class WellKnownCtapInstructionCodes
{
    /// <summary>
    /// NFCCTAP_MSG (0x10). Carries a CTAP2 command byte followed by CBOR-encoded parameters in the
    /// data field.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-command-framing">
    /// CTAP 2.3, section 11.3.5.1: Command framing</see> — <c>CLA 0x80, INS 0x10</c>, P1 bit
    /// <c>0x80</c> declares client support for <see cref="NfcCtapGetResponse"/>.
    /// </remarks>
    public static readonly InstructionCode NfcCtapMsg = InstructionCode.Create(0x10, "NFCCTAP_MSG");

    /// <summary>
    /// NFCCTAP_GETRESPONSE (0x11). Polls for a response deferred by
    /// <see cref="WellKnownCtapStatusWords.ResponseStatus"/>, or cancels an in-flight request.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-ctap-response">
    /// CTAP 2.3, section 11.3.7.2: NFCCTAP_GETRESPONSE (0x11)</see> — <c>CLA 0x80, INS 0x11</c>;
    /// P1/P2 both <c>0x00</c> polls normally, P1 <c>0x11</c>/P2 <c>0x00</c> cancels.
    /// </remarks>
    public static readonly InstructionCode NfcCtapGetResponse = InstructionCode.Create(0x11, "NFCCTAP_GETRESPONSE");

    /// <summary>
    /// NFCCTAP_CONTROL (0x12). Deselects the FIDO applet (<c>END CTAP_MSG</c>, P1 <c>0x01</c>); the
    /// authenticator then ignores CTAP commands until the next explicit SELECT.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-applet-deselect">
    /// CTAP 2.3, section 11.3.4: Applet deselection</see> — <c>CLA 0x80, INS 0x12, P1 0x01, P2 0x00</c>,
    /// no data, no Le.
    /// </remarks>
    public static readonly InstructionCode NfcCtapControl = InstructionCode.Create(0x12, "NFCCTAP_CONTROL");


    /// <summary>
    /// Gets a value indicating whether <paramref name="code"/> is <see cref="NfcCtapMsg"/>.
    /// </summary>
    /// <param name="code">The instruction code to check.</param>
    /// <returns><see langword="true"/> if <paramref name="code"/> is <c>NFCCTAP_MSG</c>.</returns>
    public static bool IsNfcCtapMsg(InstructionCode code) => code == NfcCtapMsg;

    /// <summary>
    /// Gets a value indicating whether <paramref name="code"/> is <see cref="NfcCtapGetResponse"/>.
    /// </summary>
    /// <param name="code">The instruction code to check.</param>
    /// <returns><see langword="true"/> if <paramref name="code"/> is <c>NFCCTAP_GETRESPONSE</c>.</returns>
    public static bool IsNfcCtapGetResponse(InstructionCode code) => code == NfcCtapGetResponse;

    /// <summary>
    /// Gets a value indicating whether <paramref name="code"/> is <see cref="NfcCtapControl"/>.
    /// </summary>
    /// <param name="code">The instruction code to check.</param>
    /// <returns><see langword="true"/> if <paramref name="code"/> is <c>NFCCTAP_CONTROL</c>.</returns>
    public static bool IsNfcCtapControl(InstructionCode code) => code == NfcCtapControl;
}
