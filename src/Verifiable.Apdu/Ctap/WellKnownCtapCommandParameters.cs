namespace Verifiable.Apdu.Ctap;

/// <summary>
/// ISO/IEC 7816-4 command parameter bytes (CLA and P1 values) specific to the CTAP2-over-NFC binding.
/// </summary>
/// <remarks>
/// <para>
/// Unlike <see cref="WellKnownCtapInstructionCodes"/> and <see cref="WellKnownCtapStatusWords"/>, these
/// are not wrapped in a registered wire type: CLA and P1 already ride as plain <see cref="byte"/>
/// parameters through <see cref="CommandApdu"/>'s <c>Build*</c> factories, so they are named here as
/// plain constants — true spec literals, not values built through a registration seam.
/// </para>
/// <para>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-command-framing">
/// CTAP 2.3, section 11.3.5.1: Command framing</see> fixes <see cref="ClassByte"/> as the CLA for
/// every <see cref="WellKnownCtapInstructionCodes.NfcCtapMsg"/>,
/// <see cref="WellKnownCtapInstructionCodes.NfcCtapGetResponse"/>, and
/// <see cref="WellKnownCtapInstructionCodes.NfcCtapControl"/> command;
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-ctap-msg">
/// section 11.3.7.1: NFCCTAP_MSG (0x10)</see> defines <see cref="SupportsGetResponseP1Bit"/>;
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-applet-deselect">
/// section 11.3.4: Applet deselection</see> defines <see cref="DeselectControlP1"/>;
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-ctap-response">
/// section 11.3.7.2: NFCCTAP_GETRESPONSE (0x11)</see> defines <see cref="CancelP1"/>.
/// </para>
/// <para>
/// Applet selection per
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-applet-selection">
/// section 11.3.3: Applet selection</see> defines nothing CTAP-specific: it instantiates the plain
/// inter-industry ISO/IEC 7816-4 SELECT, so its header values are the generic
/// <see cref="WellKnownCommandParameters"/> names
/// (<see cref="WellKnownCommandParameters.InterIndustryClassByte"/>,
/// <see cref="WellKnownCommandParameters.SelectByDfNameP1"/>,
/// <see cref="WellKnownCommandParameters.SelectFirstOrOnlyOccurrenceFciP2"/>), not members here.
/// </para>
/// </remarks>
public static class WellKnownCtapCommandParameters
{
    /// <summary>
    /// The CLA byte (<c>0x80</c>) for every NFCCTAP_MSG, NFCCTAP_GETRESPONSE, and NFCCTAP_CONTROL command.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-command-framing">
    /// CTAP 2.3, section 11.3.5.1: Command framing</see>. Distinct from
    /// <see cref="WellKnownCommandParameters.InterIndustryClassByte"/> (<c>0x00</c>), which the plain
    /// ISO/IEC 7816-4 SELECT and GET RESPONSE commands use.
    /// </remarks>
    public const byte ClassByte = 0x80;

    /// <summary>
    /// NFCCTAP_MSG P1 bit (<c>0x80</c>) declaring that the client supports NFCCTAP_GETRESPONSE.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-ctap-msg">
    /// CTAP 2.3, section 11.3.7.1: NFCCTAP_MSG (0x10)</see>.
    /// </remarks>
    public const byte SupportsGetResponseP1Bit = 0x80;

    /// <summary>
    /// NFCCTAP_CONTROL P1 value (<c>0x01</c>) for "End CTAP_MSG" applet deselection.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-applet-deselect">
    /// CTAP 2.3, section 11.3.4: Applet deselection</see>.
    /// </remarks>
    public const byte DeselectControlP1 = 0x01;

    /// <summary>
    /// NFCCTAP_GETRESPONSE P1 value (<c>0x11</c>) for the cancel variant.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-ctap-response">
    /// CTAP 2.3, section 11.3.7.2: NFCCTAP_GETRESPONSE (0x11)</see>.
    /// </remarks>
    public const byte CancelP1 = 0x11;


    /// <summary>
    /// Gets a value indicating whether <paramref name="classByte"/> is <see cref="ClassByte"/>.
    /// </summary>
    /// <param name="classByte">The CLA byte to check.</param>
    /// <returns><see langword="true"/> if <paramref name="classByte"/> is the NFCCTAP class byte.</returns>
    public static bool IsClassByte(byte classByte) => classByte == ClassByte;

    /// <summary>
    /// Gets a value indicating whether <paramref name="p1Bit"/> is <see cref="SupportsGetResponseP1Bit"/>.
    /// </summary>
    /// <param name="p1Bit">The NFCCTAP_MSG P1 byte to check.</param>
    /// <returns><see langword="true"/> if <paramref name="p1Bit"/> declares NFCCTAP_GETRESPONSE support.</returns>
    public static bool IsSupportsGetResponseP1Bit(byte p1Bit) => p1Bit == SupportsGetResponseP1Bit;

    /// <summary>
    /// Gets a value indicating whether <paramref name="p1"/> is <see cref="DeselectControlP1"/>.
    /// </summary>
    /// <param name="p1">The NFCCTAP_CONTROL P1 byte to check.</param>
    /// <returns><see langword="true"/> if <paramref name="p1"/> requests applet deselection.</returns>
    public static bool IsDeselectControlP1(byte p1) => p1 == DeselectControlP1;

    /// <summary>
    /// Gets a value indicating whether <paramref name="p1"/> is <see cref="CancelP1"/>.
    /// </summary>
    /// <param name="p1">The NFCCTAP_GETRESPONSE P1 byte to check.</param>
    /// <returns><see langword="true"/> if <paramref name="p1"/> requests the cancel variant.</returns>
    public static bool IsCancelP1(byte p1) => p1 == CancelP1;
}
