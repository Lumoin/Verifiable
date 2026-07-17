namespace Verifiable.Apdu;

/// <summary>
/// ISO/IEC 7816-4 inter-industry command parameter bytes (CLA and P1/P2 values) shared by the
/// command builders in this library.
/// </summary>
/// <remarks>
/// <para>
/// These are true inter-industry spec literals: CLA and P1/P2 ride as plain <see cref="byte"/>
/// parameters through <see cref="CommandApdu"/>'s <c>Build*</c> factories, so they are named here as
/// plain constants rather than wrapped in a registered wire type the way
/// <see cref="InstructionCode"/> and <see cref="StatusWord"/> values are.
/// </para>
/// <para>
/// Card-application profiles (eMRTD, CTAP-over-NFC, and so on) instantiate these inter-industry
/// values rather than redefining them; profile-specific parameter bytes live in the profile's own
/// well-known class (for example <c>Verifiable.Apdu.Ctap.WellKnownCtapCommandParameters</c>).
/// </para>
/// </remarks>
public static class WellKnownCommandParameters
{
    /// <summary>
    /// The inter-industry class byte (<c>0x00</c>): inter-industry command, no secure messaging,
    /// basic logical channel.
    /// </summary>
    /// <remarks>
    /// ISO/IEC 7816-4 encodes command chaining, secure messaging, and the logical channel number in
    /// the CLA byte; <c>0x00</c> is the plain inter-industry class with none of those set.
    /// </remarks>
    public const byte InterIndustryClassByte = 0x00;

    /// <summary>
    /// SELECT P1 value (<c>0x04</c>): select by DF name. For applications the DF name is the
    /// application identifier (AID), making this the select-by-AID form.
    /// </summary>
    /// <remarks>
    /// ISO/IEC 7816-4 defines the SELECT P1 selection-method encoding; <c>0x04</c> selects a
    /// dedicated file by its name, given in the command data field.
    /// </remarks>
    public const byte SelectByDfNameP1 = 0x04;

    /// <summary>
    /// SELECT P2 value (<c>0x00</c>): first or only occurrence, return the File Control
    /// Information (FCI) template.
    /// </summary>
    /// <remarks>
    /// ISO/IEC 7816-4 encodes the occurrence selection and the response-data preference in the
    /// SELECT P2 byte; <c>0x00</c> is both defaults at once.
    /// </remarks>
    public const byte SelectFirstOrOnlyOccurrenceFciP2 = 0x00;

    /// <summary>
    /// The reserved-for-future-use byte (<c>0x00</c>) ISO/IEC 7816-4 requires wherever a command's
    /// P1 or P2 position carries no defined meaning for the current instruction.
    /// </summary>
    /// <remarks>
    /// Shares its numeric value with <see cref="InterIndustryClassByte"/> and
    /// <see cref="SelectFirstOrOnlyOccurrenceFciP2"/> by coincidence of both being zero, not by
    /// relation — an RFU parameter position and a defined-zero parameter value are distinct
    /// concepts that happen to share a bit pattern.
    /// </remarks>
    public const byte ReservedForFutureUse = 0x00;


    /// <summary>
    /// Gets a value indicating whether <paramref name="classByte"/> is <see cref="InterIndustryClassByte"/>.
    /// </summary>
    /// <param name="classByte">The CLA byte to check.</param>
    /// <returns><see langword="true"/> if <paramref name="classByte"/> is the plain inter-industry class byte.</returns>
    public static bool IsInterIndustryClassByte(byte classByte) => classByte == InterIndustryClassByte;

    /// <summary>
    /// Gets a value indicating whether <paramref name="p1"/> is <see cref="SelectByDfNameP1"/>.
    /// </summary>
    /// <param name="p1">The SELECT P1 byte to check.</param>
    /// <returns><see langword="true"/> if <paramref name="p1"/> selects by DF name.</returns>
    public static bool IsSelectByDfNameP1(byte p1) => p1 == SelectByDfNameP1;

    /// <summary>
    /// Gets a value indicating whether <paramref name="p2"/> is <see cref="SelectFirstOrOnlyOccurrenceFciP2"/>.
    /// </summary>
    /// <param name="p2">The SELECT P2 byte to check.</param>
    /// <returns><see langword="true"/> if <paramref name="p2"/> selects the first/only occurrence and requests the FCI template.</returns>
    public static bool IsSelectFirstOrOnlyOccurrenceFciP2(byte p2) => p2 == SelectFirstOrOnlyOccurrenceFciP2;

    /// <summary>
    /// Gets a value indicating whether <paramref name="value"/> is <see cref="ReservedForFutureUse"/>.
    /// </summary>
    /// <param name="value">The P1 or P2 byte to check.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is the reserved-for-future-use byte.</returns>
    public static bool IsReservedForFutureUse(byte value) => value == ReservedForFutureUse;
}
