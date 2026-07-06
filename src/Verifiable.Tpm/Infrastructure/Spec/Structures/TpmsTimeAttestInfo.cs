using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Time-specific attestation information (TPMS_TIME_ATTEST_INFO), the <c>time</c> member of TPMU_ATTEST.
/// </summary>
/// <remarks>
/// <para>
/// Produced by <c>TPM2_GetTime()</c>: attests the TPM's current time and clock/reset state, plus its firmware
/// version (TPM 2.0 Library Part 3, Section 18.7).
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPMS_TIME_INFO time;                     // The current TPM time.
///     UINT64         firmwareVersion;          // A vendor-specific value indicating the version of the firmware.
/// } TPMS_TIME_ATTEST_INFO;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 10.12.2, Table 122.
/// </para>
/// </remarks>
/// <param name="Time">The current TPM time and clock/reset state.</param>
/// <param name="FirmwareVersion">A vendor-specific firmware version value.</param>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmsTimeAttestInfo(TpmsTimeInfo Time, ulong FirmwareVersion): ITpmWireType
{
    /// <summary>
    /// The serialized size of this fixed-layout structure, in bytes.
    /// </summary>
    public const int SerializedSize = TpmsTimeInfo.SerializedSize + sizeof(ulong);

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        Time.WriteTo(ref writer);
        writer.WriteUInt64(FirmwareVersion);
    }

    /// <summary>
    /// Parses a time-attest-info structure from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed time-attest info.</returns>
    public static TpmsTimeAttestInfo Parse(ref TpmReader reader)
    {
        TpmsTimeInfo time = TpmsTimeInfo.Parse(ref reader);
        ulong firmwareVersion = reader.ReadUInt64();

        return new TpmsTimeAttestInfo(time, firmwareVersion);
    }

    private string DebuggerDisplay => $"TPMS_TIME_ATTEST_INFO({Time}, fw={FirmwareVersion})";
}
