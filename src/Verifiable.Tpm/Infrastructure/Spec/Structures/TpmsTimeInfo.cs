using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Standard TPM time information (TPMS_TIME_INFO): the TPM's monotonic time counter plus the clock/reset state.
/// </summary>
/// <remarks>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT64          time;                    // Time in milliseconds since the last _TPM_Init or TPM2_Startup().
///     TPMS_CLOCK_INFO clockInfo;                // Clock, resetCount, restartCount, safe.
/// } TPMS_TIME_INFO;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 10.11.6, Table 166.
/// </para>
/// </remarks>
/// <param name="Time">Time in milliseconds since the last <c>_TPM_Init</c> or <c>TPM2_Startup()</c>.</param>
/// <param name="ClockInfo">The clock and reset state.</param>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmsTimeInfo(ulong Time, TpmsClockInfo ClockInfo): ITpmWireType
{
    /// <summary>
    /// The serialized size of this fixed-layout structure, in bytes.
    /// </summary>
    public const int SerializedSize = sizeof(ulong) + TpmsClockInfo.SerializedSize;

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteUInt64(Time);
        ClockInfo.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses a time-info structure from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed time info.</returns>
    public static TpmsTimeInfo Parse(ref TpmReader reader)
    {
        ulong time = reader.ReadUInt64();
        TpmsClockInfo clockInfo = TpmsClockInfo.Parse(ref reader);

        return new TpmsTimeInfo(time, clockInfo);
    }

    private string DebuggerDisplay => $"TPMS_TIME_INFO(Time={Time}, {ClockInfo})";
}
