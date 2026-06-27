using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Clock and reset state reported inside an attestation (TPMS_CLOCK_INFO).
/// </summary>
/// <remarks>
/// <para>
/// Appears in every TPMS_ATTEST and reports the TPM's monotonic <see cref="Clock"/> together with the
/// <see cref="ResetCount"/> / <see cref="RestartCount"/> that change across reboots and resumes, plus the
/// <see cref="Safe"/> flag indicating whether <see cref="Clock"/> is known not to have gone backwards.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT64      clock;                       // Time in ms since the last TPM2_Clear().
///     UINT32      resetCount;                  // Number of TPM Resets since the last TPM2_Clear().
///     UINT32      restartCount;                // Number of TPM Restarts/Resumes since the last TPM Reset.
///     TPMI_YES_NO safe;                        // YES if the value of clock is guaranteed not to have decreased.
/// } TPMS_CLOCK_INFO;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 10.11.1, Table 165.
/// </para>
/// </remarks>
/// <param name="Clock">Time in milliseconds since the last <c>TPM2_Clear()</c>.</param>
/// <param name="ResetCount">Number of TPM Resets since the last <c>TPM2_Clear()</c>.</param>
/// <param name="RestartCount">Number of TPM Restarts or Resumes since the last TPM Reset.</param>
/// <param name="Safe">Whether <paramref name="Clock"/> is guaranteed not to have decreased.</param>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmsClockInfo(ulong Clock, uint ResetCount, uint RestartCount, TpmiYesNo Safe): ITpmWireType
{
    /// <summary>
    /// The serialized size of this fixed-layout structure, in bytes.
    /// </summary>
    public const int SerializedSize = sizeof(ulong) + sizeof(uint) + sizeof(uint) + sizeof(byte);

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteUInt64(Clock);
        writer.WriteUInt32(ResetCount);
        writer.WriteUInt32(RestartCount);
        Safe.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses a clock-info structure from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed clock info.</returns>
    public static TpmsClockInfo Parse(ref TpmReader reader)
    {
        ulong clock = reader.ReadUInt64();
        uint resetCount = reader.ReadUInt32();
        uint restartCount = reader.ReadUInt32();
        TpmiYesNo safe = TpmiYesNo.Parse(ref reader);

        return new TpmsClockInfo(clock, resetCount, restartCount, safe);
    }

    private string DebuggerDisplay => $"TPMS_CLOCK_INFO(Clock={Clock}, Reset={ResetCount}, Restart={RestartCount}, Safe={Safe.IsYes})";
}
