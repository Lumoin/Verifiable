using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response parameters for TPM2_ReadClock.
/// </summary>
/// <remarks>
/// <para>
/// This type represents the complete response parameter area for the TPM2_ReadClock command: a single
/// fixed-layout <c>TPMS_TIME_INFO</c> (TPM 2.0 Library Part 3, Section 29.1, Table 203).
/// </para>
/// <para>
/// Unlike <see cref="GetTimeResponse"/>, this value is uncertified and unsigned — it carries no
/// <c>TPM2B_ATTEST</c> and no <c>TPMT_SIGNATURE</c>.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class ReadClockResponse: ITpmWireType
{
    /// <summary>
    /// Gets the current time, clock, resetCount, restartCount, and Safe snapshot.
    /// </summary>
    public TpmsTimeInfo CurrentTime { get; }

    private ReadClockResponse(TpmsTimeInfo currentTime)
    {
        CurrentTime = currentTime;
    }

    /// <summary>
    /// Parses the response parameters from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for allocations (unused; this response owns no pooled memory).</param>
    /// <returns>The parsed response.</returns>
    public static ReadClockResponse Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        TpmsTimeInfo currentTime = TpmsTimeInfo.Parse(ref reader);

        return new ReadClockResponse(currentTime);
    }

    private string DebuggerDisplay => $"ReadClockResponse({CurrentTime})";
}
