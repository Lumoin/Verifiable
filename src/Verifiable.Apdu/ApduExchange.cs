using System;
using System.Diagnostics;

namespace Verifiable.Apdu;

/// <summary>
/// A captured command/response APDU exchange with timing information.
/// </summary>
/// <remarks>
/// <para>
/// Exchanges are captured by <see cref="ApduRecorder"/> via the
/// <see cref="IObservable{T}"/> pattern on <see cref="ApduDevice"/>.
/// Each exchange records the raw bytes of both command and response,
/// along with high-resolution timestamps for performance analysis.
/// </para>
/// <para>
/// The command and response bytes are copied at capture time so they
/// remain valid after the original buffers are disposed.
/// </para>
/// </remarks>
/// <param name="StartTicks">
/// The <see cref="Stopwatch.GetTimestamp"/> value when the command was submitted.
/// </param>
/// <param name="EndTicks">
/// The <see cref="Stopwatch.GetTimestamp"/> value when the response was received.
/// </param>
/// <param name="Command">
/// The complete command APDU bytes (CLA, INS, P1, P2, optional Lc, data, Le).
/// </param>
/// <param name="Response">
/// The complete response APDU bytes (data + SW1 + SW2), or empty if a
/// transport error occurred.
/// </param>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record ApduExchange(
    long StartTicks,
    long EndTicks,
    ReadOnlyMemory<byte> Command,
    ReadOnlyMemory<byte> Response)
{
    /// <summary>
    /// Gets the elapsed duration of this exchange.
    /// </summary>
    public TimeSpan Elapsed => Stopwatch.GetElapsedTime(StartTicks, EndTicks);

    /// <summary>
    /// Gets the instruction byte from the command header.
    /// </summary>
    public byte Instruction => Command.Span[1];

    /// <summary>
    /// Gets the status word from the response, or <see langword="null"/>
    /// if the response is too short (transport error).
    /// </summary>
    public StatusWord? StatusWord
    {
        get
        {
            if(Response.Length < ApduConstants.StatusWordSize)
            {
                return null;
            }

            ReadOnlySpan<byte> span = Response.Span;
            byte sw1 = span[Response.Length - 2];
            byte sw2 = span[Response.Length - 1];
            return Verifiable.Apdu.StatusWord.FromBytes(sw1, sw2);
        }
    }

    /// <summary>
    /// Gets the instruction name for display purposes.
    /// </summary>
    public string InstructionName => InstructionCodeNames.GetName(Instruction);

    private string DebuggerDisplay
    {
        get
        {
            string swText = StatusWord is { } sw
                ? $"SW=0x{sw.Value:X4}"
                : "no response";

            return $"{InstructionName} → {swText} ({Elapsed.TotalMilliseconds:F1}ms, " +
                   $"cmd={Command.Length}B, rsp={Response.Length}B)";
        }
    }
}
