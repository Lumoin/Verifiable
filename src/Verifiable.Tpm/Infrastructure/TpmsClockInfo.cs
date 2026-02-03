using System;
using System.Buffers.Binary;

namespace Verifiable.Tpm.Structures;

/// <summary>
/// TPMS_CLOCK_INFO - clock and reset counter values.
/// </summary>
/// <remarks>
/// <para>
/// This structure contains information about the TPM's internal clock and counters
/// that track resets and restarts. It is embedded within <see cref="TpmsTimeInfo"/>.
/// </para>
/// <para>
/// Wire format (big-endian, 17 bytes total):
/// </para>
/// <list type="bullet">
///   <item><description>Bytes 0-7: Clock (uint64) - total time powered in milliseconds.</description></item>
///   <item><description>Bytes 8-11: ResetCount (uint32) - number of TPM resets since manufacture.</description></item>
///   <item><description>Bytes 12-15: RestartCount (uint32) - number of restarts since last reset.</description></item>
///   <item><description>Byte 16: Safe (TPMI_YES_NO) - 1 if clock has not rolled over or been set backward.</description></item>
/// </list>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 2: Structures, Section 10.11.1 - TPMS_CLOCK_INFO.
/// </para>
/// </remarks>
/// <seealso cref="TpmsTimeInfo"/>
public readonly struct TpmsClockInfo: IEquatable<TpmsClockInfo>
{
    /// <summary>
    /// Size in bytes when serialized (clock: 8 + resetCount: 4 + restartCount: 4 + safe: 1 = 17).
    /// </summary>
    public const int Size = 17;

    /// <summary>
    /// Gets the total time in milliseconds the TPM has been powered.
    /// </summary>
    /// <remarks>
    /// This value is incremented while the TPM has power and is maintained across
    /// TPM2_Shutdown/TPM2_Startup cycles.
    /// </remarks>
    public ulong Clock { get; }

    /// <summary>
    /// Gets the number of TPM resets since the TPM was manufactured.
    /// </summary>
    /// <remarks>
    /// A reset occurs when the TPM loses power or receives a TPM2_Startup(CLEAR).
    /// </remarks>
    public uint ResetCount { get; }

    /// <summary>
    /// Gets the number of TPM restarts since the last reset.
    /// </summary>
    /// <remarks>
    /// A restart occurs on TPM2_Startup(STATE) without a prior reset.
    /// </remarks>
    public uint RestartCount { get; }

    /// <summary>
    /// Gets a value indicating whether the clock value is safe.
    /// </summary>
    /// <remarks>
    /// Returns <c>true</c> if the clock has not rolled over and has not been
    /// set backward. A <c>false</c> value indicates the clock may not be reliable
    /// for time-based comparisons.
    /// </remarks>
    public bool Safe { get; }

    /// <summary>
    /// Initializes clock info with the specified values.
    /// </summary>
    /// <param name="clock">Total powered time in milliseconds.</param>
    /// <param name="resetCount">Number of resets since manufacture.</param>
    /// <param name="restartCount">Number of restarts since last reset.</param>
    /// <param name="safe">Whether the clock value is reliable.</param>
    public TpmsClockInfo(ulong clock, uint resetCount, uint restartCount, bool safe)
    {
        Clock = clock;
        ResetCount = resetCount;
        RestartCount = restartCount;
        Safe = safe;
    }

    /// <summary>
    /// Reads clock info from a byte span.
    /// </summary>
    /// <param name="source">Source bytes, must be at least <see cref="Size"/> bytes.</param>
    /// <returns>The parsed clock info.</returns>
    public static TpmsClockInfo ReadFrom(ReadOnlySpan<byte> source)
    {
        return new TpmsClockInfo(
            BinaryPrimitives.ReadUInt64BigEndian(source),
            BinaryPrimitives.ReadUInt32BigEndian(source[8..]),
            BinaryPrimitives.ReadUInt32BigEndian(source[12..]),
            source[16] != 0);
    }

    /// <inheritdoc/>
    public bool Equals(TpmsClockInfo other)
    {
        return Clock == other.Clock
            && ResetCount == other.ResetCount
            && RestartCount == other.RestartCount
            && Safe == other.Safe;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return obj is TpmsClockInfo other && Equals(other);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Clock, ResetCount, RestartCount, Safe);
    }

    /// <summary>
    /// Determines whether two <see cref="TpmsClockInfo"/> instances are equal.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><c>true</c> if equal; otherwise, <c>false</c>.</returns>
    public static bool operator ==(TpmsClockInfo left, TpmsClockInfo right)
    {
        return left.Equals(right);
    }

    /// <summary>
    /// Determines whether two <see cref="TpmsClockInfo"/> instances are not equal.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><c>true</c> if not equal; otherwise, <c>false</c>.</returns>
    public static bool operator !=(TpmsClockInfo left, TpmsClockInfo right)
    {
        return !left.Equals(right);
    }
}