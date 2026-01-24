using System;
using System.Buffers.Binary;

namespace Verifiable.Tpm.Structures;

/// <summary>
/// TPMS_TIME_INFO - time and clock information from TPM2_ReadClock.
/// </summary>
/// <remarks>
/// <para>
/// This structure is returned by the TPM2_ReadClock command and contains
/// both the time since last startup and detailed clock information.
/// </para>
/// <para>
/// Wire format (big-endian, 25 bytes total):
/// </para>
/// <list type="bullet">
///   <item><description>Bytes 0-7: Time (uint64) - milliseconds since last TPM2_Startup.</description></item>
///   <item><description>Bytes 8-24: ClockInfo (<see cref="TpmsClockInfo"/>) - embedded clock structure.</description></item>
/// </list>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 2: Structures, Section 10.11.6 - TPMS_TIME_INFO.
/// </para>
/// </remarks>
/// <seealso cref="TpmsClockInfo"/>
/// <seealso cref="Tpm2CcConstants.TPM2_CC_ReadClock"/>
public readonly struct TpmsTimeInfo: IEquatable<TpmsTimeInfo>
{
    /// <summary>
    /// Size in bytes when serialized (time: 8 + clockInfo: 17 = 25).
    /// </summary>
    public const int Size = sizeof(ulong) + TpmsClockInfo.Size;

    /// <summary>
    /// Gets the time in milliseconds since the last TPM2_Startup command.
    /// </summary>
    /// <remarks>
    /// This counter resets on each TPM startup and increments while the TPM is operational.
    /// </remarks>
    public ulong Time { get; }

    /// <summary>
    /// Gets the clock information including total powered time and reset/restart counters.
    /// </summary>
    /// <seealso cref="TpmsClockInfo"/>
    public TpmsClockInfo ClockInfo { get; }

    /// <summary>
    /// Initializes time info with the specified values.
    /// </summary>
    /// <param name="time">Time since startup in milliseconds.</param>
    /// <param name="clockInfo">Clock and counter information.</param>
    public TpmsTimeInfo(ulong time, TpmsClockInfo clockInfo)
    {
        Time = time;
        ClockInfo = clockInfo;
    }

    /// <summary>
    /// Reads time info from a byte span.
    /// </summary>
    /// <param name="source">Source bytes, must be at least <see cref="Size"/> bytes.</param>
    /// <returns>The parsed time info.</returns>
    public static TpmsTimeInfo ReadFrom(ReadOnlySpan<byte> source)
    {
        ulong time = BinaryPrimitives.ReadUInt64BigEndian(source);
        TpmsClockInfo clockInfo = TpmsClockInfo.ReadFrom(source[sizeof(ulong)..]);
        return new TpmsTimeInfo(time, clockInfo);
    }

    /// <inheritdoc/>
    public bool Equals(TpmsTimeInfo other)
    {
        return Time == other.Time && ClockInfo.Equals(other.ClockInfo);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return obj is TpmsTimeInfo other && Equals(other);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Time, ClockInfo);
    }

    /// <summary>
    /// Determines whether two <see cref="TpmsTimeInfo"/> instances are equal.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><c>true</c> if equal; otherwise, <c>false</c>.</returns>
    public static bool operator ==(TpmsTimeInfo left, TpmsTimeInfo right)
    {
        return left.Equals(right);
    }

    /// <summary>
    /// Determines whether two <see cref="TpmsTimeInfo"/> instances are not equal.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><c>true</c> if not equal; otherwise, <c>false</c>.</returns>
    public static bool operator !=(TpmsTimeInfo left, TpmsTimeInfo right)
    {
        return !left.Equals(right);
    }
}