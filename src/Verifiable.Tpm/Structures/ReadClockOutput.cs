using System;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tpm.Commands;

/// <summary>
/// Output for the TPM2_ReadClock command.
/// </summary>
/// <remarks>
/// <para>
/// Contains the current clock and time values from the TPM.
/// </para>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 3: Commands, Section 17.4 - TPM2_ReadClock.
/// </para>
/// </remarks>
public readonly struct ReadClockOutput: ITpmCommandOutput<ReadClockOutput>, IEquatable<ReadClockOutput>
{
    /// <summary>
    /// Gets the time in milliseconds since the last _TPM_Init.
    /// </summary>
    public ulong Time { get; }

    /// <summary>
    /// Gets the clock value in milliseconds.
    /// </summary>
    public ulong Clock { get; }

    /// <summary>
    /// Gets the number of TPM resets since the TPM was manufactured.
    /// </summary>
    public uint ResetCount { get; }

    /// <summary>
    /// Gets the number of times TPM2_Shutdown was followed by TPM2_Startup.
    /// </summary>
    public uint RestartCount { get; }

    /// <summary>
    /// Gets a value indicating whether the clock value is considered safe.
    /// </summary>
    public bool Safe { get; }

    /// <summary>
    /// Gets the serialized size in bytes.
    /// </summary>
    public int SerializedSize => sizeof(ulong) + sizeof(ulong) + sizeof(uint) + sizeof(uint) + sizeof(byte);

    /// <summary>
    /// Initializes a new instance of the <see cref="ReadClockOutput"/> struct.
    /// </summary>
    /// <param name="time">Time since last init.</param>
    /// <param name="clock">Clock value.</param>
    /// <param name="resetCount">Reset count.</param>
    /// <param name="restartCount">Restart count.</param>
    /// <param name="safe">Safe indicator.</param>
    public ReadClockOutput(ulong time, ulong clock, uint resetCount, uint restartCount, bool safe)
    {
        Time = time;
        Clock = clock;
        ResetCount = resetCount;
        RestartCount = restartCount;
        Safe = safe;
    }

    /// <inheritdoc/>
    public static TpmParseResult<ReadClockOutput> Parse(ReadOnlySpan<byte> source)
    {
        var reader = new TpmReader(source);

        ulong time = reader.ReadUInt64();
        ulong clock = reader.ReadUInt64();
        uint resetCount = reader.ReadUInt32();
        uint restartCount = reader.ReadUInt32();
        bool safe = reader.ReadByte() != 0;

        return new TpmParseResult<ReadClockOutput>(
            new ReadClockOutput(time, clock, resetCount, restartCount, safe),
            reader.Consumed);
    }

    /// <inheritdoc/>
    public void WriteTo(Span<byte> destination)
    {
        var writer = new TpmWriter(destination);

        writer.WriteUInt64(Time);
        writer.WriteUInt64(Clock);
        writer.WriteUInt32(ResetCount);
        writer.WriteUInt32(RestartCount);
        writer.WriteByte(Safe ? (byte)1 : (byte)0);
    }

    /// <inheritdoc/>
    public bool Equals(ReadClockOutput other)
    {
        return Time == other.Time &&
               Clock == other.Clock &&
               ResetCount == other.ResetCount &&
               RestartCount == other.RestartCount &&
               Safe == other.Safe;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is ReadClockOutput other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(Time, Clock, ResetCount, RestartCount, Safe);

    /// <summary>
    /// Determines whether two instances are equal.
    /// </summary>
    public static bool operator ==(ReadClockOutput left, ReadClockOutput right) => left.Equals(right);

    /// <summary>
    /// Determines whether two instances are not equal.
    /// </summary>
    public static bool operator !=(ReadClockOutput left, ReadClockOutput right) => !left.Equals(right);
}