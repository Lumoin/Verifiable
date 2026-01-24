using System;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tpm.Commands;

/// <summary>
/// Input for the TPM2_ReadClock command.
/// </summary>
/// <remarks>
/// <para>
/// TPM2_ReadClock has no input parameters. The command returns the current
/// clock and time values.
/// </para>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 3: Commands, Section 17.4 - TPM2_ReadClock.
/// </para>
/// </remarks>
public readonly struct ReadClockInput: ITpmCommandInput<ReadClockInput>, IEquatable<ReadClockInput>
{
    /// <inheritdoc/>
    public static Tpm2CcConstants CommandCode => Tpm2CcConstants.TPM2_CC_ReadClock;

    /// <inheritdoc/>
    public int SerializedSize => 0;

    /// <inheritdoc/>
    public static TpmParseResult<ReadClockInput> Parse(ReadOnlySpan<byte> source)
    {
        return new TpmParseResult<ReadClockInput>(new ReadClockInput(), 0);
    }

    /// <inheritdoc/>
    public void WriteTo(Span<byte> destination)
    {
        //No parameters to write.
    }

    /// <inheritdoc/>
    public bool Equals(ReadClockInput other) => true;

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is ReadClockInput;

    /// <inheritdoc/>
    public override int GetHashCode() => 0;

    /// <summary>
    /// Determines whether two instances are equal.
    /// </summary>
    public static bool operator ==(ReadClockInput left, ReadClockInput right) => true;

    /// <summary>
    /// Determines whether two instances are not equal.
    /// </summary>
    public static bool operator !=(ReadClockInput left, ReadClockInput right) => false;
}