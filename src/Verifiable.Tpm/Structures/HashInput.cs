using System;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tpm.Commands;

/// <summary>
/// Input for the TPM2_Hash command.
/// </summary>
/// <remarks>
/// <para>
/// TPM2_Hash performs a hash operation on a data buffer and returns the result.
/// </para>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 3: Commands, Section 15.4 - TPM2_Hash.
/// </para>
/// </remarks>
public readonly struct HashInput: ITpmCommandInput<HashInput>, IEquatable<HashInput>
{
    /// <summary>
    /// Gets the hash algorithm to use.
    /// </summary>
    public Tpm2AlgId Algorithm { get; }

    /// <summary>
    /// Gets the data to hash.
    /// </summary>
    public ReadOnlyMemory<byte> Data { get; }

    /// <summary>
    /// Gets the hierarchy for ticket generation (TPM_RH_NULL for no ticket).
    /// </summary>
    public uint Hierarchy { get; }

    /// <inheritdoc/>
    public static Tpm2CcConstants CommandCode => Tpm2CcConstants.TPM2_CC_Hash;

    /// <inheritdoc/>
    public int SerializedSize => sizeof(ushort) + Data.Length + sizeof(ushort) + sizeof(uint);

    /// <summary>
    /// Initializes a new instance of the <see cref="HashInput"/> struct.
    /// </summary>
    /// <param name="algorithm">The hash algorithm to use.</param>
    /// <param name="data">The data to hash.</param>
    /// <param name="hierarchy">The hierarchy for ticket generation (default: TPM_RH_NULL).</param>
    public HashInput(Tpm2AlgId algorithm, byte[] data, uint hierarchy = 0x40000007)
    {
        Algorithm = algorithm;
        Data = data;
        Hierarchy = hierarchy;
    }

    /// <inheritdoc/>
    public static TpmParseResult<HashInput> Parse(ReadOnlySpan<byte> source)
    {
        var reader = new TpmReader(source);

        byte[] data = reader.ReadTpm2b().ToArray();
        ushort algorithm = reader.ReadUInt16();
        uint hierarchy = reader.ReadUInt32();

        return new TpmParseResult<HashInput>(
            new HashInput((Tpm2AlgId)algorithm, data, hierarchy),
            reader.Consumed);
    }

    /// <inheritdoc/>
    public void WriteTo(Span<byte> destination)
    {
        var writer = new TpmWriter(destination);

        writer.WriteTpm2b(Data.Span);
        writer.WriteUInt16((ushort)Algorithm);
        writer.WriteUInt32(Hierarchy);
    }

    /// <inheritdoc/>
    public bool Equals(HashInput other)
    {
        return Algorithm == other.Algorithm &&
               Hierarchy == other.Hierarchy &&
               Data.Span.SequenceEqual(other.Data.Span);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is HashInput other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Algorithm);
        hash.Add(Hierarchy);
        hash.AddBytes(Data.Span);
        return hash.ToHashCode();
    }

    /// <summary>
    /// Determines whether two instances are equal.
    /// </summary>
    public static bool operator ==(HashInput left, HashInput right) => left.Equals(right);

    /// <summary>
    /// Determines whether two instances are not equal.
    /// </summary>
    public static bool operator !=(HashInput left, HashInput right) => !left.Equals(right);
}