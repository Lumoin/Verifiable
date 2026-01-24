using System;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure;

namespace Verifiable.Tpm.Commands;

/// <summary>
/// Output from the TPM2_GetRandom command.
/// </summary>
[DebuggerDisplay("GetRandom: {Bytes.Length} bytes")]
public readonly struct GetRandomOutput : ITpmCommandOutput<GetRandomOutput>, IEquatable<GetRandomOutput>
{
    /// <summary>
    /// Gets the random bytes from the TPM.
    /// </summary>
    public ReadOnlyMemory<byte> Bytes { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="GetRandomOutput"/> struct.
    /// </summary>
    /// <param name="bytes">The random bytes.</param>
    public GetRandomOutput(ReadOnlyMemory<byte> bytes)
    {
        Bytes = bytes;
    }

    /// <inheritdoc/>
    public int SerializedSize => sizeof(ushort) + Bytes.Length;

    /// <inheritdoc/>
    public static TpmParseResult<GetRandomOutput> Parse(ReadOnlySpan<byte> source)
    {
        var reader = new TpmReader(source);
        ReadOnlySpan<byte> bytes = reader.ReadTpm2b();
        return new TpmParseResult<GetRandomOutput>(new GetRandomOutput(bytes.ToArray()), reader.Consumed);
    }

    /// <inheritdoc/>
    public void WriteTo(Span<byte> destination)
    {
        var writer = new TpmWriter(destination);
        writer.WriteTpm2b(Bytes.Span);
    }

    /// <inheritdoc/>
    public bool Equals(GetRandomOutput other) => Bytes.Span.SequenceEqual(other.Bytes.Span);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is GetRandomOutput other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        foreach (byte b in Bytes.Span)
        {
            hash.Add(b);
        }

        return hash.ToHashCode();
    }

    /// <summary>
    /// Determines whether two instances are equal.
    /// </summary>
    public static bool operator ==(GetRandomOutput left, GetRandomOutput right) => left.Equals(right);

    /// <summary>
    /// Determines whether two instances are not equal.
    /// </summary>
    public static bool operator !=(GetRandomOutput left, GetRandomOutput right) => !left.Equals(right);
}
