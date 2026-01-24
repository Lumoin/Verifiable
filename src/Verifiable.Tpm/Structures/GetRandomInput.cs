using System;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tpm.Commands;

/// <summary>
/// Input for the TPM2_GetRandom command.
/// </summary>
[DebuggerDisplay("GetRandom: {BytesRequested} bytes")]
public readonly struct GetRandomInput : ITpmCommandInput<GetRandomInput>, IEquatable<GetRandomInput>
{
    /// <summary>
    /// Gets the number of random bytes requested.
    /// </summary>
    public ushort BytesRequested { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="GetRandomInput"/> struct.
    /// </summary>
    /// <param name="bytesRequested">The number of random bytes to request.</param>
    public GetRandomInput(ushort bytesRequested)
    {
        BytesRequested = bytesRequested;
    }

    /// <inheritdoc/>
    public static Tpm2CcConstants CommandCode => Tpm2CcConstants.TPM2_CC_GetRandom;

    /// <inheritdoc/>
    public int SerializedSize => sizeof(ushort);

    /// <inheritdoc/>
    public static TpmParseResult<GetRandomInput> Parse(ReadOnlySpan<byte> source)
    {
        var reader = new TpmReader(source);
        ushort bytesRequested = reader.ReadUInt16();
        return new TpmParseResult<GetRandomInput>(new GetRandomInput(bytesRequested), reader.Consumed);
    }

    /// <inheritdoc/>
    public void WriteTo(Span<byte> destination)
    {
        var writer = new TpmWriter(destination);
        writer.WriteUInt16(BytesRequested);
    }

    /// <inheritdoc/>
    public bool Equals(GetRandomInput other) => BytesRequested == other.BytesRequested;

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is GetRandomInput other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => BytesRequested.GetHashCode();

    /// <summary>
    /// Determines whether two instances are equal.
    /// </summary>
    public static bool operator ==(GetRandomInput left, GetRandomInput right) => left.Equals(right);

    /// <summary>
    /// Determines whether two instances are not equal.
    /// </summary>
    public static bool operator !=(GetRandomInput left, GetRandomInput right) => !left.Equals(right);
}
