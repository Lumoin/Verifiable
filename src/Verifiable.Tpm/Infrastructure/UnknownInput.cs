using System;
using Verifiable.Tpm.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Represents command input for an unregistered command code.
/// </summary>
/// <remarks>
/// <para>
/// Used by <see cref="TpmBufferParser"/> when parsing a command with an
/// unknown command code. Contains the raw parameter bytes.
/// </para>
/// </remarks>
public readonly struct UnknownInput: IEquatable<UnknownInput>
{
    /// <summary>
    /// Gets the command code that was not recognized.
    /// </summary>
    public TpmCcConstants CommandCode { get; }

    /// <summary>
    /// Gets the raw parameter bytes.
    /// </summary>
    public ReadOnlyMemory<byte> RawBytes { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="UnknownInput"/> struct.
    /// </summary>
    /// <param name="commandCode">The unrecognized command code.</param>
    /// <param name="rawBytes">The raw parameter bytes.</param>
    public UnknownInput(TpmCcConstants commandCode, byte[] rawBytes)
    {
        CommandCode = commandCode;
        RawBytes = rawBytes;
    }

    /// <inheritdoc/>
    public bool Equals(UnknownInput other)
    {
        return CommandCode == other.CommandCode &&
               RawBytes.Span.SequenceEqual(other.RawBytes.Span);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return obj is UnknownInput other && Equals(other);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(CommandCode);
        hash.AddBytes(RawBytes.Span);
        return hash.ToHashCode();
    }

    /// <summary>
    /// Determines whether two unknown inputs are equal.
    /// </summary>
    public static bool operator ==(UnknownInput left, UnknownInput right)
    {
        return left.Equals(right);
    }

    /// <summary>
    /// Determines whether two unknown inputs are not equal.
    /// </summary>
    public static bool operator !=(UnknownInput left, UnknownInput right)
    {
        return !left.Equals(right);
    }
}