using System;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Represents command output for an unregistered command code.
/// </summary>
/// <remarks>
/// <para>
/// Used by <see cref="TpmBufferParser"/> when parsing a response with an
/// unknown command code. Contains the raw response body bytes.
/// </para>
/// </remarks>
public readonly struct UnknownOutput: IEquatable<UnknownOutput>
{
    /// <summary>
    /// Gets the raw response body bytes.
    /// </summary>
    public ReadOnlyMemory<byte> RawBytes { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="UnknownOutput"/> struct.
    /// </summary>
    /// <param name="rawBytes">The raw response body bytes.</param>
    public UnknownOutput(byte[] rawBytes)
    {
        RawBytes = rawBytes;
    }

    /// <inheritdoc/>
    public bool Equals(UnknownOutput other)
    {
        return RawBytes.Span.SequenceEqual(other.RawBytes.Span);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return obj is UnknownOutput other && Equals(other);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(RawBytes.Span);
        return hash.ToHashCode();
    }

    /// <summary>
    /// Determines whether two unknown outputs are equal.
    /// </summary>
    public static bool operator ==(UnknownOutput left, UnknownOutput right)
    {
        return left.Equals(right);
    }

    /// <summary>
    /// Determines whether two unknown outputs are not equal.
    /// </summary>
    public static bool operator !=(UnknownOutput left, UnknownOutput right)
    {
        return !left.Equals(right);
    }
}