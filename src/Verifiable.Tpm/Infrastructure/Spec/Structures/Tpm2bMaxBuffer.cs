using System;
using System.Buffers.Binary;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// TPM2B_MAX_BUFFER - a sized buffer for general data.
/// </summary>
/// <remarks>
/// <para>
/// This structure holds variable-length data prefixed with a 16-bit size field.
/// The maximum size is implementation-dependent but is at least 1024 bytes.
/// </para>
/// <para>
/// Wire format (big-endian):
/// </para>
/// <list type="bullet">
///   <item><description>Bytes 0-1: Size (uint16) - number of octets in buffer.</description></item>
///   <item><description>Bytes 2+: Buffer - the data.</description></item>
/// </list>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 2: Structures, Section 10.4.2 - TPM2B_MAX_BUFFER.
/// </para>
/// </remarks>
/// <seealso cref="Tpm2bDigest"/>
public readonly struct Tpm2bMaxBuffer: IEquatable<Tpm2bMaxBuffer>
{
    /// <summary>
    /// Gets the buffer data.
    /// </summary>
    public ReadOnlyMemory<byte> Buffer { get; }

    /// <summary>
    /// Initializes a new buffer from existing data.
    /// </summary>
    /// <param name="buffer">The data.</param>
    public Tpm2bMaxBuffer(ReadOnlyMemory<byte> buffer)
    {
        Buffer = buffer;
    }

    /// <summary>
    /// Gets the serialized size of this structure (size field + buffer length).
    /// </summary>
    public int SerializedSize => sizeof(ushort) + Buffer.Length;

    /// <summary>
    /// Writes this structure to a byte span.
    /// </summary>
    /// <param name="destination">Destination bytes.</param>
    /// <returns>Number of bytes written.</returns>
    public int WriteTo(Span<byte> destination)
    {
        BinaryPrimitives.WriteUInt16BigEndian(destination, (ushort)Buffer.Length);
        Buffer.Span.CopyTo(destination[sizeof(ushort)..]);
        return SerializedSize;
    }

    /// <summary>
    /// Reads a buffer from a byte span.
    /// </summary>
    /// <param name="source">Source bytes containing the serialized buffer.</param>
    /// <param name="bytesRead">Number of bytes consumed from the source.</param>
    /// <returns>The parsed buffer.</returns>
    public static Tpm2bMaxBuffer ReadFrom(ReadOnlySpan<byte> source, out int bytesRead)
    {
        ushort size = BinaryPrimitives.ReadUInt16BigEndian(source);
        bytesRead = sizeof(ushort) + size;
        return new Tpm2bMaxBuffer(source.Slice(sizeof(ushort), size).ToArray());
    }

    /// <inheritdoc/>
    public bool Equals(Tpm2bMaxBuffer other)
    {
        return Buffer.Span.SequenceEqual(other.Buffer.Span);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return obj is Tpm2bMaxBuffer other && Equals(other);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(Buffer.Span);
        return hash.ToHashCode();
    }

    /// <summary>
    /// Determines whether two <see cref="Tpm2bMaxBuffer"/> instances are equal.
    /// </summary>
    /// <param name="left">The first buffer to compare.</param>
    /// <param name="right">The second buffer to compare.</param>
    /// <returns><c>true</c> if the buffers are equal; otherwise, <c>false</c>.</returns>
    public static bool operator ==(Tpm2bMaxBuffer left, Tpm2bMaxBuffer right)
    {
        return left.Equals(right);
    }

    /// <summary>
    /// Determines whether two <see cref="Tpm2bMaxBuffer"/> instances are not equal.
    /// </summary>
    /// <param name="left">The first buffer to compare.</param>
    /// <param name="right">The second buffer to compare.</param>
    /// <returns><c>true</c> if the buffers are not equal; otherwise, <c>false</c>.</returns>
    public static bool operator !=(Tpm2bMaxBuffer left, Tpm2bMaxBuffer right)
    {
        return !left.Equals(right);
    }
}