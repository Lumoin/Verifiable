using System;
using System.Buffers.Binary;

namespace Verifiable.Tpm.Structures;

/// <summary>
/// TPM2B_DIGEST - a sized buffer for digest values.
/// </summary>
/// <remarks>
/// <para>
/// This structure holds variable-length digest data prefixed with a 16-bit size field.
/// The maximum size depends on the largest hash algorithm supported by the TPM,
/// typically 64 bytes for SHA-512.
/// </para>
/// <para>
/// Wire format (big-endian):
/// </para>
/// <list type="bullet">
///   <item><description>Bytes 0-1: Size (uint16) - number of octets in buffer.</description></item>
///   <item><description>Bytes 2+: Buffer - the digest data.</description></item>
/// </list>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 2: Structures, Section 10.4.1 - TPM2B_DIGEST.
/// </para>
/// </remarks>
/// <seealso cref="Tpm2bMaxBuffer"/>
public readonly struct Tpm2bDigest: IEquatable<Tpm2bDigest>
{
    /// <summary>
    /// Gets the digest bytes.
    /// </summary>
    public ReadOnlyMemory<byte> Buffer { get; }

    /// <summary>
    /// Initializes a new digest from existing data.
    /// </summary>
    /// <param name="buffer">The digest data.</param>
    public Tpm2bDigest(ReadOnlyMemory<byte> buffer)
    {
        Buffer = buffer;
    }

    /// <summary>
    /// Gets the serialized size of this structure (size field + buffer length).
    /// </summary>
    public int SerializedSize => sizeof(ushort) + Buffer.Length;

    /// <summary>
    /// Reads a digest from a byte span.
    /// </summary>
    /// <param name="source">Source bytes containing the serialized digest.</param>
    /// <param name="bytesRead">Number of bytes consumed from the source.</param>
    /// <returns>The parsed digest.</returns>
    public static Tpm2bDigest ReadFrom(ReadOnlySpan<byte> source, out int bytesRead)
    {
        ushort size = BinaryPrimitives.ReadUInt16BigEndian(source);
        bytesRead = sizeof(ushort) + size;
        return new Tpm2bDigest(source.Slice(sizeof(ushort), size).ToArray());
    }

    /// <inheritdoc/>
    public bool Equals(Tpm2bDigest other)
    {
        return Buffer.Span.SequenceEqual(other.Buffer.Span);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return obj is Tpm2bDigest other && Equals(other);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(Buffer.Span);

        return hash.ToHashCode();
    }

    /// <summary>
    /// Determines whether two <see cref="Tpm2bDigest"/> instances are equal.
    /// </summary>
    /// <param name="left">The first digest to compare.</param>
    /// <param name="right">The second digest to compare.</param>
    /// <returns><c>true</c> if the digests are equal; otherwise, <c>false</c>.</returns>
    public static bool operator ==(Tpm2bDigest left, Tpm2bDigest right)
    {
        return left.Equals(right);
    }

    /// <summary>
    /// Determines whether two <see cref="Tpm2bDigest"/> instances are not equal.
    /// </summary>
    /// <param name="left">The first digest to compare.</param>
    /// <param name="right">The second digest to compare.</param>
    /// <returns><c>true</c> if the digests are not equal; otherwise, <c>false</c>.</returns>
    public static bool operator !=(Tpm2bDigest left, Tpm2bDigest right)
    {
        return !left.Equals(right);
    }
}