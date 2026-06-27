using System;
using System.Buffers.Binary;

namespace Verifiable.Apdu;

/// <summary>
/// A position-tracking writer for APDU byte buffers.
/// </summary>
/// <remarks>
/// <para>
/// APDU command structures use big-endian byte order for multi-byte fields
/// (extended length Lc/Le). This writer provides primitives for constructing
/// APDU commands while tracking position.
/// </para>
/// </remarks>
public ref struct ApduWriter
{
    private Span<byte> remaining;
    private int written;

    /// <summary>
    /// Initializes a new instance of the <see cref="ApduWriter"/> struct.
    /// </summary>
    /// <param name="buffer">The buffer to write to.</param>
    public ApduWriter(Span<byte> buffer)
    {
        remaining = buffer;
        written = 0;
    }

    /// <summary>
    /// Gets the number of bytes written so far.
    /// </summary>
    public int Written => written;

    /// <summary>
    /// Gets the number of bytes remaining in the buffer.
    /// </summary>
    public int Remaining => remaining.Length;

    /// <summary>
    /// Writes a single byte.
    /// </summary>
    /// <param name="value">The byte value.</param>
    public void WriteByte(byte value)
    {
        remaining[0] = value;
        Advance(1);
    }

    /// <summary>
    /// Writes a big-endian unsigned 16-bit integer.
    /// </summary>
    /// <param name="value">The value to write.</param>
    public void WriteUInt16(ushort value)
    {
        BinaryPrimitives.WriteUInt16BigEndian(remaining, value);
        Advance(sizeof(ushort));
    }

    /// <summary>
    /// Writes a sequence of bytes.
    /// </summary>
    /// <param name="bytes">The bytes to write.</param>
    public void WriteBytes(scoped ReadOnlySpan<byte> bytes)
    {
        bytes.CopyTo(remaining);
        Advance(bytes.Length);
    }

    /// <summary>
    /// Writes the four-byte command APDU header.
    /// </summary>
    /// <param name="cla">Class byte.</param>
    /// <param name="ins">Instruction byte.</param>
    /// <param name="p1">Parameter 1.</param>
    /// <param name="p2">Parameter 2.</param>
    public void WriteHeader(byte cla, byte ins, byte p1, byte p2)
    {
        remaining[0] = cla;
        remaining[1] = ins;
        remaining[2] = p1;
        remaining[3] = p2;
        Advance(ApduConstants.CommandHeaderSize);
    }

    private void Advance(int count)
    {
        remaining = remaining[count..];
        written += count;
    }
}
