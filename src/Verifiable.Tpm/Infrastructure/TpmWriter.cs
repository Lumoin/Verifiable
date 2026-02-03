using System;
using System.Buffers.Binary;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// A position-tracking writer for TPM byte buffers.
/// </summary>
/// <remarks>
/// <para>
/// All TPM structures use big-endian byte order. This writer provides
/// primitives for writing TPM data types while tracking position.
/// </para>
/// </remarks>
public ref struct TpmWriter
{
    private Span<byte> _remaining;
    private int _written;

    /// <summary>
    /// Initializes a new instance of the <see cref="TpmWriter"/> struct.
    /// </summary>
    /// <param name="buffer">The buffer to write to.</param>
    public TpmWriter(Span<byte> buffer)
    {
        _remaining = buffer;
        _written = 0;
    }

    /// <summary>
    /// Gets the number of bytes written so far.
    /// </summary>
    public int Written => _written;

    /// <summary>
    /// Gets the number of bytes remaining in the buffer.
    /// </summary>
    public int Remaining => _remaining.Length;

    /// <summary>
    /// Writes a single byte.
    /// </summary>
    /// <param name="value">The byte value.</param>
    public void WriteByte(byte value)
    {
        _remaining[0] = value;
        Advance(1);
    }

    /// <summary>
    /// Writes a big-endian unsigned 16-bit integer.
    /// </summary>
    /// <param name="value">The value to write.</param>
    public void WriteUInt16(ushort value)
    {
        BinaryPrimitives.WriteUInt16BigEndian(_remaining, value);
        Advance(sizeof(ushort));
    }

    /// <summary>
    /// Writes a big-endian unsigned 32-bit integer.
    /// </summary>
    /// <param name="value">The value to write.</param>
    public void WriteUInt32(uint value)
    {
        BinaryPrimitives.WriteUInt32BigEndian(_remaining, value);
        Advance(sizeof(uint));
    }

    /// <summary>
    /// Writes a big-endian unsigned 64-bit integer.
    /// </summary>
    /// <param name="value">The value to write.</param>
    public void WriteUInt64(ulong value)
    {
        BinaryPrimitives.WriteUInt64BigEndian(_remaining, value);
        Advance(sizeof(ulong));
    }

    /// <summary>
    /// Writes a sequence of bytes.
    /// </summary>
    /// <param name="bytes">The bytes to write.</param>
    /// <remarks>
    /// The <c>scoped</c> modifier ensures stackalloc'd spans can be passed safely.
    /// </remarks>
    public void WriteBytes(scoped ReadOnlySpan<byte> bytes)
    {
        bytes.CopyTo(_remaining);
        Advance(bytes.Length);
    }

    /// <summary>
    /// Writes a TPM2B structure (2-byte length prefix followed by data).
    /// </summary>
    /// <param name="data">The data bytes to write.</param>
    /// <remarks>
    /// The <c>scoped</c> modifier ensures stackalloc'd spans can be passed safely.
    /// </remarks>
    public void WriteTpm2b(scoped ReadOnlySpan<byte> data)
    {
        WriteUInt16((ushort)data.Length);
        WriteBytes(data);
    }

    private void Advance(int count)
    {
        _remaining = _remaining[count..];
        _written += count;
    }
}