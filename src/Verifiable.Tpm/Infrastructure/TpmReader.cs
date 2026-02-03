using System;
using System.Buffers.Binary;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// A position-tracking reader for TPM byte buffers.
/// </summary>
/// <remarks>
/// <para>
/// All TPM structures use big-endian byte order. This reader provides
/// primitives for reading TPM data types while tracking position.
/// </para>
/// <para>
/// <b>Zero-copy support:</b> Use <see cref="ReadTpm2bBlob"/> to get offset/length
/// references instead of copying bytes. The returned <see cref="TpmBlob"/> can
/// later be resolved against the original buffer.
/// </para>
/// </remarks>
public ref struct TpmReader
{
    private readonly ReadOnlySpan<byte> _original;
    private ReadOnlySpan<byte> _remaining;
    private int _consumed;

    /// <summary>
    /// Initializes a new instance of the <see cref="TpmReader"/> struct.
    /// </summary>
    /// <param name="buffer">The buffer to read from.</param>
    public TpmReader(ReadOnlySpan<byte> buffer)
    {
        _original = buffer;
        _remaining = buffer;
        _consumed = 0;
    }

    /// <summary>
    /// Gets the number of bytes consumed so far.
    /// </summary>
    public int Consumed => _consumed;

    /// <summary>
    /// Gets the number of bytes remaining.
    /// </summary>
    public int Remaining => _remaining.Length;

    /// <summary>
    /// Gets a value indicating whether the buffer is empty.
    /// </summary>
    public bool IsEmpty => _remaining.IsEmpty;

    /// <summary>
    /// Gets the current position in the original buffer.
    /// </summary>
    public int Position => _consumed;

    /// <summary>
    /// Reads a single byte.
    /// </summary>
    /// <returns>The byte value.</returns>
    public byte ReadByte()
    {
        byte value = _remaining[0];
        Advance(1);
        return value;
    }

    /// <summary>
    /// Reads a big-endian unsigned 16-bit integer.
    /// </summary>
    /// <returns>The value.</returns>
    public ushort ReadUInt16()
    {
        ushort value = BinaryPrimitives.ReadUInt16BigEndian(_remaining);
        Advance(sizeof(ushort));
        return value;
    }

    /// <summary>
    /// Reads a big-endian unsigned 32-bit integer.
    /// </summary>
    /// <returns>The value.</returns>
    public uint ReadUInt32()
    {
        uint value = BinaryPrimitives.ReadUInt32BigEndian(_remaining);
        Advance(sizeof(uint));
        return value;
    }

    /// <summary>
    /// Reads a big-endian unsigned 64-bit integer.
    /// </summary>
    /// <returns>The value.</returns>
    public ulong ReadUInt64()
    {
        ulong value = BinaryPrimitives.ReadUInt64BigEndian(_remaining);
        Advance(sizeof(ulong));
        return value;
    }

    /// <summary>
    /// Reads a specified number of bytes.
    /// </summary>
    /// <param name="count">The number of bytes to read.</param>
    /// <returns>A span containing the bytes.</returns>
    public ReadOnlySpan<byte> ReadBytes(int count)
    {
        ReadOnlySpan<byte> bytes = _remaining[..count];
        Advance(count);
        return bytes;
    }

    /// <summary>
    /// Reads a TPM2B structure (2-byte length prefix followed by data).
    /// </summary>
    /// <returns>A span containing the data bytes without the length prefix.</returns>
    public ReadOnlySpan<byte> ReadTpm2b()
    {
        ushort length = ReadUInt16();
        return ReadBytes(length);
    }

    /// <summary>
    /// Reads a TPM2B structure and returns a blob reference (zero-copy).
    /// </summary>
    /// <returns>A blob containing offset and length into the original buffer.</returns>
    /// <remarks>
    /// The returned blob's offset points to the data bytes (after the length prefix).
    /// Use <see cref="TpmBlob.AsSpan"/> with the original buffer to access the bytes.
    /// </remarks>
    public TpmBlob ReadTpm2bBlob()
    {
        ushort length = ReadUInt16();
        int offset = _consumed;
        Advance(length);
        return new TpmBlob(offset, length);
    }

    /// <summary>
    /// Reads a fixed number of bytes and returns a blob reference (zero-copy).
    /// </summary>
    /// <param name="count">The number of bytes to read.</param>
    /// <returns>A blob containing offset and length into the original buffer.</returns>
    public TpmBlob ReadBlob(int count)
    {
        int offset = _consumed;
        Advance(count);
        return new TpmBlob(offset, count);
    }

    /// <summary>
    /// Peeks at bytes without consuming them.
    /// </summary>
    /// <param name="count">The number of bytes to peek.</param>
    /// <returns>A span containing the bytes.</returns>
    public ReadOnlySpan<byte> PeekBytes(int count) => _remaining[..count];

    /// <summary>
    /// Skips a specified number of bytes.
    /// </summary>
    /// <param name="count">The number of bytes to skip.</param>
    public void Skip(int count) => Advance(count);

    private void Advance(int count)
    {
        _remaining = _remaining[count..];
        _consumed += count;
    }
}