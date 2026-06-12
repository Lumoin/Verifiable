using System;
using System.Buffers.Binary;

namespace Verifiable.Apdu;

/// <summary>
/// A position-tracking reader for APDU byte buffers.
/// </summary>
/// <remarks>
/// <para>
/// Used by response parsers to read typed values from response data.
/// Multi-byte fields are big-endian per ISO/IEC 7816.
/// </para>
/// </remarks>
public ref struct ApduReader
{
    private readonly ReadOnlySpan<byte> original;
    private ReadOnlySpan<byte> remaining;
    private int consumed;

    /// <summary>
    /// Initializes a new instance of the <see cref="ApduReader"/> struct.
    /// </summary>
    /// <param name="buffer">The buffer to read from.</param>
    public ApduReader(ReadOnlySpan<byte> buffer)
    {
        original = buffer;
        remaining = buffer;
        consumed = 0;
    }

    /// <summary>
    /// Gets the number of bytes consumed so far.
    /// </summary>
    public int Consumed => consumed;

    /// <summary>
    /// Gets the number of bytes remaining.
    /// </summary>
    public int Remaining => remaining.Length;

    /// <summary>
    /// Gets a value indicating whether the buffer has been fully consumed.
    /// </summary>
    public bool IsEmpty => remaining.IsEmpty;

    /// <summary>
    /// Gets the current position in the original buffer.
    /// </summary>
    public int Position => consumed;

    /// <summary>
    /// Reads a single byte.
    /// </summary>
    /// <returns>The byte value.</returns>
    public byte ReadByte()
    {
        byte value = remaining[0];
        Advance(1);
        return value;
    }

    /// <summary>
    /// Reads a big-endian unsigned 16-bit integer.
    /// </summary>
    /// <returns>The value.</returns>
    public ushort ReadUInt16()
    {
        ushort value = BinaryPrimitives.ReadUInt16BigEndian(remaining);
        Advance(sizeof(ushort));
        return value;
    }

    /// <summary>
    /// Reads a specified number of bytes.
    /// </summary>
    /// <param name="count">The number of bytes to read.</param>
    /// <returns>A span containing the bytes.</returns>
    public ReadOnlySpan<byte> ReadBytes(int count)
    {
        ReadOnlySpan<byte> bytes = remaining[..count];
        Advance(count);
        return bytes;
    }

    /// <summary>
    /// Reads all remaining bytes.
    /// </summary>
    /// <returns>A span containing the remaining bytes.</returns>
    public ReadOnlySpan<byte> ReadRemainingBytes()
    {
        ReadOnlySpan<byte> bytes = remaining;
        Advance(remaining.Length);
        return bytes;
    }

    /// <summary>
    /// Reads a BER-TLV length field (1 or 3 bytes).
    /// </summary>
    /// <returns>The decoded length.</returns>
    /// <remarks>
    /// Short form: single byte 0x00–0x7F.
    /// Long form (2-byte payload): 0x81 followed by one length byte.
    /// Long form (3-byte payload): 0x82 followed by two big-endian length bytes.
    /// </remarks>
    public int ReadTlvLength()
    {
        byte first = ReadByte();

        if(first <= 0x7F)
        {
            return first;
        }

        if(first == 0x81)
        {
            return ReadByte();
        }

        if(first == 0x82)
        {
            return ReadUInt16();
        }

        throw new InvalidOperationException(
            $"Unsupported BER-TLV length encoding: 0x{first:X2}.");
    }

    /// <summary>
    /// Peeks at bytes without consuming them.
    /// </summary>
    /// <param name="count">The number of bytes to peek.</param>
    /// <returns>A span containing the bytes.</returns>
    public ReadOnlySpan<byte> PeekBytes(int count) => remaining[..count];

    /// <summary>
    /// Skips a specified number of bytes.
    /// </summary>
    /// <param name="count">The number of bytes to skip.</param>
    public void Skip(int count) => Advance(count);

    private void Advance(int count)
    {
        remaining = remaining[count..];
        consumed += count;
    }
}
