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
    /// Reads a BER-TLV tag of one or two bytes — the read counterpart of <see cref="BerTlvWriter.WriteTag"/>.
    /// </summary>
    /// <returns>The tag as an integer; a two-byte tag is returned as <c>(first &lt;&lt; 8) | second</c>.</returns>
    /// <remarks>
    /// A tag whose low five bits are all set (<c>0x1F</c>) continues into a second byte. The eMRTD
    /// structures this reader serves use tags of at most two bytes (e.g. the card-verifiable certificate
    /// tags <c>0x7F4E</c>, <c>0x7F49</c>, <c>0x5F37</c>), matching <see cref="BerTlvWriter"/>.
    /// </remarks>
    public int ReadTag()
    {
        byte first = ReadByte();
        if((first & 0x1F) == 0x1F)
        {
            return (first << 8) | ReadByte();
        }

        return first;
    }

    /// <summary>
    /// Reads a BER-TLV definite length field (1 to 5 bytes).
    /// </summary>
    /// <returns>The decoded length.</returns>
    /// <remarks>
    /// Short form: a single byte 0x00–0x7F. Long form: 0x8N introduces N big-endian length bytes — 0x81
    /// (one byte), 0x82 (two), 0x83 (three), 0x84 (four). The three- and four-byte forms appear in large DER
    /// structures such as an ICAO CSCA Master List, whose SET OF Certificate routinely exceeds 64 KiB. A
    /// four-byte length is rejected when it would exceed <see cref="int.MaxValue"/>.
    /// </remarks>
    public int ReadTlvLength()
    {
        byte first = ReadByte();

        if(first <= 0x7F)
        {
            return first;
        }

        int byteCount = first - 0x80;
        if(byteCount is < 1 or > 4)
        {
            throw new InvalidOperationException($"Unsupported BER-TLV length encoding: 0x{first:X2}.");
        }

        long length = 0;
        for(int index = 0; index < byteCount; index++)
        {
            length = (length << 8) | ReadByte();
        }

        if(length > int.MaxValue)
        {
            throw new InvalidOperationException("The BER-TLV length exceeds the supported maximum.");
        }

        return (int)length;
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
