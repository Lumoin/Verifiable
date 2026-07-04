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
    /// <summary>The largest length the short form encodes directly in a single byte.</summary>
    private const int ShortFormMaxLength = 0x7F;

    /// <summary>The high bit of a long-form leading byte; its low bits give the count of length bytes that follow.</summary>
    private const int LongFormMarker = 0x80;

    /// <summary>The most long-form length bytes supported (a four-byte length spans a CSCA Master List).</summary>
    private const int MaxLongFormLengthBytes = 4;

    /// <summary>The number of bits in a byte — the shift accumulating successive big-endian tag or length bytes.</summary>
    private const int BitsPerByte = 8;

    /// <summary>The bit pattern in a tag's low five bits that signals the tag continues into a second byte.</summary>
    private const int MultiByteTagMarker = 0x1F;


    /// <summary>
    /// Initializes a new instance of the <see cref="ApduReader"/> struct.
    /// </summary>
    /// <param name="buffer">The buffer to read from.</param>
    public ApduReader(ReadOnlySpan<byte> buffer)
    {
        Unread = buffer;
        Consumed = 0;
    }


    /// <summary>Gets the bytes not yet consumed — the cursor's forward view over the buffer.</summary>
    private ReadOnlySpan<byte> Unread { get; set; }

    /// <summary>Gets the number of bytes consumed so far.</summary>
    public int Consumed { get; private set; }

    /// <summary>Gets the number of bytes remaining.</summary>
    public readonly int Remaining => Unread.Length;

    /// <summary>Gets a value indicating whether the buffer has been fully consumed.</summary>
    public readonly bool IsEmpty => Unread.IsEmpty;

    /// <summary>Gets the current position in the buffer.</summary>
    public readonly int Position => Consumed;


    /// <summary>
    /// Reads a single byte.
    /// </summary>
    /// <returns>The byte value.</returns>
    /// <exception cref="InvalidOperationException">The buffer is exhausted.</exception>
    public byte ReadByte()
    {
        EnsureAvailable(1);
        byte value = Unread[0];
        Advance(1);

        return value;
    }


    /// <summary>
    /// Reads a big-endian unsigned 16-bit integer.
    /// </summary>
    /// <returns>The value.</returns>
    /// <exception cref="InvalidOperationException">Fewer than two bytes remain.</exception>
    public ushort ReadUInt16()
    {
        EnsureAvailable(sizeof(ushort));
        ushort value = BinaryPrimitives.ReadUInt16BigEndian(Unread);
        Advance(sizeof(ushort));

        return value;
    }


    /// <summary>
    /// Reads a specified number of bytes.
    /// </summary>
    /// <param name="count">The number of bytes to read.</param>
    /// <returns>A span containing the bytes.</returns>
    /// <exception cref="InvalidOperationException">Fewer than <paramref name="count"/> bytes remain.</exception>
    public ReadOnlySpan<byte> ReadBytes(int count)
    {
        EnsureAvailable(count);
        ReadOnlySpan<byte> bytes = Unread[..count];
        Advance(count);

        return bytes;
    }


    /// <summary>
    /// Reads all remaining bytes.
    /// </summary>
    /// <returns>A span containing the remaining bytes.</returns>
    public ReadOnlySpan<byte> ReadRemainingBytes()
    {
        ReadOnlySpan<byte> bytes = Unread;
        Advance(Unread.Length);

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
        if((first & MultiByteTagMarker) == MultiByteTagMarker)
        {
            return (first << BitsPerByte) | ReadByte();
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
    /// four-byte length is rejected when it, added to the current position, would exceed <see cref="int.MaxValue"/>;
    /// a length that merely runs past the buffer is caught when the value is read, by the bounds-checked reads.
    /// </remarks>
    public int ReadTlvLength()
    {
        byte first = ReadByte();
        if(first <= ShortFormMaxLength)
        {
            return first;
        }

        int lengthBytes = first - LongFormMarker;
        if(lengthBytes is < 1 or > MaxLongFormLengthBytes)
        {
            throw new InvalidOperationException($"Unsupported BER-TLV length encoding: 0x{first:X2}.");
        }

        long length = 0;
        for(int index = 0; index < lengthBytes; index++)
        {
            length = (length << BitsPerByte) | ReadByte();
        }

        //Reject a length whose element end (Consumed + length) would exceed int range. Added to the cursor in a
        //container's `end` marker, such a length wraps negative and lets the loop skip the body — silently
        //accepting a lie — and the cast to int below must not overflow either. The value need not be buffered yet
        //(this decodes a length field in isolation), so a length that merely runs past the buffer is caught later,
        //when the value is read, where the bounds-checked reads reject it with this same exception type.
        if(length > int.MaxValue - Consumed)
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
    /// <exception cref="InvalidOperationException">Fewer than <paramref name="count"/> bytes remain.</exception>
    public readonly ReadOnlySpan<byte> PeekBytes(int count)
    {
        EnsureAvailable(count);

        return Unread[..count];
    }


    /// <summary>
    /// Skips a specified number of bytes.
    /// </summary>
    /// <param name="count">The number of bytes to skip.</param>
    /// <exception cref="InvalidOperationException">Fewer than <paramref name="count"/> bytes remain.</exception>
    public void Skip(int count)
    {
        EnsureAvailable(count);
        Advance(count);
    }


    /// <summary>
    /// Verifies that at least <paramref name="count"/> bytes remain, so a malformed or truncated structure is
    /// rejected with the reader's documented <see cref="InvalidOperationException"/> rather than escaping as an
    /// out-of-range exception from a slice or index. The unsigned comparison also rejects a negative count.
    /// </summary>
    /// <param name="count">The number of bytes the caller is about to read.</param>
    /// <exception cref="InvalidOperationException">Fewer than <paramref name="count"/> bytes remain, or the count is negative.</exception>
    private readonly void EnsureAvailable(int count)
    {
        if((uint)count > (uint)Unread.Length)
        {
            throw new InvalidOperationException($"The APDU buffer is truncated: {count} bytes were required but {Unread.Length} remain.");
        }
    }


    private void Advance(int count)
    {
        Unread = Unread[count..];
        Consumed += count;
    }
}
