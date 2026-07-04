using System;
using System.Text;

namespace Verifiable.Apdu;

/// <summary>
/// A position-tracking writer for BER-TLV structures — the encoding counterpart of
/// <see cref="ApduReader"/>'s tag and length reading. It writes tags (one or two bytes), definite-length
/// fields (short or long form), and values into a caller-provided buffer.
/// </summary>
/// <remarks>
/// <para>
/// Constructed (nested) elements are written header-first, so a caller computes a content length up front
/// with <see cref="ElementSize"/> / <see cref="LengthFieldSize"/> / <see cref="TagSize"/>, writes the
/// outer header with <see cref="WriteHeader"/>, then writes the inner elements into the same buffer. Tags
/// up to two bytes and definite lengths through the four-byte long form are supported, spanning the eMRTD
/// LDS data groups and the larger structures (high-resolution biometrics, a CSCA Master List) that exceed 64 KiB.
/// </para>
/// </remarks>
public ref struct BerTlvWriter
{
    /// <summary>The largest content length the short form encodes directly in a single byte.</summary>
    private const int ShortFormMaxLength = 0x7F;

    /// <summary>The high bit set on a long-form leading byte, ORed with the count of length bytes that follow.</summary>
    private const int LongFormMarker = 0x80;

    /// <summary>The number of bits in a byte — the shift between successive big-endian tag or length bytes.</summary>
    private const int BitsPerByte = 8;

    /// <summary>The largest tag value that encodes in a single byte; a larger tag takes two bytes.</summary>
    private const int MaxSingleByteTag = 0xFF;

    /// <summary>The largest content length a one-byte long-form length holds.</summary>
    private const int OneByteMaxLength = 0xFF;

    /// <summary>The largest content length a two-byte long-form length holds.</summary>
    private const int TwoByteMaxLength = 0xFFFF;

    /// <summary>The largest content length a three-byte long-form length holds.</summary>
    private const int ThreeByteMaxLength = 0xFFFFFF;


    /// <summary>
    /// Initialises a writer over <paramref name="buffer"/>, which must be at least the total encoded size.
    /// </summary>
    /// <param name="buffer">The destination buffer.</param>
    public BerTlvWriter(Span<byte> buffer)
    {
        Buffer = buffer;
        Position = 0;
    }


    /// <summary>Gets the destination buffer the elements are written into.</summary>
    private Span<byte> Buffer { get; }

    /// <summary>Gets or sets the write cursor: the number of bytes written so far.</summary>
    private int Position { get; set; }

    /// <summary>Gets the number of bytes written so far.</summary>
    public readonly int Written => Position;


    /// <summary>
    /// Writes a BER-TLV tag, as two bytes when it exceeds one byte.
    /// </summary>
    /// <param name="tag">The tag (1 or 2 bytes).</param>
    public void WriteTag(int tag)
    {
        if(tag > MaxSingleByteTag)
        {
            Buffer[Position++] = (byte)(tag >> BitsPerByte);
        }

        Buffer[Position++] = (byte)tag;
    }


    /// <summary>
    /// Writes a BER-TLV definite-length field (short form, or long form with <c>0x81</c> through <c>0x84</c>),
    /// spanning the same one-to-four length-byte range <see cref="ApduReader.ReadTlvLength"/> reads.
    /// </summary>
    /// <param name="length">The content length.</param>
    /// <remarks>
    /// The three- and four-byte long forms matter for content that exceeds 64 KiB (a high-resolution biometric
    /// image or a CSCA Master List): a writer that stopped at the two-byte form would silently emit the low 16
    /// bits of the length while writing the full content, producing a corrupt, self-desynchronising structure.
    /// </remarks>
    public void WriteLength(int length)
    {
        if(length <= ShortFormMaxLength)
        {
            Buffer[Position++] = (byte)length;

            return;
        }

        int lengthBytes = LongFormByteCount(length);
        Buffer[Position++] = (byte)(LongFormMarker | lengthBytes);
        for(int shift = (lengthBytes - 1) * BitsPerByte; shift >= 0; shift -= BitsPerByte)
        {
            Buffer[Position++] = (byte)(length >> shift);
        }
    }


    /// <summary>
    /// Writes raw value bytes at the current position.
    /// </summary>
    /// <param name="value">The bytes to write.</param>
    public void WriteValue(scoped ReadOnlySpan<byte> value)
    {
        value.CopyTo(Buffer[Position..]);
        Position += value.Length;
    }


    /// <summary>
    /// Writes the ASCII bytes of <paramref name="value"/> at the current position.
    /// </summary>
    /// <param name="value">The ASCII string to write.</param>
    public void WriteAscii(string value)
    {
        Position += Encoding.ASCII.GetBytes(value, Buffer[Position..]);
    }


    /// <summary>
    /// Writes the header of a constructed element: its tag and content length.
    /// </summary>
    /// <param name="tag">The element tag.</param>
    /// <param name="contentLength">The length of the content that follows.</param>
    public void WriteHeader(int tag, int contentLength)
    {
        WriteTag(tag);
        WriteLength(contentLength);
    }


    /// <summary>
    /// Writes a complete primitive element: tag, length, and value.
    /// </summary>
    /// <param name="tag">The element tag.</param>
    /// <param name="value">The element value.</param>
    public void WriteElement(int tag, scoped ReadOnlySpan<byte> value)
    {
        WriteHeader(tag, value.Length);
        WriteValue(value);
    }


    /// <summary>
    /// The number of bytes a tag occupies (1 or 2).
    /// </summary>
    /// <param name="tag">The tag.</param>
    /// <returns>The tag size in bytes.</returns>
    public static int TagSize(int tag) => tag > MaxSingleByteTag ? 2 : 1;


    /// <summary>
    /// The number of bytes a definite-length field occupies for <paramref name="contentLength"/>, matching the
    /// one-to-four long-form range <see cref="WriteLength"/> emits (the leading byte plus the length bytes).
    /// </summary>
    /// <param name="contentLength">The content length.</param>
    /// <returns>The length-field size in bytes.</returns>
    public static int LengthFieldSize(int contentLength) =>
        contentLength <= ShortFormMaxLength ? 1 : 1 + LongFormByteCount(contentLength);


    /// <summary>
    /// The number of long-form length bytes needed to hold <paramref name="length"/>, one through four.
    /// </summary>
    /// <param name="length">A content length greater than the short-form maximum.</param>
    /// <returns>The number of big-endian length bytes.</returns>
    private static int LongFormByteCount(int length) => length switch
    {
        <= OneByteMaxLength => 1,
        <= TwoByteMaxLength => 2,
        <= ThreeByteMaxLength => 3,
        _ => 4
    };


    /// <summary>
    /// The total encoded size of an element: tag + length field + content.
    /// </summary>
    /// <param name="tag">The element tag.</param>
    /// <param name="contentLength">The content length.</param>
    /// <returns>The total encoded size in bytes.</returns>
    public static int ElementSize(int tag, int contentLength) =>
        TagSize(tag) + LengthFieldSize(contentLength) + contentLength;
}
