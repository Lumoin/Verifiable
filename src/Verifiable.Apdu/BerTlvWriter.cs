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
/// up to two bytes and lengths up to <c>0xFFFF</c> are supported, which covers the eMRTD LDS data groups.
/// </para>
/// </remarks>
public ref struct BerTlvWriter
{
    private readonly Span<byte> buffer;
    private int position;


    /// <summary>
    /// Initialises a writer over <paramref name="buffer"/>, which must be at least the total encoded size.
    /// </summary>
    /// <param name="buffer">The destination buffer.</param>
    public BerTlvWriter(Span<byte> buffer)
    {
        this.buffer = buffer;
        position = 0;
    }


    /// <summary>Gets the number of bytes written so far.</summary>
    public readonly int Written => position;


    /// <summary>
    /// Writes a BER-TLV tag, as two bytes when it exceeds one byte.
    /// </summary>
    /// <param name="tag">The tag (1 or 2 bytes).</param>
    public void WriteTag(int tag)
    {
        if(tag > 0xFF)
        {
            buffer[position++] = (byte)(tag >> 8);
        }

        buffer[position++] = (byte)tag;
    }


    /// <summary>
    /// Writes a BER-TLV definite-length field (short form, or long form with <c>0x81</c> / <c>0x82</c>).
    /// </summary>
    /// <param name="length">The content length.</param>
    public void WriteLength(int length)
    {
        if(length <= 0x7F)
        {
            buffer[position++] = (byte)length;
        }
        else if(length <= 0xFF)
        {
            buffer[position++] = 0x81;
            buffer[position++] = (byte)length;
        }
        else
        {
            buffer[position++] = 0x82;
            buffer[position++] = (byte)(length >> 8);
            buffer[position++] = (byte)length;
        }
    }


    /// <summary>
    /// Writes raw value bytes at the current position.
    /// </summary>
    /// <param name="value">The bytes to write.</param>
    public void WriteValue(scoped ReadOnlySpan<byte> value)
    {
        value.CopyTo(buffer[position..]);
        position += value.Length;
    }


    /// <summary>
    /// Writes the ASCII bytes of <paramref name="value"/> at the current position.
    /// </summary>
    /// <param name="value">The ASCII string to write.</param>
    public void WriteAscii(string value)
    {
        position += Encoding.ASCII.GetBytes(value, buffer[position..]);
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
    public static int TagSize(int tag) => tag > 0xFF ? 2 : 1;


    /// <summary>
    /// The number of bytes a definite-length field occupies for <paramref name="contentLength"/>.
    /// </summary>
    /// <param name="contentLength">The content length.</param>
    /// <returns>The length-field size in bytes.</returns>
    public static int LengthFieldSize(int contentLength) =>
        contentLength <= 0x7F ? 1 : contentLength <= 0xFF ? 2 : 3;


    /// <summary>
    /// The total encoded size of an element: tag + length field + content.
    /// </summary>
    /// <param name="tag">The element tag.</param>
    /// <param name="contentLength">The content length.</param>
    /// <returns>The total encoded size in bytes.</returns>
    public static int ElementSize(int tag, int contentLength) =>
        TagSize(tag) + LengthFieldSize(contentLength) + contentLength;
}
