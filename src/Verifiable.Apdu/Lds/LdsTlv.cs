using System;
using System.Text;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// Shared BER-TLV helpers for the LDS data-group parsers and writers: reading multi-byte tags and writing
/// optional ASCII character-string elements, so the per-data-group code stays a thin field list.
/// </summary>
internal static class LdsTlv
{
    /// <summary>
    /// Reads a BER-TLV tag, which is two bytes when the low five bits of the first byte are all set.
    /// </summary>
    /// <param name="reader">The reader, advanced past the tag.</param>
    /// <returns>The tag value (one or two bytes packed big-endian).</returns>
    public static int ReadTag(ref ApduReader reader)
    {
        int tag = reader.ReadByte();
        if((tag & 0x1F) == 0x1F)
        {
            tag = (tag << 8) | reader.ReadByte();
        }

        return tag;
    }


    /// <summary>
    /// The encoded size of an optional ASCII character-string element, or zero when the value is absent.
    /// </summary>
    /// <param name="tag">The element tag.</param>
    /// <param name="value">The character-string value, or <see langword="null"/> when the element is omitted.</param>
    /// <returns>The element's encoded size, or zero.</returns>
    public static int OptionalElementSize(int tag, string? value) =>
        value is null ? 0 : BerTlvWriter.ElementSize(tag, Encoding.ASCII.GetByteCount(value));


    /// <summary>
    /// Writes an optional ASCII character-string element (tag, length, then the ASCII bytes) into
    /// <paramref name="writer"/>; a <see langword="null"/> value writes nothing.
    /// </summary>
    /// <param name="writer">The writer, advanced past the element when one is written.</param>
    /// <param name="tag">The element tag.</param>
    /// <param name="value">The character-string value, or <see langword="null"/> to omit the element.</param>
    public static void WriteOptionalAscii(ref BerTlvWriter writer, int tag, string? value)
    {
        if(value is not null)
        {
            writer.WriteHeader(tag, Encoding.ASCII.GetByteCount(value));
            writer.WriteAscii(value);
        }
    }
}
