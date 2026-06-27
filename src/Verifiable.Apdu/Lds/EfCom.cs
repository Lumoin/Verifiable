using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// The parsed EF.COM (Common Data Elements) file of an ICAO Doc 9303 eMRTD: the LDS and Unicode
/// version strings and the list of data-group tags present on the chip.
/// </summary>
/// <remarks>
/// <para>
/// EF.COM (file identifier <c>0x011E</c>, BER-TLV tag <c>0x60</c>) is the inventory the inspection
/// system reads first: <c>5F01</c> carries the four-character LDS version, <c>5F36</c> the
/// six-character Unicode version, and <c>5C</c> the tag list — one byte per data group present
/// (<c>0x61</c> for DG1, <c>0x75</c> for DG2, and so on). EF.COM is a presence list only; the
/// authoritative, signed list of data groups and their hashes is in EF.SOD.
/// </para>
/// </remarks>
public sealed class EfCom
{
    /// <summary>The eMRTD elementary file identifier of EF.COM.</summary>
    public const ushort FileIdentifier = 0x011E;

    /// <summary>BER-TLV tag for EF.COM.</summary>
    private const int EfComTag = 0x60;

    /// <summary>BER-TLV tag for the LDS version object (DO'5F01').</summary>
    private const int LdsVersionTag = 0x5F01;

    /// <summary>BER-TLV tag for the Unicode version object (DO'5F36').</summary>
    private const int UnicodeVersionTag = 0x5F36;

    /// <summary>BER-TLV tag for the data-group tag-list object (DO'5C').</summary>
    private const int TagListTag = 0x5C;


    /// <summary>Gets the four-character LDS version string (for example <c>"0107"</c> for LDS 1.7).</summary>
    public string LdsVersion { get; }

    /// <summary>Gets the six-character Unicode version string (for example <c>"040000"</c> for Unicode 4.0.0).</summary>
    public string UnicodeVersion { get; }

    /// <summary>Gets the data-group tags present on the chip, in the order EF.COM lists them.</summary>
    public IReadOnlyList<byte> DataGroupTags { get; }


    private EfCom(string ldsVersion, string unicodeVersion, byte[] dataGroupTags)
    {
        LdsVersion = ldsVersion;
        UnicodeVersion = unicodeVersion;
        DataGroupTags = dataGroupTags;
    }


    /// <summary>
    /// Parses an EF.COM file.
    /// </summary>
    /// <param name="efCom">The EF.COM file bytes (the BER-TLV structure beginning with tag <c>0x60</c>).</param>
    /// <returns>The parsed <see cref="EfCom"/>.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the structure is not a well-formed EF.COM.</exception>
    public static EfCom Parse(ReadOnlySpan<byte> efCom)
    {
        var reader = new ApduReader(efCom);
        if(ReadTag(ref reader) != EfComTag)
        {
            throw new InvalidOperationException("The data is not an EF.COM file (expected BER-TLV tag 0x60).");
        }

        int contentLength = reader.ReadTlvLength();
        var content = new ApduReader(reader.ReadBytes(contentLength));

        string? ldsVersion = null;
        string? unicodeVersion = null;
        byte[]? dataGroupTags = null;

        while(!content.IsEmpty)
        {
            int tag = ReadTag(ref content);
            int length = content.ReadTlvLength();
            ReadOnlySpan<byte> value = content.ReadBytes(length);

            switch(tag)
            {
                case LdsVersionTag:
                    ldsVersion = System.Text.Encoding.ASCII.GetString(value);
                    break;
                case UnicodeVersionTag:
                    unicodeVersion = System.Text.Encoding.ASCII.GetString(value);
                    break;
                case TagListTag:
                    dataGroupTags = value.ToArray();
                    break;
                default:
                    //Unknown elements are skipped so a newer LDS minor version still parses.
                    break;
            }
        }

        if(ldsVersion is null || unicodeVersion is null || dataGroupTags is null)
        {
            throw new InvalidOperationException("EF.COM is missing the LDS version, the Unicode version, or the tag list.");
        }

        return new EfCom(ldsVersion, unicodeVersion, dataGroupTags);
    }


    /// <summary>
    /// Writes an EF.COM file from its parts — the inverse of <see cref="Parse"/>.
    /// </summary>
    /// <param name="ldsVersion">The four-character LDS version string (for example <c>"0107"</c>).</param>
    /// <param name="unicodeVersion">The six-character Unicode version string (for example <c>"040000"</c>).</param>
    /// <param name="dataGroupTags">The data-group presence tags, one byte each (for example <c>0x61</c> for DG1).</param>
    /// <param name="pool">The memory pool for the file carrier.</param>
    /// <returns>The EF.COM <see cref="ElementaryFile"/>. The caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned ElementaryFile, which the caller disposes; the catch disposes it on failure.")]
    public static ElementaryFile Write(string ldsVersion, string unicodeVersion, ReadOnlySpan<byte> dataGroupTags, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(ldsVersion);
        ArgumentNullException.ThrowIfNull(unicodeVersion);
        ArgumentNullException.ThrowIfNull(pool);

        int contentLength =
            BerTlvWriter.ElementSize(LdsVersionTag, ldsVersion.Length)
            + BerTlvWriter.ElementSize(UnicodeVersionTag, unicodeVersion.Length)
            + BerTlvWriter.ElementSize(TagListTag, dataGroupTags.Length);
        int total = BerTlvWriter.ElementSize(EfComTag, contentLength);

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            var writer = new BerTlvWriter(owner.Memory.Span[..total]);
            writer.WriteHeader(EfComTag, contentLength);
            writer.WriteHeader(LdsVersionTag, ldsVersion.Length);
            writer.WriteAscii(ldsVersion);
            writer.WriteHeader(UnicodeVersionTag, unicodeVersion.Length);
            writer.WriteAscii(unicodeVersion);
            writer.WriteElement(TagListTag, dataGroupTags);

            return new ElementaryFile(owner, FileIdentifier);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Reads a BER-TLV tag, which is two bytes when the low five bits of the first byte are all set.
    /// </summary>
    private static int ReadTag(ref ApduReader reader)
    {
        int tag = reader.ReadByte();
        if((tag & 0x1F) == 0x1F)
        {
            tag = (tag << 8) | reader.ReadByte();
        }

        return tag;
    }
}
