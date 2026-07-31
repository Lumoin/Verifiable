using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// One entry of an archive as the oracle read it out of the raw octets.
/// </summary>
/// <param name="Name">The entry name, decoded as UTF-8.</param>
/// <param name="Flags">The general purpose bit flag field.</param>
/// <param name="Method">The compression method field.</param>
/// <param name="DosTime">The MS-DOS time field.</param>
/// <param name="DosDate">The MS-DOS date field.</param>
/// <param name="Crc32">The CRC-32 field.</param>
/// <param name="CompressedByteLength">The compressed size field.</param>
/// <param name="UncompressedByteLength">The uncompressed size field.</param>
/// <param name="ExtraFieldByteLength">The extra field length field.</param>
/// <param name="HeaderOffset">Where the header this was read from begins.</param>
/// <param name="DataOffset">Where the entry's data begins, for a local file header; zero for a central directory record.</param>
internal sealed record OracleZipEntry(
    string Name,
    ushort Flags,
    ushort Method,
    ushort DosTime,
    ushort DosDate,
    uint Crc32,
    uint CompressedByteLength,
    uint UncompressedByteLength,
    ushort ExtraFieldByteLength,
    int HeaderOffset,
    int DataOffset);


/// <summary>
/// An archive as the oracle read it out of the raw octets.
/// </summary>
/// <param name="LocalHeaders">Every local file header, in the order they appear in the archive.</param>
/// <param name="CentralDirectory">Every central directory record, in the order the directory lists them.</param>
/// <param name="Comment">The ZIP archive comment, or <see langword="null"/> when there is none.</param>
/// <param name="CentralDirectoryOffset">Where the central directory begins.</param>
/// <param name="CentralDirectoryByteLength">How many octets the central directory occupies.</param>
/// <param name="DeclaredEntryCount">How many records the end-of-central-directory record says there are.</param>
/// <param name="ThisDiskNumber">The end record's "number of this disk" field.</param>
/// <param name="CentralDirectoryDiskNumber">The end record's "disk where the central directory starts" field.</param>
internal sealed record OracleZipArchive(
    IReadOnlyList<OracleZipEntry> LocalHeaders,
    IReadOnlyList<OracleZipEntry> CentralDirectory,
    string? Comment,
    int CentralDirectoryOffset,
    uint CentralDirectoryByteLength,
    ushort DeclaredEntryCount,
    ushort ThisDiskNumber,
    ushort CentralDirectoryDiskNumber);


/// <summary>
/// One entry an archive is built from by <see cref="AsicZipStructureOracle.BuildRawArchive"/>, with every field
/// a hostile producer controls left open.
/// </summary>
internal sealed record RawZipEntrySpec
{
    /// <summary>Gets the entry name to write, verbatim — including one that names a path outside the archive.</summary>
    public required string Name { get; init; }

    /// <summary>Gets the entry's octets before compression.</summary>
    public required byte[] Content { get; init; }

    /// <summary>Gets the compression method to write. 0 is stored, 8 is deflated; anything else is written as stated and the content stored.</summary>
    public ushort Method { get; init; }

    /// <summary>Gets the general purpose bit flag to write.</summary>
    public ushort Flags { get; init; }

    /// <summary>Gets the extra field to write in both headers.</summary>
    public byte[] ExtraField { get; init; } = [];

    /// <summary>Gets the uncompressed size to declare, when it is to be something other than the truth.</summary>
    public uint? DeclaredUncompressedByteLength { get; init; }

    /// <summary>Gets the CRC-32 to declare, when it is to be something other than the truth.</summary>
    public uint? DeclaredCrc32 { get; init; }
}


/// <summary>
/// An archive built by <see cref="AsicZipStructureOracle.BuildRawArchive"/>.
/// </summary>
internal sealed record RawZipArchiveSpec
{
    /// <summary>Gets the entries to write, in the order they are to appear.</summary>
    public required IReadOnlyList<RawZipEntrySpec> Entries { get; init; }

    /// <summary>
    /// Gets a local file header to write before every listed entry and to leave out of the central directory —
    /// the shape an archive takes when what sits at its first octet is not what its directory describes.
    /// </summary>
    public RawZipEntrySpec? UnlistedFirstEntry { get; init; }

    /// <summary>Gets the ZIP archive comment to write, or <see langword="null"/> for none.</summary>
    public string? Comment { get; init; }

    /// <summary>Gets the disk number to write in the end-of-central-directory record.</summary>
    public ushort DiskNumber { get; init; }

    /// <summary>Gets whether to write a ZIP64 end-of-central-directory locator before the end record.</summary>
    public bool IncludeZip64Locator { get; init; }
}


/// <summary>
/// An independent reader and writer of the ZIP structures an Associated Signature Container is made of, written
/// from the format's own field layout and from Annex A.1 of ETSI EN 319 162-1 V1.1.1.
/// </summary>
/// <remarks>
/// <para>
/// <strong>What makes it independent.</strong> It calls neither <see cref="ZipArchive"/> nor anything in
/// <c>Verifiable.Cryptography.Pki</c>: it locates the end-of-central-directory record itself, walks the central
/// directory itself, parses local file headers itself, and computes CRC-32 with a bitwise loop rather than with
/// a lookup table. A container the library writes is therefore checked by a second implementation of the same
/// format rather than by the one that produced it. <see cref="DeflateStream"/> is used to inflate a deflated
/// entry's octets, which is a codec rather than an archive reader — the rule the wave states is that the oracle
/// must not use the archive reader the production path uses, and it does not.
/// </para>
/// <para>
/// <strong>Why it also writes.</strong> The rules Annex A.1 states are rules about what a container must
/// <em>not</em> be, and a hostile container cannot be produced by a library that refuses to produce one. The
/// builder here writes whatever it is told to — a <c>mimetype</c> entry that is second, one that is compressed,
/// one that carries an extra field, a name that escapes the archive, an entry that lies about its own size —
/// so that every refusal the reader states has a real archive behind it.
/// </para>
/// </remarks>
internal static class AsicZipStructureOracle
{
    /// <summary>The ZIP local file header signature, <c>PK\3\4</c>.</summary>
    private static uint LocalFileHeaderSignature { get; } = 0x04034b50;

    /// <summary>The ZIP central directory file header signature, <c>PK\1\2</c>.</summary>
    private static uint CentralDirectoryHeaderSignature { get; } = 0x02014b50;

    /// <summary>The ZIP end-of-central-directory record signature, <c>PK\5\6</c>.</summary>
    private static uint EndOfCentralDirectorySignature { get; } = 0x06054b50;

    /// <summary>The ZIP64 end-of-central-directory locator signature, <c>PK\6\7</c>.</summary>
    private static uint Zip64LocatorSignature { get; } = 0x07064b50;


    /// <summary>
    /// Reads an archive's structures out of its octets.
    /// </summary>
    /// <param name="container">The archive's octets.</param>
    /// <returns>Every structure the archive carries.</returns>
    /// <exception cref="InvalidOperationException">When the octets do not carry the structures a ZIP archive is made of.</exception>
    public static OracleZipArchive Parse(ReadOnlySpan<byte> container)
    {
        int endRecordOffset = LocateEndRecord(container);
        ushort thisDisk = ReadUInt16(container, endRecordOffset + 4);
        ushort centralDirectoryDisk = ReadUInt16(container, endRecordOffset + 6);
        ushort declaredEntryCount = ReadUInt16(container, endRecordOffset + 10);
        uint centralDirectoryByteLength = ReadUInt32(container, endRecordOffset + 12);
        uint centralDirectoryOffset = ReadUInt32(container, endRecordOffset + 16);
        ushort commentByteLength = ReadUInt16(container, endRecordOffset + 20);
        string? comment = commentByteLength == 0
            ? null
            : Encoding.UTF8.GetString(container.Slice(endRecordOffset + 22, commentByteLength));

        var centralDirectory = new List<OracleZipEntry>(declaredEntryCount);
        int cursor = (int)centralDirectoryOffset;
        for(int i = 0; i < declaredEntryCount; ++i)
        {
            if(ReadUInt32(container, cursor) != CentralDirectoryHeaderSignature)
            {
                throw new InvalidOperationException($"The central directory record {i} does not begin with the central directory signature.");
            }

            ushort nameByteLength = ReadUInt16(container, cursor + 28);
            ushort extraByteLength = ReadUInt16(container, cursor + 30);
            ushort recordCommentByteLength = ReadUInt16(container, cursor + 32);
            centralDirectory.Add(new OracleZipEntry(
                Encoding.UTF8.GetString(container.Slice(cursor + 46, nameByteLength)),
                ReadUInt16(container, cursor + 8),
                ReadUInt16(container, cursor + 10),
                ReadUInt16(container, cursor + 12),
                ReadUInt16(container, cursor + 14),
                ReadUInt32(container, cursor + 16),
                ReadUInt32(container, cursor + 20),
                ReadUInt32(container, cursor + 24),
                extraByteLength,
                (int)ReadUInt32(container, cursor + 42),
                0));

            cursor += 46 + nameByteLength + extraByteLength + recordCommentByteLength;
        }

        var localHeaders = new List<OracleZipEntry>(centralDirectory.Count);
        for(int i = 0; i < centralDirectory.Count; ++i)
        {
            localHeaders.Add(ParseLocalHeader(container, centralDirectory[i].HeaderOffset));
        }

        return new OracleZipArchive(
            localHeaders,
            centralDirectory,
            comment,
            (int)centralDirectoryOffset,
            centralDirectoryByteLength,
            declaredEntryCount,
            thisDisk,
            centralDirectoryDisk);
    }


    /// <summary>
    /// Reads one local file header.
    /// </summary>
    /// <param name="container">The archive's octets.</param>
    /// <param name="headerOffset">Where the header begins.</param>
    /// <returns>The header's fields, with the offset its data begins at.</returns>
    /// <exception cref="InvalidOperationException">When the octets at the offset are not a local file header.</exception>
    public static OracleZipEntry ParseLocalHeader(ReadOnlySpan<byte> container, int headerOffset)
    {
        if(ReadUInt32(container, headerOffset) != LocalFileHeaderSignature)
        {
            throw new InvalidOperationException($"There is no local file header at offset {headerOffset}.");
        }

        ushort nameByteLength = ReadUInt16(container, headerOffset + 26);
        ushort extraByteLength = ReadUInt16(container, headerOffset + 28);

        return new OracleZipEntry(
            Encoding.UTF8.GetString(container.Slice(headerOffset + 30, nameByteLength)),
            ReadUInt16(container, headerOffset + 6),
            ReadUInt16(container, headerOffset + 8),
            ReadUInt16(container, headerOffset + 10),
            ReadUInt16(container, headerOffset + 12),
            ReadUInt32(container, headerOffset + 14),
            ReadUInt32(container, headerOffset + 18),
            ReadUInt32(container, headerOffset + 22),
            extraByteLength,
            headerOffset,
            headerOffset + 30 + nameByteLength + extraByteLength);
    }


    /// <summary>
    /// Runs the media type recognition the Annex A.1 NOTE of ETSI EN 319 162-1 V1.1.1 describes, step by step:
    /// the local file header signature at offset 0, the string <c>mimetype</c> at offset 30, the length in the
    /// four octets at offset 18, and the media type at offset 38.
    /// </summary>
    /// <param name="container">The archive's octets.</param>
    /// <returns>The media type, or <see langword="null"/> when the recognition does not apply.</returns>
    public static string? MediaTypeAtOffset38(ReadOnlySpan<byte> container)
    {
        if(container.Length < 38 || ReadUInt32(container, 0) != LocalFileHeaderSignature)
        {
            return null;
        }

        if(!container.Slice(30, 8).SequenceEqual("mimetype"u8))
        {
            return null;
        }

        uint length = ReadUInt32(container, 18);
        if(38 + length > (uint)container.Length)
        {
            return null;
        }

        return Encoding.UTF8.GetString(container.Slice(38, (int)length));
    }


    /// <summary>
    /// Reads an entry's octets out of the archive, inflating them when the entry is deflated.
    /// </summary>
    /// <param name="container">The archive's octets.</param>
    /// <param name="localHeader">The entry's local file header, as <see cref="ParseLocalHeader"/> read it.</param>
    /// <returns>The entry's octets before compression.</returns>
    public static byte[] ReadEntryContent(ReadOnlySpan<byte> container, OracleZipEntry localHeader)
    {
        byte[] stored = container.Slice(localHeader.DataOffset, (int)localHeader.CompressedByteLength).ToArray();
        if(localHeader.Method == 0)
        {
            return stored;
        }

        using var compressed = new MemoryStream(stored, writable: false);
        using var inflater = new DeflateStream(compressed, CompressionMode.Decompress);
        using var inflated = new MemoryStream();
        inflater.CopyTo(inflated);

        return inflated.ToArray();
    }


    /// <summary>
    /// Reads an entry's octets out of the archive, taking the compressed length from the central directory
    /// record when the local file header declares a trailing data descriptor.
    /// </summary>
    /// <param name="container">The archive's octets.</param>
    /// <param name="localHeader">The entry's local file header, as <see cref="ParseLocalHeader"/> read it.</param>
    /// <param name="directoryRecord">The same entry's central directory record.</param>
    /// <returns>The entry's octets before compression.</returns>
    /// <remarks>
    /// General purpose bit 3 makes the local file header's CRC-32 and both size fields meaningless by design —
    /// a producer streaming an entry writes zeros there and states the real values in a data descriptor that
    /// follows the compressed octets, and the central directory record carries them too. A reader taking the
    /// local header's zero would read no octets at all and conclude the entry is empty, which is not a refusal
    /// but a silently wrong answer. Archives this library writes never declare a data descriptor
    /// (<c>AsicZipAuthoring</c> writes neither the flag nor the structure), so this overload exists for the
    /// third-party archives of the reference-artifact leg, where it is common.
    /// </remarks>
    public static byte[] ReadEntryContent(ReadOnlySpan<byte> container, OracleZipEntry localHeader, OracleZipEntry directoryRecord)
    {
        ArgumentNullException.ThrowIfNull(localHeader);
        ArgumentNullException.ThrowIfNull(directoryRecord);

        const ushort DataDescriptorFlag = 0x0008;
        if((localHeader.Flags & DataDescriptorFlag) == 0)
        {
            return ReadEntryContent(container, localHeader);
        }

        return ReadEntryContent(
            container,
            localHeader with { CompressedByteLength = directoryRecord.CompressedByteLength, UncompressedByteLength = directoryRecord.UncompressedByteLength });
    }


    /// <summary>
    /// Computes the CRC-32 of IETF RFC 1952 clause 8 with a bitwise loop and no lookup table, so that the value
    /// a container records is checked by a different computation from the one that produced it.
    /// </summary>
    /// <param name="data">The octets to checksum.</param>
    /// <returns>The CRC-32 value.</returns>
    public static uint Crc32(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFFu;
        for(int i = 0; i < data.Length; ++i)
        {
            crc ^= data[i];
            for(int bit = 0; bit < 8; ++bit)
            {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
            }
        }

        return crc ^ 0xFFFFFFFFu;
    }


    /// <summary>
    /// Converts an MS-DOS date and time field pair into the instant they name.
    /// </summary>
    /// <param name="dosTime">The MS-DOS time field.</param>
    /// <param name="dosDate">The MS-DOS date field.</param>
    /// <returns>The instant, in UTC.</returns>
    public static DateTimeOffset InstantOf(ushort dosTime, ushort dosDate) =>
        new(
            1980 + ((dosDate >> 9) & 0x7F),
            (dosDate >> 5) & 0x0F,
            dosDate & 0x1F,
            (dosTime >> 11) & 0x1F,
            (dosTime >> 5) & 0x3F,
            (dosTime & 0x1F) * 2,
            TimeSpan.Zero);


    /// <summary>
    /// Writes an archive exactly as it is specified, including archives no conformant producer would write.
    /// </summary>
    /// <param name="spec">What to write.</param>
    /// <returns>The archive's octets.</returns>
    public static byte[] BuildRawArchive(RawZipArchiveSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);

        using var archive = new MemoryStream();
        var localHeaderOffsets = new List<int>(spec.Entries.Count);
        var storedContent = new List<byte[]>(spec.Entries.Count);

        if(spec.UnlistedFirstEntry is not null)
        {
            WriteLocalHeaderAndData(archive, spec.UnlistedFirstEntry);
        }

        for(int i = 0; i < spec.Entries.Count; ++i)
        {
            localHeaderOffsets.Add((int)archive.Position);
            storedContent.Add(WriteLocalHeaderAndData(archive, spec.Entries[i]));
        }

        int centralDirectoryOffset = (int)archive.Position;
        for(int i = 0; i < spec.Entries.Count; ++i)
        {
            RawZipEntrySpec entry = spec.Entries[i];
            byte[] nameOctets = Encoding.UTF8.GetBytes(entry.Name);

            WriteUInt32(archive, CentralDirectoryHeaderSignature);
            WriteUInt16(archive, 0x0014);
            WriteUInt16(archive, 20);
            WriteUInt16(archive, entry.Flags);
            WriteUInt16(archive, entry.Method);
            WriteUInt16(archive, 0);
            WriteUInt16(archive, 0x21);
            WriteUInt32(archive, entry.DeclaredCrc32 ?? Crc32(entry.Content));
            WriteUInt32(archive, (uint)storedContent[i].Length);
            WriteUInt32(archive, entry.DeclaredUncompressedByteLength ?? (uint)entry.Content.Length);
            WriteUInt16(archive, (ushort)nameOctets.Length);
            WriteUInt16(archive, (ushort)entry.ExtraField.Length);
            WriteUInt16(archive, 0);
            WriteUInt16(archive, 0);
            WriteUInt16(archive, 0);
            WriteUInt32(archive, 0);
            WriteUInt32(archive, (uint)localHeaderOffsets[i]);
            archive.Write(nameOctets);
            archive.Write(entry.ExtraField);
        }

        int centralDirectoryByteLength = (int)archive.Position - centralDirectoryOffset;

        if(spec.IncludeZip64Locator)
        {
            WriteUInt32(archive, Zip64LocatorSignature);
            WriteUInt32(archive, 0);
            WriteUInt32(archive, (uint)centralDirectoryOffset);
            WriteUInt32(archive, 0);
            WriteUInt32(archive, 1);
        }

        byte[] commentOctets = spec.Comment is null ? [] : Encoding.UTF8.GetBytes(spec.Comment);
        WriteUInt32(archive, EndOfCentralDirectorySignature);
        WriteUInt16(archive, spec.DiskNumber);
        WriteUInt16(archive, spec.DiskNumber);
        WriteUInt16(archive, (ushort)spec.Entries.Count);
        WriteUInt16(archive, (ushort)spec.Entries.Count);
        WriteUInt32(archive, (uint)centralDirectoryByteLength);
        WriteUInt32(archive, (uint)centralDirectoryOffset);
        WriteUInt16(archive, (ushort)commentOctets.Length);
        archive.Write(commentOctets);

        return archive.ToArray();
    }


    /// <summary>
    /// Writes one local file header and the entry's data.
    /// </summary>
    /// <param name="archive">The stream to write to.</param>
    /// <param name="entry">The entry to write.</param>
    /// <returns>The octets that were written as the entry's data, which the central directory has to repeat the length of.</returns>
    private static byte[] WriteLocalHeaderAndData(Stream archive, RawZipEntrySpec entry)
    {
        byte[] nameOctets = Encoding.UTF8.GetBytes(entry.Name);
        byte[] payload = entry.Method == 8 ? Deflate(entry.Content) : entry.Content;

        WriteUInt32(archive, LocalFileHeaderSignature);
        WriteUInt16(archive, 20);
        WriteUInt16(archive, entry.Flags);
        WriteUInt16(archive, entry.Method);
        WriteUInt16(archive, 0);
        WriteUInt16(archive, 0x21);
        WriteUInt32(archive, entry.DeclaredCrc32 ?? Crc32(entry.Content));
        WriteUInt32(archive, (uint)payload.Length);
        WriteUInt32(archive, entry.DeclaredUncompressedByteLength ?? (uint)entry.Content.Length);
        WriteUInt16(archive, (ushort)nameOctets.Length);
        WriteUInt16(archive, (ushort)entry.ExtraField.Length);
        archive.Write(nameOctets);
        archive.Write(entry.ExtraField);
        archive.Write(payload);

        return payload;
    }


    /// <summary>
    /// Finds the end-of-central-directory record by scanning back from the archive's end.
    /// </summary>
    /// <param name="container">The archive's octets.</param>
    /// <returns>Where the record begins.</returns>
    /// <exception cref="InvalidOperationException">When the octets carry no such record.</exception>
    private static int LocateEndRecord(ReadOnlySpan<byte> container)
    {
        for(int offset = container.Length - 22; offset >= 0; --offset)
        {
            if(ReadUInt32(container, offset) != EndOfCentralDirectorySignature)
            {
                continue;
            }

            ushort commentByteLength = ReadUInt16(container, offset + 20);
            if(offset + 22 + commentByteLength == container.Length)
            {
                return offset;
            }
        }

        throw new InvalidOperationException("The octets carry no end-of-central-directory record.");
    }


    /// <summary>
    /// Compresses octets with the deflate codec, for entries a specification says are deflated.
    /// </summary>
    /// <param name="content">The octets to compress.</param>
    /// <returns>The compressed octets.</returns>
    private static byte[] Deflate(byte[] content)
    {
        using var compressed = new MemoryStream();
        using(var deflater = new DeflateStream(compressed, CompressionLevel.Optimal, leaveOpen: true))
        {
            deflater.Write(content);
        }

        return compressed.ToArray();
    }


    /// <summary>Reads a little-endian sixteen-bit field.</summary>
    /// <param name="container">The octets to read from.</param>
    /// <param name="offset">Where the field begins.</param>
    /// <returns>The field's value.</returns>
    private static ushort ReadUInt16(ReadOnlySpan<byte> container, int offset) =>
        (ushort)(container[offset] | (container[offset + 1] << 8));


    /// <summary>Reads a little-endian thirty-two-bit field.</summary>
    /// <param name="container">The octets to read from.</param>
    /// <param name="offset">Where the field begins.</param>
    /// <returns>The field's value.</returns>
    private static uint ReadUInt32(ReadOnlySpan<byte> container, int offset) =>
        (uint)(container[offset] | (container[offset + 1] << 8) | (container[offset + 2] << 16) | (container[offset + 3] << 24));


    /// <summary>Writes a little-endian sixteen-bit field.</summary>
    /// <param name="archive">The stream to write to.</param>
    /// <param name="value">The value to write.</param>
    private static void WriteUInt16(Stream archive, ushort value) =>
        archive.Write([(byte)(value & 0xFF), (byte)((value >> 8) & 0xFF)]);


    /// <summary>Writes a little-endian thirty-two-bit field.</summary>
    /// <param name="archive">The stream to write to.</param>
    /// <param name="value">The value to write.</param>
    private static void WriteUInt32(Stream archive, uint value) =>
        archive.Write([(byte)(value & 0xFF), (byte)((value >> 8) & 0xFF), (byte)((value >> 16) & 0xFF), (byte)((value >> 24) & 0xFF)]);
}
