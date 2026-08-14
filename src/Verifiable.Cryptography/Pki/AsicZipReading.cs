using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// What a reader concluded about a container it did not make.
/// </summary>
/// <remarks>
/// <para>
/// A container arrives from whoever produced it, so every way it can be wrong is a value here rather than an
/// exception: nothing an attacker-supplied archive states escapes <see cref="AsicZipReading.Read"/> as a throw.
/// The split follows the one <see cref="EvidenceRecordVerificationStatus"/> makes against
/// <see cref="EvidenceRecordCreationFailureKind"/> — generator faults are exceptions, reader conclusions are
/// statuses.
/// </para>
/// <para>
/// <see cref="NotRead"/> occupies zero so a default-initialised status never reads as a container that was read.
/// </para>
/// </remarks>
public enum AsicZipReadStatus
{
    /// <summary>No read has been attempted. The value of an unset field, by design.</summary>
    NotRead = 0,

    /// <summary>The container was read; every entry is available.</summary>
    Read = 1,

    /// <summary>
    /// The octets do not begin with a ZIP local file header, or carry no end-of-central-directory record.
    /// Annex A.1 item 4 of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
    /// ETSI EN 319 162-1 V1.1.1</see> states that "the first 4 octets of the ASiC container file shall have the
    /// hex values: "50 4B 03 04"".
    /// </summary>
    NotZipArchive = 2,

    /// <summary>A structure of the archive is truncated, or two structures state different things about the same entry.</summary>
    ArchiveMalformed = 3,

    /// <summary>
    /// The archive declares a disk other than the first, which clause 4.2 item 2 a forbids: "ASiC containers
    /// shall not use the multiple volumes split feature."
    /// </summary>
    SplitArchiveDeclared = 4,

    /// <summary>
    /// The archive needs the ZIP64 extensions, which this library neither writes nor reads. A container of the
    /// sizes <see cref="AsicZipReadLimits"/> admits never needs them, so an archive that does is out of scope
    /// rather than malformed.
    /// </summary>
    Zip64Required = 5,

    /// <summary>
    /// An entry is encrypted. Clause 5.3.1's Table 1 item a requires baseline containers to comply with
    /// ISO/IEC 21320-1, whose stated purpose the NOTE under that table gives as "excluding encryption"; Annex
    /// A.1 item 6 forbids it outright for the <c>mimetype</c> entry.
    /// </summary>
    EntryEncrypted = 6,

    /// <summary>
    /// An entry states a compression method other than 0 (stored) or 8 (deflated), which clause 4.2 item 2 c
    /// restricts a container to.
    /// </summary>
    UnsupportedCompressionMethod = 7,

    /// <summary>The archive holds more entries than the caller's limits admit.</summary>
    EntryCountExceeded = 8,

    /// <summary>An entry name was refused; <see cref="AsicZipReadResult.RejectedEntryNameStatus"/> names why.</summary>
    EntryNameRejected = 9,

    /// <summary>Two entries carry the same name, so the archive names one file object twice and a reference to it resolves to neither.</summary>
    DuplicateEntryName = 10,

    /// <summary>An entry, or the archive as a whole, declares more uncompressed octets than the caller's limits admit.</summary>
    UncompressedSizeExceeded = 11,

    /// <summary>An entry expands by more than the caller's limits admit — the archive is a decompression bomb.</summary>
    CompressionRatioExceeded = 12,

    /// <summary>The ZIP archive comment is longer than the caller's limits admit.</summary>
    CommentTooLong = 13,

    /// <summary>
    /// The archive carries a <c>mimetype</c> entry that is not the first file in it, which Annex A.1 item 1
    /// requires: ""mimetype" shall be the first file in the ASiC container."
    /// </summary>
    MimetypeNotFirstEntry = 14,

    /// <summary>
    /// The <c>mimetype</c> entry is compressed, which Annex A.1 item 3 forbids: ""mimetype" shall not be
    /// compressed (i.e. compression method in its ZIP header at offset 8 shall be set to zero)."
    /// </summary>
    MimetypeCompressed = 15,

    /// <summary>
    /// The <c>mimetype</c> entry carries an extra field, which Annex A.1 item 2 forbids: ""mimetype" shall not
    /// contain "Extra fields" in its ZIP header (i.e. extra field length at offset 28 shall be set to zero)."
    /// This is the rule that puts the media type at <see cref="AsicWellKnown.MediaTypeOffset"/>, so an archive
    /// breaking it is one where the Annex A.1 NOTE's recognition feature reads something else.
    /// </summary>
    MimetypeCarriesExtraField = 16,

    /// <summary>
    /// The <c>mimetype</c> entry states its sizes in a trailing data descriptor rather than in its local file
    /// header, so the four octets at <see cref="AsicWellKnown.MediaTypeLengthOffset"/> the Annex A.1 NOTE reads
    /// the media type's length from state zero.
    /// </summary>
    MimetypeUsesDataDescriptor = 17,

    /// <summary>
    /// The <c>mimetype</c> entry's declared length runs past the container, its two size fields disagree, or its
    /// content is not a media type.
    /// </summary>
    MimetypeEntryMalformed = 18,

    /// <summary>An entry's octets do not match the CRC-32 its headers record, so the archive is corrupt.</summary>
    EntryChecksumMismatch = 19,

    /// <summary>The container's own octets are more than the caller's limits admit, before anything in it was parsed.</summary>
    ContainerTooLarge = 20
}


/// <summary>
/// The bounds a container is read within.
/// </summary>
/// <remarks>
/// <para>
/// Every bound here exists because the archive states its own sizes, and a reader that believes them can be made
/// to allocate whatever the producer chose. The defaults are far above any container of signed data objects,
/// manifests, signatures, time assertions and Evidence Records, and far below what makes a container a denial of
/// service; a caller archiving something unusual raises the one bound it needs rather than all of them.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record AsicZipReadLimits
{
    /// <summary>Gets the bounds this library reads a container within when a caller states none of its own.</summary>
    public static AsicZipReadLimits Conformant { get; } = new();


    /// <summary>Gets the largest number of octets the container itself may occupy. 256 MiB by default.</summary>
    public int MaximumContainerByteLength { get; init; } = 256 * 1024 * 1024;

    /// <summary>Gets the largest number of entries the archive may declare. 4096 by default.</summary>
    public int MaximumEntryCount { get; init; } = 4096;

    /// <summary>Gets the largest number of octets one entry may hold once decompressed. 64 MiB by default.</summary>
    public long MaximumEntryUncompressedByteLength { get; init; } = 64L * 1024 * 1024;

    /// <summary>Gets the largest number of octets every entry together may hold once decompressed. 256 MiB by default.</summary>
    public long MaximumTotalUncompressedByteLength { get; init; } = 256L * 1024 * 1024;

    /// <summary>Gets the largest number of UTF-8 octets an entry name may occupy. 512 by default.</summary>
    public int MaximumEntryNameByteLength { get; init; } = 512;

    /// <summary>Gets the largest number of octets the ZIP archive comment may occupy. 4096 by default.</summary>
    public int MaximumArchiveCommentByteLength { get; init; } = 4096;

    /// <summary>
    /// Gets how many times larger than its stored form an entry may become. 250 by default, against the
    /// roughly 1032:1 a deflate stream can reach at its theoretical maximum — a bound no manifest, signature or
    /// Evidence Record approaches, and one a bomb built out of a single repeated octet cannot stay under.
    /// </summary>
    public int MaximumEntryExpansionRatio { get; init; } = 250;

    /// <summary>
    /// Gets the size below which the expansion ratio is not checked, 4096 octets by default. A small entry's
    /// ratio says nothing — a two-octet stored form legitimately expands to a few hundred octets of a highly
    /// regular manifest — and no entry this small is a bomb whatever its ratio.
    /// </summary>
    public long ExpansionRatioMinimumUncompressedByteLength { get; init; } = 4096;


    /// <summary>A short debugger string showing the two bounds that matter most.</summary>
    private string DebuggerDisplay =>
        $"AsicZipReadLimits({MaximumEntryCount} entries, {MaximumTotalUncompressedByteLength} octets, ratio {MaximumEntryExpansionRatio})";
}


/// <summary>
/// One entry of a container that was read: its name, its decompressed octets, and what its headers recorded.
/// </summary>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class AsicZipEntry: IDisposable
{
    /// <summary>Gets the entry name as the container carries it: root-relative and <c>/</c>-separated (Annex A.6).</summary>
    public required string Name { get; init; }

    /// <summary>
    /// Gets the entry's decompressed octets, tagged <see cref="AsicTags.ContainerEntry"/>. Owned by this
    /// instance, which the owning <see cref="AsicZipContainer"/> disposes. A folder entry carries no octets.
    /// </summary>
    public required PooledMemory Content { get; init; }

    /// <summary>Gets how the container stored the octets.</summary>
    public required AsicZipCompressionMethod CompressionMethod { get; init; }

    /// <summary>
    /// Gets the instant the entry's headers record, in UTC, or <see langword="null"/> when the MS-DOS date and
    /// time fields do not name a valid instant — which producers that leave them zero do. The value is
    /// informational: no requirement of ETSI EN 319 162-1 or -2 rests on it, and every integrity statement about
    /// an entry is made by a manifest digest or a signature over the entry's octets.
    /// </summary>
    public required DateTimeOffset? LastModified { get; init; }

    /// <summary>Gets how many octets the entry occupied in the container, after compression.</summary>
    public required long CompressedByteLength { get; init; }

    /// <summary>
    /// Gets whether the entry names a folder rather than a file object — a name ending in the ZIP separator,
    /// which ZIP writes to record an empty folder and which carries no octets.
    /// </summary>
    public required bool IsFolder { get; init; }


    /// <summary>Gets whether the entry lives in the <c>META-INF</c> folder, where clauses 4.3.3.2 and 4.4.4.2 place every piece of container metadata.</summary>
    public bool IsMetaInf => AsicWellKnown.IsMetaInfEntryName(Name);


    /// <inheritdoc/>
    public void Dispose() => Content.Dispose();


    /// <summary>A short debugger string showing the entry's name, size and method.</summary>
    private string DebuggerDisplay => $"AsicZipEntry({Name}, {Content.Length} bytes, {CompressionMethod})";
}


/// <summary>
/// A container that was read: every entry, the media type its <c>mimetype</c> entry states, and the ZIP archive
/// comment.
/// </summary>
/// <remarks>
/// This is the ZIP layer's view of a container and nothing more. Which entries are manifests, which are
/// signatures, which are time assertions and which are Evidence Records is a question about their names and
/// their content that clauses 4.3.3.2, 4.4.4.2 and A.7 answer, and a layer above this one asks.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class AsicZipContainer: IDisposable
{
    /// <summary>Gets the entries, in the order the archive's central directory lists them. Owned by this instance.</summary>
    public required IReadOnlyList<AsicZipEntry> Entries { get; init; }

    /// <summary>
    /// Gets the media type the <c>mimetype</c> entry states, or <see langword="null"/> when the container
    /// carries no such entry — which clauses 4.3.3.2 item 1 and 4.4.4.2 item 1 both admit.
    /// </summary>
    public string? MediaType { get; init; }

    /// <summary>Gets the ZIP archive comment, or <see langword="null"/> when the container carries none.</summary>
    public string? ArchiveComment { get; init; }

    /// <summary>
    /// Gets whether the container's media type is readable at <see cref="AsicWellKnown.MediaTypeOffset"/> —
    /// the recognition feature the Annex A.1 NOTE describes, which holds exactly when the <c>mimetype</c> entry
    /// is first, stored, and carries no extra field.
    /// </summary>
    public bool MediaTypeReadableAtOffset38 { get; init; }


    /// <summary>
    /// Gets the media type the ZIP archive comment states, when it carries one of the clause 4.3.3.1 item 3
    /// form.
    /// </summary>
    public string? CommentMediaType => AsicWellKnown.MediaTypeFromComment(ArchiveComment);


    /// <summary>
    /// Finds an entry by its exact name.
    /// </summary>
    /// <param name="entryName">The name to look for, compared ordinally.</param>
    /// <returns>The entry, or <see langword="null"/> when the container carries none by that name.</returns>
    /// <remarks>
    /// The comparison is ordinal and case-sensitive because a ZIP entry name is an octet sequence rather than a
    /// file-system name, and a reader that folded case would resolve a manifest reference to a file object the
    /// producer did not name.
    /// </remarks>
    public AsicZipEntry? FindEntry(string entryName)
    {
        for(int i = 0; i < Entries.Count; ++i)
        {
            if(string.Equals(Entries[i].Name, entryName, StringComparison.Ordinal))
            {
                return Entries[i];
            }
        }

        return null;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        for(int i = 0; i < Entries.Count; ++i)
        {
            Entries[i].Dispose();
        }
    }


    /// <summary>A short debugger string showing the media type and how many entries the container carries.</summary>
    private string DebuggerDisplay => $"AsicZipContainer({MediaType ?? "no mimetype"}, {Entries.Count} entries)";
}


/// <summary>
/// What <see cref="AsicZipReading.Read"/> concluded, and the container when it read one.
/// </summary>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class AsicZipReadResult: IDisposable
{
    /// <summary>Gets what the reader concluded.</summary>
    public required AsicZipReadStatus Status { get; init; }

    /// <summary>Gets the container, or <see langword="null"/> when none was read. Owned by this instance.</summary>
    public AsicZipContainer? Container { get; init; }

    /// <summary>Gets the entry a status refers to, or <see langword="null"/> when the status refers to the archive as a whole.</summary>
    public string? RejectedEntryName { get; init; }

    /// <summary>
    /// Gets why an entry name was refused, when <see cref="Status"/> is
    /// <see cref="AsicZipReadStatus.EntryNameRejected"/>.
    /// </summary>
    public AsicZipEntryNameStatus RejectedEntryNameStatus { get; init; }


    /// <summary>Gets whether a container was read.</summary>
    public bool IsRead => Status == AsicZipReadStatus.Read && Container is not null;


    /// <inheritdoc/>
    public void Dispose() => Container?.Dispose();


    /// <summary>A short debugger string showing the status and the entry it refers to.</summary>
    private string DebuggerDisplay => $"AsicZipReadResult({Status}{(RejectedEntryName is null ? string.Empty : $", {RejectedEntryName}")})";
}


/// <summary>
/// Reads the octets of an Associated Signature Container: the archive's structure with this library's own
/// parser, the entries' content with the runtime's.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why two parsers.</strong> <see cref="ZipArchive"/> decompresses correctly and is the right tool for
/// getting an entry's octets out of an archive. It cannot answer the question Annex A.1 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> asks, because that question is about octet offsets: whether the
/// <c>mimetype</c> entry is the <em>first file</em>, whether its compression method field at offset 8 is zero,
/// whether its extra field length at offset 28 is zero, and therefore whether the container's media type is
/// readable at offset 38. No archive interface exposes any of that. This reader walks the first local file
/// header and the whole central directory itself, applies every rule the specification states there, and hands
/// only the decompression to the runtime.
/// </para>
/// <para>
/// <strong>The two parsers check each other.</strong> The entry count, every entry name and every entry's
/// CRC-32 are compared between this library's central-directory walk and what the runtime's reader produced. An
/// archive the two disagree about is refused rather than read one way and validated the other — the shape of
/// attack that a signature check and a content extraction disagreeing about which octets an entry holds would
/// otherwise open.
/// </para>
/// <para>
/// <strong>Bounds.</strong> Every size, count and length the archive declares is checked against
/// <see cref="AsicZipReadLimits"/> before anything is allocated or decompressed, and an entry that expands by
/// more than the caller admits is refused before its stream is opened. The walk is a loop over a flat list with
/// a bounded iteration count; there is no recursion anywhere, so no nesting an archive states can exhaust the
/// stack.
/// </para>
/// <para>
/// <strong>Nothing throws on hostile input.</strong> Every way an archive can be wrong is an
/// <see cref="AsicZipReadStatus"/>, including the failures the runtime's reader raises as exceptions, which are
/// caught and classified.
/// </para>
/// </remarks>
public static class AsicZipReading
{
    /// <summary>The ZIP local file header signature, <c>PK\3\4</c>.</summary>
    private const uint LocalFileHeaderSignature = 0x04034b50;

    /// <summary>The ZIP central directory file header signature, <c>PK\1\2</c>.</summary>
    private const uint CentralDirectoryHeaderSignature = 0x02014b50;

    /// <summary>The ZIP end-of-central-directory record signature, <c>PK\5\6</c>.</summary>
    private const uint EndOfCentralDirectorySignature = 0x06054b50;

    /// <summary>The ZIP64 end-of-central-directory locator signature, <c>PK\6\7</c> — present exactly when the archive needs the ZIP64 extensions.</summary>
    private const uint Zip64EndOfCentralDirectoryLocatorSignature = 0x07064b50;

    /// <summary>The length of a ZIP local file header before its name and extra field, 30 octets.</summary>
    private const int LocalFileHeaderByteLength = 30;

    /// <summary>The length of a ZIP central directory file header before its name, extra field and comment, 46 octets.</summary>
    private const int CentralDirectoryHeaderByteLength = 46;

    /// <summary>The length of a ZIP end-of-central-directory record before its comment, 22 octets.</summary>
    private const int EndOfCentralDirectoryByteLength = 22;

    /// <summary>The length of a ZIP64 end-of-central-directory locator, 20 octets.</summary>
    private const int Zip64LocatorByteLength = 20;

    /// <summary>The largest ZIP archive comment the format can state, and therefore how far back the end-of-central-directory record can sit.</summary>
    private const int LargestZipCommentByteLength = 65535;

    /// <summary>General purpose bit 0, which states that the entry is encrypted.</summary>
    private const ushort EncryptedFlag = 0x0001;

    /// <summary>General purpose bit 3, which states that the entry's sizes follow the data rather than preceding it.</summary>
    private const ushort DataDescriptorFlag = 0x0008;

    /// <summary>General purpose bit 6, which states that the entry uses strong encryption.</summary>
    private const ushort StrongEncryptionFlag = 0x0040;

    /// <summary>General purpose bit 13, which states that the local header's fields are masked because the central directory is encrypted.</summary>
    private const ushort MaskedLocalHeaderFlag = 0x2000;

    /// <summary>The value a sixteen-bit ZIP field carries when its real value is in the ZIP64 extended information.</summary>
    private const ushort Zip64SentinelUInt16 = 0xFFFF;

    /// <summary>The value a thirty-two-bit ZIP field carries when its real value is in the ZIP64 extended information.</summary>
    private const uint Zip64SentinelUInt32 = 0xFFFFFFFF;

    /// <summary>The first year MS-DOS date fields represent, 1980.</summary>
    private const int DosEpochYear = 1980;

    /// <summary>The smallest printable ASCII octet a media type may carry.</summary>
    private const byte SmallestPrintableAscii = 0x21;

    /// <summary>The largest printable ASCII octet a media type may carry.</summary>
    private const byte LargestPrintableAscii = 0x7E;


    /// <summary>A UTF-8 encoding that raises rather than substituting, so octets that are not UTF-8 are refused.</summary>
    private static UTF8Encoding StrictUtf8 { get; } = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>The octets the name of the <c>mimetype</c> entry occupies, compared against the container's first local file header.</summary>
    private static byte[] MimetypeEntryNameOctets { get; } = Encoding.UTF8.GetBytes(AsicWellKnown.MimetypeEntryName);


    /// <summary>
    /// Reads a container.
    /// </summary>
    /// <param name="containerBytes">The container's octets, as they arrived.</param>
    /// <param name="limits">The bounds to read within. <see cref="AsicZipReadLimits.Conformant"/> is the default set.</param>
    /// <param name="pool">The memory pool every entry's octets are rented from.</param>
    /// <returns>What the reader concluded, and the container when it read one. The caller owns and disposes the result.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="limits"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// The octets are taken as <see cref="ReadOnlyMemory{T}"/> rather than as a span because the runtime's
    /// archive reader reads from a <see cref="Stream"/>, and a stream cannot be built over a span. Nothing is
    /// retained: every entry's octets are copied into memory rented from <paramref name="pool"/>, so the caller
    /// may reuse the buffer it passed as soon as this method returns.
    /// </remarks>
    public static AsicZipReadResult Read(ReadOnlyMemory<byte> containerBytes, AsicZipReadLimits limits, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(limits);
        ArgumentNullException.ThrowIfNull(pool);

        var directory = new List<CentralDirectoryEntry>();
        AsicZipRefusal? refusal = ExamineStructure(containerBytes.Span, limits, directory, out ContainerFacts facts);

        return refusal is { } stated ? ToResult(stated) : ExtractEntries(containerBytes, directory, facts, pool);
    }


    /// <summary>
    /// Applies every structural rule the archive can be judged by without decompressing anything: the ZIP
    /// structures themselves, the caller's bounds, the entry names, the agreement between the two descriptions
    /// of each entry, and the Annex A.1 rules about the <c>mimetype</c> entry.
    /// </summary>
    /// <param name="container">The container's octets.</param>
    /// <param name="limits">The bounds to read within.</param>
    /// <param name="directory">The list the central directory's records are collected into.</param>
    /// <param name="facts">What the structures state about the container as a whole.</param>
    /// <returns>A refusal, or <see langword="null"/> when every rule held.</returns>
    /// <remarks>
    /// It is deliberately separate from <see cref="Read"/> and returns a value rather than a result: a method
    /// that cannot build a disposable cannot leak one, so every refusal path here is a plain return with nothing
    /// to own.
    /// </remarks>
    private static AsicZipRefusal? ExamineStructure(
        ReadOnlySpan<byte> container,
        AsicZipReadLimits limits,
        List<CentralDirectoryEntry> directory,
        out ContainerFacts facts)
    {
        facts = default;
        if(container.Length > limits.MaximumContainerByteLength)
        {
            return Refused(AsicZipReadStatus.ContainerTooLarge);
        }

        if(container.Length < LocalFileHeaderByteLength + EndOfCentralDirectoryByteLength
            || BinaryPrimitives.ReadUInt32LittleEndian(container) != LocalFileHeaderSignature)
        {
            return Refused(AsicZipReadStatus.NotZipArchive);
        }

        if(!TryLocateEndOfCentralDirectory(container, out int endRecordOffset))
        {
            return Refused(AsicZipReadStatus.NotZipArchive);
        }

        if(endRecordOffset >= Zip64LocatorByteLength
            && BinaryPrimitives.ReadUInt32LittleEndian(container[(endRecordOffset - Zip64LocatorByteLength)..]) == Zip64EndOfCentralDirectoryLocatorSignature)
        {
            return Refused(AsicZipReadStatus.Zip64Required);
        }

        ReadOnlySpan<byte> endRecord = container[endRecordOffset..];
        ushort thisDisk = BinaryPrimitives.ReadUInt16LittleEndian(endRecord[4..]);
        ushort centralDirectoryDisk = BinaryPrimitives.ReadUInt16LittleEndian(endRecord[6..]);
        ushort entriesOnDisk = BinaryPrimitives.ReadUInt16LittleEndian(endRecord[8..]);
        ushort entryCount = BinaryPrimitives.ReadUInt16LittleEndian(endRecord[10..]);
        uint centralDirectoryByteLength = BinaryPrimitives.ReadUInt32LittleEndian(endRecord[12..]);
        uint centralDirectoryOffset = BinaryPrimitives.ReadUInt32LittleEndian(endRecord[16..]);
        ushort commentByteLength = BinaryPrimitives.ReadUInt16LittleEndian(endRecord[20..]);

        if(thisDisk != 0 || centralDirectoryDisk != 0)
        {
            return Refused(AsicZipReadStatus.SplitArchiveDeclared);
        }

        if(entriesOnDisk == Zip64SentinelUInt16 || entryCount == Zip64SentinelUInt16
            || centralDirectoryByteLength == Zip64SentinelUInt32 || centralDirectoryOffset == Zip64SentinelUInt32)
        {
            return Refused(AsicZipReadStatus.Zip64Required);
        }

        if(entriesOnDisk != entryCount)
        {
            return Refused(AsicZipReadStatus.ArchiveMalformed);
        }

        if(entryCount > limits.MaximumEntryCount)
        {
            return Refused(AsicZipReadStatus.EntryCountExceeded);
        }

        if(commentByteLength > limits.MaximumArchiveCommentByteLength)
        {
            return Refused(AsicZipReadStatus.CommentTooLong);
        }

        if((long)centralDirectoryOffset + centralDirectoryByteLength > endRecordOffset)
        {
            return Refused(AsicZipReadStatus.ArchiveMalformed);
        }

        string? archiveComment = null;
        if(commentByteLength > 0)
        {
            if(!TryDecodeUtf8(endRecord.Slice(EndOfCentralDirectoryByteLength, commentByteLength), out archiveComment))
            {
                //Clause 4.2 item 2 b: "File names and comments shall be encoded with ISO/IEC 10646 UNICODE UTF-8."
                return Refused(AsicZipReadStatus.ArchiveMalformed);
            }
        }

        directory.Capacity = entryCount;
        AsicZipRefusal? directoryRefusal = WalkCentralDirectory(container, (int)centralDirectoryOffset, entryCount, limits, directory);
        if(directoryRefusal is not null)
        {
            return directoryRefusal;
        }

        AsicZipRefusal? localHeaderRefusal = CrossCheckLocalHeaders(container, directory);
        if(localHeaderRefusal is not null)
        {
            return localHeaderRefusal;
        }

        AsicZipRefusal? mimetypeRefusal = StateMediaType(container, directory, out string? mediaType, out bool readableAtOffset38);
        if(mimetypeRefusal is not null)
        {
            return mimetypeRefusal;
        }

        facts = new ContainerFacts(archiveComment, mediaType, readableAtOffset38);

        return null;
    }


    /// <summary>
    /// Finds the end-of-central-directory record, which sits at the end of the archive behind a comment of
    /// unstated length.
    /// </summary>
    /// <param name="container">The container's octets.</param>
    /// <param name="endRecordOffset">The offset the record begins at, when one was found.</param>
    /// <returns><see langword="true"/> when a record was found.</returns>
    /// <remarks>
    /// The record's own comment-length field has to account for exactly the octets that follow it, which is what
    /// tells a genuine record from the same four octets appearing inside an entry's data or inside the comment.
    /// The search is bounded by the largest comment the format can state, so an archive cannot make it walk
    /// further than 64 KiB whatever its size.
    /// </remarks>
    private static bool TryLocateEndOfCentralDirectory(ReadOnlySpan<byte> container, out int endRecordOffset)
    {
        int highest = container.Length - EndOfCentralDirectoryByteLength;
        int lowest = Math.Max(0, container.Length - EndOfCentralDirectoryByteLength - LargestZipCommentByteLength);
        for(int offset = highest; offset >= lowest; --offset)
        {
            if(BinaryPrimitives.ReadUInt32LittleEndian(container[offset..]) != EndOfCentralDirectorySignature)
            {
                continue;
            }

            ushort commentByteLength = BinaryPrimitives.ReadUInt16LittleEndian(container[(offset + 20)..]);
            if(offset + EndOfCentralDirectoryByteLength + commentByteLength == container.Length)
            {
                endRecordOffset = offset;

                return true;
            }
        }

        endRecordOffset = 0;

        return false;
    }


    /// <summary>
    /// Walks the central directory, applying every structural rule to each record and collecting what the
    /// entries declare.
    /// </summary>
    /// <param name="container">The container's octets.</param>
    /// <param name="centralDirectoryOffset">Where the directory begins.</param>
    /// <param name="entryCount">How many records the end record says are there.</param>
    /// <param name="limits">The bounds to read within.</param>
    /// <param name="directory">The list the records are collected into.</param>
    /// <returns>A refusal, or <see langword="null"/> when every record passed.</returns>
    private static AsicZipRefusal? WalkCentralDirectory(
        ReadOnlySpan<byte> container,
        int centralDirectoryOffset,
        int entryCount,
        AsicZipReadLimits limits,
        List<CentralDirectoryEntry> directory)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        long totalUncompressedByteLength = 0;
        int cursor = centralDirectoryOffset;

        for(int i = 0; i < entryCount; ++i)
        {
            if(cursor < 0 || cursor > container.Length - CentralDirectoryHeaderByteLength)
            {
                return Refused(AsicZipReadStatus.ArchiveMalformed);
            }

            ReadOnlySpan<byte> header = container[cursor..];
            if(BinaryPrimitives.ReadUInt32LittleEndian(header) != CentralDirectoryHeaderSignature)
            {
                return Refused(AsicZipReadStatus.ArchiveMalformed);
            }

            ushort flags = BinaryPrimitives.ReadUInt16LittleEndian(header[8..]);
            ushort method = BinaryPrimitives.ReadUInt16LittleEndian(header[10..]);
            ushort dosTime = BinaryPrimitives.ReadUInt16LittleEndian(header[12..]);
            ushort dosDate = BinaryPrimitives.ReadUInt16LittleEndian(header[14..]);
            uint crc = BinaryPrimitives.ReadUInt32LittleEndian(header[16..]);
            uint compressedByteLength = BinaryPrimitives.ReadUInt32LittleEndian(header[20..]);
            uint uncompressedByteLength = BinaryPrimitives.ReadUInt32LittleEndian(header[24..]);
            ushort nameByteLength = BinaryPrimitives.ReadUInt16LittleEndian(header[28..]);
            ushort extraByteLength = BinaryPrimitives.ReadUInt16LittleEndian(header[30..]);
            ushort commentByteLength = BinaryPrimitives.ReadUInt16LittleEndian(header[32..]);
            ushort diskNumberStart = BinaryPrimitives.ReadUInt16LittleEndian(header[34..]);
            uint localHeaderOffset = BinaryPrimitives.ReadUInt32LittleEndian(header[42..]);

            if((flags & (EncryptedFlag | StrongEncryptionFlag | MaskedLocalHeaderFlag)) != 0)
            {
                return Refused(AsicZipReadStatus.EntryEncrypted);
            }

            if(diskNumberStart != 0)
            {
                return Refused(AsicZipReadStatus.SplitArchiveDeclared);
            }

            if(compressedByteLength == Zip64SentinelUInt32 || uncompressedByteLength == Zip64SentinelUInt32 || localHeaderOffset == Zip64SentinelUInt32)
            {
                return Refused(AsicZipReadStatus.Zip64Required);
            }

            if(method is not ((ushort)AsicZipCompressionMethod.Stored or (ushort)AsicZipCompressionMethod.Deflated))
            {
                return Refused(AsicZipReadStatus.UnsupportedCompressionMethod);
            }

            var compressionMethod = (AsicZipCompressionMethod)method;

            long recordByteLength = (long)CentralDirectoryHeaderByteLength + nameByteLength + extraByteLength + commentByteLength;
            if(cursor + recordByteLength > container.Length)
            {
                return Refused(AsicZipReadStatus.ArchiveMalformed);
            }

            if(nameByteLength > limits.MaximumEntryNameByteLength)
            {
                return Refused(AsicZipReadStatus.EntryNameRejected, null, AsicZipEntryNameStatus.TooLong);
            }

            if(!TryDecodeUtf8(header.Slice(CentralDirectoryHeaderByteLength, nameByteLength), out string? name))
            {
                return Refused(AsicZipReadStatus.EntryNameRejected, null, AsicZipEntryNameStatus.NotUtf8);
            }

            AsicZipEntryNameStatus nameStatus = AsicZipEntryNaming.Validate(name, limits.MaximumEntryNameByteLength);
            if(nameStatus != AsicZipEntryNameStatus.Accepted)
            {
                return Refused(AsicZipReadStatus.EntryNameRejected, name, nameStatus);
            }

            if(!names.Add(name))
            {
                return Refused(AsicZipReadStatus.DuplicateEntryName, name);
            }

            if(uncompressedByteLength > limits.MaximumEntryUncompressedByteLength)
            {
                return Refused(AsicZipReadStatus.UncompressedSizeExceeded, name);
            }

            totalUncompressedByteLength += uncompressedByteLength;
            if(totalUncompressedByteLength > limits.MaximumTotalUncompressedByteLength)
            {
                return Refused(AsicZipReadStatus.UncompressedSizeExceeded, name);
            }

            if(IsDecompressionBomb(compressedByteLength, uncompressedByteLength, limits))
            {
                return Refused(AsicZipReadStatus.CompressionRatioExceeded, name);
            }

            if((long)localHeaderOffset + LocalFileHeaderByteLength > centralDirectoryOffset)
            {
                return Refused(AsicZipReadStatus.ArchiveMalformed, name);
            }

            directory.Add(new CentralDirectoryEntry(
                name,
                compressionMethod,
                dosTime,
                dosDate,
                crc,
                compressedByteLength,
                uncompressedByteLength,
                localHeaderOffset));

            cursor += (int)recordByteLength;
        }

        return null;
    }


    /// <summary>
    /// Checks every entry's local file header against the central directory record that points at it.
    /// </summary>
    /// <param name="container">The container's octets.</param>
    /// <param name="directory">The records the central directory walk collected.</param>
    /// <returns>A refusal, or <see langword="null"/> when the two structures describe the same entries.</returns>
    /// <remarks>
    /// <para>
    /// A ZIP archive states every entry twice, and nothing in the format requires the two statements to agree.
    /// An archive whose central directory names an entry <c>data.txt</c> while the local header at the offset it
    /// points to names something else is one where a consumer reading through the directory and a consumer
    /// reading through the local headers see different file objects under the same name — which for a container
    /// whose whole purpose is to say which octets a signature covers is the difference between a valid signature
    /// and a substituted data object. The two statements are therefore required to agree here.
    /// </para>
    /// <para>
    /// The compressed size, the uncompressed size and the CRC-32 are compared only when the entry does not
    /// declare a trailing data descriptor, because general purpose bit 3 makes exactly those three fields of the
    /// local header meaningless by design. The extra field lengths are not compared at all: differing extra
    /// fields between the two headers is ordinary ZIP, and Annex A.1 constrains the length only for the
    /// <c>mimetype</c> entry, which <see cref="StateMediaType"/> checks at the octet.
    /// </para>
    /// </remarks>
    private static AsicZipRefusal? CrossCheckLocalHeaders(ReadOnlySpan<byte> container, List<CentralDirectoryEntry> directory)
    {
        for(int i = 0; i < directory.Count; ++i)
        {
            CentralDirectoryEntry declared = directory[i];
            int headerOffset = (int)declared.LocalHeaderOffset;
            if(headerOffset > container.Length - LocalFileHeaderByteLength
                || BinaryPrimitives.ReadUInt32LittleEndian(container[headerOffset..]) != LocalFileHeaderSignature)
            {
                return Refused(AsicZipReadStatus.ArchiveMalformed, declared.Name);
            }

            ReadOnlySpan<byte> header = container[headerOffset..];
            ushort flags = BinaryPrimitives.ReadUInt16LittleEndian(header[6..]);
            ushort method = BinaryPrimitives.ReadUInt16LittleEndian(header[8..]);
            ushort nameByteLength = BinaryPrimitives.ReadUInt16LittleEndian(header[26..]);
            ushort extraByteLength = BinaryPrimitives.ReadUInt16LittleEndian(header[28..]);

            if((flags & (EncryptedFlag | StrongEncryptionFlag | MaskedLocalHeaderFlag)) != 0)
            {
                return Refused(AsicZipReadStatus.EntryEncrypted, declared.Name);
            }

            if((long)headerOffset + LocalFileHeaderByteLength + nameByteLength + extraByteLength > container.Length)
            {
                return Refused(AsicZipReadStatus.ArchiveMalformed, declared.Name);
            }

            if(!TryDecodeUtf8(header.Slice(LocalFileHeaderByteLength, nameByteLength), out string? localName)
                || !string.Equals(localName, declared.Name, StringComparison.Ordinal))
            {
                return Refused(AsicZipReadStatus.ArchiveMalformed, declared.Name);
            }

            if(method != (ushort)declared.CompressionMethod)
            {
                return Refused(AsicZipReadStatus.ArchiveMalformed, declared.Name);
            }

            if((flags & DataDescriptorFlag) == 0)
            {
                uint crc = BinaryPrimitives.ReadUInt32LittleEndian(header[14..]);
                uint compressedByteLength = BinaryPrimitives.ReadUInt32LittleEndian(header[18..]);
                uint uncompressedByteLength = BinaryPrimitives.ReadUInt32LittleEndian(header[22..]);
                if(crc != declared.Crc32 || compressedByteLength != declared.CompressedByteLength || uncompressedByteLength != declared.UncompressedByteLength)
                {
                    return Refused(AsicZipReadStatus.ArchiveMalformed, declared.Name);
                }
            }
        }

        return null;
    }


    /// <summary>
    /// Applies the Annex A.1 rules to the container's first local file header and reads the media type out of
    /// it.
    /// </summary>
    /// <param name="container">The container's octets.</param>
    /// <param name="directory">The records the central directory walk collected.</param>
    /// <param name="mediaType">The media type the <c>mimetype</c> entry states, or <see langword="null"/> when the container carries no such entry.</param>
    /// <param name="readableAtOffset38">Whether the media type is readable at <see cref="AsicWellKnown.MediaTypeOffset"/>.</param>
    /// <returns>A refusal, or <see langword="null"/> when the container satisfies Annex A.1 or carries no <c>mimetype</c> entry.</returns>
    /// <remarks>
    /// This is the check the runtime's archive reader cannot make. It reads the local file header at offset zero
    /// field by field, because every rule Annex A.1 states is about where an octet sits rather than about what
    /// the archive's directory says.
    /// </remarks>
    private static AsicZipRefusal? StateMediaType(
        ReadOnlySpan<byte> container,
        List<CentralDirectoryEntry> directory,
        out string? mediaType,
        out bool readableAtOffset38)
    {
        mediaType = null;
        readableAtOffset38 = false;

        bool directoryNamesMimetype = false;
        bool directoryPlacesMimetypeFirst = false;
        for(int i = 0; i < directory.Count; ++i)
        {
            if(AsicWellKnown.IsMimetypeEntryName(directory[i].Name))
            {
                directoryNamesMimetype = true;

                //The record has to point at the container's first octet. A directory naming the entry while
                //pointing somewhere else is an archive where the media type an application sniffs out of
                //offset 38 and the one a reader extracts through the directory are two different values.
                directoryPlacesMimetypeFirst = directory[i].LocalHeaderOffset == 0;
                break;
            }
        }

        ushort firstNameByteLength = BinaryPrimitives.ReadUInt16LittleEndian(container[26..]);
        bool firstEntryIsMimetype =
            firstNameByteLength == MimetypeEntryNameOctets.Length
            && container.Length >= AsicWellKnown.MimetypeNameOffset + firstNameByteLength
            && container.Slice(AsicWellKnown.MimetypeNameOffset, firstNameByteLength).SequenceEqual(MimetypeEntryNameOctets);

        if(!directoryNamesMimetype)
        {
            //A first entry the central directory does not name is an archive whose two structures disagree, and
            //an archive with no "mimetype" entry at all is conformant: clauses 4.3.3.2 item 1 and 4.4.4.2 item 1
            //both make the entry a "may".
            return firstEntryIsMimetype ? Refused(AsicZipReadStatus.ArchiveMalformed, AsicWellKnown.MimetypeEntryName) : null;
        }

        if(!firstEntryIsMimetype || !directoryPlacesMimetypeFirst)
        {
            return Refused(AsicZipReadStatus.MimetypeNotFirstEntry, AsicWellKnown.MimetypeEntryName);
        }

        ushort flags = BinaryPrimitives.ReadUInt16LittleEndian(container[6..]);
        ushort method = BinaryPrimitives.ReadUInt16LittleEndian(container[8..]);
        uint compressedByteLength = BinaryPrimitives.ReadUInt32LittleEndian(container[18..]);
        uint uncompressedByteLength = BinaryPrimitives.ReadUInt32LittleEndian(container[22..]);
        ushort extraByteLength = BinaryPrimitives.ReadUInt16LittleEndian(container[28..]);

        if((flags & (EncryptedFlag | StrongEncryptionFlag)) != 0)
        {
            //Annex A.1 item 6: "The "mimetype" shall not be compressed or encrypted inside the ASiC container."
            return Refused(AsicZipReadStatus.EntryEncrypted, AsicWellKnown.MimetypeEntryName);
        }

        if((flags & DataDescriptorFlag) != 0)
        {
            return Refused(AsicZipReadStatus.MimetypeUsesDataDescriptor, AsicWellKnown.MimetypeEntryName);
        }

        if(method != (ushort)AsicZipCompressionMethod.Stored)
        {
            return Refused(AsicZipReadStatus.MimetypeCompressed, AsicWellKnown.MimetypeEntryName);
        }

        if(extraByteLength != 0)
        {
            return Refused(AsicZipReadStatus.MimetypeCarriesExtraField, AsicWellKnown.MimetypeEntryName);
        }

        if(compressedByteLength != uncompressedByteLength
            || uncompressedByteLength == 0
            || (long)AsicWellKnown.MediaTypeOffset + uncompressedByteLength > container.Length)
        {
            return Refused(AsicZipReadStatus.MimetypeEntryMalformed, AsicWellKnown.MimetypeEntryName);
        }

        ReadOnlySpan<byte> mediaTypeOctets = container.Slice(AsicWellKnown.MediaTypeOffset, (int)uncompressedByteLength);
        for(int i = 0; i < mediaTypeOctets.Length; ++i)
        {
            if(mediaTypeOctets[i] < SmallestPrintableAscii || mediaTypeOctets[i] > LargestPrintableAscii)
            {
                return Refused(AsicZipReadStatus.MimetypeEntryMalformed, AsicWellKnown.MimetypeEntryName);
            }
        }

        if(!TryDecodeUtf8(mediaTypeOctets, out mediaType))
        {
            return Refused(AsicZipReadStatus.MimetypeEntryMalformed, AsicWellKnown.MimetypeEntryName);
        }

        readableAtOffset38 = true;

        return null;
    }


    /// <summary>
    /// Decompresses every entry with the runtime's archive reader and checks what it produced against what this
    /// library's central-directory walk declared.
    /// </summary>
    /// <param name="containerBytes">The container's octets.</param>
    /// <param name="directory">The records the central directory walk collected.</param>
    /// <param name="facts">What the archive's structures state about the container as a whole.</param>
    /// <param name="pool">The memory pool every entry's octets are rented from.</param>
    /// <returns>The container, or a refusal.</returns>
    private static AsicZipReadResult ExtractEntries(
        ReadOnlyMemory<byte> containerBytes,
        List<CentralDirectoryEntry> directory,
        ContainerFacts facts,
        BaseMemoryPool pool)
    {
        var entries = new List<AsicZipEntry>(directory.Count);
        try
        {
            using var source = new ReadOnlyMemoryStream(containerBytes);
            using var archive = new ZipArchive(source, ZipArchiveMode.Read, leaveOpen: true, entryNameEncoding: Encoding.UTF8);

            if(archive.Entries.Count != directory.Count)
            {
                DisposeAll(entries);

                return ToResult(Refused(AsicZipReadStatus.ArchiveMalformed));
            }

            for(int i = 0; i < directory.Count; ++i)
            {
                CentralDirectoryEntry declared = directory[i];
                ZipArchiveEntry actual = archive.Entries[i];
                if(!string.Equals(actual.FullName, declared.Name, StringComparison.Ordinal) || actual.Crc32 != declared.Crc32)
                {
                    DisposeAll(entries);

                    return ToResult(Refused(AsicZipReadStatus.ArchiveMalformed, declared.Name));
                }

                bool isFolder = AsicZipEntryNaming.IsFolderEntryName(declared.Name);
                if(isFolder && declared.UncompressedByteLength != 0)
                {
                    DisposeAll(entries);

                    return ToResult(Refused(AsicZipReadStatus.ArchiveMalformed, declared.Name));
                }

                PooledMemory content = ReadEntryContent(actual, declared, pool, out AsicZipReadStatus contentStatus);
                if(contentStatus != AsicZipReadStatus.Read)
                {
                    content.Dispose();
                    DisposeAll(entries);

                    return ToResult(Refused(contentStatus, declared.Name));
                }

                entries.Add(new AsicZipEntry
                {
                    Name = declared.Name,
                    Content = content,
                    CompressionMethod = declared.CompressionMethod,
                    LastModified = FromDosDateTime(declared.DosTime, declared.DosDate),
                    CompressedByteLength = declared.CompressedByteLength,
                    IsFolder = isFolder
                });
            }
        }
        catch(InvalidDataException)
        {
            //The runtime's reader raises this for every structural fault it finds and for a CRC mismatch. It is
            //an adversary-reachable condition rather than a programming error, so it becomes a status.
            DisposeAll(entries);

            return ToResult(Refused(AsicZipReadStatus.ArchiveMalformed));
        }
        catch
        {
            DisposeAll(entries);

            throw;
        }

        var container = new AsicZipContainer
        {
            Entries = entries,
            MediaType = facts.MediaType,
            ArchiveComment = facts.ArchiveComment,
            MediaTypeReadableAtOffset38 = facts.MediaTypeReadableAtOffset38
        };

        return new AsicZipReadResult { Status = AsicZipReadStatus.Read, Container = container };
    }


    /// <summary>
    /// Reads exactly the octets an entry declares, and no more.
    /// </summary>
    /// <param name="entry">The entry as the runtime's reader sees it.</param>
    /// <param name="declared">The entry as the central directory declares it.</param>
    /// <param name="pool">The memory pool the octets are rented from.</param>
    /// <param name="status">What reading the entry concluded.</param>
    /// <returns>The entry's octets, which the caller owns whatever <paramref name="status"/> says.</returns>
    /// <remarks>
    /// Reading exactly the declared length and then checking that the stream is at its end is what makes the
    /// bound from the central directory real: an entry whose stream produces more octets than its headers
    /// declare would otherwise decompress past every size check performed before it was opened.
    /// </remarks>
    private static PooledMemory ReadEntryContent(ZipArchiveEntry entry, CentralDirectoryEntry declared, BaseMemoryPool pool, out AsicZipReadStatus status)
    {
        int uncompressedByteLength = (int)declared.UncompressedByteLength;
        IMemoryOwner<byte> owner = pool.Rent(Math.Max(uncompressedByteLength, 1));
        try
        {
            if(uncompressedByteLength > 0)
            {
                using Stream content = entry.Open();
                content.ReadExactly(owner.Memory.Span[..uncompressedByteLength]);
                if(content.ReadByte() != -1)
                {
                    status = AsicZipReadStatus.ArchiveMalformed;

                    return new PooledMemory(owner, 0, AsicTags.ContainerEntry);
                }
            }

            //One implementation of the checksum serves both directions, so a container this library writes and
            //one it reads cannot disagree about what the field means. That the implementation is the format's
            //rather than merely self-consistent is established by the independent computation the tests check
            //written containers against, and by the third-party containers the reference-artifact leg reads.
            uint computed = AsicZipAuthoring.ComputeCrc32(owner.Memory.Span[..uncompressedByteLength]);
            status = computed == declared.Crc32 ? AsicZipReadStatus.Read : AsicZipReadStatus.EntryChecksumMismatch;

            return new PooledMemory(owner, uncompressedByteLength, AsicTags.ContainerEntry);
        }
        catch(EndOfStreamException)
        {
            status = AsicZipReadStatus.ArchiveMalformed;

            return new PooledMemory(owner, 0, AsicTags.ContainerEntry);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Determines whether an entry expands by more than the caller admits.
    /// </summary>
    /// <param name="compressedByteLength">How many octets the entry occupies in the archive.</param>
    /// <param name="uncompressedByteLength">How many octets it declares once decompressed.</param>
    /// <param name="limits">The bounds to read within.</param>
    /// <returns><see langword="true"/> when the entry is a decompression bomb by the caller's measure.</returns>
    private static bool IsDecompressionBomb(uint compressedByteLength, uint uncompressedByteLength, AsicZipReadLimits limits)
    {
        if(uncompressedByteLength <= limits.ExpansionRatioMinimumUncompressedByteLength)
        {
            return false;
        }

        return compressedByteLength == 0 || uncompressedByteLength / (long)compressedByteLength > limits.MaximumEntryExpansionRatio;
    }


    /// <summary>
    /// Decodes octets as UTF-8, refusing anything that is not.
    /// </summary>
    /// <param name="octets">The octets to decode.</param>
    /// <param name="value">The decoded string, when the octets were UTF-8.</param>
    /// <returns><see langword="true"/> when the octets decoded.</returns>
    /// <remarks>
    /// The decoding is strict rather than replacing, so an entry name that is not UTF-8 is refused rather than
    /// turned into one carrying replacement characters. Clause 4.2 item 2 b requires UTF-8, and a name that
    /// silently changed shape while being read is a name a manifest reference no longer resolves against.
    /// </remarks>
    private static bool TryDecodeUtf8(ReadOnlySpan<byte> octets, [NotNullWhen(true)] out string? value)
    {
        try
        {
            value = StrictUtf8.GetString(octets);

            return true;
        }
        catch(DecoderFallbackException)
        {
            value = null;

            return false;
        }
    }


    /// <summary>
    /// Converts the MS-DOS date and time fields of a ZIP header into an instant.
    /// </summary>
    /// <param name="dosTime">The MS-DOS time field.</param>
    /// <param name="dosDate">The MS-DOS date field.</param>
    /// <returns>The instant in UTC, or <see langword="null"/> when the fields do not name one.</returns>
    /// <remarks>
    /// Producers that record nothing leave both fields zero, which names month zero and day zero. That is not a
    /// structural fault of the archive — nothing in ETSI EN 319 162-1 or -2 rests on the value — so it becomes
    /// an absent instant rather than a refusal.
    /// </remarks>
    private static DateTimeOffset? FromDosDateTime(ushort dosTime, ushort dosDate)
    {
        int year = DosEpochYear + ((dosDate >> 9) & 0x7F);
        int month = (dosDate >> 5) & 0x0F;
        int day = dosDate & 0x1F;
        int hour = (dosTime >> 11) & 0x1F;
        int minute = (dosTime >> 5) & 0x3F;
        int second = (dosTime & 0x1F) * 2;

        if(month is < 1 or > 12 || day < 1 || day > DateTime.DaysInMonth(year, month) || hour > 23 || minute > 59 || second > 59)
        {
            return null;
        }

        return new DateTimeOffset(year, month, day, hour, minute, second, TimeSpan.Zero);
    }


    /// <summary>
    /// Disposes every entry read so far, for the paths that abandon a partly-built container.
    /// </summary>
    /// <param name="entries">The entries to dispose.</param>
    private static void DisposeAll(List<AsicZipEntry> entries)
    {
        for(int i = 0; i < entries.Count; ++i)
        {
            entries[i].Dispose();
        }
    }


    /// <summary>
    /// States a refusal.
    /// </summary>
    /// <param name="status">What the reader concluded.</param>
    /// <param name="entryName">The entry the status refers to, or <see langword="null"/>.</param>
    /// <param name="nameStatus">Why an entry name was refused, when that is the status.</param>
    /// <returns>The refusal.</returns>
    private static AsicZipRefusal Refused(
        AsicZipReadStatus status,
        string? entryName = null,
        AsicZipEntryNameStatus nameStatus = AsicZipEntryNameStatus.NotEvaluated) =>
        new(status, entryName, nameStatus);


    /// <summary>
    /// Turns a refusal into the result a caller receives.
    /// </summary>
    /// <param name="refusal">The refusal to report.</param>
    /// <returns>The result, which carries no container.</returns>
    private static AsicZipReadResult ToResult(AsicZipRefusal refusal) =>
        new() { Status = refusal.Status, RejectedEntryName = refusal.EntryName, RejectedEntryNameStatus = refusal.NameStatus };


    /// <summary>
    /// A refusal as the structural checks state it, before it becomes the result a caller receives.
    /// </summary>
    /// <param name="Status">What the reader concluded.</param>
    /// <param name="EntryName">The entry the status refers to, or <see langword="null"/>.</param>
    /// <param name="NameStatus">Why an entry name was refused, when that is the status.</param>
    /// <remarks>
    /// A value rather than the result type, so that the methods stating refusals hold nothing that has to be
    /// disposed on any path and only <see cref="Read"/> ever builds something a caller owns.
    /// </remarks>
    private readonly record struct AsicZipRefusal(AsicZipReadStatus Status, string? EntryName, AsicZipEntryNameStatus NameStatus);


    /// <summary>
    /// What an archive's structures state about the container as a whole, once every structural rule has held.
    /// </summary>
    /// <param name="ArchiveComment">The ZIP archive comment, or <see langword="null"/>.</param>
    /// <param name="MediaType">The media type the <c>mimetype</c> entry states, or <see langword="null"/>.</param>
    /// <param name="MediaTypeReadableAtOffset38">Whether the media type is readable at <see cref="AsicWellKnown.MediaTypeOffset"/>.</param>
    private readonly record struct ContainerFacts(string? ArchiveComment, string? MediaType, bool MediaTypeReadableAtOffset38);


    /// <summary>One entry as the central directory declares it.</summary>
    /// <param name="Name">The entry name, decoded strictly as UTF-8.</param>
    /// <param name="CompressionMethod">The method the record states.</param>
    /// <param name="DosTime">The MS-DOS time field.</param>
    /// <param name="DosDate">The MS-DOS date field.</param>
    /// <param name="Crc32">The CRC-32 of the uncompressed octets.</param>
    /// <param name="CompressedByteLength">How many octets the entry occupies in the archive.</param>
    /// <param name="UncompressedByteLength">How many octets it declares once decompressed.</param>
    /// <param name="LocalHeaderOffset">Where the entry's local file header begins.</param>
    private readonly record struct CentralDirectoryEntry(
        string Name,
        AsicZipCompressionMethod CompressionMethod,
        ushort DosTime,
        ushort DosDate,
        uint Crc32,
        uint CompressedByteLength,
        uint UncompressedByteLength,
        uint LocalHeaderOffset);


    /// <summary>
    /// A seekable, read-only <see cref="Stream"/> over <see cref="ReadOnlyMemory{T}"/>.
    /// </summary>
    /// <remarks>
    /// The runtime's archive reader reads from a stream and seeks in it, and a container's octets live in pooled
    /// memory this library does not copy into a managed array to read. Nothing here writes, so the writing
    /// members refuse rather than pretend.
    /// </remarks>
    private sealed class ReadOnlyMemoryStream: Stream
    {
        /// <summary>The octets this stream reads from.</summary>
        private readonly ReadOnlyMemory<byte> source;

        /// <summary>How many octets have been read.</summary>
        private int position;


        /// <summary>
        /// Initializes a new stream over octets the caller keeps alive for as long as the stream is used.
        /// </summary>
        /// <param name="source">The octets to read.</param>
        public ReadOnlyMemoryStream(ReadOnlyMemory<byte> source) => this.source = source;


        /// <inheritdoc/>
        public override bool CanRead => true;

        /// <inheritdoc/>
        public override bool CanSeek => true;

        /// <inheritdoc/>
        public override bool CanWrite => false;

        /// <inheritdoc/>
        public override long Length => source.Length;

        /// <inheritdoc/>
        public override long Position
        {
            get => position;
            set
            {
                ArgumentOutOfRangeException.ThrowIfNegative(value);
                ArgumentOutOfRangeException.ThrowIfGreaterThan(value, (long)source.Length);

                position = (int)value;
            }
        }


        /// <inheritdoc/>
        public override void Flush()
        {
        }


        /// <inheritdoc/>
        public override int Read(byte[] buffer, int offset, int count)
        {
            ArgumentNullException.ThrowIfNull(buffer);

            return Read(new Span<byte>(buffer, offset, count));
        }


        /// <inheritdoc/>
        public override int Read(Span<byte> buffer)
        {
            int available = Math.Min(buffer.Length, source.Length - position);
            source.Span.Slice(position, available).CopyTo(buffer);
            position += available;

            return available;
        }


        /// <inheritdoc/>
        public override int ReadByte() => position < source.Length ? source.Span[position++] : -1;


        /// <inheritdoc/>
        public override long Seek(long offset, SeekOrigin origin)
        {
            long target = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => position + offset,
                SeekOrigin.End => source.Length + offset,
                _ => throw new ArgumentOutOfRangeException(nameof(origin))
            };

            Position = target;

            return position;
        }


        /// <inheritdoc/>
        public override void SetLength(long value) =>
            throw new NotSupportedException("A container's octets are read-only.");


        /// <inheritdoc/>
        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException("A container's octets are read-only.");
    }
}
