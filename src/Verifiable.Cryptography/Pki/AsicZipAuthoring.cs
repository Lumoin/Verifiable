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
/// The ZIP compression methods an Associated Signature Container entry is written with.
/// </summary>
/// <remarks>
/// Clause 4.2 item 2 c of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> states that "only 0 ("stored") or 8 ("deflated") values should be used as ZIP
/// compression method", and Table 1 item a hardens that to a requirement for baseline containers by way of
/// ISO/IEC 21320-1. The values here are the ZIP method numbers themselves, so a written header field is this
/// enumeration's numeric value with no mapping table in between.
/// </remarks>
[SuppressMessage("Design", "CA1027:Mark enums with FlagsAttribute",
    Justification = "The two values are the ZIP compression method numbers 0 and 8, which are alternatives rather than combinable bits; the numeric gap between them is the format's, not a bit assignment.")]
public enum AsicZipCompressionMethod
{
    /// <summary>ZIP method 0, "stored": the entry's octets appear in the container unchanged.</summary>
    Stored = 0,

    /// <summary>ZIP method 8, "deflated": the entry's octets are compressed per <see href="https://www.rfc-editor.org/rfc/rfc1951">IETF RFC 1951</see>.</summary>
    Deflated = 8
}


/// <summary>
/// One entry a container is written from: its name, its octets, and how they are to be stored.
/// </summary>
/// <remarks>
/// The <c>mimetype</c> entry is not expressible here. Annex A.1 binds four properties to it at once — first
/// entry, method 0, no extra field, and therefore its content at
/// <see cref="AsicWellKnown.MediaTypeOffset"/> — which a caller can only get wrong. It is stated instead as
/// <see cref="AsicZipAuthoringContext.MediaType"/>, and <see cref="AsicZipAuthoring"/> refuses an entry named
/// <c>mimetype</c> supplied here.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record AsicZipEntrySource
{
    /// <summary>Gets the entry name, as it is to appear in the container. Root-relative, <c>/</c>-separated (Annex A.6).</summary>
    public required string Name { get; init; }

    /// <summary>Gets the entry's octets as the container is to carry them, before any compression.</summary>
    public required ReadOnlyMemory<byte> Content { get; init; }

    /// <summary>
    /// Gets how the octets are stored. <see cref="AsicZipCompressionMethod.Stored"/> is the default because it
    /// is the only method that keeps a container's octets a function of its content alone: a deflate encoder's
    /// exact output is its implementation's, while a stored entry's is the entry.
    /// </summary>
    public AsicZipCompressionMethod CompressionMethod { get; init; } = AsicZipCompressionMethod.Stored;

    /// <summary>
    /// Gets the instant recorded as this entry's last modification, or <see langword="null"/> to record
    /// <see cref="AsicZipAuthoringContext.LastModified"/>. Stating it per entry is what lets a container that is
    /// augmented later carry every untouched entry's original instant forward.
    /// </summary>
    public DateTimeOffset? LastModified { get; init; }


    /// <summary>A short debugger string showing the entry's name, size and method.</summary>
    private string DebuggerDisplay => $"AsicZipEntrySource({Name}, {Content.Length} bytes, {CompressionMethod})";
}


/// <summary>
/// Everything a container is written from: its media type, its entries, the instant its entries record, and the
/// optional ZIP archive comment.
/// </summary>
/// <remarks>
/// <para>
/// There is no ambient input. The instant is the caller's, so a container written twice from the same context is
/// the same octets; nothing here reads a clock, a file system or an environment.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record AsicZipAuthoringContext
{
    /// <summary>
    /// Gets the media type written as the container's first entry per Annex A.1, or <see langword="null"/> to
    /// write no <c>mimetype</c> entry at all — which clauses 4.3.3.2 item 1 and 4.4.4.2 item 1 both admit
    /// ("may contain a "mimetype" file").
    /// </summary>
    public string? MediaType { get; init; }

    /// <summary>Gets the entries the container carries, in the order they are to be written.</summary>
    public required IReadOnlyList<AsicZipEntrySource> Entries { get; init; }

    /// <summary>
    /// Gets the instant recorded for every entry that does not state its own
    /// (<see cref="AsicZipEntrySource.LastModified"/>).
    /// </summary>
    /// <remarks>
    /// ZIP records a modification instant in MS-DOS form, at two-second resolution and with no time zone. This
    /// library converts the value to UTC and records that, so the octets never depend on where they were
    /// written; a reader recovers the same instant as an offset of zero.
    /// </remarks>
    public required DateTimeOffset LastModified { get; init; }

    /// <summary>
    /// Gets the ZIP archive comment, or <see langword="null"/> to write none. Clauses 4.3.3.1 item 3 and
    /// 4.4.4.1 item 3 admit the value <see cref="AsicWellKnown.MediaTypeComment"/> builds; anything else a
    /// caller states is written verbatim.
    /// </summary>
    public string? ArchiveComment { get; init; }


    /// <summary>A short debugger string showing the media type and how many entries the container carries.</summary>
    private string DebuggerDisplay => $"AsicZipAuthoringContext({MediaType ?? "no mimetype"}, {Entries.Count} entries)";
}


/// <summary>
/// Names why a container could not be written.
/// </summary>
/// <remarks>
/// These are generator-side faults: material the caller supplied that a conformant container cannot be built
/// from. They are deliberately not <see cref="AsicZipReadStatus"/>, which describes what a reader concludes
/// about a container it did not make — the same split <see cref="EvidenceRecordCreationFailureKind"/> makes
/// against <see cref="EvidenceRecordVerificationStatus"/>.
/// </remarks>
public enum AsicZipAuthoringFailureKind
{
    /// <summary>No failure has been classified.</summary>
    NotEvaluated = 0,

    /// <summary>
    /// No entry was supplied. Clause 4.3.3.2 item 2 requires one data file for ASiC-S and clause 4.4.2 item 2
    /// requires "one or more data files" for ASiC-E, so a container holding nothing but a media type is not a
    /// container of either type.
    /// </summary>
    NoEntries = 1,

    /// <summary>More entries were supplied than <see cref="AsicZipAuthoring.MaximumEntryCount"/> admits.</summary>
    EntryCountExceeded = 2,

    /// <summary>An entry name was refused; the message names it and the <see cref="AsicZipEntryNameStatus"/> that refused it.</summary>
    EntryNameRejected = 3,

    /// <summary>Two entries carry the same name, so the container would name one file object twice.</summary>
    DuplicateEntryName = 4,

    /// <summary>
    /// An entry was supplied under the name <c>mimetype</c>, which Annex A.1 binds four properties to at once
    /// and which this library therefore writes only from <see cref="AsicZipAuthoringContext.MediaType"/>.
    /// </summary>
    MimetypeEntrySuppliedDirectly = 5,

    /// <summary>The media type is empty, longer than <see cref="AsicZipAuthoring.MaximumMediaTypeByteLength"/>, or carries an octet outside printable ASCII.</summary>
    MediaTypeRejected = 6,

    /// <summary>An entry's octets exceed <see cref="AsicZipAuthoring.MaximumEntryByteLength"/>.</summary>
    EntryTooLarge = 7,

    /// <summary>The container's octets would exceed <see cref="AsicZipAuthoring.MaximumContainerByteLength"/>.</summary>
    ContainerTooLarge = 8,

    /// <summary>An instant lies outside the range MS-DOS date fields represent, so the container could not record it.</summary>
    InstantNotRepresentable = 9,

    /// <summary>The archive comment exceeds <see cref="AsicZipAuthoring.MaximumArchiveCommentByteLength"/>.</summary>
    CommentTooLong = 10,

    /// <summary>An entry states a compression method that is neither <see cref="AsicZipCompressionMethod.Stored"/> nor <see cref="AsicZipCompressionMethod.Deflated"/>.</summary>
    UnsupportedCompressionMethod = 11
}


/// <summary>
/// The generator-side fault of a container authoring.
/// </summary>
/// <remarks>
/// Authoring reports faults as exceptions, following the CAdES and Evidence Record creation surfaces already in
/// this library: a generator handing in material a container cannot be built from is a composition fault of the
/// caller rather than an adversarial input to be classified and reported.
/// </remarks>
[DebuggerDisplay("AsicZipAuthoringException({FailureKind}): {Message}")]
public sealed class AsicZipAuthoringException: Exception
{
    /// <summary>Gets what could not be done.</summary>
    public AsicZipAuthoringFailureKind FailureKind { get; }


    /// <summary>Initializes a new <see cref="AsicZipAuthoringException"/> with an unclassified fault.</summary>
    public AsicZipAuthoringException(): this(AsicZipAuthoringFailureKind.NoEntries, "The container could not be written.")
    {
    }


    /// <summary>Initializes a new <see cref="AsicZipAuthoringException"/> with an unclassified fault.</summary>
    /// <param name="message">The message describing the fault.</param>
    public AsicZipAuthoringException(string message): this(AsicZipAuthoringFailureKind.NoEntries, message)
    {
    }


    /// <summary>Initializes a new <see cref="AsicZipAuthoringException"/> with an unclassified fault.</summary>
    /// <param name="message">The message describing the fault.</param>
    /// <param name="innerException">The exception that caused it.</param>
    public AsicZipAuthoringException(string message, Exception innerException)
        : this(AsicZipAuthoringFailureKind.NoEntries, message, innerException)
    {
    }


    /// <summary>Initializes a new <see cref="AsicZipAuthoringException"/>.</summary>
    /// <param name="failureKind">What could not be done.</param>
    /// <param name="message">The message describing the fault.</param>
    public AsicZipAuthoringException(AsicZipAuthoringFailureKind failureKind, string message): base(message)
    {
        FailureKind = failureKind;
    }


    /// <summary>Initializes a new <see cref="AsicZipAuthoringException"/>.</summary>
    /// <param name="failureKind">What could not be done.</param>
    /// <param name="message">The message describing the fault.</param>
    /// <param name="innerException">The exception that caused it.</param>
    public AsicZipAuthoringException(AsicZipAuthoringFailureKind failureKind, string message, Exception innerException)
        : base(message, innerException)
    {
        FailureKind = failureKind;
    }
}


/// <summary>
/// Writes the octets of an Associated Signature Container: the ZIP local file headers, the central directory and
/// the end-of-central-directory record, field by field.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why this library writes the archive itself.</strong> Annex A.1 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> constrains the container at the octet: the <c>mimetype</c> entry "shall be the
/// first file in the ASiC container", "shall not contain "Extra fields" in its ZIP header (i.e. extra field
/// length at offset 28 shall be set to zero)", "shall not be compressed (i.e. compression method in its ZIP
/// header at offset 8 shall be set to zero)", and the first four octets of the container "shall have the hex
/// values: "50 4B 03 04"". Those four rules together are what put the container's media type at
/// <see cref="AsicWellKnown.MediaTypeOffset"/>, which the Annex A.1 NOTE makes the recognition feature of the
/// whole format. A general-purpose archive writer offers no way to state them — it is entitled to add extra
/// fields, and none of its interfaces admit "this entry's content begins at octet 38". The same reason produced
/// the <see cref="System.Formats.Asn1.AsnWriter"/>-based request builders of <see cref="OcspRequests"/> and
/// <see cref="TimestampRequests"/>: where the wire format is the requirement, the library writes the wire
/// format.
/// </para>
/// <para>
/// <strong>What is written, and what is refused.</strong> Every entry is stored (method 0) or deflated
/// (method 8) per clause 4.2 item 2 c; no entry carries an extra field, a data descriptor or encryption; every
/// disk number is zero, so clause 4.2 item 2 a's "ASiC containers shall not use the multiple volumes split
/// feature" holds by construction; and every size, count and offset is bounded below the values that would
/// require the ZIP64 extensions, so no container this library writes needs them. Entry names and the archive
/// comment are UTF-8 with the language-encoding flag set, which is clause 4.2 item 2 b's "File names and
/// comments shall be encoded with ISO/IEC 10646 UNICODE UTF-8".
/// </para>
/// <para>
/// <strong>Determinism.</strong> Nothing here reads a clock, a file system or an environment: the recorded
/// instants are the caller's, the "version made by" field names a fixed host rather than the running one, and
/// external file attributes are zero. Two calls with the same context therefore produce the same octets. A
/// deflated entry's compressed octets are the runtime deflate encoder's and are reproducible for that runtime;
/// <see cref="AsicZipCompressionMethod.Stored"/>, the default, makes even that dependence go away.
/// </para>
/// <para>
/// <strong>Synchronous by nature.</strong> Writing a container is pure computation over memory — a CRC-32, a
/// deflate, and field writes — with no I/O and no cryptographic digest, so there is nothing for an asynchronous
/// signature to await. The Evidence Record and CAdES surfaces are asynchronous where they reach the registered
/// digest seam or a Time-Stamping Authority; this one reaches neither.
/// </para>
/// </remarks>
public static class AsicZipAuthoring
{
    /// <summary>The ZIP local file header signature, <c>PK\3\4</c> — the four octets Annex A.1 item 4 requires a container to begin with.</summary>
    private const uint LocalFileHeaderSignature = 0x04034b50;

    /// <summary>The ZIP central directory file header signature, <c>PK\1\2</c>.</summary>
    private const uint CentralDirectoryHeaderSignature = 0x02014b50;

    /// <summary>The ZIP end-of-central-directory record signature, <c>PK\5\6</c>.</summary>
    private const uint EndOfCentralDirectorySignature = 0x06054b50;

    /// <summary>The length of a ZIP local file header before its name and extra field, 30 octets.</summary>
    private const int LocalFileHeaderByteLength = 30;

    /// <summary>The length of a ZIP central directory file header before its name, extra field and comment, 46 octets.</summary>
    private const int CentralDirectoryHeaderByteLength = 46;

    /// <summary>The length of a ZIP end-of-central-directory record before its comment, 22 octets.</summary>
    private const int EndOfCentralDirectoryByteLength = 22;

    /// <summary>The "version needed to extract" a stored entry states, 1.0.</summary>
    private const ushort VersionNeededStored = 10;

    /// <summary>The "version needed to extract" a deflated entry states, 2.0.</summary>
    private const ushort VersionNeededDeflated = 20;

    /// <summary>
    /// The "version made by" every central directory header states: host system 0 (MS-DOS/FAT) in the high
    /// octet and ZIP specification version 2.0 in the low one. Fixed rather than derived from the running
    /// platform, so the octets of a container do not record where it was written.
    /// </summary>
    private const ushort VersionMadeBy = 0x0014;

    /// <summary>
    /// General purpose bit 11, the language encoding flag, which states that the entry's name and comment are
    /// UTF-8 — clause 4.2 item 2 b's requirement, signalled rather than assumed. No other bit is ever set: bit 0
    /// would mean encryption, bit 3 a data descriptor, and bits 1, 2 and 6 belong to methods this library does
    /// not write.
    /// </summary>
    private const ushort GeneralPurposeUtf8NameFlag = 0x0800;

    /// <summary>The first year MS-DOS date fields represent, 1980.</summary>
    private const int DosEpochYear = 1980;

    /// <summary>The last year MS-DOS date fields represent, 2107 — the seven-bit year field's last value.</summary>
    private const int DosLastYear = 2107;

    /// <summary>The smallest printable ASCII octet a media type may carry.</summary>
    private const byte SmallestPrintableAscii = 0x21;

    /// <summary>The largest printable ASCII octet a media type may carry.</summary>
    private const byte LargestPrintableAscii = 0x7E;


    /// <summary>
    /// The largest number of entries a container is written with, 4096 — far beyond what any container of signed
    /// data objects, manifests, signatures, time assertions and Evidence Records holds, and far below the 65 535
    /// a ZIP end-of-central-directory record's entry count field can state without the ZIP64 extensions.
    /// </summary>
    public static int MaximumEntryCount { get; } = 4096;

    /// <summary>
    /// The largest number of octets one entry is written with, 64 MiB. The bound keeps every size field of the
    /// archive well below the value that would require the ZIP64 extensions, which this library does not write.
    /// </summary>
    public static int MaximumEntryByteLength { get; } = 64 * 1024 * 1024;

    /// <summary>
    /// The largest number of octets a container is written with, 256 MiB. A container is built in pooled memory
    /// in one piece, so this is also the largest single rental the authoring performs.
    /// </summary>
    public static int MaximumContainerByteLength { get; } = 256 * 1024 * 1024;

    /// <summary>
    /// The largest number of UTF-8 octets an entry name is written with, 512. ZIP states a name's length in
    /// sixteen bits; this bound is what a container of the shape Annex A.6 describes actually needs.
    /// </summary>
    public static int MaximumEntryNameByteLength { get; } = 512;

    /// <summary>The largest number of UTF-8 octets the ZIP archive comment is written with, 4096.</summary>
    public static int MaximumArchiveCommentByteLength { get; } = 4096;

    /// <summary>
    /// The largest number of octets a media type is written with, 255. The bound is what keeps the Annex A.1
    /// NOTE's recognition feature meaningful: an application sniffing a container reads the media type out of
    /// the first octets of the file, and a media type longer than this is not one.
    /// </summary>
    public static int MaximumMediaTypeByteLength { get; } = 255;

    /// <summary>The earliest instant a container can record, 1980-01-01T00:00:00Z — the MS-DOS date epoch.</summary>
    public static DateTimeOffset EarliestRepresentableInstant { get; } = new(DosEpochYear, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The latest instant a container can record, 2107-12-31T23:59:58Z — the last value MS-DOS date and time fields state.</summary>
    public static DateTimeOffset LatestRepresentableInstant { get; } = new(DosLastYear, 12, 31, 23, 59, 58, TimeSpan.Zero);


    /// <summary>
    /// The CRC-32 table of <see href="https://www.rfc-editor.org/rfc/rfc1952#section-8">IETF RFC 1952 clause
    /// 8</see>, the checksum ZIP records for every entry.
    /// </summary>
    /// <remarks>
    /// This is a structural checksum of the archive format, not a cryptographic digest: it detects accidental
    /// corruption of a stored or deflated stream and nothing else. It is therefore computed here rather than
    /// through the registered <c>ComputeDigestAsync</c> seam, which exists so that every <em>cryptographic</em>
    /// digest of this library is algorithm-agile and observable. Nothing in an ASiC container's integrity rests
    /// on a CRC — the manifests' <c>ds:DigestValue</c> elements and the signatures over them do.
    /// </remarks>
    private static uint[] Crc32Table { get; } = BuildCrc32Table();


    /// <summary>
    /// Writes a container's octets.
    /// </summary>
    /// <param name="context">The media type, entries, instant and comment the container is written from.</param>
    /// <param name="pool">The memory pool the container's octets are rented from.</param>
    /// <returns>The container's octets, tagged <see cref="AsicTags.Container"/>. The caller owns and disposes them.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="AsicZipAuthoringException">When the supplied material is not a container this library writes; <see cref="AsicZipAuthoringException.FailureKind"/> names which rule refused it.</exception>
    public static PooledMemory Write(AsicZipAuthoringContext context, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);

        List<PlannedEntry> planned = PlanEntries(context);
        int commentByteLength = StateCommentByteLength(context.ArchiveComment);

        var writer = new PooledZipWriter(pool, EstimateContainerByteLength(planned, commentByteLength), MaximumContainerByteLength);
        try
        {
            var written = new List<WrittenEntry>(planned.Count);
            for(int i = 0; i < planned.Count; ++i)
            {
                written.Add(WriteEntry(writer, planned[i]));
            }

            uint centralDirectoryOffset = (uint)writer.WrittenByteLength;
            for(int i = 0; i < written.Count; ++i)
            {
                WriteCentralDirectoryHeader(writer, written[i]);
            }

            uint centralDirectoryByteLength = (uint)writer.WrittenByteLength - centralDirectoryOffset;

            writer.WriteUInt32(EndOfCentralDirectorySignature);
            writer.WriteUInt16(0);
            writer.WriteUInt16(0);
            writer.WriteUInt16((ushort)written.Count);
            writer.WriteUInt16((ushort)written.Count);
            writer.WriteUInt32(centralDirectoryByteLength);
            writer.WriteUInt32(centralDirectoryOffset);
            writer.WriteUInt16((ushort)commentByteLength);
            if(commentByteLength > 0)
            {
                _ = writer.WriteUtf8(context.ArchiveComment!);
            }

            return writer.Detach(AsicTags.Container);
        }
        finally
        {
            writer.Dispose();
        }
    }


    /// <summary>
    /// Turns a context into the exact sequence of entries the container is written from, with the
    /// <c>mimetype</c> entry first when a media type is stated, and refuses everything a container cannot carry.
    /// </summary>
    /// <param name="context">The context to plan.</param>
    /// <returns>The entries in write order.</returns>
    /// <exception cref="AsicZipAuthoringException">When the context does not describe a container this library writes.</exception>
    private static List<PlannedEntry> PlanEntries(AsicZipAuthoringContext context)
    {
        ArgumentNullException.ThrowIfNull(context.Entries);

        if(context.Entries.Count == 0)
        {
            throw new AsicZipAuthoringException(
                AsicZipAuthoringFailureKind.NoEntries,
                "A container carries at least one file object (ETSI EN 319 162-1 clause 4.3.3.2 item 2, clause 4.4.2 item 2).");
        }

        if(context.Entries.Count + 1 > MaximumEntryCount)
        {
            throw new AsicZipAuthoringException(
                AsicZipAuthoringFailureKind.EntryCountExceeded,
                $"A container is written with at most {MaximumEntryCount} entries.");
        }

        var planned = new List<PlannedEntry>(context.Entries.Count + 1);
        var names = new HashSet<string>(StringComparer.Ordinal);

        if(context.MediaType is not null)
        {
            planned.Add(new PlannedEntry(
                AsicWellKnown.MimetypeEntryName,
                StateMediaTypeOctets(context.MediaType),
                AsicZipCompressionMethod.Stored,
                context.LastModified));
            _ = names.Add(AsicWellKnown.MimetypeEntryName);
        }

        for(int i = 0; i < context.Entries.Count; ++i)
        {
            AsicZipEntrySource source = context.Entries[i];
            ArgumentNullException.ThrowIfNull(source);

            if(AsicWellKnown.IsMimetypeEntryName(source.Name))
            {
                throw new AsicZipAuthoringException(
                    AsicZipAuthoringFailureKind.MimetypeEntrySuppliedDirectly,
                    "The \"mimetype\" entry is written from AsicZipAuthoringContext.MediaType, because ETSI EN 319 162-1 Annex A.1 binds its position, its compression method and its extra field length together.");
            }

            AsicZipEntryNameStatus nameStatus = AsicZipEntryNaming.Validate(source.Name, MaximumEntryNameByteLength);
            if(nameStatus != AsicZipEntryNameStatus.Accepted)
            {
                throw new AsicZipAuthoringException(
                    AsicZipAuthoringFailureKind.EntryNameRejected,
                    $"The entry name \"{source.Name}\" was refused as {nameStatus} (ETSI EN 319 162-1 Annex A.6).");
            }

            if(!names.Add(source.Name))
            {
                throw new AsicZipAuthoringException(
                    AsicZipAuthoringFailureKind.DuplicateEntryName,
                    $"The entry name \"{source.Name}\" is written twice, so the container would name one file object twice.");
            }

            if(source.Content.Length > MaximumEntryByteLength)
            {
                throw new AsicZipAuthoringException(
                    AsicZipAuthoringFailureKind.EntryTooLarge,
                    $"The entry \"{source.Name}\" holds {source.Content.Length} octets, and an entry is written with at most {MaximumEntryByteLength}.");
            }

            _ = source.CompressionMethod switch
            {
                AsicZipCompressionMethod.Stored or AsicZipCompressionMethod.Deflated => true,
                _ => throw new AsicZipAuthoringException(
                    AsicZipAuthoringFailureKind.UnsupportedCompressionMethod,
                    $"The entry \"{source.Name}\" states compression method {(int)source.CompressionMethod}; ETSI EN 319 162-1 clause 4.2 item 2 c admits 0 (stored) and 8 (deflated).")
            };

            planned.Add(new PlannedEntry(source.Name, source.Content, source.CompressionMethod, source.LastModified ?? context.LastModified));
        }

        return planned;
    }


    /// <summary>
    /// Encodes a media type into the octets the <c>mimetype</c> entry carries, refusing anything that would make
    /// the Annex A.1 NOTE's recognition feature state something other than a media type.
    /// </summary>
    /// <param name="mediaType">The media type to write.</param>
    /// <returns>The entry's octets.</returns>
    /// <exception cref="AsicZipAuthoringException">When the value is not a media type this library writes.</exception>
    private static ReadOnlyMemory<byte> StateMediaTypeOctets(string mediaType)
    {
        if(mediaType.Length == 0 || Encoding.UTF8.GetByteCount(mediaType) > MaximumMediaTypeByteLength)
        {
            throw new AsicZipAuthoringException(
                AsicZipAuthoringFailureKind.MediaTypeRejected,
                $"A container's media type is between 1 and {MaximumMediaTypeByteLength} octets (ETSI EN 319 162-1 Annex A.1).");
        }

        byte[] octets = Encoding.UTF8.GetBytes(mediaType);
        for(int i = 0; i < octets.Length; ++i)
        {
            if(octets[i] < SmallestPrintableAscii || octets[i] > LargestPrintableAscii)
            {
                throw new AsicZipAuthoringException(
                    AsicZipAuthoringFailureKind.MediaTypeRejected,
                    "A container's media type is printable ASCII with no white space (IETF RFC 2045 clause 5.1); the value carries an octet that is not.");
            }
        }

        return octets;
    }


    /// <summary>
    /// States how many UTF-8 octets the archive comment occupies, refusing one longer than a container carries.
    /// </summary>
    /// <param name="comment">The archive comment, or <see langword="null"/>.</param>
    /// <returns>The comment's octet count, or zero when there is none.</returns>
    /// <exception cref="AsicZipAuthoringException">When the comment exceeds <see cref="MaximumArchiveCommentByteLength"/>.</exception>
    private static int StateCommentByteLength(string? comment)
    {
        if(comment is null || comment.Length == 0)
        {
            return 0;
        }

        int byteLength = Encoding.UTF8.GetByteCount(comment);
        if(byteLength > MaximumArchiveCommentByteLength)
        {
            throw new AsicZipAuthoringException(
                AsicZipAuthoringFailureKind.CommentTooLong,
                $"A container's ZIP comment is written with at most {MaximumArchiveCommentByteLength} octets.");
        }

        return byteLength;
    }


    /// <summary>
    /// Writes one entry's local file header and its data, and returns what the central directory has to repeat.
    /// </summary>
    /// <param name="writer">The buffer the container is being written into.</param>
    /// <param name="entry">The entry to write.</param>
    /// <returns>The fields the entry's central directory header states.</returns>
    /// <exception cref="AsicZipAuthoringException">When the entry's instant is not representable, or the container outgrows its bound.</exception>
    private static WrittenEntry WriteEntry(PooledZipWriter writer, PlannedEntry entry)
    {
        (ushort dosTime, ushort dosDate) = ToDosDateTime(entry.LastModified);
        uint crc = ComputeCrc32(entry.Content.Span);
        ushort versionNeeded = entry.CompressionMethod == AsicZipCompressionMethod.Deflated ? VersionNeededDeflated : VersionNeededStored;
        int nameByteLength = Encoding.UTF8.GetByteCount(entry.Name);
        uint localHeaderOffset = (uint)writer.WrittenByteLength;

        writer.WriteUInt32(LocalFileHeaderSignature);
        writer.WriteUInt16(versionNeeded);
        writer.WriteUInt16(GeneralPurposeUtf8NameFlag);
        writer.WriteUInt16((ushort)entry.CompressionMethod);
        writer.WriteUInt16(dosTime);
        writer.WriteUInt16(dosDate);
        writer.WriteUInt32(crc);

        //The compressed size is written now and patched after the data, because a deflated entry's length is
        //only known once it has been produced. Patching keeps the size in the header where a reader expects it;
        //the alternative the ZIP format offers — general purpose bit 3 and a trailing data descriptor — is what
        //ETSI EN 319 162-1 Annex A.1 forbids for the "mimetype" entry, and this library writes no entry that way.
        int compressedSizeOffset = writer.WrittenByteLength;
        writer.WriteUInt32(0);
        writer.WriteUInt32((uint)entry.Content.Length);
        writer.WriteUInt16((ushort)nameByteLength);

        //The extra field length is zero for every entry, which is what ETSI EN 319 162-1 Annex A.1 item 2
        //requires of the "mimetype" entry ("extra field length at offset 28 shall be set to zero") and what
        //keeps the container's media type readable at AsicWellKnown.MediaTypeOffset.
        writer.WriteUInt16(0);
        _ = writer.WriteUtf8(entry.Name);

        int dataOffset = writer.WrittenByteLength;
        if(entry.CompressionMethod == AsicZipCompressionMethod.Deflated)
        {
            using(var deflate = new DeflateStream(writer, CompressionLevel.Optimal, leaveOpen: true))
            {
                deflate.Write(entry.Content.Span);
            }
        }
        else
        {
            writer.Write(entry.Content.Span);
        }

        uint compressedByteLength = (uint)(writer.WrittenByteLength - dataOffset);
        writer.PatchUInt32(compressedSizeOffset, compressedByteLength);

        return new WrittenEntry(
            entry.Name,
            nameByteLength,
            entry.CompressionMethod,
            dosTime,
            dosDate,
            crc,
            compressedByteLength,
            (uint)entry.Content.Length,
            localHeaderOffset);
    }


    /// <summary>
    /// Writes one entry's central directory file header.
    /// </summary>
    /// <param name="writer">The buffer the container is being written into.</param>
    /// <param name="entry">The entry whose local header was already written.</param>
    private static void WriteCentralDirectoryHeader(PooledZipWriter writer, WrittenEntry entry)
    {
        ushort versionNeeded = entry.CompressionMethod == AsicZipCompressionMethod.Deflated ? VersionNeededDeflated : VersionNeededStored;

        writer.WriteUInt32(CentralDirectoryHeaderSignature);
        writer.WriteUInt16(VersionMadeBy);
        writer.WriteUInt16(versionNeeded);
        writer.WriteUInt16(GeneralPurposeUtf8NameFlag);
        writer.WriteUInt16((ushort)entry.CompressionMethod);
        writer.WriteUInt16(entry.DosTime);
        writer.WriteUInt16(entry.DosDate);
        writer.WriteUInt32(entry.Crc32);
        writer.WriteUInt32(entry.CompressedByteLength);
        writer.WriteUInt32(entry.UncompressedByteLength);
        writer.WriteUInt16((ushort)entry.NameByteLength);
        writer.WriteUInt16(0);
        writer.WriteUInt16(0);

        //Disk number start, internal file attributes and external file attributes are all zero: the first
        //because ETSI EN 319 162-1 clause 4.2 item 2 a forbids split archives, the last because an external
        //attribute would record the writing platform's file mode in the container's octets.
        writer.WriteUInt16(0);
        writer.WriteUInt16(0);
        writer.WriteUInt32(0);
        writer.WriteUInt32(entry.LocalHeaderOffset);
        _ = writer.WriteUtf8(entry.Name);
    }


    /// <summary>
    /// Estimates how many octets a container needs, so the buffer it is written into is rented once.
    /// </summary>
    /// <param name="planned">The entries in write order.</param>
    /// <param name="commentByteLength">The archive comment's octet count.</param>
    /// <returns>An initial capacity, never below one octet.</returns>
    private static int EstimateContainerByteLength(List<PlannedEntry> planned, int commentByteLength)
    {
        long estimate = EndOfCentralDirectoryByteLength + commentByteLength;
        for(int i = 0; i < planned.Count; ++i)
        {
            estimate += LocalFileHeaderByteLength + CentralDirectoryHeaderByteLength;
            estimate += 2L * Encoding.UTF8.GetByteCount(planned[i].Name);
            estimate += planned[i].Content.Length;
        }

        return (int)Math.Clamp(estimate, 1, MaximumContainerByteLength);
    }


    /// <summary>
    /// Converts an instant to the MS-DOS date and time fields a ZIP header records.
    /// </summary>
    /// <param name="instant">The instant to record.</param>
    /// <returns>The time and date fields, in that order.</returns>
    /// <exception cref="AsicZipAuthoringException">When the instant lies outside the range MS-DOS date fields represent.</exception>
    /// <remarks>
    /// The instant is converted to UTC first, so a container's octets do not record the offset of whoever wrote
    /// it. The two-second resolution of the MS-DOS time field is the format's; an odd second is recorded as the
    /// even second below it, which <see cref="AsicZipReading"/> recovers as such.
    /// </remarks>
    private static (ushort Time, ushort Date) ToDosDateTime(DateTimeOffset instant)
    {
        if(instant < EarliestRepresentableInstant || instant > LatestRepresentableInstant)
        {
            throw new AsicZipAuthoringException(
                AsicZipAuthoringFailureKind.InstantNotRepresentable,
                $"A ZIP header records an instant between {EarliestRepresentableInstant:O} and {LatestRepresentableInstant:O}; {instant:O} is outside that range.");
        }

        DateTime utc = instant.UtcDateTime;
        ushort time = (ushort)((utc.Hour << 11) | (utc.Minute << 5) | (utc.Second / 2));
        ushort date = (ushort)(((utc.Year - DosEpochYear) << 9) | (utc.Month << 5) | utc.Day);

        return (time, date);
    }


    /// <summary>
    /// Computes the CRC-32 of <see href="https://www.rfc-editor.org/rfc/rfc1952#section-8">IETF RFC 1952 clause
    /// 8</see> over an entry's uncompressed octets.
    /// </summary>
    /// <param name="data">The octets to checksum.</param>
    /// <returns>The CRC-32 value the entry's headers record.</returns>
    /// <remarks>See <see cref="Crc32Table"/> for why this is not computed through the registered digest seam.</remarks>
    internal static uint ComputeCrc32(ReadOnlySpan<byte> data)
    {
        uint[] table = Crc32Table;
        uint crc = 0xFFFFFFFFu;
        for(int i = 0; i < data.Length; ++i)
        {
            crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
        }

        return crc ^ 0xFFFFFFFFu;
    }


    /// <summary>
    /// Builds the CRC-32 lookup table from the reversed polynomial <c>0xEDB88320</c>.
    /// </summary>
    /// <returns>The 256-entry table.</returns>
    private static uint[] BuildCrc32Table()
    {
        const uint ReversedPolynomial = 0xEDB88320u;

        uint[] table = new uint[256];
        for(uint i = 0; i < table.Length; ++i)
        {
            uint value = i;
            for(int bit = 0; bit < 8; ++bit)
            {
                value = (value & 1) != 0 ? (value >> 1) ^ ReversedPolynomial : value >> 1;
            }

            table[i] = value;
        }

        return table;
    }


    /// <summary>One entry as the authoring resolved it, before anything has been written.</summary>
    /// <param name="Name">The entry name.</param>
    /// <param name="Content">The entry's uncompressed octets.</param>
    /// <param name="CompressionMethod">How the octets are stored.</param>
    /// <param name="LastModified">The instant the entry records.</param>
    private readonly record struct PlannedEntry(
        string Name,
        ReadOnlyMemory<byte> Content,
        AsicZipCompressionMethod CompressionMethod,
        DateTimeOffset LastModified);


    /// <summary>One entry as it was written, carrying what its central directory header has to repeat.</summary>
    /// <param name="Name">The entry name.</param>
    /// <param name="NameByteLength">The name's UTF-8 octet count.</param>
    /// <param name="CompressionMethod">The method the local header states.</param>
    /// <param name="DosTime">The MS-DOS time field.</param>
    /// <param name="DosDate">The MS-DOS date field.</param>
    /// <param name="Crc32">The CRC-32 of the uncompressed octets.</param>
    /// <param name="CompressedByteLength">The octet count of the data as written.</param>
    /// <param name="UncompressedByteLength">The octet count of the data before compression.</param>
    /// <param name="LocalHeaderOffset">The offset the entry's local file header begins at.</param>
    private readonly record struct WrittenEntry(
        string Name,
        int NameByteLength,
        AsicZipCompressionMethod CompressionMethod,
        ushort DosTime,
        ushort DosDate,
        uint Crc32,
        uint CompressedByteLength,
        uint UncompressedByteLength,
        uint LocalHeaderOffset);


    /// <summary>
    /// A write-only, randomly patchable buffer over pooled memory, which a <see cref="DeflateStream"/> can be
    /// pointed at directly.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Two properties motivate it. A container is built in one buffer rented from the caller's pool rather than
    /// in a managed array, which is what the rest of this library does with octets of any size; and a field
    /// already written can be patched, which is what lets a deflated entry's compressed size sit in its local
    /// file header instead of in a trailing data descriptor.
    /// </para>
    /// <para>
    /// It is a <see cref="Stream"/> only because <see cref="DeflateStream"/> writes to one. Nothing seeks it and
    /// nothing reads it, so those members refuse rather than pretend.
    /// </para>
    /// </remarks>
    private sealed class PooledZipWriter: Stream
    {
        /// <summary>The pool every buffer of this writer is rented from.</summary>
        private readonly BaseMemoryPool pool;

        /// <summary>The largest number of octets this writer accepts.</summary>
        private readonly int maximumByteLength;

        /// <summary>The current buffer, or <see langword="null"/> once it has been detached or disposed.</summary>
        private IMemoryOwner<byte>? buffer;

        /// <summary>How many octets of <see cref="buffer"/> have been written.</summary>
        private int written;


        /// <summary>
        /// Initializes a new writer over a buffer rented from a pool.
        /// </summary>
        /// <param name="pool">The pool to rent from.</param>
        /// <param name="initialByteLength">The capacity to rent first.</param>
        /// <param name="maximumByteLength">The largest number of octets this writer accepts.</param>
        public PooledZipWriter(BaseMemoryPool pool, int initialByteLength, int maximumByteLength)
        {
            this.pool = pool;
            this.maximumByteLength = maximumByteLength;
            buffer = pool.Rent(initialByteLength);
        }


        /// <summary>Gets how many octets have been written.</summary>
        public int WrittenByteLength => written;

        /// <inheritdoc/>
        public override bool CanRead => false;

        /// <inheritdoc/>
        public override bool CanSeek => false;

        /// <inheritdoc/>
        public override bool CanWrite => true;

        /// <inheritdoc/>
        public override long Length => throw new NotSupportedException("A container writer is not seekable; its written length is AsicZipAuthoring.PooledZipWriter.WrittenByteLength.");

        /// <inheritdoc/>
        public override long Position
        {
            get => throw new NotSupportedException("A container writer is not seekable.");
            set => throw new NotSupportedException("A container writer is not seekable.");
        }


        /// <inheritdoc/>
        public override void Flush()
        {
        }


        /// <inheritdoc/>
        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException("A container writer is write-only.");


        /// <inheritdoc/>
        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException("A container writer is not seekable.");


        /// <inheritdoc/>
        public override void SetLength(long value) =>
            throw new NotSupportedException("A container writer grows as it is written to.");


        /// <inheritdoc/>
        public override void Write(byte[] buffer, int offset, int count)
        {
            ArgumentNullException.ThrowIfNull(buffer);

            Write(new ReadOnlySpan<byte>(buffer, offset, count));
        }


        /// <inheritdoc/>
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            Span<byte> destination = Reserve(buffer.Length);
            buffer.CopyTo(destination);
        }


        /// <summary>
        /// Writes a sixteen-bit field in the little-endian order Annex A.1 item 5 requires: "All multi-octets
        /// values shall be little-endian."
        /// </summary>
        /// <param name="value">The value to write.</param>
        public void WriteUInt16(ushort value) => BinaryPrimitives.WriteUInt16LittleEndian(Reserve(sizeof(ushort)), value);


        /// <summary>Writes a thirty-two-bit field in little-endian order (Annex A.1 item 5).</summary>
        /// <param name="value">The value to write.</param>
        public void WriteUInt32(uint value) => BinaryPrimitives.WriteUInt32LittleEndian(Reserve(sizeof(uint)), value);


        /// <summary>
        /// Writes a string as UTF-8, which clause 4.2 item 2 b requires of every name and comment a container
        /// carries.
        /// </summary>
        /// <param name="value">The string to write.</param>
        /// <returns>How many octets it occupied.</returns>
        public int WriteUtf8(string value)
        {
            int byteLength = Encoding.UTF8.GetByteCount(value);
            Span<byte> destination = Reserve(byteLength);

            return Encoding.UTF8.GetBytes(value, destination);
        }


        /// <summary>Overwrites a thirty-two-bit field that has already been written.</summary>
        /// <param name="offset">The octet offset of the field.</param>
        /// <param name="value">The value to write there.</param>
        public void PatchUInt32(int offset, uint value) =>
            BinaryPrimitives.WriteUInt32LittleEndian(CurrentBuffer.Memory.Span.Slice(offset, sizeof(uint)), value);


        /// <summary>
        /// Hands the written octets over as a pooled carrier and gives up ownership of the buffer.
        /// </summary>
        /// <param name="tag">The tag the carrier is created with.</param>
        /// <returns>The carrier, which the caller owns and disposes.</returns>
        public PooledMemory Detach(Tag tag)
        {
            IMemoryOwner<byte> owner = CurrentBuffer;
            buffer = null;

            return new PooledMemory(owner, written, tag);
        }


        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            if(disposing && buffer is not null)
            {
                buffer.Memory.Span[..written].Clear();
                buffer.Dispose();
                buffer = null;
            }

            base.Dispose(disposing);
        }


        /// <summary>Gets the current buffer, or fails when it has been detached or disposed.</summary>
        private IMemoryOwner<byte> CurrentBuffer =>
            buffer ?? throw new ObjectDisposedException(nameof(PooledZipWriter), "The container's buffer has been handed over.");


        /// <summary>
        /// Makes room for a field and advances past it, growing the buffer when it does not fit.
        /// </summary>
        /// <param name="byteLength">How many octets to reserve.</param>
        /// <returns>The reserved span, which the caller writes into.</returns>
        /// <exception cref="AsicZipAuthoringException">When the container would exceed its bound.</exception>
        private Span<byte> Reserve(int byteLength)
        {
            long required = (long)written + byteLength;
            if(required > maximumByteLength)
            {
                throw new AsicZipAuthoringException(
                    AsicZipAuthoringFailureKind.ContainerTooLarge,
                    $"A container is written with at most {maximumByteLength} octets.");
            }

            IMemoryOwner<byte> current = CurrentBuffer;
            if(required > current.Memory.Length)
            {
                long grown = Math.Min((long)current.Memory.Length * 2, maximumByteLength);
                IMemoryOwner<byte> replacement = pool.Rent((int)Math.Max(grown, required));
                current.Memory.Span[..written].CopyTo(replacement.Memory.Span);
                current.Memory.Span[..written].Clear();
                current.Dispose();
                buffer = replacement;
                current = replacement;
            }

            Span<byte> reserved = current.Memory.Span.Slice(written, byteLength);
            written += byteLength;

            return reserved;
        }
    }
}
