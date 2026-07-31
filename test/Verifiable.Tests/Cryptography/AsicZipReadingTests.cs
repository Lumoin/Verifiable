using System;
using System.Collections.Generic;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="AsicZipReading"/>: what a reader concludes about a container it did not
/// make, against the rules Annex A.1, clause 4.2 and Annex A.6 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> state, and against the ways an archive is a denial of service rather than a
/// container.
/// </summary>
/// <remarks>
/// <para>
/// Every hostile input here is a real archive rather than a mutated field: <see cref="AsicZipStructureOracle"/>
/// writes the ZIP structures itself, so a <c>mimetype</c> entry that is second, one that is compressed, one that
/// carries an extra field, a name that escapes the container and an entry that lies about its own size all
/// exist as octets a producer could actually hand over. A test that only corrupted a byte of a well-formed
/// container would never reach the rules that are about which entry comes first.
/// </para>
/// <para>
/// Nothing in this class expects an exception from the reader. A container is attacker-supplied, so every way
/// it can be wrong is an <see cref="AsicZipReadStatus"/>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class AsicZipReadingTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The instant every container in this class records.</summary>
    private static DateTimeOffset Instant { get; } = TestClock.CanonicalEpoch;


    /// <summary>
    /// A container this library wrote reads back with every entry's name, octets, method and instant unchanged,
    /// with its media type recognised, and with the archive comment it carries.
    /// </summary>
    [TestMethod]
    public void AContainerThisLibraryWroteReadsBackUnchanged()
    {
        byte[] dataObject = [.. "the signed data object"u8];
        byte[] manifest = [.. "<asic:ASiCManifest/>"u8];
        DateTimeOffset older = Instant.AddDays(-30);

        using PooledMemory container = AsicZipAuthoring.Write(
            new AsicZipAuthoringContext
            {
                MediaType = AsicWellKnown.AsicExtendedMediaType,
                Entries =
                [
                    new AsicZipEntrySource { Name = "data/sopimus-\u00e4\u00e4ni.txt", Content = dataObject, LastModified = older },
                    new AsicZipEntrySource { Name = "META-INF/ASiCManifest1.xml", Content = manifest, CompressionMethod = AsicZipCompressionMethod.Deflated }
                ],
                LastModified = Instant,
                ArchiveComment = AsicWellKnown.MediaTypeComment(AsicWellKnown.AsicExtendedMediaType)
            },
            BaseMemoryPool.Shared);

        using AsicZipReadResult result = AsicZipReading.Read(container.AsReadOnlyMemory(), AsicZipReadLimits.Conformant, BaseMemoryPool.Shared);

        Assert.AreEqual(AsicZipReadStatus.Read, result.Status);
        Assert.IsTrue(result.IsRead);

        AsicZipContainer read = result.Container!;
        Assert.AreEqual(AsicWellKnown.AsicExtendedMediaType, read.MediaType);
        Assert.IsTrue(read.MediaTypeReadableAtOffset38, "Annex A.1's recognition feature holds for a container this library wrote.");
        Assert.AreEqual(AsicWellKnown.AsicExtendedMediaType, read.CommentMediaType);
        Assert.HasCount(3, read.Entries, "The mimetype entry and the two stated entries.");

        Assert.AreEqual(AsicWellKnown.MimetypeEntryName, read.Entries[0].Name);
        Assert.AreEqual(AsicZipCompressionMethod.Stored, read.Entries[0].CompressionMethod);

        AsicZipEntry data = read.FindEntry("data/sopimus-\u00e4\u00e4ni.txt")!;
        Assert.IsTrue(data.Content.AsReadOnlySpan().SequenceEqual(dataObject), "A stored entry reads back as the octets it was written from.");
        Assert.AreEqual(older, data.LastModified);
        Assert.IsFalse(data.IsMetaInf);
        Assert.AreEqual(AsicObjectKind.ContainerEntry, data.Content.Tag.Get<AsicObjectKind>());

        AsicZipEntry metadata = read.FindEntry("META-INF/ASiCManifest1.xml")!;
        Assert.IsTrue(metadata.Content.AsReadOnlySpan().SequenceEqual(manifest), "A deflated entry inflates back to the octets it was written from.");
        Assert.AreEqual(AsicZipCompressionMethod.Deflated, metadata.CompressionMethod);
        Assert.AreEqual(Instant, metadata.LastModified);
        Assert.IsTrue(metadata.IsMetaInf);
    }


    /// <summary>
    /// A container carrying no <c>mimetype</c> entry reads, because clauses 4.3.3.2 item 1 and 4.4.4.2 item 1
    /// both make the entry a "may"; it simply states no media type and no recognition at offset 38.
    /// </summary>
    [TestMethod]
    public void AContainerWithNoMimetypeEntryReadsAndStatesNoMediaType()
    {
        using PooledMemory container = AsicZipAuthoring.Write(
            new AsicZipAuthoringContext
            {
                MediaType = null,
                Entries = [new AsicZipEntrySource { Name = "data.txt", Content = "data"u8.ToArray() }],
                LastModified = Instant
            },
            BaseMemoryPool.Shared);

        using AsicZipReadResult result = AsicZipReading.Read(container.AsReadOnlyMemory(), AsicZipReadLimits.Conformant, BaseMemoryPool.Shared);

        Assert.AreEqual(AsicZipReadStatus.Read, result.Status);
        Assert.IsNull(result.Container!.MediaType);
        Assert.IsFalse(result.Container.MediaTypeReadableAtOffset38);
    }


    /// <summary>
    /// A <c>mimetype</c> entry that is not the first file is refused — Annex A.1 item 1: ""mimetype" shall be
    /// the first file in the ASiC container."
    /// </summary>
    [TestMethod]
    public void AMimetypeEntryThatIsNotFirstIsRefused()
    {
        byte[] archive = AsicZipStructureOracle.BuildRawArchive(new RawZipArchiveSpec
        {
            Entries =
            [
                RawEntry("data.txt", [.. "data"u8]),
                RawEntry(AsicWellKnown.MimetypeEntryName, [.. "application/vnd.etsi.asic-e+zip"u8])
            ]
        });

        AssertRefused(archive, AsicZipReadStatus.MimetypeNotFirstEntry);
    }


    /// <summary>
    /// A compressed <c>mimetype</c> entry is refused — Annex A.1 item 3: ""mimetype" shall not be compressed
    /// (i.e. compression method in its ZIP header at offset 8 shall be set to zero)."
    /// </summary>
    [TestMethod]
    public void ACompressedMimetypeEntryIsRefused()
    {
        byte[] archive = AsicZipStructureOracle.BuildRawArchive(new RawZipArchiveSpec
        {
            Entries =
            [
                RawEntry(AsicWellKnown.MimetypeEntryName, [.. "application/vnd.etsi.asic-e+zip"u8]) with { Method = 8 },
                RawEntry("data.txt", [.. "data"u8])
            ]
        });

        AssertRefused(archive, AsicZipReadStatus.MimetypeCompressed);
    }


    /// <summary>
    /// A <c>mimetype</c> entry carrying an extra field is refused — Annex A.1 item 2: ""mimetype" shall not
    /// contain "Extra fields" in its ZIP header (i.e. extra field length at offset 28 shall be set to zero)".
    /// The extra field is exactly what moves the media type away from offset 38, so this is the rule the whole
    /// recognition feature rests on.
    /// </summary>
    [TestMethod]
    public void AMimetypeEntryCarryingAnExtraFieldIsRefused()
    {
        byte[] archive = AsicZipStructureOracle.BuildRawArchive(new RawZipArchiveSpec
        {
            Entries =
            [
                RawEntry(AsicWellKnown.MimetypeEntryName, [.. "application/vnd.etsi.asic-e+zip"u8]) with { ExtraField = [0x55, 0x54, 0x05, 0x00] },
                RawEntry("data.txt", [.. "data"u8])
            ]
        });

        AssertRefused(archive, AsicZipReadStatus.MimetypeCarriesExtraField);
    }


    /// <summary>
    /// A <c>mimetype</c> entry that states its sizes in a trailing data descriptor is refused: the four octets
    /// at offset 18 the Annex A.1 NOTE reads the media type's length from then state zero.
    /// </summary>
    [TestMethod]
    public void AMimetypeEntryUsingADataDescriptorIsRefused()
    {
        byte[] archive = AsicZipStructureOracle.BuildRawArchive(new RawZipArchiveSpec
        {
            Entries =
            [
                RawEntry(AsicWellKnown.MimetypeEntryName, [.. "application/vnd.etsi.asic-e+zip"u8]) with { Flags = 0x0008 },
                RawEntry("data.txt", [.. "data"u8])
            ]
        });

        AssertRefused(archive, AsicZipReadStatus.MimetypeUsesDataDescriptor);
    }


    /// <summary>
    /// An encrypted entry is refused. Annex A.1 item 6 forbids encrypting the <c>mimetype</c> entry outright,
    /// and the NOTE under Table 1 gives excluding encryption as the purpose of the ISO/IEC 21320-1 conformance
    /// clause 5.3.1 item a requires of baseline containers.
    /// </summary>
    [TestMethod]
    public void AnEncryptedEntryIsRefused()
    {
        byte[] archive = AsicZipStructureOracle.BuildRawArchive(new RawZipArchiveSpec
        {
            Entries = [RawEntry("secret.bin", [.. "data"u8]) with { Flags = 0x0001 }]
        });

        AssertRefused(archive, AsicZipReadStatus.EntryEncrypted);
    }


    /// <summary>
    /// An archive declaring a disk other than the first is refused — clause 4.2 item 2 a: "ASiC containers
    /// shall not use the multiple volumes split feature."
    /// </summary>
    [TestMethod]
    public void ASplitArchiveIsRefused()
    {
        byte[] archive = AsicZipStructureOracle.BuildRawArchive(new RawZipArchiveSpec
        {
            Entries = [RawEntry("data.txt", [.. "data"u8])],
            DiskNumber = 1
        });

        AssertRefused(archive, AsicZipReadStatus.SplitArchiveDeclared);
    }


    /// <summary>
    /// An archive carrying the ZIP64 locator is refused: a container of the sizes this library reads within
    /// never needs the ZIP64 extensions, so an archive that declares them is out of scope rather than one to be
    /// read part-way.
    /// </summary>
    [TestMethod]
    public void AnArchiveDeclaringZip64IsRefused()
    {
        byte[] archive = AsicZipStructureOracle.BuildRawArchive(new RawZipArchiveSpec
        {
            Entries = [RawEntry("data.txt", [.. "data"u8])],
            IncludeZip64Locator = true
        });

        AssertRefused(archive, AsicZipReadStatus.Zip64Required);
    }


    /// <summary>
    /// A name that names something other than a file object inside the container is refused, and the reason it
    /// was refused is reported — Annex A.6 item 3: "References to data objects outside the container shall not
    /// be allowed."
    /// </summary>
    /// <param name="entryName">The name the archive carries.</param>
    /// <param name="expected">Why it is refused.</param>
    [TestMethod]
    [DataRow("../outside.txt", AsicZipEntryNameStatus.Traversal, DisplayName = "a parent segment")]
    [DataRow("data/../../outside.txt", AsicZipEntryNameStatus.Traversal, DisplayName = "a parent segment further in")]
    [DataRow("/absolute.txt", AsicZipEntryNameStatus.Absolute, DisplayName = "an absolute path")]
    [DataRow("data\\windows.txt", AsicZipEntryNameStatus.BackslashSeparator, DisplayName = "a backslash separator")]
    [DataRow("C:/volume.txt", AsicZipEntryNameStatus.VolumeQualified, DisplayName = "a volume qualifier")]
    [DataRow("data//empty.txt", AsicZipEntryNameStatus.EmptySegment, DisplayName = "an empty segment")]
    [DataRow("./here.txt", AsicZipEntryNameStatus.Traversal, DisplayName = "a current-folder segment")]
    public void ANameThatEscapesTheContainerIsRefused(string entryName, AsicZipEntryNameStatus expected)
    {
        byte[] archive = AsicZipStructureOracle.BuildRawArchive(new RawZipArchiveSpec
        {
            Entries = [RawEntry(entryName, [.. "data"u8])]
        });

        using AsicZipReadResult result = Read(archive, AsicZipReadLimits.Conformant);
        Assert.AreEqual(AsicZipReadStatus.EntryNameRejected, result.Status);
        Assert.AreEqual(expected, result.RejectedEntryNameStatus);
    }


    /// <summary>
    /// Two entries under one name are refused: a manifest reference to that name would resolve to neither of
    /// them in particular, which is a way to have a digest checked against one file object and a signature
    /// applied to another.
    /// </summary>
    [TestMethod]
    public void TwoEntriesUnderOneNameAreRefused()
    {
        byte[] archive = AsicZipStructureOracle.BuildRawArchive(new RawZipArchiveSpec
        {
            Entries = [RawEntry("data.txt", [.. "first"u8]), RawEntry("data.txt", [.. "second"u8])]
        });

        AssertRefused(archive, AsicZipReadStatus.DuplicateEntryName);
    }


    /// <summary>
    /// A compression method other than the two clause 4.2 item 2 c admits is refused rather than passed to a
    /// codec this library does not name.
    /// </summary>
    [TestMethod]
    public void ACompressionMethodOutsideClause42Item2CIsRefused()
    {
        byte[] archive = AsicZipStructureOracle.BuildRawArchive(new RawZipArchiveSpec
        {
            Entries = [RawEntry("data.txt", [.. "data"u8]) with { Method = 12 }]
        });

        AssertRefused(archive, AsicZipReadStatus.UnsupportedCompressionMethod);
    }


    /// <summary>
    /// An entry that expands by more than the caller admits is refused before its stream is opened. The archive
    /// here is a real bomb: a mebibyte of one repeated octet, which deflate stores in about a kibibyte.
    /// </summary>
    [TestMethod]
    public void AnEntryThatExpandsBeyondTheRatioIsRefused()
    {
        byte[] bomb = new byte[1024 * 1024];
        using PooledMemory container = AsicZipAuthoring.Write(
            new AsicZipAuthoringContext
            {
                MediaType = AsicWellKnown.AsicExtendedMediaType,
                Entries = [new AsicZipEntrySource { Name = "bomb.bin", Content = bomb, CompressionMethod = AsicZipCompressionMethod.Deflated }],
                LastModified = Instant
            },
            BaseMemoryPool.Shared);

        using AsicZipReadResult result = AsicZipReading.Read(container.AsReadOnlyMemory(), AsicZipReadLimits.Conformant, BaseMemoryPool.Shared);
        Assert.AreEqual(AsicZipReadStatus.CompressionRatioExceeded, result.Status);
        Assert.AreEqual("bomb.bin", result.RejectedEntryName);
    }


    /// <summary>
    /// The caller's bounds are hard: an archive holding more entries, more octets, a longer comment or more
    /// octets in total than the caller admits is refused rather than read part-way.
    /// </summary>
    /// <param name="limits">The bounds to read within.</param>
    /// <param name="expected">What the reader concludes.</param>
    [TestMethod]
    [DynamicData(nameof(BoundedReadCases))]
    public void ABoundTheCallerStatedIsAHardError(AsicZipReadLimits limits, AsicZipReadStatus expected)
    {
        using PooledMemory container = AsicZipAuthoring.Write(
            new AsicZipAuthoringContext
            {
                MediaType = AsicWellKnown.AsicExtendedMediaType,
                Entries =
                [
                    new AsicZipEntrySource { Name = "data.txt", Content = "the signed data object"u8.ToArray() },
                    new AsicZipEntrySource { Name = "META-INF/signature1.p7s", Content = "signature"u8.ToArray() }
                ],
                LastModified = Instant,
                ArchiveComment = AsicWellKnown.MediaTypeComment(AsicWellKnown.AsicExtendedMediaType)
            },
            BaseMemoryPool.Shared);

        using AsicZipReadResult result = AsicZipReading.Read(container.AsReadOnlyMemory(), limits, BaseMemoryPool.Shared);
        Assert.AreEqual(expected, result.Status);
    }


    /// <summary>The bounds and the conclusions <see cref="ABoundTheCallerStatedIsAHardError"/> checks.</summary>
    private static IEnumerable<object[]> BoundedReadCases =>
    [
        [AsicZipReadLimits.Conformant with { MaximumEntryCount = 2 }, AsicZipReadStatus.EntryCountExceeded],
        [AsicZipReadLimits.Conformant with { MaximumEntryUncompressedByteLength = 4 }, AsicZipReadStatus.UncompressedSizeExceeded],
        [AsicZipReadLimits.Conformant with { MaximumTotalUncompressedByteLength = 40 }, AsicZipReadStatus.UncompressedSizeExceeded],
        [AsicZipReadLimits.Conformant with { MaximumArchiveCommentByteLength = 4 }, AsicZipReadStatus.CommentTooLong],
        [AsicZipReadLimits.Conformant with { MaximumContainerByteLength = 64 }, AsicZipReadStatus.ContainerTooLarge],
        [AsicZipReadLimits.Conformant with { MaximumEntryNameByteLength = 4 }, AsicZipReadStatus.EntryNameRejected]
    ];


    /// <summary>
    /// An entry that declares more octets than it holds is refused: reading exactly the declared length and
    /// then checking that the stream is at its end is what makes every size bound checked before the entry was
    /// opened describe the octets that actually come out of it.
    /// </summary>
    [TestMethod]
    public void AnEntryDeclaringMoreOctetsThanItHoldsIsRefused()
    {
        byte[] content = [.. "four"u8];
        byte[] archive = AsicZipStructureOracle.BuildRawArchive(new RawZipArchiveSpec
        {
            Entries = [RawEntry("data.txt", content) with { DeclaredUncompressedByteLength = (uint)content.Length + 64 }]
        });

        AssertRefused(archive, AsicZipReadStatus.ArchiveMalformed);
    }


    /// <summary>
    /// An entry whose octets do not match the checksum its headers record is refused, whether the checksum was
    /// wrong when the archive was made or the octets were changed afterwards.
    /// </summary>
    [TestMethod]
    public void AnEntryWhoseChecksumDoesNotMatchItsOctetsIsRefused()
    {
        byte[] archive = AsicZipStructureOracle.BuildRawArchive(new RawZipArchiveSpec
        {
            Entries = [RawEntry("data.txt", [.. "the signed data object"u8]) with { DeclaredCrc32 = 0xDEADBEEF }]
        });

        AssertRefused(archive, AsicZipReadStatus.EntryChecksumMismatch);
    }


    /// <summary>
    /// Changing one octet of an entry's data inside a container this library wrote makes the container refuse
    /// to read — the corruption is caught by the archive's own checksum before any consumer sees the octets.
    /// </summary>
    [TestMethod]
    public void AChangedOctetInsideAWrittenContainerIsCaught()
    {
        byte[] content = [.. "the signed data object"u8];
        using PooledMemory container = AsicZipAuthoring.Write(
            new AsicZipAuthoringContext
            {
                MediaType = AsicWellKnown.AsicExtendedMediaType,
                Entries = [new AsicZipEntrySource { Name = "data.txt", Content = content }],
                LastModified = Instant
            },
            BaseMemoryPool.Shared);

        byte[] tampered = container.AsReadOnlySpan().ToArray();
        OracleZipArchive parsed = AsicZipStructureOracle.Parse(tampered);
        int dataOffset = parsed.LocalHeaders[1].DataOffset;
        tampered[dataOffset] ^= 0x01;

        AssertRefused(tampered, AsicZipReadStatus.EntryChecksumMismatch);
    }


    /// <summary>
    /// Octets that are not an archive at all, and an archive whose end is missing, are refused as such rather
    /// than partially parsed.
    /// </summary>
    [TestMethod]
    public void OctetsThatAreNotAnArchiveAreRefused()
    {
        AssertRefused(new byte[128], AsicZipReadStatus.NotZipArchive);

        using PooledMemory container = AsicZipAuthoring.Write(
            new AsicZipAuthoringContext
            {
                MediaType = AsicWellKnown.AsicExtendedMediaType,
                Entries = [new AsicZipEntrySource { Name = "data.txt", Content = "data"u8.ToArray() }],
                LastModified = Instant
            },
            BaseMemoryPool.Shared);

        byte[] truncated = container.AsReadOnlySpan()[..(container.Length - 8)].ToArray();
        AssertRefused(truncated, AsicZipReadStatus.NotZipArchive);
    }


    /// <summary>
    /// A folder entry reads as one: clause 4.4.2 item 2 places data files "in any folder structure outside the
    /// root META-INF folder", and ZIP records an empty folder as a name ending in the separator with no octets.
    /// </summary>
    [TestMethod]
    public void AFolderEntryReadsAsAFolderCarryingNoOctets()
    {
        byte[] archive = AsicZipStructureOracle.BuildRawArchive(new RawZipArchiveSpec
        {
            Entries = [RawEntry("data/", []), RawEntry("data/file.txt", [.. "data"u8])]
        });

        using AsicZipReadResult result = Read(archive, AsicZipReadLimits.Conformant);
        Assert.AreEqual(AsicZipReadStatus.Read, result.Status);
        Assert.IsTrue(result.Container!.Entries[0].IsFolder);
        Assert.AreEqual(0, result.Container.Entries[0].Content.Length);
        Assert.IsFalse(result.Container.Entries[1].IsFolder);
    }


    /// <summary>
    /// An entry name that is not valid UTF-8 is refused — clause 4.2 item 2 b: "File names and comments shall
    /// be encoded with ISO/IEC 10646 UNICODE UTF-8." A name that silently changed shape while being read is a
    /// name a manifest reference no longer resolves against.
    /// </summary>
    [TestMethod]
    public void AnEntryNameThatIsNotUtf8IsRefused()
    {
        byte[] archive = AsicZipStructureOracle.BuildRawArchive(new RawZipArchiveSpec
        {
            Entries = [RawEntry("data.txt", [.. "data"u8])]
        });

        //The name occupies eight octets starting at offset 30 of the local header and at offset 46 of the
        //central directory record; 0xFF begins no UTF-8 sequence.
        OracleZipArchive parsed = AsicZipStructureOracle.Parse(archive);
        archive[30] = 0xFF;
        archive[parsed.CentralDirectoryOffset + 46] = 0xFF;

        using AsicZipReadResult result = Read(archive, AsicZipReadLimits.Conformant);
        Assert.AreEqual(AsicZipReadStatus.EntryNameRejected, result.Status);
        Assert.AreEqual(AsicZipEntryNameStatus.NotUtf8, result.RejectedEntryNameStatus);
    }


    /// <summary>
    /// An archive whose two descriptions of an entry disagree is refused. A ZIP archive states every entry
    /// twice — once in the local file header and once in the central directory — and nothing in the format
    /// requires the two to agree; for a container whose purpose is to say which octets a signature covers, a
    /// consumer reading through the directory and one reading through the local headers seeing different file
    /// objects under one name is the difference between a valid signature and a substituted data object.
    /// </summary>
    [TestMethod]
    public void AnArchiveWhoseLocalHeaderAndDirectoryDisagreeIsRefused()
    {
        byte[] archive = AsicZipStructureOracle.BuildRawArchive(new RawZipArchiveSpec
        {
            Entries = [RawEntry("data.txt", [.. "the signed data object"u8])]
        });

        //Both names occupy eight octets, so renaming the local header's copy alone leaves every length field
        //of the archive correct and changes only which file object the two structures name.
        OracleZipArchive parsed = AsicZipStructureOracle.Parse(archive);
        "evil.txt"u8.CopyTo(archive.AsSpan(parsed.LocalHeaders[0].HeaderOffset + 30));

        AssertRefused(archive, AsicZipReadStatus.ArchiveMalformed);
    }


    /// <summary>
    /// An archive whose first octets are a <c>mimetype</c> local file header its central directory does not
    /// point at is refused. Annex A.1 item 1 makes the entry the first file in the container, and this is the
    /// shape that breaks it while every header in the archive stays internally consistent: an application
    /// sniffing the media type out of offset 38 reads the decoy, while a reader following the directory
    /// extracts the entry sitting further in.
    /// </summary>
    [TestMethod]
    public void AnArchiveWhoseFirstOctetsAreADecoyMimetypeEntryIsRefused()
    {
        byte[] archive = AsicZipStructureOracle.BuildRawArchive(new RawZipArchiveSpec
        {
            UnlistedFirstEntry = RawEntry(AsicWellKnown.MimetypeEntryName, [.. "application/vnd.etsi.asic-s+zip"u8]),
            Entries =
            [
                RawEntry(AsicWellKnown.MimetypeEntryName, [.. "application/vnd.etsi.asic-e+zip"u8]),
                RawEntry("data.txt", [.. "the signed data object"u8])
            ]
        });

        Assert.AreEqual(
            AsicWellKnown.AsicSimpleMediaType,
            AsicZipStructureOracle.MediaTypeAtOffset38(archive),
            "The decoy is what the Annex A.1 NOTE's recognition reads, which is why the archive has to be refused.");

        AssertRefused(archive, AsicZipReadStatus.MimetypeNotFirstEntry);
    }


    /// <summary>
    /// Reads an archive within the stated bounds.
    /// </summary>
    /// <param name="archive">The archive's octets.</param>
    /// <param name="limits">The bounds to read within.</param>
    /// <returns>What the reader concluded, which the caller disposes.</returns>
    private static AsicZipReadResult Read(byte[] archive, AsicZipReadLimits limits) =>
        AsicZipReading.Read(archive, limits, BaseMemoryPool.Shared);


    /// <summary>
    /// Asserts that an archive is refused with a stated conclusion, and that nothing was handed back with it.
    /// </summary>
    /// <param name="archive">The archive's octets.</param>
    /// <param name="expected">What the reader is to conclude.</param>
    private static void AssertRefused(byte[] archive, AsicZipReadStatus expected)
    {
        using AsicZipReadResult result = Read(archive, AsicZipReadLimits.Conformant);
        Assert.AreEqual(expected, result.Status);
        Assert.IsFalse(result.IsRead, "A refused archive hands back no container.");
        Assert.IsNull(result.Container);
    }


    /// <summary>Builds a stored raw entry.</summary>
    /// <param name="name">The entry name to write verbatim.</param>
    /// <param name="content">The entry's octets.</param>
    /// <returns>The entry specification.</returns>
    private static RawZipEntrySpec RawEntry(string name, byte[] content) =>
        new() { Name = name, Content = content };
}
