using System;
using System.Collections.Generic;
using System.Text;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="AsicZipAuthoring"/>: the octets an Associated Signature Container is made
/// of, against the rules Annex A.1 and clause 4.2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> state at the octet.
/// </summary>
/// <remarks>
/// <para>
/// Every structural claim here is checked by <see cref="AsicZipStructureOracle"/>, an independent reader of the
/// same format that shares no code with the writer under test and computes CRC-32 by a different method. A test
/// that read the container back with the library's own reader would pass with a consistently wrong local file
/// header, which is the one thing Annex A.1 is entirely about.
/// </para>
/// <para>
/// The instant every container here records is <see cref="TestClock.CanonicalEpoch"/>, because the authoring
/// takes its instant from the caller and reads no clock — which is itself asserted by
/// <see cref="TheSameContextProducesTheSameOctets"/>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class AsicZipAuthoringTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The instant every container in this class records.</summary>
    private static DateTimeOffset Instant { get; } = TestClock.CanonicalEpoch;


    /// <summary>
    /// The container begins with the four octets Annex A.1 item 4 requires: "the first 4 octets of the ASiC
    /// container file shall have the hex values: "50 4B 03 04"".
    /// </summary>
    [TestMethod]
    public void TheContainerBeginsWithTheLocalFileHeaderMagicOfAnnexA1Item4()
    {
        using PooledMemory container = WriteExtendedContainer();

        ReadOnlySpan<byte> octets = container.AsReadOnlySpan();
        Assert.AreEqual(0x50, octets[0]);
        Assert.AreEqual(0x4B, octets[1]);
        Assert.AreEqual(0x03, octets[2]);
        Assert.AreEqual(0x04, octets[3]);
    }


    /// <summary>
    /// The <c>mimetype</c> entry is the first file in the container (Annex A.1 item 1), is stored rather than
    /// compressed (item 3, "compression method in its ZIP header at offset 8 shall be set to zero"), carries no
    /// extra field (item 2, "extra field length at offset 28 shall be set to zero"), and states its sizes in its
    /// own header rather than in a trailing data descriptor.
    /// </summary>
    [TestMethod]
    public void TheMimetypeEntryIsFirstStoredAndCarriesNoExtraField()
    {
        using PooledMemory container = WriteExtendedContainer();

        OracleZipArchive archive = AsicZipStructureOracle.Parse(container.AsReadOnlySpan());
        OracleZipEntry first = archive.LocalHeaders[0];

        Assert.AreEqual(AsicWellKnown.MimetypeEntryName, first.Name, "Annex A.1 item 1 makes the mimetype entry the first file in the container.");
        Assert.AreEqual(0, first.HeaderOffset, "The first file's local header is the container's first octet.");
        Assert.AreEqual(0, (int)first.Method, "Annex A.1 item 3 sets the compression method at offset 8 to zero.");
        Assert.AreEqual(0, (int)first.ExtraFieldByteLength, "Annex A.1 item 2 sets the extra field length at offset 28 to zero.");
        Assert.AreEqual(0, first.Flags & 0x0008, "No data descriptor follows the entry, so its sizes are in its own header.");
        Assert.AreEqual(0, first.Flags & 0x0001, "Annex A.1 item 6 forbids encrypting the mimetype entry.");
        Assert.AreEqual(first.CompressedByteLength, first.UncompressedByteLength, "A stored entry's two sizes are the same value.");
    }


    /// <summary>
    /// The container's media type is readable by the algorithm the Annex A.1 NOTE describes: the string
    /// <c>mimetype</c> at offset 30, the length in the four octets at offset 18, and the media type at offset 38.
    /// </summary>
    [TestMethod]
    public void TheMediaTypeIsReadableAtOffset38ByTheAnnexA1NoteAlgorithm()
    {
        using PooledMemory container = WriteExtendedContainer();

        ReadOnlySpan<byte> octets = container.AsReadOnlySpan();
        Assert.IsTrue(
            octets.Slice(AsicWellKnown.MimetypeNameOffset, AsicWellKnown.MimetypeEntryName.Length).SequenceEqual("mimetype"u8),
            "The Annex A.1 NOTE finds the string \"mimetype\" starting at offset 30.");
        Assert.AreEqual(
            AsicWellKnown.AsicExtendedMediaType,
            AsicZipStructureOracle.MediaTypeAtOffset38(octets),
            "The Annex A.1 NOTE reads the media type from offset 38 for the length the four octets at offset 18 state.");
    }


    /// <summary>
    /// Every central directory record repeats what its entry's local file header states, and points at the
    /// offset that header actually begins at — which is what makes the two structures of the archive one
    /// description of the same entries.
    /// </summary>
    [TestMethod]
    public void TheCentralDirectoryRepeatsEveryLocalFileHeader()
    {
        using PooledMemory container = WriteExtendedContainer();

        OracleZipArchive archive = AsicZipStructureOracle.Parse(container.AsReadOnlySpan());
        Assert.HasCount(3, archive.CentralDirectory, "The container carries the mimetype entry and the two entries stated.");
        Assert.HasCount(3, archive.LocalHeaders);

        for(int i = 0; i < archive.CentralDirectory.Count; ++i)
        {
            OracleZipEntry central = archive.CentralDirectory[i];
            OracleZipEntry local = archive.LocalHeaders[i];

            Assert.AreEqual(central.Name, local.Name);
            Assert.AreEqual(central.Method, local.Method);
            Assert.AreEqual(central.Flags, local.Flags);
            Assert.AreEqual(central.Crc32, local.Crc32);
            Assert.AreEqual(central.CompressedByteLength, local.CompressedByteLength);
            Assert.AreEqual(central.UncompressedByteLength, local.UncompressedByteLength);
            Assert.AreEqual(central.DosTime, local.DosTime);
            Assert.AreEqual(central.DosDate, local.DosDate);
            Assert.AreEqual(0, (int)central.ExtraFieldByteLength, "No entry carries an extra field.");
        }
    }


    /// <summary>
    /// The end-of-central-directory record counts every entry once, locates the central directory where it
    /// actually is, and names the first disk — clause 4.2 item 2 a: "ASiC containers shall not use the multiple
    /// volumes split feature."
    /// </summary>
    [TestMethod]
    public void TheEndRecordCountsAndLocatesTheCentralDirectoryOnOneDisk()
    {
        using PooledMemory container = WriteExtendedContainer();

        OracleZipArchive archive = AsicZipStructureOracle.Parse(container.AsReadOnlySpan());
        Assert.AreEqual(3, (int)archive.DeclaredEntryCount);
        Assert.AreEqual(0, (int)archive.ThisDiskNumber);
        Assert.AreEqual(0, (int)archive.CentralDirectoryDiskNumber);
        Assert.AreEqual(
            archive.CentralDirectoryOffset + (int)archive.CentralDirectoryByteLength,
            container.Length - 22,
            "The central directory ends where the end record begins, and the container carries no comment.");
    }


    /// <summary>
    /// A stored entry carries its octets into the container unchanged, and the CRC-32 its headers record is the
    /// one an independent computation reaches over those octets.
    /// </summary>
    [TestMethod]
    public void AStoredEntryCarriesItsOctetsAndItsChecksum()
    {
        byte[] content = [.. "the signed data object"u8];
        using PooledMemory container = Write(AsicWellKnown.AsicSimpleMediaType, [Stored("data.txt", content)]);

        OracleZipArchive archive = AsicZipStructureOracle.Parse(container.AsReadOnlySpan());
        OracleZipEntry entry = archive.LocalHeaders[1];

        Assert.AreEqual("data.txt", entry.Name);
        Assert.AreEqual(0, (int)entry.Method);
        Assert.IsTrue(
            container.AsReadOnlySpan().Slice(entry.DataOffset, content.Length).SequenceEqual(content),
            "A stored entry's octets appear in the container unchanged.");
        Assert.AreEqual(AsicZipStructureOracle.Crc32(content), entry.Crc32);
    }


    /// <summary>
    /// A deflated entry states compression method 8 — the only other method clause 4.2 item 2 c admits — and
    /// inflates back to exactly the octets it was written from, with the same CRC-32 an independent computation
    /// reaches over them.
    /// </summary>
    [TestMethod]
    public void ADeflatedEntryStatesMethod8AndInflatesToItsOctets()
    {
        byte[] content = new byte[8192];
        for(int i = 0; i < content.Length; ++i)
        {
            content[i] = (byte)(i % 7);
        }

        using PooledMemory container = Write(AsicWellKnown.AsicExtendedMediaType, [Deflated("data/large.bin", content)]);

        OracleZipArchive archive = AsicZipStructureOracle.Parse(container.AsReadOnlySpan());
        OracleZipEntry entry = archive.LocalHeaders[1];

        Assert.AreEqual(8, (int)entry.Method, "Deflate is ZIP method 8 (IETF RFC 1951).");
        Assert.IsLessThan(entry.UncompressedByteLength, entry.CompressedByteLength, "The entry was actually compressed.");
        Assert.IsTrue(
            AsicZipStructureOracle.ReadEntryContent(container.AsReadOnlySpan(), entry).AsSpan().SequenceEqual(content),
            "Inflating the entry recovers the octets it was written from.");
        Assert.AreEqual(AsicZipStructureOracle.Crc32(content), entry.Crc32, "The CRC-32 is over the uncompressed octets.");
    }


    /// <summary>
    /// Every entry records the instant the caller stated, converted to UTC, and an entry stating its own
    /// instant records that one instead — which is what lets an augmentation carry an untouched entry's
    /// original instant forward.
    /// </summary>
    [TestMethod]
    public void EveryEntryRecordsTheInstantTheCallerStated()
    {
        DateTimeOffset older = Instant.AddDays(-100);
        using PooledMemory container = Write(
            AsicWellKnown.AsicExtendedMediaType,
            [Stored("recent.txt", [.. "recent"u8]), Stored("older.txt", [.. "older"u8]) with { LastModified = older }]);

        OracleZipArchive archive = AsicZipStructureOracle.Parse(container.AsReadOnlySpan());
        Assert.AreEqual(Instant, AsicZipStructureOracle.InstantOf(archive.LocalHeaders[1].DosTime, archive.LocalHeaders[1].DosDate));
        Assert.AreEqual(older, AsicZipStructureOracle.InstantOf(archive.LocalHeaders[2].DosTime, archive.LocalHeaders[2].DosDate));
    }


    /// <summary>
    /// The same context produces the same octets, which is what "no OS timestamp, no ambient state" means at
    /// the octet: nothing in the container records when or where it was written.
    /// </summary>
    [TestMethod]
    public void TheSameContextProducesTheSameOctets()
    {
        using PooledMemory first = WriteExtendedContainer();
        using PooledMemory second = WriteExtendedContainer();

        Assert.IsTrue(first.AsReadOnlySpan().SequenceEqual(second.AsReadOnlySpan()), "A container is a function of its context alone.");
    }


    /// <summary>
    /// The ZIP archive comment carries the value clauses 4.3.3.1 item 3 and 4.4.4.1 item 3 admit, and the
    /// well-known helper reads the media type back out of it.
    /// </summary>
    [TestMethod]
    public void TheArchiveCommentCarriesTheMediaTypePerClause4331Item3()
    {
        var context = new AsicZipAuthoringContext
        {
            MediaType = AsicWellKnown.AsicSimpleMediaType,
            Entries = [Stored("data.txt", [.. "data"u8])],
            LastModified = Instant,
            ArchiveComment = AsicWellKnown.MediaTypeComment(AsicWellKnown.AsicSimpleMediaType)
        };

        using PooledMemory container = AsicZipAuthoring.Write(context, BaseMemoryPool.Shared);

        OracleZipArchive archive = AsicZipStructureOracle.Parse(container.AsReadOnlySpan());
        Assert.AreEqual("mimetype=" + AsicWellKnown.AsicSimpleMediaType, archive.Comment);
        Assert.AreEqual(AsicWellKnown.AsicSimpleMediaType, AsicWellKnown.MediaTypeFromComment(archive.Comment));
    }


    /// <summary>
    /// A container written without a media type carries no <c>mimetype</c> entry at all, which clauses 4.3.3.2
    /// item 1 and 4.4.4.2 item 1 both admit ("may contain a "mimetype" file"), and its first file is the
    /// caller's.
    /// </summary>
    [TestMethod]
    public void AContainerWithoutAMediaTypeCarriesNoMimetypeEntry()
    {
        using PooledMemory container = Write(mediaType: null, [Stored("data.txt", [.. "data"u8])]);

        OracleZipArchive archive = AsicZipStructureOracle.Parse(container.AsReadOnlySpan());
        Assert.HasCount(1, archive.LocalHeaders);
        Assert.AreEqual("data.txt", archive.LocalHeaders[0].Name);
        Assert.IsNull(AsicZipStructureOracle.MediaTypeAtOffset38(container.AsReadOnlySpan()), "There is no media type to recognise at offset 38.");
    }


    /// <summary>
    /// An entry name's length field states how many UTF-8 octets the name occupies, not how many characters it
    /// has — clause 4.2 item 2 b: "File names and comments shall be encoded with ISO/IEC 10646 UNICODE UTF-8."
    /// </summary>
    [TestMethod]
    public void AnEntryNameStatesItsUtf8OctetLength()
    {
        const string Name = "data/sopimus-\u00e4\u00e4ni.txt";
        using PooledMemory container = Write(AsicWellKnown.AsicExtendedMediaType, [Stored(Name, [.. "data"u8])]);

        OracleZipArchive archive = AsicZipStructureOracle.Parse(container.AsReadOnlySpan());
        Assert.AreEqual(Name, archive.LocalHeaders[1].Name, "The name reads back as the octets it was written as.");
        Assert.AreEqual(Encoding.UTF8.GetByteCount(Name), Encoding.UTF8.GetByteCount(archive.CentralDirectory[1].Name));
        Assert.AreNotEqual(Name.Length, Encoding.UTF8.GetByteCount(Name), "The name is one whose octet count differs from its character count.");
    }


    /// <summary>
    /// An entry supplied under the name Annex A.1 reserves is refused: the entry's position, its compression
    /// method and its extra field length are bound together by that annex, and the only way to state them all
    /// correctly is the media type parameter.
    /// </summary>
    [TestMethod]
    public void AnEntryNamedMimetypeIsRefused()
    {
        var context = new AsicZipAuthoringContext
        {
            MediaType = null,
            Entries = [Stored(AsicWellKnown.MimetypeEntryName, [.. "application/vnd.etsi.asic-e+zip"u8])],
            LastModified = Instant
        };

        var exception = Assert.Throws<AsicZipAuthoringException>(() => AsicZipAuthoring.Write(context, BaseMemoryPool.Shared));
        Assert.AreEqual(AsicZipAuthoringFailureKind.MimetypeEntrySuppliedDirectly, exception.FailureKind);
    }


    /// <summary>
    /// A name that names something other than a file object inside the container is refused, whichever way it
    /// does so — Annex A.6 item 3: "References to data objects outside the container shall not be allowed."
    /// </summary>
    /// <param name="entryName">The name to refuse.</param>
    [TestMethod]
    [DataRow("../outside.txt", DisplayName = "a parent segment")]
    [DataRow("data/../../outside.txt", DisplayName = "a parent segment further in")]
    [DataRow("/absolute.txt", DisplayName = "an absolute path")]
    [DataRow("data\\windows.txt", DisplayName = "a backslash separator")]
    [DataRow("C:/volume.txt", DisplayName = "a volume qualifier")]
    [DataRow("data//empty.txt", DisplayName = "an empty segment")]
    [DataRow("./here.txt", DisplayName = "a current-folder segment")]
    [DataRow("", DisplayName = "an empty name")]
    public void ANameThatEscapesTheContainerIsRefused(string entryName)
    {
        var context = new AsicZipAuthoringContext
        {
            MediaType = AsicWellKnown.AsicExtendedMediaType,
            Entries = [Stored(entryName, [.. "data"u8])],
            LastModified = Instant
        };

        var exception = Assert.Throws<AsicZipAuthoringException>(() => AsicZipAuthoring.Write(context, BaseMemoryPool.Shared));
        Assert.AreEqual(AsicZipAuthoringFailureKind.EntryNameRejected, exception.FailureKind);
    }


    /// <summary>
    /// Two entries under one name are refused: the container would name one file object twice, and a manifest
    /// reference to that name would resolve to neither of them in particular.
    /// </summary>
    [TestMethod]
    public void TwoEntriesUnderOneNameAreRefused()
    {
        var context = new AsicZipAuthoringContext
        {
            MediaType = AsicWellKnown.AsicExtendedMediaType,
            Entries = [Stored("data.txt", [.. "first"u8]), Stored("data.txt", [.. "second"u8])],
            LastModified = Instant
        };

        var exception = Assert.Throws<AsicZipAuthoringException>(() => AsicZipAuthoring.Write(context, BaseMemoryPool.Shared));
        Assert.AreEqual(AsicZipAuthoringFailureKind.DuplicateEntryName, exception.FailureKind);
    }


    /// <summary>
    /// A container holding nothing but a media type is refused: clause 4.3.3.2 item 2 requires one data file
    /// for ASiC-S and clause 4.4.2 item 2 requires "one or more data files" for ASiC-E.
    /// </summary>
    [TestMethod]
    public void AContainerWithNoFileObjectIsRefused()
    {
        var context = new AsicZipAuthoringContext
        {
            MediaType = AsicWellKnown.AsicExtendedMediaType,
            Entries = [],
            LastModified = Instant
        };

        var exception = Assert.Throws<AsicZipAuthoringException>(() => AsicZipAuthoring.Write(context, BaseMemoryPool.Shared));
        Assert.AreEqual(AsicZipAuthoringFailureKind.NoEntries, exception.FailureKind);
    }


    /// <summary>
    /// An instant a ZIP header cannot record is refused rather than silently written as something else, because
    /// a container's headers are octets a later augmentation preserves.
    /// </summary>
    [TestMethod]
    public void AnInstantOutsideTheMsDosRangeIsRefused()
    {
        var context = new AsicZipAuthoringContext
        {
            MediaType = AsicWellKnown.AsicExtendedMediaType,
            Entries = [Stored("data.txt", [.. "data"u8])],
            LastModified = new DateTimeOffset(1979, 12, 31, 23, 59, 58, TimeSpan.Zero)
        };

        var exception = Assert.Throws<AsicZipAuthoringException>(() => AsicZipAuthoring.Write(context, BaseMemoryPool.Shared));
        Assert.AreEqual(AsicZipAuthoringFailureKind.InstantNotRepresentable, exception.FailureKind);
    }


    /// <summary>
    /// A compression method other than the two clause 4.2 item 2 c admits is refused, so no container this
    /// library writes needs a reader outside that clause.
    /// </summary>
    [TestMethod]
    public void ACompressionMethodOutsideClause42Item2CIsRefused()
    {
        var context = new AsicZipAuthoringContext
        {
            MediaType = AsicWellKnown.AsicExtendedMediaType,
            Entries = [Stored("data.txt", [.. "data"u8]) with { CompressionMethod = (AsicZipCompressionMethod)12 }],
            LastModified = Instant
        };

        var exception = Assert.Throws<AsicZipAuthoringException>(() => AsicZipAuthoring.Write(context, BaseMemoryPool.Shared));
        Assert.AreEqual(AsicZipAuthoringFailureKind.UnsupportedCompressionMethod, exception.FailureKind);
    }


    /// <summary>
    /// A media type that is not printable ASCII, or is longer than a media type is, is refused — otherwise the
    /// Annex A.1 NOTE's recognition would state something that is not a media type.
    /// </summary>
    /// <param name="mediaType">The value to refuse.</param>
    [TestMethod]
    [DataRow("", DisplayName = "an empty media type")]
    [DataRow("application/vnd.etsi.asic-e+zip ", DisplayName = "a trailing space")]
    [DataRow("application/vnd.etsi\tasic", DisplayName = "a control character")]
    public void AMediaTypeThatIsNotOneIsRefused(string mediaType)
    {
        var context = new AsicZipAuthoringContext
        {
            MediaType = mediaType,
            Entries = [Stored("data.txt", [.. "data"u8])],
            LastModified = Instant
        };

        var exception = Assert.Throws<AsicZipAuthoringException>(() => AsicZipAuthoring.Write(context, BaseMemoryPool.Shared));
        Assert.AreEqual(AsicZipAuthoringFailureKind.MediaTypeRejected, exception.FailureKind);
    }


    /// <summary>
    /// An archive comment longer than a container carries is refused rather than truncated.
    /// </summary>
    [TestMethod]
    public void AnArchiveCommentLongerThanTheBoundIsRefused()
    {
        var context = new AsicZipAuthoringContext
        {
            MediaType = AsicWellKnown.AsicExtendedMediaType,
            Entries = [Stored("data.txt", [.. "data"u8])],
            LastModified = Instant,
            ArchiveComment = new string('c', AsicZipAuthoring.MaximumArchiveCommentByteLength + 1)
        };

        var exception = Assert.Throws<AsicZipAuthoringException>(() => AsicZipAuthoring.Write(context, BaseMemoryPool.Shared));
        Assert.AreEqual(AsicZipAuthoringFailureKind.CommentTooLong, exception.FailureKind);
    }


    /// <summary>
    /// The container's octets ride a pooled carrier tagged with what they are, so a consumer routes and reports
    /// on them without parsing them again.
    /// </summary>
    [TestMethod]
    public void TheContainerRidesAPooledCarrierTaggedAsOne()
    {
        using PooledMemory container = WriteExtendedContainer();

        Assert.AreEqual(AsicObjectKind.Container, container.Tag.Get<AsicObjectKind>());
        Assert.AreEqual(AsicTags.Container, container.Tag);
    }


    /// <summary>
    /// Writes the container every structural test in this class reads: an ASiC-E media type, one stored entry
    /// and one deflated entry in the <c>META-INF</c> folder.
    /// </summary>
    /// <returns>The container's octets, which the caller disposes.</returns>
    private static PooledMemory WriteExtendedContainer() =>
        Write(
            AsicWellKnown.AsicExtendedMediaType,
            [
                Stored("data.txt", [.. "the signed data object"u8]),
                Deflated("META-INF/ASiCManifest1.xml", [.. "<manifest/>"u8])
            ]);


    /// <summary>
    /// Writes a container from a media type and a list of entries at <see cref="Instant"/>.
    /// </summary>
    /// <param name="mediaType">The media type, or <see langword="null"/> to write no mimetype entry.</param>
    /// <param name="entries">The entries to write.</param>
    /// <returns>The container's octets, which the caller disposes.</returns>
    private static PooledMemory Write(string? mediaType, IReadOnlyList<AsicZipEntrySource> entries) =>
        AsicZipAuthoring.Write(
            new AsicZipAuthoringContext { MediaType = mediaType, Entries = entries, LastModified = Instant },
            BaseMemoryPool.Shared);


    /// <summary>Builds a stored entry.</summary>
    /// <param name="name">The entry name.</param>
    /// <param name="content">The entry's octets.</param>
    /// <returns>The entry.</returns>
    private static AsicZipEntrySource Stored(string name, byte[] content) =>
        new() { Name = name, Content = content, CompressionMethod = AsicZipCompressionMethod.Stored };


    /// <summary>Builds a deflated entry.</summary>
    /// <param name="name">The entry name.</param>
    /// <param name="content">The entry's octets.</param>
    /// <returns>The entry.</returns>
    private static AsicZipEntrySource Deflated(string name, byte[] content) =>
        new() { Name = name, Content = content, CompressionMethod = AsicZipCompressionMethod.Deflated };
}
