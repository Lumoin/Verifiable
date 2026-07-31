using System;
using System.Collections.Generic;
using System.Text;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for <see cref="EArkPackageSnapshotReading"/> and <see cref="EArkPackageSnapshot"/>: the two
/// ways an Information Package arrives — the entries a caller states, and a generic archive — reach the same
/// value, and neither of them can be talked past the bounds it is read within.
/// </summary>
/// <remarks>
/// <para>
/// The load-bearing test is
/// <see cref="TheSameContentStatedDirectlyAndArchivedProducesTheSameSnapshot"/>: the two paths exist so that one
/// classifier and one rule list serve a folder tree and an archive alike, which is only true if the two produce
/// the same value. The hostile-input tests are its counterweight — everything a producer controls is bounded on
/// both paths, and every refusal names what it refused.
/// </para>
/// <para>
/// Every carrier is rented from the house pool, every result is disposed, and every instant is stated rather than
/// read from a clock.
/// </para>
/// </remarks>
[TestClass]
internal sealed class EArkPackageSnapshotTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The instant every archive this class writes records for its entries.</summary>
    private static DateTimeOffset Archived { get; } = new(2026, 7, 31, 13, 20, 0, TimeSpan.Zero);

    /// <summary>The name of the root folder an archived package unpacks to (<c>CSIPSTR1</c>, <c>CSIPSTR2</c>).</summary>
    private const string RootFolder = "urn-uuid-3f0c1d2e";

    /// <summary>A small package that fills the positions the folder-structure requirements name.</summary>
    private static IReadOnlyList<EArkPackageEntrySource> ConformantPackage { get; } =
    [
        EArkPackageSource.TextFile("METS.xml", "<mets/>"),
        EArkPackageSource.TextFile("metadata/preservation/PREMIS.xml", "<premis/>"),
        EArkPackageSource.TextFile("metadata/descriptive/EAD.xml", "<ead/>"),
        EArkPackageSource.TextFile("schemas/mets.xsd", "<xs:schema/>"),
        EArkPackageSource.TextFile("documentation/manual.txt", "how this package was made"),
        EArkPackageSource.TextFile("representations/rep1/METS.xml", "<mets/>"),
        EArkPackageSource.TextFile("representations/rep1/data/record.bin", "the bits themselves")
    ];


    /// <summary>
    /// The entries a caller states become a snapshot whose names are ordered ordinally, so that two snapshots of
    /// the same content are the same sequence however the caller enumerated its source.
    /// </summary>
    [TestMethod]
    public void AStatedPackageBecomesASnapshotOrderedOrdinallyByName()
    {
        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            [.. Reversed(ConformantPackage)],
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.AreEqual(EArkPackageSnapshotStatus.Read, read.Status);
        Assert.IsNotNull(read.Snapshot);

        var names = new List<string>(read.Snapshot.Entries.Count);
        for(int i = 0; i < read.Snapshot.Entries.Count; ++i)
        {
            names.Add(read.Snapshot.Entries[i].Name);
        }

        for(int i = 1; i < names.Count; ++i)
        {
            Assert.IsLessThan(
                0,
                string.CompareOrdinal(names[i - 1], names[i]),
                $"\"{names[i - 1]}\" and \"{names[i]}\" are not in ascending ordinal order.");
        }
    }


    /// <summary>
    /// Every folder a name implies is present exactly once, whether or not the source recorded it. It is what
    /// makes a package archived without folder entries and the same package read from a directory the same value.
    /// </summary>
    [TestMethod]
    public void TheFolderEntriesTheNamesImplyAreMaterialisedExactlyOnce()
    {
        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            ConformantPackage,
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.IsNotNull(read.Snapshot);

        string[] expected =
        [
            "documentation/",
            "metadata/",
            "metadata/descriptive/",
            "metadata/preservation/",
            "representations/",
            "representations/rep1/",
            "representations/rep1/data/",
            "schemas/"
        ];

        var folders = new List<string>();
        for(int i = 0; i < read.Snapshot.Entries.Count; ++i)
        {
            EArkPackageEntry entry = read.Snapshot.Entries[i];
            if(entry.IsFolder)
            {
                folders.Add(entry.Name);
                Assert.AreEqual(0, entry.Content.Length, $"The folder entry \"{entry.Name}\" carries octets.");
            }
        }

        Assert.AreSequenceEqual(expected, folders);
        Assert.AreEqual(ConformantPackage.Count + expected.Length, read.Snapshot.EntryCount);
    }


    /// <summary>
    /// A folder a caller states itself is not materialised a second time, and the entry the caller stated is the
    /// one that survives.
    /// </summary>
    [TestMethod]
    public void AFolderTheCallerStatesIsNotMaterialisedTwice()
    {
        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            [EArkPackageSource.Folder("metadata"), EArkPackageSource.TextFile("metadata/notes.txt", "a note")],
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.IsNotNull(read.Snapshot);
        Assert.AreEqual(2, read.Snapshot.EntryCount);
        Assert.IsNotNull(read.Snapshot.FindEntry("metadata/"));
    }


    /// <summary>
    /// An archive that unpacks to one root folder — which <c>CSIPSTR1</c> requires of an archived package — has
    /// that folder's name stripped from every entry and carried as the fact <c>CSIPSTR1</c> and <c>CSIPSTR2</c>
    /// are judged from.
    /// </summary>
    [TestMethod]
    public void AnArchiveUnpackingToOneRootFolderHasItStrippedAndNamed()
    {
        using PooledMemory archive = EArkPackageSource.WriteArchive(ConformantPackage, RootFolder, Archived, BaseMemoryPool.Shared);
        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.ReadArchive(
            archive.AsReadOnlyMemory(),
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.AreEqual(EArkPackageSnapshotStatus.Read, read.Status);
        Assert.IsNotNull(read.Snapshot);
        Assert.IsTrue(read.Snapshot.HasSingleRootFolder);
        Assert.AreEqual(RootFolder, read.Snapshot.RootFolderName);
        Assert.IsNotNull(read.Snapshot.FindEntry("METS.xml"));
        Assert.IsNull(read.Snapshot.FindEntry($"{RootFolder}/METS.xml"));
    }


    /// <summary>
    /// An archive whose entries do not all sit under one folder says so and keeps its names, because whether a
    /// package satisfies <c>CSIPSTR1</c> is a judgment and this layer states facts.
    /// </summary>
    [TestMethod]
    public void AnArchiveWithoutOneRootFolderSaysSoAndKeepsItsNames()
    {
        using PooledMemory archive = AsicZipAuthoring.Write(
            new AsicZipAuthoringContext
            {
                Entries =
                [
                    new AsicZipEntrySource { Name = "METS.xml", Content = Encoding.UTF8.GetBytes("<mets/>") },
                    new AsicZipEntrySource { Name = "representations/rep1/data/record.bin", Content = Encoding.UTF8.GetBytes("bits") }
                ],
                LastModified = Archived
            },
            BaseMemoryPool.Shared);

        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.ReadArchive(
            archive.AsReadOnlyMemory(),
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.AreEqual(EArkPackageSnapshotStatus.Read, read.Status);
        Assert.IsNotNull(read.Snapshot);
        Assert.IsFalse(read.Snapshot.HasSingleRootFolder);
        Assert.IsNull(read.Snapshot.RootFolderName);
        Assert.IsNotNull(read.Snapshot.FindEntry("METS.xml"));
    }


    /// <summary>
    /// <strong>The property the two paths exist for.</strong> The same content stated directly and the same
    /// content archived produce snapshots that agree entry for entry — same names, same order, same octets, same
    /// folder flags, same root-folder fact.
    /// </summary>
    [TestMethod]
    public void TheSameContentStatedDirectlyAndArchivedProducesTheSameSnapshot()
    {
        using EArkPackageSnapshotResult stated = EArkPackageSnapshotReading.Create(
            ConformantPackage,
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared,
            RootFolder);

        using PooledMemory archive = EArkPackageSource.WriteArchive(ConformantPackage, RootFolder, Archived, BaseMemoryPool.Shared);
        using EArkPackageSnapshotResult archived = EArkPackageSnapshotReading.ReadArchive(
            archive.AsReadOnlyMemory(),
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        AssertSameSnapshot(stated, archived);
    }


    /// <summary>
    /// The same property over material nobody in this repository wrote: a reference package read from a folder
    /// tree and the same package archived produce the same snapshot, octets included.
    /// </summary>
    [TestMethod]
    public void AReferencePackageReadFromAFolderAndFromAnArchiveIsTheSameSnapshot()
    {
        string? packageRoot = EArkPackageSource.FindRichestPackageRoot();
        if(packageRoot is null)
        {
            Assert.Inconclusive(EArkPackageSource.MissingPackagesMessage);

            return;
        }

        string rootFolderName = EArkPackageSource.RootFolderNameOf(packageRoot);
        IReadOnlyList<EArkPackageEntrySource> entries = EArkPackageSource.StateEntries(packageRoot);

        using EArkPackageSnapshotResult fromFolder = EArkPackageSnapshotReading.Create(
            entries,
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared,
            rootFolderName);

        using PooledMemory archive = EArkPackageSource.WriteArchive(entries, rootFolderName, Archived, BaseMemoryPool.Shared);
        using EArkPackageSnapshotResult fromArchive = EArkPackageSnapshotReading.ReadArchive(
            archive.AsReadOnlyMemory(),
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        AssertSameSnapshot(fromFolder, fromArchive);
        Assert.IsGreaterThan(0L, fromFolder.Snapshot!.TotalByteLength, "The reference package carried no octets, so the comparison proved nothing about content.");
    }


    /// <summary>
    /// A package with no entries at all is a snapshot with none — an empty package is a fact about a package,
    /// not a fault in reading one.
    /// </summary>
    [TestMethod]
    public void AnEmptyPackageIsASnapshotWithNoEntries()
    {
        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create([], EArkPackageLimits.Conformant, BaseMemoryPool.Shared);

        Assert.AreEqual(EArkPackageSnapshotStatus.Read, read.Status);
        Assert.IsNotNull(read.Snapshot);
        Assert.AreEqual(0, read.Snapshot.EntryCount);
        Assert.AreEqual(0L, read.Snapshot.TotalByteLength);
    }


    /// <summary>
    /// Octets that are not an archive at all are refused by the archive layer, and the refusal reaches the caller
    /// as the archive layer stated it rather than flattened into one E-ARK status.
    /// </summary>
    [TestMethod]
    [DataRow(0, DisplayName = "no octets at all")]
    [DataRow(64, DisplayName = "octets that are not an archive")]
    public void OctetsThatAreNotAnArchiveAreRefusedWithTheArchiveLayersOwnStatus(int byteLength)
    {
        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.ReadArchive(
            new byte[byteLength],
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.AreEqual(EArkPackageSnapshotStatus.ArchiveRefused, read.Status);
        Assert.AreEqual(AsicZipReadStatus.NotZipArchive, read.ArchiveStatus);
        Assert.IsNull(read.Snapshot);
    }


    /// <summary>
    /// Every way an entry name can name something outside the package is refused on the path a caller states its
    /// entries on, and the refusal names which rule refused it.
    /// </summary>
    [TestMethod]
    [DataRow("../outside.txt", AsicZipEntryNameStatus.Traversal, DisplayName = "a parent segment")]
    [DataRow("data/../../outside.txt", AsicZipEntryNameStatus.Traversal, DisplayName = "a parent segment further in")]
    [DataRow("./here.txt", AsicZipEntryNameStatus.Traversal, DisplayName = "a current-folder segment")]
    [DataRow("/METS.xml", AsicZipEntryNameStatus.Absolute, DisplayName = "a path from a file-system root")]
    [DataRow("data\\record.bin", AsicZipEntryNameStatus.BackslashSeparator, DisplayName = "a native path separator")]
    [DataRow("C:/METS.xml", AsicZipEntryNameStatus.VolumeQualified, DisplayName = "a volume qualifier")]
    [DataRow("data//record.bin", AsicZipEntryNameStatus.EmptySegment, DisplayName = "an empty segment")]
    [DataRow("data/\u0001.bin", AsicZipEntryNameStatus.ControlCharacter, DisplayName = "a control character")]
    [DataRow("", AsicZipEntryNameStatus.Empty, DisplayName = "no name at all")]
    public void AHostileEntryNameIsRefusedOnTheStatedPath(string entryName, AsicZipEntryNameStatus expected)
    {
        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            [EArkPackageSource.TextFile(entryName, "content")],
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.AreEqual(EArkPackageSnapshotStatus.EntryNameRefused, read.Status);
        Assert.AreEqual(expected, read.RejectedEntryNameStatus);
        Assert.IsNull(read.Snapshot);
    }


    /// <summary>
    /// The same names are refused when they arrive inside an archive, and the rule that refused them is the same
    /// one. The status differs — the archive layer refuses the archive before this layer sees an entry — and that
    /// is what <see cref="EArkPackageSnapshotResult.ArchiveStatus"/> exists to keep visible.
    /// </summary>
    [TestMethod]
    [DataRow("../outside.txt", AsicZipEntryNameStatus.Traversal, DisplayName = "a parent segment")]
    [DataRow("/METS.xml", AsicZipEntryNameStatus.Absolute, DisplayName = "a path from a file-system root")]
    [DataRow("data\\record.bin", AsicZipEntryNameStatus.BackslashSeparator, DisplayName = "a native path separator")]
    [DataRow("C:/METS.xml", AsicZipEntryNameStatus.VolumeQualified, DisplayName = "a volume qualifier")]
    [DataRow("data//record.bin", AsicZipEntryNameStatus.EmptySegment, DisplayName = "an empty segment")]
    public void AHostileEntryNameIsRefusedOnTheArchivePathByTheSameRule(string entryName, AsicZipEntryNameStatus expected)
    {
        byte[] archive = AsicZipStructureOracle.BuildRawArchive(new RawZipArchiveSpec
        {
            Entries = [new RawZipEntrySpec { Name = entryName, Content = Encoding.UTF8.GetBytes("content") }]
        });

        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.ReadArchive(
            archive,
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.AreEqual(EArkPackageSnapshotStatus.ArchiveRefused, read.Status);
        Assert.AreEqual(AsicZipReadStatus.EntryNameRejected, read.ArchiveStatus);
        Assert.AreEqual(expected, read.RejectedEntryNameStatus);
        Assert.IsNull(read.Snapshot);
    }


    /// <summary>
    /// A package naming the same entry twice is refused rather than read, because a manifest reference to that
    /// name would resolve to neither of them.
    /// </summary>
    [TestMethod]
    public void APackageNamingOneEntryTwiceIsRefused()
    {
        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            [EArkPackageSource.TextFile("METS.xml", "<mets/>"), EArkPackageSource.TextFile("METS.xml", "<mets/>")],
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.AreEqual(EArkPackageSnapshotStatus.DuplicateEntryName, read.Status);
        Assert.AreEqual("METS.xml", read.RejectedEntryName);
    }


    /// <summary>
    /// A name stated as a file where another name uses it as a folder does not resolve to one tree, and is
    /// refused on both paths — the archive layer admits the pair, because a ZIP name is an octet string and the
    /// two names differ.
    /// </summary>
    [TestMethod]
    public void ANameThatIsBothAFileAndAFolderIsRefused()
    {
        using EArkPackageSnapshotResult stated = EArkPackageSnapshotReading.Create(
            [EArkPackageSource.TextFile("metadata", "not a folder"), EArkPackageSource.TextFile("metadata/notes.txt", "a note")],
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.AreEqual(EArkPackageSnapshotStatus.EntryNameCollidesWithFolder, stated.Status);

        using PooledMemory archive = AsicZipAuthoring.Write(
            new AsicZipAuthoringContext
            {
                Entries =
                [
                    new AsicZipEntrySource { Name = "metadata", Content = Encoding.UTF8.GetBytes("not a folder") },
                    new AsicZipEntrySource { Name = "metadata/notes.txt", Content = Encoding.UTF8.GetBytes("a note") }
                ],
                LastModified = Archived
            },
            BaseMemoryPool.Shared);

        using EArkPackageSnapshotResult archived = EArkPackageSnapshotReading.ReadArchive(
            archive.AsReadOnlyMemory(),
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.AreEqual(EArkPackageSnapshotStatus.EntryNameCollidesWithFolder, archived.Status);
    }


    /// <summary>
    /// A folder entry stated where another name already states a folder of that path is a duplicate rather than a
    /// collision, which keeps the two refusals apart.
    /// </summary>
    [TestMethod]
    public void AFolderStatedTwiceIsADuplicateRatherThanACollision()
    {
        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            [EArkPackageSource.Folder("metadata"), EArkPackageSource.Folder("metadata")],
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.AreEqual(EArkPackageSnapshotStatus.DuplicateEntryName, read.Status);
    }


    /// <summary>
    /// Every bound the shared limits record states refuses a package that exceeds it, on the path a caller
    /// states its entries on.
    /// </summary>
    [TestMethod]
    public void EachStatedBoundRefusesThePackageThatExceedsIt()
    {
        var beyondCount = new EArkPackageLimits { MaximumEntryCount = 2 };
        using EArkPackageSnapshotResult count = EArkPackageSnapshotReading.Create(
            [EArkPackageSource.TextFile("a.txt", "a"), EArkPackageSource.TextFile("b.txt", "b"), EArkPackageSource.TextFile("c.txt", "c")],
            beyondCount,
            BaseMemoryPool.Shared);
        Assert.AreEqual(EArkPackageSnapshotStatus.EntryCountExceeded, count.Status);

        var beyondBytes = new EArkPackageLimits { MaximumTotalByteLength = 8 };
        using EArkPackageSnapshotResult bytes = EArkPackageSnapshotReading.Create(
            [EArkPackageSource.TextFile("a.txt", "0123456789")],
            beyondBytes,
            BaseMemoryPool.Shared);
        Assert.AreEqual(EArkPackageSnapshotStatus.TotalByteLengthExceeded, bytes.Status);

        var beyondName = new EArkPackageLimits { MaximumEntryNameByteLength = 4 };
        using EArkPackageSnapshotResult name = EArkPackageSnapshotReading.Create(
            [EArkPackageSource.TextFile("METS.xml", "<mets/>")],
            beyondName,
            BaseMemoryPool.Shared);
        Assert.AreEqual(EArkPackageSnapshotStatus.EntryNameRefused, name.Status);
        Assert.AreEqual(AsicZipEntryNameStatus.TooLong, name.RejectedEntryNameStatus);

        var beyondDepth = new EArkPackageLimits { MaximumFolderDepth = 2 };
        using EArkPackageSnapshotResult depth = EArkPackageSnapshotReading.Create(
            [EArkPackageSource.TextFile("representations/rep1/data/record.bin", "bits")],
            beyondDepth,
            BaseMemoryPool.Shared);
        Assert.AreEqual(EArkPackageSnapshotStatus.FolderDepthExceeded, depth.Status);
    }


    /// <summary>
    /// A package inside every bound is read, so the bounds above refuse for the reason stated rather than because
    /// the fixture was unreadable.
    /// </summary>
    [TestMethod]
    public void APackageInsideEveryBoundIsRead()
    {
        var limits = new EArkPackageLimits
        {
            MaximumEntryCount = 32,
            MaximumTotalByteLength = 4096,
            MaximumEntryNameByteLength = 64,
            MaximumFolderDepth = 4
        };

        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(ConformantPackage, limits, BaseMemoryPool.Shared);

        Assert.AreEqual(EArkPackageSnapshotStatus.Read, read.Status);
    }


    /// <summary>
    /// A tree deep enough to exhaust a recursive reader's stack is refused by a counter rather than by an
    /// overflow, on the path a caller states its entries on.
    /// </summary>
    [TestMethod]
    public void ATreeDeeperThanAnyStackIsRefusedByACounter()
    {
        var name = new StringBuilder();
        for(int i = 0; i < 20_000; ++i)
        {
            _ = name.Append("d/");
        }

        _ = name.Append("record.bin");

        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            [EArkPackageSource.TextFile(name.ToString(), "bits")],
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        //The name bound is reached first, which is itself the point: nothing walks 20 000 segments before a
        //bound applies. Raising only the name bound leaves the depth bound to refuse it.
        Assert.AreEqual(EArkPackageSnapshotStatus.EntryNameRefused, read.Status);

        using EArkPackageSnapshotResult deep = EArkPackageSnapshotReading.Create(
            [EArkPackageSource.TextFile(name.ToString(), "bits")],
            new EArkPackageLimits { MaximumEntryNameByteLength = 262_144 },
            BaseMemoryPool.Shared);

        Assert.AreEqual(EArkPackageSnapshotStatus.FolderDepthExceeded, deep.Status);
    }


    /// <summary>
    /// The folder entries the reader materialises count towards the entry bound, so a package cannot state a few
    /// deep names and reach an unbounded number of entries.
    /// </summary>
    [TestMethod]
    public void TheMaterialisedFolderEntriesCountTowardsTheEntryBound()
    {
        var limits = new EArkPackageLimits { MaximumEntryCount = 3 };

        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            [EArkPackageSource.TextFile("a/b/c/record.bin", "bits")],
            limits,
            BaseMemoryPool.Shared);

        Assert.AreEqual(EArkPackageSnapshotStatus.EntryCountExceeded, read.Status);
    }


    /// <summary>
    /// Nothing the caller passed is retained: the snapshot carries its own copy of every entry's octets, so a
    /// caller reusing its buffers cannot change what a validation reads.
    /// </summary>
    [TestMethod]
    public void TheSnapshotCarriesItsOwnCopyOfEveryEntrysOctets()
    {
        byte[] mutable = Encoding.UTF8.GetBytes("original");
        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            [new EArkPackageEntrySource { Name = "record.bin", Content = mutable }],
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.IsNotNull(read.Snapshot);
        Array.Fill(mutable, (byte)0x00);

        EArkPackageEntry? entry = read.Snapshot.FindEntry("record.bin");
        Assert.IsNotNull(entry);
        Assert.AreEqual("original", Encoding.UTF8.GetString(entry.Content.AsReadOnlySpan()));
    }


    /// <summary>
    /// Every entry's octets ride in a carrier tagged as a package entry, so a block of package octets can be
    /// routed and reported on without re-reading the package.
    /// </summary>
    [TestMethod]
    public void EveryEntrysOctetsRideInAPackageEntryCarrier()
    {
        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            ConformantPackage,
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.IsNotNull(read.Snapshot);
        for(int i = 0; i < read.Snapshot.Entries.Count; ++i)
        {
            Assert.AreEqual(EArkTags.PackageEntry, read.Snapshot.Entries[i].Content.Tag);
        }
    }


    /// <summary>
    /// No status this stage declares reads as a success before it has been computed: zero names the unevaluated
    /// value on every one of them.
    /// </summary>
    [TestMethod]
    public void ADefaultInitialisedStatusNeverReadsAsSuccess()
    {
        Assert.AreEqual(nameof(EArkPackageSnapshotStatus.NotRead), Enum.GetName(default(EArkPackageSnapshotStatus)));
        Assert.AreEqual(nameof(EArkPackageEntryPlacement.NotEvaluated), Enum.GetName(default(EArkPackageEntryPlacement)));

        using var result = new EArkPackageSnapshotResult { Status = default };
        Assert.IsFalse(result.IsRead);
    }


    /// <summary>
    /// The shared limits record hands the archive layer the bounds it shares with it, so one stated bound governs
    /// both paths rather than two records disagreeing — with the headroom the archive layer needs because it sees
    /// every name before the root-folder prefix is stripped and every entry before the root folder's own is
    /// dropped.
    /// </summary>
    /// <remarks>
    /// The two bounds the paths would otherwise disagree on are the name length and the entry count: the archive
    /// layer applies them to the archive's own strings and the archive's own count, and only afterwards is the
    /// <c>CSIPSTR1</c> root folder stripped. The headroom is exactly what a root folder can add — a root name is
    /// itself an entry name and so is bounded by the same value, and the root folder contributes exactly one
    /// entry — so the value each bound really governs is the post-normalization one on both paths.
    /// </remarks>
    [TestMethod]
    public void TheSharedBoundsGovernTheArchiveLayerToo()
    {
        var limits = new EArkPackageLimits
        {
            MaximumEntryCount = 7,
            MaximumEntryNameByteLength = 11,
            MaximumTotalByteLength = 13
        };

        AsicZipReadLimits archive = limits.ToArchiveLimits();

        Assert.AreEqual(limits.MaximumEntryCount + 1, archive.MaximumEntryCount, "One entry of headroom for the root folder's own entry, which the read then drops.");
        Assert.AreEqual(limits.MaximumEntryNameByteLength * 2, archive.MaximumEntryNameByteLength, "Room for the root-folder prefix, which the read then strips.");
        Assert.AreEqual(limits.MaximumTotalByteLength, archive.MaximumTotalUncompressedByteLength);
        Assert.AreEqual(AsicZipReadLimits.Conformant.MaximumEntryExpansionRatio, archive.MaximumEntryExpansionRatio);

        //The headroom is bounded arithmetic, not unbounded: a record stating the largest bounds representable
        //hands the archive layer those bounds rather than wrapping into a negative one that admits everything.
        AsicZipReadLimits saturated = new EArkPackageLimits
        {
            MaximumEntryCount = int.MaxValue,
            MaximumEntryNameByteLength = int.MaxValue
        }.ToArchiveLimits();

        Assert.AreEqual(int.MaxValue, saturated.MaximumEntryCount);
        Assert.AreEqual(int.MaxValue, saturated.MaximumEntryNameByteLength);
    }


    /// <summary>
    /// The documented equivalence holds AT the shared bounds, not only well inside them: a package the folder
    /// path admits is admitted by the archive path once it is archived under a <c>CSIPSTR1</c> root folder, and
    /// a package the folder path refuses is refused there too.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the property three doc blocks state — <see cref="EArkPackageLimits"/>' remarks, those of
    /// <see cref="EArkPackageLimits.ToArchiveLimits"/> and the reading method's own — and the bounds are where it
    /// could fail without anyone noticing, because the archive layer runs before the root prefix is stripped and
    /// before the root folder's own entry is dropped. The failure it guards against is not an admission hole:
    /// the archive path was the STRICTER one, so the package that paid was the conformant one, the one that
    /// carries the root folder <c>CSIPSTR1</c> requires.
    /// </para>
    /// <para>
    /// Both bounds are exercised in both directions — at the bound, where both paths admit, and one octet or one
    /// entry over it, where both refuse.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void TheTwoPathsAdmitTheSamePackageAtTheSharedBounds()
    {
        //The name bound, at the bound. The name is root-relative and exactly as long as the bound allows; the
        //archived form carries the root prefix on top of it and is therefore longer than the bound.
        var nameLimits = new EArkPackageLimits { MaximumEntryNameByteLength = 64 };
        string atTheBound = "data/" + new string('n', 64 - "data/".Length);
        Assert.AreEqual(64, Encoding.UTF8.GetByteCount(atTheBound));
        Assert.IsGreaterThan(nameLimits.MaximumEntryNameByteLength, Encoding.UTF8.GetByteCount(RootFolder + "/" + atTheBound));

        AssertBothPathsAgree(
            [EArkPackageSource.TextFile("METS.xml", "<mets/>"), EArkPackageSource.TextFile(atTheBound, "payload")],
            nameLimits,
            admitted: true);

        //One octet over it, where both refuse under the same status.
        string overTheBound = atTheBound + "o";
        AssertBothPathsAgree(
            [EArkPackageSource.TextFile("METS.xml", "<mets/>"), EArkPackageSource.TextFile(overTheBound, "payload")],
            nameLimits,
            admitted: false);

        //The entry-count bound, at the bound. The archive carries one entry more than the package does, because
        //the root folder has an entry of its own that the read drops.
        var countLimits = new EArkPackageLimits { MaximumEntryCount = 3 };
        AssertBothPathsAgree(
            [
                EArkPackageSource.TextFile("METS.xml", "<mets/>"),
                EArkPackageSource.Folder("data"),
                EArkPackageSource.TextFile("data/f.txt", "payload")
            ],
            countLimits,
            admitted: true);

        //One entry over it, where both refuse.
        AssertBothPathsAgree(
            [
                EArkPackageSource.TextFile("METS.xml", "<mets/>"),
                EArkPackageSource.Folder("data"),
                EArkPackageSource.TextFile("data/f.txt", "payload"),
                EArkPackageSource.TextFile("data/g.txt", "payload")
            ],
            countLimits,
            admitted: false);
    }


    /// <summary>
    /// Reads one package along both paths under the same limits and asserts they agree on admitting it.
    /// </summary>
    /// <param name="entries">The package's entries, under names relative to the package root.</param>
    /// <param name="limits">The bounds both reads are performed within.</param>
    /// <param name="admitted">Whether the package is expected to be admitted.</param>
    private static void AssertBothPathsAgree(
        IReadOnlyList<EArkPackageEntrySource> entries,
        EArkPackageLimits limits,
        bool admitted)
    {
        using EArkPackageSnapshotResult fromFolder = EArkPackageSnapshotReading.Create(
            entries,
            limits,
            BaseMemoryPool.Shared,
            RootFolder);

        using PooledMemory archive = EArkPackageSource.WriteArchive(entries, RootFolder, Archived, BaseMemoryPool.Shared);
        using EArkPackageSnapshotResult fromArchive = EArkPackageSnapshotReading.ReadArchive(
            archive.AsReadOnlyMemory(),
            limits,
            BaseMemoryPool.Shared);

        Assert.AreEqual(admitted, fromFolder.IsRead, $"The folder path {(admitted ? "refused" : "admitted")} a package it was expected to {(admitted ? "admit" : "refuse")}.");
        Assert.AreEqual(admitted, fromArchive.IsRead, $"The archive path {(admitted ? "refused" : "admitted")} a package the folder path {(admitted ? "admitted" : "refused")}.");

        if(admitted)
        {
            AssertSameSnapshot(fromFolder, fromArchive);
        }
    }


    /// <summary>
    /// Asserts that two reads produced the same snapshot, entry for entry.
    /// </summary>
    /// <param name="left">The first read.</param>
    /// <param name="right">The second read.</param>
    private static void AssertSameSnapshot(EArkPackageSnapshotResult left, EArkPackageSnapshotResult right)
    {
        Assert.AreEqual(EArkPackageSnapshotStatus.Read, left.Status);
        Assert.AreEqual(EArkPackageSnapshotStatus.Read, right.Status);
        Assert.IsNotNull(left.Snapshot);
        Assert.IsNotNull(right.Snapshot);

        Assert.AreEqual(left.Snapshot.RootFolderName, right.Snapshot.RootFolderName);
        Assert.AreEqual(left.Snapshot.HasSingleRootFolder, right.Snapshot.HasSingleRootFolder);
        Assert.AreEqual(left.Snapshot.TotalByteLength, right.Snapshot.TotalByteLength);
        Assert.AreEqual(left.Snapshot.EntryCount, right.Snapshot.EntryCount);

        for(int i = 0; i < left.Snapshot.EntryCount; ++i)
        {
            EArkPackageEntry expected = left.Snapshot.Entries[i];
            EArkPackageEntry actual = right.Snapshot.Entries[i];

            Assert.AreEqual(expected.Name, actual.Name);
            Assert.AreEqual(expected.IsFolder, actual.IsFolder);
            Assert.IsTrue(
                expected.Content.AsReadOnlySpan().SequenceEqual(actual.Content.AsReadOnlySpan()),
                $"The octets of \"{expected.Name}\" differ between the two paths.");
        }
    }


    /// <summary>
    /// States a list in the opposite order, so that a test can prove ordering is imposed rather than inherited.
    /// </summary>
    /// <param name="entries">The entries to reverse.</param>
    /// <returns>The entries, last first.</returns>
    private static IEnumerable<EArkPackageEntrySource> Reversed(IReadOnlyList<EArkPackageEntrySource> entries)
    {
        for(int i = entries.Count - 1; i >= 0; --i)
        {
            yield return entries[i];
        }
    }
}
