using System;
using System.Collections.Generic;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for <see cref="EArkPackageReading"/>: the position every entry of an Information Package
/// holds, read from its name alone, against the folder-structure requirements <c>CSIPSTR1</c> to <c>CSIPSTR16</c>
/// of
/// <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 clause
/// 4.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// The classifier states facts and judges nothing, so every test here asserts what the layout <em>is</em> — which
/// folders exist, which files sit where, how many representations there are — and none asserts that a package
/// conforms. Only <c>CSIPSTR1</c> and <c>CSIPSTR4</c> are MUSTs; everything else is a SHOULD or a MAY, and
/// <c>CSIPSTR14</c> admits folders the vocabulary does not name at all.
/// </para>
/// <para>
/// The reference leg is <see cref="EveryReferencePackageIsClassifiedCompletely"/>, which runs over every
/// Information Package the optional local material carries — packages nothing in this repository wrote — and
/// checks the classification is total and self-consistent on each. It states names only, because the classifier
/// reads names and nothing else.
/// </para>
/// </remarks>
[TestClass]
internal sealed class EArkPackageClassificationTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>A package filling every position the folder-structure requirements name, at both levels.</summary>
    private static IReadOnlyList<EArkPackageEntrySource> FullPackage { get; } =
    [
        EArkPackageSource.TextFile("METS.xml", "<mets/>"),
        EArkPackageSource.TextFile("metadata/summary.txt", "metadata outside the named sub-folders"),
        EArkPackageSource.TextFile("metadata/preservation/PREMIS.xml", "<premis/>"),
        EArkPackageSource.TextFile("metadata/descriptive/EAD.xml", "<ead/>"),
        EArkPackageSource.TextFile("metadata/other/notes.txt", "other metadata"),
        EArkPackageSource.TextFile("schemas/mets.xsd", "<xs:schema/>"),
        EArkPackageSource.TextFile("documentation/manual.txt", "how this package was made"),
        EArkPackageSource.TextFile("representations/rep1/METS.xml", "<mets/>"),
        EArkPackageSource.TextFile("representations/rep1/data/record.bin", "the bits themselves"),
        EArkPackageSource.TextFile("representations/rep1/metadata/preservation/PREMIS.xml", "<premis/>"),
        EArkPackageSource.TextFile("representations/rep1/schemas/mets.xsd", "<xs:schema/>"),
        EArkPackageSource.TextFile("representations/rep1/documentation/readme.txt", "about this representation"),
        EArkPackageSource.TextFile("representations/rep2/METS.xml", "<mets/>"),
        EArkPackageSource.TextFile("representations/rep2/data/record.bin", "a second representation of the same content")
    ];


    /// <summary>
    /// A package holding every named folder states every one of them as present, and each file reaches the
    /// position its name puts it at.
    /// </summary>
    [TestMethod]
    public void EveryNamedFolderOfTheSpecificationIsStatedAsPresent()
    {
        using EArkPackageSnapshotResult read = Read(FullPackage);
        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);

        Assert.IsTrue(facts.Package.HasManifest, "CSIPSTR4: the root METS.xml was not found.");
        Assert.AreEqual("METS.xml", facts.Package.Manifest!.Name);
        Assert.IsTrue(facts.Package.HasMetadataFolder, "CSIPSTR5");
        Assert.IsTrue(facts.Package.HasPreservationMetadataFolder, "CSIPSTR6");
        Assert.IsTrue(facts.Package.HasDescriptiveMetadataFolder, "CSIPSTR7");
        Assert.IsTrue(facts.Package.HasOtherMetadataFolder, "CSIPSTR8");
        Assert.IsTrue(facts.HasRepresentationsFolder, "CSIPSTR9");
        Assert.IsTrue(facts.Package.HasSchemasFolder, "CSIPSTR15");
        Assert.IsTrue(facts.Package.HasDocumentationFolder, "CSIPSTR16");
        Assert.IsFalse(facts.Package.HasDataFolder, "CSIPSTR11 places a data folder inside a representation only.");

        Assert.HasCount(1, facts.Package.MetadataFiles);
        Assert.HasCount(1, facts.Package.PreservationMetadataFiles);
        Assert.HasCount(1, facts.Package.DescriptiveMetadataFiles);
        Assert.HasCount(1, facts.Package.OtherMetadataFiles);
        Assert.HasCount(1, facts.Package.SchemaFiles);
        Assert.HasCount(1, facts.Package.DocumentationFiles);
        Assert.IsEmpty(facts.Package.MisplacedEntries);
        Assert.IsEmpty(facts.Package.ExtensionFiles);
    }


    /// <summary>
    /// Each representation is its own level with the same shape as the package, and the representations come out
    /// in the ordinal order of their labels.
    /// </summary>
    [TestMethod]
    public void EachRepresentationIsItsOwnLevelWithTheSameShape()
    {
        using EArkPackageSnapshotResult read = Read(FullPackage);
        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);

        Assert.HasCount(2, facts.Representations);
        Assert.AreEqual("rep1", facts.Representations[0].Label);
        Assert.AreEqual("rep2", facts.Representations[1].Label);
        Assert.AreEqual("representations/rep1/", facts.Representations[0].FolderEntryName);

        EArkRepresentationFacts? first = facts.FindRepresentation("rep1");
        Assert.IsNotNull(first);
        Assert.IsTrue(first.Contents.HasManifest, "CSIPSTR12");
        Assert.AreEqual("representations/rep1/METS.xml", first.Contents.Manifest!.Name);
        Assert.IsTrue(first.Contents.HasDataFolder, "CSIPSTR11");
        Assert.IsTrue(first.Contents.HasMetadataFolder, "CSIPSTR13");
        Assert.IsTrue(first.Contents.HasPreservationMetadataFolder, "CSIPSTR6 at representation level");
        Assert.IsTrue(first.Contents.HasSchemasFolder, "CSIPSTR15 at representation level");
        Assert.IsTrue(first.Contents.HasDocumentationFolder, "CSIPSTR16 at representation level");
        Assert.HasCount(1, first.Contents.DataFiles);

        EArkRepresentationFacts? second = facts.FindRepresentation("rep2");
        Assert.IsNotNull(second);
        Assert.IsFalse(second.Contents.HasSchemasFolder, "CSIPSTR15 is a SHOULD, and this representation has no schemas folder.");
        Assert.IsFalse(second.Contents.HasDocumentationFolder, "CSIPSTR16 is a SHOULD, and this representation has no documentation folder.");
    }


    /// <summary>
    /// The minimal package <c>CSIPSTR1</c> and <c>CSIPSTR4</c> together admit — a root folder holding nothing but
    /// <c>METS.xml</c> — is classified as exactly that, with every SHOULD-level folder absent and nothing
    /// misplaced.
    /// </summary>
    [TestMethod]
    public void TheMinimalPackageIsAManifestAndNothingElse()
    {
        using EArkPackageSnapshotResult read = Read([EArkPackageSource.TextFile("METS.xml", "<mets/>")]);
        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);

        Assert.IsTrue(facts.Package.HasManifest);
        Assert.IsFalse(facts.Package.HasMetadataFolder);
        Assert.IsFalse(facts.HasRepresentationsFolder);
        Assert.IsFalse(facts.Package.HasSchemasFolder);
        Assert.IsFalse(facts.Package.HasDocumentationFolder);
        Assert.IsEmpty(facts.Representations);
        Assert.IsEmpty(facts.Package.MisplacedEntries);
        Assert.IsFalse(facts.IsEmpty);
    }


    /// <summary>
    /// A package holding nothing at all is stated as empty rather than refused, and every position of it is
    /// absent.
    /// </summary>
    [TestMethod]
    public void AnEmptyPackageIsStatedAsEmpty()
    {
        using EArkPackageSnapshotResult read = Read([]);
        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);

        Assert.IsTrue(facts.IsEmpty);
        Assert.IsFalse(facts.Package.HasManifest);
        Assert.IsEmpty(facts.Entries);
        Assert.IsEmpty(facts.Representations);
    }


    /// <summary>
    /// A named folder that exists but holds nothing is present all the same. Every folder requirement asks
    /// whether the folder is there, and the specification's own companion text says the folders "ought to be
    /// present even if they are empty".
    /// </summary>
    [TestMethod]
    public void AnEmptyNamedFolderIsPresentWithNoFilesInIt()
    {
        using EArkPackageSnapshotResult read = Read(
        [
            EArkPackageSource.TextFile("METS.xml", "<mets/>"),
            EArkPackageSource.Folder("metadata"),
            EArkPackageSource.Folder("metadata/preservation"),
            EArkPackageSource.Folder("documentation")
        ]);

        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);

        Assert.IsTrue(facts.Package.HasMetadataFolder);
        Assert.IsTrue(facts.Package.HasPreservationMetadataFolder);
        Assert.IsTrue(facts.Package.HasDocumentationFolder);
        Assert.IsEmpty(facts.Package.MetadataFiles);
        Assert.IsEmpty(facts.Package.PreservationMetadataFiles);
        Assert.IsEmpty(facts.Package.DocumentationFiles);
    }


    /// <summary>
    /// A folder the vocabulary does not name is an extension point rather than a fault, which is what
    /// <c>CSIPSTR14</c> states: "the IP MAY be extended with additional sub-folders".
    /// </summary>
    [TestMethod]
    public void AFolderTheSpecificationDoesNotNameIsAnExtensionPoint()
    {
        using EArkPackageSnapshotResult read = Read(
        [
            EArkPackageSource.TextFile("METS.xml", "<mets/>"),
            EArkPackageSource.TextFile("submission/agreement.pdf", "an agreement"),
            EArkPackageSource.TextFile("README.md", "about this package")
        ]);

        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);

        Assert.HasCount(2, facts.Package.ExtensionFiles);
        Assert.IsEmpty(facts.Package.MisplacedEntries);
        Assert.AreEqual(EArkPackageEntryPlacement.Extension, PlacementOf(facts, "submission/agreement.pdf"));
        Assert.AreEqual(EArkPackageEntryPlacement.Extension, PlacementOf(facts, "README.md"));
        Assert.AreEqual(EArkPackageEntryPlacement.Extension, PlacementOf(facts, "submission/"));
    }


    /// <summary>
    /// A sub-folder of <c>metadata</c> that is none of the two the specification names is metadata of the level,
    /// because <c>CSIPSTR8</c> admits "additional sub-folders" beside them.
    /// </summary>
    [TestMethod]
    public void AMetadataSubFolderTheSpecificationDoesNotNameIsStillMetadata()
    {
        using EArkPackageSnapshotResult read = Read([EArkPackageSource.TextFile("metadata/technical/format.xml", "<format/>")]);
        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);

        Assert.AreEqual(EArkPackageEntryPlacement.Metadata, PlacementOf(facts, "metadata/technical/format.xml"));
        Assert.HasCount(1, facts.Package.MetadataFiles);
        Assert.IsFalse(facts.Package.HasOtherMetadataFolder, "CSIPSTR8 names metadata/other, and this package has no folder of that name.");
    }


    /// <summary>
    /// Every entry carrying a name the specification fixes at a position it does not put that name at is stated
    /// as misplaced, each for the requirement that places it somewhere else.
    /// </summary>
    [TestMethod]
    [DataRow("data/record.bin", DisplayName = "CSIPSTR11 places a data folder inside a representation")]
    [DataRow("representations/loose.txt", DisplayName = "CSIPSTR10 places one sub-folder per representation")]
    [DataRow("representations/rep1/representations/rep2/METS.xml", DisplayName = "CSIPSTR9 names the representations folder for the package")]
    public void AFixedNameAtAPositionTheSpecificationDoesNotPutItAtIsMisplaced(string entryName)
    {
        using EArkPackageSnapshotResult read = Read(
            [EArkPackageSource.TextFile("METS.xml", "<mets/>"), EArkPackageSource.TextFile(entryName, "content")]);

        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);

        Assert.AreEqual(EArkPackageEntryPlacement.Misplaced, PlacementOf(facts, entryName));
    }


    /// <summary>
    /// The manifest name used as a folder rather than as the file <c>CSIPSTR4</c> names is misplaced, and the
    /// level reports no manifest.
    /// </summary>
    [TestMethod]
    public void TheManifestNameUsedAsAFolderIsMisplacedAndIsNotAManifest()
    {
        using EArkPackageSnapshotResult read = Read([EArkPackageSource.TextFile("METS.xml/inside.txt", "content")]);
        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);

        Assert.IsFalse(facts.Package.HasManifest);
        Assert.AreEqual(EArkPackageEntryPlacement.Misplaced, PlacementOf(facts, "METS.xml/"));
        Assert.AreEqual(EArkPackageEntryPlacement.Misplaced, PlacementOf(facts, "METS.xml/inside.txt"));
    }


    /// <summary>
    /// A file deeper inside a named folder keeps that folder's position even when its own name is one the
    /// specification fixes elsewhere. Reading <c>metadata/descriptive/METS.xml</c> as a misplaced manifest would
    /// be this library inventing a requirement, and the rule is asserted here so that it cannot drift silently.
    /// </summary>
    [TestMethod]
    public void AManifestNameDeeperInsideANamedFolderKeepsThatFoldersPosition()
    {
        using EArkPackageSnapshotResult read = Read([EArkPackageSource.TextFile("metadata/descriptive/METS.xml", "<mets/>")]);
        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);

        Assert.AreEqual(EArkPackageEntryPlacement.DescriptiveMetadata, PlacementOf(facts, "metadata/descriptive/METS.xml"));
        Assert.IsEmpty(facts.Package.MisplacedEntries);
    }


    /// <summary>
    /// A file whose name differs from the manifest's only in case is not the manifest, and neither is one with a
    /// character added. <c>CSIPSTR4</c> names the file <c>METS.xml</c> literally, and matching case-insensitively
    /// would admit a package whose manifest a conforming reader on a case-sensitive file system cannot find.
    /// </summary>
    /// <remarks>
    /// <strong>This is a corpus finding, not a hypothetical.</strong> The reference material ships packages that
    /// break <c>CSIPSTR4</c> in exactly these ways — a manifest named in camel case, and one with a letter added
    /// at either end — and the first of them is what showed that a file system finding a name is not the same
    /// question as this library recognising it. The names below are the shapes those packages use.
    /// </remarks>
    [TestMethod]
    [DataRow("Mets.xml", DisplayName = "the manifest name in camel case")]
    [DataRow("mets.xml", DisplayName = "the manifest name in lower case")]
    [DataRow("METSa.xml", DisplayName = "a letter added at the end of the name")]
    [DataRow("aMETS.xml", DisplayName = "a letter added at the front of the name")]
    public void AFileWhoseNameIsNotExactlyTheManifestsIsNotTheManifest(string entryName)
    {
        using EArkPackageSnapshotResult read = Read([EArkPackageSource.TextFile(entryName, "<mets/>")]);
        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);

        Assert.IsFalse(facts.Package.HasManifest, $"\"{entryName}\" was taken for the manifest CSIPSTR4 names.");
        Assert.AreEqual(EArkPackageEntryPlacement.Extension, PlacementOf(facts, entryName));
    }


    /// <summary>
    /// A representation folder holding nothing is still a representation, which is what lets a rule state that it
    /// carries no manifest instead of failing to see it at all.
    /// </summary>
    [TestMethod]
    public void AnEmptyRepresentationFolderIsStillARepresentation()
    {
        using EArkPackageSnapshotResult read = Read(
            [EArkPackageSource.TextFile("METS.xml", "<mets/>"), EArkPackageSource.Folder("representations/rep1")]);

        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);

        Assert.HasCount(1, facts.Representations);
        Assert.AreEqual("rep1", facts.Representations[0].Label);
        Assert.IsFalse(facts.Representations[0].Contents.HasManifest, "CSIPSTR12 is a SHOULD and this representation carries no manifest.");
        Assert.IsTrue(facts.HasRepresentationsFolder);
    }


    /// <summary>
    /// Every entry of the snapshot is classified exactly once, no entry is left unevaluated, and the classified
    /// list is the snapshot in the snapshot's own order — the property every rule that reads these facts depends
    /// on.
    /// </summary>
    [TestMethod]
    public void TheClassificationIsTotalAndInTheSnapshotsOwnOrder()
    {
        using EArkPackageSnapshotResult read = Read(FullPackage);
        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);

        AssertClassificationIsTotal(facts);
    }


    /// <summary>
    /// The classifier is a function of the snapshot alone: stating the facts twice from one snapshot answers the
    /// same thing, and nothing about a package is read from anywhere else.
    /// </summary>
    [TestMethod]
    public void StatingTheFactsTwiceFromOneSnapshotAnswersTheSame()
    {
        using EArkPackageSnapshotResult read = Read(FullPackage);
        EArkPackageFacts first = EArkPackageReading.StateFacts(read.Snapshot!);
        EArkPackageFacts second = EArkPackageReading.StateFacts(read.Snapshot!);

        Assert.AreEqual(first.Package.HasManifest, second.Package.HasManifest);
        Assert.HasCount(first.Representations.Count, second.Representations);
        Assert.HasCount(first.Entries.Count, second.Entries);
        for(int i = 0; i < first.Entries.Count; ++i)
        {
            Assert.AreEqual(first.Entries[i].Placement, second.Entries[i].Placement);
            Assert.AreEqual(first.Entries[i].RepresentationLabel, second.Entries[i].RepresentationLabel);
        }
    }


    /// <summary>
    /// A package archived and a package stated directly reach the same classification, which is what makes one
    /// rule list serve a folder tree and an archive alike.
    /// </summary>
    [TestMethod]
    public void AnArchivedPackageAndAStatedPackageAreClassifiedTheSame()
    {
        using EArkPackageSnapshotResult stated = Read(FullPackage);
        EArkPackageFacts fromStated = EArkPackageReading.StateFacts(stated.Snapshot!);

        using PooledMemory archive = EArkPackageSource.WriteArchive(
            FullPackage,
            "urn-uuid-8b7a6c5d",
            new DateTimeOffset(2026, 7, 31, 13, 20, 0, TimeSpan.Zero),
            BaseMemoryPool.Shared);

        using EArkPackageSnapshotResult archived = EArkPackageSnapshotReading.ReadArchive(
            archive.AsReadOnlyMemory(),
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        EArkPackageFacts fromArchive = EArkPackageReading.StateFacts(archived.Snapshot!);

        Assert.HasCount(fromStated.Entries.Count, fromArchive.Entries);
        for(int i = 0; i < fromStated.Entries.Count; ++i)
        {
            Assert.AreEqual(fromStated.Entries[i].Entry.Name, fromArchive.Entries[i].Entry.Name);
            Assert.AreEqual(fromStated.Entries[i].Placement, fromArchive.Entries[i].Placement);
            Assert.AreEqual(fromStated.Entries[i].RepresentationLabel, fromArchive.Entries[i].RepresentationLabel);
        }

        Assert.AreEqual("urn-uuid-8b7a6c5d", fromArchive.RootFolderName);
        Assert.IsTrue(fromArchive.HasSingleRootFolder);
    }


    /// <summary>
    /// <strong>The reference leg.</strong> Every Information Package the optional local material carries —
    /// packages nothing in this repository wrote, found by their layout rather than by anyone's folder name — is
    /// classified completely: every entry reaches exactly one position, every representation the layout names is
    /// found, and the root manifest <c>CSIPSTR4</c> requires is where the requirement puts it.
    /// </summary>
    [TestMethod]
    public void EveryReferencePackageIsClassifiedCompletely()
    {
        IReadOnlyList<string> roots = EArkPackageSource.FindPackageRoots();
        if(roots.Count == 0)
        {
            Assert.Inconclusive(EArkPackageSource.MissingPackagesMessage);

            return;
        }

        for(int i = 0; i < roots.Count; ++i)
        {
            string root = roots[i];
            using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
                EArkPackageSource.StateNames(root),
                EArkPackageLimits.Conformant,
                BaseMemoryPool.Shared,
                EArkPackageSource.RootFolderNameOf(root));

            Assert.AreEqual(EArkPackageSnapshotStatus.Read, read.Status, $"The package at \"{root}\" was refused.");

            EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);
            AssertClassificationIsTotal(facts);

            Assert.IsTrue(facts.Package.HasManifest, $"CSIPSTR4: the package at \"{root}\" has no root METS.xml, yet it was found by having one.");
            Assert.IsTrue(facts.HasRepresentationsFolder, $"CSIPSTR9: the package at \"{root}\" has no representations folder, yet it was found by having one.");
        }

        TestContext.WriteLine($"Classified {roots.Count} reference Information Packages found by layout.");
    }


    /// <summary>
    /// Asserts that a classification accounts for every entry of its snapshot exactly once, in the snapshot's own
    /// order, with no entry left unevaluated and every representation label matching the folder it came from.
    /// </summary>
    /// <param name="facts">The facts to check.</param>
    private static void AssertClassificationIsTotal(EArkPackageFacts facts)
    {
        Assert.HasCount(facts.Snapshot.EntryCount, facts.Entries);

        var labels = new HashSet<string>(StringComparer.Ordinal);
        for(int i = 0; i < facts.Entries.Count; ++i)
        {
            EArkClassifiedEntry classified = facts.Entries[i];

            Assert.AreSame(facts.Snapshot.Entries[i], classified.Entry);
            Assert.AreNotEqual(
                EArkPackageEntryPlacement.NotEvaluated,
                classified.Placement,
                $"The entry \"{classified.Entry.Name}\" reached no position.");

            if(classified.RepresentationLabel is not null)
            {
                _ = labels.Add(classified.RepresentationLabel);
                Assert.StartsWith(
                    $"{EArkWellKnown.RepresentationsFolderName}{EArkWellKnown.PathSeparator}{classified.RepresentationLabel}{EArkWellKnown.PathSeparator}",
                    classified.Entry.Name);
            }
        }

        Assert.HasCount(labels.Count, facts.Representations);
        for(int i = 0; i < facts.Representations.Count; ++i)
        {
            Assert.Contains(facts.Representations[i].Label, labels);
        }
    }


    /// <summary>
    /// States the position a classification gave one named entry.
    /// </summary>
    /// <param name="facts">The facts to read.</param>
    /// <param name="entryName">The entry name, compared ordinally.</param>
    /// <returns>The position, or <see cref="EArkPackageEntryPlacement.NotEvaluated"/> when the package holds no such entry.</returns>
    private static EArkPackageEntryPlacement PlacementOf(EArkPackageFacts facts, string entryName)
    {
        for(int i = 0; i < facts.Entries.Count; ++i)
        {
            if(string.Equals(facts.Entries[i].Entry.Name, entryName, StringComparison.Ordinal))
            {
                return facts.Entries[i].Placement;
            }
        }

        return EArkPackageEntryPlacement.NotEvaluated;
    }


    /// <summary>
    /// Reads a hand-built tree into a snapshot within the default bounds.
    /// </summary>
    /// <param name="entries">The entries the tree holds.</param>
    /// <returns>The read result, which the caller disposes.</returns>
    private static EArkPackageSnapshotResult Read(IReadOnlyList<EArkPackageEntrySource> entries)
    {
        EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(entries, EArkPackageLimits.Conformant, BaseMemoryPool.Shared);
        Assert.AreEqual(EArkPackageSnapshotStatus.Read, read.Status);

        return read;
    }
}
