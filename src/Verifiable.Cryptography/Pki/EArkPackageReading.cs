using System;
using System.Collections.Generic;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// States what an Information Package's layout says about it: which of the positions the folder-structure
/// requirements of
/// <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 clause
/// 4.1</see> name are filled, which representations the package holds, and where each entry sits.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Names decide, and nothing else.</strong> Every position here comes from an entry's name compared
/// against <see cref="EArkWellKnown"/>, which is what the specification itself does: <c>CSIPSTR4</c> names
/// <c>METS.xml</c>, <c>CSIPSTR5</c> to <c>CSIPSTR8</c> name <c>metadata</c> and its sub-folders,
/// <c>CSIPSTR9</c> to <c>CSIPSTR13</c> name <c>representations</c> and what a representation folder holds, and
/// <c>CSIPSTR15</c> and <c>CSIPSTR16</c> name <c>schemas</c> and <c>documentation</c>. No file's content is
/// opened to decide what it is; a manifest is a file called <c>METS.xml</c> at a level's root until something
/// parses it.
/// </para>
/// <para>
/// <strong>This is the analogue of the container reader, not a reuse of it.</strong> An Information Package is
/// a folder tree with a fixed vocabulary of folder names; an Associated Signature Container is an archive with
/// a fixed vocabulary of entry-name patterns inside one reserved folder. The two classifications share their
/// shape — read names, sort into positions, verify nothing — and share nothing else.
/// </para>
/// <para>
/// <strong>Facts, not judgments.</strong> Every folder rule except <c>CSIPSTR1</c> and <c>CSIPSTR4</c> is a
/// SHOULD or a MAY, so an absent folder is a fact rather than a fault, and <c>CSIPSTR14</c> admits folders this
/// vocabulary does not name at all. Nothing here decides whether a package conforms.
/// </para>
/// </remarks>
public static class EArkPackageReading
{
    /// <summary>
    /// States the facts a package's layout carries.
    /// </summary>
    /// <param name="snapshot">The package as a value. Not owned by the returned facts; whoever owns it disposes it.</param>
    /// <returns>The facts. Classification cannot fail: an entry the vocabulary does not name is a position of its own.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="snapshot"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// The walk is a single loop over a flat, already-bounded list; the tree is expressed in the names rather
    /// than descended, so no layout a producer states can exhaust the stack.
    /// </remarks>
    public static EArkPackageFacts StateFacts(EArkPackageSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var packageLevel = new LevelBuilder();
        var representations = new Dictionary<string, RepresentationBuilder>(StringComparer.Ordinal);
        var classified = new List<EArkClassifiedEntry>(snapshot.Entries.Count);
        bool hasRepresentationsFolder = false;

        for(int i = 0; i < snapshot.Entries.Count; ++i)
        {
            EArkPackageEntry entry = snapshot.Entries[i];
            string canonical = entry.IsFolder ? entry.Name[..^1] : entry.Name;
            string[] segments = canonical.Split(EArkWellKnown.PathSeparator);

            string? label = null;
            EArkPackageEntryPlacement placement;
            int remaining;

            if(string.Equals(segments[0], EArkWellKnown.RepresentationsFolderName, StringComparison.Ordinal))
            {
                if(segments.Length == 1)
                {
                    placement = EArkPackageEntryPlacement.Representations;
                    remaining = 1;
                    hasRepresentationsFolder |= entry.IsFolder;
                }
                else if(segments.Length == 2)
                {
                    //CSIPSTR10: the folder holds one sub-folder per representation, so a file directly in it
                    //carries a fixed name at a position the specification does not put a file at.
                    placement = entry.IsFolder ? EArkPackageEntryPlacement.RepresentationRoot : EArkPackageEntryPlacement.Misplaced;
                    remaining = 1;
                    label = entry.IsFolder ? segments[1] : null;
                }
                else
                {
                    label = segments[1];
                    remaining = segments.Length - 2;
                    placement = StatePlacement(segments, 2, entry.IsFolder, isRepresentationLevel: true);
                }
            }
            else
            {
                remaining = segments.Length;
                placement = StatePlacement(segments, 0, entry.IsFolder, isRepresentationLevel: false);
            }

            classified.Add(new EArkClassifiedEntry { Entry = entry, Placement = placement, RepresentationLabel = label });

            if(label is null)
            {
                packageLevel.Add(entry, placement, remaining);

                continue;
            }

            if(!representations.TryGetValue(label, out RepresentationBuilder? representation))
            {
                representation = new RepresentationBuilder(label);
                representations.Add(label, representation);
            }

            if(placement == EArkPackageEntryPlacement.RepresentationRoot)
            {
                representation.FolderEntryName = entry.Name;

                continue;
            }

            representation.Level.Add(entry, placement, remaining);
        }

        var stated = new List<EArkRepresentationFacts>(representations.Count);
        foreach(KeyValuePair<string, RepresentationBuilder> representation in representations)
        {
            stated.Add(representation.Value.Build());
        }

        stated.Sort(static (left, right) => string.CompareOrdinal(left.Label, right.Label));

        return new EArkPackageFacts
        {
            Snapshot = snapshot,
            Package = packageLevel.Build(),
            HasRepresentationsFolder = hasRepresentationsFolder,
            Representations = stated,
            Entries = classified
        };
    }


    /// <summary>
    /// States the position one entry holds within one level of a package.
    /// </summary>
    /// <param name="segments">The entry's name, split at the path separator, without a trailing empty segment.</param>
    /// <param name="start">The segment the level begins at — zero for the package, two for a representation.</param>
    /// <param name="isFolder">Whether the entry names a folder.</param>
    /// <param name="isRepresentationLevel">Whether the level is a representation's rather than the package's.</param>
    /// <returns>The position the folder-structure requirements give the entry.</returns>
    private static EArkPackageEntryPlacement StatePlacement(string[] segments, int start, bool isFolder, bool isRepresentationLevel)
    {
        int remaining = segments.Length - start;
        if(remaining <= 0)
        {
            return EArkPackageEntryPlacement.RepresentationRoot;
        }

        string head = segments[start];

        if(string.Equals(head, EArkWellKnown.PackageManifestFileName, StringComparison.Ordinal))
        {
            //CSIPSTR4 and CSIPSTR12 both name a FILE at a level's root. The same name used as a folder, or as a
            //path segment with entries below it, is that fixed name at a position neither requirement states.
            return remaining == 1 && !isFolder ? EArkPackageEntryPlacement.Manifest : EArkPackageEntryPlacement.Misplaced;
        }

        if(string.Equals(head, EArkWellKnown.MetadataFolderName, StringComparison.Ordinal))
        {
            if(remaining == 1)
            {
                return EArkPackageEntryPlacement.Metadata;
            }

            string second = segments[start + 1];

            //CSIPSTR8 admits further sub-folders beside the two the specification names, so anything that is
            //neither is metadata of the level rather than a fault.
            return second switch
            {
                _ when string.Equals(second, EArkWellKnown.PreservationMetadataSubFolderName, StringComparison.Ordinal) => EArkPackageEntryPlacement.PreservationMetadata,
                _ when string.Equals(second, EArkWellKnown.DescriptiveMetadataSubFolderName, StringComparison.Ordinal) => EArkPackageEntryPlacement.DescriptiveMetadata,
                _ when string.Equals(second, EArkWellKnown.OtherMetadataSubFolderName, StringComparison.Ordinal) => EArkPackageEntryPlacement.OtherMetadata,
                _ => EArkPackageEntryPlacement.Metadata
            };
        }

        if(string.Equals(head, EArkWellKnown.SchemasFolderName, StringComparison.Ordinal))
        {
            return EArkPackageEntryPlacement.Schemas;
        }

        if(string.Equals(head, EArkWellKnown.DocumentationFolderName, StringComparison.Ordinal))
        {
            return EArkPackageEntryPlacement.Documentation;
        }

        if(string.Equals(head, EArkWellKnown.RepresentationDataFolderName, StringComparison.Ordinal))
        {
            //CSIPSTR11 places a data folder inside a representation and nowhere else.
            return isRepresentationLevel ? EArkPackageEntryPlacement.Data : EArkPackageEntryPlacement.Misplaced;
        }

        if(string.Equals(head, EArkWellKnown.RepresentationsFolderName, StringComparison.Ordinal))
        {
            //Only reachable at a representation's level: the package's own representations folder is routed
            //before this method is called. CSIPSTR9 names the folder for the package, and no requirement puts
            //one inside a representation.
            return EArkPackageEntryPlacement.Misplaced;
        }

        return EArkPackageEntryPlacement.Extension;
    }


    /// <summary>
    /// Collects the entries of one level of a package as they are classified, so that
    /// <see cref="EArkLevelFacts"/> can be stated once at the end rather than rebuilt per entry.
    /// </summary>
    private sealed class LevelBuilder
    {
        /// <summary>The <c>METS.xml</c> file at the level's root, once one has been seen.</summary>
        private EArkPackageEntry? manifest;

        /// <summary>Whether the level's <c>metadata</c> folder has been seen.</summary>
        private bool hasMetadataFolder;

        /// <summary>Whether the level's <c>metadata/preservation</c> folder has been seen.</summary>
        private bool hasPreservationMetadataFolder;

        /// <summary>Whether the level's <c>metadata/descriptive</c> folder has been seen.</summary>
        private bool hasDescriptiveMetadataFolder;

        /// <summary>Whether the level's <c>metadata/other</c> folder has been seen.</summary>
        private bool hasOtherMetadataFolder;

        /// <summary>Whether the level's <c>schemas</c> folder has been seen.</summary>
        private bool hasSchemasFolder;

        /// <summary>Whether the level's <c>documentation</c> folder has been seen.</summary>
        private bool hasDocumentationFolder;

        /// <summary>Whether the level's <c>data</c> folder has been seen.</summary>
        private bool hasDataFolder;

        /// <summary>The files in the level's <c>metadata</c> folder outside its named sub-folders.</summary>
        private readonly List<EArkPackageEntry>metadataFiles = [];

        /// <summary>The files in the level's <c>metadata/preservation</c> folder.</summary>
        private readonly List<EArkPackageEntry>preservationMetadataFiles = [];

        /// <summary>The files in the level's <c>metadata/descriptive</c> folder.</summary>
        private readonly List<EArkPackageEntry>descriptiveMetadataFiles = [];

        /// <summary>The files in the level's <c>metadata/other</c> folder.</summary>
        private readonly List<EArkPackageEntry>otherMetadataFiles = [];

        /// <summary>The files in the level's <c>schemas</c> folder.</summary>
        private readonly List<EArkPackageEntry>schemaFiles = [];

        /// <summary>The files in the level's <c>documentation</c> folder.</summary>
        private readonly List<EArkPackageEntry>documentationFiles = [];

        /// <summary>The files in the level's <c>data</c> folder.</summary>
        private readonly List<EArkPackageEntry>dataFiles = [];

        /// <summary>The files at positions the vocabulary names none of.</summary>
        private readonly List<EArkPackageEntry>extensionFiles = [];

        /// <summary>The entries carrying a fixed name at a position the specification does not put it at.</summary>
        private readonly List<EArkPackageEntry>misplacedEntries = [];


        /// <summary>
        /// Records one entry at the position it was classified to.
        /// </summary>
        /// <param name="entry">The entry.</param>
        /// <param name="placement">The position the layout gives it.</param>
        /// <param name="remaining">How many segments of the name belong to this level, which is what tells a named folder itself from something inside it.</param>
        public void Add(EArkPackageEntry entry, EArkPackageEntryPlacement placement, int remaining)
        {
            //A named folder's own entry states presence; a file inside it states content. A folder deeper inside
            //a named folder is neither: the position is already recorded and the folder holds no octets.
            _ = placement switch
            {
                EArkPackageEntryPlacement.Manifest => Assign(entry, ref manifest),
                EArkPackageEntryPlacement.Metadata => Record(entry, remaining == 1, ref hasMetadataFolder, metadataFiles),
                EArkPackageEntryPlacement.PreservationMetadata => Record(entry, remaining == 2, ref hasPreservationMetadataFolder, preservationMetadataFiles),
                EArkPackageEntryPlacement.DescriptiveMetadata => Record(entry, remaining == 2, ref hasDescriptiveMetadataFolder, descriptiveMetadataFiles),
                EArkPackageEntryPlacement.OtherMetadata => Record(entry, remaining == 2, ref hasOtherMetadataFolder, otherMetadataFiles),
                EArkPackageEntryPlacement.Schemas => Record(entry, remaining == 1, ref hasSchemasFolder, schemaFiles),
                EArkPackageEntryPlacement.Documentation => Record(entry, remaining == 1, ref hasDocumentationFolder, documentationFiles),
                EArkPackageEntryPlacement.Data => Record(entry, remaining == 1, ref hasDataFolder, dataFiles),
                EArkPackageEntryPlacement.Extension => AddFile(entry, extensionFiles),
                EArkPackageEntryPlacement.Misplaced => AddEntry(entry, misplacedEntries),
                _ => true
            };

            //Records a named folder's presence, or a file inside it.
            static bool Record(EArkPackageEntry entry, bool isTheFolderItself, ref bool presence, List<EArkPackageEntry> files)
            {
                if(entry.IsFolder)
                {
                    presence |= isTheFolderItself;

                    return true;
                }

                files.Add(entry);

                return true;
            }

            //Records the level's manifest, keeping the first when a level somehow states two.
            static bool Assign(EArkPackageEntry entry, ref EArkPackageEntry? manifest)
            {
                manifest ??= entry;

                return true;
            }

            //Records a file and ignores a folder, for positions that have no presence flag of their own.
            static bool AddFile(EArkPackageEntry entry, List<EArkPackageEntry> files)
            {
                if(!entry.IsFolder)
                {
                    files.Add(entry);
                }

                return true;
            }

            //Records an entry whether it is a file or a folder, because a misplaced folder is itself the fact.
            static bool AddEntry(EArkPackageEntry entry, List<EArkPackageEntry> entries)
            {
                entries.Add(entry);

                return true;
            }
        }


        /// <summary>
        /// States the level's facts.
        /// </summary>
        /// <returns>What the level holds.</returns>
        public EArkLevelFacts Build() => new()
        {
            Manifest = manifest,
            HasMetadataFolder = hasMetadataFolder,
            HasPreservationMetadataFolder = hasPreservationMetadataFolder,
            HasDescriptiveMetadataFolder = hasDescriptiveMetadataFolder,
            HasOtherMetadataFolder = hasOtherMetadataFolder,
            HasSchemasFolder = hasSchemasFolder,
            HasDocumentationFolder = hasDocumentationFolder,
            HasDataFolder = hasDataFolder,
            MetadataFiles = metadataFiles,
            PreservationMetadataFiles = preservationMetadataFiles,
            DescriptiveMetadataFiles = descriptiveMetadataFiles,
            OtherMetadataFiles = otherMetadataFiles,
            SchemaFiles = schemaFiles,
            DocumentationFiles = documentationFiles,
            DataFiles = dataFiles,
            ExtensionFiles = extensionFiles,
            MisplacedEntries = misplacedEntries
        };
    }


    /// <summary>
    /// Collects one representation as its entries are classified.
    /// </summary>
    /// <param name="label">The representation's label — the name of its folder under <c>representations</c>.</param>
    private sealed class RepresentationBuilder(string label)
    {
        /// <summary>Gets the representation's label (<c>CSIPSTR10</c>).</summary>
        public string Label { get; } = label;

        /// <summary>Gets what the representation's folder holds.</summary>
        public LevelBuilder Level { get; } = new();

        /// <summary>
        /// Gets or sets the name of the representation's own folder entry. The snapshot materialises every
        /// folder a name implies, so this is set for every representation an entry names.
        /// </summary>
        public string? FolderEntryName { get; set; }


        /// <summary>
        /// States the representation's facts.
        /// </summary>
        /// <returns>What the representation holds.</returns>
        public EArkRepresentationFacts Build() => new()
        {
            Label = Label,
            FolderEntryName = FolderEntryName
                ?? $"{EArkWellKnown.RepresentationsFolderName}{EArkWellKnown.PathSeparator}{Label}{EArkWellKnown.PathSeparator}",
            Contents = Level.Build()
        };
    }
}
