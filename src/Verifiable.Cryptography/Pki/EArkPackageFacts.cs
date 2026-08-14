using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The position the folder-structure requirements of
/// <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 clause
/// 4.1</see> give one entry of an Information Package.
/// </summary>
/// <remarks>
/// <para>
/// A position is a fact about where an entry sits, never a judgment about whether it should. Every
/// <c>CSIPSTR</c> requirement except <c>CSIPSTR1</c> and <c>CSIPSTR4</c> is a SHOULD or a MAY, so a package
/// missing a named folder is ordinary and a package carrying folders of its own is expressly admitted by
/// <c>CSIPSTR14</c>. What each position means for conformance is a validation profile's conclusion.
/// </para>
/// <para>
/// The same values serve both levels the specification gives a package: the package itself and each
/// representation, whose layout <c>CSIPSTR12</c>, <c>CSIPSTR13</c>, <c>CSIPSTR15</c> and <c>CSIPSTR16</c> make
/// the same shape. Which level an entry belongs to is stated beside its position, by
/// <see cref="EArkClassifiedEntry.RepresentationLabel"/>.
/// </para>
/// <para>
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised placement never reads as a position the
/// specification names.
/// </para>
/// </remarks>
public enum EArkPackageEntryPlacement
{
    /// <summary>No position stated. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The <c>METS.xml</c> file at the root of the package (<c>CSIPSTR4</c>) or of a representation (<c>CSIPSTR12</c>).</summary>
    Manifest = 1,

    /// <summary>The <c>metadata</c> folder, or something in it that is in none of the three sub-folders the specification names (<c>CSIPSTR5</c>, <c>CSIPSTR13</c>, <c>CSIPSTR8</c>).</summary>
    Metadata = 2,

    /// <summary>The <c>metadata/preservation</c> folder or something in it (<c>CSIPSTR6</c>).</summary>
    PreservationMetadata = 3,

    /// <summary>The <c>metadata/descriptive</c> folder or something in it (<c>CSIPSTR7</c>).</summary>
    DescriptiveMetadata = 4,

    /// <summary>The <c>metadata/other</c> folder or something in it (<c>CSIPSTR8</c>).</summary>
    OtherMetadata = 5,

    /// <summary>The <c>schemas</c> folder or something in it, at package or representation level (<c>CSIPSTR15</c>).</summary>
    Schemas = 6,

    /// <summary>The <c>documentation</c> folder or something in it, at package or representation level (<c>CSIPSTR16</c>).</summary>
    Documentation = 7,

    /// <summary>The <c>representations</c> folder itself (<c>CSIPSTR9</c>).</summary>
    Representations = 8,

    /// <summary>One representation's own folder under <c>representations</c> (<c>CSIPSTR10</c>).</summary>
    RepresentationRoot = 9,

    /// <summary>A representation's <c>data</c> folder or something in it (<c>CSIPSTR11</c>).</summary>
    Data = 10,

    /// <summary>
    /// An entry the specification names no position for, which <c>CSIPSTR14</c> expressly admits: "the IP MAY be
    /// extended with additional sub-folders". It is an extension point, not a fault.
    /// </summary>
    Extension = 11,

    /// <summary>
    /// An entry carrying a name the specification fixes, at a position the specification does not put that name
    /// at: a <c>data</c> folder at package level, where <c>CSIPSTR11</c> puts one only inside a representation; a
    /// file directly under <c>representations</c>, where <c>CSIPSTR10</c> puts one sub-folder per representation;
    /// a <c>METS.xml</c> used as a folder rather than as the manifest file <c>CSIPSTR4</c> and <c>CSIPSTR12</c>
    /// name; a <c>representations</c> folder inside a representation, which no requirement places there.
    /// </summary>
    /// <remarks>
    /// A file deeper inside a named folder keeps that folder's position even when its own name is one the
    /// specification fixes elsewhere — <c>metadata/descriptive/METS.xml</c> is a descriptive-metadata file, and
    /// reading it as a misplaced manifest would be this library inventing a requirement.
    /// </remarks>
    Misplaced = 12
}


/// <summary>
/// One entry of a package together with the position the layout gives it.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> <see cref="Entry"/> is a non-owning reference into the
/// <see cref="EArkPackageSnapshot"/> the facts were stated from, which its own owner disposes.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record EArkClassifiedEntry
{
    /// <summary>Gets the entry.</summary>
    public required EArkPackageEntry Entry { get; init; }

    /// <summary>Gets the position the layout gives it.</summary>
    public required EArkPackageEntryPlacement Placement { get; init; }

    /// <summary>
    /// Gets the label of the representation the entry belongs to (<c>CSIPSTR10</c>), or <see langword="null"/>
    /// when the entry belongs to the package itself.
    /// </summary>
    public string? RepresentationLabel { get; init; }


    /// <summary>A short debugger string showing the position, the representation and the name.</summary>
    private string DebuggerDisplay =>
        $"EArkClassifiedEntry({Placement}{(RepresentationLabel is null ? string.Empty : $"@{RepresentationLabel}")}, {Entry.Name})";
}


/// <summary>
/// What one level of a package holds: the folders it has and the files at each position.
/// </summary>
/// <remarks>
/// <para>
/// The package and each of its representations have the same shape — a manifest, a <c>metadata</c> folder with
/// its named sub-folders, <c>schemas</c> and <c>documentation</c> — so one record states both, and only the
/// positions that exist at one level (<see cref="DataFiles"/> for a representation) are empty at the other.
/// </para>
/// <para>
/// <strong>Presence is stated apart from content.</strong> A folder that exists but holds nothing is a fact a
/// requirement turns on: every folder rule of <c>CSIPSTR5</c> to <c>CSIPSTR16</c> asks whether the folder is
/// there, not whether it has files in it, and the companion text to those requirements says outright that the
/// folders "ought to be present even if they are empty". The <c>Has…</c> members answer the first question and
/// the file lists the second.
/// </para>
/// <para>
/// <strong>Ownership.</strong> Every entry here is a non-owning reference into the snapshot the facts were
/// stated from.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record EArkLevelFacts
{
    /// <summary>Gets the <c>METS.xml</c> file at this level's root, or <see langword="null"/> when there is none.</summary>
    public EArkPackageEntry? Manifest { get; init; }

    /// <summary>Gets whether this level has a <c>metadata</c> folder (<c>CSIPSTR5</c>, <c>CSIPSTR13</c>).</summary>
    public required bool HasMetadataFolder { get; init; }

    /// <summary>Gets whether this level has a <c>metadata/preservation</c> folder (<c>CSIPSTR6</c>).</summary>
    public required bool HasPreservationMetadataFolder { get; init; }

    /// <summary>Gets whether this level has a <c>metadata/descriptive</c> folder (<c>CSIPSTR7</c>).</summary>
    public required bool HasDescriptiveMetadataFolder { get; init; }

    /// <summary>Gets whether this level has a <c>metadata/other</c> folder (<c>CSIPSTR8</c>).</summary>
    public required bool HasOtherMetadataFolder { get; init; }

    /// <summary>Gets whether this level has a <c>schemas</c> folder (<c>CSIPSTR15</c>).</summary>
    public required bool HasSchemasFolder { get; init; }

    /// <summary>Gets whether this level has a <c>documentation</c> folder (<c>CSIPSTR16</c>).</summary>
    public required bool HasDocumentationFolder { get; init; }

    /// <summary>Gets whether this level has a <c>data</c> folder (<c>CSIPSTR11</c>), which the specification places only inside a representation.</summary>
    public required bool HasDataFolder { get; init; }

    /// <summary>Gets the files in the <c>metadata</c> folder that are in none of its three named sub-folders.</summary>
    public required IReadOnlyList<EArkPackageEntry> MetadataFiles { get; init; }

    /// <summary>Gets the files in <c>metadata/preservation</c> (<c>CSIPSTR6</c>).</summary>
    public required IReadOnlyList<EArkPackageEntry> PreservationMetadataFiles { get; init; }

    /// <summary>Gets the files in <c>metadata/descriptive</c> (<c>CSIPSTR7</c>).</summary>
    public required IReadOnlyList<EArkPackageEntry> DescriptiveMetadataFiles { get; init; }

    /// <summary>Gets the files in <c>metadata/other</c> (<c>CSIPSTR8</c>).</summary>
    public required IReadOnlyList<EArkPackageEntry> OtherMetadataFiles { get; init; }

    /// <summary>Gets the files in <c>schemas</c> (<c>CSIPSTR15</c>).</summary>
    public required IReadOnlyList<EArkPackageEntry> SchemaFiles { get; init; }

    /// <summary>Gets the files in <c>documentation</c> (<c>CSIPSTR16</c>).</summary>
    public required IReadOnlyList<EArkPackageEntry> DocumentationFiles { get; init; }

    /// <summary>Gets the files in a representation's <c>data</c> folder (<c>CSIPSTR11</c>).</summary>
    public required IReadOnlyList<EArkPackageEntry> DataFiles { get; init; }

    /// <summary>Gets the files at positions the specification names none of, which <c>CSIPSTR14</c> admits.</summary>
    public required IReadOnlyList<EArkPackageEntry> ExtensionFiles { get; init; }

    /// <summary>Gets the entries carrying a name the specification fixes at a position it does not put that name at; see <see cref="EArkPackageEntryPlacement.Misplaced"/>.</summary>
    public required IReadOnlyList<EArkPackageEntry> MisplacedEntries { get; init; }


    /// <summary>Gets whether this level has a <c>METS.xml</c> file at its root (<c>CSIPSTR4</c>, <c>CSIPSTR12</c>).</summary>
    public bool HasManifest => Manifest is not null;


    /// <summary>A short debugger string showing which named folders the level has.</summary>
    private string DebuggerDisplay =>
        $"EArkLevelFacts(manifest {HasManifest}, metadata {HasMetadataFolder}, schemas {HasSchemasFolder}, documentation {HasDocumentationFolder}, data {HasDataFolder})";
}


/// <summary>
/// One representation of a package: the label its folder is named with, and what that folder holds.
/// </summary>
/// <remarks>
/// <c>CSIPSTR10</c> asks a package to hold "one sub-folder per representation", each "uniquely named" within the
/// package; the label is that folder's name, which the snapshot's own duplicate rule makes unique.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record EArkRepresentationFacts
{
    /// <summary>Gets the representation's label — the name of its folder under <c>representations</c> (<c>CSIPSTR10</c>).</summary>
    public required string Label { get; init; }

    /// <summary>Gets the name of the representation's folder entry, root-relative and ending in the path separator.</summary>
    public required string FolderEntryName { get; init; }

    /// <summary>Gets what the representation's folder holds.</summary>
    public required EArkLevelFacts Contents { get; init; }


    /// <summary>A short debugger string showing the label and whether the representation carries its own manifest.</summary>
    private string DebuggerDisplay => $"EArkRepresentationFacts({Label}, manifest {Contents.HasManifest})";
}


/// <summary>
/// What one Information Package states about itself by its layout: which of the positions
/// <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 clause
/// 4.1</see> names are filled, which are empty, and which entries carry a fixed name at a position the
/// specification does not put it at.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Nothing here is judged.</strong> These are the facts a validation starts from — which folders exist,
/// which files sit where, how many representations there are, whether the package arrived under a single root
/// folder. Whether the package conforms is a rule list's conclusion, and every rule of that list reads its
/// answer from here rather than walking the tree again.
/// </para>
/// <para>
/// <strong>Ownership.</strong> These facts hold non-owning references into <see cref="Snapshot"/>; whoever owns
/// the snapshot disposes it, and disposing it invalidates every entry these facts point at. That is the
/// opposite of the container reader's arrangement, where the facts own the archive, and it is deliberate: a
/// package snapshot is a value a caller builds once and may state facts about more than once.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record EArkPackageFacts
{
    /// <summary>Gets the snapshot the facts were stated from. Not owned by this instance.</summary>
    public required EArkPackageSnapshot Snapshot { get; init; }

    /// <summary>Gets what the package's own root holds.</summary>
    public required EArkLevelFacts Package { get; init; }

    /// <summary>Gets whether the package has a <c>representations</c> folder (<c>CSIPSTR9</c>).</summary>
    public required bool HasRepresentationsFolder { get; init; }

    /// <summary>Gets the representations, in the ordinal order of their labels (<c>CSIPSTR10</c>).</summary>
    public required IReadOnlyList<EArkRepresentationFacts> Representations { get; init; }

    /// <summary>Gets every entry of the snapshot with the position the layout gives it, in the snapshot's own order.</summary>
    public required IReadOnlyList<EArkClassifiedEntry> Entries { get; init; }


    /// <summary>Gets whether the package's entries were found under exactly one root folder — the fact <c>CSIPSTR1</c> is judged from.</summary>
    public bool HasSingleRootFolder => Snapshot.HasSingleRootFolder;

    /// <summary>Gets the name of that root folder, or <see langword="null"/> when there is none to state — the fact <c>CSIPSTR2</c> is judged from.</summary>
    public string? RootFolderName => Snapshot.RootFolderName;

    /// <summary>Gets whether the package holds no entries at all.</summary>
    public bool IsEmpty => Snapshot.EntryCount == 0;


    /// <summary>
    /// Finds one representation by its label.
    /// </summary>
    /// <param name="label">The label, compared ordinally.</param>
    /// <returns>The representation, or <see langword="null"/> when the package carries none under that label.</returns>
    public EArkRepresentationFacts? FindRepresentation(string label)
    {
        for(int i = 0; i < Representations.Count; ++i)
        {
            if(string.Equals(Representations[i].Label, label, System.StringComparison.Ordinal))
            {
                return Representations[i];
            }
        }

        return null;
    }


    /// <summary>A short debugger string showing the manifest, the representation count and the root folder.</summary>
    private string DebuggerDisplay =>
        $"EArkPackageFacts(manifest {Package.HasManifest}, {Representations.Count} representations, root {RootFolderName ?? "none stated"})";
}
