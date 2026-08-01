using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Turns an Information Package sitting on a file system into the value snapshot the library validates, and finds
/// the reference packages the optional local material carries.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why this lives here and not in the library.</strong> Contract ruling R-4 keeps every file-system walk
/// out of validation: a package reaches the library as a value a caller states, so that a rule is a pure function
/// of what it was handed, cannot be pointed at a link leading out of the package, and can be replayed. Reading a
/// directory is exactly the step a caller performs and is therefore staged here, in the same way the worked XML
/// bindings are staged beside the seams they implement.
/// </para>
/// <para>
/// <strong>Discovery is by layout, never by the name of a folder somebody cloned.</strong> A package is
/// recognised by what
/// <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 clause
/// 4.1</see> says a package is: a folder holding a <c>METS.xml</c> file (<c>CSIPSTR4</c>) and a
/// <c>representations</c> sub-folder (<c>CSIPSTR9</c>). Nothing here knows what the reference material is called
/// or where it came from.
/// </para>
/// <para>
/// The reference material lives under <c>tempdocs/</c>, which is not a repository asset, so every discovery
/// method answers an empty result when it is absent and the tests that use it report inconclusive — the shape
/// <see cref="EArkSchemaOracle"/> established.
/// </para>
/// </remarks>
internal static class EArkPackageSource
{
    /// <summary>What a test reports when the optional local reference material is absent.</summary>
    internal static string MissingPackagesMessage { get; } =
        "No Information Package was found under tempdocs/earchiving-reference; the reference packages are optional local reference material, not a repository asset.";

    /// <summary>The separator an entry name of a package uses, whichever file system the package was read from.</summary>
    private static char EntrySeparator { get; } = EArkWellKnown.PathSeparator;


    /// <summary>
    /// Finds every folder under the reference material that is an Information Package by its layout.
    /// </summary>
    /// <returns>
    /// The package roots, ordered ordinally by path so that a test picking one picks the same one every run.
    /// Empty when the reference material is absent.
    /// </returns>
    /// <remarks>
    /// <para>
    /// A package root is a folder that directly holds a <c>METS.xml</c> file and a <c>representations</c>
    /// sub-folder. A representation's own folder is not one: it holds its <c>METS.xml</c> (<c>CSIPSTR12</c>) but
    /// no <c>representations</c> folder of its own, which is what keeps the two levels apart without reading a
    /// single file.
    /// </para>
    /// <para>
    /// <strong>Both names are compared ordinally, and that is load-bearing.</strong> A file system matches names
    /// case-insensitively on some platforms and case-sensitively on others, while the library compares the names
    /// the specification fixes exactly — a package whose manifest a case-folding file system finds is not a
    /// package a conforming reader on a case-sensitive one can read. The reference material carries exactly that
    /// case, deliberately: it ships packages that break <c>CSIPSTR4</c> by naming the manifest in camel case, and
    /// a discovery that let the file system decide would find them and then assert they carry a manifest the
    /// library correctly refuses to see.
    /// </para>
    /// </remarks>
    internal static IReadOnlyList<string> FindPackageRoots()
    {
        string? referenceMaterial = TryFindReferenceMaterial();
        if(referenceMaterial is null)
        {
            return [];
        }

        var roots = new List<string>();
        foreach(string manifest in Directory.EnumerateFiles(referenceMaterial, EArkWellKnown.PackageManifestFileName, SearchOption.AllDirectories))
        {
            string? candidate = Path.GetDirectoryName(manifest);
            if(candidate is not null
                && string.Equals(Path.GetFileName(manifest), EArkWellKnown.PackageManifestFileName, StringComparison.Ordinal)
                && HasChildFolder(candidate, EArkWellKnown.RepresentationsFolderName))
            {
                roots.Add(candidate);
            }
        }

        roots.Sort(static (left, right) => string.CompareOrdinal(left, right));

        return roots;
    }


    /// <summary>
    /// States whether a folder holds a sub-folder of exactly the given name, compared ordinally whatever the
    /// file system would compare.
    /// </summary>
    /// <param name="parent">The folder to look in.</param>
    /// <param name="folderName">The sub-folder's name, which may itself be a relative path of segments.</param>
    /// <returns><see langword="true"/> when the sub-folder is there under exactly that name.</returns>
    private static bool HasChildFolder(string parent, string folderName)
    {
        string current = parent;
        foreach(string segment in folderName.Split(EntrySeparator))
        {
            string? found = null;
            foreach(string candidate in Directory.EnumerateDirectories(current))
            {
                if(string.Equals(Path.GetFileName(candidate), segment, StringComparison.Ordinal))
                {
                    found = candidate;
                    break;
                }
            }

            if(found is null)
            {
                return false;
            }

            current = found;
        }

        return true;
    }


    /// <summary>
    /// Finds the package root whose layout fills every position the folder-structure requirements name, which is
    /// the richest input a classifier can be given.
    /// </summary>
    /// <returns>The root, or <see langword="null"/> when the reference material carries none.</returns>
    /// <remarks>
    /// The predicate is the five folders <c>CSIPSTR6</c>, <c>CSIPSTR7</c>, <c>CSIPSTR9</c>, <c>CSIPSTR15</c> and
    /// <c>CSIPSTR16</c> name. More than one package satisfies it, and the ordinally first is taken so that the
    /// test reads the same package every run.
    /// </remarks>
    internal static string? FindRichestPackageRoot()
    {
        IReadOnlyList<string> roots = FindPackageRoots();
        for(int i = 0; i < roots.Count; ++i)
        {
            string root = roots[i];
            if(HasChildFolder(root, EArkWellKnown.PreservationMetadataFolderName)
                && HasChildFolder(root, EArkWellKnown.DescriptiveMetadataFolderName)
                && HasChildFolder(root, EArkWellKnown.SchemasFolderName)
                && HasChildFolder(root, EArkWellKnown.DocumentationFolderName))
            {
                return root;
            }
        }

        return null;
    }


    /// <summary>
    /// States the entries of a package on a file system, without reading any octets.
    /// </summary>
    /// <param name="packageRoot">The package's root folder.</param>
    /// <returns>Every folder and file below the root, under names relative to it.</returns>
    /// <remarks>
    /// The classifier reads names and nothing else, so a name-only statement is a complete input for it. It is
    /// what lets every package the reference material carries be classified without reading a hundred megabytes.
    /// </remarks>
    internal static IReadOnlyList<EArkPackageEntrySource> StateNames(string packageRoot)
    {
        var entries = new List<EArkPackageEntrySource>();
        foreach(string folder in Directory.EnumerateDirectories(packageRoot, "*", SearchOption.AllDirectories))
        {
            entries.Add(new EArkPackageEntrySource { Name = ToEntryName(packageRoot, folder) + EntrySeparator });
        }

        foreach(string file in Directory.EnumerateFiles(packageRoot, "*", SearchOption.AllDirectories))
        {
            entries.Add(new EArkPackageEntrySource { Name = ToEntryName(packageRoot, file) });
        }

        return entries;
    }


    /// <summary>
    /// States the entries of a package on a file system with their octets.
    /// </summary>
    /// <param name="packageRoot">The package's root folder.</param>
    /// <returns>Every folder and file below the root, folders carrying nothing and files carrying their octets.</returns>
    /// <remarks>
    /// The octets are read into arrays this method owns and the snapshot reader copies them into pooled carriers,
    /// so the arrays are unreachable the moment the snapshot exists — the same hand-over
    /// <see cref="AsicZipEntrySource"/> makes when a container is written.
    /// </remarks>
    internal static IReadOnlyList<EArkPackageEntrySource> StateEntries(string packageRoot)
    {
        var entries = new List<EArkPackageEntrySource>();
        foreach(string folder in Directory.EnumerateDirectories(packageRoot, "*", SearchOption.AllDirectories))
        {
            entries.Add(new EArkPackageEntrySource { Name = ToEntryName(packageRoot, folder) + EntrySeparator });
        }

        foreach(string file in Directory.EnumerateFiles(packageRoot, "*", SearchOption.AllDirectories))
        {
            entries.Add(new EArkPackageEntrySource { Name = ToEntryName(packageRoot, file), Content = File.ReadAllBytes(file) });
        }

        return entries;
    }


    /// <summary>
    /// Reads a package on a file system into the value snapshot the library validates.
    /// </summary>
    /// <param name="packageRoot">The package's root folder, whose name becomes the snapshot's root-folder fact.</param>
    /// <param name="limits">The bounds to read within.</param>
    /// <param name="pool">The memory pool every entry's octets are rented from.</param>
    /// <returns>What the reader concluded. The caller owns and disposes it.</returns>
    internal static EArkPackageSnapshotResult ReadFolder(string packageRoot, EArkPackageLimits limits, BaseMemoryPool pool) =>
        EArkPackageSnapshotReading.Create(StateEntries(packageRoot), limits, pool, RootFolderNameOf(packageRoot));


    /// <summary>
    /// Writes the same entries into a generic archive that unpacks to one root folder, as <c>CSIPSTR1</c> asks an
    /// archived package to.
    /// </summary>
    /// <param name="entries">The package's entries, under names relative to the package root.</param>
    /// <param name="rootFolderName">The name of the folder the archive is to unpack to.</param>
    /// <param name="lastModified">The instant every entry records, stated rather than read from a clock.</param>
    /// <param name="pool">The memory pool the archive's octets are rented from.</param>
    /// <returns>The archive's octets. The caller owns and disposes them.</returns>
    /// <remarks>
    /// The archive writer this uses is the container layer's, because it is the only ZIP writer this repository
    /// has and a package archived by it is a plain ZIP: no media type is stated, so no <c>mimetype</c> entry is
    /// written and none of the container-format rules that entry carries applies.
    /// </remarks>
    internal static PooledMemory WriteArchive(
        IReadOnlyList<EArkPackageEntrySource> entries,
        string rootFolderName,
        DateTimeOffset lastModified,
        BaseMemoryPool pool)
    {
        var archived = new List<AsicZipEntrySource>(entries.Count + 1)
        {
            new() { Name = rootFolderName + EntrySeparator, Content = ReadOnlyMemory<byte>.Empty }
        };

        for(int i = 0; i < entries.Count; ++i)
        {
            archived.Add(new AsicZipEntrySource
            {
                Name = rootFolderName + EntrySeparator + entries[i].Name,
                Content = entries[i].Content
            });
        }

        return AsicZipAuthoring.Write(
            new AsicZipAuthoringContext { Entries = archived, LastModified = lastModified },
            pool);
    }


    /// <summary>
    /// States the root-folder name a package's own folder gives it, which <c>CSIPSTR2</c> asks to be the
    /// package's <c>mets/@OBJID</c>.
    /// </summary>
    /// <param name="packageRoot">The package's root folder.</param>
    /// <returns>The folder's own name, without any path leading to it.</returns>
    internal static string RootFolderNameOf(string packageRoot) =>
        new DirectoryInfo(packageRoot).Name;


    /// <summary>
    /// Turns a path on a file system into an entry name relative to the package root.
    /// </summary>
    /// <param name="packageRoot">The package's root folder.</param>
    /// <param name="path">The path to name.</param>
    /// <returns>The name, root-relative and separated by the package separator whichever separator the file system uses.</returns>
    private static string ToEntryName(string packageRoot, string path) =>
        Path.GetRelativePath(packageRoot, path)
            .Replace(Path.DirectorySeparatorChar, EntrySeparator)
            .Replace(Path.AltDirectorySeparatorChar, EntrySeparator);


    /// <summary>
    /// Walks up from the test assembly's location to the repository root and names the reference-material folder.
    /// </summary>
    /// <returns>The folder's path, or <see langword="null"/> when it is absent.</returns>
    private static string? TryFindReferenceMaterial()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while(current is not null && !File.Exists(Path.Combine(current.FullName, "Verifiable.slnx")))
        {
            current = current.Parent;
        }

        if(current is null)
        {
            return null;
        }

        string referenceMaterial = Path.Combine(current.FullName, "tempdocs", "earchiving-reference");

        return Directory.Exists(referenceMaterial) ? referenceMaterial : null;
    }


    /// <summary>
    /// States an entry's octets from text, for the hand-built trees the classification tests are written over.
    /// </summary>
    /// <param name="name">The entry name, root-relative and <c>/</c>-separated.</param>
    /// <param name="content">The entry's content as text, encoded as UTF-8.</param>
    /// <returns>The entry.</returns>
    internal static EArkPackageEntrySource TextFile(string name, string content) =>
        new() { Name = name, Content = Encoding.UTF8.GetBytes(content) };


    /// <summary>
    /// States a folder entry, for the hand-built trees the classification tests are written over.
    /// </summary>
    /// <param name="name">The folder name, root-relative and <c>/</c>-separated, without a trailing separator.</param>
    /// <returns>The entry.</returns>
    internal static EArkPackageEntrySource Folder(string name) =>
        new() { Name = name + EntrySeparator };
}
