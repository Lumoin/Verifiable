using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Turns an Information Package sitting on a file system into the entries or value snapshot the library
/// validates.
/// </summary>
/// <remarks>
/// This library keeps every file-system walk out of validation: a package reaches the library as a value a
/// caller states, so that a rule is a pure function of what it was handed, cannot be pointed at a link leading out
/// of the package, and can be replayed. Reading a directory is exactly the step a caller performs and is
/// therefore staged here, in the same way the worked XML bindings are staged beside the seams they implement.
/// </remarks>
internal static class EArkPackageSource
{
    /// <summary>The separator an entry name of a package uses, whichever file system the package was read from.</summary>
    private static char EntrySeparator { get; } = EArkWellKnown.PathSeparator;


    /// <summary>
    /// States the entries of a package on a file system, without reading any octets.
    /// </summary>
    /// <param name="packageRoot">The package's root folder.</param>
    /// <returns>Every folder and file below the root, under names relative to it.</returns>
    /// <remarks>
    /// The classifier reads names and nothing else, so a name-only statement is a complete input for it — a
    /// package can be classified without reading a single one of its octets.
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
