using System;
using System.Buffers;
using System.Collections.Generic;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Builds an <see cref="EArkPackageSnapshot"/> from the two ways an Information Package arrives: the entries a
/// caller read out of a folder tree, and a generic archive.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Nothing here touches a file system.</strong> The folder path is the caller's — it states the entries
/// it read, and this library normalises and bounds them. That is deliberate: a validation that walked a live
/// tree would depend on what the tree looked like while it ran, could be pointed at a link leading out of the
/// package, and could not be replayed. A worked filesystem-to-snapshot helper is staged as a promotable example
/// under the test project.
/// </para>
/// <para>
/// <strong>What the archive path reuses, and what it does not.</strong> It reuses exactly two things from the
/// container layer: <see cref="AsicZipReading"/>'s hostile-input archive parsing — the central-directory and
/// local-header cross-check, the ZIP64 and split-archive refusals, the decompression-bomb bound — and
/// <see cref="AsicZipEntryNaming"/>'s path-safety rules. It reuses none of the container semantics above that
/// layer, because an Information Package is a folder tree that happens to be archived rather than a container
/// format: the layout of
/// <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 clause
/// 4.1</see> gives an entry its meaning, and <c>CSIPSTR3</c> leaves the archive format itself to the parties
/// exchanging the package.
/// </para>
/// <para>
/// <strong>One consequence of that reuse is stated rather than hidden.</strong> The archive layer applies the
/// media-type rules of its own source specification when, and only when, an archive names an entry
/// <c>mimetype</c> at its root. E-ARK gives no meaning to such an entry, so those rules are inert for every
/// package — but an archive that really carries one is judged by them, and is refused rather than silently
/// reinterpreted. The refusal reaches the caller verbatim as
/// <see cref="EArkPackageSnapshotResult.ArchiveStatus"/>. Writing a second archive parser to remove one
/// conditional leg would trade a documented edge for two implementations of the same format, which is the worse
/// of the two.
/// </para>
/// </remarks>
public static class EArkPackageSnapshotReading
{
    /// <summary>
    /// Builds a snapshot from entries a caller read.
    /// </summary>
    /// <param name="entries">The entries, under names relative to the package root.</param>
    /// <param name="limits">The bounds to read within. <see cref="EArkPackageLimits.Conformant"/> is the default set.</param>
    /// <param name="pool">The memory pool every entry's octets are rented from.</param>
    /// <param name="rootFolderName">
    /// The name of the folder the caller read the entries relative to, when it has one to state. It is carried
    /// as the fact <c>CSIPSTR1</c> and <c>CSIPSTR2</c> are judged from and is never used to resolve a name.
    /// </param>
    /// <returns>What the reader concluded, and the snapshot when it read one. The caller owns and disposes the result.</returns>
    /// <exception cref="ArgumentNullException">When an argument other than <paramref name="rootFolderName"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// Nothing is retained: every entry's octets are copied into memory rented from <paramref name="pool"/>, so
    /// the caller may reuse the buffers it passed as soon as this method returns.
    /// </remarks>
    public static EArkPackageSnapshotResult Create(
        IReadOnlyList<EArkPackageEntrySource> entries,
        EArkPackageLimits limits,
        MemoryPool<byte> pool,
        string? rootFolderName = null)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentNullException.ThrowIfNull(limits);
        ArgumentNullException.ThrowIfNull(pool);

        //A caller stating entries has already named the root it read them relative to, so the single-root fact
        //CSIPSTR1 is judged from holds by construction on this path. Only the archive path can find otherwise.
        return Build(entries, limits, pool, rootFolderName, hasSingleRootFolder: true);
    }


    /// <summary>
    /// Builds a snapshot from a package that arrived as an archive.
    /// </summary>
    /// <param name="archiveBytes">The archive's octets, as they arrived.</param>
    /// <param name="limits">The bounds to read within. <see cref="EArkPackageLimits.Conformant"/> is the default set.</param>
    /// <param name="pool">The memory pool every entry's octets are rented from.</param>
    /// <returns>What the reader concluded, and the snapshot when it read one. The caller owns and disposes the result.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <remarks>
    /// <para>
    /// <c>CSIPSTR1</c> requires an archived package to unpack to a single root folder. Where the archive does
    /// exactly that, the folder's name is stripped from every entry so that the snapshot's names are relative to
    /// the package root whichever way the package arrived, and the name is carried as
    /// <see cref="EArkPackageSnapshot.RootFolderName"/>. Where it does not, the names are left as the archive
    /// states them and <see cref="EArkPackageSnapshot.HasSingleRootFolder"/> says so. Neither outcome is a
    /// refusal: whether a package satisfies <c>CSIPSTR1</c> is a judgment, and this method states facts.
    /// </para>
    /// <para>
    /// The archive's entries are read into pooled carriers by the archive layer and copied once more into the
    /// snapshot's own, after which the archive's are released. The copy is what lets the snapshot outlive the
    /// archive it came from, which every caller of this method needs.
    /// </para>
    /// </remarks>
    public static EArkPackageSnapshotResult ReadArchive(ReadOnlyMemory<byte> archiveBytes, EArkPackageLimits limits, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(limits);
        ArgumentNullException.ThrowIfNull(pool);

        using AsicZipReadResult archive = AsicZipReading.Read(archiveBytes, limits.ToArchiveLimits(), pool);
        if(!archive.IsRead || archive.Container is null)
        {
            return new EArkPackageSnapshotResult
            {
                Status = EArkPackageSnapshotStatus.ArchiveRefused,
                ArchiveStatus = archive.Status,
                RejectedEntryName = archive.RejectedEntryName,
                RejectedEntryNameStatus = archive.RejectedEntryNameStatus
            };
        }

        IReadOnlyList<AsicZipEntry> archived = archive.Container.Entries;
        bool hasSingleRootFolder = TryStateRootFolder(archived, out string? rootFolderName);
        int prefixLength = hasSingleRootFolder ? rootFolderName!.Length + 1 : 0;

        var sources = new List<EArkPackageEntrySource>(archived.Count);
        for(int i = 0; i < archived.Count; ++i)
        {
            AsicZipEntry entry = archived[i];
            string name = entry.Name[prefixLength..];
            if(name.Length == 0)
            {
                //The root folder's own entry becomes nothing once its name is stripped: the package root is the
                //snapshot's root and is not an entry of it.
                continue;
            }

            sources.Add(new EArkPackageEntrySource { Name = name, Content = entry.Content.AsReadOnlyMemory() });
        }

        return Build(sources, limits, pool, rootFolderName, hasSingleRootFolder);
    }


    /// <summary>
    /// States whether every entry of an archive sits under one root folder, and names it.
    /// </summary>
    /// <param name="entries">The archive's entries.</param>
    /// <param name="rootFolderName">The folder's name, when there is exactly one.</param>
    /// <returns><see langword="true"/> when every entry sits under one root folder.</returns>
    /// <remarks>
    /// The first path segment of the first entry is the candidate, and every entry has to sit under it. An
    /// archive whose first entry is a file at the archive root has no such segment and therefore no single root
    /// folder, which is the shape <c>CSIPSTR1</c> forbids and this method reports rather than repairs.
    /// </remarks>
    private static bool TryStateRootFolder(IReadOnlyList<AsicZipEntry> entries, out string? rootFolderName)
    {
        rootFolderName = null;
        if(entries.Count == 0)
        {
            return false;
        }

        int separatorIndex = entries[0].Name.IndexOf(EArkWellKnown.PathSeparator, StringComparison.Ordinal);
        if(separatorIndex <= 0)
        {
            return false;
        }

        string candidate = entries[0].Name[..separatorIndex];
        for(int i = 0; i < entries.Count; ++i)
        {
            string name = entries[i].Name;
            if(name.Length <= candidate.Length
                || !name.StartsWith(candidate, StringComparison.Ordinal)
                || name[candidate.Length] != EArkWellKnown.PathSeparator)
            {
                return false;
            }
        }

        rootFolderName = candidate;

        return true;
    }


    /// <summary>
    /// Applies every rule and bound to a set of stated entries, materialises the folder entries their names
    /// imply, and builds the snapshot.
    /// </summary>
    /// <param name="entries">The entries, under names relative to the package root.</param>
    /// <param name="limits">The bounds to read within.</param>
    /// <param name="pool">The memory pool every entry's octets are rented from.</param>
    /// <param name="rootFolderName">The name of the folder the package sat under, when there is one.</param>
    /// <param name="hasSingleRootFolder">Whether the package's entries were found under exactly one root folder.</param>
    /// <returns>The snapshot, or the reason the entries were refused.</returns>
    /// <remarks>
    /// <para>
    /// One implementation serves both sources, so a package admitted along one path is admitted along the other
    /// and the two produce the same snapshot. The walk is a loop over a flat list with a bounded iteration
    /// count; there is no recursion anywhere, so no layout a producer states can exhaust the stack.
    /// </para>
    /// <para>
    /// This is where every bound of <see cref="EArkPackageLimits"/> decides, and it decides over the values the
    /// snapshot holds — names relative to the package root, and the entries the package has. The archive layer
    /// runs earlier and over the archive's own strings, which is why
    /// <see cref="EArkPackageLimits.ToArchiveLimits"/> gives it the headroom a root folder occupies instead of
    /// the bare bounds. The root folder's own name is bounded here too, on both paths, because it is what the
    /// headroom is sized against.
    /// </para>
    /// </remarks>
    private static EArkPackageSnapshotResult Build(
        IReadOnlyList<EArkPackageEntrySource> entries,
        EArkPackageLimits limits,
        MemoryPool<byte> pool,
        string? rootFolderName,
        bool hasSingleRootFolder)
    {
        if(rootFolderName is not null)
        {
            string rootEntryName = rootFolderName + EArkWellKnown.PathSeparator;
            AsicZipEntryNameStatus rootStatus = AsicZipEntryNaming.Validate(rootEntryName, limits.MaximumEntryNameByteLength);
            if(rootStatus != AsicZipEntryNameStatus.Accepted)
            {
                return Refused(EArkPackageSnapshotStatus.EntryNameRefused, rootEntryName, rootStatus);
            }
        }

        if(entries.Count > limits.MaximumEntryCount)
        {
            return Refused(EArkPackageSnapshotStatus.EntryCountExceeded);
        }

        //Canonical name (no trailing separator) to whether that name is a folder. It is what makes a duplicate,
        //a file-against-folder collision and an already-stated ancestor one question rather than three.
        var kinds = new Dictionary<string, bool>(entries.Count, StringComparer.Ordinal);
        var stated = new List<EArkPackageEntrySource>(entries.Count);
        long totalByteLength = 0;

        for(int i = 0; i < entries.Count; ++i)
        {
            EArkPackageEntrySource source = entries[i];
            ArgumentNullException.ThrowIfNull(source);

            AsicZipEntryNameStatus nameStatus = AsicZipEntryNaming.Validate(source.Name, limits.MaximumEntryNameByteLength);
            if(nameStatus != AsicZipEntryNameStatus.Accepted)
            {
                return Refused(EArkPackageSnapshotStatus.EntryNameRefused, source.Name, nameStatus);
            }

            if(EArkPackageEntry.DepthOf(source.Name) > limits.MaximumFolderDepth)
            {
                return Refused(EArkPackageSnapshotStatus.FolderDepthExceeded, source.Name);
            }

            bool isFolder = AsicZipEntryNaming.IsFolderEntryName(source.Name);
            string canonical = isFolder ? source.Name[..^1] : source.Name;
            if(kinds.TryGetValue(canonical, out bool statedAsFolder))
            {
                return Refused(
                    statedAsFolder == isFolder
                        ? EArkPackageSnapshotStatus.DuplicateEntryName
                        : EArkPackageSnapshotStatus.EntryNameCollidesWithFolder,
                    source.Name);
            }

            kinds.Add(canonical, isFolder);
            stated.Add(source);

            totalByteLength += isFolder ? 0 : source.Content.Length;
            if(totalByteLength > limits.MaximumTotalByteLength)
            {
                return Refused(EArkPackageSnapshotStatus.TotalByteLengthExceeded, source.Name);
            }
        }

        var implied = new List<string>();
        for(int i = 0; i < stated.Count; ++i)
        {
            string name = stated[i].Name;
            for(int at = 0; at < name.Length - 1; ++at)
            {
                if(name[at] != EArkWellKnown.PathSeparator)
                {
                    continue;
                }

                string ancestor = name[..at];
                if(kinds.TryGetValue(ancestor, out bool statedAsFolder))
                {
                    if(!statedAsFolder)
                    {
                        //A name states a file where an ancestor of another name states a folder, so the two
                        //together do not resolve to one tree.
                        return Refused(EArkPackageSnapshotStatus.EntryNameCollidesWithFolder, name);
                    }

                    continue;
                }

                kinds.Add(ancestor, true);
                implied.Add(ancestor + EArkWellKnown.PathSeparator);
            }
        }

        if(stated.Count + implied.Count > limits.MaximumEntryCount)
        {
            return Refused(EArkPackageSnapshotStatus.EntryCountExceeded);
        }

        var built = new List<EArkPackageEntry>(stated.Count + implied.Count);
        try
        {
            for(int i = 0; i < stated.Count; ++i)
            {
                EArkPackageEntrySource source = stated[i];
                bool isFolder = AsicZipEntryNaming.IsFolderEntryName(source.Name);
                built.Add(new EArkPackageEntry
                {
                    Name = source.Name,
                    Content = PooledMemory.FromBytes(isFolder ? ReadOnlySpan<byte>.Empty : source.Content.Span, pool, EArkTags.PackageEntry),
                    IsFolder = isFolder
                });
            }

            for(int i = 0; i < implied.Count; ++i)
            {
                built.Add(new EArkPackageEntry
                {
                    Name = implied[i],
                    Content = PooledMemory.FromBytes(ReadOnlySpan<byte>.Empty, pool, EArkTags.PackageEntry),
                    IsFolder = true
                });
            }
        }
        catch
        {
            for(int i = 0; i < built.Count; ++i)
            {
                built[i].Dispose();
            }

            throw;
        }

        built.Sort(static (left, right) => string.CompareOrdinal(left.Name, right.Name));

        return new EArkPackageSnapshotResult
        {
            Status = EArkPackageSnapshotStatus.Read,
            Snapshot = new EArkPackageSnapshot
            {
                Entries = built,
                RootFolderName = rootFolderName,
                HasSingleRootFolder = hasSingleRootFolder,
                TotalByteLength = totalByteLength
            }
        };
    }


    /// <summary>
    /// States a refusal.
    /// </summary>
    /// <param name="status">What the reader concluded.</param>
    /// <param name="entryName">The entry the status refers to, or <see langword="null"/>.</param>
    /// <param name="nameStatus">Which entry-name rule refused the name, when that is the status.</param>
    /// <returns>The result, which carries no snapshot.</returns>
    /// <remarks>
    /// Every refusal path builds nothing that has to be disposed, so a method that refuses cannot leak a
    /// carrier — the discipline <see cref="AsicZipReading"/> states for the same reason.
    /// </remarks>
    private static EArkPackageSnapshotResult Refused(
        EArkPackageSnapshotStatus status,
        string? entryName = null,
        AsicZipEntryNameStatus nameStatus = AsicZipEntryNameStatus.NotEvaluated) =>
        new()
        {
            Status = status,
            RejectedEntryName = entryName,
            RejectedEntryNameStatus = nameStatus
        };
}
