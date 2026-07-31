using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One entry a caller hands an Information Package over as: the name it sits under and the octets it holds.
/// </summary>
/// <remarks>
/// <para>
/// The name is root-relative and <c>/</c>-separated whatever the caller read it from, so a package handed over
/// from a folder tree and the same package handed over from an archive state the same names. A name ending in
/// the separator names a folder, which carries no octets; the folder entries a caller does not state are
/// materialised by <see cref="EArkPackageSnapshotReading"/> from the names of the entries below them, so a
/// caller never has to know whether the source it read from recorded them.
/// </para>
/// <para>
/// <strong>Nothing is retained.</strong> The octets are copied into memory rented from the caller's pool while
/// the snapshot is built, so the caller may release whatever it read them into as soon as the call returns —
/// the discipline <see cref="AsicZipReading.Read"/> states for a container's octets.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record EArkPackageEntrySource
{
    /// <summary>Gets the entry name, root-relative and <c>/</c>-separated, a folder entry ending in the separator.</summary>
    public required string Name { get; init; }

    /// <summary>Gets the entry's octets. Empty for a folder entry, which carries none.</summary>
    public ReadOnlyMemory<byte> Content { get; init; }


    /// <summary>A short debugger string showing the entry's name and size.</summary>
    private string DebuggerDisplay => $"EArkPackageEntrySource({Name}, {Content.Length} bytes)";
}


/// <summary>
/// One entry of a package snapshot: its normalised name, its octets in a pooled carrier, and whether it names a
/// folder.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> The entry owns <see cref="Content"/>, and the <see cref="EArkPackageSnapshot"/>
/// that surfaced it disposes it. Everything that classifies a package holds non-owning references to entries.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class EArkPackageEntry: IDisposable
{
    /// <summary>
    /// Gets the entry name, root-relative to the package root and <c>/</c>-separated, a folder entry ending in
    /// the separator.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>Gets the entry's octets, tagged <see cref="EArkTags.PackageEntry"/>. Owned by this instance; a folder entry carries none.</summary>
    public required PooledMemory Content { get; init; }

    /// <summary>Gets whether the entry names a folder rather than a file.</summary>
    public required bool IsFolder { get; init; }


    /// <summary>
    /// Gets how deep below the package root the entry sits, counted in path segments. A file at the root is at
    /// depth zero; the trailing separator of a folder entry names no segment of its own.
    /// </summary>
    public int Depth => DepthOf(Name);


    /// <summary>
    /// States how deep below the package root a name sits, counted in path segments.
    /// </summary>
    /// <param name="entryName">The entry name, root-relative and <c>/</c>-separated.</param>
    /// <returns>The depth, zero for a name at the package root.</returns>
    /// <remarks>
    /// One implementation serves the bound the snapshot applies and the value a caller reads, so a package
    /// admitted by the bound cannot report a depth the bound would have refused.
    /// </remarks>
    public static int DepthOf(string entryName)
    {
        ArgumentNullException.ThrowIfNull(entryName);

        int depth = 0;
        int lastIndex = entryName.Length - 1;
        for(int i = 0; i < entryName.Length; ++i)
        {
            if(entryName[i] == EArkWellKnown.PathSeparator && i != lastIndex)
            {
                ++depth;
            }
        }

        return depth;
    }


    /// <inheritdoc/>
    public void Dispose() => Content.Dispose();


    /// <summary>A short debugger string showing the entry's name and size.</summary>
    private string DebuggerDisplay => $"EArkPackageEntry({Name}, {(IsFolder ? "folder" : $"{Content.Length} bytes")})";
}


/// <summary>
/// An Information Package as a value: every entry it holds, under names relative to the package root, with the
/// octets in pooled carriers.
/// </summary>
/// <remarks>
/// <para>
/// <strong>A package reaches this library as a snapshot and never as a live file system.</strong> The caller
/// states what it read; nothing here or above opens a directory, follows a link or re-reads a file. That is what
/// lets one classifier and one rule list run over a folder tree, over an archive and over a package rebuilt from
/// wire octets, and what makes a validation replayable from what it was handed.
/// </para>
/// <para>
/// <strong>Two normalisations make the two sources agree.</strong> Every folder implied by an entry's name is
/// present exactly once as a folder entry, whether or not the source recorded it — an archive need not carry
/// folder entries and a directory walk always yields them — and the entries are ordered ordinally by name. Two
/// snapshots of the same content are therefore the same sequence whichever way the package arrived.
/// </para>
/// <para>
/// <strong>Ownership.</strong> This instance owns every entry and therefore every entry's octets. Disposing it
/// disposes them all.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class EArkPackageSnapshot: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>Gets every entry, ordered ordinally by name, folder entries included. Owned by this instance.</summary>
    public required IReadOnlyList<EArkPackageEntry> Entries { get; init; }

    /// <summary>
    /// Gets the name of the single folder an archived package unpacked to, or <see langword="null"/> when the
    /// snapshot was not built from an archive or the archive did not unpack to exactly one folder.
    /// </summary>
    /// <remarks>
    /// <c>CSIPSTR1</c> of
    /// <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 clause
    /// 4.1</see> requires an archived package to unpack to a single root folder and <c>CSIPSTR2</c> recommends
    /// naming it with the package's own <c>mets/@OBJID</c>. Both are stated here as facts about what arrived;
    /// whether a package satisfies them is a judgment a validation profile makes.
    /// </remarks>
    public string? RootFolderName { get; init; }

    /// <summary>
    /// Gets whether the package's entries were found under exactly one root folder — the fact <c>CSIPSTR1</c>
    /// is judged from. A snapshot a caller stated directly reports <see langword="true"/>, because a caller
    /// handing over entries has already named the root it read them relative to.
    /// </summary>
    public required bool HasSingleRootFolder { get; init; }

    /// <summary>Gets how many octets every entry together holds, which the caller's byte bound was applied to.</summary>
    public required long TotalByteLength { get; init; }


    /// <summary>Gets how many entries the snapshot holds, folder entries included.</summary>
    public int EntryCount => Entries.Count;


    /// <summary>
    /// Finds one entry by its exact name.
    /// </summary>
    /// <param name="entryName">The name to look for.</param>
    /// <returns>The entry, or <see langword="null"/> when the snapshot holds none under that name.</returns>
    /// <remarks>
    /// The comparison is ordinal and case-sensitive: packages are exchanged between file systems that do not
    /// agree on case, and a reader that folded case would resolve a manifest reference to a file the producer
    /// did not name.
    /// </remarks>
    public EArkPackageEntry? FindEntry(string entryName)
    {
        for(int i = 0; i < Entries.Count; ++i)
        {
            if(string.Equals(Entries[i].Name, entryName, StringComparison.Ordinal))
            {
                return Entries[i];
            }
        }

        return null;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            for(int i = 0; i < Entries.Count; ++i)
            {
                Entries[i].Dispose();
            }

            disposed = true;
        }
    }


    /// <summary>A short debugger string showing the entry count and the root folder.</summary>
    private string DebuggerDisplay =>
        $"EArkPackageSnapshot({Entries.Count} entries, {TotalByteLength} bytes, root {RootFolderName ?? "stated by the caller"})";
}


/// <summary>
/// What reading an Information Package into a snapshot concluded.
/// </summary>
/// <remarks>
/// <para>
/// A package arrives from whoever produced it, so every way it can be wrong is a value here rather than an
/// exception — the split <see cref="AsicZipReadStatus"/> already makes between generator faults, which throw,
/// and reader conclusions, which are statuses.
/// </para>
/// <para>
/// <see cref="NotRead"/> occupies zero so a default-initialised status never reads as a package that was read.
/// </para>
/// </remarks>
public enum EArkPackageSnapshotStatus
{
    /// <summary>No read has been attempted. The value of an unset field, by design.</summary>
    NotRead = 0,

    /// <summary>The package was read; every entry is available.</summary>
    Read = 1,

    /// <summary>
    /// The archive the package arrived in was refused;
    /// <see cref="EArkPackageSnapshotResult.ArchiveStatus"/> states why, verbatim as the archive layer stated
    /// it.
    /// </summary>
    ArchiveRefused = 2,

    /// <summary>
    /// An entry name was refused; <see cref="EArkPackageSnapshotResult.RejectedEntryNameStatus"/> names which
    /// rule refused it.
    /// </summary>
    EntryNameRefused = 3,

    /// <summary>The package holds more entries than the caller's bounds admit, counting the folder entries the reader materialised.</summary>
    EntryCountExceeded = 4,

    /// <summary>The package's entries hold more octets together than the caller's bounds admit.</summary>
    TotalByteLengthExceeded = 5,

    /// <summary>An entry sits deeper below the package root than the caller's bounds admit.</summary>
    FolderDepthExceeded = 6,

    /// <summary>
    /// Two entries carry the same name, so the package names one file twice and a manifest reference to it
    /// resolves to neither.
    /// </summary>
    DuplicateEntryName = 7,

    /// <summary>
    /// An entry name states a file where the same name is already a folder, or a folder where it is already a
    /// file — a package whose layout does not resolve to one tree.
    /// </summary>
    EntryNameCollidesWithFolder = 8
}


/// <summary>
/// What <see cref="EArkPackageSnapshotReading"/> concluded, and the snapshot when it read one.
/// </summary>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class EArkPackageSnapshotResult: IDisposable
{
    /// <summary>Gets what the reader concluded.</summary>
    public required EArkPackageSnapshotStatus Status { get; init; }

    /// <summary>Gets the snapshot, or <see langword="null"/> when none was read. Owned by this instance.</summary>
    public EArkPackageSnapshot? Snapshot { get; init; }

    /// <summary>
    /// Gets what the archive layer concluded, when the package arrived in an archive. Carried verbatim so that
    /// nothing about why an archive was refused is lost on the way through — the discipline
    /// <see cref="AsicContainerReadResult"/> established.
    /// </summary>
    public AsicZipReadStatus ArchiveStatus { get; init; }

    /// <summary>Gets the entry a status refers to, or <see langword="null"/> when it refers to the package as a whole.</summary>
    public string? RejectedEntryName { get; init; }

    /// <summary>Gets which entry-name rule refused a name, when <see cref="Status"/> is <see cref="EArkPackageSnapshotStatus.EntryNameRefused"/>.</summary>
    public AsicZipEntryNameStatus RejectedEntryNameStatus { get; init; }


    /// <summary>Gets whether a snapshot was read.</summary>
    public bool IsRead => Status == EArkPackageSnapshotStatus.Read && Snapshot is not null;


    /// <inheritdoc/>
    public void Dispose() => Snapshot?.Dispose();


    /// <summary>A short debugger string showing the status and the entry it refers to.</summary>
    private string DebuggerDisplay =>
        $"EArkPackageSnapshotResult({Status}{(RejectedEntryName is null ? string.Empty : $", {RejectedEntryName}")})";
}
