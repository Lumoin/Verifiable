using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The bounds an E-ARK information package is read and validated within.
/// </summary>
/// <remarks>
/// <para>
/// A package arrives as a folder tree or as an archive that someone else built, and nothing in it is
/// authenticated until its own evidence has been verified — which cannot happen until the tree has been read.
/// Every bound here therefore exists to make a package that is hostile rather than merely large a refusal
/// instead of a resource exhaustion. No source specification states a bound of its own: E-ARK CSIP fixes a
/// layout, not a size, so these values are this library's, and a caller archiving something unusual raises the
/// one bound it needs rather than all of them.
/// </para>
/// <para>
/// One record serves both paths a package arrives by — a plain folder snapshot and a generic archive — so the
/// same package is admitted whichever way it was handed over. Every bound stated here governs the package as the
/// snapshot holds it: entry names relative to the package root, and the entries the package has. An archive
/// writes those names under a <c>CSIPSTR1</c> root folder and carries an entry for the folder itself, both of
/// which are removed as the snapshot is read, so <see cref="ToArchiveLimits"/> gives the archive layer the
/// headroom a root folder occupies rather than letting it judge the un-normalized strings — see its remarks. The
/// byte bound is applied where the octets are read; a validation running over a name snapshot alone applies the
/// entry-count, name-length and depth bounds.
/// </para>
/// <para>
/// <strong>The archive-only bounds.</strong> An archive states sizes a folder tree has no counterpart for — how
/// many octets the archive itself occupies, how far one entry expands, how long the archive comment is — and
/// those live in <see cref="Archive"/> rather than being restated here. The four bounds this record states
/// itself are the authority: <see cref="ToArchiveLimits"/> writes them over the archive record's own where the
/// two overlap, so a package admitted along one path is admitted along the other. The one asymmetry that stands
/// is stated rather than hidden — <see cref="AsicZipReadLimits.MaximumContainerByteLength"/> bounds the archive
/// as it arrived and has no folder counterpart, as the remarks on <see cref="Archive"/> say.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record EArkPackageLimits
{
    /// <summary>Gets the bounds this library reads and validates a package within when a caller states none of its own.</summary>
    public static EArkPackageLimits Conformant { get; } = new();


    /// <summary>Gets the largest number of entries a package may hold, counting folders. 65 536 by default.</summary>
    public int MaximumEntryCount { get; init; } = 65_536;

    /// <summary>Gets the largest number of octets every entry together may hold once read. 1 GiB by default.</summary>
    public long MaximumTotalByteLength { get; init; } = 1024L * 1024 * 1024;

    /// <summary>Gets the largest number of UTF-8 octets one entry name may occupy. 512 by default, the bound an archived package is read under.</summary>
    public int MaximumEntryNameByteLength { get; init; } = 512;

    /// <summary>
    /// Gets the deepest an entry may sit below the package root, counted in path segments. 32 by default,
    /// against a layout whose deepest specified position — a representation's data folder — is three.
    /// </summary>
    public int MaximumFolderDepth { get; init; } = 32;

    /// <summary>
    /// Gets the bounds that only an archive has: the archive's own octet length, one entry's decompressed
    /// length, the expansion ratio that makes an entry a decompression bomb, and the archive comment's length.
    /// </summary>
    /// <remarks>
    /// The three bounds this record shares with an archive — how many entries, how long a name, how many octets
    /// in total — are taken from this record rather than from here; see <see cref="ToArchiveLimits"/>. Note that
    /// <see cref="AsicZipReadLimits.MaximumContainerByteLength"/> bounds the archive as it arrived, before
    /// decompression, and its default is below <see cref="MaximumTotalByteLength"/>: an archived package larger
    /// than that is refused for being a large archive rather than for holding many octets, which fails closed.
    /// </remarks>
    public AsicZipReadLimits Archive { get; init; } = AsicZipReadLimits.Conformant;


    /// <summary>
    /// States the bounds the archive layer reads within, with the bounds this record shares with it taken from
    /// this record and the two of them that need it given the headroom a root folder occupies.
    /// </summary>
    /// <returns>The archive bounds, which are <see cref="Archive"/> with the three shared bounds overwritten.</returns>
    /// <remarks>
    /// <para>
    /// <strong>Why two of the three are not copied across unchanged.</strong> The archive layer judges the
    /// archive as it arrived: names as the central directory writes them, and the count the end-of-central-
    /// directory record states. An Information Package archive satisfying <c>CSIPSTR1</c> writes every name
    /// under one root folder and carries an entry for the folder itself, and both are removed while the snapshot
    /// is read. Handing the archive layer the bounds unchanged would therefore apply them to different strings
    /// and a different count than the folder path applies them to, and the archive path would be stricter by the
    /// prefix and by one entry — so the same package could be admitted from a folder tree and refused from its
    /// own archive.
    /// </para>
    /// <para>
    /// <strong>The headroom is exactly what a root folder can occupy, not a relaxation.</strong> A root folder's
    /// name is an entry name and so is held to <see cref="MaximumEntryNameByteLength"/> like every other, which
    /// makes a prefixed name at most twice that bound; and a root folder contributes exactly one entry. The
    /// post-strip name and the post-strip count are then held to the stated bounds where the snapshot is built,
    /// which is the only place either bound really decides anything. The arithmetic saturates rather than
    /// wrapping, so a record stating the largest representable bound cannot hand the archive layer a negative
    /// one.
    /// </para>
    /// </remarks>
    public AsicZipReadLimits ToArchiveLimits() => Archive with
    {
        MaximumEntryCount = AddWithoutOverflow(MaximumEntryCount, 1),
        MaximumEntryNameByteLength = AddWithoutOverflow(MaximumEntryNameByteLength, MaximumEntryNameByteLength),
        MaximumTotalUncompressedByteLength = MaximumTotalByteLength
    };


    /// <summary>Adds two bounds, saturating at <see cref="int.MaxValue"/> rather than wrapping.</summary>
    /// <param name="bound">The stated bound.</param>
    /// <param name="headroom">The headroom to add to it.</param>
    /// <returns>The sum, or <see cref="int.MaxValue"/> when the sum is not representable.</returns>
    private static int AddWithoutOverflow(int bound, int headroom)
    {
        long sum = (long)bound + headroom;

        return sum > int.MaxValue ? int.MaxValue : (int)sum;
    }


    /// <summary>A short debugger string showing the three bounds a name snapshot is checked against.</summary>
    private string DebuggerDisplay =>
        $"EArkPackageLimits({MaximumEntryCount} entries, name {MaximumEntryNameByteLength} octets, depth {MaximumFolderDepth})";
}
