using System;
using System.Text;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Names why a container entry name was refused.
/// </summary>
/// <remarks>
/// <para>
/// Entry names arrive from whoever produced the container, and a ZIP entry name is an octet string that no part
/// of the ZIP format constrains: a name may name a path outside the container, may use a separator the format
/// does not define, and may be long enough to be a denial of service on its own. Annex A.6 item 1 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> requires valid naming and item 3 states that "References to data objects
/// outside the container shall not be allowed"; this enumeration is the closed set of ways a name fails that.
/// </para>
/// <para>
/// <see cref="Accepted"/> is deliberately not zero: a status that has not been computed must not read as an
/// accepted name.
/// </para>
/// </remarks>
public enum AsicZipEntryNameStatus
{
    /// <summary>The name has not been examined. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The name is one this library reads and writes.</summary>
    Accepted = 1,

    /// <summary>The name is empty, or names nothing but a folder separator.</summary>
    Empty = 2,

    /// <summary>The name is longer than the caller's octet bound.</summary>
    TooLong = 3,

    /// <summary>
    /// The name carries a backslash. ZIP names use <c>/</c> as their only separator, so a backslash is either a
    /// literal character a file system would read as a separator, or a producer writing native paths — both of
    /// which turn extraction into a path-traversal primitive.
    /// </summary>
    BackslashSeparator = 4,

    /// <summary>The name begins with <c>/</c>, which names a path from a file-system root rather than from the container root.</summary>
    Absolute = 5,

    /// <summary>The name carries a colon, which names a drive or an alternate data stream on some file systems.</summary>
    VolumeQualified = 6,

    /// <summary>A path segment is <c>.</c> or <c>..</c>, which resolves to somewhere other than where the name reads.</summary>
    Traversal = 7,

    /// <summary>Two separators are adjacent, so a segment is empty and the name does not resolve to one location.</summary>
    EmptySegment = 8,

    /// <summary>The name carries a control character, which no container needs and which corrupts any place the name is reported.</summary>
    ControlCharacter = 9,

    /// <summary>
    /// The octets of the name are not valid UTF-8, which clause 4.2 item 2 b requires: "File names and comments
    /// shall be encoded with ISO/IEC 10646 UNICODE UTF-8."
    /// </summary>
    NotUtf8 = 10
}


/// <summary>
/// The entry-name rules both the container author and the container reader apply, in one place so that a name
/// this library writes is one it also reads back.
/// </summary>
/// <remarks>
/// <para>
/// The rules are a superset of what
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> Annex A.6 states, and the surplus is deliberate. Annex A.6 item 3 forbids
/// references to data objects outside the container; a name that carries <c>..</c>, an absolute prefix, a
/// backslash or a volume qualifier is exactly such a reference expressed through the name rather than through a
/// manifest URI, and refusing it at the container boundary means no consumer of an entry has to re-derive the
/// rule.
/// </para>
/// <para>
/// A name ending in <c>/</c> is a folder entry, which ZIP writes to record an empty folder and which clause
/// 4.4.2 item 2's "in any folder structure outside the root META-INF folder" makes legitimate to encounter. The
/// part before the trailing separator is validated as any other name.
/// </para>
/// </remarks>
public static class AsicZipEntryNaming
{
    /// <summary>The separator ZIP entry names use, and the only one this library accepts.</summary>
    public static char Separator { get; } = '/';

    /// <summary>
    /// U+FFFD, the character a lenient UTF-8 decode substitutes for octets that are not valid UTF-8. Named here
    /// rather than written as a literal so that the rule does not depend on how this source file is encoded.
    /// </summary>
    private static char ReplacementCharacter { get; } = (char)0xFFFD;


    /// <summary>
    /// Examines a container entry name against every rule this library applies to one.
    /// </summary>
    /// <param name="entryName">The name as it appears in the container, or <see langword="null"/>.</param>
    /// <param name="maximumByteLength">The largest number of UTF-8 octets the name may occupy.</param>
    /// <returns>Why the name was refused, or <see cref="AsicZipEntryNameStatus.Accepted"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="maximumByteLength"/> is not positive.</exception>
    public static AsicZipEntryNameStatus Validate(string? entryName, int maximumByteLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumByteLength);

        if(string.IsNullOrEmpty(entryName))
        {
            return AsicZipEntryNameStatus.Empty;
        }

        //The replacement character is what a lenient UTF-8 decode leaves behind where the octets were not
        //UTF-8. The reader decodes strictly and never produces one, so a name carrying it reached this method
        //from a caller that decoded leniently; refusing it keeps clause 4.2 item 2 b enforced on both paths.
        if(entryName.Contains(ReplacementCharacter, StringComparison.Ordinal))
        {
            return AsicZipEntryNameStatus.NotUtf8;
        }

        if(Encoding.UTF8.GetByteCount(entryName) > maximumByteLength)
        {
            return AsicZipEntryNameStatus.TooLong;
        }

        if(entryName.Contains('\\', StringComparison.Ordinal))
        {
            return AsicZipEntryNameStatus.BackslashSeparator;
        }

        if(entryName.Contains(':', StringComparison.Ordinal))
        {
            return AsicZipEntryNameStatus.VolumeQualified;
        }

        if(entryName[0] == Separator)
        {
            return AsicZipEntryNameStatus.Absolute;
        }

        for(int i = 0; i < entryName.Length; ++i)
        {
            if(char.IsControl(entryName[i]))
            {
                return AsicZipEntryNameStatus.ControlCharacter;
            }
        }

        //A trailing separator marks a folder entry; everything before it is validated as any other name, which
        //also makes a name that is nothing but a separator come out as Empty rather than as an empty segment.
        ReadOnlySpan<char> significant = entryName.AsSpan();
        if(significant[^1] == Separator)
        {
            significant = significant[..^1];
        }

        if(significant.IsEmpty)
        {
            return AsicZipEntryNameStatus.Empty;
        }

        foreach(Range segment in significant.Split(Separator))
        {
            ReadOnlySpan<char> part = significant[segment];
            if(part.IsEmpty)
            {
                return AsicZipEntryNameStatus.EmptySegment;
            }

            if(part.SequenceEqual(".") || part.SequenceEqual(".."))
            {
                return AsicZipEntryNameStatus.Traversal;
            }
        }

        return AsicZipEntryNameStatus.Accepted;
    }


    /// <summary>
    /// Determines whether a container entry name is a folder entry — a name ending in the ZIP separator, which
    /// carries no content.
    /// </summary>
    /// <param name="entryName">The name as it appears in the container, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the name names a folder rather than a file object.</returns>
    public static bool IsFolderEntryName(string? entryName) =>
        entryName is { Length: > 0 } && entryName[^1] == Separator;
}
