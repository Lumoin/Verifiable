using System;
using System.Buffers;
using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Names why a container reference could not be resolved to a container entry name.
/// </summary>
/// <remarks>
/// <para>
/// A reference arrives inside a manifest, which arrives inside a container someone else produced, so every
/// member of this enumeration is a refusal of attacker-supplied text rather than a caller fault. Annex A.6
/// item 3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> — "References to data objects outside the container shall not be allowed" —
/// is what most of them enforce.
/// </para>
/// <para>
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised status never reads as a resolved
/// reference.
/// </para>
/// </remarks>
public enum AsicContainerUriStatus
{
    /// <summary>The reference has not been examined. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The reference names an entry of the container.</summary>
    Resolved = 1,

    /// <summary>The reference is absent or empty, so it names nothing.</summary>
    Empty = 2,

    /// <summary>The reference is longer than the caller's bound.</summary>
    TooLong = 3,

    /// <summary>
    /// The reference carries a scheme or an authority — <c>http://…</c>, <c>file:…</c>, <c>//host/…</c> — so it
    /// names something outside the container, which Annex A.6 item 3 forbids.
    /// </summary>
    NotContainerRelative = 4,

    /// <summary>The reference carries a query or a fragment, neither of which addresses anything in a container.</summary>
    QueryOrFragmentPresent = 5,

    /// <summary>A percent-encoded octet is truncated or is not two hexadecimal digits.</summary>
    MalformedPercentEncoding = 6,

    /// <summary>The decoded octets are not valid UTF-8, which clause 4.2 item 2 b requires container names to be.</summary>
    NotUtf8 = 7,

    /// <summary>
    /// The decoded reference is not a name this container format admits; the accompanying
    /// <see cref="AsicZipEntryNameStatus"/> states which rule refused it.
    /// </summary>
    NotAnEntryName = 8
}


/// <summary>
/// The outcome of resolving one container reference.
/// </summary>
/// <param name="Status">Whether the reference resolved, and if not why.</param>
/// <param name="EntryName">The container entry name the reference names, when it resolved.</param>
/// <param name="EntryNameStatus">
/// Which entry-name rule refused the decoded reference, when <see cref="Status"/> is
/// <see cref="AsicContainerUriStatus.NotAnEntryName"/>.
/// </param>
[DebuggerDisplay("AsicContainerUriResolution: {Status}, {EntryName}")]
public readonly record struct AsicContainerUriResolution(
    AsicContainerUriStatus Status,
    string? EntryName,
    AsicZipEntryNameStatus EntryNameStatus)
{
    /// <summary>Gets whether the reference names an entry of the container.</summary>
    public bool IsResolved => Status == AsicContainerUriStatus.Resolved && EntryName is not null;
}


/// <summary>
/// Resolves the relative references a manifest carries — <c>SigReference</c>'s <c>URI</c> and every
/// <c>DataObjectReference</c>'s <c>URI</c> — against the container root, and writes references for names.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The base is the container root, not the manifest's folder.</strong> Annex A.6 item 2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> states it outright: "relative URIs present in metadata stored in the
/// "META-INF" folder subtree containing a relative path shall be resolved considering the root directory as
/// the base URI, not taking into account the "META-INF" folder where signature metadata are stored". A
/// <c>DataObjectReference</c> reading <c>URI="file1.xml"</c> inside <c>META-INF/ASiCManifest1.xml</c>
/// therefore names the container entry <c>file1.xml</c> and never <c>META-INF/file1.xml</c>.
/// </para>
/// <para>
/// <strong>Which is why no general relative-URI resolution is performed.</strong> Resolving a reference
/// against the referring document's own location — what
/// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-5">IETF RFC 3986 clause 5</see> specifies and
/// what every general-purpose URI type implements — produces exactly the wrong answer here, and would produce
/// it silently. This class performs the one operation Annex A.6 defines: decode the reference and read it as
/// a name from the root. There is no base-URI parameter because there is no base but the root.
/// </para>
/// <para>
/// <strong>What is refused.</strong> A reference carrying a scheme, an authority, a query or a fragment names
/// something a container has no notion of, and Annex A.6 item 3 forbids naming anything outside the container
/// at all. What survives decoding is then put through <see cref="AsicZipEntryNaming.Validate"/> — the same
/// rules the container reader and the container author apply — so a manifest cannot name a path the container
/// layer would refuse to carry.
/// </para>
/// <para>
/// <strong>Both bounds travel with the call.</strong> The character bound of a reference and the octet bound of
/// the name it decodes to are parameters, and the octet bound a run states is the one its reader states
/// (<see cref="AsicZipReadLimits.MaximumEntryNameByteLength"/>). Keeping the resolver on a fixed value while the
/// reader takes the caller's would break the invariant the paragraph above states in one direction: a container
/// whose entry the reader was told to carry would have a manifest reference naming that entry that cannot
/// resolve. The defaults are the conformant ones, so a run stating nothing behaves exactly as before.
/// </para>
/// </remarks>
public static class AsicContainerUri
{
    /// <summary>
    /// The largest number of characters a reference may occupy by default, 2048 — above the 1536 characters the
    /// conformant 512-octet entry name of <see cref="AsicZipReadLimits.Conformant"/> occupies once every octet
    /// of it has been percent-encoded to three characters, with room for the separators a nested name carries.
    /// </summary>
    /// <remarks>
    /// A caller archiving something unusual raises the reader's octet bound
    /// (<see cref="AsicZipReadLimits.MaximumEntryNameByteLength"/>) and states BOTH bounds on the resolution,
    /// through <see cref="Resolve(string?, int, int)"/>: this default derives from the conformant octet bound and
    /// is not wide enough for a name three times longer than it.
    /// </remarks>
    public static int DefaultMaximumLength { get; } = 2048;

    /// <summary>The character that introduces a percent-encoded octet, per IETF RFC 3986 clause 2.1.</summary>
    private static char PercentSign { get; } = '%';

    /// <summary>
    /// The unreserved characters of
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-2.3">IETF RFC 3986 clause 2.3</see> that are
    /// not letters or digits, which <see cref="ToReference"/> writes as themselves.
    /// </summary>
    private static string AdditionalUnreservedCharacters { get; } = "-._~";

    /// <summary>The upper-case hexadecimal digits a percent-encoded octet is written with, per IETF RFC 3986 clause 2.1.</summary>
    private static string HexadecimalDigits { get; } = "0123456789ABCDEF";

    /// <summary>
    /// The largest number of octets a decoded reference may occupy unless a caller states another, taken from
    /// <see cref="AsicZipReadLimits.Conformant"/> so that a run stating no bound of its own resolves exactly the
    /// names a conformant reader carries.
    /// </summary>
    private static int DefaultMaximumEntryNameByteLength { get; } = AsicZipReadLimits.Conformant.MaximumEntryNameByteLength;


    /// <summary>
    /// Resolves a manifest reference to the container entry name it names, under the two bounds the run states.
    /// </summary>
    /// <param name="reference">The <c>URI</c> attribute value, or <see langword="null"/>.</param>
    /// <param name="maximumLength">The largest number of characters the reference may occupy.</param>
    /// <param name="maximumEntryNameByteLength">The largest number of UTF-8 octets the decoded name may occupy — the run's own <see cref="AsicZipReadLimits.MaximumEntryNameByteLength"/>, so that the resolver admits exactly the names its reader admits.</param>
    /// <returns>The resolution.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="maximumLength"/> or <paramref name="maximumEntryNameByteLength"/> is not positive.</exception>
    /// <remarks>
    /// The octet bound is a parameter rather than a constant because the container reader's own bound is one
    /// (<see cref="AsicZipReadLimits.MaximumEntryNameByteLength"/>, which
    /// <see cref="AsicZipReading"/> documents as the one bound "a caller archiving something unusual" raises).
    /// A resolver pinned to the conformant value would refuse the very names such a run's reader carried in
    /// full, and would report that as the manifest naming something unresolvable rather than as the two bounds
    /// disagreeing. Nothing normative fixes either number: EN 319 162-1 states no entry-name length bound at all,
    /// so both are this library's hostile-input caps.
    /// </remarks>
    public static AsicContainerUriResolution Resolve(string? reference, int maximumLength, int maximumEntryNameByteLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumLength);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumEntryNameByteLength);

        if(string.IsNullOrEmpty(reference))
        {
            return new AsicContainerUriResolution(AsicContainerUriStatus.Empty, null, AsicZipEntryNameStatus.NotEvaluated);
        }

        if(reference.Length > maximumLength)
        {
            return new AsicContainerUriResolution(AsicContainerUriStatus.TooLong, null, AsicZipEntryNameStatus.NotEvaluated);
        }

        if(reference.Contains('?', StringComparison.Ordinal) || reference.Contains('#', StringComparison.Ordinal))
        {
            return new AsicContainerUriResolution(AsicContainerUriStatus.QueryOrFragmentPresent, null, AsicZipEntryNameStatus.NotEvaluated);
        }

        //A network-path reference names an authority (RFC 3986 clause 4.2), which is by definition outside the
        //container. It is tested before the colon rule because "//host/x" carries no colon at all.
        if(reference.StartsWith("//", StringComparison.Ordinal))
        {
            return new AsicContainerUriResolution(AsicContainerUriStatus.NotContainerRelative, null, AsicZipEntryNameStatus.NotEvaluated);
        }

        //A colon anywhere is refused rather than only a colon in the first segment. RFC 3986 clause 4.2 admits a
        //colon later in a relative path, but AsicZipEntryNaming refuses a colon in an entry name outright (it
        //names a volume or an alternate data stream on some file systems), so a reference carrying one could
        //never name an entry this library will read or write, and refusing it here says why.
        if(reference.Contains(':', StringComparison.Ordinal))
        {
            return new AsicContainerUriResolution(AsicContainerUriStatus.NotContainerRelative, null, AsicZipEntryNameStatus.NotEvaluated);
        }

        //A path-absolute reference is a relative reference in the RFC 3986 clause 4.2 sense, and Annex A.6
        //item 2's base is the root, so a leading separator states the base the resolution already uses. The
        //separator itself is dropped rather than kept, because a container entry name never carries one.
        ReadOnlySpan<char> path = reference.AsSpan();
        if(path[0] == AsicZipEntryNaming.Separator)
        {
            path = path[1..];
        }

        if(path.IsEmpty)
        {
            return new AsicContainerUriResolution(AsicContainerUriStatus.Empty, null, AsicZipEntryNameStatus.NotEvaluated);
        }

        (AsicContainerUriStatus decodeStatus, string? decoded) = Decode(path);
        if(decodeStatus != AsicContainerUriStatus.Resolved)
        {
            return new AsicContainerUriResolution(decodeStatus, null, AsicZipEntryNameStatus.NotEvaluated);
        }

        AsicZipEntryNameStatus nameStatus = AsicZipEntryNaming.Validate(decoded, maximumEntryNameByteLength);

        return nameStatus == AsicZipEntryNameStatus.Accepted
            ? new AsicContainerUriResolution(AsicContainerUriStatus.Resolved, decoded, nameStatus)
            : new AsicContainerUriResolution(AsicContainerUriStatus.NotAnEntryName, null, nameStatus);
    }


    /// <summary>
    /// Resolves a manifest reference under the caller's character bound and the conformant octet bound.
    /// </summary>
    /// <param name="reference">The <c>URI</c> attribute value, or <see langword="null"/>.</param>
    /// <param name="maximumLength">The largest number of characters the reference may occupy.</param>
    /// <returns>The resolution.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="maximumLength"/> is not positive.</exception>
    public static AsicContainerUriResolution Resolve(string? reference, int maximumLength) =>
        Resolve(reference, maximumLength, DefaultMaximumEntryNameByteLength);


    /// <summary>
    /// Resolves a manifest reference under <see cref="DefaultMaximumLength"/> and the conformant octet bound.
    /// </summary>
    /// <param name="reference">The <c>URI</c> attribute value, or <see langword="null"/>.</param>
    /// <returns>The resolution.</returns>
    public static AsicContainerUriResolution Resolve(string? reference) =>
        Resolve(reference, DefaultMaximumLength, DefaultMaximumEntryNameByteLength);


    /// <summary>
    /// Writes the relative reference that names a container entry — the inverse of
    /// <see cref="Resolve(string?, int, int)"/>, used when a manifest is created rather than read.
    /// </summary>
    /// <param name="entryName">The container entry name to name.</param>
    /// <param name="maximumEntryNameByteLength">The largest number of UTF-8 octets the name may occupy — the run's own <see cref="AsicZipReadLimits.MaximumEntryNameByteLength"/>, so that a manifest can name every entry the run carries.</param>
    /// <returns>The reference to write into a <c>URI</c> attribute.</returns>
    /// <exception cref="ArgumentException">When <paramref name="entryName"/> is not a name this library carries under that bound.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="maximumEntryNameByteLength"/> is not positive.</exception>
    /// <remarks>
    /// Every octet outside the unreserved set of
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-2.3">IETF RFC 3986 clause 2.3</see> is
    /// percent-encoded, including the ones a URI would admit unescaped in a path segment. Encoding more than
    /// the minimum is always correct — clause 2.1 makes the decoded octets what a reference identifies — and
    /// it keeps the written form independent of which delimiter set a consumer implements. The separator is
    /// the one exception: it is a path separator in the reference exactly as it is in the entry name.
    /// </remarks>
    public static string ToReference(string entryName, int maximumEntryNameByteLength)
    {
        ArgumentException.ThrowIfNullOrEmpty(entryName);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumEntryNameByteLength);

        AsicZipEntryNameStatus status = AsicZipEntryNaming.Validate(entryName, maximumEntryNameByteLength);
        if(status != AsicZipEntryNameStatus.Accepted)
        {
            throw new ArgumentException(
                string.Create(CultureInfo.InvariantCulture, $"'{entryName}' is not a container entry name: {status}."),
                nameof(entryName));
        }

        int maximumOctets = Encoding.UTF8.GetMaxByteCount(entryName.Length);
        byte[] rented = ArrayPool<byte>.Shared.Rent(maximumOctets);
        try
        {
            int octetCount = Encoding.UTF8.GetBytes(entryName, rented);
            var builder = new StringBuilder(octetCount);
            for(int i = 0; i < octetCount; ++i)
            {
                byte octet = rented[i];
                char character = (char)octet;
                bool isUnreserved = char.IsAsciiLetterOrDigit(character)
                    || AdditionalUnreservedCharacters.Contains(character, StringComparison.Ordinal)
                    || character == AsicZipEntryNaming.Separator;

                if(isUnreserved)
                {
                    _ = builder.Append(character);
                }
                else
                {
                    _ = builder.Append(PercentSign).Append(HexadecimalDigits[octet >> 4]).Append(HexadecimalDigits[octet & 0x0F]);
                }
            }

            return builder.ToString();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }


    /// <summary>
    /// Writes the relative reference that names a container entry, under the conformant octet bound.
    /// </summary>
    /// <param name="entryName">The container entry name to name.</param>
    /// <returns>The reference to write into a <c>URI</c> attribute.</returns>
    /// <exception cref="ArgumentException">When <paramref name="entryName"/> is not a name this library carries.</exception>
    public static string ToReference(string entryName) => ToReference(entryName, DefaultMaximumEntryNameByteLength);


    /// <summary>
    /// Percent-decodes a reference's octets and reads them as UTF-8, per IETF RFC 3986 clause 2.1.
    /// </summary>
    /// <param name="path">The reference, with any leading separator already removed.</param>
    /// <returns>The status and, when it is <see cref="AsicContainerUriStatus.Resolved"/>, the decoded name.</returns>
    private static (AsicContainerUriStatus Status, string? Decoded) Decode(ReadOnlySpan<char> path)
    {
        byte[] rented = ArrayPool<byte>.Shared.Rent(Encoding.UTF8.GetMaxByteCount(path.Length));
        try
        {
            int written = 0;
            for(int i = 0; i < path.Length; ++i)
            {
                char current = path[i];
                if(current != PercentSign)
                {
                    //A character above the ASCII range reached the reference without being percent-encoded.
                    //Its own UTF-8 octets are what it names, so they are written; a surrogate pair is handled
                    //by encoding the remaining span rather than the character, which cannot be encoded alone.
                    if(char.IsAscii(current))
                    {
                        rented[written++] = (byte)current;

                        continue;
                    }

                    int sequenceLength = char.IsHighSurrogate(current) && i + 1 < path.Length && char.IsLowSurrogate(path[i + 1]) ? 2 : 1;
                    ReadOnlySpan<char> sequence = path.Slice(i, sequenceLength);
                    if(!Encoding.UTF8.TryGetBytes(sequence, rented.AsSpan(written), out int encoded))
                    {
                        return (AsicContainerUriStatus.NotUtf8, null);
                    }

                    written += encoded;
                    i += sequenceLength - 1;

                    continue;
                }

                if(i + 2 >= path.Length
                    || !TryReadHexDigit(path[i + 1], out int high)
                    || !TryReadHexDigit(path[i + 2], out int low))
                {
                    return (AsicContainerUriStatus.MalformedPercentEncoding, null);
                }

                rented[written++] = (byte)((high << 4) | low);
                i += 2;
            }

            //The octets are decoded strictly: a percent-encoded sequence that is not valid UTF-8 is a name no
            //conformant container carries (clause 4.2 item 2 b), and decoding it leniently would substitute a
            //replacement character and change which entry the reference names.
            try
            {
                string decoded = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true)
                    .GetString(rented, 0, written);

                return (AsicContainerUriStatus.Resolved, decoded);
            }
            catch(DecoderFallbackException)
            {
                return (AsicContainerUriStatus.NotUtf8, null);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }


    /// <summary>
    /// Reads one hexadecimal digit of a percent-encoded octet.
    /// </summary>
    /// <param name="character">The character to read.</param>
    /// <param name="value">The value it names, when it is a hexadecimal digit.</param>
    /// <returns><see langword="true"/> when the character is a hexadecimal digit.</returns>
    private static bool TryReadHexDigit(char character, out int value)
    {
        value = character switch
        {
            >= '0' and <= '9' => character - '0',
            >= 'a' and <= 'f' => character - 'a' + 10,
            >= 'A' and <= 'F' => character - 'A' + 10,
            _ => -1
        };

        return value >= 0;
    }
}
