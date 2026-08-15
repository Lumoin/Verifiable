using System;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The wire names an Associated Signature Container fixes — media types, container file extensions, the reserved
/// entry names and the byte offsets the <c>mimetype</c> entry is recognised at — together with the recognition
/// helpers a dispatch site uses instead of comparing string literals at the call site.
/// </summary>
/// <remarks>
/// <para>
/// Every value here is stated by
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see>: the media types and their extensions by Annex A.2, the extension rules by
/// clauses 4.3.3.1 and 4.4.4.1, the <c>mimetype</c> entry and the offsets by Annex A.1, and the
/// <c>META-INF</c> folder by clauses 4.3.3.2 and 4.4.4.2.
/// </para>
/// <para>
/// <strong>Comparisons are case-insensitive, in both families.</strong> A media type is case-insensitive by
/// <see href="https://www.rfc-editor.org/rfc/rfc2045#section-5.1">IETF RFC 2045 clause 5.1</see>, and a container
/// file extension reaches this library from file systems that do not agree on case. The values this library
/// <em>writes</em> are the lower-case forms named here.
/// </para>
/// </remarks>
public static class AsicWellKnown
{
    /// <summary>
    /// The media type of an ASiC-S container, <c>application/vnd.etsi.asic-s+zip</c> (Annex A.2). Clause
    /// 4.3.3.1 item 1 makes it the content of the <c>mimetype</c> entry whenever the signed file object has no
    /// media type of its own.
    /// </summary>
    public static string AsicSimpleMediaType { get; } = "application/vnd.etsi.asic-s+zip";

    /// <summary>
    /// The media type of an ASiC-E container, <c>application/vnd.etsi.asic-e+zip</c> (Annex A.2). Clause
    /// 4.4.4.1 item 2 makes it the content of the <c>mimetype</c> entry unconditionally for the CAdES flavour —
    /// unlike the XAdES flavour of clause 4.4.3.1, that clause states no "original media type" alternative.
    /// </summary>
    public static string AsicExtendedMediaType { get; } = "application/vnd.etsi.asic-e+zip";

    /// <summary>The primary ASiC-S container file extension, <c>.asics</c> (clause 4.3.3.1 item 2 a, Annex A.2).</summary>
    public static string AsicSimpleExtension { get; } = ".asics";

    /// <summary>
    /// The short ASiC-S container file extension, <c>.scs</c>, which clause 4.3.3.1 item 2 b admits "in case the
    /// operating system or file system does not support more than three characters".
    /// </summary>
    public static string AsicSimpleShortExtension { get; } = ".scs";

    /// <summary>The primary ASiC-E container file extension, <c>.asice</c> (clauses 4.4.3.1 and 4.4.4.1 item 1 a, Annex A.2).</summary>
    public static string AsicExtendedExtension { get; } = ".asice";

    /// <summary>
    /// The short ASiC-E container file extension, <c>.sce</c>, which clauses 4.4.3.1 and 4.4.4.1 item 1 b admit
    /// for file systems limited to three characters.
    /// </summary>
    public static string AsicExtendedShortExtension { get; } = ".sce";

    /// <summary>
    /// The plain <c>.zip</c> extension clause 4.3.3.1 item 2 c admits "in case the container is intended to be
    /// handled manually". The clause binds a consequence to it: "in case c) item 1) a) of the present clause
    /// shall apply", so a <c>.zip</c>-named ASiC-S container states the fixed
    /// <see cref="AsicSimpleMediaType"/> in its <c>mimetype</c> entry rather than the signed object's own media
    /// type. This library accepts the extension on read and never writes it.
    /// </summary>
    public static string ZipExtension { get; } = ".zip";

    /// <summary>
    /// The name of the entry that carries the container's media type, <c>mimetype</c> (Annex A.1). It is a
    /// root-level name with no folder part, which is what puts its content at
    /// <see cref="MediaTypeOffset"/> in a conformant container.
    /// </summary>
    public static string MimetypeEntryName { get; } = "mimetype";

    /// <summary>The name of the folder every piece of container metadata lives in, <c>META-INF</c> (clauses 4.3.3.2 item 3 and 4.4.4.2).</summary>
    public static string MetaInfFolderName { get; } = "META-INF";

    /// <summary>The <c>META-INF/</c> entry-name prefix, the form a container entry name actually carries.</summary>
    public static string MetaInfPathPrefix { get; } = "META-INF/";

    /// <summary>
    /// The prefix of the ZIP archive comment clauses 4.3.2 item 3, 4.3.3.1 item 3 and 4.4.4.1 item 3 admit,
    /// <c>mimetype=</c>, followed by a media type.
    /// </summary>
    public static string MediaTypeCommentPrefix { get; } = "mimetype=";

    /// <summary>
    /// The offset the <c>mimetype</c> entry's name sits at in a conformant container, 30 — the length of a ZIP
    /// local file header. The Annex A.1 NOTE states it: "An application can ascertain if this feature is used by
    /// checking if the string "mimetype" is found starting at offset 30."
    /// </summary>
    public static int MimetypeNameOffset { get; } = 30;

    /// <summary>
    /// The offset the container's media type string sits at in a conformant container, 38 — the
    /// <see cref="MimetypeNameOffset"/> plus the eight octets of the name, which only holds because Annex A.1
    /// forbids the entry an extra field. The Annex A.1 NOTE states it: "it can be assumed that a string
    /// representing the container media type is present starting at offset 38".
    /// </summary>
    public static int MediaTypeOffset { get; } = 38;

    /// <summary>
    /// The offset the media type string's length is read from, 18 — the local file header's compressed-size
    /// field, which equals the uncompressed size because Annex A.1 forbids the entry compression. The Annex A.1
    /// NOTE states it: "the length of this string is contained in the 4 octets starting at offset 18".
    /// </summary>
    public static int MediaTypeLengthOffset { get; } = 18;


    /// <summary>
    /// Determines whether a media type is <see cref="AsicSimpleMediaType"/>.
    /// </summary>
    /// <param name="mediaType">The media type to test, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value names an ASiC-S container.</returns>
    public static bool IsAsicSimpleMediaType(string? mediaType) =>
        string.Equals(mediaType, AsicSimpleMediaType, StringComparison.OrdinalIgnoreCase);


    /// <summary>
    /// Determines whether a media type is <see cref="AsicExtendedMediaType"/>.
    /// </summary>
    /// <param name="mediaType">The media type to test, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value names an ASiC-E container.</returns>
    public static bool IsAsicExtendedMediaType(string? mediaType) =>
        string.Equals(mediaType, AsicExtendedMediaType, StringComparison.OrdinalIgnoreCase);


    /// <summary>
    /// Determines whether a media type is either of the two Annex A.2 container media types.
    /// </summary>
    /// <param name="mediaType">The media type to test, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value names an ASiC container.</returns>
    /// <remarks>
    /// A container whose <c>mimetype</c> entry states neither is not thereby non-conformant: clause 4.3.3.1
    /// item 1 b admits "the media type associated to the signed file object" for ASiC-S. The distinction is why
    /// this helper exists beside the two specific ones rather than in place of them.
    /// </remarks>
    public static bool IsAsicMediaType(string? mediaType) =>
        IsAsicSimpleMediaType(mediaType) || IsAsicExtendedMediaType(mediaType);


    /// <summary>
    /// Determines whether a file extension is one of the two ASiC-S extensions clause 4.3.3.1 item 2 names,
    /// <c>.asics</c> or <c>.scs</c>.
    /// </summary>
    /// <param name="extension">The extension including its leading dot, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the extension names an ASiC-S container.</returns>
    public static bool IsAsicSimpleExtension(string? extension) =>
        string.Equals(extension, AsicSimpleExtension, StringComparison.OrdinalIgnoreCase)
        || string.Equals(extension, AsicSimpleShortExtension, StringComparison.OrdinalIgnoreCase);


    /// <summary>
    /// Determines whether a file extension is one of the two ASiC-E extensions clauses 4.4.3.1 and 4.4.4.1
    /// item 1 name, <c>.asice</c> or <c>.sce</c>.
    /// </summary>
    /// <param name="extension">The extension including its leading dot, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the extension names an ASiC-E container.</returns>
    public static bool IsAsicExtendedExtension(string? extension) =>
        string.Equals(extension, AsicExtendedExtension, StringComparison.OrdinalIgnoreCase)
        || string.Equals(extension, AsicExtendedShortExtension, StringComparison.OrdinalIgnoreCase);


    /// <summary>
    /// Determines whether a file extension is one this library accepts a container under: the four ASiC
    /// extensions, or the plain <c>.zip</c> of clause 4.3.3.1 item 2 c.
    /// </summary>
    /// <param name="extension">The extension including its leading dot, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when a container may be read from under this extension.</returns>
    /// <remarks>
    /// Acceptance is wider than emission by design: this library writes only <see cref="AsicSimpleExtension"/>
    /// and <see cref="AsicExtendedExtension"/> — the primary forms clause 4.3.3.1 item 2 a and clause 4.4.4.1
    /// item 1 a state — while a container it is handed may legitimately carry any of the five.
    /// </remarks>
    public static bool IsAcceptedContainerExtension(string? extension) =>
        IsAsicSimpleExtension(extension)
        || IsAsicExtendedExtension(extension)
        || string.Equals(extension, ZipExtension, StringComparison.OrdinalIgnoreCase);


    /// <summary>
    /// Determines whether a container entry name is the <c>mimetype</c> entry of Annex A.1.
    /// </summary>
    /// <param name="entryName">The container entry name, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the name is exactly <c>mimetype</c>.</returns>
    /// <remarks>
    /// The comparison is ordinal and case-sensitive, unlike the media type and extension helpers: Annex A.1
    /// names one entry, entry names inside a ZIP are octet sequences rather than file-system names, and an entry
    /// called <c>MIMETYPE</c> is a different entry that no reader is entitled to treat as this one.
    /// </remarks>
    public static bool IsMimetypeEntryName(string? entryName) =>
        string.Equals(entryName, MimetypeEntryName, StringComparison.Ordinal);


    /// <summary>
    /// Determines whether a container entry name is inside the <c>META-INF</c> folder — where clauses 4.3.3.2
    /// and 4.4.4.2 place every signature, time assertion, Evidence Record and manifest.
    /// </summary>
    /// <param name="entryName">The container entry name, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the name begins with <c>META-INF/</c>.</returns>
    public static bool IsMetaInfEntryName(string? entryName) =>
        entryName is not null && entryName.StartsWith(MetaInfPathPrefix, StringComparison.Ordinal);


    /// <summary>
    /// Builds the ZIP archive comment clause 4.3.3.1 item 3 describes: <c>mimetype=</c> followed by a media type.
    /// </summary>
    /// <param name="mediaType">The media type to state.</param>
    /// <returns>The comment value.</returns>
    /// <exception cref="ArgumentException">When <paramref name="mediaType"/> is empty or white space.</exception>
    /// <remarks>
    /// No space follows the <c>=</c>. Clause 4.3.3.1 item 3 writes the prefix as <c>"mimetype="</c> while clause
    /// 4.4.4.1 item 3 prints <c>"mimetype= application/vnd.etsi.asic-e+zip"</c> with one; this library writes the
    /// tighter form and <see cref="MediaTypeFromComment"/> reads either.
    /// </remarks>
    public static string MediaTypeComment(string mediaType)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(mediaType);

        return MediaTypeCommentPrefix + mediaType;
    }


    /// <summary>
    /// Reads the media type out of a ZIP archive comment of the clause 4.3.3.1 item 3 form.
    /// </summary>
    /// <param name="comment">The archive comment, or <see langword="null"/> when the container carries none.</param>
    /// <returns>The media type the comment states, or <see langword="null"/> when it states none.</returns>
    /// <remarks>
    /// Leading white space between the <c>=</c> and the media type is accepted because clause 4.4.4.1 item 3
    /// prints it that way; trailing white space is trimmed for the same reason. A comment that does not begin
    /// with <see cref="MediaTypeCommentPrefix"/> carries no media type and yields <see langword="null"/> rather
    /// than an error — the comment is a "may", and its absence or its use for something else is conformant.
    /// </remarks>
    public static string? MediaTypeFromComment(string? comment)
    {
        if(comment is null || !comment.StartsWith(MediaTypeCommentPrefix, StringComparison.Ordinal))
        {
            return null;
        }

        string value = comment[MediaTypeCommentPrefix.Length..].Trim();

        return value.Length == 0 ? null : value;
    }
}
