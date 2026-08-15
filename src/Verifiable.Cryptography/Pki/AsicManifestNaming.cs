using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Which of the three roles a manifest file carries — the classification a validator has to make before it
/// knows which rule set applies to a manifest's <c>SigReference</c> and <c>DataObjectReference</c> content.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The role is a property of the file name, never of the content.</strong>
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> clause 3.1 defines <c>ASiCManifest</c>, <c>ASiCArchiveManifest</c> and
/// <c>ASiCEvidenceRecordManifest</c> as three uses of one XML element type — Annex A.4.2's
/// <c>ASiCManifestType</c>, which carries no namespace, attribute or child element that says which of the
/// three a given file is. Clause 4.4.4.2 and Annex A.7 therefore select files by name pattern, and this
/// enumeration is the result of applying those patterns. It is deliberately not a member of
/// <see cref="AsicManifest"/>: a document that stated its own role could disagree with the name it is stored
/// under, and the name is what the specification's own procedures dispatch on.
/// </para>
/// <para>
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised field never reads as a classified role.
/// </para>
/// </remarks>
public enum AsicManifestRole
{
    /// <summary>The name has not been examined. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The name matches none of the three manifest patterns, so the file is not a manifest at all.</summary>
    NotAManifest = 1,

    /// <summary>
    /// An <c>ASiCManifest</c> file (clause 4.4.4.2 item 2: files whose name matches
    /// <c>META-INF/ASiCManifest*.xml</c>), whose <c>SigReference</c> names a CAdES object or a time assertion
    /// that applies to the manifest file itself.
    /// </summary>
    Signature = 2,

    /// <summary>
    /// An <c>ASiCArchiveManifest</c> file (Annex A.7: the newest is named <c>META-INF/ASiCArchiveManifest.xml</c>
    /// and every earlier one has been renamed to match <c>META-INF/*ASiCArchiveManifest*.xml</c>), the
    /// container-level long-term-availability chain.
    /// </summary>
    Archive = 3,

    /// <summary>
    /// An <c>ASiCEvidenceRecordManifest</c> file (clause 4.4.3.2 item 4: files whose name matches
    /// <c>META-INF/ASiCEvidenceRecordManifest*.xml</c>), whose <c>SigReference</c> names an Evidence Record
    /// that applies to the files the sibling <c>DataObjectReference</c> elements name — and, per the clause
    /// 4.4.4.2 NOTE 2, not to the manifest file itself.
    /// </summary>
    EvidenceRecord = 4,

    /// <summary>
    /// The name matches more than one of the three patterns, so no single rule set applies to it. Refused
    /// rather than resolved by precedence: the specification states three patterns and no ordering between
    /// them, and a file a producer can steer into two roles at once is a file a validator and a producer can
    /// disagree about.
    /// </summary>
    Ambiguous = 5
}


/// <summary>
/// Which kind of file inside the <c>META-INF</c> folder a name is being created for.
/// </summary>
/// <remarks>
/// The kinds are exactly the wildcard-named file classes
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> clauses 4.4.3.2, 4.4.4.2 and Annex A.7 require "avoiding any name collision
/// with other elements already present in the container": manifests of the three roles, the CAdES object, the
/// time-stamp token and the two Evidence Record forms.
/// </remarks>
public enum AsicContainerFileKind
{
    /// <summary>No file kind stated. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>An <c>ASiCManifest</c> file (clause 4.4.4.2 item 2).</summary>
    SignatureManifest = 1,

    /// <summary>An <c>ASiCArchiveManifest</c> file (Annex A.7).</summary>
    ArchiveManifest = 2,

    /// <summary>An <c>ASiCEvidenceRecordManifest</c> file (clause 4.4.3.2 item 4).</summary>
    EvidenceRecordManifest = 3,

    /// <summary>A CAdES object, <c>META-INF/*signature*.p7s</c> (clause 4.4.4.2 item 3 a).</summary>
    Signature = 4,

    /// <summary>An RFC 3161 time-stamp token, <c>META-INF/*timestamp*.tst</c> (clause 4.4.4.2 item 3 b).</summary>
    Timestamp = 5,

    /// <summary>An RFC 4998 Evidence Record, <c>META-INF/*evidencerecord*.ers</c> (clause 4.4.4.2 item 4 a).</summary>
    BinaryEvidenceRecord = 6,

    /// <summary>An RFC 6283 Evidence Record, <c>META-INF/*evidencerecord*.xml</c> (clause 4.4.4.2 item 4 b).</summary>
    XmlEvidenceRecord = 7
}


/// <summary>
/// Names why a container file name could not be created.
/// </summary>
/// <remarks>
/// These are generator-side faults, in the same sense as <see cref="AsicZipAuthoringFailureKind"/>: material
/// or container state the caller supplied that no conformant name can be derived from.
/// </remarks>
public enum AsicManifestNamingFailureKind
{
    /// <summary>No failure has been classified.</summary>
    NotEvaluated = 0,

    /// <summary>The file kind is <see cref="AsicContainerFileKind.NotEvaluated"/> or a value outside the enumeration.</summary>
    UnsupportedFileKind = 1,

    /// <summary>Every numeric suffix up to <see cref="AsicManifestNaming.MaximumNameSuffix"/> is already taken by an entry of the container.</summary>
    SuffixSpaceExhausted = 2,

    /// <summary>
    /// The fixed name Annex A.7 item 1 c a) mandates for a new <c>ASiCArchiveManifest</c> file is already
    /// present, so the previous one has not been renamed as Annex A.7 item 2 a) requires.
    /// </summary>
    FixedNameAlreadyPresent = 3
}


/// <summary>
/// The generator-side fault of deriving a container file name.
/// </summary>
[DebuggerDisplay("AsicManifestNamingException({FailureKind}): {Message}")]
public sealed class AsicManifestNamingException: Exception
{
    /// <summary>Gets what could not be done.</summary>
    public AsicManifestNamingFailureKind FailureKind { get; }


    /// <summary>Initializes a new <see cref="AsicManifestNamingException"/> with an unclassified fault.</summary>
    public AsicManifestNamingException(): this(AsicManifestNamingFailureKind.UnsupportedFileKind, "The container file name could not be created.")
    {
    }


    /// <summary>Initializes a new <see cref="AsicManifestNamingException"/> with an unclassified fault.</summary>
    /// <param name="message">The message describing the fault.</param>
    public AsicManifestNamingException(string message): this(AsicManifestNamingFailureKind.UnsupportedFileKind, message)
    {
    }


    /// <summary>Initializes a new <see cref="AsicManifestNamingException"/> with an unclassified fault.</summary>
    /// <param name="message">The message describing the fault.</param>
    /// <param name="innerException">The exception that caused it.</param>
    public AsicManifestNamingException(string message, Exception innerException)
        : this(AsicManifestNamingFailureKind.UnsupportedFileKind, message, innerException)
    {
    }


    /// <summary>Initializes a new <see cref="AsicManifestNamingException"/>.</summary>
    /// <param name="failureKind">What could not be done.</param>
    /// <param name="message">The message describing the fault.</param>
    public AsicManifestNamingException(AsicManifestNamingFailureKind failureKind, string message): base(message)
    {
        FailureKind = failureKind;
    }


    /// <summary>Initializes a new <see cref="AsicManifestNamingException"/>.</summary>
    /// <param name="failureKind">What could not be done.</param>
    /// <param name="message">The message describing the fault.</param>
    /// <param name="innerException">The exception that caused it.</param>
    public AsicManifestNamingException(AsicManifestNamingFailureKind failureKind, string message, Exception innerException)
        : base(message, innerException)
    {
        FailureKind = failureKind;
    }
}


/// <summary>
/// The file-name rules of the <c>META-INF</c> folder: which role a manifest file name carries, which kind of
/// file every other <c>META-INF</c> name is, and the names this library creates.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The wildcard convention.</strong> Annex A.6 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> states one grammar rule and no more: "the character "*" denotes an arbitrary
/// character string of any length, including zero". Every pattern in clauses 4.3.3.2, 4.4.3.2, 4.4.4.2 and
/// Annex A.7 is written in that grammar, and this class implements it as a literal-substring test: a leading
/// <c>*</c> means the token may be preceded by anything, its absence means the name begins with the token.
/// </para>
/// <para>
/// <strong>Matching is ordinal and case-sensitive, and that is load-bearing.</strong> A container entry name is
/// an octet sequence rather than a file-system name, and the patterns overlap the moment case is ignored:
/// <c>META-INF/ASiCEvidenceRecordManifest1.xml</c> would match <c>META-INF/*evidencerecord*.xml</c>, the
/// clause 4.4.4.2 item 4 b pattern for an Evidence Record in XML form, and every manifest of that role would
/// be dispatched to the Evidence Record verifier. Case-sensitively the two are disjoint, which is what the
/// specification's own spelling of the patterns relies on.
/// </para>
/// <para>
/// <strong>The creation scheme is this library's, the mandate is the specification's.</strong> Annex A.7
/// item 1 c c) and item 2 a) require a new name "avoiding any name collision with other elements already
/// present in the container" and state no scheme for producing one. This library appends the lowest positive
/// decimal integer that leaves the name free — <c>META-INF/ASiCManifest1.xml</c>,
/// <c>META-INF/signature1.p7s</c>, <c>META-INF/timestamp1.tst</c>,
/// <c>META-INF/evidencerecord1.ers</c> — which is the shape Part 2's own worked example prints, and refuses
/// rather than invents when the space is exhausted.
/// </para>
/// </remarks>
public static class AsicManifestNaming
{
    /// <summary>The token an <c>ASiCManifest</c> file name begins with, after the <c>META-INF/</c> prefix (clause 4.4.4.2 item 2).</summary>
    public static string SignatureManifestToken { get; } = "ASiCManifest";

    /// <summary>The token an <c>ASiCArchiveManifest</c> file name contains (Annex A.7 items 1 c a) and 2 a)).</summary>
    public static string ArchiveManifestToken { get; } = "ASiCArchiveManifest";

    /// <summary>The token an <c>ASiCEvidenceRecordManifest</c> file name begins with, after the <c>META-INF/</c> prefix (clause 4.4.3.2 item 4).</summary>
    public static string EvidenceRecordManifestToken { get; } = "ASiCEvidenceRecordManifest";

    /// <summary>The token a CAdES object's file name contains, <c>signature</c> (clause 4.4.4.2 item 3 a).</summary>
    public static string SignatureToken { get; } = "signature";

    /// <summary>The token a time-stamp token's file name contains, <c>timestamp</c> (clause 4.4.4.2 item 3 b).</summary>
    public static string TimestampToken { get; } = "timestamp";

    /// <summary>The token an Evidence Record's file name contains, <c>evidencerecord</c> (clause 4.4.4.2 item 4).</summary>
    public static string EvidenceRecordToken { get; } = "evidencerecord";

    /// <summary>The extension of every manifest file and of an Evidence Record in XML form, <c>.xml</c>.</summary>
    public static string XmlExtension { get; } = ".xml";

    /// <summary>The extension of a CAdES object, <c>.p7s</c> (clause 4.4.4.2 item 3 a).</summary>
    public static string SignatureExtension { get; } = ".p7s";

    /// <summary>The extension of a time-stamp token, <c>.tst</c> (clause 4.4.4.2 item 3 b).</summary>
    public static string TimestampExtension { get; } = ".tst";

    /// <summary>The extension of an Evidence Record in the RFC 4998 form, <c>.ers</c> (clause 4.4.4.2 item 4 a).</summary>
    public static string BinaryEvidenceRecordExtension { get; } = ".ers";

    /// <summary>
    /// The name Annex A.7 item 1 c a) fixes for a newly added <c>ASiCArchiveManifest</c> file,
    /// <c>META-INF/ASiCArchiveManifest.xml</c> — "The ASiCArchiveManifest file shall: a) be named
    /// "ASiCArchiveManifest.xml"". Every earlier one carries a name
    /// <see cref="CreateEntryName(AsicContainerFileKind, IEnumerable{string})"/> produced.
    /// </summary>
    public static string FixedArchiveManifestEntryName { get; } = AsicWellKnown.MetaInfPathPrefix + ArchiveManifestToken + XmlExtension;

    /// <summary>
    /// The name clause 4.3.3.2 item 4 b fixes for the CAdES object of an ASiC-S container,
    /// <c>META-INF/signature.p7s</c>.
    /// </summary>
    /// <remarks>
    /// The four ASiC-S names below carry no numeric suffix, and that is the clause's own doing: "The META-INF
    /// folder shall contain only one of the following files", each named outright. They are therefore the one
    /// place a created name cannot move out of the way of a collision, which is why
    /// <see cref="CreateEntryName(AsicContainerFileKind, IEnumerable{string})"/> never produces the unsuffixed
    /// form and the ASiC-S composition refuses a collision instead of renaming.
    /// </remarks>
    public static string SimpleSignatureEntryName { get; } = AsicWellKnown.MetaInfPathPrefix + SignatureToken + SignatureExtension;

    /// <summary>The name clause 4.3.3.2 item 4 a fixes for the time-stamp token of an ASiC-S container, <c>META-INF/timestamp.tst</c>.</summary>
    public static string SimpleTimestampEntryName { get; } = AsicWellKnown.MetaInfPathPrefix + TimestampToken + TimestampExtension;

    /// <summary>The name clause 4.3.3.2 item 4 d fixes for the RFC 4998 Evidence Record of an ASiC-S container, <c>META-INF/evidencerecord.ers</c>.</summary>
    public static string SimpleBinaryEvidenceRecordEntryName { get; } = AsicWellKnown.MetaInfPathPrefix + EvidenceRecordToken + BinaryEvidenceRecordExtension;

    /// <summary>The name clause 4.3.3.2 item 4 e fixes for the RFC 6283 Evidence Record of an ASiC-S container, <c>META-INF/evidencerecord.xml</c>.</summary>
    public static string SimpleXmlEvidenceRecordEntryName { get; } = AsicWellKnown.MetaInfPathPrefix + EvidenceRecordToken + XmlExtension;

    /// <summary>
    /// The largest numeric suffix <see cref="CreateEntryName(AsicContainerFileKind, IEnumerable{string})"/>
    /// will try before refusing, 4096 — the entry-count bound the container author enforces, so the search can
    /// only be exhausted by a container that is already at its limit.
    /// </summary>
    public static int MaximumNameSuffix { get; } = 4096;


    /// <summary>
    /// Classifies a container entry name into one of the three manifest roles.
    /// </summary>
    /// <param name="entryName">The container entry name, or <see langword="null"/>.</param>
    /// <returns>The role, <see cref="AsicManifestRole.NotAManifest"/>, or <see cref="AsicManifestRole.Ambiguous"/>.</returns>
    /// <remarks>
    /// A manifest lives in the <c>META-INF</c> folder — clause 4.4.4.2's patterns are written with the folder
    /// in them — so a name outside it is <see cref="AsicManifestRole.NotAManifest"/> however it is spelled,
    /// and a name naming a deeper folder inside <c>META-INF</c> is too: the patterns admit no separator after
    /// the prefix.
    /// </remarks>
    public static AsicManifestRole RoleFromEntryName(string? entryName)
    {
        if(!TryTakeMetaInfLeaf(entryName, out string leaf))
        {
            return AsicManifestRole.NotAManifest;
        }

        if(!leaf.EndsWith(XmlExtension, StringComparison.Ordinal))
        {
            return AsicManifestRole.NotAManifest;
        }

        //Every pattern is applied to the same name and the matches are counted rather than ordered: the three
        //tokens are disjoint on the names the specification itself prints, but nothing stops a producer from
        //writing a name that carries two of them, and choosing one by precedence would decide silently which
        //rule set a validator applies to a file its producer may have meant for the other.
        bool isSignature = leaf.StartsWith(SignatureManifestToken, StringComparison.Ordinal);
        bool isArchive = leaf.Contains(ArchiveManifestToken, StringComparison.Ordinal);
        bool isEvidenceRecord = leaf.StartsWith(EvidenceRecordManifestToken, StringComparison.Ordinal);

        int matches = (isSignature ? 1 : 0) + (isArchive ? 1 : 0) + (isEvidenceRecord ? 1 : 0);

        return matches switch
        {
            0 => AsicManifestRole.NotAManifest,
            1 when isSignature => AsicManifestRole.Signature,
            1 when isArchive => AsicManifestRole.Archive,
            1 => AsicManifestRole.EvidenceRecord,
            _ => AsicManifestRole.Ambiguous
        };
    }


    /// <summary>Determines whether an entry name is an <c>ASiCManifest</c> file (clause 4.4.4.2 item 2).</summary>
    /// <param name="entryName">The container entry name, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the name carries that role and no other.</returns>
    public static bool IsSignatureManifestEntryName(string? entryName) =>
        RoleFromEntryName(entryName) == AsicManifestRole.Signature;


    /// <summary>Determines whether an entry name is an <c>ASiCArchiveManifest</c> file (Annex A.7).</summary>
    /// <param name="entryName">The container entry name, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the name carries that role and no other.</returns>
    public static bool IsArchiveManifestEntryName(string? entryName) =>
        RoleFromEntryName(entryName) == AsicManifestRole.Archive;


    /// <summary>Determines whether an entry name is an <c>ASiCEvidenceRecordManifest</c> file (clause 4.4.3.2 item 4).</summary>
    /// <param name="entryName">The container entry name, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the name carries that role and no other.</returns>
    public static bool IsEvidenceRecordManifestEntryName(string? entryName) =>
        RoleFromEntryName(entryName) == AsicManifestRole.EvidenceRecord;


    /// <summary>Determines whether an entry name is a CAdES object, <c>META-INF/*signature*.p7s</c> (clause 4.4.4.2 item 3 a).</summary>
    /// <param name="entryName">The container entry name, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the name matches the pattern.</returns>
    public static bool IsSignatureEntryName(string? entryName) =>
        MatchesMetaInfPattern(entryName, SignatureToken, SignatureExtension);


    /// <summary>Determines whether an entry name is a time-stamp token, <c>META-INF/*timestamp*.tst</c> (clause 4.4.4.2 item 3 b).</summary>
    /// <param name="entryName">The container entry name, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the name matches the pattern.</returns>
    public static bool IsTimestampEntryName(string? entryName) =>
        MatchesMetaInfPattern(entryName, TimestampToken, TimestampExtension);


    /// <summary>Determines whether an entry name is an RFC 4998 Evidence Record, <c>META-INF/*evidencerecord*.ers</c> (clause 4.4.4.2 item 4 a).</summary>
    /// <param name="entryName">The container entry name, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the name matches the pattern.</returns>
    public static bool IsBinaryEvidenceRecordEntryName(string? entryName) =>
        MatchesMetaInfPattern(entryName, EvidenceRecordToken, BinaryEvidenceRecordExtension);


    /// <summary>
    /// Determines whether an entry name is an RFC 6283 Evidence Record, <c>META-INF/*evidencerecord*.xml</c>
    /// (clause 4.4.4.2 item 4 b).
    /// </summary>
    /// <param name="entryName">The container entry name, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the name matches the pattern.</returns>
    /// <remarks>
    /// This is the pattern that collides with <see cref="AsicManifestRole.EvidenceRecord"/>'s the moment case
    /// is ignored, so the ordinal comparison this class applies throughout is what keeps a manifest out of the
    /// Evidence Record dispatch of clause 4.4.4.2 item 4.
    /// </remarks>
    public static bool IsXmlEvidenceRecordEntryName(string? entryName) =>
        MatchesMetaInfPattern(entryName, EvidenceRecordToken, XmlExtension);


    /// <summary>
    /// Creates a <c>META-INF</c> entry name of the requested kind that collides with nothing already in the
    /// container.
    /// </summary>
    /// <param name="fileKind">Which kind of file the name is for.</param>
    /// <param name="existingEntryNames">Every entry name the container already carries.</param>
    /// <returns>The created entry name.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="existingEntryNames"/> is <see langword="null"/>.</exception>
    /// <exception cref="AsicManifestNamingException">
    /// When <paramref name="fileKind"/> is not a file kind, or every suffix up to
    /// <see cref="MaximumNameSuffix"/> is taken.
    /// </exception>
    /// <remarks>
    /// The suffix starts at 1 and the unsuffixed form is never produced, for two reasons: clause 4.3.3.2
    /// item 4 gives the unsuffixed names (<c>signature.p7s</c>, <c>timestamp.tst</c>,
    /// <c>evidencerecord.ers</c>) a meaning of their own in an ASiC-S container, where the folder holds
    /// exactly one file; and <see cref="FixedArchiveManifestEntryName"/> is the name Annex A.7 reserves for the
    /// newest archive manifest, so producing it here would collide with the one name the specification fixes.
    /// </remarks>
    public static string CreateEntryName(AsicContainerFileKind fileKind, IEnumerable<string> existingEntryNames)
    {
        ArgumentNullException.ThrowIfNull(existingEntryNames);

        (string token, string extension) = fileKind switch
        {
            AsicContainerFileKind.SignatureManifest => (SignatureManifestToken, XmlExtension),
            AsicContainerFileKind.ArchiveManifest => (ArchiveManifestToken, XmlExtension),
            AsicContainerFileKind.EvidenceRecordManifest => (EvidenceRecordManifestToken, XmlExtension),
            AsicContainerFileKind.Signature => (SignatureToken, SignatureExtension),
            AsicContainerFileKind.Timestamp => (TimestampToken, TimestampExtension),
            AsicContainerFileKind.BinaryEvidenceRecord => (EvidenceRecordToken, BinaryEvidenceRecordExtension),
            AsicContainerFileKind.XmlEvidenceRecord => (EvidenceRecordToken, XmlExtension),
            _ => throw new AsicManifestNamingException(
                AsicManifestNamingFailureKind.UnsupportedFileKind,
                $"'{fileKind}' does not name a kind of file the META-INF folder holds.")
        };

        var taken = new HashSet<string>(existingEntryNames, StringComparer.Ordinal);
        for(int suffix = 1; suffix <= MaximumNameSuffix; ++suffix)
        {
            string candidate = string.Create(
                CultureInfo.InvariantCulture,
                $"{AsicWellKnown.MetaInfPathPrefix}{token}{suffix}{extension}");

            if(!taken.Contains(candidate))
            {
                return candidate;
            }
        }

        throw new AsicManifestNamingException(
            AsicManifestNamingFailureKind.SuffixSpaceExhausted,
            $"Every '{token}' name up to suffix {MaximumNameSuffix} is already present in the container.");
    }


    /// <summary>
    /// States the name Annex A.7 item 1 c a) fixes for a newly added <c>ASiCArchiveManifest</c> file, refusing
    /// when the container still carries one under that name.
    /// </summary>
    /// <param name="existingEntryNames">Every entry name the container already carries.</param>
    /// <returns><see cref="FixedArchiveManifestEntryName"/>.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="existingEntryNames"/> is <see langword="null"/>.</exception>
    /// <exception cref="AsicManifestNamingException">When the fixed name is already present.</exception>
    /// <remarks>
    /// Annex A.7 item 2 a) makes renaming the previous archive manifest the first step of every subsequent
    /// addition, so meeting the fixed name still occupied means that step has not been performed. Refusing here
    /// rather than overwriting is what keeps the octets a time-stamp token already committed to intact — the
    /// rename changes an entry name and nothing else.
    /// </remarks>
    public static string CreateFixedArchiveManifestEntryName(IEnumerable<string> existingEntryNames)
    {
        ArgumentNullException.ThrowIfNull(existingEntryNames);

        foreach(string existing in existingEntryNames)
        {
            if(string.Equals(existing, FixedArchiveManifestEntryName, StringComparison.Ordinal))
            {
                throw new AsicManifestNamingException(
                    AsicManifestNamingFailureKind.FixedNameAlreadyPresent,
                    $"'{FixedArchiveManifestEntryName}' is already present; Annex A.7 item 2 a) requires the previous archive manifest to be renamed first.");
            }
        }

        return FixedArchiveManifestEntryName;
    }


    /// <summary>
    /// Tests a name against a <c>META-INF/*token*extension</c> pattern of the Annex A.6 grammar.
    /// </summary>
    /// <param name="entryName">The container entry name, or <see langword="null"/>.</param>
    /// <param name="token">The literal the name must carry between the folder prefix and the extension.</param>
    /// <param name="extension">The extension the name must end with.</param>
    /// <returns><see langword="true"/> when the name matches.</returns>
    private static bool MatchesMetaInfPattern(string? entryName, string token, string extension)
    {
        if(!TryTakeMetaInfLeaf(entryName, out string leaf))
        {
            return false;
        }

        if(!leaf.EndsWith(extension, StringComparison.Ordinal))
        {
            return false;
        }

        //The token has to sit before the extension rather than anywhere in the name, so that a name whose
        //extension happens to spell the token — there is none among these six, but a later pattern could —
        //cannot match on its own extension.
        ReadOnlySpan<char> stem = leaf.AsSpan(0, leaf.Length - extension.Length);

        return stem.Contains(token, StringComparison.Ordinal);
    }


    /// <summary>
    /// Takes the part of an entry name that follows the <c>META-INF/</c> prefix, when the name names a file
    /// directly inside that folder.
    /// </summary>
    /// <param name="entryName">The container entry name, or <see langword="null"/>.</param>
    /// <param name="leaf">The part after the prefix, or the empty string when there is none.</param>
    /// <returns><see langword="true"/> when the name is a file directly inside <c>META-INF</c>.</returns>
    /// <remarks>
    /// A name carrying a further separator names a file in a folder below <c>META-INF</c>, which none of the
    /// clause 4.4.4.2 patterns admits: each is written as <c>META-INF/</c> followed by a pattern with no
    /// separator in it.
    /// </remarks>
    private static bool TryTakeMetaInfLeaf(string? entryName, out string leaf)
    {
        leaf = string.Empty;
        if(!AsicWellKnown.IsMetaInfEntryName(entryName))
        {
            return false;
        }

        string candidate = entryName![AsicWellKnown.MetaInfPathPrefix.Length..];
        if(candidate.Length == 0 || candidate.Contains(AsicZipEntryNaming.Separator, StringComparison.Ordinal))
        {
            return false;
        }

        leaf = candidate;

        return true;
    }
}
