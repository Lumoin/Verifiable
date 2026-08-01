using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Which of the two Evidence Record forms clause 4.4.4.2 item 4 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> admits a container entry carries — the distinction the dispatch rule of that
/// item turns on.
/// </summary>
/// <remarks>
/// The form is read from the entry's name and from nothing else, exactly as the clause states it: item 4 a) names
/// <c>META-INF/*evidencerecord*.ers</c> for <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see>
/// and item 4 b) names <c>META-INF/*evidencerecord*.xml</c> for
/// <see href="https://www.rfc-editor.org/rfc/rfc6283">IETF RFC 6283</see>.
/// </remarks>
public enum AsicEvidenceRecordForm
{
    /// <summary>No form stated. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The Evidence Record Syntax of IETF RFC 4998, carried by a <c>*evidencerecord*.ers</c> entry.</summary>
    Binary = 1,

    /// <summary>The XML Evidence Record Syntax of IETF RFC 6283, carried by a <c>*evidencerecord*.xml</c> entry.</summary>
    Xml = 2
}


/// <summary>
/// One manifest file a container carries: the entry it is stored as, and the role its name gives it.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> <see cref="Entry"/> is a non-owning reference to an entry the
/// <see cref="AsicContainerFacts"/> that surfaced it owns.
/// </remarks>
[DebuggerDisplay("AsicManifestFile: {Role}, {Entry.Name}")]
public sealed record AsicManifestFile
{
    /// <summary>The entry the manifest is stored as.</summary>
    public required AsicZipEntry Entry { get; init; }

    /// <summary>The role the entry's name gives the manifest (clause 4.4.4.2 item 2, clause 4.4.3.2 item 4 and Annex A.7).</summary>
    public required AsicManifestRole Role { get; init; }
}


/// <summary>
/// One Evidence Record file a container carries: the entry it is stored as, and the form its name gives it.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> <see cref="Entry"/> is a non-owning reference to an entry the
/// <see cref="AsicContainerFacts"/> that surfaced it owns.
/// </remarks>
[DebuggerDisplay("AsicEvidenceRecordFile: {Form}, {Entry.Name}")]
public sealed record AsicEvidenceRecordFile
{
    /// <summary>The entry the Evidence Record is stored as.</summary>
    public required AsicZipEntry Entry { get; init; }

    /// <summary>Which of the two forms of clause 4.4.4.2 item 4 the entry's name states.</summary>
    public required AsicEvidenceRecordForm Form { get; init; }
}


/// <summary>
/// What one container states about itself: the archive it is, the media type it declares, and the file objects
/// clauses 4.3.3.2 and 4.4.4.2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> give a meaning to, each sorted into the class its name puts it in.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Nothing here is verified.</strong> These are the facts a validator starts from — which entries exist,
/// what each one's name makes it, what the container calls itself. Whether the digests match, whether the
/// signatures verify and whether the Evidence Records prove anything is
/// <see cref="AsicContainerValidation"/>'s conclusion.
/// </para>
/// <para>
/// <strong>Ownership.</strong> This instance owns <see cref="Container"/> and therefore every entry's octets;
/// every list here holds non-owning references into it. Disposing this disposes them all.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class AsicContainerFacts: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>The archive itself, with every entry's octets. Owned by this instance.</summary>
    public required AsicZipContainer Container { get; init; }

    /// <summary>Which of the two container shapes of clause 4.1.2 the container has, as far as its own statements and its layout establish one.</summary>
    public required AsicContainerShape Shape { get; init; }

    /// <summary>Which named profile the container's file objects put it in; see the remarks on <see cref="AsicContainerProfile"/>.</summary>
    public required AsicContainerProfile Profile { get; init; }

    /// <summary>The media type the <c>mimetype</c> entry states, or <see langword="null"/> when the container carries no such entry.</summary>
    public string? MediaType { get; init; }

    /// <summary>Whether the media type is readable by the Annex A.1 NOTE recognition — the "magic number" at octet 38 of the archive.</summary>
    public bool MediaTypeReadableAtOffset38 { get; init; }

    /// <summary>The data file objects: every entry that is not the <c>mimetype</c> entry, not a folder and not inside <c>META-INF</c> (clause 4.4.2 item 2).</summary>
    public required IReadOnlyList<AsicZipEntry> DataObjects { get; init; }

    /// <summary>Every manifest file, with its role.</summary>
    public required IReadOnlyList<AsicManifestFile> Manifests { get; init; }

    /// <summary>Every CAdES object, <c>META-INF/*signature*.p7s</c> (clause 4.4.4.2 item 3 a) and clause 4.3.3.2 item 4 b)).</summary>
    public required IReadOnlyList<AsicZipEntry> Signatures { get; init; }

    /// <summary>Every time assertion, <c>META-INF/*timestamp*.tst</c> (clause 4.4.4.2 item 3 b) and clause 4.3.3.2 item 4 c)).</summary>
    public required IReadOnlyList<AsicZipEntry> TimeAssertions { get; init; }

    /// <summary>Every Evidence Record, in either of the two forms of clause 4.4.4.2 item 4.</summary>
    public required IReadOnlyList<AsicEvidenceRecordFile> EvidenceRecords { get; init; }

    /// <summary>The archive manifest under the fixed name Annex A.7 item 1 c a) mandates, or <see langword="null"/> when the container carries no chain.</summary>
    public AsicZipEntry? FixedArchiveManifest { get; init; }


    /// <summary>
    /// Finds one entry by name.
    /// </summary>
    /// <param name="entryName">The entry name, compared ordinally.</param>
    /// <returns>The entry, or <see langword="null"/> when the container carries none under that name.</returns>
    public AsicZipEntry? FindEntry(string entryName) => Container.FindEntry(entryName);


    /// <summary>Disposes the archive and, with it, every entry these facts point at.</summary>
    public void Dispose()
    {
        if(!disposed)
        {
            Container.Dispose();
            disposed = true;
        }
    }


    /// <summary>A short debugger string showing the shape, the profile and how many file objects of each class the container carries.</summary>
    private string DebuggerDisplay =>
        $"AsicContainerFacts({Shape}, {Profile}, {DataObjects.Count} data, {Manifests.Count} manifests, {Signatures.Count} signatures, {TimeAssertions.Count} time assertions, {EvidenceRecords.Count} evidence records)";
}


/// <summary>
/// The outcome of reading a container's facts: the facts, or the reason the octets were refused.
/// </summary>
/// <remarks>
/// A container arrives from outside, so a refusal is a status rather than an exception — the discipline
/// <see cref="AsicZipReadResult"/> already applies, and this result carries that surface's own status verbatim so
/// nothing about why the archive was refused is lost on the way through.
/// </remarks>
[DebuggerDisplay("AsicContainerReadResult: {Status}")]
public sealed class AsicContainerReadResult: IDisposable
{
    /// <summary>Whether the archive was read, and if not why (<see cref="AsicZipReadStatus.Read"/> is the only success).</summary>
    public required AsicZipReadStatus Status { get; init; }

    /// <summary>The facts; non-<see langword="null"/> only when <see cref="Status"/> is <see cref="AsicZipReadStatus.Read"/>. Owned by this result.</summary>
    public AsicContainerFacts? Facts { get; init; }

    /// <summary>The entry name that was refused, when a name-shaped status names one.</summary>
    public string? RejectedEntryName { get; init; }

    /// <summary>Which entry-name rule refused it, when <see cref="Status"/> is <see cref="AsicZipReadStatus.EntryNameRefused"/>.</summary>
    public AsicZipEntryNameStatus RejectedEntryNameStatus { get; init; }

    /// <summary>Whether the facts were read.</summary>
    public bool IsRead => Status == AsicZipReadStatus.Read && Facts is not null;


    /// <summary>Disposes the facts, when present.</summary>
    public void Dispose() => Facts?.Dispose();
}


/// <summary>
/// Reads an Associated Signature Container's facts: the archive under the hostile-input bounds of
/// <see cref="AsicZipReading"/>, and the meaning clauses 4.3.3 and 4.4.4 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> give each entry by the name it is stored under.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Names decide, and nothing else.</strong> Every classification here comes from
/// <see cref="AsicManifestNaming"/> and <see cref="AsicWellKnown"/>, which is what the specification itself does:
/// clause 4.4.4.2 selects manifests by <c>META-INF/ASiCManifest*.xml</c>, their protective objects by
/// <c>*signature*.p7s</c> / <c>*timestamp*.tst</c>, and Evidence Records by <c>*evidencerecord*.ers</c> /
/// <c>*evidencerecord*.xml</c>. No file's content is opened to decide what it is.
/// </para>
/// <para>
/// <strong>The media type is read twice, on purpose.</strong> <see cref="AsicContainerFacts.MediaType"/> is the
/// <c>mimetype</c> entry's content as the central directory points at it, and
/// <see cref="AsicContainerFacts.MediaTypeReadableAtOffset38"/> states whether the Annex A.1 NOTE recognition —
/// the one an operating system performs, which reads octets at a fixed offset and consults no directory — reaches
/// the same value. A container where the two disagree is one the reader has already refused
/// (<see cref="AsicZipReadStatus.MimetypeEntryNotAtOffsetZero"/> and its neighbours); the fact is surfaced so a
/// report can state it rather than assume it.
/// </para>
/// </remarks>
public static class AsicContainerReading
{
    /// <summary>
    /// Reads a container's facts.
    /// </summary>
    /// <param name="containerBytes">The container's octets.</param>
    /// <param name="limits">The bounds the archive is read within.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <returns>The facts, or the reason the octets were refused. The caller owns and disposes the result.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public static AsicContainerReadResult Read(ReadOnlyMemory<byte> containerBytes, AsicZipReadLimits limits, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(limits);
        ArgumentNullException.ThrowIfNull(pool);

        //The archive is read into a result this method owns until the facts take the container over; the local is
        //nulled out at exactly that point, so the finally releases it on every path that did not transfer it.
        AsicZipReadResult? read = AsicZipReading.Read(containerBytes, limits, pool);
        try
        {
            return StateFacts(read);
        }
        finally
        {
            read?.Dispose();
        }

        AsicContainerReadResult StateFacts(AsicZipReadResult result)
        {
            if(!result.IsRead || result.Container is null)
            {
                return new AsicContainerReadResult
                {
                    Status = result.Status,
                    RejectedEntryName = result.RejectedEntryName,
                    RejectedEntryNameStatus = result.RejectedEntryNameStatus
                };
            }

            AsicContainerReadResult facts = BuildFacts(result.Container);
            read = null;

            return facts;
        }
    }


    /// <summary>
    /// Sorts a read archive's entries into the classes clauses 4.3.3.2 and 4.4.4.2 give a meaning to, and states
    /// the container's shape and profile.
    /// </summary>
    /// <param name="container">The archive, whose ownership transfers to the returned facts.</param>
    /// <returns>The facts, wrapped in a successful result.</returns>
    private static AsicContainerReadResult BuildFacts(AsicZipContainer container)
    {
        var dataObjects = new List<AsicZipEntry>();
        var manifests = new List<AsicManifestFile>();
        var signatures = new List<AsicZipEntry>();
        var timeAssertions = new List<AsicZipEntry>();
        var evidenceRecords = new List<AsicEvidenceRecordFile>();
        AsicZipEntry? fixedArchiveManifest = null;

        for(int i = 0; i < container.Entries.Count; ++i)
        {
            AsicZipEntry entry = container.Entries[i];
            if(entry.IsFolder || AsicWellKnown.IsMimetypeEntryName(entry.Name))
            {
                continue;
            }

            if(!entry.IsMetaInf)
            {
                //Clause 4.4.2 item 2: every data file object lives outside META-INF, in any folder structure.
                dataObjects.Add(entry);

                continue;
            }

            AsicManifestRole role = AsicManifestNaming.RoleFromEntryName(entry.Name);
            if(role is AsicManifestRole.Signature or AsicManifestRole.Archive or AsicManifestRole.EvidenceRecord or AsicManifestRole.Ambiguous)
            {
                manifests.Add(new AsicManifestFile { Entry = entry, Role = role });
                if(role == AsicManifestRole.Archive
                    && string.Equals(entry.Name, AsicManifestNaming.FixedArchiveManifestEntryName, StringComparison.Ordinal))
                {
                    fixedArchiveManifest = entry;
                }

                continue;
            }

            if(AsicManifestNaming.IsSignatureEntryName(entry.Name))
            {
                signatures.Add(entry);

                continue;
            }

            if(AsicManifestNaming.IsTimestampEntryName(entry.Name))
            {
                timeAssertions.Add(entry);

                continue;
            }

            if(AsicManifestNaming.IsBinaryEvidenceRecordEntryName(entry.Name))
            {
                evidenceRecords.Add(new AsicEvidenceRecordFile { Entry = entry, Form = AsicEvidenceRecordForm.Binary });

                continue;
            }

            if(AsicManifestNaming.IsXmlEvidenceRecordEntryName(entry.Name))
            {
                evidenceRecords.Add(new AsicEvidenceRecordFile { Entry = entry, Form = AsicEvidenceRecordForm.Xml });
            }

            //Anything else inside META-INF is the "any other file object" of clause 4.4.3.2 item 5 d), which
            //carries no obligation for a validator and is deliberately not classified.
        }

        AsicContainerShape shape = StateShape(container.MediaType, manifests, dataObjects);

        return new AsicContainerReadResult
        {
            Status = AsicZipReadStatus.Read,
            Facts = new AsicContainerFacts
            {
                Container = container,
                Shape = shape,
                Profile = StateProfile(shape, manifests, signatures, timeAssertions, evidenceRecords),
                MediaType = container.MediaType,
                MediaTypeReadableAtOffset38 = container.MediaTypeReadableAtOffset38,
                DataObjects = dataObjects,
                Manifests = manifests,
                Signatures = signatures,
                TimeAssertions = timeAssertions,
                EvidenceRecords = evidenceRecords,
                FixedArchiveManifest = fixedArchiveManifest
            }
        };
    }


    /// <summary>
    /// States which of the two container shapes of clause 4.1.2 a container has.
    /// </summary>
    /// <param name="mediaType">The media type the <c>mimetype</c> entry states, when it carries one.</param>
    /// <param name="manifests">The manifest files the container carries.</param>
    /// <param name="dataObjects">The data file objects the container carries.</param>
    /// <returns>The shape, or <see cref="AsicContainerShape.NotEvaluated"/> when neither the declaration nor the layout states one.</returns>
    /// <remarks>
    /// The container's own declaration decides where it makes one: clauses 4.3.3.1 item 1 and 4.4.4.1 item 2 fix
    /// the two registered media types, and a container stating one has said which shape it is. Where the
    /// <c>mimetype</c> entry is absent — which clauses 4.3.3.2 item 1 and 4.4.4.2 item 1 both admit — the layout
    /// answers instead: a manifest file is an ASiC-E construct (clause 4.4.4.2 item 2), and exactly one data file
    /// at the root with no manifest is the ASiC-S shape of clause 4.3.3.2 item 3.
    /// </remarks>
    private static AsicContainerShape StateShape(
        string? mediaType,
        List<AsicManifestFile> manifests,
        List<AsicZipEntry> dataObjects)
    {
        if(AsicWellKnown.IsAsicSimpleMediaType(mediaType))
        {
            return AsicContainerShape.Simple;
        }

        if(AsicWellKnown.IsAsicExtendedMediaType(mediaType))
        {
            return AsicContainerShape.Extended;
        }

        if(manifests.Count > 0 || dataObjects.Count > 1)
        {
            return AsicContainerShape.Extended;
        }

        return dataObjects.Count == 1 ? AsicContainerShape.Simple : AsicContainerShape.NotEvaluated;
    }


    /// <summary>
    /// States which named profile a container's file objects put it in.
    /// </summary>
    /// <param name="shape">The container's shape.</param>
    /// <param name="manifests">The manifest files the container carries.</param>
    /// <param name="signatures">The CAdES objects the container carries.</param>
    /// <param name="timeAssertions">The time assertions the container carries.</param>
    /// <param name="evidenceRecords">The Evidence Records the container carries.</param>
    /// <returns>The profile, or <see cref="AsicContainerProfile.NotEvaluated"/> when the container carries no protective object at all.</returns>
    /// <remarks>
    /// <para>
    /// The three profiles of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916202/01.01.01_60/en_31916202v010101p.pdf">
    /// ETSI EN 319 162-2 V1.1.1</see> each pick one branch of Part 1's options — clause 4.2.1 the ASiC-S time
    /// assertion, clause 4.3.1 the ASiC-E <c>*signature*.p7s</c> branch, clause 4.3.2 the ASiC-E time-assertion
    /// and Evidence Record branches — so which protective objects a container carries is what states its profile.
    /// A container carrying branches two profiles keep apart is Part 1's own clause 4.4.4.2 NOTE 1 container and
    /// conforms to neither, which is <see cref="AsicContainerProfile.ExtendedGeneral"/>.
    /// </para>
    /// <para>
    /// <strong>The archive-manifest chain is not counted, and that rule is this wave's.</strong> Annex A.7's
    /// chain adds one <c>*timestamp*.tst</c> per <c>*ASiCArchiveManifest*.xml</c> to a container of any profile,
    /// because clause 4.4.5 item 2 a) offers it as the container-level long-term mechanism for ASiC-E containers
    /// with CAdES signatures. Counting those tokens as time assertions would report every long-term ASiC-E CAdES
    /// container as the mixed container of NOTE 1. The tokens the chain accounts for are therefore subtracted;
    /// which token belongs to which manifest is stated by the manifests themselves, and
    /// <see cref="AsicContainerValidation"/> — which parses them — reports that authoritatively.
    /// </para>
    /// </remarks>
    private static AsicContainerProfile StateProfile(
        AsicContainerShape shape,
        List<AsicManifestFile> manifests,
        List<AsicZipEntry> signatures,
        List<AsicZipEntry> timeAssertions,
        List<AsicEvidenceRecordFile> evidenceRecords)
    {
        int archiveManifests = 0;
        for(int i = 0; i < manifests.Count; ++i)
        {
            archiveManifests += manifests[i].Role == AsicManifestRole.Archive ? 1 : 0;
        }

        int standaloneTimeAssertions = Math.Max(timeAssertions.Count - archiveManifests, 0);
        bool hasTimeAssertionMaterial = standaloneTimeAssertions > 0 || evidenceRecords.Count > 0;

        return shape switch
        {
            AsicContainerShape.Simple when signatures.Count > 0 && !hasTimeAssertionMaterial => AsicContainerProfile.SimpleBaselineCAdES,
            AsicContainerShape.Simple when signatures.Count == 0 && hasTimeAssertionMaterial => AsicContainerProfile.SimpleTimeAssertion,
            AsicContainerShape.Simple => AsicContainerProfile.NotEvaluated,
            AsicContainerShape.Extended when signatures.Count > 0 && !hasTimeAssertionMaterial => AsicContainerProfile.ExtendedCAdES,
            AsicContainerShape.Extended when signatures.Count == 0 && hasTimeAssertionMaterial => AsicContainerProfile.ExtendedTimeAssertion,
            AsicContainerShape.Extended when signatures.Count > 0 && hasTimeAssertionMaterial => AsicContainerProfile.ExtendedGeneral,
            _ => AsicContainerProfile.NotEvaluated
        };
    }
}
