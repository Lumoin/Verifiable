using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Which of the two container shapes an Associated Signature Container has.
/// </summary>
/// <remarks>
/// <para>
/// Clause 4.1.2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> defines exactly two: ASiC-S, which carries one data file at the container
/// root and one signature or time assertion beside it in <c>META-INF</c>, and ASiC-E, which carries one or
/// more data files in any folder structure outside <c>META-INF</c> and associates them with signatures or
/// time assertions through manifest files.
/// </para>
/// <para>
/// The names follow <see cref="AsicWellKnown.AsicSimpleMediaType"/> and
/// <see cref="AsicWellKnown.AsicExtendedMediaType"/>, which are already this library's words for the two.
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised field never reads as a container shape.
/// </para>
/// </remarks>
public enum AsicContainerShape
{
    /// <summary>No shape stated. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>ASiC-S (clause 4.3): one data file at the container root, one signature or time assertion in <c>META-INF</c>.</summary>
    Simple = 1,

    /// <summary>ASiC-E (clause 4.4): one or more data files outside <c>META-INF</c>, associated through manifest files.</summary>
    Extended = 2
}


/// <summary>
/// Which named profile a container conforms to — the statement a producer makes about what it built and a
/// validator checks a container against.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The profiles are disjoint by construction, and a container claims at most one.</strong>
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916202/01.01.01_60/en_31916202v010101p.pdf">
/// ETSI EN 319 162-2 V1.1.1</see> defines three of them, and each narrows one of Part 1's own container types
/// by picking one branch of its options: clause 4.2.1 pins ASiC-S to a time assertion and excludes the
/// signature branches, clause 4.3.1 pins ASiC-E to the <c>*signature*.p7s</c> branch of clause 4.4.4.2 item 3,
/// and clause 4.3.2 pins ASiC-E to the <c>*timestamp*.tst</c> branch or either Evidence Record branch. Part 1's
/// clause 4.4.4.2 NOTE 1 states that a container "can contain a mix of CAdES signatures, time-stamp tokens and
/// evidence records"; such a container is Part 1 conformant and conforms to no Part 2 profile, which is what
/// <see cref="ExtendedGeneral"/> states.
/// </para>
/// <para>
/// <see cref="SimpleBaselineCAdES"/> is Part 1's own, not Part 2's: clause 5.3.2.2's Table 3 is the baseline
/// requirement table for ASiC-S with a CAdES signature, and Part 2 defines no profile for that combination.
/// Part 1 clause 5 defines no baseline table for ASiC-E with CAdES at all — clause 5.1 scopes the baseline
/// levels to ASiC-S-CAdES, ASiC-S-XAdES and ASiC-E-XAdES — so <see cref="ExtendedCAdES"/> names Part 2 clause
/// 4.3.1's additional container rather than a baseline.
/// </para>
/// <para>
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised field never reads as a conformance claim.
/// </para>
/// </remarks>
public enum AsicContainerProfile
{
    /// <summary>No profile stated. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>
    /// ASiC-S carrying <c>META-INF/signature.p7s</c> — the baseline container of Part 1 clause 5.3.2.2
    /// (Table 3), whose closed set is the optional <c>mimetype</c> entry, one data file and that signature.
    /// </summary>
    SimpleBaselineCAdES = 1,

    /// <summary>
    /// The ASiC-S time assertion additional container of Part 2 clause 4.2.1: one data file and one of
    /// <c>META-INF/timestamp.tst</c>, <c>META-INF/evidencerecord.ers</c> or
    /// <c>META-INF/evidencerecord.xml</c>, with the signature branches excluded.
    /// </summary>
    SimpleTimeAssertion = 2,

    /// <summary>
    /// The ASiC-E CAdES additional container of Part 2 clause 4.3.1: every <c>ASiCManifest</c> file protected
    /// by a <c>META-INF/*signature*.p7s</c> CAdES object, with the bare time-stamp branch excluded.
    /// </summary>
    ExtendedCAdES = 3,

    /// <summary>
    /// The ASiC-E time assertion additional container of Part 2 clause 4.3.2: every manifest file protected by
    /// a <c>META-INF/*timestamp*.tst</c> token or naming a <c>META-INF/*evidencerecord*.ers</c>/<c>.xml</c>
    /// Evidence Record, with the CAdES signature branch excluded.
    /// </summary>
    ExtendedTimeAssertion = 4,

    /// <summary>
    /// An ASiC-E container conformant to Part 1 clause 4.4.4 that mixes branches Part 2's two ASiC-E profiles
    /// keep apart, so it conforms to neither of them individually. Part 1 clause 4.4.4.2 NOTE 1 admits exactly
    /// this container; nothing about it is defective, and stating the fact is what keeps a conformance claim
    /// honest.
    /// </summary>
    ExtendedGeneral = 5
}


/// <summary>
/// One file object a container is created around: the entry it becomes, the media type a manifest states for
/// it, and the two qualifiers Annex A.4.2's <c>DataObjectReferenceType</c> admits.
/// </summary>
/// <remarks>
/// <para>
/// This is the creation-side counterpart of <see cref="AsicDataObjectReference"/>: a caller supplies the
/// octets and the qualifiers, and the creation surface computes the digest through the registered seam and
/// writes both the entry and the reference. The digest is never a caller input, because a manifest whose
/// <c>ds:DigestValue</c> does not match the entry beside it is a container clause 4.4.4.2 item d makes an
/// unconditional error.
/// </para>
/// <para>
/// <see cref="Content"/> is a borrowed view of the caller's own memory; nothing here takes ownership.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record AsicDataObject
{
    /// <summary>
    /// Gets the container entry name the object is written under: root-relative, <c>/</c>-separated, and — for
    /// an ASiC-E container — outside the <c>META-INF</c> folder, which clause 4.4.2 item 2 requires of every
    /// data file.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>Gets the object's octets, as the container is to carry them and as the digest is computed over them.</summary>
    public required ReadOnlyMemory<byte> Content { get; init; }

    /// <summary>
    /// Gets the media type a manifest's <c>MimeType</c> attribute states for the object, which Annex A.4.1
    /// item 3 requires the element to "allow to indicate", or <see langword="null"/> to state none.
    /// </summary>
    /// <remarks>
    /// For an ASiC-S container the value has a second job: clause 4.3.3.1 item 1 b makes the container's own
    /// <c>mimetype</c> entry state "the media type associated to the signed file object" whenever the object
    /// has one, and item 1 a ii makes it <see cref="AsicWellKnown.AsicSimpleMediaType"/> when it has none.
    /// </remarks>
    public string? MediaType { get; init; }

    /// <summary>Gets how the entry's octets are stored; see <see cref="AsicZipEntrySource.CompressionMethod"/> for why storing is the default.</summary>
    public AsicZipCompressionMethod CompressionMethod { get; init; } = AsicZipCompressionMethod.Stored;

    /// <summary>
    /// Gets the <c>Rootfile</c> attribute a manifest states for the object, or <see langword="null"/> to state
    /// none — see <see cref="AsicDataObjectReference.IsRootFile"/> for the two unrelated meanings the
    /// attribute carries.
    /// </summary>
    public bool? IsRootFile { get; init; }

    /// <summary>
    /// Gets the instant the entry records, or <see langword="null"/> to record the container's own; see
    /// <see cref="AsicZipEntrySource.LastModified"/>.
    /// </summary>
    public DateTimeOffset? LastModified { get; init; }


    /// <summary>A short debugger string showing the object's name, size and media type.</summary>
    private string DebuggerDisplay => $"AsicDataObject({Name}, {Content.Length} bytes, {MediaType ?? "no media type"})";
}


/// <summary>
/// A container this library created: its octets, the conformance facts it was built to, and the names of the
/// entries a caller has to know about afterwards.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The octets are the container.</strong> <see cref="Container"/> holds the whole ZIP archive
/// <see cref="AsicZipAuthoring.Write"/> produced, tagged <see cref="AsicTags.Container"/>; the caller owns and
/// disposes it. <see cref="FileExtension"/> states the extension the file it is written to carries — clause
/// 4.3.3.1 item 2 a's <c>.asics</c> or clause 4.4.4.1 item 1 a's <c>.asice</c>, the two primary forms this
/// library writes.
/// </para>
/// <para>
/// The four entry-name properties are the ones a caller cannot rediscover without re-reading the container:
/// the names this library chose for the manifest, the CAdES object, the time-stamp token and the Evidence
/// Record. Each is <see langword="null"/> when the container carries no file of that kind.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class AsicContainerCreationResult: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>Gets the container's octets, tagged <see cref="AsicTags.Container"/>. Owned by this instance.</summary>
    public required PooledMemory Container { get; init; }

    /// <summary>Gets which of the two container shapes was built.</summary>
    public required AsicContainerShape Shape { get; init; }

    /// <summary>Gets the profile the container conforms to.</summary>
    public required AsicContainerProfile Profile { get; init; }

    /// <summary>Gets the media type the container's <c>mimetype</c> entry states.</summary>
    public required string MediaType { get; init; }

    /// <summary>Gets the file extension the container is written under, including its leading dot.</summary>
    public required string FileExtension { get; init; }

    /// <summary>Gets every entry name the container carries, in the order they were written — the <c>mimetype</c> entry first.</summary>
    public required IReadOnlyList<string> EntryNames { get; init; }

    /// <summary>Gets the name of the manifest file, or <see langword="null"/> when the container carries none (every ASiC-S container).</summary>
    public string? ManifestEntryName { get; init; }

    /// <summary>Gets the name of the CAdES object, or <see langword="null"/> when the container carries none.</summary>
    public string? SignatureEntryName { get; init; }

    /// <summary>Gets the name of the time-stamp token, or <see langword="null"/> when the container carries none.</summary>
    public string? TimestampEntryName { get; init; }

    /// <summary>Gets the name of the Evidence Record, or <see langword="null"/> when the container carries none.</summary>
    public string? EvidenceRecordEntryName { get; init; }

    /// <summary>
    /// Gets the <c>genTime</c> the acquired time-stamp token asserts, or <see langword="null"/> when the
    /// container carries no time-stamp token of its own.
    /// </summary>
    /// <remarks>
    /// A container carrying an Evidence Record has a time-stamp token too, inside that record; the instant it
    /// asserts is <see cref="EvidenceRecordArchiveTime"/> and not this, because the two are reached by
    /// completely different verification paths and a caller that confused them would state a proof of existence
    /// it cannot show.
    /// </remarks>
    public DateTimeOffset? TimestampTime { get; init; }

    /// <summary>
    /// Gets the instant the Evidence Record's initial Archive Timestamp asserts, or <see langword="null"/> when
    /// the container carries no Evidence Record.
    /// </summary>
    public DateTimeOffset? EvidenceRecordArchiveTime { get; init; }


    /// <summary>Disposes <see cref="Container"/>.</summary>
    public void Dispose()
    {
        if(!disposed)
        {
            Container.Dispose();
            disposed = true;
        }
    }


    /// <summary>A short debugger string showing the profile, the container's size and how many entries it carries.</summary>
    private string DebuggerDisplay => $"AsicContainerCreationResult({Profile}, {Container.Length} bytes, {EntryNames.Count} entries)";
}
