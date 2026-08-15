using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Names why a container could not be created.
/// </summary>
/// <remarks>
/// These are generator-side faults in the same sense as <see cref="AsicZipAuthoringFailureKind"/> and
/// <see cref="AsicManifestNamingFailureKind"/>: material the caller supplied that no conformant container can be
/// built from. They are deliberately not <see cref="AsicZipReadStatus"/>, which describes what a reader concludes
/// about a container it did not make.
/// </remarks>
public enum AsicContainerCreationFailureKind
{
    /// <summary>No failure has been classified.</summary>
    NotEvaluated = 0,

    /// <summary>
    /// No data object was supplied. Clause 4.3.3.2 item 2 requires one data file for ASiC-S and clause 4.4.2
    /// item 2 requires "one or more data files" for ASiC-E, so a container holding only metadata is neither.
    /// </summary>
    NoDataObject = 1,

    /// <summary>
    /// More than one data object was supplied for an ASiC-S container. Clause 4.3.3.2 item 2: "Shall contain one
    /// data file at the root level. It shall be the only file object present at the container root level besides
    /// the optional "mimetype"".
    /// </summary>
    SimpleContainerNotSingleDataObject = 2,

    /// <summary>
    /// A data object name is not a name a container may carry; the message names it and the
    /// <see cref="AsicZipEntryNameStatus"/> that refused it.
    /// </summary>
    DataObjectNameRejected = 3,

    /// <summary>Two data objects carry the same name, so the container would name one file object twice.</summary>
    DuplicateDataObjectName = 4,

    /// <summary>
    /// A data object is named inside the <c>META-INF</c> folder, which clause 4.4.2 item 2 forbids: the signed or
    /// time-asserted data files sit "in any folder structure outside the root META-INF folder".
    /// </summary>
    DataObjectInMetaInf = 5,

    /// <summary>
    /// An ASiC-S data object is not at the container root level, which clause 4.3.3.2 item 2 requires, or it is
    /// named <c>mimetype</c>, which Annex A.1 reserves for the media type entry.
    /// </summary>
    DataObjectNotAtContainerRoot = 6,

    /// <summary>
    /// A digest algorithm this surface will not create a container under was stated: MD5 (clause 5.2.1: "MD5
    /// algorithm shall not be used as digest algorithm"), SHA-1, an algorithm the library does not compute, or one
    /// a supplied <see cref="CryptographicConstraints"/> table does not assert reliable at the stated instant.
    /// </summary>
    DigestAlgorithmRefused = 7,

    /// <summary>
    /// An ASiC-E container was asked for and no <see cref="EncodeAsicManifestDelegate"/> was supplied. Clause
    /// 4.4.4.2 item 2 makes a manifest file mandatory for the shape, and this library ships no XML implementation
    /// of the seam that writes one.
    /// </summary>
    ManifestEncoderMissing = 8,

    /// <summary>
    /// The supplied <see cref="EncodeAsicManifestDelegate"/> did not produce a document; the message carries the
    /// <see cref="AsicManifestEncodeStatus"/> and the reason it stated.
    /// </summary>
    ManifestEncodingFailed = 9,

    /// <summary>
    /// A name this library has to write is already taken by a data object — the collision refusal the
    /// "avoiding any name collision with other elements already present in the container" mandate of clause
    /// 4.4.4.2 and Annex A.7 requires, applied to the fixed ASiC-S names that carry no numeric suffix.
    /// </summary>
    EntryNameCollision = 10,

    /// <summary>
    /// The Evidence Record creation produced no record for the data object group, which cannot happen for a
    /// group this surface built and is refused rather than indexed into.
    /// </summary>
    EvidenceRecordNotProduced = 11
}


/// <summary>
/// The generator-side fault of creating an Associated Signature Container.
/// </summary>
/// <remarks>
/// Creation reports faults as exceptions, following <see cref="AsicZipAuthoringException"/>,
/// <see cref="AsicManifestNamingException"/> and the CAdES and Evidence Record creation surfaces: a generator
/// handing in material a container cannot be built from is a composition fault of the caller rather than an
/// adversarial input to be classified and reported. Faults that belong to a layer below stay that layer's:
/// a digest algorithm the CAdES signer's own profile does not use is refused by
/// <see cref="CAdESSignatureCreation"/>, and a Time-Stamping Authority answering something unverifiable is
/// refused by <see cref="TimestampAcquisition"/>.
/// </remarks>
[DebuggerDisplay("AsicContainerCreationException({FailureKind}): {Message}")]
public sealed class AsicContainerCreationException: Exception
{
    /// <summary>Gets what could not be done.</summary>
    public AsicContainerCreationFailureKind FailureKind { get; }


    /// <summary>Initializes a new <see cref="AsicContainerCreationException"/> with an unclassified fault.</summary>
    public AsicContainerCreationException(): this(AsicContainerCreationFailureKind.NoDataObject, "The container could not be created.")
    {
    }


    /// <summary>Initializes a new <see cref="AsicContainerCreationException"/> with an unclassified fault.</summary>
    /// <param name="message">The message describing the fault.</param>
    public AsicContainerCreationException(string message): this(AsicContainerCreationFailureKind.NoDataObject, message)
    {
    }


    /// <summary>Initializes a new <see cref="AsicContainerCreationException"/> with an unclassified fault.</summary>
    /// <param name="message">The message describing the fault.</param>
    /// <param name="innerException">The exception that caused it.</param>
    public AsicContainerCreationException(string message, Exception innerException)
        : this(AsicContainerCreationFailureKind.NoDataObject, message, innerException)
    {
    }


    /// <summary>Initializes a new <see cref="AsicContainerCreationException"/>.</summary>
    /// <param name="failureKind">What could not be done.</param>
    /// <param name="message">The message describing the fault.</param>
    public AsicContainerCreationException(AsicContainerCreationFailureKind failureKind, string message): base(message)
    {
        FailureKind = failureKind;
    }


    /// <summary>Initializes a new <see cref="AsicContainerCreationException"/>.</summary>
    /// <param name="failureKind">What could not be done.</param>
    /// <param name="message">The message describing the fault.</param>
    /// <param name="innerException">The exception that caused it.</param>
    public AsicContainerCreationException(AsicContainerCreationFailureKind failureKind, string message, Exception innerException)
        : base(message, innerException)
    {
        FailureKind = failureKind;
    }
}


/// <summary>
/// Everything a CAdES-protected container is built from: which shape, the data objects, the signer, and the
/// serialisation seam the manifest reaches the container through.
/// </summary>
/// <remarks>
/// <para>
/// The two shapes it builds are the two the specification defines for a CAdES object: ASiC-S with
/// <c>META-INF/signature.p7s</c> over the single data file (clause 4.3.3.2 item 4 b, the baseline container of
/// clause 5.3.2.2), and ASiC-E with an <c>ASiCManifest</c> file protected by a
/// <c>META-INF/*signature*.p7s</c> CAdES object (clause 4.4.4.2 item 3 a, the additional container of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916202/01.01.01_60/en_31916202v010101p.pdf">
/// ETSI EN 319 162-2 V1.1.1</see> clause 4.3.1).
/// </para>
/// <para>
/// <strong>Nothing here is ambient.</strong> The instants are the caller's, the digest reaches the registered
/// seam, and the manifest reaches XML through a delegate carried in this record rather than captured by one —
/// the no-closure-capture discipline every context record of this namespace applies.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record AsicContainerSignatureContext
{
    /// <summary>Gets which of the two container shapes to build (clause 4.1.2).</summary>
    public required AsicContainerShape Shape { get; init; }

    /// <summary>
    /// Gets the data objects the container carries. Exactly one for
    /// <see cref="AsicContainerShape.Simple"/> (clause 4.3.3.2 item 2); one or more for
    /// <see cref="AsicContainerShape.Extended"/> (clause 4.4.2 item 2).
    /// </summary>
    public required IReadOnlyList<AsicDataObject> DataObjects { get; init; }

    /// <summary>Gets the signer's certificate. The caller retains ownership.</summary>
    public required PkiCertificateMemory SignerCertificate { get; init; }

    /// <summary>
    /// Gets the <c>signing-time</c> attribute value, which is also the instant a supplied
    /// <see cref="AlgorithmConstraints"/> table is assessed at.
    /// </summary>
    public required DateTimeOffset SigningTime { get; init; }

    /// <summary>Gets the instant every container entry records; see <see cref="AsicZipAuthoringContext.LastModified"/>.</summary>
    public required DateTimeOffset LastModified { get; init; }

    /// <summary>
    /// Gets the algorithm every <c>ds:DigestMethod</c> of the manifest names and every
    /// <c>ds:DigestValue</c> is computed under. Unused for <see cref="AsicContainerShape.Simple"/>, which
    /// carries no manifest.
    /// </summary>
    public PkiDigestAlgorithm ManifestDigestAlgorithm { get; init; } = PkiDigestAlgorithm.Sha256;

    /// <summary>
    /// Gets the algorithm the detached CAdES signature's <c>message-digest</c> attribute is computed under.
    /// </summary>
    /// <remarks>
    /// It has to be the digest the signer's own algorithm profile uses, because
    /// <see cref="CAdESSignatureCreation"/> owns that table and refuses a preparation that disagrees with it.
    /// SHA-256 is the default because it is what the P-256 and RSA profiles use.
    /// </remarks>
    public PkiDigestAlgorithm SignatureDigestAlgorithm { get; init; } = PkiDigestAlgorithm.Sha256;

    /// <summary>Gets a caller-supplied dated cryptographic-constraints table, or <see langword="null"/> to apply only the hard MD5/SHA-1 refusals.</summary>
    public CryptographicConstraints? AlgorithmConstraints { get; init; }

    /// <summary>
    /// Gets the seam the <c>ASiCManifest</c> document is written through. Required for
    /// <see cref="AsicContainerShape.Extended"/>; ignored for <see cref="AsicContainerShape.Simple"/>, which
    /// carries no manifest.
    /// </summary>
    public EncodeAsicManifestDelegate? EncodeManifest { get; init; }

    /// <summary>
    /// Gets the <c>MimeType</c> attribute the manifest's <c>SigReference</c> states for the CAdES object, or
    /// <see langword="null"/> to state none. Annex A.4.2 calls the attribute descriptive; nothing is validated
    /// against it.
    /// </summary>
    public string? SignatureReferenceMediaType { get; init; }

    /// <summary>
    /// Gets whether the ZIP archive comment states the container's media type, which clauses 4.3.3.1 item 3 and
    /// 4.4.4.1 item 3 admit ("may"). Absent by default, the conformant reading of a permission.
    /// </summary>
    public bool StateMediaTypeArchiveComment { get; init; }

    /// <summary>
    /// Gets whether the signature carries the opt-in <c>cms-algorithm-protection</c> attribute
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6211">IETF RFC 6211</see>). Read by
    /// <see cref="AsicContainerCreation.SignAsync"/> only, which is where the signing algorithm — and therefore
    /// the identifier the attribute names — is known; the three-phase path states it as
    /// <see cref="CmsAlgorithmProtectionSignatureAlgorithmOid"/> instead, mirroring
    /// <see cref="CAdESSignatureCreation.PrepareAsync"/>.
    /// </summary>
    public bool IncludeCmsAlgorithmProtection { get; init; }

    /// <summary>
    /// Gets the signature algorithm identifier the opt-in <c>cms-algorithm-protection</c> attribute names, or
    /// <see langword="null"/> to carry no such attribute. Read by
    /// <see cref="AsicContainerCreation.PrepareSignatureAsync"/> only; a remote signer's algorithm is the
    /// caller's knowledge, not this library's.
    /// </summary>
    public string? CmsAlgorithmProtectionSignatureAlgorithmOid { get; init; }

    /// <summary>Gets the optional clause 6.3 signed attributes the CAdES object carries, or <see langword="null"/> to carry none.</summary>
    public CAdESOptionalSignedAttributes? OptionalSignedAttributes { get; init; }

    /// <summary>
    /// Gets certificates placed in the CAdES object's own certificate set, or <see langword="null"/> to place
    /// none beyond the signer's. Read by <see cref="AsicContainerCreation.SignAsync"/>; the three-phase path
    /// takes them at <see cref="AsicContainerCreation.CompleteSignature"/>, where
    /// <see cref="CAdESSignatureCreation.Complete"/> takes them.
    /// </summary>
    public IReadOnlyList<PkiCertificateMemory>? AdditionalCertificates { get; init; }


    /// <summary>A short debugger string showing the shape and how many data objects the container carries.</summary>
    private string DebuggerDisplay => $"AsicContainerSignatureContext({Shape}, {DataObjects.Count} data objects)";
}


/// <summary>
/// Everything a time-assertion container is built from: which shape, the data objects, the Time-Stamping
/// Authority seam, and the serialisation seam the manifest reaches the container through.
/// </summary>
/// <remarks>
/// The two shapes it builds are the ASiC-S time assertion additional container of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916202/01.01.01_60/en_31916202v010101p.pdf">
/// ETSI EN 319 162-2 V1.1.1</see> clause 4.2.1 (<c>META-INF/timestamp.tst</c> applying to the data file, Part 1
/// clause 4.3.3.2 item 4 a) and the ASiC-E time assertion additional container of clause 4.3.2
/// (<c>META-INF/*timestamp*.tst</c> applying to an <c>ASiCManifest</c> file, Part 1 clause 4.4.4.2 item 3 b).
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record AsicContainerTimeAssertionContext
{
    /// <summary>Gets which of the two container shapes to build (clause 4.1.2).</summary>
    public required AsicContainerShape Shape { get; init; }

    /// <summary>Gets the data objects the container carries; exactly one for <see cref="AsicContainerShape.Simple"/>.</summary>
    public required IReadOnlyList<AsicDataObject> DataObjects { get; init; }

    /// <summary>Gets the instant every container entry records, and the instant a supplied <see cref="AlgorithmConstraints"/> table is assessed at.</summary>
    public required DateTimeOffset LastModified { get; init; }

    /// <summary>Gets the Time-Stamping Authority to contact, in whatever form the transport delegate understands.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "Forwarded verbatim into TimestampFetchContext.TsaUri, which is deliberately a string for the reason that property gives: the transport delegate owns URI parsing and scheme policy.")]
    public required string TsaUri { get; init; }

    /// <summary>Gets the transport that carries the time-stamp request to the authority and its response back.</summary>
    public required FetchTimestampResponseAsyncDelegate FetchTimestampResponse { get; init; }

    /// <summary>Gets the algorithm the token's <c>messageImprint</c> is computed under.</summary>
    public PkiDigestAlgorithm ImprintAlgorithm { get; init; } = PkiDigestAlgorithm.Sha256;

    /// <summary>Gets the algorithm every <c>ds:DigestMethod</c> of the manifest names; unused for <see cref="AsicContainerShape.Simple"/>.</summary>
    public PkiDigestAlgorithm ManifestDigestAlgorithm { get; init; } = PkiDigestAlgorithm.Sha256;

    /// <summary>Gets a caller-supplied dated cryptographic-constraints table, or <see langword="null"/> to apply only the hard MD5/SHA-1 refusals.</summary>
    public CryptographicConstraints? AlgorithmConstraints { get; init; }

    /// <summary>Gets the seam the <c>ASiCManifest</c> document is written through. Required for <see cref="AsicContainerShape.Extended"/>.</summary>
    public EncodeAsicManifestDelegate? EncodeManifest { get; init; }

    /// <summary>
    /// Gets the <c>MimeType</c> attribute the manifest's <c>SigReference</c> states for the token, or
    /// <see langword="null"/> to state none. Annex A.2 NOTE 2 names a registered media type for a time-stamp
    /// token, which is defined by a document outside this one; the value is descriptive and is never validated.
    /// </summary>
    public string? TimestampReferenceMediaType { get; init; }

    /// <summary>Gets whether the ZIP archive comment states the container's media type (clauses 4.3.3.1 item 3 and 4.4.4.1 item 3, "may").</summary>
    public bool StateMediaTypeArchiveComment { get; init; }

    /// <summary>Gets the Time-Stamping Authority policy the request asks for, or <see langword="null"/> to ask for none.</summary>
    public string? TimestampPolicyOid { get; init; }


    /// <summary>A short debugger string showing the shape and how many data objects the container carries.</summary>
    private string DebuggerDisplay => $"AsicContainerTimeAssertionContext({Shape}, {DataObjects.Count} data objects)";
}


/// <summary>
/// Everything an Evidence Record container is built from: which shape, the data objects the record archives, and
/// the Time-Stamping Authority the record's initial Archive Timestamp is taken from.
/// </summary>
/// <remarks>
/// <para>
/// The record is the RFC 4998 form throughout — <c>META-INF/evidencerecord.ers</c> for ASiC-S (Part 1 clause
/// 4.3.3.2 item 4 d) and <c>META-INF/*evidencerecord*.ers</c> beside an <c>ASiCEvidenceRecordManifest</c> file
/// for ASiC-E (clause 4.4.4.2 item 4 a). The XML form of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283">IETF RFC 6283</see> is not produced by this library.
/// </para>
/// <para>
/// <strong>The record covers the data objects, not the manifest.</strong> The clause 4.4.4.2 NOTE 2 states it
/// outright: "In case the URI attribute of SigReference in the ASiCManifest file references an ER the
/// ASiCManifest file itself is not covered by the ER." The record is therefore built before the manifest exists,
/// over exactly the file objects the manifest's <c>DataObjectReference</c> elements go on to name — which is
/// clause 4.4.3.2 item 4 b's "apply to all the container files referenced by ASiCManifest".
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record AsicContainerEvidenceRecordContext
{
    /// <summary>Gets which of the two container shapes to build (clause 4.1.2).</summary>
    public required AsicContainerShape Shape { get; init; }

    /// <summary>Gets the data objects the record archives and the container carries; exactly one for <see cref="AsicContainerShape.Simple"/>.</summary>
    public required IReadOnlyList<AsicDataObject> DataObjects { get; init; }

    /// <summary>Gets the instant every container entry records, and the instant a supplied <see cref="AlgorithmConstraints"/> table is assessed at.</summary>
    public required DateTimeOffset LastModified { get; init; }

    /// <summary>Gets the Time-Stamping Authority to contact, in whatever form the transport delegate understands.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "Forwarded verbatim into TimestampFetchContext.TsaUri, which is deliberately a string for the reason that property gives: the transport delegate owns URI parsing and scheme policy.")]
    public required string TsaUri { get; init; }

    /// <summary>Gets the transport that carries the time-stamp request to the authority and its response back.</summary>
    public required FetchTimestampResponseAsyncDelegate FetchTimestampResponse { get; init; }

    /// <summary>
    /// Gets the algorithm the record's hash tree is built under, which is also the algorithm every
    /// <c>ds:DigestMethod</c> of the <c>ASiCEvidenceRecordManifest</c> names.
    /// </summary>
    /// <remarks>
    /// Clause 4.4.3.2 item 4 binds the two together: the <c>ds:DigestMethod</c> element "shall match the digest
    /// algorithm used to create the initial Archive Time-stamp protecting the first <c>ReducedHashTree</c>". One
    /// property therefore states both, so the two cannot be given different values.
    /// </remarks>
    public PkiDigestAlgorithm DigestAlgorithm { get; init; } = PkiDigestAlgorithm.Sha256;

    /// <summary>Gets a caller-supplied dated cryptographic-constraints table, or <see langword="null"/> to apply only the hard MD5/SHA-1 refusals.</summary>
    public CryptographicConstraints? AlgorithmConstraints { get; init; }

    /// <summary>Gets the seam the <c>ASiCEvidenceRecordManifest</c> document is written through. Required for <see cref="AsicContainerShape.Extended"/>.</summary>
    public EncodeAsicManifestDelegate? EncodeManifest { get; init; }

    /// <summary>Gets the <c>MimeType</c> attribute the manifest's <c>SigReference</c> states for the record, or <see langword="null"/> to state none.</summary>
    public string? EvidenceRecordReferenceMediaType { get; init; }

    /// <summary>Gets whether the ZIP archive comment states the container's media type (clauses 4.3.3.1 item 3 and 4.4.4.1 item 3, "may").</summary>
    public bool StateMediaTypeArchiveComment { get; init; }

    /// <summary>Gets how many children an inner node of the record's hash tree is given; see <see cref="EvidenceRecordHashTreeBuildContext.NodeArity"/>.</summary>
    public int NodeArity { get; init; } = EvidenceRecordHashTree.DefaultNodeArity;

    /// <summary>Gets the Time-Stamping Authority policy the record's time-stamp request asks for, or <see langword="null"/> to ask for none.</summary>
    public string? TimestampPolicyOid { get; init; }


    /// <summary>A short debugger string showing the shape and how many data objects the record archives.</summary>
    private string DebuggerDisplay => $"AsicContainerEvidenceRecordContext({Shape}, {DataObjects.Count} data objects)";
}


/// <summary>
/// Everything the assembly of one container needs once the names are chosen and the manifest, if any, has been
/// written: the entries the data objects become, the manifest's octets, and the conformance facts the result
/// states.
/// </summary>
/// <remarks>
/// The plan is what makes the three-phase split possible without the phases having to agree on a parameter list:
/// phase one produces it, phase three consumes it, and the convenience one-shot path produces and consumes it in
/// one call. It is internal because it is a composition detail, and the octets it holds for the data objects are
/// borrowed views of the caller's own memory — only <see cref="ManifestDocument"/> is owned.
/// </remarks>
internal sealed class AsicContainerPlan: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>Gets which container shape is being built.</summary>
    public required AsicContainerShape Shape { get; init; }

    /// <summary>Gets the profile the finished container conforms to.</summary>
    public required AsicContainerProfile Profile { get; init; }

    /// <summary>Gets the media type the container's <c>mimetype</c> entry states.</summary>
    public required string MediaType { get; init; }

    /// <summary>Gets the file extension the container is written under.</summary>
    public required string FileExtension { get; init; }

    /// <summary>Gets the instant every entry records unless it states its own.</summary>
    public required DateTimeOffset LastModified { get; init; }

    /// <summary>Gets the ZIP archive comment, or <see langword="null"/> to write none.</summary>
    public string? ArchiveComment { get; init; }

    /// <summary>Gets the entries the data objects become, in the order they are written.</summary>
    public required IReadOnlyList<AsicZipEntrySource> DataObjectEntries { get; init; }

    /// <summary>Gets the manifest document's octets, or <see langword="null"/> for a container carrying no manifest. Owned by this instance.</summary>
    public PooledMemory? ManifestDocument { get; init; }

    /// <summary>Gets the entry name the manifest is stored under, or <see langword="null"/> when there is none.</summary>
    public string? ManifestEntryName { get; init; }

    /// <summary>Gets the entry name the CAdES object, time-stamp token or Evidence Record is stored under.</summary>
    public required string MetadataEntryName { get; init; }

    /// <summary>Gets which kind of file <see cref="MetadataEntryName"/> names.</summary>
    public required AsicContainerFileKind MetadataFileKind { get; init; }

    /// <summary>
    /// Gets the octets a CAdES object or a time-stamp token protects: the manifest's for an ASiC-E container
    /// (Annex A.4.1: the signature or token "shall apply to the file containing the <c>ASiCManifest</c>
    /// element"), the single data file's for an ASiC-S container, and empty for an Evidence Record container,
    /// whose record covers the data objects rather than the manifest (clause 4.4.4.2 NOTE 2). Borrowed.
    /// </summary>
    public ReadOnlyMemory<byte> ProtectedOctets { get; init; }


    /// <summary>Disposes <see cref="ManifestDocument"/>, the only carrier this plan owns.</summary>
    public void Dispose()
    {
        if(!disposed)
        {
            ManifestDocument?.Dispose();
            disposed = true;
        }
    }
}


/// <summary>
/// Phase one of the container signing split: the octets a signer signs, together with everything the container
/// is assembled from once the signature value comes back.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why the split reaches the container layer at all.</strong>
/// <see cref="CAdESSignatureCreation"/> splits signing into prepare/complete so that a signing key that lives
/// somewhere else — a remote signing service, a smart card, a hardware module — never has to be reachable from
/// the code that builds the signature. An ASiC-E container makes the same split necessary one layer up: the
/// octets to be signed are the <em>manifest file's</em>, and the manifest names the signature file it is
/// protected by (Annex A.4.1), so the entry names have to be chosen and the manifest written before anything can
/// be signed. This carrier is what lets those decisions be made once, survive the round trip to the signer, and
/// still produce a container whose manifest and signature agree.
/// </para>
/// <para>
/// <strong>What is owned and what is borrowed.</strong> This instance owns
/// <see cref="SignaturePreparation"/> and the manifest's octets, and disposing it disposes them. The data
/// objects' octets are borrowed views of the caller's own memory: they have to stay valid until
/// <see cref="AsicContainerCreation.CompleteSignature"/> has run.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class AsicContainerSignaturePreparation: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>
    /// Initialises a new preparation, taking ownership of both the plan and the CAdES preparation.
    /// </summary>
    /// <param name="plan">Everything the assembly needs. Ownership transfers to this instance.</param>
    /// <param name="signaturePreparation">The CAdES phase-one result. Ownership transfers to this instance.</param>
    internal AsicContainerSignaturePreparation(AsicContainerPlan plan, CAdESSignaturePreparation signaturePreparation)
    {
        Plan = plan;
        SignaturePreparation = signaturePreparation;
    }


    /// <summary>Gets everything the assembly needs once the signature value is known. Owned by this instance.</summary>
    internal AsicContainerPlan Plan { get; }

    /// <summary>Gets the CAdES phase-one result, whose <see cref="CAdESSignaturePreparation.SigningInput"/> is the octets a signer signs. Owned by this instance.</summary>
    public CAdESSignaturePreparation SignaturePreparation { get; }

    /// <summary>Gets which container shape is being built.</summary>
    public AsicContainerShape Shape => Plan.Shape;

    /// <summary>Gets the profile the finished container will conform to.</summary>
    public AsicContainerProfile Profile => Plan.Profile;

    /// <summary>
    /// Gets the manifest document's octets — the file object the CAdES signature protects — or
    /// <see langword="null"/> for an ASiC-S container, which carries no manifest. Owned by this instance.
    /// </summary>
    public PooledMemory? ManifestDocument => Plan.ManifestDocument;

    /// <summary>Gets the entry name the manifest is stored under, or <see langword="null"/> when there is none.</summary>
    public string? ManifestEntryName => Plan.ManifestEntryName;

    /// <summary>Gets the entry name the CAdES object is stored under, which the manifest's <c>SigReference</c> already names.</summary>
    public string SignatureEntryName => Plan.MetadataEntryName;


    /// <summary>Disposes the plan and the CAdES preparation.</summary>
    public void Dispose()
    {
        if(!disposed)
        {
            SignaturePreparation.Dispose();
            Plan.Dispose();
            disposed = true;
        }
    }


    /// <summary>A short debugger string showing the profile and what the signature will protect.</summary>
    private string DebuggerDisplay => $"AsicContainerSignaturePreparation({Profile}, protecting {ManifestEntryName ?? "the data file"})";
}


/// <summary>
/// Builds Associated Signature Containers: the ASiC-S and ASiC-E shapes of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> clauses 4.3 and 4.4, in the CAdES, time-assertion and Evidence Record
/// flavours the profiles of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916202/01.01.01_60/en_31916202v010101p.pdf">
/// ETSI EN 319 162-2 V1.1.1</see> clause 4 define.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This layer composes; it computes almost nothing of its own.</strong> The container's octets come from
/// <see cref="AsicZipAuthoring"/>, the manifest's from the <see cref="EncodeAsicManifestDelegate"/> seam, the
/// CAdES object from <see cref="CAdESSignatureCreation"/>, the time-stamp token from
/// <see cref="TimestampAcquisition"/> and the Evidence Record from <see cref="EvidenceRecords"/>. What is new
/// here is the composition itself: which entry names are chosen, which file object each protective object is
/// taken over, and which profile the finished container is entitled to claim.
/// </para>
/// <para>
/// <strong>One profile per container.</strong> Part 1 clause 4.4.4.2 NOTE 1 admits a container mixing CAdES
/// signatures, time-stamp tokens and Evidence Records, and such a container conforms to Part 1 while conforming
/// to neither Part 2 ASiC-E profile individually. This surface never builds one:
/// <see cref="AsicContainerProfile.ExtendedGeneral"/> is a fact a validator states about a container it was
/// handed, not a target a generator aims at.
/// </para>
/// <para>
/// <strong>Single-signer CAdES objects.</strong> Clause 4.4.4.2 item 3 a admits "one CAdES object including one
/// or more detached CAdES signatures"; this surface emits one signature per object. Adding a parallel
/// <c>SignerInfo</c> to an existing object is a CAdES-layer capability that does not exist yet; the reading side
/// handles several already.
/// </para>
/// <para>
/// <strong>Fail-closed.</strong> An empty container, an ASiC-S container with more than one data file, a data
/// object named inside <c>META-INF</c>, two data objects with one name, a name a container may not carry, a
/// digest algorithm clause 5.2.1 refuses or a supplied constraints table does not assert reliable, a missing
/// manifest seam and a seam that returns no document are each refused with an
/// <see cref="AsicContainerCreationException"/> before any octet is written. A Time-Stamping Authority answering
/// something that does not verify is refused by <see cref="TimestampAcquisition"/>, so an unverifiable token is
/// never written into a container.
/// </para>
/// </remarks>
public static class AsicContainerCreation
{
    /// <summary>The MD5 digest algorithm object identifier (<see href="https://www.rfc-editor.org/rfc/rfc1319">IETF RFC 1319</see>) — refused unconditionally, clause 5.2.1.</summary>
    private const string Md5Oid = "1.2.840.113549.2.5";


    /// <summary>
    /// Runs phase one of the container signing split: chooses the entry names, writes the manifest when the
    /// shape has one, and prepares the detached CAdES signature over the file object that shape protects.
    /// </summary>
    /// <param name="context">Everything the container is built from.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The preparation; its <see cref="AsicContainerSignaturePreparation.SignaturePreparation"/> carries the octets a signer signs. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="AsicContainerCreationException">When the supplied material is not a container this library builds.</exception>
    public static async ValueTask<AsicContainerSignaturePreparation> PrepareSignatureAsync(
        AsicContainerSignatureContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        AsicContainerPlan plan = await BuildSignaturePlanAsync(context, pool, cancellationToken).ConfigureAwait(false);
        try
        {
            using DigestValue protectedDigest = await CryptographicKeyEvents.ComputeDigestAsync(
                plan.ProtectedOctets, context.SignatureDigestAlgorithm.OutputByteLength, context.SignatureDigestAlgorithm.DigestTag, pool,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            CAdESSignaturePreparation signaturePreparation = await CAdESSignatureCreation.PrepareAsync(
                context.SignerCertificate,
                content: null,
                detachedContentDigest: protectedDigest.AsReadOnlyMemory(),
                context.SignatureDigestAlgorithm,
                context.SigningTime,
                context.AlgorithmConstraints,
                context.CmsAlgorithmProtectionSignatureAlgorithmOid,
                pool,
                cancellationToken,
                context.OptionalSignedAttributes).ConfigureAwait(false);

            return new AsicContainerSignaturePreparation(plan, signaturePreparation);
        }
        catch
        {
            plan.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Runs phase three of the container signing split: completes the detached CAdES signature from an
    /// externally produced signature value and writes the container.
    /// </summary>
    /// <param name="preparation">The phase-one result. The caller keeps ownership and disposes it.</param>
    /// <param name="signerCertificate">The signer's certificate; the same one phase one prepared against.</param>
    /// <param name="signingAlgorithm">The algorithm the signature value was produced with.</param>
    /// <param name="signatureValue">The externally produced signature value, in the wire form CAdES expects.</param>
    /// <param name="additionalCertificates">Certificates to place in the CAdES object's own certificate set, or <see langword="null"/> to place none.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <returns>The container. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="AsicZipAuthoringException">When the composed entries are not a container that can be written.</exception>
    public static AsicContainerCreationResult CompleteSignature(
        AsicContainerSignaturePreparation preparation,
        PkiCertificateMemory signerCertificate,
        CryptoAlgorithm signingAlgorithm,
        ReadOnlyMemory<byte> signatureValue,
        IReadOnlyList<PkiCertificateMemory>? additionalCertificates,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(preparation);
        ArgumentNullException.ThrowIfNull(signerCertificate);
        ArgumentNullException.ThrowIfNull(pool);

        using CmsSignedData signature = CAdESSignatureCreation.Complete(
            preparation.SignaturePreparation, signerCertificate, signingAlgorithm, signatureValue, additionalCertificates, pool);

        return Assemble(preparation.Plan, signature.AsReadOnlyMemory(), timestampTime: null, evidenceRecordArchiveTime: null, pool);
    }


    /// <summary>
    /// Builds a CAdES-protected container in one call, signing with a key this process holds.
    /// </summary>
    /// <param name="context">Everything the container is built from.</param>
    /// <param name="privateKey">The signing key; its <see cref="Tag"/> selects the registered signing function.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The container. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="AsicContainerCreationException">When the supplied material is not a container this library builds.</exception>
    /// <remarks>
    /// The signing itself goes through <see cref="CAdESSignatureCreation.SignAsync(PkiCertificateMemory, PrivateKeyMemory, ReadOnlyMemory{byte}?, ReadOnlyMemory{byte}?, DateTimeOffset, IReadOnlyList{PkiCertificateMemory}?, CryptographicConstraints?, bool, BaseMemoryPool, CancellationToken, CAdESOptionalSignedAttributes?)"/>,
    /// which owns the table mapping a signing algorithm to its digest and signature encodings. A
    /// <see cref="AsicContainerSignatureContext.SignatureDigestAlgorithm"/> that is not the one the signer's
    /// profile uses is therefore refused there rather than here — by the layer that owns the rule.
    /// </remarks>
    public static async ValueTask<AsicContainerCreationResult> SignAsync(
        AsicContainerSignatureContext context,
        PrivateKeyMemory privateKey,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        using AsicContainerPlan plan = await BuildSignaturePlanAsync(context, pool, cancellationToken).ConfigureAwait(false);
        using DigestValue protectedDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            plan.ProtectedOctets, context.SignatureDigestAlgorithm.OutputByteLength, context.SignatureDigestAlgorithm.DigestTag, pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        using CmsSignedData signature = await CAdESSignatureCreation.SignAsync(
            context.SignerCertificate,
            privateKey,
            content: null,
            detachedContentDigest: protectedDigest.AsReadOnlyMemory(),
            context.SigningTime,
            context.AdditionalCertificates,
            context.AlgorithmConstraints,
            context.IncludeCmsAlgorithmProtection,
            pool,
            cancellationToken,
            context.OptionalSignedAttributes).ConfigureAwait(false);

        return Assemble(plan, signature.AsReadOnlyMemory(), timestampTime: null, evidenceRecordArchiveTime: null, pool);
    }


    /// <summary>
    /// Builds a time-assertion container: an RFC 3161 time-stamp token taken over the data file (ASiC-S) or over
    /// the <c>ASiCManifest</c> file (ASiC-E), written beside the data objects it protects.
    /// </summary>
    /// <param name="context">Everything the container is built from.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The container. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="AsicContainerCreationException">When the supplied material is not a container this library builds.</exception>
    /// <exception cref="TimestampAcquisitionException">When the Time-Stamping Authority's answer does not verify against the request; no token is written in that case.</exception>
    public static async ValueTask<AsicContainerCreationResult> CreateTimeAssertionAsync(
        AsicContainerTimeAssertionContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        EnsureDigestAlgorithmAllowedForCreation(
            context.ImprintAlgorithm, context.AlgorithmConstraints, context.LastModified, "ASiC time assertion message imprint");

        AsicContainerPlan plan = await BuildTimeAssertionPlanAsync(context, pool, cancellationToken).ConfigureAwait(false);
        using(plan)
        {
            using DigestValue imprint = await CryptographicKeyEvents.ComputeDigestAsync(
                plan.ProtectedOctets, context.ImprintAlgorithm.OutputByteLength, context.ImprintAlgorithm.DigestTag, pool,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            using AcquiredTimestampToken token = await TimestampAcquisition.AcquireAsync(
                imprint,
                context.TsaUri,
                context.FetchTimestampResponse,
                pool,
                context.TimestampPolicyOid,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            return Assemble(plan, token.Token.AsReadOnlyMemory(), token.Info.GenerationTime, evidenceRecordArchiveTime: null, pool);
        }
    }


    /// <summary>
    /// Builds an Evidence Record container: an RFC 4998 Evidence Record over the data objects, written beside
    /// them and — for ASiC-E — beside the <c>ASiCEvidenceRecordManifest</c> file that names both.
    /// </summary>
    /// <param name="context">Everything the container is built from.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The container. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="AsicContainerCreationException">When the supplied material is not a container this library builds.</exception>
    /// <exception cref="TimestampAcquisitionException">When the Time-Stamping Authority's answer does not verify against the request; no record is written in that case.</exception>
    /// <remarks>
    /// The data objects form one data object group, which is what clause 4.4.3.2 item 4 b requires: the record
    /// has to "apply to all the container files referenced by <c>ASiCManifest</c> with
    /// <c>DataObjectReference</c> elements". A record proving one member of a group proves it against that
    /// group's own reduced hash tree, so one group is also what makes the manifest's reference list and the
    /// record's coverage the same set.
    /// </remarks>
    public static async ValueTask<AsicContainerCreationResult> CreateEvidenceRecordAsync(
        AsicContainerEvidenceRecordContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        ValidateDataObjects(context.Shape, context.DataObjects);
        EnsureDigestAlgorithmAllowedForCreation(
            context.DigestAlgorithm, context.AlgorithmConstraints, context.LastModified, "ASiC Evidence Record hash tree");

        var archivedObjects = new List<ReadOnlyMemory<byte>>(context.DataObjects.Count);
        for(int i = 0; i < context.DataObjects.Count; ++i)
        {
            archivedObjects.Add(context.DataObjects[i].Content);
        }

        using EvidenceRecordCreation creation = await EvidenceRecords.CreateInitialAsync(
            new EvidenceRecordCreationContext
            {
                DataObjectGroups = [new EvidenceRecordDataObjectGroup { DataObjects = archivedObjects }],
                DigestAlgorithm = context.DigestAlgorithm,
                TsaUri = context.TsaUri,
                FetchTimestampResponse = context.FetchTimestampResponse,
                NodeArity = context.NodeArity,
                TimestampPolicyOid = context.TimestampPolicyOid
            },
            pool,
            cancellationToken).ConfigureAwait(false);

        if(creation.EvidenceRecords.Count == 0)
        {
            throw new AsicContainerCreationException(
                AsicContainerCreationFailureKind.EvidenceRecordNotProduced,
                "The Evidence Record creation produced no record for the container's single data object group.");
        }

        using AsicContainerPlan plan = await BuildEvidenceRecordPlanAsync(context, pool, cancellationToken).ConfigureAwait(false);

        return Assemble(plan, creation.EvidenceRecords[0].AsReadOnlyMemory(), timestampTime: null, creation.ArchiveTime, pool);
    }


    /// <summary>
    /// Builds the plan for a CAdES-protected container: validates the data objects, chooses the names, and
    /// writes the manifest when the shape has one.
    /// </summary>
    /// <param name="context">Everything the container is built from.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The plan. The caller owns and disposes it.</returns>
    private static async ValueTask<AsicContainerPlan> BuildSignaturePlanAsync(
        AsicContainerSignatureContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context.SignerCertificate);
        ValidateDataObjects(context.Shape, context.DataObjects);

        List<AsicZipEntrySource> entries = BuildDataObjectEntries(context.DataObjects, context.LastModified);
        string mediaType = ResolveMediaType(context.Shape, context.DataObjects);

        if(context.Shape == AsicContainerShape.Simple)
        {
            string simpleSignatureName = RefuseCollision(AsicManifestNaming.SimpleSignatureEntryName, entries);

            return new AsicContainerPlan
            {
                Shape = AsicContainerShape.Simple,
                Profile = AsicContainerProfile.SimpleBaselineCAdES,
                MediaType = mediaType,
                FileExtension = AsicWellKnown.AsicSimpleExtension,
                LastModified = context.LastModified,
                ArchiveComment = ResolveArchiveComment(context.StateMediaTypeArchiveComment, mediaType),
                DataObjectEntries = entries,
                MetadataEntryName = simpleSignatureName,
                MetadataFileKind = AsicContainerFileKind.Signature,
                ProtectedOctets = context.DataObjects[0].Content
            };
        }

        EnsureDigestAlgorithmAllowedForCreation(
            context.ManifestDigestAlgorithm, context.AlgorithmConstraints, context.SigningTime, "ASiCManifest ds:DigestMethod");

        var taken = new List<string>(entries.Count + 1);
        for(int i = 0; i < entries.Count; ++i)
        {
            taken.Add(entries[i].Name);
        }

        string signatureName = AsicManifestNaming.CreateEntryName(AsicContainerFileKind.Signature, taken);
        taken.Add(signatureName);
        string manifestName = AsicManifestNaming.CreateEntryName(AsicContainerFileKind.SignatureManifest, taken);

        PooledMemory manifestDocument = await WriteManifestAsync(
            context.EncodeManifest,
            signatureName,
            context.SignatureReferenceMediaType,
            context.DataObjects,
            context.ManifestDigestAlgorithm,
            pool,
            cancellationToken).ConfigureAwait(false);

        return new AsicContainerPlan
        {
            Shape = AsicContainerShape.Extended,
            Profile = AsicContainerProfile.ExtendedCAdES,
            MediaType = mediaType,
            FileExtension = AsicWellKnown.AsicExtendedExtension,
            LastModified = context.LastModified,
            ArchiveComment = ResolveArchiveComment(context.StateMediaTypeArchiveComment, mediaType),
            DataObjectEntries = entries,
            ManifestDocument = manifestDocument,
            ManifestEntryName = manifestName,
            MetadataEntryName = signatureName,
            MetadataFileKind = AsicContainerFileKind.Signature,
            ProtectedOctets = manifestDocument.AsReadOnlyMemory()
        };
    }


    /// <summary>
    /// Builds the plan for a time-assertion container.
    /// </summary>
    /// <param name="context">Everything the container is built from.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The plan. The caller owns and disposes it.</returns>
    private static async ValueTask<AsicContainerPlan> BuildTimeAssertionPlanAsync(
        AsicContainerTimeAssertionContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ValidateDataObjects(context.Shape, context.DataObjects);

        List<AsicZipEntrySource> entries = BuildDataObjectEntries(context.DataObjects, context.LastModified);
        string mediaType = ResolveMediaType(context.Shape, context.DataObjects);

        if(context.Shape == AsicContainerShape.Simple)
        {
            string simpleTimestampName = RefuseCollision(AsicManifestNaming.SimpleTimestampEntryName, entries);

            return new AsicContainerPlan
            {
                Shape = AsicContainerShape.Simple,
                Profile = AsicContainerProfile.SimpleTimeAssertion,
                MediaType = mediaType,
                FileExtension = AsicWellKnown.AsicSimpleExtension,
                LastModified = context.LastModified,
                ArchiveComment = ResolveArchiveComment(context.StateMediaTypeArchiveComment, mediaType),
                DataObjectEntries = entries,
                MetadataEntryName = simpleTimestampName,
                MetadataFileKind = AsicContainerFileKind.Timestamp,
                ProtectedOctets = context.DataObjects[0].Content
            };
        }

        EnsureDigestAlgorithmAllowedForCreation(
            context.ManifestDigestAlgorithm, context.AlgorithmConstraints, context.LastModified, "ASiCManifest ds:DigestMethod");

        var taken = new List<string>(entries.Count + 1);
        for(int i = 0; i < entries.Count; ++i)
        {
            taken.Add(entries[i].Name);
        }

        string timestampName = AsicManifestNaming.CreateEntryName(AsicContainerFileKind.Timestamp, taken);
        taken.Add(timestampName);
        string manifestName = AsicManifestNaming.CreateEntryName(AsicContainerFileKind.SignatureManifest, taken);

        PooledMemory manifestDocument = await WriteManifestAsync(
            context.EncodeManifest,
            timestampName,
            context.TimestampReferenceMediaType,
            context.DataObjects,
            context.ManifestDigestAlgorithm,
            pool,
            cancellationToken).ConfigureAwait(false);

        return new AsicContainerPlan
        {
            Shape = AsicContainerShape.Extended,
            Profile = AsicContainerProfile.ExtendedTimeAssertion,
            MediaType = mediaType,
            FileExtension = AsicWellKnown.AsicExtendedExtension,
            LastModified = context.LastModified,
            ArchiveComment = ResolveArchiveComment(context.StateMediaTypeArchiveComment, mediaType),
            DataObjectEntries = entries,
            ManifestDocument = manifestDocument,
            ManifestEntryName = manifestName,
            MetadataEntryName = timestampName,
            MetadataFileKind = AsicContainerFileKind.Timestamp,
            ProtectedOctets = manifestDocument.AsReadOnlyMemory()
        };
    }


    /// <summary>
    /// Builds the plan for an Evidence Record container. The record itself is created before this runs, because
    /// it archives the data objects and not the manifest (clause 4.4.4.2 NOTE 2).
    /// </summary>
    /// <param name="context">Everything the container is built from.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The plan. The caller owns and disposes it.</returns>
    private static async ValueTask<AsicContainerPlan> BuildEvidenceRecordPlanAsync(
        AsicContainerEvidenceRecordContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        List<AsicZipEntrySource> entries = BuildDataObjectEntries(context.DataObjects, context.LastModified);
        string mediaType = ResolveMediaType(context.Shape, context.DataObjects);

        if(context.Shape == AsicContainerShape.Simple)
        {
            string simpleRecordName = RefuseCollision(AsicManifestNaming.SimpleBinaryEvidenceRecordEntryName, entries);

            return new AsicContainerPlan
            {
                Shape = AsicContainerShape.Simple,
                Profile = AsicContainerProfile.SimpleTimeAssertion,
                MediaType = mediaType,
                FileExtension = AsicWellKnown.AsicSimpleExtension,
                LastModified = context.LastModified,
                ArchiveComment = ResolveArchiveComment(context.StateMediaTypeArchiveComment, mediaType),
                DataObjectEntries = entries,
                MetadataEntryName = simpleRecordName,
                MetadataFileKind = AsicContainerFileKind.BinaryEvidenceRecord
            };
        }

        var taken = new List<string>(entries.Count + 1);
        for(int i = 0; i < entries.Count; ++i)
        {
            taken.Add(entries[i].Name);
        }

        string recordName = AsicManifestNaming.CreateEntryName(AsicContainerFileKind.BinaryEvidenceRecord, taken);
        taken.Add(recordName);
        string manifestName = AsicManifestNaming.CreateEntryName(AsicContainerFileKind.EvidenceRecordManifest, taken);

        PooledMemory manifestDocument = await WriteManifestAsync(
            context.EncodeManifest,
            recordName,
            context.EvidenceRecordReferenceMediaType,
            context.DataObjects,
            context.DigestAlgorithm,
            pool,
            cancellationToken).ConfigureAwait(false);

        return new AsicContainerPlan
        {
            Shape = AsicContainerShape.Extended,
            Profile = AsicContainerProfile.ExtendedTimeAssertion,
            MediaType = mediaType,
            FileExtension = AsicWellKnown.AsicExtendedExtension,
            LastModified = context.LastModified,
            ArchiveComment = ResolveArchiveComment(context.StateMediaTypeArchiveComment, mediaType),
            DataObjectEntries = entries,
            ManifestDocument = manifestDocument,
            ManifestEntryName = manifestName,
            MetadataEntryName = recordName,
            MetadataFileKind = AsicContainerFileKind.BinaryEvidenceRecord
        };
    }


    /// <summary>
    /// Writes the container's octets from a finished plan and the protective object it carries.
    /// </summary>
    /// <param name="plan">Everything the assembly needs.</param>
    /// <param name="metadataObject">The CAdES object, time-stamp token or Evidence Record octets.</param>
    /// <param name="timestampTime">The <c>genTime</c> an acquired token asserts, or <see langword="null"/> when the container carries no bare token.</param>
    /// <param name="evidenceRecordArchiveTime">The instant an Evidence Record's initial Archive Timestamp asserts, or <see langword="null"/> when the container carries no record.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <returns>The container. The caller owns and disposes it.</returns>
    /// <remarks>
    /// The entry order after the <c>mimetype</c> entry is this library's: the data objects, then the manifest,
    /// then the protective object. Annex A.1 constrains the position of the <c>mimetype</c> entry and of nothing
    /// else, and <see cref="AsicZipAuthoring"/> writes that entry itself.
    /// </remarks>
    private static AsicContainerCreationResult Assemble(
        AsicContainerPlan plan,
        ReadOnlyMemory<byte> metadataObject,
        DateTimeOffset? timestampTime,
        DateTimeOffset? evidenceRecordArchiveTime,
        BaseMemoryPool pool)
    {
        var entries = new List<AsicZipEntrySource>(plan.DataObjectEntries.Count + 2);
        entries.AddRange(plan.DataObjectEntries);

        if(plan.ManifestDocument is { } manifestDocument && plan.ManifestEntryName is { } manifestEntryName)
        {
            entries.Add(new AsicZipEntrySource { Name = manifestEntryName, Content = manifestDocument.AsReadOnlyMemory() });
        }

        entries.Add(new AsicZipEntrySource { Name = plan.MetadataEntryName, Content = metadataObject });

        PooledMemory container = AsicZipAuthoring.Write(
            new AsicZipAuthoringContext
            {
                MediaType = plan.MediaType,
                Entries = entries,
                LastModified = plan.LastModified,
                ArchiveComment = plan.ArchiveComment
            },
            pool);

        try
        {
            var entryNames = new List<string>(entries.Count + 1) { AsicWellKnown.MimetypeEntryName };
            for(int i = 0; i < entries.Count; ++i)
            {
                entryNames.Add(entries[i].Name);
            }

            return new AsicContainerCreationResult
            {
                Container = container,
                Shape = plan.Shape,
                Profile = plan.Profile,
                MediaType = plan.MediaType,
                FileExtension = plan.FileExtension,
                EntryNames = entryNames,
                ManifestEntryName = plan.ManifestEntryName,
                SignatureEntryName = plan.MetadataFileKind == AsicContainerFileKind.Signature ? plan.MetadataEntryName : null,
                TimestampEntryName = plan.MetadataFileKind == AsicContainerFileKind.Timestamp ? plan.MetadataEntryName : null,
                EvidenceRecordEntryName = plan.MetadataFileKind == AsicContainerFileKind.BinaryEvidenceRecord ? plan.MetadataEntryName : null,
                TimestampTime = timestampTime,
                EvidenceRecordArchiveTime = evidenceRecordArchiveTime
            };
        }
        catch
        {
            container.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Builds the <c>ASiCManifest</c> element for a container and writes it through the supplied seam.
    /// </summary>
    /// <param name="encodeManifest">The seam, or <see langword="null"/> when the caller supplied none.</param>
    /// <param name="referencedEntryName">The entry the <c>SigReference</c> names.</param>
    /// <param name="referencedMediaType">The <c>MimeType</c> the <c>SigReference</c> states, or <see langword="null"/> to state none.</param>
    /// <param name="dataObjects">The file objects the <c>DataObjectReference</c> elements name.</param>
    /// <param name="digestAlgorithm">The algorithm every <c>ds:DigestMethod</c> names.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The manifest document's octets. The caller owns and disposes them.</returns>
    /// <exception cref="AsicContainerCreationException">When no seam was supplied, or the seam produced no document.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every digest and reference built here transfers to the manifest, which the using disposes; the returned document is the caller's.")]
    private static async ValueTask<PooledMemory> WriteManifestAsync(
        EncodeAsicManifestDelegate? encodeManifest,
        string referencedEntryName,
        string? referencedMediaType,
        IReadOnlyList<AsicDataObject> dataObjects,
        PkiDigestAlgorithm digestAlgorithm,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        if(encodeManifest is null)
        {
            throw new AsicContainerCreationException(
                AsicContainerCreationFailureKind.ManifestEncoderMissing,
                "An ASiC-E container carries one or more manifest files (clause 4.4.4.2 item 2), and this library ships no implementation of the manifest serialisation seam; supply one.");
        }

        var references = new List<AsicDataObjectReference>(dataObjects.Count);
        try
        {
            for(int i = 0; i < dataObjects.Count; ++i)
            {
                AsicDataObject dataObject = dataObjects[i];
                DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                    dataObject.Content, digestAlgorithm.OutputByteLength, digestAlgorithm.DigestTag, pool,
                    cancellationToken: cancellationToken).ConfigureAwait(false);

                references.Add(new AsicDataObjectReference
                {
                    Uri = AsicContainerUri.ToReference(dataObject.Name),
                    DigestAlgorithm = digestAlgorithm,
                    Digest = digest,
                    MimeType = dataObject.MediaType,
                    IsRootFile = dataObject.IsRootFile
                });
            }
        }
        catch
        {
            for(int i = 0; i < references.Count; ++i)
            {
                references[i].Dispose();
            }

            throw;
        }

        using var manifest = new AsicManifest
        {
            SignatureReference = new AsicSignatureReference
            {
                Uri = AsicContainerUri.ToReference(referencedEntryName),
                MimeType = referencedMediaType
            },
            DataObjectReferences = references
        };

        using AsicManifestEncodeResult encoded = await encodeManifest(
            new AsicManifestEncodeContext { Manifest = manifest }, pool, cancellationToken).ConfigureAwait(false);

        if(!encoded.IsEncoded || encoded.Document is null)
        {
            throw new AsicContainerCreationException(
                AsicContainerCreationFailureKind.ManifestEncodingFailed,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"The manifest serialisation seam produced no document ({encoded.Status}): {encoded.FailureReason ?? "no reason stated"}."));
        }

        return PooledMemory.FromBytes(encoded.Document.AsReadOnlySpan(), pool, AsicTags.Manifest);
    }


    /// <summary>
    /// Refuses the data objects a conformant container cannot be built from.
    /// </summary>
    /// <param name="shape">Which container shape is being built.</param>
    /// <param name="dataObjects">The data objects the caller supplied.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="dataObjects"/> is <see langword="null"/>.</exception>
    /// <exception cref="AsicContainerCreationException">When the data objects are not a container's.</exception>
    /// <remarks>
    /// The reserved-word rule of clause 4.4.3.2 item 5 d i — a name may not contain "signature", "timestamp",
    /// "manifest" or "container.xml" — is deliberately NOT applied here. That item governs "any other file
    /// object" a container carries: files that are neither signed nor required to validate it. A data object is
    /// the signed file object itself, and refusing one called <c>signature-policy.pdf</c> would refuse a
    /// container the specification admits.
    /// </remarks>
    private static void ValidateDataObjects(AsicContainerShape shape, IReadOnlyList<AsicDataObject> dataObjects)
    {
        ArgumentNullException.ThrowIfNull(dataObjects);

        if(dataObjects.Count == 0)
        {
            throw new AsicContainerCreationException(
                AsicContainerCreationFailureKind.NoDataObject,
                "A container carries at least one data file (clause 4.3.3.2 item 2 for ASiC-S, clause 4.4.2 item 2 for ASiC-E).");
        }

        if(shape == AsicContainerShape.Simple && dataObjects.Count != 1)
        {
            throw new AsicContainerCreationException(
                AsicContainerCreationFailureKind.SimpleContainerNotSingleDataObject,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"An ASiC-S container carries exactly one data file (clause 4.3.3.2 item 2); {dataObjects.Count} were supplied."));
        }

        var names = new HashSet<string>(StringComparer.Ordinal);
        for(int i = 0; i < dataObjects.Count; ++i)
        {
            AsicDataObject dataObject = dataObjects[i];
            AsicZipEntryNameStatus status = AsicZipEntryNaming.Validate(dataObject.Name, AsicZipAuthoring.MaximumEntryNameByteLength);
            if(status != AsicZipEntryNameStatus.Accepted)
            {
                throw new AsicContainerCreationException(
                    AsicContainerCreationFailureKind.DataObjectNameRejected,
                    string.Create(CultureInfo.InvariantCulture, $"The data object name '{dataObject.Name}' is not a name a container may carry ({status})."));
            }

            if(AsicWellKnown.IsMimetypeEntryName(dataObject.Name))
            {
                throw new AsicContainerCreationException(
                    AsicContainerCreationFailureKind.DataObjectNotAtContainerRoot,
                    "Annex A.1 reserves the root-level name 'mimetype' for the entry that states the container's media type.");
            }

            if(AsicWellKnown.IsMetaInfEntryName(dataObject.Name))
            {
                throw new AsicContainerCreationException(
                    AsicContainerCreationFailureKind.DataObjectInMetaInf,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"The data object '{dataObject.Name}' is inside the META-INF folder; clause 4.4.2 item 2 places every data file outside it."));
            }

            if(shape == AsicContainerShape.Simple && dataObject.Name.Contains(AsicZipEntryNaming.Separator, StringComparison.Ordinal))
            {
                throw new AsicContainerCreationException(
                    AsicContainerCreationFailureKind.DataObjectNotAtContainerRoot,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"The ASiC-S data object '{dataObject.Name}' is not at the container root level, which clause 4.3.3.2 item 2 requires."));
            }

            if(!names.Add(dataObject.Name))
            {
                throw new AsicContainerCreationException(
                    AsicContainerCreationFailureKind.DuplicateDataObjectName,
                    string.Create(CultureInfo.InvariantCulture, $"Two data objects are named '{dataObject.Name}'; a container names each file object once."));
            }
        }
    }


    /// <summary>
    /// Turns the data objects into the container entries they become.
    /// </summary>
    /// <param name="dataObjects">The validated data objects.</param>
    /// <param name="lastModified">The instant an object that states none records.</param>
    /// <returns>The entries, in the order the data objects were supplied.</returns>
    private static List<AsicZipEntrySource> BuildDataObjectEntries(
        IReadOnlyList<AsicDataObject> dataObjects, DateTimeOffset lastModified)
    {
        var entries = new List<AsicZipEntrySource>(dataObjects.Count);
        for(int i = 0; i < dataObjects.Count; ++i)
        {
            AsicDataObject dataObject = dataObjects[i];
            entries.Add(new AsicZipEntrySource
            {
                Name = dataObject.Name,
                Content = dataObject.Content,
                CompressionMethod = dataObject.CompressionMethod,
                LastModified = dataObject.LastModified ?? lastModified
            });
        }

        return entries;
    }


    /// <summary>
    /// States the media type the container's <c>mimetype</c> entry carries.
    /// </summary>
    /// <param name="shape">Which container shape is being built.</param>
    /// <param name="dataObjects">The validated data objects.</param>
    /// <returns>The media type.</returns>
    /// <remarks>
    /// Clause 4.3.3.1 item 1 gives ASiC-S two branches — the fixed
    /// <see cref="AsicWellKnown.AsicSimpleMediaType"/> when the signed file object has no media type of its own,
    /// and that object's media type otherwise. Clause 4.4.4.1 item 2 gives the CAdES flavour of ASiC-E only one:
    /// "The "mimetype" file content shall be "application/vnd.etsi.asic-e+zip"", with no
    /// original-media-type alternative of the kind the XAdES flavour's clause 4.4.3.1 item 2 b admits.
    /// </remarks>
    private static string ResolveMediaType(AsicContainerShape shape, IReadOnlyList<AsicDataObject> dataObjects) => shape switch
    {
        AsicContainerShape.Simple => dataObjects[0].MediaType ?? AsicWellKnown.AsicSimpleMediaType,
        AsicContainerShape.Extended => AsicWellKnown.AsicExtendedMediaType,
        _ => throw new AsicContainerCreationException(
            AsicContainerCreationFailureKind.NoDataObject,
            string.Create(CultureInfo.InvariantCulture, $"'{shape}' does not name a container shape clause 4.1.2 defines."))
    };


    /// <summary>
    /// States the ZIP archive comment the container carries.
    /// </summary>
    /// <param name="stateMediaTypeComment">Whether the caller asked for the clause 4.3.3.1 item 3 comment.</param>
    /// <param name="mediaType">The container's media type.</param>
    /// <returns>The comment, or <see langword="null"/> to write none.</returns>
    private static string? ResolveArchiveComment(bool stateMediaTypeComment, string mediaType) =>
        stateMediaTypeComment ? AsicWellKnown.MediaTypeComment(mediaType) : null;


    /// <summary>
    /// Refuses a fixed ASiC-S metadata name that a data object has already taken.
    /// </summary>
    /// <param name="entryName">The fixed name clause 4.3.3.2 item 4 states.</param>
    /// <param name="entries">The entries the data objects became.</param>
    /// <returns><paramref name="entryName"/>.</returns>
    /// <exception cref="AsicContainerCreationException">When an entry already carries the name.</exception>
    /// <remarks>
    /// The suffixed ASiC-E names avoid collisions by construction — <see cref="AsicManifestNaming.CreateEntryName"/>
    /// is given every name already present — while the ASiC-S names are fixed by clause 4.3.3.2 item 4 and
    /// therefore cannot move out of the way. Validation already refuses a data object inside <c>META-INF</c>, so
    /// this refusal is unreachable through the shipped path and exists because a name a container has to write
    /// must never silently replace a file object the caller supplied.
    /// </remarks>
    private static string RefuseCollision(string entryName, List<AsicZipEntrySource> entries)
    {
        for(int i = 0; i < entries.Count; ++i)
        {
            if(string.Equals(entries[i].Name, entryName, StringComparison.Ordinal))
            {
                throw new AsicContainerCreationException(
                    AsicContainerCreationFailureKind.EntryNameCollision,
                    string.Create(CultureInfo.InvariantCulture, $"'{entryName}' is the name clause 4.3.3.2 item 4 fixes for this container's metadata file, and a data object already carries it."));
            }
        }

        return entryName;
    }


    /// <summary>
    /// Refuses a digest algorithm this surface must not create a container under: MD5 unconditionally (clause
    /// 5.2.1: "MD5 algorithm shall not be used as digest algorithm"), SHA-1 as a creation-side digest, and
    /// anything <see cref="PkiDigestAlgorithm.FromOid"/> does not itself recognise. When
    /// <paramref name="algorithmConstraints"/> is supplied, the algorithm must additionally be asserted reliable
    /// at <paramref name="instant"/>.
    /// </summary>
    /// <param name="digestAlgorithm">The digest algorithm to assess.</param>
    /// <param name="algorithmConstraints">The optional dated cryptographic-constraints table.</param>
    /// <param name="instant">The instant to assess <paramref name="algorithmConstraints"/> at.</param>
    /// <param name="use">What the algorithm is used for, named in the refusal message and in the assessed use.</param>
    /// <exception cref="AsicContainerCreationException">When the algorithm is refused.</exception>
    /// <remarks>
    /// <para>
    /// The SHA-1 refusal is this library's creation-side line rather than a clause of EN 319 162-1, which names
    /// only MD5: it is the same line <see cref="CAdESSignatureCreation"/> already draws, and a container whose
    /// manifest states SHA-1 digests would carry a weaker binding than the CAdES object protecting it. Reading a
    /// container someone else produced is unaffected — that is the reading side's decision, not this one.
    /// </para>
    /// <para>
    /// It is <see langword="internal"/> rather than <see langword="private"/> so that
    /// <see cref="AsicContainerAugmentation"/> applies the same rule from the same place: a container must not be
    /// augmentable under an algorithm it could not have been created under, and two copies of a dated
    /// reliability rule are two rules that can disagree. That surface reports the refusal as its own typed fault.
    /// </para>
    /// </remarks>
    internal static void EnsureDigestAlgorithmAllowedForCreation(
        PkiDigestAlgorithm digestAlgorithm,
        CryptographicConstraints? algorithmConstraints,
        DateTimeOffset instant,
        string use)
    {
        string oid = digestAlgorithm.Identifier.Oid;
        if(string.Equals(oid, Md5Oid, StringComparison.Ordinal))
        {
            throw new AsicContainerCreationException(
                AsicContainerCreationFailureKind.DigestAlgorithmRefused,
                string.Create(CultureInfo.InvariantCulture, $"MD5 shall not be used as a digest algorithm (ETSI EN 319 162-1 clause 5.2.1); refused for the {use}."));
        }

        if(string.Equals(oid, WellKnownOids.Sha1, StringComparison.Ordinal))
        {
            throw new AsicContainerCreationException(
                AsicContainerCreationFailureKind.DigestAlgorithmRefused,
                string.Create(CultureInfo.InvariantCulture, $"SHA-1 is refused as a creation-side digest algorithm; refused for the {use}."));
        }

        if(PkiDigestAlgorithm.FromOid(oid) is null)
        {
            throw new AsicContainerCreationException(
                AsicContainerCreationFailureKind.DigestAlgorithmRefused,
                string.Create(CultureInfo.InvariantCulture, $"Container creation supports SHA-256, SHA-384 and SHA-512 digests only; '{oid}' is not recognised for the {use}."));
        }

        if(algorithmConstraints is not null)
        {
            var algorithmUse = new AlgorithmUse(digestAlgorithm.Identifier, null, use);
            AlgorithmReliabilityAssessment assessment = algorithmConstraints.Assess(algorithmUse, instant);
            if(!assessment.IsReliable)
            {
                throw new AsicContainerCreationException(
                    AsicContainerCreationFailureKind.DigestAlgorithmRefused,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"The supplied cryptographic constraints table does not assert digest '{oid}' reliable at {instant:O} for the {use}."));
            }
        }
    }
}
