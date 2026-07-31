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
/// The baseline level an Associated Signature Container reaches, per
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> clause 5.1.
/// </summary>
/// <remarks>
/// <para>
/// The four levels are the ones clause 5.1 defines, each named after the CAdES baseline level of the signatures
/// the container incorporates. The numbering is ordered on purpose: clause 5.1 item 2 states that "the level of
/// an ASiC baseline container shall be the lowest level of the incorporated baseline signature(s)", and a
/// lowest-level rule needs an order to be computed in.
/// </para>
/// <para>
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised field never reads as a level, and so that a
/// container carrying no CAdES object at all — which has no baseline level, clause 5.1 being written about
/// containers that incorporate baseline signatures — is distinguishable from one carrying a B-B signature.
/// </para>
/// </remarks>
public enum AsicContainerLevel
{
    /// <summary>No level stated. The value of an unset field, and of a container carrying no CAdES object.</summary>
    NotEvaluated = 0,

    /// <summary>B-B: the container incorporates CAdES-B-B signatures — the baseline signed attributes and nothing above them.</summary>
    BaselineB = 1,

    /// <summary>B-T: every incorporated signature additionally carries a proof of existence for the signature value.</summary>
    BaselineT = 2,

    /// <summary>B-LT: every incorporated signature additionally carries the material required to validate it.</summary>
    BaselineLT = 3,

    /// <summary>B-LTA: every incorporated signature additionally carries an archive time-stamp.</summary>
    BaselineLTA = 4
}


/// <summary>
/// The level one CAdES object inside a container reaches, named by the entry it is stored under.
/// </summary>
/// <param name="EntryName">The container entry the CAdES object is stored under.</param>
/// <param name="Level">The level that object reaches, which is the lowest level of its own signers.</param>
[DebuggerDisplay("AsicSignatureLevel: {EntryName} = {Level}")]
public readonly record struct AsicSignatureLevel(string EntryName, AsicContainerLevel Level);


/// <summary>
/// What a container states about its own level: the level of every CAdES object it carries, and the lowest of
/// them, which clause 5.1 item 2 makes the container's level.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The levels are read structurally, from what each object carries.</strong> No signature is verified
/// here and no trust decision is made — that is the EN 319 102-1 validation process's work. This report answers
/// the one question augmentation needs answered before it starts: which objects would have to be raised for the
/// container as a whole to reach a level, given that the container's level is the lowest of theirs.
/// </para>
/// <para>
/// <see cref="Signatures"/> is in container entry order, so a caller can name the object that caps the level.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record AsicContainerLevelReport
{
    /// <summary>Gets the container's level: the lowest level of the incorporated signatures (clause 5.1 item 2).</summary>
    public required AsicContainerLevel Level { get; init; }

    /// <summary>Gets the level of every CAdES object the container carries, in container entry order.</summary>
    public required IReadOnlyList<AsicSignatureLevel> Signatures { get; init; }


    /// <summary>A short debugger string showing the container's level and how many objects it was computed over.</summary>
    private string DebuggerDisplay => $"AsicContainerLevelReport({Level}, over {Signatures.Count} CAdES objects)";
}


/// <summary>
/// Which of the two routes of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> Annex A.7 item 1 b) an augmentation places validation material through.
/// </summary>
/// <remarks>
/// <para>
/// Annex A.7 item 1 b) states both: "The generator shall use the <c>SignedData.certificates</c>/
/// <c>SignedData.crls</c> or the <c>certificate-values</c>/<c>revocation-values</c> unsigned attributes as
/// specified in CAdES". The closing clause is load-bearing — CAdES specifies not only how each route is written
/// but which of them applies:
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1</see> clause 5.5.3 selects the unsigned-attribute route for an object already
/// carrying a legacy long-term-availability attribute and the <c>SignedData</c> route otherwise, and states both
/// with <em>shall</em>.
/// </para>
/// <para>
/// <strong>The parameter is therefore a statement, not a preference.</strong> A caller names the route its
/// container's profile permits, and <see cref="AsicContainerAugmentation"/> refuses when the object's own state
/// makes clause 5.5.3 select the other one — rather than writing material into a place that clause forbids. The
/// restriction this exists for is
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916202/01.01.01_60/en_31916202v010101p.pdf">
/// ETSI EN 319 162-2 V1.1.1</see> clause 4.2.1 d), which narrows Annex A.7 for the ASiC-S time assertion
/// container to "the additional restriction that only <c>SignedData</c> shall be used to include certificate and
/// revocation information".
/// </para>
/// <para>
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised field never reads as a stated route.
/// </para>
/// </remarks>
public enum AsicValidationMaterialPlacement
{
    /// <summary>No route stated. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>
    /// <c>SignedData.certificates</c> and <c>SignedData.crls</c> — Annex A.7 item 1 b)'s first route, the one
    /// EN 319 122-1 clause 5.5.3 selects for an object carrying no legacy long-term-availability attribute, and
    /// the only one EN 319 162-2 clause 4.2.1 d) admits for the ASiC-S time assertion container.
    /// </summary>
    SignedDataFields = 1,

    /// <summary>
    /// The <c>certificate-values</c> and <c>revocation-values</c> unsigned attributes — Annex A.7 item 1 b)'s
    /// second route, which EN 319 122-1 clause 5.5.3 selects for an object carrying a legacy
    /// long-term-availability attribute, and which places the material inside that object's latest archive
    /// time-stamp token so the root <c>SignedData</c> stays untouched.
    /// </summary>
    CertificateAndRevocationValues = 2
}


/// <summary>
/// Names why a container could not be augmented.
/// </summary>
/// <remarks>
/// These are generator-side faults, in the same sense as <see cref="AsicContainerCreationFailureKind"/> and
/// <see cref="CAdESAugmentationFailureKind"/>: a container or a request the caller supplied that no conformant
/// augmentation can be performed on. What a reader concludes about a container it did not make stays
/// <see cref="AsicZipReadStatus"/>.
/// </remarks>
public enum AsicContainerAugmentationFailureKind
{
    /// <summary>No failure has been classified.</summary>
    NotEvaluated = 0,

    /// <summary>The supplied octets are not a container this library reads; the message carries the <see cref="AsicZipReadStatus"/> that refused them.</summary>
    ContainerNotRead = 1,

    /// <summary>
    /// The container carries no CAdES object, so there is no signature to raise. Clause 5.1 item 2 makes a
    /// container's level the lowest of its incorporated signatures, and a container with none has no level to
    /// raise.
    /// </summary>
    NoSignatureToRaise = 2,

    /// <summary>
    /// The augmentation would change the octets of an entry an <c>ASiCArchiveManifest</c> file already present
    /// has committed a time-stamp token to. Annex A.7 item 1 a) places validation material into the signatures
    /// and tokens <em>before</em> the first archive manifest is built, precisely because a
    /// <c>ds:DigestValue</c> already written cannot be re-derived without breaking the token over it.
    /// </summary>
    WouldBreakArchiveManifestChain = 3,

    /// <summary>No <see cref="EncodeAsicManifestDelegate"/> was supplied, and Annex A.7 item 1 c) writes a manifest file.</summary>
    ManifestEncoderMissing = 4,

    /// <summary>The supplied <see cref="EncodeAsicManifestDelegate"/> did not produce a document; the message carries the <see cref="AsicManifestEncodeStatus"/> it stated.</summary>
    ManifestEncodingFailed = 5,

    /// <summary>No <see cref="ParseAsicManifestDelegate"/> was supplied and the container carries manifest files the augmentation has to read.</summary>
    ManifestParserMissing = 6,

    /// <summary>The supplied <see cref="ParseAsicManifestDelegate"/> did not read a manifest the container carries; the message carries the <see cref="AsicManifestParseStatus"/> it stated.</summary>
    ManifestParseFailed = 7,

    /// <summary>The stated <see cref="AsicValidationMaterialPlacement"/> is not the route the container's profile or the object's own state admits.</summary>
    ValidationMaterialPlacementRefused = 8,

    /// <summary>
    /// A CAdES object's detached signed content cannot be determined from the container, so the archive
    /// time-stamp message imprint input of EN 319 122-1 clause 5.5.3 cannot be built.
    /// </summary>
    DetachedContentNotResolvable = 9,

    /// <summary>
    /// A digest algorithm this surface will not augment a container under was stated; the message names which
    /// rule refused it (clause 5.2.1's MD5 prohibition, this library's creation-side SHA-1 line, an algorithm it
    /// does not compute, or a supplied <see cref="CryptographicConstraints"/> table).
    /// </summary>
    DigestAlgorithmRefused = 10,

    /// <summary>
    /// The container carries no file object an archive manifest could reference, so Annex A.7 item 1 c b)'s
    /// "reference all the signed and/or time-asserted data ... files requiring long term validation support" has
    /// nothing to name.
    /// </summary>
    NothingToArchive = 11,

    /// <summary>
    /// The container carries an <c>ASiCArchiveManifest</c> file under a name Annex A.7 does not fix, and none
    /// under the fixed name, so which link the chain ends at cannot be determined.
    /// </summary>
    ArchiveManifestChainMalformed = 12
}


/// <summary>
/// The generator-side fault of augmenting an Associated Signature Container.
/// </summary>
/// <remarks>
/// Augmentation reports faults as exceptions, following <see cref="AsicContainerCreationException"/> and
/// <see cref="CAdESAugmentationException"/>. Faults belonging to a layer below stay that layer's: an unverifiable
/// answer from a Time-Stamping Authority is refused by <see cref="TimestampAcquisition"/> and a CAdES splice that
/// cannot be performed by <see cref="CAdESSignatureAugmentation"/>, so an unusable token is never written into a
/// container.
/// </remarks>
[DebuggerDisplay("AsicContainerAugmentationException({FailureKind}): {Message}")]
public sealed class AsicContainerAugmentationException: Exception
{
    /// <summary>Gets what could not be done.</summary>
    public AsicContainerAugmentationFailureKind FailureKind { get; }


    /// <summary>Initializes a new <see cref="AsicContainerAugmentationException"/> with an unclassified fault.</summary>
    public AsicContainerAugmentationException(): this(AsicContainerAugmentationFailureKind.ContainerNotRead, "The container could not be augmented.")
    {
    }


    /// <summary>Initializes a new <see cref="AsicContainerAugmentationException"/> with an unclassified fault.</summary>
    /// <param name="message">The message describing the fault.</param>
    public AsicContainerAugmentationException(string message): this(AsicContainerAugmentationFailureKind.ContainerNotRead, message)
    {
    }


    /// <summary>Initializes a new <see cref="AsicContainerAugmentationException"/> with an unclassified fault.</summary>
    /// <param name="message">The message describing the fault.</param>
    /// <param name="innerException">The exception that caused it.</param>
    public AsicContainerAugmentationException(string message, Exception innerException)
        : this(AsicContainerAugmentationFailureKind.ContainerNotRead, message, innerException)
    {
    }


    /// <summary>Initializes a new <see cref="AsicContainerAugmentationException"/>.</summary>
    /// <param name="failureKind">What could not be done.</param>
    /// <param name="message">The message describing the fault.</param>
    public AsicContainerAugmentationException(AsicContainerAugmentationFailureKind failureKind, string message): base(message)
    {
        FailureKind = failureKind;
    }


    /// <summary>Initializes a new <see cref="AsicContainerAugmentationException"/>.</summary>
    /// <param name="failureKind">What could not be done.</param>
    /// <param name="message">The message describing the fault.</param>
    /// <param name="innerException">The exception that caused it.</param>
    public AsicContainerAugmentationException(AsicContainerAugmentationFailureKind failureKind, string message, Exception innerException)
        : base(message, innerException)
    {
        FailureKind = failureKind;
    }
}


/// <summary>
/// What every container augmentation is given about the container it augments.
/// </summary>
/// <remarks>
/// The three augmentation contexts derive from this so that the container, the bounds it is read within and the
/// instant new entries record are stated once and in one shape. Nothing here is ambient: the bounds travel in the
/// context rather than being captured, the same discipline every context record of this namespace applies.
/// </remarks>
public abstract record AsicContainerAugmentationContext
{
    /// <summary>Gets the container's octets. The caller retains ownership.</summary>
    public required ReadOnlyMemory<byte> Container { get; init; }

    /// <summary>Gets the bounds the container is read within.</summary>
    public AsicZipReadLimits ReadLimits { get; init; } = AsicZipReadLimits.Conformant;

    /// <summary>
    /// Gets the instant an entry this augmentation adds records. An entry carried forward keeps the instant it
    /// already recorded, so a container's untouched entries are unchanged in every field a ZIP header carries.
    /// </summary>
    public required DateTimeOffset LastModified { get; init; }
}


/// <summary>
/// What one <see cref="AsicContainerAugmentation.AddSignatureTimestampsAsync"/> call needs: the container, the
/// algorithm the imprints are computed under, and how to reach a Time-Stamping Authority.
/// </summary>
/// <remarks>
/// Every CAdES object the container carries is raised, because clause 5.1 item 2 makes the container's level the
/// lowest of its signatures': raising one of two signatures raises nothing about the container.
/// </remarks>
[DebuggerDisplay("AsicContainerSignatureTimestampContext: {Container.Length} octets")]
public sealed record AsicContainerSignatureTimestampContext: AsicContainerAugmentationContext
{
    /// <summary>Gets the algorithm every message imprint is computed under.</summary>
    public PkiDigestAlgorithm MessageImprintAlgorithm { get; init; } = PkiDigestAlgorithm.Sha256;

    /// <summary>Gets the Time-Stamping Authority to contact, in whatever form the transport delegate understands.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "Forwarded verbatim into TimestampFetchContext.TsaUri, which is deliberately a string for the reason that property gives: the transport delegate owns URI parsing and scheme policy.")]
    public required string TsaUri { get; init; }

    /// <summary>Gets the transport the requests are sent through and the responses read from.</summary>
    public required FetchTimestampResponseAsyncDelegate FetchTimestampResponse { get; init; }

    /// <summary>Gets the time-stamp policy every request asks for, or <see langword="null"/> to state none.</summary>
    public string? TimestampPolicyOid { get; init; }

    /// <summary>
    /// Gets the signer's own certificate, forwarded verbatim into
    /// <see cref="CAdESSignatureTimestampContext.SigningCertificate"/> for every signature this call raises.
    /// </summary>
    /// <remarks>
    /// It is one certificate for the whole call because a container this library creates carries one signer per
    /// CAdES object and one CAdES object per manifest; a container of several signers raises with
    /// <see cref="EnforceSigningCertificateValidity"/> stated <see langword="false"/>, which is the opt-out the
    /// CAdES layer already documents.
    /// </remarks>
    public PkiCertificateMemory? SigningCertificate { get; init; }

    /// <summary>Gets the instant the signing certificate is known to have been revoked, or <see langword="null"/> when none is known.</summary>
    public DateTimeOffset? SigningCertificateRevokedAt { get; init; }

    /// <summary>Gets whether ETSI EN 319 122-1 Table 1 requirement m) is enforced; forwarded verbatim, secure default <see langword="true"/>.</summary>
    public bool EnforceSigningCertificateValidity { get; init; } = true;
}


/// <summary>
/// What one <see cref="AsicContainerAugmentation.AddSignatureValidationData"/> call needs: the container and the
/// material every CAdES object it carries is given.
/// </summary>
[DebuggerDisplay("AsicContainerValidationDataContext: {Container.Length} octets")]
public sealed record AsicContainerValidationDataContext: AsicContainerAugmentationContext
{
    /// <summary>Gets the certificates and revocation information placed into every CAdES object the container carries.</summary>
    public required CAdESValidationMaterial ValidationMaterial { get; init; }

    /// <summary>Gets which of Annex A.7 item 1 b)'s two routes the material is placed through.</summary>
    public AsicValidationMaterialPlacement Placement { get; init; } = AsicValidationMaterialPlacement.SignedDataFields;
}


/// <summary>
/// What one <see cref="AsicContainerAugmentation.AddSignatureArchiveTimestampsAsync"/> call needs: the container,
/// the material requirement s) of ETSI EN 319 122-1 Table 1 has placed first, the algorithm the imprints and hash
/// indexes are computed under, how to reach a Time-Stamping Authority, and the seam that reads the manifests the
/// signatures are detached over.
/// </summary>
/// <remarks>
/// The detached signed content of an ASiC-E CAdES object is the <c>ASiCManifest</c> file whose
/// <c>SigReference</c> names it (Annex A.4.1), and of an ASiC-S CAdES object the single data file (clause
/// 4.3.3.2 item 4 b). Resolving the first needs the manifests read, which is why
/// <see cref="ParseManifest"/> is stated here and not at the two lower augmentations, neither of which computes
/// anything over the signed content.
/// </remarks>
[DebuggerDisplay("AsicContainerSignatureArchiveTimestampContext: {Container.Length} octets")]
public sealed record AsicContainerSignatureArchiveTimestampContext: AsicContainerAugmentationContext
{
    /// <summary>Gets the algorithm every message imprint and hash index is computed under.</summary>
    public PkiDigestAlgorithm MessageImprintAlgorithm { get; init; } = PkiDigestAlgorithm.Sha256;

    /// <summary>Gets the Time-Stamping Authority to contact, in whatever form the transport delegate understands.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "Forwarded verbatim into TimestampFetchContext.TsaUri, which is deliberately a string for the reason that property gives: the transport delegate owns URI parsing and scheme policy.")]
    public required string TsaUri { get; init; }

    /// <summary>Gets the transport the requests are sent through and the responses read from.</summary>
    public required FetchTimestampResponseAsyncDelegate FetchTimestampResponse { get; init; }

    /// <summary>Gets the material placed before each archive time-stamp is generated; <see cref="CAdESValidationMaterial.None"/> states that everything needed is already there.</summary>
    public CAdESValidationMaterial ValidationMaterial { get; init; } = CAdESValidationMaterial.None;

    /// <summary>Gets which of Annex A.7 item 1 b)'s two routes <see cref="ValidationMaterial"/> is placed through.</summary>
    public AsicValidationMaterialPlacement Placement { get; init; } = AsicValidationMaterialPlacement.SignedDataFields;

    /// <summary>Gets the seam the container's manifest files are read through, required for an ASiC-E container.</summary>
    public ParseAsicManifestDelegate? ParseManifest { get; init; }

    /// <summary>Gets the bounds every manifest is parsed within.</summary>
    public AsicManifestParseLimits ManifestParseLimits { get; init; } = AsicManifestParseLimits.Conformant;

    /// <summary>Gets the time-stamp policy every request asks for, or <see langword="null"/> to state none.</summary>
    public string? TimestampPolicyOid { get; init; }

    /// <summary>Gets the signer's own certificate, forwarded verbatim into <see cref="CAdESArchiveTimestampContext.SigningCertificate"/> for every signature this call raises.</summary>
    public PkiCertificateMemory? SigningCertificate { get; init; }

    /// <summary>Gets the instant the signing certificate is known to have been revoked, or <see langword="null"/> when none is known.</summary>
    public DateTimeOffset? SigningCertificateRevokedAt { get; init; }

    /// <summary>
    /// Gets whether the acquired tokens' generation times are checked against <see cref="SigningCertificate"/>;
    /// forwarded verbatim, secure default <see langword="true"/>, and the knob a caller raising a container long
    /// after its signing certificates expired states for itself.
    /// </summary>
    public bool EnforceSigningCertificateValidity { get; init; } = true;
}


/// <summary>
/// What one <see cref="AsicContainerAugmentation.AddContainerArchiveTimestampAsync"/> call needs: the container,
/// the algorithms the manifest digests and the token imprint are computed under, how to reach a Time-Stamping
/// Authority, and the two manifest seams the chain is written and read through.
/// </summary>
/// <remarks>
/// This is the container-level long-term-availability mechanism of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> Annex A.7, which is a different and independent layer from the CAdES-internal
/// archive time-stamp the three <c>AddSignature*</c> augmentations reach: clause 4.1.2 NOTE 1 states that a
/// signature-internal archive time-stamp does not cover the file objects a manifest references, so a container
/// whose every object is protected needs both.
/// </remarks>
[DebuggerDisplay("AsicContainerArchiveTimestampContext: {Container.Length} octets")]
public sealed record AsicContainerArchiveTimestampContext: AsicContainerAugmentationContext
{
    /// <summary>Gets the Time-Stamping Authority to contact, in whatever form the transport delegate understands.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "Forwarded verbatim into TimestampFetchContext.TsaUri, which is deliberately a string for the reason that property gives: the transport delegate owns URI parsing and scheme policy.")]
    public required string TsaUri { get; init; }

    /// <summary>Gets the transport the time-stamp request is sent through and the response read from.</summary>
    public required FetchTimestampResponseAsyncDelegate FetchTimestampResponse { get; init; }

    /// <summary>Gets the seam the new <c>ASiCArchiveManifest</c> document is written through.</summary>
    public required EncodeAsicManifestDelegate EncodeManifest { get; init; }

    /// <summary>
    /// Gets the seam the archive manifest already present is read through, required for every addition after the
    /// first: Annex A.7 item 2 names the token "applied to the last <c>ASiCArchiveManifest</c> file", and which
    /// token that is, is what the manifest's own <c>SigReference</c> states.
    /// </summary>
    public ParseAsicManifestDelegate? ParseManifest { get; init; }

    /// <summary>Gets the bounds the archive manifest already present is parsed within.</summary>
    public AsicManifestParseLimits ManifestParseLimits { get; init; } = AsicManifestParseLimits.Conformant;

    /// <summary>Gets the algorithm every <c>ds:DigestMethod</c> of the new archive manifest names.</summary>
    public PkiDigestAlgorithm DigestAlgorithm { get; init; } = PkiDigestAlgorithm.Sha256;

    /// <summary>Gets the algorithm the new token's <c>messageImprint</c> is computed under.</summary>
    public PkiDigestAlgorithm ImprintAlgorithm { get; init; } = PkiDigestAlgorithm.Sha256;

    /// <summary>Gets a caller-supplied dated cryptographic-constraints table, or <see langword="null"/> to apply only the hard MD5/SHA-1 refusals.</summary>
    public CryptographicConstraints? AlgorithmConstraints { get; init; }

    /// <summary>
    /// Gets the certificates and revocation information Annex A.7 item 1 a) has present in the objects requiring
    /// long term availability; <see cref="CAdESValidationMaterial.None"/> states that everything needed is
    /// already there.
    /// </summary>
    public CAdESValidationMaterial ValidationMaterial { get; init; } = CAdESValidationMaterial.None;

    /// <summary>Gets which of Annex A.7 item 1 b)'s two routes <see cref="ValidationMaterial"/> is placed through.</summary>
    public AsicValidationMaterialPlacement Placement { get; init; } = AsicValidationMaterialPlacement.SignedDataFields;

    /// <summary>Gets the <c>MimeType</c> the new manifest's <c>SigReference</c> states for the token, or <see langword="null"/> to state none.</summary>
    public string? TimestampReferenceMediaType { get; init; }

    /// <summary>Gets the time-stamp policy the request asks for, or <see langword="null"/> to state none.</summary>
    public string? TimestampPolicyOid { get; init; }
}


/// <summary>
/// A container this library augmented: its octets and what the augmentation changed.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Every entry the augmentation did not deliberately replace carries the same octets it did before</strong>
/// — the byte-preservation property Annex A.7 item 2 a)'s rename rests on, and the one a
/// <c>ds:DigestValue</c> already written by an earlier chain link rests on too. The container's own octets
/// necessarily differ, because a ZIP archive states its entries' names, offsets and sizes.
/// </para>
/// <para>
/// <see cref="Container"/> is owned by this instance; the caller disposes it.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class AsicContainerAugmentationResult: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>Gets the augmented container's octets, tagged <see cref="AsicTags.Container"/>. Owned by this instance.</summary>
    public required PooledMemory Container { get; init; }

    /// <summary>Gets every entry name the augmented container carries, in the order they were written.</summary>
    public required IReadOnlyList<string> EntryNames { get; init; }

    /// <summary>Gets the names of the CAdES objects this augmentation replaced, or an empty list when it replaced none.</summary>
    public IReadOnlyList<string> RaisedSignatureEntryNames { get; init; } = [];

    /// <summary>Gets the name of the <c>ASiCArchiveManifest</c> file this augmentation added, or <see langword="null"/> when it added none.</summary>
    public string? ArchiveManifestEntryName { get; init; }

    /// <summary>
    /// Gets the name the previous <c>ASiCArchiveManifest</c> file was renamed to (Annex A.7 item 2 a)), or
    /// <see langword="null"/> when this was the first addition and there was nothing to rename.
    /// </summary>
    public string? RenamedArchiveManifestEntryName { get; init; }

    /// <summary>Gets the name of the time-stamp token this augmentation added, or <see langword="null"/> when it added none.</summary>
    public string? ArchiveTimestampEntryName { get; init; }

    /// <summary>Gets the <c>genTime</c> the added archive time-stamp token asserts, or <see langword="null"/> when none was added.</summary>
    public DateTimeOffset? ArchiveTimestampTime { get; init; }

    /// <summary>Gets how many <c>ASiCArchiveManifest</c> files the augmented container carries, the newest included.</summary>
    public int ArchiveManifestChainLength { get; init; }


    /// <summary>Disposes <see cref="Container"/>.</summary>
    public void Dispose()
    {
        if(!disposed)
        {
            Container.Dispose();
            disposed = true;
        }
    }


    /// <summary>A short debugger string showing the container's size and what the augmentation changed.</summary>
    private string DebuggerDisplay =>
        $"AsicContainerAugmentationResult({Container.Length} bytes, {RaisedSignatureEntryNames.Count} raised, chain {ArchiveManifestChainLength})";
}


/// <summary>
/// Raises Associated Signature Containers: the CAdES baseline levels of every signature a container
/// incorporates, and the container-level long-term-availability chain of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> Annex A.7.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Raising a container raises every signature in it.</strong> Clause 5.1 item 2: "The level of an ASiC
/// baseline container shall be the lowest level of the incorporated baseline signature(s)". The three
/// <c>AddSignature*</c> augmentations therefore apply to every <c>META-INF/*signature*.p7s</c> entry and to every
/// signer of each, delegating one object at a time to <see cref="CAdESSignatureAugmentation"/>, which owns the
/// CAdES rules. <see cref="StateContainerLevel"/> is the reading side of the same rule.
/// </para>
/// <para>
/// <strong>Two independent long-term-availability layers.</strong> The CAdES-internal archive time-stamp
/// <see cref="AddSignatureArchiveTimestampsAsync"/> reaches protects a signature and what it signs; Annex A.7's
/// chain, which <see cref="AddContainerArchiveTimestampAsync"/> writes, protects the container's file objects as
/// files. Clause 4.1.2 NOTE 1 states why both exist: a signature-internal archive time-stamp does not cover the
/// file objects referenced only through an <c>ASiCManifest</c>.
/// </para>
/// <para>
/// <strong>Nothing untouched changes.</strong> Every augmentation rewrites the container through
/// <see cref="AsicZipAuthoring.Write"/> from the entries <see cref="AsicZipReading.Read"/> produced, carrying each
/// entry's octets, compression method and recorded instant forward unchanged. Annex A.7 item 2 a)'s rename is
/// exactly that and nothing more — an entry name changes while its content stays as it was, because a token has
/// already committed to those octets.
/// </para>
/// <para>
/// <strong>Fail-closed.</strong> An augmentation that would change the octets of an entry an archive manifest
/// already references is refused rather than performed
/// (<see cref="AsicContainerAugmentationFailureKind.WouldBreakArchiveManifestChain"/>); a validation-material
/// route the container's profile or the object's own state does not admit is refused
/// (<see cref="AsicContainerAugmentationFailureKind.ValidationMaterialPlacementRefused"/>); and a Time-Stamping
/// Authority answering something that does not verify is refused by <see cref="TimestampAcquisition"/>, so an
/// unverifiable token never reaches a container.
/// </para>
/// </remarks>
public static class AsicContainerAugmentation
{
    /// <summary>
    /// States a container's level and the level of every CAdES object it carries — clause 5.1 item 2's
    /// lowest-level rule, computed.
    /// </summary>
    /// <param name="containerBytes">The container's octets.</param>
    /// <param name="limits">The bounds the container is read within.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <returns>The report. A container carrying no CAdES object states <see cref="AsicContainerLevel.NotEvaluated"/> and an empty list.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="AsicContainerAugmentationException">When the octets are not a container this library reads.</exception>
    /// <remarks>
    /// <para>
    /// <strong>The levels are structural, and the discriminators are the ones a reader can actually see.</strong>
    /// An archive time-stamp attribute — <c>archive-time-stamp-v3</c> or either deprecated form — names B-LTA.
    /// Revocation information names B-LT: certificates alone do not, because
    /// <see cref="CAdESSignatureCreation"/> and every other conformant producer places the signer's own
    /// certificate in a B-B signature, while revocation information appears no earlier than
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
    /// ETSI EN 319 122-1 V1.3.1</see> Table 1 requirements q) and r), which are B-LT's. A
    /// <c>signature-time-stamp</c> attribute names B-T. Anything else is B-B.
    /// </para>
    /// <para>
    /// Nothing is verified here. A structural reading states which augmentation a container still needs; whether
    /// the material it carries is <em>sufficient</em> is the EN 319 102-1 validation process's conclusion, not a
    /// generator's.
    /// </para>
    /// </remarks>
    public static AsicContainerLevelReport StateContainerLevel(
        ReadOnlyMemory<byte> containerBytes,
        AsicZipReadLimits limits,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(limits);
        ArgumentNullException.ThrowIfNull(pool);

        using AsicZipReadResult read = ReadContainer(containerBytes, limits, pool);
        AsicZipContainer container = read.Container!;

        var levels = new List<AsicSignatureLevel>();
        for(int i = 0; i < container.Entries.Count; ++i)
        {
            AsicZipEntry entry = container.Entries[i];
            if(!AsicManifestNaming.IsSignatureEntryName(entry.Name))
            {
                continue;
            }

            levels.Add(new AsicSignatureLevel(entry.Name, StateSignatureLevel(entry.Content.AsReadOnlySpan(), pool)));
        }

        AsicContainerLevel lowest = AsicContainerLevel.NotEvaluated;
        for(int i = 0; i < levels.Count; ++i)
        {
            AsicContainerLevel level = levels[i].Level;
            lowest = lowest == AsicContainerLevel.NotEvaluated || level < lowest ? level : lowest;
        }

        return new AsicContainerLevelReport { Level = lowest, Signatures = levels };
    }


    /// <summary>
    /// Raises every CAdES object the container carries to CAdES-B-T by adding a <c>signature-time-stamp</c> to
    /// each of its signers, and writes a container carrying the raised objects and nothing else changed.
    /// </summary>
    /// <param name="context">The container, the imprint algorithm and the authority to contact.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The augmented container. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="AsicContainerAugmentationException">When the container carries no CAdES object, or carries an archive manifest whose chain the change would break.</exception>
    /// <exception cref="CAdESAugmentationException">When a CAdES object cannot be augmented.</exception>
    /// <exception cref="TimestampAcquisitionException">When the authority could not be reached, or its answer does not verify.</exception>
    public static async ValueTask<AsicContainerAugmentationResult> AddSignatureTimestampsAsync(
        AsicContainerSignatureTimestampContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        using AsicZipReadResult read = ReadContainer(context.Container, context.ReadLimits, pool);
        AsicZipContainer container = read.Container!;
        List<AsicZipEntry> signatures = SelectSignatureEntries(container);
        RefuseWhenArchiveChainWouldBreak(container, signatures, "adding a signature time-stamp");

        var replacements = new Dictionary<string, PooledMemory>(StringComparer.Ordinal);
        try
        {
            for(int i = 0; i < signatures.Count; ++i)
            {
                AsicZipEntry entry = signatures[i];
                using CmsSignedData raised = await AddSignatureTimestampToEverySignerAsync(
                    entry.Content.AsReadOnlyMemory(), context, pool, cancellationToken).ConfigureAwait(false);

                replacements.Add(entry.Name, PooledMemory.FromBytes(raised.AsReadOnlySpan(), pool, AsicTags.ContainerEntry));
            }

            return AssembleRaised(container, replacements, signatures, context.LastModified, pool);
        }
        finally
        {
            foreach(PooledMemory replacement in replacements.Values)
            {
                replacement.Dispose();
            }
        }
    }


    /// <summary>
    /// Raises every CAdES object the container carries to CAdES-B-LT by placing the stated validation material
    /// into each, and writes a container carrying the raised objects and nothing else changed.
    /// </summary>
    /// <param name="context">The container, the material and the route it is placed through.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <returns>The augmented container. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="AsicContainerAugmentationException">When the container carries no CAdES object, carries an archive manifest whose chain the change would break, or an object's own state does not admit the stated route.</exception>
    /// <exception cref="CAdESAugmentationException">When a CAdES object cannot be augmented.</exception>
    /// <remarks>
    /// Synchronous by nature, as <see cref="CAdESSignatureAugmentation.AddValidationData"/> is: placing
    /// validation material is a splice over octets the caller already holds, with no digest and no authority to
    /// wait for.
    /// </remarks>
    public static AsicContainerAugmentationResult AddSignatureValidationData(
        AsicContainerValidationDataContext context,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(context.ValidationMaterial);
        ArgumentNullException.ThrowIfNull(pool);

        using AsicZipReadResult read = ReadContainer(context.Container, context.ReadLimits, pool);
        AsicZipContainer container = read.Container!;
        List<AsicZipEntry> signatures = SelectSignatureEntries(container);
        RefuseWhenArchiveChainWouldBreak(container, signatures, "placing validation material");
        RefuseUnsupportedPlacementForProfile(container, context.Placement);

        var replacements = new Dictionary<string, PooledMemory>(StringComparer.Ordinal);
        try
        {
            for(int i = 0; i < signatures.Count; ++i)
            {
                AsicZipEntry entry = signatures[i];
                using CmsSignedData placed = PlaceValidationMaterial(
                    entry.Content.AsReadOnlySpan(), entry.Name, context.ValidationMaterial, context.Placement, pool);

                replacements.Add(entry.Name, PooledMemory.FromBytes(placed.AsReadOnlySpan(), pool, AsicTags.ContainerEntry));
            }

            return AssembleRaised(container, replacements, signatures, context.LastModified, pool);
        }
        finally
        {
            foreach(PooledMemory replacement in replacements.Values)
            {
                replacement.Dispose();
            }
        }
    }


    /// <summary>
    /// Raises every CAdES object the container carries to CAdES-B-LTA by adding an <c>archive-time-stamp-v3</c>
    /// to each of its signers, over the file object that object is detached across.
    /// </summary>
    /// <param name="context">The container, the material, the imprint algorithm, the authority to contact and the manifest seam.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The augmented container. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="AsicContainerAugmentationException">When the container carries no CAdES object, carries an archive manifest whose chain the change would break, does not state what a signature is detached over, or the manifest seam is missing or refuses a document.</exception>
    /// <exception cref="CAdESAugmentationException">When a CAdES object cannot be augmented.</exception>
    /// <exception cref="TimestampAcquisitionException">When the authority could not be reached, or its answer does not verify.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Every carrier the loop builds is owned by a using of that iteration and the replacements the finally disposes; the rule's data flow does not follow ownership across the awaited augmentations inside the loop. The try/finally shape the rule prescribes was written first and does not satisfy it either.")]
    public static async ValueTask<AsicContainerAugmentationResult> AddSignatureArchiveTimestampsAsync(
        AsicContainerSignatureArchiveTimestampContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(context.ValidationMaterial);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        using AsicZipReadResult read = ReadContainer(context.Container, context.ReadLimits, pool);
        AsicZipContainer container = read.Container!;
        List<AsicZipEntry> signatures = SelectSignatureEntries(container);
        RefuseWhenArchiveChainWouldBreak(container, signatures, "adding an archive time-stamp");
        RefuseUnsupportedPlacementForProfile(container, context.Placement);

        IReadOnlyDictionary<string, ReadOnlyMemory<byte>> detachedContent = await ResolveDetachedContentAsync(
            container, signatures, context.ParseManifest, context.ManifestParseLimits, context.ReadLimits.MaximumEntryNameByteLength, pool, cancellationToken).ConfigureAwait(false);

        var replacements = new Dictionary<string, PooledMemory>(StringComparer.Ordinal);
        try
        {
            for(int i = 0; i < signatures.Count; ++i)
            {
                AsicZipEntry entry = signatures[i];
                ReadOnlyMemory<byte> content = detachedContent[entry.Name];
                using CmsSignedData placed = CopyOrPlaceValidationMaterial(
                    entry.Content.AsReadOnlySpan(), entry.Name, context.ValidationMaterial, context.Placement, pool);

                using DigestValue contentDigest = await CryptographicKeyEvents.ComputeDigestAsync(
                    content, context.MessageImprintAlgorithm.OutputByteLength, context.MessageImprintAlgorithm.DigestTag, pool,
                    cancellationToken: cancellationToken).ConfigureAwait(false);

                using CmsSignedData raised = await AddArchiveTimestampToEverySignerAsync(
                    placed.AsReadOnlyMemory(), context, contentDigest, pool, cancellationToken).ConfigureAwait(false);

                replacements.Add(entry.Name, PooledMemory.FromBytes(raised.AsReadOnlySpan(), pool, AsicTags.ContainerEntry));
            }

            return AssembleRaised(container, replacements, signatures, context.LastModified, pool);
        }
        finally
        {
            foreach(PooledMemory replacement in replacements.Values)
            {
                replacement.Dispose();
            }
        }
    }


    /// <summary>
    /// Adds a link to the container-level long-term-availability chain of Annex A.7: a new
    /// <c>META-INF/ASiCArchiveManifest.xml</c> referencing every file object the container carries, the rename of
    /// the previous archive manifest with its octets untouched, the backward <c>Rootfile</c> pointer to it, and a
    /// time-stamp token applied to the new manifest.
    /// </summary>
    /// <param name="context">The container, the algorithms, the authority to contact and the two manifest seams.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The augmented container. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="AsicContainerAugmentationException">When the container states nothing to archive, a seam is missing or refuses a document, the stated validation-material route is not admitted, or the chain already present cannot be read.</exception>
    /// <exception cref="TimestampAcquisitionException">When the authority could not be reached, or its answer does not verify.</exception>
    /// <remarks>
    /// <para>
    /// <strong>The first addition and every renewal are one algorithm.</strong> Annex A.7 states them as two
    /// items, and they differ in exactly two places: a renewal renames the manifest already present and points
    /// the new one back at it with <c>Rootfile</c> set to true (items 2 a) and 2 b) iv)), while a first addition
    /// has nothing to rename and points back at nothing. Everything else — the fixed name, the reference set, the
    /// token over the manifest — is item 1 c) verbatim.
    /// </para>
    /// <para>
    /// <strong>Which objects may still receive validation material is decided by the chain, not by the caller.</strong>
    /// Annex A.7 item 1 a) places the material into the signatures and tokens present <em>before</em> the first
    /// archive manifest is built, and item 2's intro names only "the time-stamp token applied to the last
    /// <c>ASiCArchiveManifest</c> file" for a renewal. That is not an accident of wording: every other object is
    /// already named by a <c>ds:DigestValue</c> an earlier link committed a token to, so changing its octets
    /// would break that link. This surface enforces the same boundary — on a renewal only the token the last
    /// archive manifest's <c>SigReference</c> names may receive material, which is why
    /// <see cref="AsicContainerArchiveTimestampContext.ParseManifest"/> is required from the second addition on.
    /// </para>
    /// <para>
    /// <strong>Inside an archive manifest, <c>Rootfile</c> means one thing only.</strong> Annex A.4.2 defines the
    /// attribute as the root-file marker of the container vocabulary it is borrowed from, and Annex A.7 item 2 b)
    /// iv) repurposes it as the single backward pointer of the chain. The references this surface writes
    /// therefore state the attribute for the renamed predecessor and for nothing else — item 2 b) iii)'s "all the
    /// referenced file objects above shall not have the <c>Rootfile</c> attribute or it shall be set to false",
    /// taken in its first form.
    /// </para>
    /// </remarks>
    public static async ValueTask<AsicContainerAugmentationResult> AddContainerArchiveTimestampAsync(
        AsicContainerArchiveTimestampContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(context.ValidationMaterial);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        EnsureDigestAlgorithmAllowed(context.DigestAlgorithm, context.AlgorithmConstraints, context.LastModified, "ASiCArchiveManifest ds:DigestMethod");
        EnsureDigestAlgorithmAllowed(context.ImprintAlgorithm, context.AlgorithmConstraints, context.LastModified, "ASiC archive time-stamp message imprint");

        using AsicZipReadResult read = ReadContainer(context.Container, context.ReadLimits, pool);
        AsicZipContainer container = read.Container!;
        RefuseUnsupportedPlacementForProfile(container, context.Placement);

        AsicZipEntry? previousArchiveManifest = container.FindEntry(AsicManifestNaming.FixedArchiveManifestEntryName);
        RefuseUnfixedArchiveManifestChain(container, previousArchiveManifest);

        //Annex A.7 item 2's intro names the token applied to the last archive manifest as the one whose own
        //validation material is completed on a renewal; on a first addition item 1 a) names every signature and
        //token the container carries, because nothing has committed a digest to any of them yet.
        string? renewableTokenEntryName = previousArchiveManifest is null
            ? null
            : await ResolveArchiveTimestampEntryNameAsync(
                previousArchiveManifest, context.ParseManifest, context.ManifestParseLimits, context.ReadLimits.MaximumEntryNameByteLength, pool, cancellationToken).ConfigureAwait(false);

        var names = new List<string>(container.Entries.Count + 3);
        for(int i = 0; i < container.Entries.Count; ++i)
        {
            names.Add(container.Entries[i].Name);
        }

        string? renamedArchiveManifest = null;
        if(previousArchiveManifest is not null)
        {
            renamedArchiveManifest = AsicManifestNaming.CreateEntryName(AsicContainerFileKind.ArchiveManifest, names);
            _ = names.Remove(AsicManifestNaming.FixedArchiveManifestEntryName);
            names.Add(renamedArchiveManifest);
        }

        string timestampName = AsicManifestNaming.CreateEntryName(AsicContainerFileKind.Timestamp, names);
        names.Add(timestampName);
        string archiveManifestName = AsicManifestNaming.CreateFixedArchiveManifestEntryName(names);

        var replacements = new Dictionary<string, PooledMemory>(StringComparer.Ordinal);
        var additions = new List<AsicZipEntrySource>(2);
        PooledMemory? manifestDocument = null;
        PooledMemory? tokenOctets = null;
        try
        {
            if(!context.ValidationMaterial.IsEmpty)
            {
                CollectValidationMaterialPlacements(container, renewableTokenEntryName, context.ValidationMaterial, context.Placement, replacements, pool);
            }

            List<AsicZipEntrySource> covered = BuildCoveredEntries(container, replacements, renamedArchiveManifest, context.LastModified);
            manifestDocument = await WriteArchiveManifestAsync(
                context, covered, timestampName, renamedArchiveManifest, pool, cancellationToken).ConfigureAwait(false);

            using DigestValue imprint = await CryptographicKeyEvents.ComputeDigestAsync(
                manifestDocument.AsReadOnlyMemory(), context.ImprintAlgorithm.OutputByteLength, context.ImprintAlgorithm.DigestTag, pool,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            using AcquiredTimestampToken token = await TimestampAcquisition.AcquireAsync(
                imprint.AsReadOnlyMemory(),
                context.ImprintAlgorithm,
                context.TsaUri,
                context.FetchTimestampResponse,
                pool,
                context.TimestampPolicyOid,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            tokenOctets = PooledMemory.FromBytes(token.Token.AsReadOnlySpan(), pool, AsicTags.ContainerEntry);

            additions.Add(new AsicZipEntrySource { Name = archiveManifestName, Content = manifestDocument.AsReadOnlyMemory(), LastModified = context.LastModified });
            additions.Add(new AsicZipEntrySource { Name = timestampName, Content = tokenOctets.AsReadOnlyMemory(), LastModified = context.LastModified });

            var renames = new Dictionary<string, string>(StringComparer.Ordinal);
            if(renamedArchiveManifest is not null)
            {
                renames.Add(AsicManifestNaming.FixedArchiveManifestEntryName, renamedArchiveManifest);
            }

            List<AsicZipEntrySource> entries = CarryEntriesForward(container, replacements, renames, context.LastModified);
            entries.AddRange(additions);

            PooledMemory augmented = WriteContainer(container, entries, context.LastModified, pool);
            try
            {
                return new AsicContainerAugmentationResult
                {
                    Container = augmented,
                    EntryNames = StateEntryNames(container, entries),
                    RaisedSignatureEntryNames = [.. replacements.Keys],
                    ArchiveManifestEntryName = archiveManifestName,
                    RenamedArchiveManifestEntryName = renamedArchiveManifest,
                    ArchiveTimestampEntryName = timestampName,
                    ArchiveTimestampTime = token.Info.GenerationTime,
                    ArchiveManifestChainLength = CountArchiveManifests(entries)
                };
            }
            catch
            {
                augmented.Dispose();

                throw;
            }
        }
        finally
        {
            manifestDocument?.Dispose();
            tokenOctets?.Dispose();
            foreach(PooledMemory replacement in replacements.Values)
            {
                replacement.Dispose();
            }
        }
    }


    /// <summary>
    /// Reads a container, turning the reader's refusal into this surface's typed generator fault.
    /// </summary>
    /// <param name="containerBytes">The container's octets.</param>
    /// <param name="limits">The bounds the container is read within.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <returns>The read result, which the caller disposes.</returns>
    /// <exception cref="AsicContainerAugmentationException">When the octets are not a container this library reads.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the read result transfers to the caller on success; the failure path disposes it before throwing.")]
    private static AsicZipReadResult ReadContainer(ReadOnlyMemory<byte> containerBytes, AsicZipReadLimits limits, MemoryPool<byte> pool)
    {
        AsicZipReadResult read = AsicZipReading.Read(containerBytes, limits, pool);
        if(!read.IsRead)
        {
            AsicZipReadStatus status = read.Status;
            read.Dispose();

            throw new AsicContainerAugmentationException(
                AsicContainerAugmentationFailureKind.ContainerNotRead,
                string.Create(CultureInfo.InvariantCulture, $"The supplied octets are not a container this library reads ({status})."));
        }

        return read;
    }


    /// <summary>
    /// Selects the CAdES objects a container carries, refusing a container carrying none.
    /// </summary>
    /// <param name="container">The container that was read.</param>
    /// <returns>The entries whose names clause 4.4.4.2 item 3 a dispatches as CAdES objects.</returns>
    /// <exception cref="AsicContainerAugmentationException">When the container carries none.</exception>
    private static List<AsicZipEntry> SelectSignatureEntries(AsicZipContainer container)
    {
        var signatures = new List<AsicZipEntry>();
        for(int i = 0; i < container.Entries.Count; ++i)
        {
            AsicZipEntry entry = container.Entries[i];
            if(AsicManifestNaming.IsSignatureEntryName(entry.Name))
            {
                signatures.Add(entry);
            }
        }

        if(signatures.Count == 0)
        {
            throw new AsicContainerAugmentationException(
                AsicContainerAugmentationFailureKind.NoSignatureToRaise,
                "The container carries no META-INF/*signature*.p7s file, and clause 5.1 item 2 states a container's level over the signatures it incorporates.");
        }

        return signatures;
    }


    /// <summary>
    /// Refuses an augmentation that would change the octets of an entry an <c>ASiCArchiveManifest</c> file
    /// already present has committed a time-stamp token to.
    /// </summary>
    /// <param name="container">The container that was read.</param>
    /// <param name="changing">The entries the augmentation would replace.</param>
    /// <param name="what">What the augmentation was going to do, named in the refusal message.</param>
    /// <exception cref="AsicContainerAugmentationException">When the container carries an archive manifest.</exception>
    /// <remarks>
    /// The refusal is deliberately by presence rather than by reference: an archive manifest names "all the
    /// signed and/or time-asserted data and/or signature and/or time-stamp token files requiring long term
    /// validation support" (Annex A.7 item 1 c b)), which is every object one of these augmentations touches, and
    /// a producer that referenced fewer built a chain protecting less than the annex describes. Annex A.7 item
    /// 1 a) states the order this enforces: the signatures reach the level they are to be preserved at, and the
    /// chain is started over them afterwards.
    /// </remarks>
    private static void RefuseWhenArchiveChainWouldBreak(AsicZipContainer container, List<AsicZipEntry> changing, string what)
    {
        for(int i = 0; i < container.Entries.Count; ++i)
        {
            if(!AsicManifestNaming.IsArchiveManifestEntryName(container.Entries[i].Name))
            {
                continue;
            }

            throw new AsicContainerAugmentationException(
                AsicContainerAugmentationFailureKind.WouldBreakArchiveManifestChain,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"'{container.Entries[i].Name}' has committed a time-stamp token to the octets of the container's file objects, so {what} would break the Annex A.7 chain; {changing.Count} file object(s) would have changed."));
        }
    }


    /// <summary>
    /// Refuses the <c>certificate-values</c>/<c>revocation-values</c> route for the one container profile whose
    /// own clause forbids it.
    /// </summary>
    /// <param name="container">The container that was read.</param>
    /// <param name="placement">The route the caller stated.</param>
    /// <exception cref="AsicContainerAugmentationException">When the container is an ASiC-S time assertion container and the route is the unsigned-attribute one.</exception>
    /// <remarks>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916202/01.01.01_60/en_31916202v010101p.pdf">
    /// ETSI EN 319 162-2 V1.1.1</see> clause 4.2.1 d): "if one or more ASiCArchiveManifest files are present they
    /// shall comply with ASiC part 1, clause A.7 with the additional restriction that only <c>SignedData</c> shall
    /// be used to include certificate and revocation information." The restriction binds one profile, so the
    /// container is recognised as that profile structurally — its clause 4.2.1 a) shape: one data file at the
    /// container root, no manifest file, and a <c>META-INF</c> folder carrying a time assertion rather than a
    /// signature (Part 1 clause 4.3.3.2 items 4 a), 4 d) and 4 e)).
    /// </remarks>
    private static void RefuseUnsupportedPlacementForProfile(AsicZipContainer container, AsicValidationMaterialPlacement placement)
    {
        if(placement != AsicValidationMaterialPlacement.CertificateAndRevocationValues || !IsSimpleTimeAssertionContainer(container))
        {
            return;
        }

        throw new AsicContainerAugmentationException(
            AsicContainerAugmentationFailureKind.ValidationMaterialPlacementRefused,
            "ETSI EN 319 162-2 clause 4.2.1 d) restricts the ASiC-S time assertion container to SignedData for certificate and revocation information, so the certificate-values/revocation-values route is refused for it.");
    }


    /// <summary>
    /// Determines whether a container has the shape EN 319 162-2 clause 4.2.1 a) pins for the ASiC-S time
    /// assertion container.
    /// </summary>
    /// <param name="container">The container that was read.</param>
    /// <returns><see langword="true"/> when the container carries one root data file, no manifest and a time assertion rather than a CAdES object.</returns>
    /// <remarks>
    /// This is the one structural profile test the augmentation surface makes, and it exists for exactly one
    /// restriction. Stating a container's profile in general is a reading-side conclusion over the whole of
    /// clause 4.4.4.2 and is not made here.
    /// </remarks>
    private static bool IsSimpleTimeAssertionContainer(AsicZipContainer container)
    {
        int rootDataFiles = 0;
        bool hasTimeAssertion = false;
        for(int i = 0; i < container.Entries.Count; ++i)
        {
            AsicZipEntry entry = container.Entries[i];
            if(entry.IsFolder)
            {
                continue;
            }

            if(AsicManifestNaming.RoleFromEntryName(entry.Name) != AsicManifestRole.NotAManifest
                || AsicManifestNaming.IsSignatureEntryName(entry.Name))
            {
                return false;
            }

            if(AsicManifestNaming.IsTimestampEntryName(entry.Name)
                || AsicManifestNaming.IsBinaryEvidenceRecordEntryName(entry.Name)
                || AsicManifestNaming.IsXmlEvidenceRecordEntryName(entry.Name))
            {
                hasTimeAssertion = true;

                continue;
            }

            if(!entry.IsMetaInf)
            {
                ++rootDataFiles;
            }
        }

        return hasTimeAssertion && rootDataFiles == 1;
    }


    /// <summary>
    /// Refuses a container whose <c>ASiCArchiveManifest</c> files do not include one under the fixed name.
    /// </summary>
    /// <param name="container">The container that was read.</param>
    /// <param name="previousArchiveManifest">The entry carrying the fixed name, or <see langword="null"/> when there is none.</param>
    /// <exception cref="AsicContainerAugmentationException">When archive manifests are present but none carries the fixed name.</exception>
    /// <remarks>
    /// Annex A.7 keeps exactly one archive manifest under <c>META-INF/ASiCArchiveManifest.xml</c> at all times —
    /// item 1 c a) names it for the first addition and item 2 b) i) renames the new one back to it at every
    /// renewal. A container carrying only renamed ones states a chain whose last link cannot be identified, so a
    /// new link cannot be attached to it without guessing which one it follows.
    /// </remarks>
    private static void RefuseUnfixedArchiveManifestChain(AsicZipContainer container, AsicZipEntry? previousArchiveManifest)
    {
        if(previousArchiveManifest is not null)
        {
            return;
        }

        for(int i = 0; i < container.Entries.Count; ++i)
        {
            if(!AsicManifestNaming.IsArchiveManifestEntryName(container.Entries[i].Name))
            {
                continue;
            }

            throw new AsicContainerAugmentationException(
                AsicContainerAugmentationFailureKind.ArchiveManifestChainMalformed,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"The container carries '{container.Entries[i].Name}' but nothing named '{AsicManifestNaming.FixedArchiveManifestEntryName}', so Annex A.7's last chain link cannot be identified."));
        }
    }


    /// <summary>
    /// States the level one CAdES object reaches: the lowest level of its own signers.
    /// </summary>
    /// <param name="signature">The CAdES object's octets.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <returns>The level.</returns>
    private static AsicContainerLevel StateSignatureLevel(ReadOnlySpan<byte> signature, MemoryPool<byte> pool)
    {
        using CmsSignedData signedData = CmsSignedData.FromBytes(signature, pool);
        bool carriesRevocationInformation = CmsSignedDataAugmentation.ReadRevocationInformation(signedData).Count > 0;

        int signers = CmsSignedDataAugmentation.CountSigners(signedData);
        AsicContainerLevel lowest = AsicContainerLevel.NotEvaluated;
        for(int signerIndex = 0; signerIndex < signers; ++signerIndex)
        {
            bool hasArchiveTimestamp = false;
            bool hasRevocationValues = carriesRevocationInformation;
            bool hasSignatureTimestamp = false;

            IReadOnlyList<CmsUnsignedAttributeValueLocation> attributes =
                CmsSignedDataAugmentation.LocateUnsignedAttributeValues(signedData, signerIndex);
            for(int i = 0; i < attributes.Count; ++i)
            {
                string type = attributes[i].AttributeType;
                hasArchiveTimestamp = hasArchiveTimestamp
                    || string.Equals(type, CAdESSignatureFacts.ArchiveTimestampV3AttributeOid, StringComparison.Ordinal)
                    || string.Equals(type, CAdESSignatureFacts.ArchiveTimestampV2AttributeOid, StringComparison.Ordinal)
                    || string.Equals(type, CAdESSignatureFacts.LongTermValidationAttributeOid, StringComparison.Ordinal);
                hasRevocationValues = hasRevocationValues
                    || string.Equals(type, CAdESSignatureFacts.RevocationValuesAttributeOid, StringComparison.Ordinal);
                hasSignatureTimestamp = hasSignatureTimestamp
                    || string.Equals(type, CAdESSignatureFacts.SignatureTimestampAttributeOid, StringComparison.Ordinal);
            }

            AsicContainerLevel level = (hasArchiveTimestamp, hasRevocationValues, hasSignatureTimestamp) switch
            {
                (true, _, _) => AsicContainerLevel.BaselineLTA,
                (false, true, _) => AsicContainerLevel.BaselineLT,
                (false, false, true) => AsicContainerLevel.BaselineT,
                _ => AsicContainerLevel.BaselineB
            };

            lowest = lowest == AsicContainerLevel.NotEvaluated || level < lowest ? level : lowest;
        }

        return lowest == AsicContainerLevel.NotEvaluated ? AsicContainerLevel.BaselineB : lowest;
    }


    /// <summary>
    /// Adds a <c>signature-time-stamp</c> to every signer of one CAdES object.
    /// </summary>
    /// <param name="signature">The object's octets.</param>
    /// <param name="context">The augmentation context, carrying the imprint algorithm and the authority to contact.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The augmented object. The caller owns and disposes it.</returns>
    /// <remarks>
    /// Every signer is raised because clause 5.1 item 2 states a container's level over the signatures it
    /// incorporates without distinguishing which <c>SignerInfo</c> of which file object carries them: an object
    /// whose second signer stayed at B-B caps the container just as a second file object would. The context
    /// travels as a parameter rather than being captured, the same no-closure discipline the seams keep.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The object walked forward is held in one local the finally disposes unconditionally, and is nulled out where ownership transfers to the caller; the rule's data flow does not follow that transfer across the awaited augmentation. The exact try/finally shape the rule prescribes is what is written here.")]
    private static async ValueTask<CmsSignedData> AddSignatureTimestampToEverySignerAsync(
        ReadOnlyMemory<byte> signature,
        AsicContainerSignatureTimestampContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        CmsSignedData? current = null;
        try
        {
            current = CmsSignedData.FromBytes(signature.Span, pool);
            int signers = CmsSignedDataAugmentation.CountSigners(current);
            for(int signerIndex = 0; signerIndex < signers; ++signerIndex)
            {
                CmsSignedData raised = await CAdESSignatureAugmentation.AddSignatureTimestampAsync(
                    new CAdESSignatureTimestampContext
                    {
                        SignedData = current,
                        SignerIndex = signerIndex,
                        MessageImprintAlgorithm = context.MessageImprintAlgorithm,
                        TsaUri = context.TsaUri,
                        FetchResponse = context.FetchTimestampResponse,
                        ReqPolicyOid = context.TimestampPolicyOid,
                        SigningCertificate = context.SigningCertificate,
                        SigningCertificateRevokedAt = context.SigningCertificateRevokedAt,
                        EnforceSigningCertificateValidity = context.EnforceSigningCertificateValidity
                    },
                    pool,
                    cancellationToken).ConfigureAwait(false);

                current.Dispose();
                current = raised;
            }

            CmsSignedData raisedObject = current;
            current = null;

            return raisedObject;
        }
        finally
        {
            current?.Dispose();
        }
    }


    /// <summary>
    /// Adds an <c>archive-time-stamp-v3</c> to every signer of one CAdES object.
    /// </summary>
    /// <param name="signature">The object's octets, with any validation material already placed.</param>
    /// <param name="context">The augmentation context, carrying the imprint algorithm and the authority to contact.</param>
    /// <param name="detachedContentDigest">The digest of the file object the CAdES object is detached across.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The augmented object. The caller owns and disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The object walked forward is held in one local the finally disposes unconditionally, and is nulled out where ownership transfers to the caller; the rule's data flow does not follow that transfer across the awaited augmentation. The exact try/finally shape the rule prescribes is what is written here.")]
    private static async ValueTask<CmsSignedData> AddArchiveTimestampToEverySignerAsync(
        ReadOnlyMemory<byte> signature,
        AsicContainerSignatureArchiveTimestampContext context,
        DigestValue detachedContentDigest,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        CmsSignedData? current = null;
        try
        {
            current = CmsSignedData.FromBytes(signature.Span, pool);
            int signers = CmsSignedDataAugmentation.CountSigners(current);
            for(int signerIndex = 0; signerIndex < signers; ++signerIndex)
            {
                CmsSignedData raised = await CAdESSignatureAugmentation.AddArchiveTimestampAsync(
                    new CAdESArchiveTimestampContext
                    {
                        SignedData = current,
                        SignerIndex = signerIndex,
                        MessageImprintAlgorithm = context.MessageImprintAlgorithm,
                        TsaUri = context.TsaUri,
                        FetchResponse = context.FetchTimestampResponse,
                        ValidationMaterial = CAdESValidationMaterial.None,
                        DetachedSignedContentDigest = detachedContentDigest,
                        ReqPolicyOid = context.TimestampPolicyOid,
                        SigningCertificate = context.SigningCertificate,
                        SigningCertificateRevokedAt = context.SigningCertificateRevokedAt,
                        EnforceSigningCertificateValidity = context.EnforceSigningCertificateValidity
                    },
                    pool,
                    cancellationToken).ConfigureAwait(false);

                current.Dispose();
                current = raised;
            }

            CmsSignedData raisedObject = current;
            current = null;

            return raisedObject;
        }
        finally
        {
            current?.Dispose();
        }
    }


    /// <summary>
    /// Places validation material into one CMS object through the route the caller stated, refusing when
    /// EN 319 122-1 clause 5.5.3 selects the other one.
    /// </summary>
    /// <param name="objectOctets">The CMS object's octets.</param>
    /// <param name="entryName">The entry the object is stored under, named in a refusal message.</param>
    /// <param name="material">The material to place.</param>
    /// <param name="placement">The route the caller stated.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <returns>The object with the material placed. The caller owns and disposes it.</returns>
    /// <exception cref="AsicContainerAugmentationException">When the object's own state does not admit the stated route.</exception>
    /// <remarks>
    /// Annex A.7 item 1 b)'s "as specified in CAdES" is what makes this a check rather than a switch: clause
    /// 5.5.3 states with <em>shall</em> which of the two routes applies to a given object, so a stated route the
    /// object contradicts is a request to write material where that clause forbids it.
    /// </remarks>
    private static CmsSignedData PlaceValidationMaterial(
        ReadOnlySpan<byte> objectOctets,
        string entryName,
        CAdESValidationMaterial material,
        AsicValidationMaterialPlacement placement,
        MemoryPool<byte> pool)
    {
        using CmsSignedData signedData = CmsSignedData.FromBytes(objectOctets, pool);
        CAdESValidationDataPlacement selected = CAdESSignatureAugmentation.DetectValidationDataPlacement(signedData);

        bool agrees = (placement, selected) switch
        {
            (AsicValidationMaterialPlacement.SignedDataFields, CAdESValidationDataPlacement.RootSignedData) => true,
            (AsicValidationMaterialPlacement.CertificateAndRevocationValues, CAdESValidationDataPlacement.LatestArchiveTimestampToken) => true,
            _ => false
        };

        if(!agrees)
        {
            throw new AsicContainerAugmentationException(
                AsicContainerAugmentationFailureKind.ValidationMaterialPlacementRefused,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"'{entryName}' states the '{placement}' route of Annex A.7 item 1 b), and ETSI EN 319 122-1 clause 5.5.3 selects '{selected}' for that object."));
        }

        return CAdESSignatureAugmentation.AddValidationData(signedData, signerIndex: 0, material, pool);
    }


    /// <summary>
    /// Places validation material into one CMS object, or copies the object when there is none to place.
    /// </summary>
    /// <param name="objectOctets">The CMS object's octets.</param>
    /// <param name="entryName">The entry the object is stored under, named in a refusal message.</param>
    /// <param name="material">The material to place; <see cref="CAdESValidationMaterial.None"/> states there is none.</param>
    /// <param name="placement">The route the caller stated.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <returns>The object, with the material placed when there was any. The caller owns and disposes it.</returns>
    /// <exception cref="AsicContainerAugmentationException">When the object's own state does not admit the stated route.</exception>
    /// <remarks>
    /// The copy rather than a borrowed view is what makes the two branches interchangeable at the call site:
    /// either way the caller owns exactly one carrier, which is the shape
    /// <see cref="CAdESSignatureAugmentation.AddArchiveTimestampAsync"/> takes for the same reason.
    /// </remarks>
    private static CmsSignedData CopyOrPlaceValidationMaterial(
        ReadOnlySpan<byte> objectOctets,
        string entryName,
        CAdESValidationMaterial material,
        AsicValidationMaterialPlacement placement,
        MemoryPool<byte> pool) =>
        material.IsEmpty
            ? CmsSignedData.FromBytes(objectOctets, pool)
            : PlaceValidationMaterial(objectOctets, entryName, material, placement, pool);


    /// <summary>
    /// Places validation material into the objects Annex A.7 still admits it in, and records the replacements.
    /// </summary>
    /// <param name="container">The container that was read.</param>
    /// <param name="renewableTokenEntryName">The token the last archive manifest applies to, or <see langword="null"/> on a first addition.</param>
    /// <param name="material">The material to place.</param>
    /// <param name="placement">The route the caller stated.</param>
    /// <param name="replacements">The map the produced octets are recorded in; the caller disposes what it holds.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <exception cref="AsicContainerAugmentationException">When an object's own state does not admit the stated route.</exception>
    private static void CollectValidationMaterialPlacements(
        AsicZipContainer container,
        string? renewableTokenEntryName,
        CAdESValidationMaterial material,
        AsicValidationMaterialPlacement placement,
        Dictionary<string, PooledMemory> replacements,
        MemoryPool<byte> pool)
    {
        for(int i = 0; i < container.Entries.Count; ++i)
        {
            AsicZipEntry entry = container.Entries[i];
            bool admitted = renewableTokenEntryName is null
                ? AsicManifestNaming.IsSignatureEntryName(entry.Name) || AsicManifestNaming.IsTimestampEntryName(entry.Name)
                : string.Equals(entry.Name, renewableTokenEntryName, StringComparison.Ordinal);

            if(!admitted)
            {
                continue;
            }

            using CmsSignedData placed = PlaceValidationMaterial(entry.Content.AsReadOnlySpan(), entry.Name, material, placement, pool);
            replacements.Add(entry.Name, PooledMemory.FromBytes(placed.AsReadOnlySpan(), pool, AsicTags.ContainerEntry));
        }
    }


    /// <summary>
    /// States which file object each CAdES object of the container is detached across.
    /// </summary>
    /// <param name="container">The container that was read.</param>
    /// <param name="signatures">The CAdES objects the container carries.</param>
    /// <param name="parseManifest">The manifest seam, or <see langword="null"/> when the caller supplied none.</param>
    /// <param name="limits">The bounds every manifest is parsed within.</param>
    /// <param name="maximumEntryNameByteLength">The run's own entry-name octet bound, so that a <c>SigReference</c> resolves to exactly the names this run's reader carried.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The detached content of every CAdES object, keyed by the entry it is stored under.</returns>
    /// <exception cref="AsicContainerAugmentationException">When the seam is missing, refuses a document, or the container does not state what a signature is detached over.</exception>
    private static async ValueTask<IReadOnlyDictionary<string, ReadOnlyMemory<byte>>> ResolveDetachedContentAsync(
        AsicZipContainer container,
        List<AsicZipEntry> signatures,
        ParseAsicManifestDelegate? parseManifest,
        AsicManifestParseLimits limits,
        int maximumEntryNameByteLength,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        var resolved = new Dictionary<string, ReadOnlyMemory<byte>>(StringComparer.Ordinal);
        var manifests = new List<AsicZipEntry>();
        for(int i = 0; i < container.Entries.Count; ++i)
        {
            if(AsicManifestNaming.IsSignatureManifestEntryName(container.Entries[i].Name))
            {
                manifests.Add(container.Entries[i]);
            }
        }

        if(manifests.Count == 0)
        {
            //An ASiC-S container carries no manifest: clause 4.3.3.2 item 4 b makes META-INF/signature.p7s a
            //detached signature over the single data file the container root carries.
            AsicZipEntry? dataFile = SelectSingleRootDataFile(container);
            for(int i = 0; i < signatures.Count; ++i)
            {
                if(dataFile is null)
                {
                    throw new AsicContainerAugmentationException(
                        AsicContainerAugmentationFailureKind.DetachedContentNotResolvable,
                        string.Create(
                            CultureInfo.InvariantCulture,
                            $"'{signatures[i].Name}' is carried by a container with no manifest file and no single data file at its root, so what the signature is detached over is not stated."));
                }

                resolved[signatures[i].Name] = dataFile.Content.AsReadOnlyMemory();
            }

            return resolved;
        }

        if(parseManifest is null)
        {
            throw new AsicContainerAugmentationException(
                AsicContainerAugmentationFailureKind.ManifestParserMissing,
                "An ASiC-E CAdES object is detached over the ASiCManifest file naming it (Annex A.4.1), and no manifest parsing seam was supplied to read which manifest that is.");
        }

        for(int i = 0; i < manifests.Count; ++i)
        {
            AsicZipEntry manifestEntry = manifests[i];
            using AsicManifestParseResult parsed = await parseManifest(
                new AsicManifestParseContext { Document = manifestEntry.Content, Limits = limits }, pool, cancellationToken).ConfigureAwait(false);

            if(!parsed.IsValid || parsed.Manifest is null)
            {
                throw new AsicContainerAugmentationException(
                    AsicContainerAugmentationFailureKind.ManifestParseFailed,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"'{manifestEntry.Name}' was not read by the manifest parsing seam ({parsed.Status}): {parsed.FailureReason ?? "no reason stated"}."));
            }

            AsicContainerUriResolution reference = AsicContainerUri.Resolve(
                parsed.Manifest.SignatureReference.Uri, limits.MaximumUriLength, maximumEntryNameByteLength);

            if(reference.Status == AsicContainerUriStatus.Resolved && reference.EntryName is { } referenced)
            {
                for(int j = 0; j < signatures.Count; ++j)
                {
                    if(string.Equals(signatures[j].Name, referenced, StringComparison.Ordinal))
                    {
                        resolved[referenced] = manifestEntry.Content.AsReadOnlyMemory();
                    }
                }
            }
        }

        for(int i = 0; i < signatures.Count; ++i)
        {
            if(!resolved.ContainsKey(signatures[i].Name))
            {
                throw new AsicContainerAugmentationException(
                    AsicContainerAugmentationFailureKind.DetachedContentNotResolvable,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"No ASiCManifest file of the container names '{signatures[i].Name}' in its SigReference, so what that signature is detached over is not stated."));
            }
        }

        return resolved;
    }


    /// <summary>
    /// Selects the single data file at the container root, when the container carries exactly one.
    /// </summary>
    /// <param name="container">The container that was read.</param>
    /// <returns>The entry, or <see langword="null"/> when the container carries none or several.</returns>
    private static AsicZipEntry? SelectSingleRootDataFile(AsicZipContainer container)
    {
        AsicZipEntry? found = null;
        for(int i = 0; i < container.Entries.Count; ++i)
        {
            AsicZipEntry entry = container.Entries[i];
            if(entry.IsFolder || entry.IsMetaInf || AsicWellKnown.IsMimetypeEntryName(entry.Name))
            {
                continue;
            }

            if(found is not null)
            {
                return null;
            }

            found = entry;
        }

        return found;
    }


    /// <summary>
    /// States the entry name an archive manifest's <c>SigReference</c> names.
    /// </summary>
    /// <param name="archiveManifest">The archive manifest entry.</param>
    /// <param name="parseManifest">The manifest seam, or <see langword="null"/> when the caller supplied none.</param>
    /// <param name="limits">The bounds the manifest is parsed within.</param>
    /// <param name="maximumEntryNameByteLength">The run's own entry-name octet bound, so that the <c>SigReference</c> resolves to exactly the names this run's reader carried.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The entry name the manifest's <c>SigReference</c> resolves to.</returns>
    /// <exception cref="AsicContainerAugmentationException">When the seam is missing, refuses the document, or the reference does not resolve.</exception>
    private static async ValueTask<string> ResolveArchiveTimestampEntryNameAsync(
        AsicZipEntry archiveManifest,
        ParseAsicManifestDelegate? parseManifest,
        AsicManifestParseLimits limits,
        int maximumEntryNameByteLength,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        if(parseManifest is null)
        {
            throw new AsicContainerAugmentationException(
                AsicContainerAugmentationFailureKind.ManifestParserMissing,
                "Annex A.7 item 2 completes the validation material of the token applied to the last ASiCArchiveManifest file, and no manifest parsing seam was supplied to read which token that is.");
        }

        using AsicManifestParseResult parsed = await parseManifest(
            new AsicManifestParseContext { Document = archiveManifest.Content, Limits = limits }, pool, cancellationToken).ConfigureAwait(false);

        if(!parsed.IsValid || parsed.Manifest is null)
        {
            throw new AsicContainerAugmentationException(
                AsicContainerAugmentationFailureKind.ManifestParseFailed,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"'{archiveManifest.Name}' was not read by the manifest parsing seam ({parsed.Status}): {parsed.FailureReason ?? "no reason stated"}."));
        }

        AsicContainerUriResolution reference = AsicContainerUri.Resolve(
            parsed.Manifest.SignatureReference.Uri, limits.MaximumUriLength, maximumEntryNameByteLength);

        if(reference.Status != AsicContainerUriStatus.Resolved || reference.EntryName is not { } entryName)
        {
            throw new AsicContainerAugmentationException(
                AsicContainerAugmentationFailureKind.ArchiveManifestChainMalformed,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"The SigReference of '{archiveManifest.Name}' does not resolve to a container entry ({reference.Status})."));
        }

        return entryName;
    }


    /// <summary>
    /// States the file objects the new archive manifest references: every entry the container carries except the
    /// media type entry, the folder entries, and the two files this augmentation is about to add.
    /// </summary>
    /// <param name="container">The container that was read.</param>
    /// <param name="replacements">The objects whose octets this augmentation replaced, whose new octets the digests are taken over.</param>
    /// <param name="renamedArchiveManifest">The name the previous archive manifest is renamed to, or <see langword="null"/> on a first addition.</param>
    /// <param name="lastModified">The instant an entry recording none records.</param>
    /// <returns>The entries to reference, under the names they carry in the augmented container.</returns>
    /// <exception cref="AsicContainerAugmentationException">When the container states nothing to reference.</exception>
    /// <remarks>
    /// Annex A.7 item 1 c b) says "reference all the signed and/or time-asserted data and/or signature and/or
    /// time-stamp token files requiring long term validation support" and item 2 b) iii) widens it to "all the
    /// file objects referenced by the ASiCArchiveManifest files already present, the ASiCArchiveManifest files
    /// already present, and the time-stamp tokens that apply to them". Referencing every file object rather than
    /// a chosen subset is the maximal reading of both, and the safe one: an object left unreferenced is an object
    /// the archive time-stamp does not protect. The media type entry is excluded because Annex A.1 fixes its
    /// content, position and encoding as part of the archive's own structure rather than as a file object, and
    /// folder entries because they carry no content to take a digest of.
    /// </remarks>
    private static List<AsicZipEntrySource> BuildCoveredEntries(
        AsicZipContainer container,
        Dictionary<string, PooledMemory> replacements,
        string? renamedArchiveManifest,
        DateTimeOffset lastModified)
    {
        var covered = new List<AsicZipEntrySource>(container.Entries.Count);
        for(int i = 0; i < container.Entries.Count; ++i)
        {
            AsicZipEntry entry = container.Entries[i];
            if(entry.IsFolder || AsicWellKnown.IsMimetypeEntryName(entry.Name))
            {
                continue;
            }

            string name = renamedArchiveManifest is not null
                && string.Equals(entry.Name, AsicManifestNaming.FixedArchiveManifestEntryName, StringComparison.Ordinal)
                    ? renamedArchiveManifest
                    : entry.Name;

            ReadOnlyMemory<byte> content = replacements.TryGetValue(entry.Name, out PooledMemory? replacement)
                ? replacement.AsReadOnlyMemory()
                : entry.Content.AsReadOnlyMemory();

            covered.Add(new AsicZipEntrySource
            {
                Name = name,
                Content = content,
                CompressionMethod = entry.CompressionMethod,
                LastModified = entry.LastModified ?? lastModified
            });
        }

        if(covered.Count == 0)
        {
            throw new AsicContainerAugmentationException(
                AsicContainerAugmentationFailureKind.NothingToArchive,
                "The container carries no file object an ASiCArchiveManifest could reference (Annex A.7 item 1 c b)).");
        }

        return covered;
    }


    /// <summary>
    /// Builds the new <c>ASiCArchiveManifest</c> element and writes it through the caller's seam.
    /// </summary>
    /// <param name="context">The augmentation context, carrying the seam and the digest algorithm.</param>
    /// <param name="covered">The file objects the manifest references.</param>
    /// <param name="timestampEntryName">The entry the <c>SigReference</c> names.</param>
    /// <param name="renamedArchiveManifest">The name the previous archive manifest was renamed to, which alone carries <c>Rootfile</c>, or <see langword="null"/> on a first addition.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The manifest document's octets. The caller owns and disposes them.</returns>
    /// <exception cref="AsicContainerAugmentationException">When the seam produced no document.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every digest and reference built here transfers to the manifest, which the using disposes; the returned document is the caller's.")]
    private static async ValueTask<PooledMemory> WriteArchiveManifestAsync(
        AsicContainerArchiveTimestampContext context,
        List<AsicZipEntrySource> covered,
        string timestampEntryName,
        string? renamedArchiveManifest,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        var references = new List<AsicDataObjectReference>(covered.Count);
        try
        {
            for(int i = 0; i < covered.Count; ++i)
            {
                AsicZipEntrySource entry = covered[i];
                DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                    entry.Content, context.DigestAlgorithm.OutputByteLength, context.DigestAlgorithm.DigestTag, pool,
                    cancellationToken: cancellationToken).ConfigureAwait(false);

                references.Add(new AsicDataObjectReference
                {
                    Uri = AsicContainerUri.ToReference(entry.Name, context.ReadLimits.MaximumEntryNameByteLength),
                    DigestAlgorithm = context.DigestAlgorithm,
                    Digest = digest,
                    IsRootFile = renamedArchiveManifest is not null && string.Equals(entry.Name, renamedArchiveManifest, StringComparison.Ordinal) ? true : null
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
                Uri = AsicContainerUri.ToReference(timestampEntryName, context.ReadLimits.MaximumEntryNameByteLength),
                MimeType = context.TimestampReferenceMediaType
            },
            DataObjectReferences = references
        };

        using AsicManifestEncodeResult encoded = await context.EncodeManifest(
            new AsicManifestEncodeContext { Manifest = manifest }, pool, cancellationToken).ConfigureAwait(false);

        if(!encoded.IsEncoded || encoded.Document is null)
        {
            throw new AsicContainerAugmentationException(
                AsicContainerAugmentationFailureKind.ManifestEncodingFailed,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"The manifest serialisation seam produced no ASiCArchiveManifest document ({encoded.Status}): {encoded.FailureReason ?? "no reason stated"}."));
        }

        return PooledMemory.FromBytes(encoded.Document.AsReadOnlySpan(), pool, AsicTags.Manifest);
    }


    /// <summary>
    /// Carries a container's entries forward, applying the replacements and the renames and nothing else.
    /// </summary>
    /// <param name="container">The container that was read.</param>
    /// <param name="replacements">The entries whose octets change, keyed by their present names.</param>
    /// <param name="renames">The entries whose names change, keyed by their present names.</param>
    /// <param name="lastModified">The instant an entry recording none records.</param>
    /// <returns>The entries, in the order the container carries them, with the media type entry left out.</returns>
    /// <remarks>
    /// The media type entry is left out because <see cref="AsicZipAuthoring.Write"/> writes it itself from
    /// <see cref="AsicZipAuthoringContext.MediaType"/>: Annex A.1 binds its position, its compression method and
    /// its extra field length together, so the author owns it rather than taking it as an entry.
    /// </remarks>
    private static List<AsicZipEntrySource> CarryEntriesForward(
        AsicZipContainer container,
        Dictionary<string, PooledMemory> replacements,
        Dictionary<string, string> renames,
        DateTimeOffset lastModified)
    {
        var entries = new List<AsicZipEntrySource>(container.Entries.Count);
        for(int i = 0; i < container.Entries.Count; ++i)
        {
            AsicZipEntry entry = container.Entries[i];
            if(AsicWellKnown.IsMimetypeEntryName(entry.Name))
            {
                continue;
            }

            ReadOnlyMemory<byte> content = replacements.TryGetValue(entry.Name, out PooledMemory? replacement)
                ? replacement.AsReadOnlyMemory()
                : entry.Content.AsReadOnlyMemory();

            entries.Add(new AsicZipEntrySource
            {
                Name = renames.TryGetValue(entry.Name, out string? renamed) ? renamed : entry.Name,
                Content = content,
                CompressionMethod = entry.CompressionMethod,
                LastModified = entry.LastModified ?? lastModified
            });
        }

        return entries;
    }


    /// <summary>
    /// Writes a container from the entries carried forward, keeping its media type and archive comment.
    /// </summary>
    /// <param name="container">The container that was read, whose media type and comment are kept.</param>
    /// <param name="entries">The entries to write.</param>
    /// <param name="lastModified">The instant an entry recording none records.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <returns>The container's octets. The caller owns and disposes them.</returns>
    private static PooledMemory WriteContainer(
        AsicZipContainer container,
        List<AsicZipEntrySource> entries,
        DateTimeOffset lastModified,
        MemoryPool<byte> pool) =>
        AsicZipAuthoring.Write(
            new AsicZipAuthoringContext
            {
                MediaType = container.MediaType,
                Entries = entries,
                LastModified = lastModified,
                ArchiveComment = container.ArchiveComment
            },
            pool);


    /// <summary>
    /// States every entry name the augmented container carries, the media type entry first when it has one.
    /// </summary>
    /// <param name="container">The container that was read.</param>
    /// <param name="entries">The entries that were written.</param>
    /// <returns>The names, in the order they appear in the augmented container.</returns>
    private static List<string> StateEntryNames(AsicZipContainer container, List<AsicZipEntrySource> entries)
    {
        var names = new List<string>(entries.Count + 1);
        if(container.MediaType is not null)
        {
            names.Add(AsicWellKnown.MimetypeEntryName);
        }

        for(int i = 0; i < entries.Count; ++i)
        {
            names.Add(entries[i].Name);
        }

        return names;
    }


    /// <summary>
    /// Counts the <c>ASiCArchiveManifest</c> files a written entry set carries — the length of the Annex A.7
    /// chain the container states.
    /// </summary>
    /// <param name="entries">The entries that were written.</param>
    /// <returns>The count.</returns>
    private static int CountArchiveManifests(List<AsicZipEntrySource> entries)
    {
        int count = 0;
        for(int i = 0; i < entries.Count; ++i)
        {
            if(AsicManifestNaming.IsArchiveManifestEntryName(entries[i].Name))
            {
                ++count;
            }
        }

        return count;
    }


    /// <summary>
    /// Writes the container the three <c>AddSignature*</c> augmentations produce: the same entries, with the
    /// raised CAdES objects in place of the ones that were there.
    /// </summary>
    /// <param name="container">The container that was read.</param>
    /// <param name="replacements">The raised objects, keyed by the entry they are stored under.</param>
    /// <param name="signatures">The CAdES objects that were raised.</param>
    /// <param name="lastModified">The instant an entry recording none records.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <returns>The augmented container. The caller owns and disposes it.</returns>
    private static AsicContainerAugmentationResult AssembleRaised(
        AsicZipContainer container,
        Dictionary<string, PooledMemory> replacements,
        List<AsicZipEntry> signatures,
        DateTimeOffset lastModified,
        MemoryPool<byte> pool)
    {
        List<AsicZipEntrySource> entries = CarryEntriesForward(container, replacements, new Dictionary<string, string>(StringComparer.Ordinal), lastModified);
        PooledMemory augmented = WriteContainer(container, entries, lastModified, pool);
        try
        {
            var raised = new List<string>(signatures.Count);
            for(int i = 0; i < signatures.Count; ++i)
            {
                raised.Add(signatures[i].Name);
            }

            return new AsicContainerAugmentationResult
            {
                Container = augmented,
                EntryNames = StateEntryNames(container, entries),
                RaisedSignatureEntryNames = raised,
                ArchiveManifestChainLength = CountArchiveManifests(entries)
            };
        }
        catch
        {
            augmented.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Refuses a digest algorithm this surface must not augment a container under, reusing the one place the
    /// creation-side rule lives.
    /// </summary>
    /// <param name="digestAlgorithm">The digest algorithm to assess.</param>
    /// <param name="algorithmConstraints">The optional dated cryptographic-constraints table.</param>
    /// <param name="instant">The instant to assess <paramref name="algorithmConstraints"/> at.</param>
    /// <param name="use">What the algorithm is used for, named in the refusal message.</param>
    /// <exception cref="AsicContainerAugmentationException">When the algorithm is refused.</exception>
    /// <remarks>
    /// The rule is <see cref="AsicContainerCreation"/>'s — clause 5.2.1's MD5 prohibition, this library's
    /// creation-side SHA-1 line, an algorithm it does not compute, and a supplied constraints table — and it
    /// exists once so that a container cannot be augmented under an algorithm it could not have been created
    /// under. Only the typed fault differs, because the two surfaces report their own.
    /// </remarks>
    private static void EnsureDigestAlgorithmAllowed(
        PkiDigestAlgorithm digestAlgorithm,
        CryptographicConstraints? algorithmConstraints,
        DateTimeOffset instant,
        string use)
    {
        try
        {
            AsicContainerCreation.EnsureDigestAlgorithmAllowedForCreation(digestAlgorithm, algorithmConstraints, instant, use);
        }
        catch(AsicContainerCreationException refusal)
        {
            throw new AsicContainerAugmentationException(
                AsicContainerAugmentationFailureKind.DigestAlgorithmRefused, refusal.Message, refusal);
        }
    }
}
