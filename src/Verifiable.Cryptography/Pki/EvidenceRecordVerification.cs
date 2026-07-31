using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Names why an Evidence Record could not be created.
/// </summary>
/// <remarks>
/// These are generator-side faults: an input the caller supplied that a conformant
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-3.2">RFC 4998 clause 3.2</see> record cannot be
/// built from. They are deliberately not <see cref="EvidenceRecordVerificationStatus"/>, which describes what a
/// verifier concludes about a record it did not make, following the same split
/// <see cref="CAdESAugmentationFailureKind"/> makes for CAdES.
/// </remarks>
public enum EvidenceRecordCreationFailureKind
{
    /// <summary>No failure has been classified.</summary>
    NotEvaluated = 0,

    /// <summary>No data object group, or a group holding no data object, was supplied.</summary>
    NoDataObject = 1,

    /// <summary>
    /// The acquired time-stamp token does not bind the root hash the tree produced, so attaching it would state
    /// a proof of existence for something else. Clause 4.2 step 5 obtains the time-stamp "for this root hash
    /// value" and nothing else.
    /// </summary>
    TimestampDoesNotBindRoot = 2,

    /// <summary>
    /// The time-stamp token's own <c>TSTInfo</c> could not be read, or its message imprint names an algorithm
    /// this library cannot compute, so nothing about what it binds can be established.
    /// </summary>
    TimestampNotUsable = 3,

    /// <summary>No Evidence Record was supplied to a renewal, which has nothing to renew.</summary>
    NoEvidenceRecord = 4,

    /// <summary>
    /// An Evidence Record supplied to a renewal carries no <c>ArchiveTimeStampChain</c>, or its most recent
    /// chain carries no <c>ArchiveTimeStamp</c>, so there is no structure for the renewal to build on.
    /// </summary>
    RenewalSourceMalformed = 5,

    /// <summary>
    /// Several Evidence Records were renewed together by Timestamp Renewal but their chains do not share one
    /// hash algorithm, and clause 5.2 binds the new hash tree to "the same hash algorithm as the old one", which
    /// one tree over all of them cannot satisfy for more than one algorithm at a time.
    /// </summary>
    RenewalAlgorithmMismatch = 6,

    /// <summary>
    /// The acquired time-stamp asserts a <c>genTime</c> that is not after the Archive Timestamp being renewed,
    /// so appending it would produce a structure clause 5.1 rejects: "ArchiveTimeStampChain and
    /// ArchiveTimeStampSequence MUST be ordered ascending by time of timestamp."
    /// </summary>
    RenewalNotAfterSource = 7,

    /// <summary>
    /// The CMS signature an Evidence Record was to be attached to already carries one, and
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#appendix-A">clause A</see> states the attributes
    /// "SHOULD only occur once". Attaching a further one is the documented departure a caller states through
    /// <see cref="EvidenceRecordCmsAttachmentPolicy.ChronologicalSequence"/>.
    /// </summary>
    EvidenceRecordAlreadyAttached = 8
}


/// <summary>
/// The generator-side fault of an Evidence Record creation.
/// </summary>
/// <remarks>
/// Creation reports faults as exceptions, following the CAdES creation and augmentation surfaces already in
/// this library: a generator handing in material a record cannot be built from is a composition fault of the
/// caller rather than an adversarial input to be classified and reported.
/// </remarks>
[DebuggerDisplay("EvidenceRecordCreationException({FailureKind}): {Message}")]
public sealed class EvidenceRecordCreationException: Exception
{
    /// <summary>Gets what could not be done.</summary>
    public EvidenceRecordCreationFailureKind FailureKind { get; }


    /// <summary>Initializes a new <see cref="EvidenceRecordCreationException"/> with an unclassified fault.</summary>
    public EvidenceRecordCreationException(): this(EvidenceRecordCreationFailureKind.NoDataObject, "The Evidence Record could not be created.")
    {
    }


    /// <summary>Initializes a new <see cref="EvidenceRecordCreationException"/> with an unclassified fault.</summary>
    /// <param name="message">The message describing the fault.</param>
    public EvidenceRecordCreationException(string message): this(EvidenceRecordCreationFailureKind.NoDataObject, message)
    {
    }


    /// <summary>Initializes a new <see cref="EvidenceRecordCreationException"/> with an unclassified fault.</summary>
    /// <param name="message">The message describing the fault.</param>
    /// <param name="innerException">The exception that caused it.</param>
    public EvidenceRecordCreationException(string message, Exception innerException)
        : this(EvidenceRecordCreationFailureKind.NoDataObject, message, innerException)
    {
    }


    /// <summary>Initializes a new <see cref="EvidenceRecordCreationException"/>.</summary>
    /// <param name="failureKind">What could not be done.</param>
    /// <param name="message">The message describing the fault.</param>
    public EvidenceRecordCreationException(EvidenceRecordCreationFailureKind failureKind, string message): base(message)
    {
        FailureKind = failureKind;
    }


    /// <summary>Initializes a new <see cref="EvidenceRecordCreationException"/>.</summary>
    /// <param name="failureKind">What could not be done.</param>
    /// <param name="message">The message describing the fault.</param>
    /// <param name="innerException">The exception that caused it.</param>
    public EvidenceRecordCreationException(EvidenceRecordCreationFailureKind failureKind, string message, Exception innerException)
        : base(message, innerException)
    {
        FailureKind = failureKind;
    }
}


/// <summary>
/// What a verifier concluded about an Evidence Record, an <c>ArchiveTimeStampChain</c>, or one
/// <c>ArchiveTimeStamp</c>.
/// </summary>
/// <remarks>
/// <see cref="NotVerified"/> occupies zero so a default-initialised status never reads as a successful
/// verification, mirroring <see cref="ArchiveTimestampCoverageStatus"/> and
/// <see cref="TimestampTokenInfoStatus"/>.
/// </remarks>
public enum EvidenceRecordVerificationStatus
{
    /// <summary>No verification has been attempted. The value of an unset field, by design.</summary>
    NotVerified = 0,

    /// <summary>Every check of clause 4.3 (and, for a chain or a record, clause 5.3) that this library performs held.</summary>
    Verified = 1,

    /// <summary>The structure holds no chain, an empty chain, or another shape clause 5.1 does not describe.</summary>
    Malformed = 2,

    /// <summary>
    /// Step 2 of <see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.3">clause 4.3</see>: the hash of
    /// the data object being proved is not in the first list of hash values, so the walk terminates "with
    /// negative result".
    /// </summary>
    DataObjectNotCovered = 3,

    /// <summary>
    /// Step 4 of clause 4.3: the recomputed root does not "correspond to hashedMessage ... in messageImprint
    /// field of timeStampToken", or the algorithms of the two do not correspond.
    /// </summary>
    RootMismatch = 4,

    /// <summary>The <c>timeStamp</c> field could not be opened and its <c>TSTInfo</c> read, so it binds nothing this library can check.</summary>
    TimestampNotRead = 5,

    /// <summary>
    /// Step 2 of <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.3">clause 5.3</see>: "The first
    /// hash value list of each ArchiveTimeStamp MUST contain the hash value of the timestamp of the Archive
    /// Timestamp before", or step 3's equivalent link between one chain and the chains before it, does not hold.
    /// </summary>
    ChainLinkageBroken = 6,

    /// <summary>
    /// Clause 5.1 and step 2 of clause 5.3: "all reducedHashtrees of the contained ArchiveTimeStamps MUST use
    /// the same Hash-Algorithm" within one <c>ArchiveTimeStampChain</c>, and this chain's do not.
    /// </summary>
    ChainAlgorithmInconsistent = 7,

    /// <summary>Clause 5.1: "ArchiveTimeStampChain and ArchiveTimeStampSequence MUST be ordered ascending by time of timestamp", and these are not.</summary>
    TimestampsOutOfOrder = 8,

    /// <summary>An algorithm the structure names is one this library cannot compute, so nothing it protects can be recomputed.</summary>
    UnsupportedDigestAlgorithm = 9,

    /// <summary>
    /// The optional group check of clause 4.3 ("it can be verified additionally, that only the hash values of
    /// the given data objects are in the first hash-value list") and of clause 5.3 failed: the first list holds
    /// hash values beyond the claimed group's, or is missing one of them.
    /// </summary>
    DataObjectGroupNotCoveredExclusively = 10,

    /// <summary>
    /// The record carries an <c>encryptionInfo</c> field. Clause 6 registers no algorithm for it and requires
    /// the data objects to be re-encrypted before verification, which this library cannot do, so the record is
    /// refused rather than verified against octets that are not what it covers.
    /// </summary>
    EncryptionInfoPresent = 11
}


/// <summary>
/// What a verifier concluded about one <c>ArchiveTimeStamp</c>, per
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.3">IETF RFC 4998 clause 4.3</see>.
/// </summary>
[DebuggerDisplay("EvidenceRecordArchiveTimeStampVerification({Status}, {GenerationTime})")]
public sealed class EvidenceRecordArchiveTimeStampVerification: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>
    /// Initialises a new conclusion.
    /// </summary>
    /// <param name="status">What was concluded.</param>
    /// <param name="digestAlgorithm">The algorithm the reduced hash tree was walked under.</param>
    /// <param name="generationTime">The <c>genTime</c> the embedded time-stamp asserts.</param>
    /// <param name="root">The recomputed root, owned by this instance, or <see langword="null"/> when none was reached.</param>
    internal EvidenceRecordArchiveTimeStampVerification(
        EvidenceRecordVerificationStatus status,
        AlgorithmIdentifier digestAlgorithm,
        DateTimeOffset generationTime,
        DigestValue? root)
    {
        Status = status;
        DigestAlgorithm = digestAlgorithm;
        GenerationTime = generationTime;
        Root = root;
    }


    /// <summary>Gets what was concluded.</summary>
    public EvidenceRecordVerificationStatus Status { get; }

    /// <summary>
    /// Gets the algorithm the reduced hash tree was walked under: the <c>digestAlgorithm</c> field when the
    /// structure carries one, otherwise the algorithm of the embedded time-stamp's own message imprint, as
    /// clause 4.1 requires ("If the optional field digestAlgorithm is not present, the digest algorithm of the
    /// timestamp MUST be used").
    /// </summary>
    public AlgorithmIdentifier DigestAlgorithm { get; }

    /// <summary>Gets the <c>genTime</c> the embedded time-stamp asserts, or the default when the token could not be read.</summary>
    public DateTimeOffset GenerationTime { get; }

    /// <summary>Gets the recomputed root, owned by this instance; <see langword="null"/> when the walk did not reach one.</summary>
    public DigestValue? Root { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            Root?.Dispose();
            disposed = true;
        }
    }
}


/// <summary>
/// What a verifier concluded about one <c>ArchiveTimeStampChain</c>, per
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.3">IETF RFC 4998 clause 5.3</see> step 2.
/// </summary>
/// <remarks>
/// Coverage is reported per chain rather than once for the record. Clause 5.2's Hash-Tree Renewal selects
/// "data objects d(i) referred to by initial Archive Timestamp (objects that are still present and not
/// deleted)", so an object covered by the first chain can simply be absent from a later one with no error
/// signal anywhere. A consumer that assumed coverage propagates forward would report a proof the record does
/// not make.
/// </remarks>
[DebuggerDisplay("EvidenceRecordChainVerification({Status}, covers data object {CoversDataObject})")]
public sealed class EvidenceRecordChainVerification: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>
    /// Initialises a new conclusion.
    /// </summary>
    /// <param name="status">What was concluded about the chain.</param>
    /// <param name="digestAlgorithm">The one algorithm clause 5.1 requires every member of the chain to share.</param>
    /// <param name="archiveTimeStamps">The per-member conclusions, owned by this instance.</param>
    /// <param name="coversDataObject">Whether this chain's own initial member carries the data object being proved.</param>
    internal EvidenceRecordChainVerification(
        EvidenceRecordVerificationStatus status,
        AlgorithmIdentifier digestAlgorithm,
        IReadOnlyList<EvidenceRecordArchiveTimeStampVerification> archiveTimeStamps,
        bool coversDataObject)
    {
        Status = status;
        DigestAlgorithm = digestAlgorithm;
        ArchiveTimeStamps = archiveTimeStamps;
        CoversDataObject = coversDataObject;
    }


    /// <summary>Gets what was concluded about the chain.</summary>
    public EvidenceRecordVerificationStatus Status { get; }

    /// <summary>Gets the algorithm every member of the chain is required to share (clause 5.1).</summary>
    public AlgorithmIdentifier DigestAlgorithm { get; }

    /// <summary>Gets the per-member conclusions, in the order the members are encoded. Owned by this instance.</summary>
    public IReadOnlyList<EvidenceRecordArchiveTimeStampVerification> ArchiveTimeStamps { get; }

    /// <summary>Gets whether this chain's own initial <c>ArchiveTimeStamp</c> carries the data object being proved.</summary>
    public bool CoversDataObject { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            for(int i = 0; i < ArchiveTimeStamps.Count; ++i)
            {
                ArchiveTimeStamps[i].Dispose();
            }

            disposed = true;
        }
    }
}


/// <summary>
/// What a verifier concluded about a whole Evidence Record, per
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-3.3">IETF RFC 4998 clause 3.3</see> and
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.3">clause 5.3</see>.
/// </summary>
/// <remarks>
/// The temporal half of clause 5.3 — that each member is valid "relative to the time of the following Archive
/// Timestamp" (step 2b), that a chain's algorithm is "secure at the time of the first Archive Timestamp of the
/// following ArchiveTimeStampChain" (step 2d), and that "the last Archive Timestamp has to be valid at the time
/// the verification is performed" — is not concluded here. Those are validations of the embedded time-stamp
/// tokens against a trust anchor, a revocation state and a dated algorithm-reliability table, which is the
/// time-stamp validation building block of ETSI EN 319 102-1 clause 5.4 composed by a caller.
/// <see cref="InitialArchiveTime"/> and <see cref="LatestArchiveTime"/> together with the per-member
/// <see cref="EvidenceRecordArchiveTimeStampVerification.GenerationTime"/> values are what that caller needs.
/// </remarks>
[DebuggerDisplay("EvidenceRecordVerification({Status}, {Chains.Count} chains)")]
public sealed class EvidenceRecordVerification: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>
    /// Initialises a new conclusion.
    /// </summary>
    /// <param name="status">What was concluded about the record.</param>
    /// <param name="chains">The per-chain conclusions, owned by this instance.</param>
    /// <param name="initialArchiveTime">The <c>genTime</c> of the record's initial <c>ArchiveTimeStamp</c>.</param>
    /// <param name="latestArchiveTime">The <c>genTime</c> of the record's most recent <c>ArchiveTimeStamp</c>.</param>
    /// <param name="coveredUntil">The <c>genTime</c> of the most recent <c>ArchiveTimeStamp</c> the data object's own unbroken run of proofs reaches.</param>
    internal EvidenceRecordVerification(
        EvidenceRecordVerificationStatus status,
        IReadOnlyList<EvidenceRecordChainVerification> chains,
        DateTimeOffset? initialArchiveTime,
        DateTimeOffset? latestArchiveTime,
        DateTimeOffset? coveredUntil)
    {
        Status = status;
        Chains = chains;
        InitialArchiveTime = initialArchiveTime;
        LatestArchiveTime = latestArchiveTime;
        CoveredUntil = coveredUntil;
    }


    /// <summary>Gets what was concluded about the record.</summary>
    public EvidenceRecordVerificationStatus Status { get; }

    /// <summary>Gets the per-chain conclusions, in the order the chains are encoded. Owned by this instance.</summary>
    public IReadOnlyList<EvidenceRecordChainVerification> Chains { get; }

    /// <summary>
    /// Gets the <c>genTime</c> of the record's initial <c>ArchiveTimeStamp</c> — the instant the record proves
    /// the data object existed at, when <see cref="Status"/> is
    /// <see cref="EvidenceRecordVerificationStatus.Verified"/>.
    /// </summary>
    public DateTimeOffset? InitialArchiveTime { get; }

    /// <summary>Gets the <c>genTime</c> of the record's most recent <c>ArchiveTimeStamp</c>, the one clause 5.3 requires to still be valid at verification time.</summary>
    public DateTimeOffset? LatestArchiveTime { get; }

    /// <summary>
    /// Gets the <c>genTime</c> of the most recent <c>ArchiveTimeStamp</c> that the data object being proved is
    /// carried to by an unbroken run of proofs from the initial one, or <see langword="null"/> when even the
    /// initial one does not carry it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the answer to the question a consumer of an Evidence Record actually asks, and it is not
    /// <see cref="LatestArchiveTime"/>. Clause 5.2's Hash-Tree Renewal selects "data objects d(i) referred to by
    /// initial Archive Timestamp (objects that are still present and not deleted)", so a record can perfectly
    /// well carry a chain that says nothing about this data object while saying a great deal about its siblings.
    /// The record's own most recent Archive Timestamp is then later than the instant this data object is proved
    /// to, and reading the one for the other would claim a proof the record does not make.
    /// </para>
    /// <para>
    /// The walk stops at the first chain whose
    /// <see cref="EvidenceRecordChainVerification.CoversDataObject"/> is <see langword="false"/> and, within a
    /// chain, at the first member that did not verify. A verifier cannot tell a deleted data object from a prior
    /// chain whose octets were altered — both leave the renewal value out of the next chain's first list — so
    /// nothing here claims which of the two happened; <see cref="Status"/> reports that the run ended and this
    /// property reports where.
    /// </para>
    /// </remarks>
    public DateTimeOffset? CoveredUntil { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            for(int i = 0; i < Chains.Count; ++i)
            {
                Chains[i].Dispose();
            }

            disposed = true;
        }
    }
}
