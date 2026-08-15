using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// What a verifier concluded about an Evidence Record in the XML syntax of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283">IETF RFC 6283</see>, about one of its
/// <c>ArchiveTimeStampChain</c> elements, or about one <c>ArchiveTimeStamp</c>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="NotVerified"/> occupies zero so a default-initialised status never reads as a successful
/// verification, mirroring <see cref="EvidenceRecordVerificationStatus"/> exactly.
/// </para>
/// <para>
/// The enumeration is deliberately separate from the ASN.1 form's. The two mechanisms fail in ways the other
/// one cannot: there is no canonicalization in RFC 4998 and therefore no
/// <see cref="CanonicalizationFailed"/>, and RFC 6283 has no encoding to be malformed at rest in the way a DER
/// structure is. Folding them into one enumeration would give a caller members that can never occur for the
/// form in front of it.
/// </para>
/// </remarks>
public enum XmlEvidenceRecordVerificationStatus
{
    /// <summary>No verification has been attempted. The value of an unset field, by design.</summary>
    NotVerified = 0,

    /// <summary>Every check of clause 3.3, clause 4.3 and Appendix A that this library performs held.</summary>
    Verified = 1,

    /// <summary>The structure holds no chain, an empty chain, or another shape clause 4.1 does not describe.</summary>
    Malformed = 2,

    /// <summary>
    /// Appendix A step 5.b: a digest value the Archive Time-Stamp must protect "cannot be found in the first
    /// sequence of the hash tree", so the walk exits "with a negative result".
    /// </summary>
    DataObjectNotCovered = 3,

    /// <summary>
    /// Appendix A step 5.b.ii: "calculated root hash value from the hash tree does not match the Time-Stamped
    /// value". Also the conclusion when the token's message imprint is stated under an algorithm that is not the
    /// chain's, which clause 4.1.1 forbids — the two values are then not comparable at all, which is the same
    /// negative result reached one step earlier.
    /// </summary>
    RootMismatch = 4,

    /// <summary>The <c>TimeStampToken</c> could not be opened and its <c>TSTInfo</c> read, so it binds nothing this library can check.</summary>
    TimestampNotRead = 5,

    /// <summary>
    /// Clause 4.3 step 2: "the first <c>Sequence</c> MUST contain the hash value of the <c>TimeStamp</c> element
    /// before", or step 3's equivalent link between one chain and the sequence of the chains before it, does not
    /// hold.
    /// </summary>
    ChainLinkageBroken = 6,

    /// <summary>
    /// Clause 4.1.1: "When algorithms used by a TSA are changed a new ATSC MUST be started using an equal or
    /// stronger digest algorithm", and a succeeding chain names a weaker one.
    /// </summary>
    ChainAlgorithmWeakened = 7,

    /// <summary>Clause 4.1: both element sequences "MUST be sorted by time of the Time-Stamp in ascending order", and these are not.</summary>
    TimestampsOutOfOrder = 8,

    /// <summary>An algorithm the structure names is one this library cannot compute, so nothing it protects can be recomputed.</summary>
    UnsupportedDigestAlgorithm = 9,

    /// <summary>
    /// Appendix A step 5.b, second direction: "there is a hash value in the first sequence of the hash tree
    /// which is not in the list L of digest values of protected objects". Clause 3.3 step 2 phrases this
    /// direction as a SHOULD; this library performs it by default and makes omitting it an explicit departure.
    /// </summary>
    DataObjectGroupNotCoveredExclusively = 10,

    /// <summary>
    /// The record carries an <c>EncryptionInformation</c> element. Clause 5 requires the data objects to be
    /// re-encrypted before verification, which this library cannot do, so the record is refused rather than
    /// verified against octets that are not what it covers.
    /// </summary>
    EncryptionInformationPresent = 11,

    /// <summary>
    /// The canonicalization seam did not produce the binary representation of an element the verification needs.
    /// Nothing is concluded from an element whose octets could not be determined: the digest of a guess is a
    /// digest of a guess.
    /// </summary>
    CanonicalizationFailed = 12,

    /// <summary>
    /// A <c>TimeStampToken</c> states a format this library does not read — clause 3.1.2 registers two and only
    /// <see cref="XmlEvidenceRecordWellKnown.Rfc3161TimeStampTokenType"/> is read here.
    /// </summary>
    UnsupportedTimeStampFormat = 13,

    /// <summary>
    /// Appendix A step 5.a.iii: the Archive Time-Stamp carries no hash tree, and the list of objects it must
    /// protect holds more than one value — "if an archive object is having more data objects and the hash tree
    /// is omitted, also exit with negative result" (clause 3.3 step 4).
    /// </summary>
    HashTreeMissing = 14
}


/// <summary>
/// Which of the two renewal procedures of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-4.2">IETF RFC 6283 clause 4.2</see> produced an
/// <c>ArchiveTimeStamp</c>.
/// </summary>
/// <remarks>
/// <strong>The branch point is algorithm continuity, and the structure states it.</strong> Clause 4.2.1 applies
/// "if the digest algorithm (H) to be used in the renewal process is the same as digest algorithm (H') used in
/// the last Archive Time-Stamp" and appends the new element to the last chain; clause 4.2.2 applies when the two
/// differ and creates a new chain. Where a signature format's archival branch turns on whether prior archive
/// material is present, this one turns on whether the algorithm changed — so which procedure produced an element
/// is read off where the element sits, with no guessing.
/// </remarks>
public enum XmlEvidenceRecordRenewalKind
{
    /// <summary>Nothing stated. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The initial Archive Time-Stamp: the first element of the first chain, whose hash tree covers the data objects alone (Appendix A step 4.a.i).</summary>
    Initial = 1,

    /// <summary>
    /// A Time-Stamp Renewal (clause 4.2.1): a later element of an existing chain, whose hash tree covers the
    /// preceding <c>TimeStamp</c> element (Appendix A step 4.b.i).
    /// </summary>
    TimeStampRenewal = 2,

    /// <summary>
    /// A Hash-Tree Renewal (clause 4.2.2): the first element of a succeeding chain, whose hash tree covers the
    /// data objects together with the digest of the sequence of every preceding chain (Appendix A step 4.a.ii).
    /// </summary>
    HashTreeRenewal = 3
}


/// <summary>
/// What a verifier concluded about one <c>ArchiveTimeStamp</c>, per Appendix A of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#appendix-A">IETF RFC 6283</see>.
/// </summary>
[DebuggerDisplay("XmlEvidenceRecordArchiveTimeStampVerification({Status}, {RenewalKind}, {GenerationTime})")]
public sealed class XmlEvidenceRecordArchiveTimeStampVerification: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>Initialises a new conclusion.</summary>
    /// <param name="status">What was concluded.</param>
    /// <param name="renewalKind">Which procedure of clause 4.2 the element's position states it came from.</param>
    /// <param name="chainOrder">The <c>Order</c> of the chain the element sits in.</param>
    /// <param name="order">The element's own <c>Order</c>.</param>
    /// <param name="membership">What comparing the protected list against the first <c>Sequence</c> concluded.</param>
    /// <param name="generationTime">The <c>genTime</c> the embedded time-stamp asserts.</param>
    /// <param name="root">The recomputed root, owned by this instance, or <see langword="null"/> when none was reached.</param>
    internal XmlEvidenceRecordArchiveTimeStampVerification(
        XmlEvidenceRecordVerificationStatus status,
        XmlEvidenceRecordRenewalKind renewalKind,
        int chainOrder,
        int order,
        XmlEvidenceRecordMembershipStatus membership,
        DateTimeOffset? generationTime,
        DigestValue? root)
    {
        Status = status;
        RenewalKind = renewalKind;
        ChainOrder = chainOrder;
        Order = order;
        Membership = membership;
        GenerationTime = generationTime;
        Root = root;
    }


    /// <summary>Gets what was concluded.</summary>
    public XmlEvidenceRecordVerificationStatus Status { get; }

    /// <summary>Gets which procedure of clause 4.2 the element's position states it came from.</summary>
    public XmlEvidenceRecordRenewalKind RenewalKind { get; }

    /// <summary>Gets the <c>Order</c> of the chain the element sits in.</summary>
    public int ChainOrder { get; }

    /// <summary>Gets the element's own <c>Order</c>.</summary>
    public int Order { get; }

    /// <summary>Gets what comparing the list of protected digest values against the first <c>Sequence</c> concluded (Appendix A step 5.b).</summary>
    public XmlEvidenceRecordMembershipStatus Membership { get; }

    /// <summary>Gets the <c>genTime</c> the embedded time-stamp asserts, or <see langword="null"/> when the token could not be read.</summary>
    public DateTimeOffset? GenerationTime { get; }

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
/// What a verifier concluded about one <c>ArchiveTimeStampChain</c>, per clause 4.3 of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-4.3">IETF RFC 6283</see>.
/// </summary>
/// <remarks>
/// Coverage is reported per chain rather than once for the record. A Hash-Tree Renewal selects the archive
/// objects to be renewed (clause 4.2.2 step 1), so an object covered by an earlier chain can simply be absent
/// from a later one; a consumer that assumed coverage propagates forward would report a proof the record does
/// not make. This is the same per-chain reading the ASN.1 form of the mechanism is verified under.
/// </remarks>
[DebuggerDisplay("XmlEvidenceRecordChainVerification({Status}, order {Order}, covers {CoversDataObjects})")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "An algorithm identifier is compared as written and reported as the document states it; System.Uri would normalise it.")]
public sealed class XmlEvidenceRecordChainVerification: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>Initialises a new conclusion.</summary>
    /// <param name="status">What was concluded about the chain.</param>
    /// <param name="order">The chain's <c>Order</c>.</param>
    /// <param name="digestAlgorithm">The algorithm clause 4.1.1 makes every calculation of the chain use.</param>
    /// <param name="canonicalizationMethodUri">The canonicalization identifier clause 4.1.2 makes every binary representation of the chain use.</param>
    /// <param name="archiveTimeStamps">The per-member conclusions, owned by this instance.</param>
    /// <param name="coversDataObjects">Whether this chain's own initial member carries the data objects being proved.</param>
    internal XmlEvidenceRecordChainVerification(
        XmlEvidenceRecordVerificationStatus status,
        int order,
        PkiDigestAlgorithm digestAlgorithm,
        string canonicalizationMethodUri,
        IReadOnlyList<XmlEvidenceRecordArchiveTimeStampVerification> archiveTimeStamps,
        bool coversDataObjects)
    {
        Status = status;
        Order = order;
        DigestAlgorithm = digestAlgorithm;
        CanonicalizationMethodUri = canonicalizationMethodUri;
        ArchiveTimeStamps = archiveTimeStamps;
        CoversDataObjects = coversDataObjects;
    }


    /// <summary>Gets what was concluded about the chain.</summary>
    public XmlEvidenceRecordVerificationStatus Status { get; }

    /// <summary>Gets the chain's <c>Order</c>.</summary>
    public int Order { get; }

    /// <summary>Gets the algorithm clause 4.1.1 makes every calculation of the chain use.</summary>
    public PkiDigestAlgorithm DigestAlgorithm { get; }

    /// <summary>Gets the canonicalization identifier clause 4.1.2 makes every binary representation of the chain use.</summary>
    public string CanonicalizationMethodUri { get; }

    /// <summary>Gets the per-member conclusions, in ascending <c>Order</c>. Owned by this instance.</summary>
    public IReadOnlyList<XmlEvidenceRecordArchiveTimeStampVerification> ArchiveTimeStamps { get; }

    /// <summary>Gets whether this chain's own initial <c>ArchiveTimeStamp</c> carries the data objects being proved.</summary>
    public bool CoversDataObjects { get; }


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
/// What a verifier concluded about a whole Evidence Record in the XML syntax, per clause 3.3, clause 4.3 and
/// Appendix A of <see href="https://www.rfc-editor.org/rfc/rfc6283">IETF RFC 6283</see>.
/// </summary>
/// <remarks>
/// The temporal half of the process — that each Archive Time-Stamp "MUST be valid relative to the time of the
/// succeeding Archive Time-Stamp" (clause 4.3 step 2), that a chain's algorithm "was secure at the time of the
/// first Archive Time-Stamp of the succeeding Archive Time-Stamp Chain" (the same step), and that "the last
/// Archive Time-Stamp MUST be valid at the time of verification process" — is not concluded here. Those are
/// validations of the embedded time-stamp tokens against a trust anchor, a revocation state and a dated
/// algorithm-reliability table, which is the time-stamp validation building block of ETSI EN 319 102-1 clause
/// 5.4 composed by a caller. <see cref="InitialArchiveTime"/>, <see cref="LatestArchiveTime"/> and the
/// per-member generation times are what that caller needs, and Appendix A step 7 states exactly which instant
/// each member is to be validated at: the succeeding member's, and the present for the last.
/// </remarks>
[DebuggerDisplay("XmlEvidenceRecordVerification({Status}, {Chains.Count} chains)")]
public sealed class XmlEvidenceRecordVerification: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>Initialises a new conclusion.</summary>
    /// <param name="status">What was concluded about the record.</param>
    /// <param name="chains">The per-chain conclusions, owned by this instance.</param>
    /// <param name="initialArchiveTime">The <c>genTime</c> of the record's initial Archive Time-Stamp.</param>
    /// <param name="latestArchiveTime">The <c>genTime</c> of the record's most recent Archive Time-Stamp.</param>
    /// <param name="coveredUntil">The <c>genTime</c> the data objects' own unbroken run of proofs reaches.</param>
    internal XmlEvidenceRecordVerification(
        XmlEvidenceRecordVerificationStatus status,
        IReadOnlyList<XmlEvidenceRecordChainVerification> chains,
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
    public XmlEvidenceRecordVerificationStatus Status { get; }

    /// <summary>Gets the per-chain conclusions, in ascending <c>Order</c>. Owned by this instance.</summary>
    public IReadOnlyList<XmlEvidenceRecordChainVerification> Chains { get; }

    /// <summary>
    /// Gets the <c>genTime</c> of the record's initial Archive Time-Stamp — the instant the record proves the
    /// data objects existed at, when <see cref="Status"/> is
    /// <see cref="XmlEvidenceRecordVerificationStatus.Verified"/>.
    /// </summary>
    public DateTimeOffset? InitialArchiveTime { get; }

    /// <summary>Gets the <c>genTime</c> of the record's most recent Archive Time-Stamp, the one clause 4.3 requires to still be valid at verification time.</summary>
    public DateTimeOffset? LatestArchiveTime { get; }

    /// <summary>
    /// Gets the <c>genTime</c> of the most recent Archive Time-Stamp that the data objects are carried to by an
    /// unbroken run of proofs from the initial one, or <see langword="null"/> when even the initial one does not
    /// carry them.
    /// </summary>
    /// <remarks>
    /// This is the answer to the question a consumer of an Evidence Record actually asks, and it is not
    /// <see cref="LatestArchiveTime"/>: a Hash-Tree Renewal selects which archive objects it renews, so a record
    /// can carry a chain that says nothing about these data objects while saying a great deal about others. The
    /// walk stops at the first chain whose <see cref="XmlEvidenceRecordChainVerification.CoversDataObjects"/> is
    /// <see langword="false"/> and, within a chain, at the first member that did not verify.
    /// </remarks>
    public DateTimeOffset? CoveredUntil { get; }

    /// <summary>Gets whether every check this library performs held.</summary>
    public bool IsVerified => Status == XmlEvidenceRecordVerificationStatus.Verified;


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
