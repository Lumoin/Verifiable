using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Which of the two renewal procedures of
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.2">IETF RFC 4998 clause 5.2</see> produced a
/// renewed Evidence Record.
/// </summary>
/// <remarks>
/// The two are not variants of one operation. Timestamp Renewal re-timestamps the previous time-stamp under the
/// chain's existing algorithm and appends to that chain; Hash-Tree Renewal re-hashes the data objects and every
/// prior chain under a new algorithm and starts a new chain. Clause 5.2 states the trigger for each: the first
/// answers a time-stamp whose certificate or signature algorithm is about to become unusable, the second a hash
/// algorithm that is.
/// </remarks>
public enum EvidenceRecordRenewalKind
{
    /// <summary>No renewal has been performed. The value of an unset field, by design.</summary>
    NotRenewed = 0,

    /// <summary>
    /// Timestamp Renewal: "the content of the timeStamp field of the old Archive Timestamp has to be hashed and
    /// timestamped by a new Archive Timestamp", which "MUST be added to the ArchiveTimestampChain".
    /// </summary>
    TimestampRenewal = 1,

    /// <summary>
    /// Hash-Tree Renewal: "the Archive Timestamp and the archived data objects covered by the Archive Timestamp
    /// must be hashed and timestamped again", producing a "new ArchiveTimeStampChain ... appended to the
    /// ArchiveTimeStampSequence".
    /// </summary>
    HashTreeRenewal = 2
}


/// <summary>
/// What one <see cref="EvidenceRecords.RenewTimestampAsync"/> call needs: the Evidence Records whose most recent
/// Archive Timestamp is to be re-timestamped, and how to reach a Time-Stamping Authority.
/// </summary>
/// <remarks>
/// <para>
/// Several records may be renewed together. Clause 5.2 sanctions it outright — "It is also possible to collect
/// several Archive Timestamps and to timestamp them together in a new Archive Timestamp" — and it is the same
/// centralized mode clause 3.2 describes for creation: one hash tree over every record's tip, one time-stamp
/// over its root, and one new Archive Timestamp per record carrying that record's own reduced hash tree.
/// </para>
/// <para>
/// The algorithm is not a parameter. Clause 5.2 fixes it: "This hash tree of the new Archive Timestamp MUST use
/// the same hash algorithm as the old one, which is specified in the digestAlgorithm field of the Archive
/// Timestamp or, if this value is not set (as it is optional), within the timestamp itself." Renewal therefore
/// resolves the algorithm from each record and refuses a batch whose records do not agree, rather than letting a
/// caller state one that would break the chain it is appended to.
/// </para>
/// </remarks>
public sealed record EvidenceRecordTimestampRenewalContext
{
    /// <summary>Gets the Evidence Records to renew. The caller owns them; renewal produces new records and leaves these untouched.</summary>
    public required IReadOnlyList<EvidenceRecord> EvidenceRecords { get; init; }

    /// <summary>Gets the Time-Stamping Authority to contact, in whatever form the transport delegate understands.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "Forwarded verbatim into TimestampFetchContext.TsaUri, which is deliberately a string for the reason that property gives: the transport delegate owns URI parsing and scheme policy.")]
    public required string TsaUri { get; init; }

    /// <summary>Gets the transport that carries the time-stamp request to the authority and its response back.</summary>
    public required FetchTimestampResponseAsyncDelegate FetchTimestampResponse { get; init; }

    /// <summary>Gets how many children an inner node of the hash tree is given; see <see cref="EvidenceRecordHashTreeBuildContext.NodeArity"/>.</summary>
    public int NodeArity { get; init; } = EvidenceRecordHashTree.DefaultNodeArity;

    /// <summary>
    /// Gets the <c>cryptoInfos</c> attributes to place in every produced record, or <see langword="null"/> to
    /// carry each source record's own <c>cryptoInfos</c> forward octet for octet.
    /// </summary>
    public IReadOnlyList<CmsAttribute>? CryptoInfos { get; init; }

    /// <summary>Gets whether the <c>digestAlgorithm [0]</c> field is written into every produced <c>ArchiveTimeStamp</c>; see <see cref="EvidenceRecordCreationContext.StateDigestAlgorithmField"/>.</summary>
    public bool StateDigestAlgorithmField { get; init; }

    /// <summary>Gets the Time-Stamping Authority policy the request asks for, or <see langword="null"/> to state none.</summary>
    public string? TimestampPolicyOid { get; init; }
}


/// <summary>
/// One Evidence Record and the data objects of its group that are still present, as
/// <see cref="EvidenceRecords.RenewHashTreeAsync"/> takes them.
/// </summary>
/// <remarks>
/// <para>
/// Step 2 of clause 5.2's Hash-Tree Renewal is "Select data objects d(i) referred to by initial Archive Timestamp
/// (objects that are still present and not deleted)". Deletion is therefore expressed by simply not supplying
/// the object: the procedure has no error for it, and clause 1.2 states the intent outright — "The deletion of a
/// data object in the tree does not influence the provability of others". A verifier reads the consequence back
/// per chain (<see cref="EvidenceRecordChainVerification.CoversDataObject"/>), never as a property of the whole
/// record.
/// </para>
/// <para>
/// Every data object of one group is renewed against the same encoded sequence of that group's record, which is
/// what makes them one group: clause 5.2 step 4 pairs each member's own hash with the group's single
/// <c>ha(i)</c>.
/// </para>
/// </remarks>
public sealed record EvidenceRecordHashTreeRenewalGroup
{
    /// <summary>Gets the Evidence Record whose accumulated chains are hashed as <c>atsc(i)</c>. The caller owns it; renewal leaves it untouched.</summary>
    public required EvidenceRecord EvidenceRecord { get; init; }

    /// <summary>
    /// Gets the data objects of this group that are still present, as views the caller owns for the duration of
    /// the call. An object left out is an object the renewed record stops proving, with no error — see the
    /// type's remarks.
    /// </summary>
    public required IReadOnlyList<ReadOnlyMemory<byte>> DataObjects { get; init; }
}


/// <summary>
/// What one <see cref="EvidenceRecords.RenewHashTreeAsync"/> call needs: the records and their still-present data
/// objects, the new algorithm every hash is taken under, and how to reach a Time-Stamping Authority.
/// </summary>
/// <remarks>
/// Step 1 of clause 5.2's Hash-Tree Renewal is "Select a secure hash algorithm H", which is why
/// <see cref="DigestAlgorithm"/> is a required parameter here and is derived rather than stated for Timestamp
/// Renewal: this procedure exists precisely because the previous algorithm is no longer to be relied on.
/// </remarks>
public sealed record EvidenceRecordHashTreeRenewalContext
{
    /// <summary>Gets the groups to renew. One renewed record is produced per group, in the order the groups are supplied.</summary>
    public required IReadOnlyList<EvidenceRecordHashTreeRenewalGroup> DataObjectGroups { get; init; }

    /// <summary>Gets the new algorithm — the <c>H</c> of clause 5.2 step 1 — that every hash of this renewal, and the time-stamp request over the new root, is computed under.</summary>
    public required PkiDigestAlgorithm DigestAlgorithm { get; init; }

    /// <summary>Gets the Time-Stamping Authority to contact, in whatever form the transport delegate understands.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "Forwarded verbatim into TimestampFetchContext.TsaUri, which is deliberately a string for the reason that property gives: the transport delegate owns URI parsing and scheme policy.")]
    public required string TsaUri { get; init; }

    /// <summary>Gets the transport that carries the time-stamp request to the authority and its response back.</summary>
    public required FetchTimestampResponseAsyncDelegate FetchTimestampResponse { get; init; }

    /// <summary>Gets how many children an inner node of the hash tree is given; see <see cref="EvidenceRecordHashTreeBuildContext.NodeArity"/>.</summary>
    public int NodeArity { get; init; } = EvidenceRecordHashTree.DefaultNodeArity;

    /// <summary>
    /// Gets the <c>cryptoInfos</c> attributes to place in every produced record, or <see langword="null"/> to
    /// carry each source record's own <c>cryptoInfos</c> forward octet for octet.
    /// </summary>
    public IReadOnlyList<CmsAttribute>? CryptoInfos { get; init; }

    /// <summary>Gets whether the <c>digestAlgorithm [0]</c> field is written into every produced <c>ArchiveTimeStamp</c>; see <see cref="EvidenceRecordCreationContext.StateDigestAlgorithmField"/>.</summary>
    public bool StateDigestAlgorithmField { get; init; }

    /// <summary>Gets the Time-Stamping Authority policy the request asks for, or <see langword="null"/> to state none.</summary>
    public string? TimestampPolicyOid { get; init; }
}


/// <summary>
/// The renewed Evidence Records one renewal Archive Timestamp produced, one per record renewed.
/// </summary>
/// <remarks>
/// A renewed record is a new record: it carries every chain of the record it was produced from, octet for octet,
/// plus what the renewal added. The source records are untouched and remain valid proofs of what they always
/// proved — clause 5.2 renews the protection, it does not invalidate what came before.
/// </remarks>
[DebuggerDisplay("EvidenceRecordRenewal({Kind}, {EvidenceRecords.Count} records, archived {ArchiveTime})")]
public sealed class EvidenceRecordRenewal: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>
    /// Initialises a new renewal result.
    /// </summary>
    /// <param name="kind">Which renewal procedure produced these records.</param>
    /// <param name="evidenceRecords">One renewed record per source record, in the order they were supplied. Ownership transfers to this instance.</param>
    /// <param name="archiveTime">The <c>genTime</c> the acquired time-stamp asserts.</param>
    internal EvidenceRecordRenewal(EvidenceRecordRenewalKind kind, IReadOnlyList<EvidenceRecord> evidenceRecords, DateTimeOffset archiveTime)
    {
        Kind = kind;
        EvidenceRecords = evidenceRecords;
        ArchiveTime = archiveTime;
    }


    /// <summary>Gets which renewal procedure produced these records.</summary>
    public EvidenceRecordRenewalKind Kind { get; }

    /// <summary>Gets one renewed record per source record, in the order they were supplied. Owned by this instance.</summary>
    public IReadOnlyList<EvidenceRecord> EvidenceRecords { get; }

    /// <summary>Gets the <c>genTime</c> the acquired time-stamp asserts — the instant the renewal carries the proof forward to.</summary>
    public DateTimeOffset ArchiveTime { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            for(int i = 0; i < EvidenceRecords.Count; ++i)
            {
                EvidenceRecords[i].Dispose();
            }

            disposed = true;
        }
    }
}
