using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Globalization;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Whether a <c>DigestList</c> submission was carried into a renewed Evidence Record, and if not, why.
/// </summary>
/// <remarks>
/// <see cref="Renewed"/> is deliberately not zero: a status that has not been computed must not read as a
/// renewal that happened.
/// </remarks>
public enum PreservationDigestListRenewalStatus
{
    /// <summary>No renewal has been attempted. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The submitted evidence was renewed and the renewed record is the result's.</summary>
    Renewed = 1,

    /// <summary>
    /// The <c>DigestMethod</c> element does not name an algorithm this library computes; see
    /// <see cref="PreservationDigestMethod.TryResolve"/>.
    /// </summary>
    DigestMethodNotResolvable = 2,

    /// <summary>The submission states no digest value, so there is nothing to carry forward (clause 5.6.1.1 requires one or more).</summary>
    NoDigestValue = 3,

    /// <summary>A submitted digest value is not as long as the stated digest method produces, so it is not a digest under that method.</summary>
    DigestValueLengthMismatch = 4,

    /// <summary>The submission carries no <c>Evidence</c> element, so it is a submission rather than a renewal request.</summary>
    NoEvidence = 5,

    /// <summary>
    /// The submitted evidence names a format this library does not renew. The ASN.1 evidence record of IETF RFC
    /// 4998 is renewed; the XML form of IETF RFC 6283 is verified but not produced by this library, and no other
    /// evidence format of clause A.2 has a hash-tree renewal at all.
    /// </summary>
    EvidenceFormatNotRenewable = 6,

    /// <summary>The submitted evidence's octets are not an Evidence Record this library can read.</summary>
    EvidenceNotReadable = 7,

    /// <summary>
    /// The renewal needs the data objects the digest values were computed over and the caller supplied none. See
    /// the remarks on <see cref="PreservationDigestListRenewal"/>: the shipped Hash-Tree Renewal computes the
    /// data object hashes itself, so a submission carrying only hashes cannot reach it without the objects.
    /// </summary>
    DataObjectsNotSupplied = 8,

    /// <summary>The caller supplied a different number of data objects than the submission states digest values for.</summary>
    DataObjectCountMismatch = 9,

    /// <summary>A supplied data object hashes, under the stated digest method, to no digest value the submission states.</summary>
    DigestValueNotMatched = 10
}


/// <summary>
/// Everything one <see cref="PreservationDigestListRenewal.RenewAsync"/> call needs: the submission, the data
/// objects its digest values were computed over, and how to reach a Time-Stamping Authority.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> The caller owns <see cref="DigestList"/> and the data object views and disposes
/// them; the renewed record is the result's.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservationDigestListRenewalContext
{
    /// <summary>The submission, as the <c>PO</c> component of one <c>PreservePO</c> call carried it.</summary>
    public required PreservationDigestList DigestList { get; init; }

    /// <summary>
    /// The data objects the submitted digest values were computed over, or <see langword="null"/> when the caller
    /// holds none — for which the answer is
    /// <see cref="PreservationDigestListRenewalStatus.DataObjectsNotSupplied"/> rather than a renewal.
    /// </summary>
    public IReadOnlyList<ReadOnlyMemory<byte>>? DataObjects { get; init; }

    /// <summary>The Time-Stamping Authority to contact, in whatever form the transport delegate understands.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "Forwarded verbatim into the shipped renewal context's TsaUri, which is deliberately a string for the reason that property gives: the transport delegate owns URI parsing and scheme policy.")]
    public required string TsaUri { get; init; }

    /// <summary>The transport that carries the time-stamp request to the authority and its response back.</summary>
    public required FetchTimestampResponseAsyncDelegate FetchTimestampResponse { get; init; }

    /// <summary>How many children an inner node of the renewal's hash tree is given; see <see cref="EvidenceRecordHashTreeBuildContext.NodeArity"/>.</summary>
    public int NodeArity { get; init; } = EvidenceRecordHashTree.DefaultNodeArity;

    /// <summary>The <c>cryptoInfos</c> attributes to place in the produced record, or <see langword="null"/> to carry the submitted record's forward.</summary>
    public IReadOnlyList<CmsAttribute>? CryptoInfos { get; init; }

    /// <summary>Whether the <c>digestAlgorithm [0]</c> field is written into the produced <c>ArchiveTimeStamp</c>.</summary>
    public bool StateDigestAlgorithmField { get; init; }

    /// <summary>The Time-Stamping Authority policy the renewal's request asks for, or <see langword="null"/> to state none.</summary>
    public string? TimestampPolicyOid { get; init; }


    /// <summary>A short debugger string showing what is being renewed against what.</summary>
    private string DebuggerDisplay =>
        $"PreservationDigestListRenewalContext({DigestList.DigestValues.Count} values, {DataObjects?.Count.ToString(CultureInfo.InvariantCulture) ?? "no"} data objects)";
}


/// <summary>
/// The outcome of renewing the evidence a <c>DigestList</c> submitted. On success it owns the renewed Evidence
/// Record; the caller disposes it. On failure it owns nothing.
/// </summary>
[DebuggerDisplay("PreservationDigestListRenewalResult: {Status}")]
public sealed record PreservationDigestListRenewalResult: IDisposable
{
    /// <summary>The outcome; <see cref="PreservationDigestListRenewalStatus.Renewed"/> is the only success.</summary>
    public required PreservationDigestListRenewalStatus Status { get; init; }

    /// <summary>The renewed record; non-<see langword="null"/> only when <see cref="Status"/> is <see cref="PreservationDigestListRenewalStatus.Renewed"/>. Owned by this result.</summary>
    public EvidenceRecord? EvidenceRecord { get; init; }

    /// <summary>The <c>genTime</c> the renewal's time-stamp asserts, when a renewal happened.</summary>
    public DateTimeOffset? ArchiveTime { get; init; }

    /// <summary>A short, human-readable reason, present on every outcome that is not a renewal.</summary>
    public string? FailureReason { get; init; }

    /// <summary>Returns <see langword="true"/> when <see cref="Status"/> is <see cref="PreservationDigestListRenewalStatus.Renewed"/>.</summary>
    public bool IsRenewed => Status == PreservationDigestListRenewalStatus.Renewed;


    /// <summary>Creates a successful result owning <paramref name="evidenceRecord"/>.</summary>
    /// <param name="evidenceRecord">The renewed record; ownership transfers to the result.</param>
    /// <param name="archiveTime">The instant the renewal's time-stamp asserts.</param>
    /// <returns>A <see cref="PreservationDigestListRenewalStatus.Renewed"/> result.</returns>
    public static PreservationDigestListRenewalResult Renewed(EvidenceRecord evidenceRecord, DateTimeOffset archiveTime) =>
        new() { Status = PreservationDigestListRenewalStatus.Renewed, EvidenceRecord = evidenceRecord, ArchiveTime = archiveTime };


    /// <summary>Creates a failed result that owns nothing.</summary>
    /// <param name="status">The failure status; must not be <see cref="PreservationDigestListRenewalStatus.Renewed"/>.</param>
    /// <param name="reason">A short, human-readable reason.</param>
    /// <returns>A failed result.</returns>
    public static PreservationDigestListRenewalResult Failed(PreservationDigestListRenewalStatus status, string reason) =>
        new() { Status = status, FailureReason = reason };


    /// <summary>Disposes <see cref="EvidenceRecord"/>, when present.</summary>
    public void Dispose() => EvidenceRecord?.Dispose();
}


/// <summary>
/// The composition clause 5.6.1's NOTE describes: a <c>DigestList</c> submission carrying a digest method, digest
/// values and an evidence record is a Hash-Tree Renewal request, served by the shipped renewal procedure of
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.2">IETF RFC 4998 clause 5.2</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This is a wire wrapper and adds no Evidence Record logic.</strong> The hash tree, the archive
/// time-stamp, the chain appending and the ordering rules are
/// <see cref="EvidenceRecords.RenewHashTreeAsync"/>'s, unchanged; what this class does is read the submission,
/// resolve what it names, check that what the caller holds is what the submission states, and hand the whole
/// thing over.
/// </para>
/// <para>
/// <strong>Why the data objects are needed, and what happens when there are none.</strong> Step 4 of clause 5.2
/// pairs each data object's hash under the new algorithm with the hash of the accumulated chains, and the shipped
/// renewal computes those data object hashes itself from the objects it is given — which is exactly the value a
/// submitted digest value already is. There is, in the shipped surface, no way to state a data object hash
/// instead of a data object, so a submission carrying only hashes — the privacy-preserving mode clause A.3.1.4.7
/// describes, where "the preservation service will be kept ignorant of both the semantics and the size of the
/// object" — cannot reach the renewal through this library today. That case answers
/// <see cref="PreservationDigestListRenewalStatus.DataObjectsNotSupplied"/> rather than silently doing something
/// else, and the gap is recorded rather than papered over.
/// </para>
/// <para>
/// <strong>The submitted digest values are binding, not decorative.</strong> When the caller does hold the data
/// objects, every one of them is hashed through the registered digest seam under the submission's own stated
/// method and matched against a digest value the submission carries, and a disagreement in either direction —
/// an object matching nothing, or a different number of objects than values — refuses the renewal. A service
/// that renewed evidence over objects the submitter did not ask about would produce a proof about the wrong
/// thing.
/// </para>
/// </remarks>
public static class PreservationDigestListRenewal
{
    /// <summary>
    /// Renews the evidence a <c>DigestList</c> submitted, over the data objects the caller holds.
    /// </summary>
    /// <param name="context">The submission, the data objects and the Time-Stamping Authority.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The renewed record, or the reason no renewal happened.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="TimestampAcquisitionException">When the authority's answer does not verify against the request; no record is produced in that case.</exception>
    /// <remarks>
    /// Everything a submission can get wrong is a status rather than an exception, the discipline every reading
    /// surface of this namespace applies: a submission arrives from a client and is therefore data, while a
    /// Time-Stamping Authority answering something that does not verify is the shipped surface's own fault to
    /// raise.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the read-back renewed record transfers to the returned result, which the caller disposes; the renewal that produced it is disposed by its own using.")]
    public static async ValueTask<PreservationDigestListRenewalResult> RenewAsync(
        PreservationDigestListRenewalContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);

        PreservationDigestList digestList = context.DigestList;
        if(!PreservationDigestMethod.TryResolve(digestList.DigestMethod, out PkiDigestAlgorithm algorithm))
        {
            return PreservationDigestListRenewalResult.Failed(
                PreservationDigestListRenewalStatus.DigestMethodNotResolvable,
                $"'{digestList.DigestMethod}' does not name a digest algorithm this library computes (clause 5.6.1.1 and IETF RFC 3061).");
        }

        if(digestList.DigestValues.Count == 0)
        {
            return PreservationDigestListRenewalResult.Failed(
                PreservationDigestListRenewalStatus.NoDigestValue,
                "Clause 5.6.1.1 states that the DigestValue element occurs one or more times.");
        }

        for(int i = 0; i < digestList.DigestValues.Count; ++i)
        {
            if(digestList.DigestValues[i].Length < algorithm.OutputByteLength)
            {
                return PreservationDigestListRenewalResult.Failed(
                    PreservationDigestListRenewalStatus.DigestValueLengthMismatch,
                    $"Digest value {i} is {digestList.DigestValues[i].Length} octets where the stated method produces {algorithm.OutputByteLength}.");
            }
        }

        if(digestList.Evidence is not PreservationEvidence evidence)
        {
            return PreservationDigestListRenewalResult.Failed(
                PreservationDigestListRenewalStatus.NoEvidence,
                "A renewal request carries the evidence to be augmented in the optional Evidence element (clause 5.6.1.1).");
        }

        if(!string.Equals(evidence.FormatId, PreservationFormatWellKnown.EvidenceRecordEvidenceFormat, StringComparison.Ordinal))
        {
            return PreservationDigestListRenewalResult.Failed(
                PreservationDigestListRenewalStatus.EvidenceFormatNotRenewable,
                $"'{evidence.FormatId}' is not '{PreservationFormatWellKnown.EvidenceRecordEvidenceFormat}', the one evidence format this library renews.");
        }

        if(context.DataObjects is not IReadOnlyList<ReadOnlyMemory<byte>> dataObjects || dataObjects.Count == 0)
        {
            return PreservationDigestListRenewalResult.Failed(
                PreservationDigestListRenewalStatus.DataObjectsNotSupplied,
                "The Hash-Tree Renewal of RFC 4998 clause 5.2 step 4 hashes the data objects themselves; supply the objects the submitted digest values were computed over.");
        }

        if(dataObjects.Count != digestList.DigestValues.Count)
        {
            return PreservationDigestListRenewalResult.Failed(
                PreservationDigestListRenewalStatus.DataObjectCountMismatch,
                $"The submission states {digestList.DigestValues.Count} digest values and {dataObjects.Count} data objects were supplied.");
        }

        bool agrees = await StateAgreementAsync(
            digestList.DigestValues, dataObjects, algorithm, pool, cancellationToken).ConfigureAwait(false);

        if(!agrees)
        {
            return PreservationDigestListRenewalResult.Failed(
                PreservationDigestListRenewalStatus.DigestValueNotMatched,
                "A supplied data object hashes, under the submission's own digest method, to no digest value the submission states.");
        }

        EvidenceRecord submitted;
        try
        {
            submitted = EvidenceRecord.Read(evidence.Content.AsReadOnlySpan(), pool);
        }
        catch(AsnContentException)
        {
            return PreservationDigestListRenewalResult.Failed(
                PreservationDigestListRenewalStatus.EvidenceNotReadable,
                "The submitted evidence's octets are not an Evidence Record this library reads.");
        }
        catch(CryptographicException)
        {
            return PreservationDigestListRenewalResult.Failed(
                PreservationDigestListRenewalStatus.EvidenceNotReadable,
                "The submitted evidence's octets are not an Evidence Record this library reads.");
        }

        using(submitted)
        {
            using EvidenceRecordRenewal renewal = await EvidenceRecords.RenewHashTreeAsync(
                new EvidenceRecordHashTreeRenewalContext
                {
                    DataObjectGroups = [new EvidenceRecordHashTreeRenewalGroup { EvidenceRecord = submitted, DataObjects = dataObjects }],
                    DigestAlgorithm = algorithm,
                    TsaUri = context.TsaUri,
                    FetchTimestampResponse = context.FetchTimestampResponse,
                    NodeArity = context.NodeArity,
                    CryptoInfos = context.CryptoInfos,
                    StateDigestAlgorithmField = context.StateDigestAlgorithmField,
                    TimestampPolicyOid = context.TimestampPolicyOid
                },
                pool,
                cancellationToken).ConfigureAwait(false);

            //The renewal owns the records it produced and disposes them, so the one this result hands back is
            //read out of its octets — the same move every caller of the shipped renewal makes when the record
            //has to outlive the call.
            EvidenceRecord renewed = EvidenceRecord.Read(renewal.EvidenceRecords[0].AsReadOnlySpan(), pool);

            return PreservationDigestListRenewalResult.Renewed(renewed, renewal.ArchiveTime);
        }
    }


    /// <summary>
    /// States whether every supplied data object hashes to a digest value the submission carries, each value
    /// answering for at most one object.
    /// </summary>
    /// <param name="digestValues">The digest values the submission states.</param>
    /// <param name="dataObjects">The data objects the caller holds.</param>
    /// <param name="algorithm">The algorithm the submission's digest method named.</param>
    /// <param name="pool">The memory pool the recomputed digests are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when every supplied object is answered for by a digest value of its own.</returns>
    /// <remarks>
    /// Every digest is computed through the registered digest seam, never a framework hash, so a submission is
    /// checked with the same machinery the evidence itself is built with. Matching is one value per object: two
    /// identical objects need two identical values, which is what the submission would carry for them.
    /// </remarks>
    private static async ValueTask<bool> StateAgreementAsync(
        IReadOnlyList<DigestValue> digestValues,
        IReadOnlyList<ReadOnlyMemory<byte>> dataObjects,
        PkiDigestAlgorithm algorithm,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        bool[] matched = new bool[digestValues.Count];
        for(int objectIndex = 0; objectIndex < dataObjects.Count; ++objectIndex)
        {
            using DigestValue recomputed = await CryptographicKeyEvents.ComputeDigestAsync(
                dataObjects[objectIndex],
                algorithm.OutputByteLength,
                algorithm.DigestTag,
                pool,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            if(!TryMatch(digestValues, matched, recomputed, algorithm.OutputByteLength))
            {
                return false;
            }
        }

        return true;

        //One recomputed digest against the values not yet spoken for, comparing exactly as many octets as the
        //algorithm produces — a carrier may be longer than its digest when the pool it came from rounds a
        //rental up, and the octets beyond the digest are not part of it.
        static bool TryMatch(IReadOnlyList<DigestValue> digestValues, bool[] matched, DigestValue recomputed, int length)
        {
            ReadOnlySpan<byte> computed = recomputed.AsReadOnlySpan()[..length];
            for(int i = 0; i < digestValues.Count; ++i)
            {
                if(matched[i])
                {
                    continue;
                }

                if(computed.SequenceEqual(digestValues[i].AsReadOnlySpan()[..length]))
                {
                    matched[i] = true;

                    return true;
                }
            }

            return false;
        }
    }
}
