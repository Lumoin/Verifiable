using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// What one <see cref="EvidenceRecords.CreateInitialAsync"/> call needs: the data object groups the initial
/// Archive Timestamp is to bind, the algorithm the hash tree is built under, and how to reach a Time-Stamping
/// Authority.
/// </summary>
public sealed record EvidenceRecordCreationContext
{
    /// <summary>
    /// Gets the data object groups. One Evidence Record is produced per group, each carrying that group's own
    /// reduced hash tree and all of them sharing the one time-stamp taken over the tree's root — the
    /// "centralized" mode of
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-3.2">RFC 4998 clause 3.2</see>.
    /// </summary>
    public required IReadOnlyList<EvidenceRecordDataObjectGroup> DataObjectGroups { get; init; }

    /// <summary>Gets the algorithm the whole hash tree, and the time-stamp request over its root, are computed under.</summary>
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
    /// Gets the optional <c>cryptoInfos</c> attributes to place in every produced record, or
    /// <see langword="null"/> to omit the field. Clause 3.1 leaves what goes here to policy and states outright
    /// that nothing placed here is protected by any time-stamp.
    /// </summary>
    public IReadOnlyList<CmsAttribute>? CryptoInfos { get; init; }

    /// <summary>
    /// Gets whether the <c>digestAlgorithm [0]</c> field is written into every produced <c>ArchiveTimeStamp</c>.
    /// </summary>
    /// <remarks>
    /// Clause 4.2 step 5 admits two ways of binding the tree's algorithm: "The hash algorithm in the timestamp
    /// request MUST be the same as the hash algorithm of the hash tree, or the digestAlgorithm field of the
    /// ArchiveTimeStamp MUST be present and specify the hash algorithm of the hash tree." This surface always
    /// takes the first way — it requests the time-stamp under
    /// <see cref="DigestAlgorithm"/>, the same algorithm the tree was built under — so the field is redundant
    /// and omitted by default. Setting this states it as well, which costs a few octets and satisfies both
    /// alternatives at once.
    /// </remarks>
    public bool StateDigestAlgorithmField { get; init; }

    /// <summary>Gets the Time-Stamping Authority policy the request asks for, or <see langword="null"/> to state none.</summary>
    public string? TimestampPolicyOid { get; init; }
}


/// <summary>
/// The Evidence Records one initial Archive Timestamp produced, one per data object group.
/// </summary>
[DebuggerDisplay("EvidenceRecordCreation({EvidenceRecords.Count} records, archived {ArchiveTime})")]
public sealed class EvidenceRecordCreation: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>
    /// Initialises a new creation result.
    /// </summary>
    /// <param name="evidenceRecords">One record per data object group, in the order the groups were supplied. Ownership transfers to this instance.</param>
    /// <param name="archiveTime">The <c>genTime</c> the acquired time-stamp asserts.</param>
    internal EvidenceRecordCreation(IReadOnlyList<EvidenceRecord> evidenceRecords, DateTimeOffset archiveTime)
    {
        EvidenceRecords = evidenceRecords;
        ArchiveTime = archiveTime;
    }


    /// <summary>Gets one record per data object group, in the order the groups were supplied. Owned by this instance.</summary>
    public IReadOnlyList<EvidenceRecord> EvidenceRecords { get; }

    /// <summary>Gets the <c>genTime</c> the acquired time-stamp asserts — the instant every produced record proves its data objects existed at.</summary>
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


/// <summary>
/// What one <see cref="EvidenceRecords.VerifyArchiveTimeStampAsync"/> call needs: the structure to verify and
/// the data object it is claimed to prove the existence of.
/// </summary>
public sealed record EvidenceRecordArchiveTimeStampVerificationContext
{
    /// <summary>Gets the <c>ArchiveTimeStamp</c> to verify.</summary>
    public required EvidenceRecordArchiveTimeStamp ArchiveTimeStamp { get; init; }

    /// <summary>Gets the archived data object, as a view the caller owns for the duration of the call. It is hashed under the structure's own algorithm.</summary>
    public required ReadOnlyMemory<byte> DataObject { get; init; }
}


/// <summary>
/// What one <see cref="EvidenceRecords.VerifyAsync"/> call needs: the record to verify, the data object it is
/// claimed to prove, and optionally the whole data object group for the exclusivity check clause 4.3 and clause
/// 5.3 both offer.
/// </summary>
public sealed record EvidenceRecordVerificationContext
{
    /// <summary>Gets the Evidence Record to verify. The caller owns it.</summary>
    public required EvidenceRecord EvidenceRecord { get; init; }

    /// <summary>Gets the archived data object, as a view the caller owns for the duration of the call.</summary>
    public required ReadOnlyMemory<byte> DataObject { get; init; }

    /// <summary>
    /// Gets every data object of the group <see cref="DataObject"/> belongs to, or an empty list to skip the
    /// group check.
    /// </summary>
    /// <remarks>
    /// When supplied, the additional proof of clause 4.3 is performed: "it can be verified additionally, that
    /// only the hash values of the given data objects are in the first hash-value list", generalised by clause
    /// 5.3 to "each first Archive Timestamp of the first ArchiveTimeStampChain". The check therefore applies to
    /// the record's initial Archive Timestamp only, and it fails when that list holds hash values from a wider
    /// tree — which is the correct answer to the question asked, since such a list does not state that the
    /// record binds this group and nothing else.
    /// </remarks>
    public IReadOnlyList<ReadOnlyMemory<byte>> DataObjectGroup { get; init; } = [];
}


/// <summary>
/// The Evidence Record Syntax of <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see>:
/// creating an initial Evidence Record over one or more data object groups, and verifying a record's
/// <c>ArchiveTimeStamp</c>, <c>ArchiveTimeStampChain</c> and <c>ArchiveTimeStampSequence</c> structures against
/// the data object they are claimed to prove.
/// </summary>
/// <remarks>
/// <para>
/// <strong>What this surface establishes, and what it does not.</strong> Verification here is the structural
/// half of clauses 4.3 and 5.3: the reduced hash trees carry the data object up to the roots the embedded
/// time-stamps bind, the chains link to one another the way clause 5.2's two renewal procedures leave them, one
/// algorithm governs each chain, and the asserted times ascend. Whether each embedded time-stamp is itself
/// trustworthy — a chain to a trust anchor, a revocation state, an algorithm still reliable at the instant the
/// next structure was created — is the time-stamp validation building block of ETSI EN 319 102-1 clause 5.4,
/// which a caller composes with the times this surface reports.
/// </para>
/// <para>
/// <strong>Digests and time-stamps go through the seams.</strong> Every hash value is taken through the
/// registered <see cref="ComputeDigestDelegate"/> and every time-stamp through
/// <see cref="TimestampAcquisition"/>, which verifies a token before it is ever attached. Nothing here computes
/// a digest with a framework hash or attaches a token it has not checked binds the root it was requested for.
/// </para>
/// <para>
/// <strong>DER at rest.</strong> Everything this surface emits is DER, and everything it reads back it reads as
/// the octets it was given. Clause 5.2's Hash-Tree Renewal hashes a standalone DER encoding of the chains
/// accumulated so far, so a record whose chains were re-encoded on a round trip would silently fail every
/// renewal built on top of it.
/// </para>
/// </remarks>
public static class EvidenceRecords
{
    /// <summary>
    /// The tag the encoders put on the pooled octets they return: a DER-encoded structure of the Evidence
    /// Record Syntax.
    /// </summary>
    private static Tag EncodedStructureTag => EvidenceRecord.ValueTag;


    /// <summary>
    /// Encodes one <c>ArchiveTimeStamp</c> (RFC 4998 clause 4.1) from its parts.
    /// </summary>
    /// <param name="digestAlgorithm">The <c>digestAlgorithm [0]</c> field, or <see langword="null"/> to omit it (see <see cref="EvidenceRecordCreationContext.StateDigestAlgorithmField"/>).</param>
    /// <param name="attributes">The <c>attributes [1]</c> members, or <see langword="null"/> to omit the field. The field is a <c>SET OF</c>, so the members are emitted in the canonical order DER requires whatever order they arrive in.</param>
    /// <param name="reducedHashtree">The <c>reducedHashtree [2]</c> lists, leaf level first, or <see langword="null"/> to omit the field.</param>
    /// <param name="timeStamp">The whole encoding of the <c>timeStamp</c> field: a <c>ContentInfo</c>, which for an RFC 3161 authority is the time-stamp token as it arrived.</param>
    /// <param name="pool">The memory pool the encoded value is rented from.</param>
    /// <returns>The encoded <c>ArchiveTimeStamp</c>. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="timeStamp"/> is empty.</exception>
    public static PooledMemory EncodeArchiveTimeStamp(
        AlgorithmIdentifier? digestAlgorithm,
        IReadOnlyList<CmsAttribute>? attributes,
        IReadOnlyList<EvidenceRecordPartialHashtree>? reducedHashtree,
        ReadOnlyMemory<byte> timeStamp,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(timeStamp.IsEmpty)
        {
            throw new ArgumentException("An ArchiveTimeStamp carries a timeStamp field (RFC 4998 clause 4.1).", nameof(timeStamp));
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            if(digestAlgorithm is AlgorithmIdentifier algorithm)
            {
                using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    //AlgorithmIdentifier.parameters is omitted rather than written as NULL, per RFC 5754 §2.
                    writer.WriteObjectIdentifier(algorithm.Oid);
                }
            }

            if(attributes is { Count: > 0 })
            {
                using(writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 1)))
                {
                    for(int i = 0; i < attributes.Count; ++i)
                    {
                        writer.WriteEncodedValue(attributes[i].AsReadOnlySpan());
                    }
                }
            }

            if(reducedHashtree is { Count: > 0 })
            {
                using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2)))
                {
                    for(int i = 0; i < reducedHashtree.Count; ++i)
                    {
                        using(writer.PushSequence())
                        {
                            IReadOnlyList<ReadOnlyMemory<byte>> hashValues = reducedHashtree[i].HashValues;
                            for(int j = 0; j < hashValues.Count; ++j)
                            {
                                writer.WriteOctetString(hashValues[j].Span);
                            }
                        }
                    }
                }
            }

            writer.WriteEncodedValue(timeStamp.Span);
        }

        return Materialise(writer, pool);
    }


    /// <summary>
    /// Encodes one <c>ArchiveTimeStampChain ::= SEQUENCE OF ArchiveTimeStamp</c> (RFC 4998 clause 5.1) from the
    /// whole encodings of its members, which are written verbatim.
    /// </summary>
    /// <param name="archiveTimeStamps">The members, in the ascending time order clause 5.1 requires.</param>
    /// <param name="pool">The memory pool the encoded value is rented from.</param>
    /// <returns>The encoded chain. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When no member is supplied.</exception>
    public static PooledMemory EncodeArchiveTimeStampChain(IReadOnlyList<ReadOnlyMemory<byte>> archiveTimeStamps, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(archiveTimeStamps);
        ArgumentNullException.ThrowIfNull(pool);
        if(archiveTimeStamps.Count == 0)
        {
            throw new ArgumentException("An ArchiveTimeStampChain carries at least one ArchiveTimeStamp (RFC 4998 clause 5.1).", nameof(archiveTimeStamps));
        }

        return EncodeSequenceOf(archiveTimeStamps, pool);
    }


    /// <summary>
    /// Encodes one <c>ArchiveTimeStampSequence ::= SEQUENCE OF ArchiveTimeStampChain</c> (RFC 4998 clause 5.1)
    /// from the whole encodings of its chains, which are written verbatim.
    /// </summary>
    /// <param name="archiveTimeStampChains">The chains, in the chronological order clause 5.1 requires.</param>
    /// <param name="pool">The memory pool the encoded value is rented from.</param>
    /// <returns>The encoded sequence. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When no chain is supplied.</exception>
    /// <remarks>
    /// This is the <c>atsc(i)</c> of clause 5.2's Hash-Tree Renewal: "atsc(i) is the encoded
    /// ArchiveTimeStampSequence, the concatenation of all previous Archive Timestamp Chains (in chronological
    /// order) related to data object d(i)", with the clause's own note that "The ArchiveTimeStampChains used are
    /// DER encoded, i.e., they contain sequence and length tags". The value returned is a complete element with
    /// its own outer <c>SEQUENCE</c> tag and length octets on top of each chain's; concatenating the chains
    /// without that wrapper produces different, wrong octets.
    /// </remarks>
    public static PooledMemory EncodeArchiveTimeStampSequence(IReadOnlyList<ReadOnlyMemory<byte>> archiveTimeStampChains, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(archiveTimeStampChains);
        ArgumentNullException.ThrowIfNull(pool);
        if(archiveTimeStampChains.Count == 0)
        {
            throw new ArgumentException("An ArchiveTimeStampSequence carries at least one ArchiveTimeStampChain (RFC 4998 clause 5.1).", nameof(archiveTimeStampChains));
        }

        return EncodeSequenceOf(archiveTimeStampChains, pool);
    }


    /// <summary>
    /// Creates the initial Evidence Record of clause 3.2 over the supplied data object groups: build the hash
    /// tree, obtain one time-stamp over its root, and emit one record per group.
    /// </summary>
    /// <param name="context">The groups, the algorithm, and how to reach the Time-Stamping Authority.</param>
    /// <param name="pool">The memory pool every buffer this call rents comes from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The produced records. The caller owns and disposes the result.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="context"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="EvidenceRecordCreationException">When no data object was supplied, or the acquired token does not bind the tree's root.</exception>
    /// <exception cref="TimestampAcquisitionException">When the authority could not be reached, or its response failed a check.</exception>
    /// <remarks>
    /// The token is acquired through <see cref="TimestampAcquisition.AcquireAsync"/>, which verifies the
    /// response — its status, its own message imprint against the request, and its nonce — before returning it,
    /// and this method additionally asserts that the imprint is octet for octet the root the tree produced
    /// before writing it into any record. A token that does not bind the root is never attached.
    /// </remarks>
    public static async ValueTask<EvidenceRecordCreation> CreateInitialAsync(
        EvidenceRecordCreationContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        if(context.DataObjectGroups.Count == 0)
        {
            throw new EvidenceRecordCreationException(
                EvidenceRecordCreationFailureKind.NoDataObject,
                "An initial Archive Timestamp is created over at least one data object group (RFC 4998 clause 4.2).");
        }

        using EvidenceRecordHashTreeBuild build = await EvidenceRecordHashTree.BuildAsync(
            new EvidenceRecordHashTreeBuildContext
            {
                DataObjectGroups = context.DataObjectGroups,
                DigestAlgorithm = context.DigestAlgorithm,
                NodeArity = context.NodeArity
            },
            pool,
            cancellationToken).ConfigureAwait(false);

        using AcquiredTimestampToken token = await TimestampAcquisition.AcquireAsync(
            build.Root,
            context.TsaUri,
            context.FetchTimestampResponse,
            pool,
            context.TimestampPolicyOid,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        if(!token.Info.IsRead || token.Info.MessageImprint is null)
        {
            throw new EvidenceRecordCreationException(
                EvidenceRecordCreationFailureKind.TimestampNotUsable,
                "The acquired time-stamp token's TSTInfo could not be read, so what it binds cannot be established.");
        }

        if(!token.Info.MessageImprint.AsReadOnlySpan().SequenceEqual(build.Root.AsReadOnlySpan()))
        {
            throw new EvidenceRecordCreationException(
                EvidenceRecordCreationFailureKind.TimestampDoesNotBindRoot,
                "The acquired time-stamp token does not bind the root of the hash tree it was requested for (RFC 4998 clause 4.2 step 5).");
        }

        AlgorithmIdentifier? statedAlgorithm = context.StateDigestAlgorithmField ? context.DigestAlgorithm.Identifier : null;
        var records = new List<EvidenceRecord>(context.DataObjectGroups.Count);
        try
        {
            for(int groupIndex = 0; groupIndex < build.ReducedHashtrees.Count; ++groupIndex)
            {
                records.Add(BuildRecord(
                    statedAlgorithm,
                    context.DigestAlgorithm.Identifier,
                    context.CryptoInfos,
                    build.ReducedHashtrees[groupIndex],
                    token.Token.AsReadOnlyMemory(),
                    pool));
            }

            return new EvidenceRecordCreation(records, token.Info.GenerationTime);
        }
        catch
        {
            for(int i = 0; i < records.Count; ++i)
            {
                records[i].Dispose();
            }

            throw;
        }

        //Encodes one group's Archive Timestamp, the chain that holds it and the Evidence Record that carries
        //that chain, disposing the two intermediate encodings whatever happens: only the record outlives the
        //call, and it owns its own octets.
        static EvidenceRecord BuildRecord(
            AlgorithmIdentifier? statedAlgorithm,
            AlgorithmIdentifier treeAlgorithm,
            IReadOnlyList<CmsAttribute>? cryptoInfos,
            IReadOnlyList<EvidenceRecordPartialHashtree> reducedHashtree,
            ReadOnlyMemory<byte> timeStamp,
            BaseMemoryPool pool)
        {
            PooledMemory? archiveTimeStamp = null;
            PooledMemory? chain = null;
            try
            {
                archiveTimeStamp = EncodeArchiveTimeStamp(statedAlgorithm, attributes: null, reducedHashtree, timeStamp, pool);
                chain = EncodeArchiveTimeStampChain([archiveTimeStamp.AsReadOnlyMemory()], pool);

                return EvidenceRecord.Create([treeAlgorithm], cryptoInfos, [chain.AsReadOnlyMemory()], pool);
            }
            finally
            {
                chain?.Dispose();
                archiveTimeStamp?.Dispose();
            }
        }
    }


    /// <summary>
    /// Performs the Timestamp Renewal of
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.2">clause 5.2</see>: re-timestamps the most
    /// recent <c>ArchiveTimeStamp</c> of every supplied record and appends the result to that record's own most
    /// recent <c>ArchiveTimeStampChain</c>.
    /// </summary>
    /// <param name="context">The records to renew and how to reach the Time-Stamping Authority.</param>
    /// <param name="pool">The memory pool every buffer this call rents comes from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The renewed records. The caller owns and disposes the result; the source records are untouched.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="context"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="EvidenceRecordCreationException">When no record was supplied, a record carries no structure to renew, a batch does not share one hash algorithm, the acquired token does not bind the tree's root, or its <c>genTime</c> is not after the Archive Timestamp being renewed.</exception>
    /// <exception cref="TimestampAcquisitionException">When the authority could not be reached, or its response failed a check.</exception>
    /// <remarks>
    /// <para>
    /// <strong>What is hashed.</strong> Clause 5.2 says "the content of the timeStamp field of the old Archive
    /// Timestamp has to be hashed and timestamped by a new Archive Timestamp". The octets hashed here are the
    /// whole <c>timeStamp</c> element, its own tag and length octets included. Third-party records this library
    /// was checked against carry the hash of the whole element, and the wording is the same
    /// whole-element-inclusion rule <c>atsc(i)</c> states explicitly for the sibling procedure.
    /// </para>
    /// <para>
    /// <strong>The algorithm is derived, not stated.</strong> Clause 5.2: "This hash tree of the new Archive
    /// Timestamp MUST use the same hash algorithm as the old one, which is specified in the digestAlgorithm
    /// field of the Archive Timestamp or, if this value is not set (as it is optional), within the timestamp
    /// itself." A batch whose records resolve to different algorithms is refused rather than split silently.
    /// </para>
    /// <para>
    /// <strong>The reduced hash tree is always written.</strong> Clause 5.2 permits leaving it out — "The new
    /// Archive Timestamp MAY not contain a reducedHashtree field, if the timestamp only simply covers the
    /// previous timestamp" — which is a permission, not an instruction. A structure that names what it covers is
    /// checkable on its own, so this surface always states it; <see cref="VerifyAsync"/> accepts both forms,
    /// because records written the other way exist.
    /// </para>
    /// <para>
    /// <strong>Every prior chain is carried forward octet for octet.</strong> Only the most recent chain grows,
    /// and it grows by appending; the members already in it are written back verbatim. A later Hash-Tree Renewal
    /// hashes these octets, so re-encoding any of them would break every renewal built on top.
    /// </para>
    /// </remarks>
    public static async ValueTask<EvidenceRecordRenewal> RenewTimestampAsync(
        EvidenceRecordTimestampRenewalContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        if(context.EvidenceRecords.Count == 0)
        {
            throw new EvidenceRecordCreationException(
                EvidenceRecordCreationFailureKind.NoEvidenceRecord,
                "A Timestamp Renewal renews at least one Evidence Record (RFC 4998 clause 5.2).");
        }

        var sources = new List<EvidenceRecordRenewalSource>(context.EvidenceRecords.Count);
        var groups = new List<EvidenceRecordDataObjectGroup>(context.EvidenceRecords.Count);
        for(int i = 0; i < context.EvidenceRecords.Count; ++i)
        {
            EvidenceRecordRenewalSource source = await ReadRenewalSourceAsync(context.EvidenceRecords[i], pool, cancellationToken).ConfigureAwait(false);
            if(i > 0 && source.Algorithm.Identifier != sources[0].Algorithm.Identifier)
            {
                throw new EvidenceRecordCreationException(
                    EvidenceRecordCreationFailureKind.RenewalAlgorithmMismatch,
                    "A Timestamp Renewal of several Evidence Records builds one hash tree, and clause 5.2 binds that tree to the algorithm of the Archive Timestamp being renewed, which these records do not share.");
            }

            sources.Add(source);
            groups.Add(new EvidenceRecordDataObjectGroup { DataObjects = [source.Tip.TimeStamp] });
        }

        PkiDigestAlgorithm algorithm = sources[0].Algorithm;
        using EvidenceRecordHashTreeBuild build = await EvidenceRecordHashTree.BuildAsync(
            new EvidenceRecordHashTreeBuildContext
            {
                DataObjectGroups = groups,
                DigestAlgorithm = algorithm,
                NodeArity = context.NodeArity
            },
            pool,
            cancellationToken).ConfigureAwait(false);

        using AcquiredTimestampToken token = await AcquireRenewalTokenAsync(
            build.Root, sources, context.TsaUri, context.FetchTimestampResponse, context.TimestampPolicyOid, pool, cancellationToken).ConfigureAwait(false);

        AlgorithmIdentifier? statedAlgorithm = context.StateDigestAlgorithmField ? algorithm.Identifier : null;
        var renewed = new List<EvidenceRecord>(context.EvidenceRecords.Count);
        try
        {
            for(int i = 0; i < context.EvidenceRecords.Count; ++i)
            {
                renewed.Add(AppendToLatestChain(
                    context.EvidenceRecords[i], statedAlgorithm, context.CryptoInfos, build.ReducedHashtrees[i], token.Token.AsReadOnlyMemory(), pool));
            }

            return new EvidenceRecordRenewal(EvidenceRecordRenewalKind.TimestampRenewal, renewed, token.Info.GenerationTime);
        }
        catch
        {
            for(int i = 0; i < renewed.Count; ++i)
            {
                renewed[i].Dispose();
            }

            throw;
        }

        //Rewrites one record with a new ArchiveTimeStamp appended to its most recent chain: every earlier chain
        //is written back verbatim, the most recent chain is re-encoded from its own members' verbatim encodings
        //plus the new one, and the digestAlgorithms field is unchanged because the algorithm did not change.
        static EvidenceRecord AppendToLatestChain(
            EvidenceRecord source,
            AlgorithmIdentifier? statedAlgorithm,
            IReadOnlyList<CmsAttribute>? cryptoInfos,
            IReadOnlyList<EvidenceRecordPartialHashtree> reducedHashtree,
            ReadOnlyMemory<byte> timeStamp,
            BaseMemoryPool pool)
        {
            IReadOnlyList<EvidenceRecordArchiveTimeStampChain> chains = source.ArchiveTimeStampSequence.Chains;
            IReadOnlyList<EvidenceRecordArchiveTimeStamp> members = chains[^1].ArchiveTimeStamps;

            PooledMemory? archiveTimeStamp = null;
            PooledMemory? latestChain = null;
            List<CmsAttribute>? carriedCryptoInfos = null;
            try
            {
                archiveTimeStamp = EncodeArchiveTimeStamp(statedAlgorithm, attributes: null, reducedHashtree, timeStamp, pool);

                var latestMembers = new List<ReadOnlyMemory<byte>>(members.Count + 1);
                for(int i = 0; i < members.Count; ++i)
                {
                    latestMembers.Add(members[i].Encoding);
                }

                latestMembers.Add(archiveTimeStamp.AsReadOnlyMemory());
                latestChain = EncodeArchiveTimeStampChain(latestMembers, pool);

                var chainEncodings = new List<ReadOnlyMemory<byte>>(chains.Count);
                for(int i = 0; i < chains.Count - 1; ++i)
                {
                    chainEncodings.Add(chains[i].Encoding);
                }

                chainEncodings.Add(latestChain.AsReadOnlyMemory());

                carriedCryptoInfos = cryptoInfos is null ? CopyCryptoInfos(source, pool) : null;

                return EvidenceRecord.Create(source.DigestAlgorithms, cryptoInfos ?? carriedCryptoInfos, chainEncodings, pool);
            }
            finally
            {
                DisposeAll(carriedCryptoInfos);
                latestChain?.Dispose();
                archiveTimeStamp?.Dispose();
            }
        }
    }


    /// <summary>
    /// Performs the Hash-Tree Renewal of
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.2">clause 5.2</see>: re-hashes every supplied
    /// data object together with the encoded sequence of its record's prior chains under a new algorithm, and
    /// appends a new <c>ArchiveTimeStampChain</c> holding the Archive Timestamp over that tree.
    /// </summary>
    /// <param name="context">The groups to renew, the new algorithm, and how to reach the Time-Stamping Authority.</param>
    /// <param name="pool">The memory pool every buffer this call rents comes from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The renewed records. The caller owns and disposes the result; the source records are untouched.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="context"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="EvidenceRecordCreationException">When no group or an empty group was supplied, a record carries no structure to renew, the acquired token does not bind the tree's root, or its <c>genTime</c> is not after the Archive Timestamp being renewed.</exception>
    /// <exception cref="TimestampAcquisitionException">When the authority could not be reached, or its response failed a check.</exception>
    /// <remarks>
    /// <para>
    /// The procedure is the clause's own six steps. Step 1 selects the new algorithm
    /// (<see cref="EvidenceRecordHashTreeRenewalContext.DigestAlgorithm"/>). Step 2 selects the data objects
    /// "that are still present and not deleted" — an object simply left out is an object the renewed record
    /// stops proving, which clause 1.2 states is the point of the construction. Step 3 computes
    /// <c>ha(i) = H(atsc(i))</c> over a standalone encoding of every prior chain of that group's record. Step 4
    /// pairs each data object's hash with that value
    /// (<see cref="ComputeHashTreeRenewalValueAsync"/>). Step 5 builds a hash tree over those values, and step 6
    /// puts the resulting Archive Timestamp alone in a new chain appended to the sequence.
    /// </para>
    /// <para>
    /// <strong>The <c>digestAlgorithms</c> field gains the new algorithm once.</strong> Clause 3.1 states that
    /// "The ordering of the values is not relevant" and says nothing about repetition; a record that renewed
    /// twice under one algorithm names it once, which is what third-party records with more chains than
    /// algorithms carry.
    /// </para>
    /// </remarks>
    public static async ValueTask<EvidenceRecordRenewal> RenewHashTreeAsync(
        EvidenceRecordHashTreeRenewalContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        if(context.DataObjectGroups.Count == 0)
        {
            throw new EvidenceRecordCreationException(
                EvidenceRecordCreationFailureKind.NoEvidenceRecord,
                "A Hash-Tree Renewal renews at least one Evidence Record (RFC 4998 clause 5.2).");
        }

        PkiDigestAlgorithm algorithm = context.DigestAlgorithm;
        var sources = new List<EvidenceRecordRenewalSource>(context.DataObjectGroups.Count);
        var owned = new List<DigestValue>();
        var leafGroups = new List<IReadOnlyList<ReadOnlyMemory<byte>>>(context.DataObjectGroups.Count);
        try
        {
            for(int groupIndex = 0; groupIndex < context.DataObjectGroups.Count; ++groupIndex)
            {
                EvidenceRecordHashTreeRenewalGroup group = context.DataObjectGroups[groupIndex];
                if(group.DataObjects.Count == 0)
                {
                    throw new EvidenceRecordCreationException(
                        EvidenceRecordCreationFailureKind.NoDataObject,
                        "A Hash-Tree Renewal group holds at least one still-present data object (RFC 4998 clause 5.2 step 2).");
                }

                sources.Add(await ReadRenewalSourceAsync(group.EvidenceRecord, pool, cancellationToken).ConfigureAwait(false));

                //Step 3: ha(i) is computed once per group, over the standalone encoding of every chain that
                //record has accumulated, because step 4 pairs the same value with every member of the group.
                using DigestValue sequenceHash = await ComputeArchiveTimeStampSequenceHashAsync(
                    group.EvidenceRecord.ArchiveTimeStampSequence.Chains, group.EvidenceRecord.ArchiveTimeStampSequence.Chains.Count, algorithm, pool, cancellationToken).ConfigureAwait(false);

                var leaves = new List<ReadOnlyMemory<byte>>(group.DataObjects.Count);
                for(int objectIndex = 0; objectIndex < group.DataObjects.Count; ++objectIndex)
                {
                    using DigestValue dataObjectHash = await CryptographicKeyEvents.ComputeDigestAsync(
                        group.DataObjects[objectIndex], algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
                    DigestValue leaf = await CombineRenewalHashesAsync(
                        dataObjectHash.AsReadOnlyMemory(), sequenceHash.AsReadOnlyMemory(), algorithm, pool, cancellationToken).ConfigureAwait(false);
                    owned.Add(leaf);
                    leaves.Add(leaf.AsReadOnlyMemory()[..algorithm.OutputByteLength]);
                }

                leafGroups.Add(leaves);
            }

            //Step 5: the tree is built over the values step 4 produced, which are hash values already.
            using EvidenceRecordHashTreeBuild build = await EvidenceRecordHashTree.BuildFromHashValuesAsync(
                new EvidenceRecordHashTreeHashValueBuildContext
                {
                    HashValueGroups = leafGroups,
                    DigestAlgorithm = algorithm,
                    NodeArity = context.NodeArity
                },
                pool,
                cancellationToken).ConfigureAwait(false);

            using AcquiredTimestampToken token = await AcquireRenewalTokenAsync(
                build.Root, sources, context.TsaUri, context.FetchTimestampResponse, context.TimestampPolicyOid, pool, cancellationToken).ConfigureAwait(false);

            AlgorithmIdentifier? statedAlgorithm = context.StateDigestAlgorithmField ? algorithm.Identifier : null;
            var renewed = new List<EvidenceRecord>(context.DataObjectGroups.Count);
            try
            {
                for(int groupIndex = 0; groupIndex < context.DataObjectGroups.Count; ++groupIndex)
                {
                    renewed.Add(AppendNewChain(
                        context.DataObjectGroups[groupIndex].EvidenceRecord,
                        algorithm.Identifier,
                        statedAlgorithm,
                        context.CryptoInfos,
                        build.ReducedHashtrees[groupIndex],
                        token.Token.AsReadOnlyMemory(),
                        pool));
                }

                return new EvidenceRecordRenewal(EvidenceRecordRenewalKind.HashTreeRenewal, renewed, token.Info.GenerationTime);
            }
            catch
            {
                for(int i = 0; i < renewed.Count; ++i)
                {
                    renewed[i].Dispose();
                }

                throw;
            }
        }
        finally
        {
            for(int i = 0; i < owned.Count; ++i)
            {
                owned[i].Dispose();
            }
        }

        //Rewrites one record with a new chain appended: every chain the record already carries is written back
        //verbatim, the new chain holds the renewal's single Archive Timestamp, and digestAlgorithms names the
        //new algorithm unless it already did.
        static EvidenceRecord AppendNewChain(
            EvidenceRecord source,
            AlgorithmIdentifier renewalAlgorithm,
            AlgorithmIdentifier? statedAlgorithm,
            IReadOnlyList<CmsAttribute>? cryptoInfos,
            IReadOnlyList<EvidenceRecordPartialHashtree> reducedHashtree,
            ReadOnlyMemory<byte> timeStamp,
            BaseMemoryPool pool)
        {
            IReadOnlyList<EvidenceRecordArchiveTimeStampChain> chains = source.ArchiveTimeStampSequence.Chains;

            PooledMemory? archiveTimeStamp = null;
            PooledMemory? newChain = null;
            List<CmsAttribute>? carriedCryptoInfos = null;
            try
            {
                archiveTimeStamp = EncodeArchiveTimeStamp(statedAlgorithm, attributes: null, reducedHashtree, timeStamp, pool);
                newChain = EncodeArchiveTimeStampChain([archiveTimeStamp.AsReadOnlyMemory()], pool);

                var chainEncodings = new List<ReadOnlyMemory<byte>>(chains.Count + 1);
                for(int i = 0; i < chains.Count; ++i)
                {
                    chainEncodings.Add(chains[i].Encoding);
                }

                chainEncodings.Add(newChain.AsReadOnlyMemory());

                var algorithms = new List<AlgorithmIdentifier>(source.DigestAlgorithms.Count + 1);
                algorithms.AddRange(source.DigestAlgorithms);
                if(!algorithms.Contains(renewalAlgorithm))
                {
                    algorithms.Add(renewalAlgorithm);
                }

                carriedCryptoInfos = cryptoInfos is null ? CopyCryptoInfos(source, pool) : null;

                return EvidenceRecord.Create(algorithms, cryptoInfos ?? carriedCryptoInfos, chainEncodings, pool);
            }
            finally
            {
                DisposeAll(carriedCryptoInfos);
                newChain?.Dispose();
                archiveTimeStamp?.Dispose();
            }
        }
    }


    /// <summary>
    /// Computes the value clause 5.2's Hash-Tree Renewal makes the first list of a new chain's initial Archive
    /// Timestamp hold for one data object: <c>h(i)' = H(h(i) + ha(i))</c>.
    /// </summary>
    /// <param name="dataObject">The archived data object, as a view the caller owns for the duration of the call.</param>
    /// <param name="archiveTimeStampSequence">The standalone encoding of the <c>ArchiveTimeStampSequence</c> holding every prior chain — the <c>atsc(i)</c> of step 3, as <see cref="EncodeArchiveTimeStampSequence"/> produces it.</param>
    /// <param name="algorithm">The new chain's algorithm, which both hashes and the combination are taken under.</param>
    /// <param name="pool">The memory pool every buffer this call rents comes from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The value. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">When no digest delegate has been registered.</exception>
    /// <remarks>
    /// The combination is positional and unsorted; see <see cref="VerifyAsync"/> for RFC 4998's own contradiction
    /// on this point and the evidence the reading was settled by. This is the surface a caller reproduces the
    /// rule through, and it is the same code generation and verification both reach, so neither can drift from
    /// the other.
    /// </remarks>
    public static async ValueTask<DigestValue> ComputeHashTreeRenewalValueAsync(
        ReadOnlyMemory<byte> dataObject,
        ReadOnlyMemory<byte> archiveTimeStampSequence,
        PkiDigestAlgorithm algorithm,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        using DigestValue dataObjectHash = await CryptographicKeyEvents.ComputeDigestAsync(
            dataObject, algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
        using DigestValue sequenceHash = await CryptographicKeyEvents.ComputeDigestAsync(
            archiveTimeStampSequence, algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return await CombineRenewalHashesAsync(
            dataObjectHash.AsReadOnlyMemory(), sequenceHash.AsReadOnlyMemory(), algorithm, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies one <c>ArchiveTimeStamp</c> against a data object, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.3">clause 4.3</see>.
    /// </summary>
    /// <param name="context">The structure and the data object it is claimed to prove.</param>
    /// <param name="pool">The memory pool every buffer this call rents comes from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The conclusion, which the caller disposes in every case.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="context"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static async ValueTask<EvidenceRecordArchiveTimeStampVerification> VerifyArchiveTimeStampAsync(
        EvidenceRecordArchiveTimeStampVerificationContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);

        using TimestampTokenInfo info = await ReadTimeStampAsync(context.ArchiveTimeStamp, pool, cancellationToken).ConfigureAwait(false);
        if(!info.IsRead)
        {
            return new EvidenceRecordArchiveTimeStampVerification(
                EvidenceRecordVerificationStatus.TimestampNotRead, default, default, root: null);
        }

        PkiDigestAlgorithm? algorithm = ResolveDigestAlgorithm(context.ArchiveTimeStamp, info);
        if(algorithm is null)
        {
            return new EvidenceRecordArchiveTimeStampVerification(
                EvidenceRecordVerificationStatus.UnsupportedDigestAlgorithm, context.ArchiveTimeStamp.DigestAlgorithm ?? info.MessageImprintAlgorithm, info.GenerationTime, root: null);
        }

        using DigestValue dataObjectHash = await CryptographicKeyEvents.ComputeDigestAsync(
            context.DataObject, algorithm.Value.OutputByteLength, algorithm.Value.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return await VerifyArchiveTimeStampCoreAsync(
            context.ArchiveTimeStamp, info, algorithm.Value, dataObjectHash, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies a whole Evidence Record against a data object, per clause 3.3 and
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.3">clause 5.3</see>.
    /// </summary>
    /// <param name="context">The record, the data object it is claimed to prove, and optionally its group.</param>
    /// <param name="pool">The memory pool every buffer this call rents comes from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The conclusion, which the caller disposes in every case.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="context"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// <para>
    /// The walk is the clause's own. Step 1 verifies that "the first Archive Timestamp of the first
    /// ArchiveTimestampChain (the initial Archive Timestamp) contains the hash value of the data object". Step 2
    /// verifies, within each chain, that "The first hash value list of each ArchiveTimeStamp MUST contain the
    /// hash value of the timestamp of the Archive Timestamp before" and that "All Archive Timestamps within a
    /// chain MUST use the same hash algorithm". Step 3 verifies, for every chain after the first, that its
    /// initial member's first list "contains a hash value of the concatenation of the data object hash and the
    /// hash value of all older ArchiveTimeStampChain".
    /// </para>
    /// <para>
    /// <strong>The concatenation of step 3 is positional.</strong> RFC 4998 contradicts itself here: clause 5.2
    /// step 4 states "Concatenate each h(i) with ha(i) and generate hash values h(i)' = H (h(i)+ ha(i))", while
    /// the worked example of Figure 4 gives "h1' = H( binary sorted and concatenated (H(d1), ha(1)))". The two
    /// produce different values whenever <c>h(i)</c> sorts after <c>ha(i)</c>, so they are wire-incompatible and
    /// one of them has to be chosen. This library implements the step-4 prose — the data object hash first,
    /// then the hash of the encoded prior sequence, with no sorting — because that is what third-party
    /// Hash-Tree Renewal artifacts this implementation was checked against are built with. The choice is a
    /// single rule applied in one place (<see cref="CombineRenewalHashesAsync"/>) that generation
    /// (<see cref="RenewHashTreeAsync"/>) and verification both reach, so that changing it, if evidence ever
    /// demands, changes both at once.
    /// </para>
    /// <para>
    /// Coverage is reported per chain. Clause 5.2's Hash-Tree Renewal admits dropping data objects that are no
    /// longer present, so a record can perfectly well cover an object in its first chain and not in its second;
    /// <see cref="EvidenceRecordChainVerification.CoversDataObject"/> states that per chain instead of assuming
    /// it propagates.
    /// </para>
    /// </remarks>
    public static async ValueTask<EvidenceRecordVerification> VerifyAsync(
        EvidenceRecordVerificationContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);

        if(context.EvidenceRecord.HasEncryptionInfo)
        {
            return new EvidenceRecordVerification(EvidenceRecordVerificationStatus.EncryptionInfoPresent, [], null, null, null);
        }

        IReadOnlyList<EvidenceRecordArchiveTimeStampChain> chains = context.EvidenceRecord.ArchiveTimeStampSequence.Chains;
        if(chains.Count == 0)
        {
            return new EvidenceRecordVerification(EvidenceRecordVerificationStatus.Malformed, [], null, null, null);
        }

        var chainResults = new List<EvidenceRecordChainVerification>(chains.Count);
        try
        {
            EvidenceRecordVerificationStatus overall = EvidenceRecordVerificationStatus.Verified;
            DateTimeOffset? initialArchiveTime = null;
            DateTimeOffset? latestArchiveTime = null;
            DateTimeOffset? previousTime = null;

            for(int chainIndex = 0; chainIndex < chains.Count; ++chainIndex)
            {
                EvidenceRecordChainVerification chainResult = await VerifyChainAsync(
                    chains, chainIndex, context.DataObject, chainIndex == 0 ? context.DataObjectGroup : [], pool, cancellationToken).ConfigureAwait(false);
                chainResults.Add(chainResult);

                if(overall == EvidenceRecordVerificationStatus.Verified && chainResult.Status != EvidenceRecordVerificationStatus.Verified)
                {
                    overall = chainResult.Status;
                }

                for(int i = 0; i < chainResult.ArchiveTimeStamps.Count; ++i)
                {
                    if(chainResult.ArchiveTimeStamps[i].Status == EvidenceRecordVerificationStatus.TimestampNotRead)
                    {
                        //A structure whose time-stamp could not be read asserts no instant at all, so it is
                        //neither an instant to report nor one to compare an ordering against; the reason it did
                        //not verify is already the conclusion.
                        continue;
                    }

                    DateTimeOffset generationTime = chainResult.ArchiveTimeStamps[i].GenerationTime;
                    initialArchiveTime ??= generationTime;
                    latestArchiveTime = generationTime;

                    if(overall == EvidenceRecordVerificationStatus.Verified && previousTime is DateTimeOffset earlier && generationTime < earlier)
                    {
                        //Clause 5.1: "ArchiveTimeStampChain and ArchiveTimeStampSequence MUST be ordered
                        //ascending by time of timestamp." It is reported only when nothing else has already
                        //failed, so that the first reason a record stopped verifying is the one reported.
                        overall = EvidenceRecordVerificationStatus.TimestampsOutOfOrder;
                    }

                    previousTime = generationTime;
                }
            }

            return new EvidenceRecordVerification(overall, chainResults, initialArchiveTime, latestArchiveTime, StateCoveredUntil(chainResults));
        }
        catch
        {
            for(int i = 0; i < chainResults.Count; ++i)
            {
                chainResults[i].Dispose();
            }

            throw;
        }

        //Walks the per-chain conclusions for the longest unbroken run of proofs the data object is carried by,
        //and reports the instant that run reaches. It stops at the first chain that does not carry the object
        //and, within a chain, at the first member that did not verify: clause 5.2's Hash-Tree Renewal admits
        //dropping data objects, so a later chain can be perfectly valid and say nothing about this one.
        static DateTimeOffset? StateCoveredUntil(List<EvidenceRecordChainVerification> chainResults)
        {
            DateTimeOffset? coveredUntil = null;
            for(int chainIndex = 0; chainIndex < chainResults.Count; ++chainIndex)
            {
                if(!chainResults[chainIndex].CoversDataObject)
                {
                    return coveredUntil;
                }

                IReadOnlyList<EvidenceRecordArchiveTimeStampVerification> members = chainResults[chainIndex].ArchiveTimeStamps;
                for(int memberIndex = 0; memberIndex < members.Count; ++memberIndex)
                {
                    if(members[memberIndex].Status != EvidenceRecordVerificationStatus.Verified)
                    {
                        return coveredUntil;
                    }

                    coveredUntil = members[memberIndex].GenerationTime;
                }
            }

            return coveredUntil;
        }
    }


    /// <summary>
    /// Verifies one <c>ArchiveTimeStampChain</c> of a sequence: its initial member against the data object (or,
    /// for a chain after the first, against the Hash-Tree Renewal value the older chains produce), and every
    /// later member against the one before it.
    /// </summary>
    /// <param name="chains">Every chain of the sequence, needed because a chain after the first is proved against the encoding of the ones before it.</param>
    /// <param name="chainIndex">The zero-based index of the chain being verified.</param>
    /// <param name="dataObject">The archived data object.</param>
    /// <param name="dataObjectGroup">The group to check exclusivity for, or an empty list to skip the check.</param>
    /// <param name="pool">The memory pool every buffer rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The chain's conclusion, which the caller disposes.</returns>
    private static async ValueTask<EvidenceRecordChainVerification> VerifyChainAsync(
        IReadOnlyList<EvidenceRecordArchiveTimeStampChain> chains,
        int chainIndex,
        ReadOnlyMemory<byte> dataObject,
        IReadOnlyList<ReadOnlyMemory<byte>> dataObjectGroup,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<EvidenceRecordArchiveTimeStamp> members = chains[chainIndex].ArchiveTimeStamps;
        if(members.Count == 0)
        {
            return new EvidenceRecordChainVerification(EvidenceRecordVerificationStatus.Malformed, default, [], coversDataObject: false);
        }

        var memberResults = new List<EvidenceRecordArchiveTimeStampVerification>(members.Count);
        try
        {
            using TimestampTokenInfo initialInfo = await ReadTimeStampAsync(members[0], pool, cancellationToken).ConfigureAwait(false);
            if(!initialInfo.IsRead)
            {
                memberResults.Add(new EvidenceRecordArchiveTimeStampVerification(
                    EvidenceRecordVerificationStatus.TimestampNotRead, default, default, root: null));

                return new EvidenceRecordChainVerification(
                    EvidenceRecordVerificationStatus.TimestampNotRead, default, memberResults, coversDataObject: false);
            }

            PkiDigestAlgorithm? resolved = ResolveDigestAlgorithm(members[0], initialInfo);
            if(resolved is null)
            {
                memberResults.Add(new EvidenceRecordArchiveTimeStampVerification(
                    EvidenceRecordVerificationStatus.UnsupportedDigestAlgorithm,
                    members[0].DigestAlgorithm ?? initialInfo.MessageImprintAlgorithm,
                    initialInfo.GenerationTime,
                    root: null));

                return new EvidenceRecordChainVerification(
                    EvidenceRecordVerificationStatus.UnsupportedDigestAlgorithm,
                    members[0].DigestAlgorithm ?? initialInfo.MessageImprintAlgorithm,
                    memberResults,
                    coversDataObject: false);
            }

            PkiDigestAlgorithm algorithm = resolved.Value;
            EvidenceRecordVerificationStatus chainStatus = EvidenceRecordVerificationStatus.Verified;

            using(DigestValue initialProvedHash = chainIndex == 0
                ? await CryptographicKeyEvents.ComputeDigestAsync(
                    dataObject, algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false)
                : await ComputeHashTreeRenewalHashAsync(chains, chainIndex, dataObject, algorithm, pool, cancellationToken).ConfigureAwait(false))
            {
                EvidenceRecordArchiveTimeStampVerification initialResult = await VerifyArchiveTimeStampCoreAsync(
                    members[0], initialInfo, algorithm, initialProvedHash, pool, cancellationToken).ConfigureAwait(false);
                memberResults.Add(initialResult);

                if(initialResult.Status != EvidenceRecordVerificationStatus.Verified)
                {
                    //A chain after the first does not carry the data object directly; a first list that does not
                    //hold the Hash-Tree Renewal value is a broken link between chains, which is step 3 of clause
                    //5.3 rather than step 1's coverage question.
                    chainStatus = chainIndex > 0 && initialResult.Status == EvidenceRecordVerificationStatus.DataObjectNotCovered
                        ? EvidenceRecordVerificationStatus.ChainLinkageBroken
                        : initialResult.Status;
                }
                else if(dataObjectGroup.Count > 0)
                {
                    chainStatus = await StateGroupExclusivityAsync(members[0], dataObjectGroup, algorithm, pool, cancellationToken).ConfigureAwait(false);
                }
            }

            bool coversDataObject = memberResults[0].Status == EvidenceRecordVerificationStatus.Verified;
            for(int memberIndex = 1; memberIndex < members.Count; ++memberIndex)
            {
                using TimestampTokenInfo info = await ReadTimeStampAsync(members[memberIndex], pool, cancellationToken).ConfigureAwait(false);
                if(!info.IsRead)
                {
                    memberResults.Add(new EvidenceRecordArchiveTimeStampVerification(
                        EvidenceRecordVerificationStatus.TimestampNotRead, algorithm.Identifier, default, root: null));
                    chainStatus = ReplaceWhenVerified(chainStatus, EvidenceRecordVerificationStatus.TimestampNotRead);

                    continue;
                }

                PkiDigestAlgorithm? memberAlgorithm = ResolveDigestAlgorithm(members[memberIndex], info);
                if(memberAlgorithm is null || memberAlgorithm.Value.Identifier != algorithm.Identifier)
                {
                    //Clause 5.1 and clause 5.3 step 2: every member of one chain uses the same hash algorithm.
                    memberResults.Add(new EvidenceRecordArchiveTimeStampVerification(
                        EvidenceRecordVerificationStatus.ChainAlgorithmInconsistent,
                        members[memberIndex].DigestAlgorithm ?? info.MessageImprintAlgorithm,
                        info.GenerationTime,
                        root: null));
                    chainStatus = ReplaceWhenVerified(chainStatus, EvidenceRecordVerificationStatus.ChainAlgorithmInconsistent);

                    continue;
                }

                using DigestValue linkHash = await CryptographicKeyEvents.ComputeDigestAsync(
                    members[memberIndex - 1].TimeStamp, algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
                EvidenceRecordArchiveTimeStampVerification memberResult = await VerifyArchiveTimeStampCoreAsync(
                    members[memberIndex], info, algorithm, linkHash, pool, cancellationToken).ConfigureAwait(false);
                memberResults.Add(memberResult);

                if(memberResult.Status != EvidenceRecordVerificationStatus.Verified)
                {
                    chainStatus = ReplaceWhenVerified(
                        chainStatus,
                        memberResult.Status == EvidenceRecordVerificationStatus.DataObjectNotCovered
                            ? EvidenceRecordVerificationStatus.ChainLinkageBroken
                            : memberResult.Status);
                }
            }

            return new EvidenceRecordChainVerification(chainStatus, algorithm.Identifier, memberResults, coversDataObject);
        }
        catch
        {
            for(int i = 0; i < memberResults.Count; ++i)
            {
                memberResults[i].Dispose();
            }

            throw;
        }

        //Keeps the first non-verifying status a chain reached, so a later failure never overwrites the reason
        //the chain first stopped verifying.
        static EvidenceRecordVerificationStatus ReplaceWhenVerified(
            EvidenceRecordVerificationStatus current, EvidenceRecordVerificationStatus candidate) =>
            current == EvidenceRecordVerificationStatus.Verified ? candidate : current;
    }


    /// <summary>
    /// Verifies one <c>ArchiveTimeStamp</c> whose time-stamp has already been read and whose algorithm has
    /// already been resolved, against a value that is claimed to be in its first list of hash values.
    /// </summary>
    /// <param name="archiveTimeStamp">The structure to verify.</param>
    /// <param name="info">The already-read facts of its <c>timeStamp</c> field.</param>
    /// <param name="algorithm">The algorithm the reduced hash tree is walked under.</param>
    /// <param name="provedHash">The hash value the first list is claimed to hold. The caller owns it.</param>
    /// <param name="pool">The memory pool every buffer rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The conclusion, which the caller disposes.</returns>
    private static async ValueTask<EvidenceRecordArchiveTimeStampVerification> VerifyArchiveTimeStampCoreAsync(
        EvidenceRecordArchiveTimeStamp archiveTimeStamp,
        TimestampTokenInfo info,
        PkiDigestAlgorithm algorithm,
        DigestValue provedHash,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        //Step 4 of clause 4.3: "digestAlgorithm must correspond to hashAlgorithm field ... in messageImprint
        //field of timeStampToken". A structure whose stated tree algorithm is not the one its own time-stamp
        //took the root under states a root nothing checked.
        if(info.MessageImprintAlgorithm != algorithm.Identifier)
        {
            return new EvidenceRecordArchiveTimeStampVerification(
                EvidenceRecordVerificationStatus.RootMismatch, algorithm.Identifier, info.GenerationTime, root: null);
        }

        using EvidenceRecordRootComputation computation = await EvidenceRecordHashTree.ComputeRootAsync(
            new EvidenceRecordRootComputationContext
            {
                DataObjectHash = provedHash,
                ReducedHashtree = archiveTimeStamp.ReducedHashtree,
                DigestAlgorithm = algorithm
            },
            pool,
            cancellationToken).ConfigureAwait(false);

        if(computation.Status != EvidenceRecordRootStatus.Computed || computation.Root is null)
        {
            EvidenceRecordVerificationStatus status = computation.Status switch
            {
                EvidenceRecordRootStatus.HashValueNotInFirstList => EvidenceRecordVerificationStatus.DataObjectNotCovered,
                _ => EvidenceRecordVerificationStatus.Malformed
            };

            return new EvidenceRecordArchiveTimeStampVerification(status, algorithm.Identifier, info.GenerationTime, root: null);
        }

        if(info.MessageImprint is null || !info.MessageImprint.AsReadOnlySpan().SequenceEqual(computation.Root.AsReadOnlySpan()))
        {
            return new EvidenceRecordArchiveTimeStampVerification(
                EvidenceRecordVerificationStatus.RootMismatch, algorithm.Identifier, info.GenerationTime, root: null);
        }

        DigestValue root = CopyDigest(computation.Root.AsReadOnlySpan(), algorithm.DigestTag, pool);

        return new EvidenceRecordArchiveTimeStampVerification(
            EvidenceRecordVerificationStatus.Verified, algorithm.Identifier, info.GenerationTime, root);
    }


    /// <summary>
    /// Computes the value clause 5.2's Hash-Tree Renewal makes the first list of a new chain's initial member
    /// hold for one data object: <c>h(i)' = H(h(i) + ha(i))</c>, where <c>ha(i)</c> is the hash of the encoded
    /// <c>ArchiveTimeStampSequence</c> of every older chain.
    /// </summary>
    /// <param name="chains">Every chain of the sequence.</param>
    /// <param name="chainIndex">The index of the chain whose initial member is being proved; the chains before it are the ones hashed.</param>
    /// <param name="dataObject">The archived data object.</param>
    /// <param name="algorithm">The new chain's own algorithm, which every hash of this computation is taken under.</param>
    /// <param name="pool">The memory pool every buffer rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The value. The caller owns and disposes it.</returns>
    /// <remarks>
    /// The concatenation is positional, the data object hash first — see the remarks on <see cref="VerifyAsync"/>
    /// for the RFC's own contradiction here and why this reading was taken.
    /// </remarks>
    private static async ValueTask<DigestValue> ComputeHashTreeRenewalHashAsync(
        IReadOnlyList<EvidenceRecordArchiveTimeStampChain> chains,
        int chainIndex,
        ReadOnlyMemory<byte> dataObject,
        PkiDigestAlgorithm algorithm,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        using DigestValue sequenceHash = await ComputeArchiveTimeStampSequenceHashAsync(
            chains, chainIndex, algorithm, pool, cancellationToken).ConfigureAwait(false);
        using DigestValue dataObjectHash = await CryptographicKeyEvents.ComputeDigestAsync(
            dataObject, algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return await CombineRenewalHashesAsync(
            dataObjectHash.AsReadOnlyMemory(), sequenceHash.AsReadOnlyMemory(), algorithm, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Computes the <c>ha(i)</c> of clause 5.2 step 3: the hash of a standalone encoding of the
    /// <c>ArchiveTimeStampSequence</c> holding the first <paramref name="chainCount"/> chains.
    /// </summary>
    /// <param name="chains">Every chain of the sequence.</param>
    /// <param name="chainCount">How many of them, from the first, the encoding holds — every chain older than the one being produced or proved.</param>
    /// <param name="algorithm">The algorithm the hash is taken under.</param>
    /// <param name="pool">The memory pool every buffer rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The hash. The caller owns and disposes it.</returns>
    /// <remarks>
    /// The octets hashed are a complete element, its own outer <c>SEQUENCE</c> tag and length octets included on
    /// top of each chain's: "atsc(i) is the encoded ArchiveTimeStampSequence ... Note: The ArchiveTimeStampChains
    /// used are DER encoded, i.e., they contain sequence and length tags." Each chain is written back exactly as
    /// it was read, never re-encoded.
    /// </remarks>
    private static async ValueTask<DigestValue> ComputeArchiveTimeStampSequenceHashAsync(
        IReadOnlyList<EvidenceRecordArchiveTimeStampChain> chains,
        int chainCount,
        PkiDigestAlgorithm algorithm,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        var olderChains = new List<ReadOnlyMemory<byte>>(chainCount);
        for(int i = 0; i < chainCount; ++i)
        {
            olderChains.Add(chains[i].Encoding);
        }

        using PooledMemory archiveTimeStampSequence = EncodeArchiveTimeStampSequence(olderChains, pool);

        return await CryptographicKeyEvents.ComputeDigestAsync(
            archiveTimeStampSequence.AsReadOnlyMemory(), algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Combines the two hashes of clause 5.2 step 4 into the renewal value: <c>h(i)' = H(h(i) + ha(i))</c>, the
    /// data object's hash first and the encoded prior sequence's hash second, concatenated without sorting.
    /// </summary>
    /// <param name="dataObjectHash">The <c>h(i)</c> of step 4 — for a chain after the first, the hash of the data object under that chain's algorithm.</param>
    /// <param name="archiveTimeStampSequenceHash">The <c>ha(i)</c> of step 3.</param>
    /// <param name="algorithm">The algorithm both were computed under, and the combination is computed under.</param>
    /// <param name="pool">The memory pool every buffer rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The renewal value. The caller owns and disposes it.</returns>
    /// <remarks>
    /// <para>
    /// <strong>This is the one place the Hash-Tree Renewal combination rule exists</strong>, reached by
    /// generation (<see cref="RenewHashTreeAsync"/>), by verification (<see cref="VerifyAsync"/>) and by the
    /// surface a caller reproduces it through (<see cref="ComputeHashTreeRenewalValueAsync"/>). RFC 4998
    /// contradicts itself here — clause 5.2 step 4 states "Concatenate each h(i) with ha(i) and generate hash
    /// values h(i)' = H (h(i)+ ha(i))" while the worked example of Figure 4 states
    /// "h1' = H( binary sorted and concatenated (H(d1), ha(1)))" — and the two produce different values whenever
    /// <c>h(i)</c> sorts after <c>ha(i)</c>, so they are wire-incompatible and one has to be chosen. The step-4
    /// prose is what third-party renewed records carry, so it is what this library computes; keeping the rule in
    /// one place is what makes changing it, should evidence ever demand, a change to generation and verification
    /// at once rather than to one of them.
    /// </para>
    /// <para>
    /// Note that this combination is deliberately <em>not</em>
    /// <see cref="EvidenceRecordHashTree.CombineAsync"/>, which is the node rule of clause 4.2 and does sort.
    /// The two look alike and are not the same rule.
    /// </para>
    /// </remarks>
    private static async ValueTask<DigestValue> CombineRenewalHashesAsync(
        ReadOnlyMemory<byte> dataObjectHash,
        ReadOnlyMemory<byte> archiveTimeStampSequenceHash,
        PkiDigestAlgorithm algorithm,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        int total = algorithm.OutputByteLength * 2;
        using IMemoryOwner<byte> concatenation = pool.Rent(total);
        dataObjectHash[..algorithm.OutputByteLength].CopyTo(concatenation.Memory);
        archiveTimeStampSequenceHash[..algorithm.OutputByteLength].CopyTo(concatenation.Memory[algorithm.OutputByteLength..]);

        return await CryptographicKeyEvents.ComputeDigestAsync(
            concatenation.Memory[..total], algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Reads what a renewal needs to know about the record it renews: its most recent <c>ArchiveTimeStamp</c>,
    /// the algorithm that structure's hash tree was built under, and the instant its time-stamp asserts.
    /// </summary>
    /// <param name="evidenceRecord">The record to renew.</param>
    /// <param name="pool">The memory pool every buffer rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The facts a renewal builds on.</returns>
    /// <exception cref="EvidenceRecordCreationException">When the record carries no chain or an empty one, or its most recent time-stamp cannot be read or names an algorithm this library cannot compute.</exception>
    private static async ValueTask<EvidenceRecordRenewalSource> ReadRenewalSourceAsync(
        EvidenceRecord evidenceRecord,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(evidenceRecord);

        IReadOnlyList<EvidenceRecordArchiveTimeStampChain> chains = evidenceRecord.ArchiveTimeStampSequence.Chains;
        if(chains.Count == 0 || chains[^1].ArchiveTimeStamps.Count == 0)
        {
            throw new EvidenceRecordCreationException(
                EvidenceRecordCreationFailureKind.RenewalSourceMalformed,
                "A renewal builds on the most recent ArchiveTimeStamp of the most recent ArchiveTimeStampChain, and this record carries none (RFC 4998 clause 5.1).");
        }

        EvidenceRecordArchiveTimeStamp tip = chains[^1].ArchiveTimeStamps[^1];
        using TimestampTokenInfo info = await ReadTimeStampAsync(tip, pool, cancellationToken).ConfigureAwait(false);
        if(!info.IsRead)
        {
            throw new EvidenceRecordCreationException(
                EvidenceRecordCreationFailureKind.TimestampNotUsable,
                "The most recent ArchiveTimeStamp's own time-stamp could not be read, so neither the algorithm its hash tree used nor the instant it asserts can be established (RFC 4998 clause 5.2).");
        }

        PkiDigestAlgorithm? algorithm = ResolveDigestAlgorithm(tip, info);
        if(algorithm is null)
        {
            throw new EvidenceRecordCreationException(
                EvidenceRecordCreationFailureKind.TimestampNotUsable,
                "The most recent ArchiveTimeStamp names a digest algorithm this library cannot compute, so a renewal under it would state a tree it cannot build (RFC 4998 clause 5.2).");
        }

        return new EvidenceRecordRenewalSource(tip, algorithm.Value, info.GenerationTime);
    }


    /// <summary>
    /// Acquires the time-stamp a renewal attaches, and refuses it unless it binds the root the renewal's tree
    /// produced and asserts an instant after every Archive Timestamp being renewed.
    /// </summary>
    /// <param name="root">The root of the renewal's hash tree, carrying the algorithm the tree was built under in its own tag.</param>
    /// <param name="sources">The Archive Timestamps being renewed, whose asserted instants the new one has to follow.</param>
    /// <param name="tsaUri">The authority to contact.</param>
    /// <param name="fetchTimestampResponse">The transport that carries the request and its response.</param>
    /// <param name="timestampPolicyOid">The policy the request asks for, or <see langword="null"/> to state none.</param>
    /// <param name="pool">The memory pool every buffer rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The acquired token. The caller owns and disposes it.</returns>
    /// <exception cref="EvidenceRecordCreationException">When the token cannot be read, does not bind the root, or does not follow the structures being renewed.</exception>
    /// <exception cref="TimestampAcquisitionException">When the authority could not be reached, or its response failed a check.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the acquired token transfers to the caller; the catch disposes it when this method refuses it.")]
    private static async ValueTask<AcquiredTimestampToken> AcquireRenewalTokenAsync(
        DigestValue root,
        IReadOnlyList<EvidenceRecordRenewalSource> sources,
        string tsaUri,
        FetchTimestampResponseAsyncDelegate fetchTimestampResponse,
        string? timestampPolicyOid,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        AcquiredTimestampToken token = await TimestampAcquisition.AcquireAsync(
            root, tsaUri, fetchTimestampResponse, pool, timestampPolicyOid, cancellationToken: cancellationToken).ConfigureAwait(false);
        try
        {
            if(!token.Info.IsRead || token.Info.MessageImprint is null)
            {
                throw new EvidenceRecordCreationException(
                    EvidenceRecordCreationFailureKind.TimestampNotUsable,
                    "The acquired time-stamp token's TSTInfo could not be read, so what it binds cannot be established.");
            }

            if(!token.Info.MessageImprint.AsReadOnlySpan().SequenceEqual(root.AsReadOnlySpan()))
            {
                throw new EvidenceRecordCreationException(
                    EvidenceRecordCreationFailureKind.TimestampDoesNotBindRoot,
                    "The acquired time-stamp token does not bind the root of the hash tree it was requested for (RFC 4998 clause 4.2 step 5).");
            }

            for(int i = 0; i < sources.Count; ++i)
            {
                if(token.Info.GenerationTime < sources[i].GenerationTime)
                {
                    throw new EvidenceRecordCreationException(
                        EvidenceRecordCreationFailureKind.RenewalNotAfterSource,
                        "The acquired time-stamp asserts an instant before the Archive Timestamp being renewed, and clause 5.1 requires an ArchiveTimeStampChain and an ArchiveTimeStampSequence to be ordered ascending by time of timestamp.");
                }
            }

            return token;
        }
        catch
        {
            token.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Copies a record's <c>cryptoInfos</c> members so a renewed record can carry them forward octet for octet.
    /// </summary>
    /// <param name="evidenceRecord">The record being renewed.</param>
    /// <param name="pool">The memory pool the copies are rented from.</param>
    /// <returns>The copies, which the caller disposes, or <see langword="null"/> when the record carries none.</returns>
    /// <exception cref="AsnContentException">When a member is not a well-formed <c>Attribute</c>.</exception>
    /// <remarks>
    /// Clause 3.1 leaves what goes here to policy and states that nothing placed here is protected by any
    /// time-stamp, so a renewal neither validates nor rewrites it — it carries the octets across unchanged, and
    /// a caller that wants different content states it on the renewal context instead.
    /// </remarks>
    private static List<CmsAttribute>? CopyCryptoInfos(EvidenceRecord evidenceRecord, BaseMemoryPool pool)
    {
        IReadOnlyList<ReadOnlyMemory<byte>> cryptoInfos = evidenceRecord.CryptoInfos;
        if(cryptoInfos.Count == 0)
        {
            return null;
        }

        var copies = new List<CmsAttribute>(cryptoInfos.Count);
        try
        {
            for(int i = 0; i < cryptoInfos.Count; ++i)
            {
                ReadOnlyMemory<byte> encoded = cryptoInfos[i];
                var reader = new AsnReader(encoded, AsnEncodingRules.DER);
                AsnReader attribute = reader.ReadSequence();
                string attributeType = attribute.ReadObjectIdentifier();

                IMemoryOwner<byte> owner = pool.Rent(encoded.Length);
                try
                {
                    encoded.Span.CopyTo(owner.Memory.Span);
                    copies.Add(new CmsAttribute(attributeType, owner, encoded.Length));
                }
                catch
                {
                    owner.Dispose();

                    throw;
                }
            }

            return copies;
        }
        catch
        {
            DisposeAll(copies);

            throw;
        }
    }


    /// <summary>
    /// Disposes every attribute of a list, tolerating <see langword="null"/> so a <c>finally</c> block need not
    /// test for it.
    /// </summary>
    /// <param name="attributes">The attributes to dispose, or <see langword="null"/>.</param>
    private static void DisposeAll(List<CmsAttribute>? attributes)
    {
        if(attributes is null)
        {
            return;
        }

        for(int i = 0; i < attributes.Count; ++i)
        {
            attributes[i].Dispose();
        }
    }


    /// <summary>
    /// Performs the additional group proof clause 4.3 offers: that the first list of hash values holds the
    /// hashes of the claimed group's data objects and nothing else.
    /// </summary>
    /// <param name="archiveTimeStamp">The initial <c>ArchiveTimeStamp</c> of the record's first chain.</param>
    /// <param name="dataObjectGroup">Every data object of the claimed group.</param>
    /// <param name="algorithm">The algorithm the tree was built under.</param>
    /// <param name="pool">The memory pool every buffer rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see cref="EvidenceRecordVerificationStatus.Verified"/> when the list holds exactly the group, otherwise <see cref="EvidenceRecordVerificationStatus.DataObjectGroupNotCoveredExclusively"/>.</returns>
    private static async ValueTask<EvidenceRecordVerificationStatus> StateGroupExclusivityAsync(
        EvidenceRecordArchiveTimeStamp archiveTimeStamp,
        IReadOnlyList<ReadOnlyMemory<byte>> dataObjectGroup,
        PkiDigestAlgorithm algorithm,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        if(archiveTimeStamp.ReducedHashtree.Count == 0)
        {
            //Nothing states which objects the root covers, so exclusivity cannot be proved either way.
            return EvidenceRecordVerificationStatus.DataObjectGroupNotCoveredExclusively;
        }

        IReadOnlyList<ReadOnlyMemory<byte>> firstList = archiveTimeStamp.ReducedHashtree[0].HashValues;
        if(firstList.Count != dataObjectGroup.Count)
        {
            return EvidenceRecordVerificationStatus.DataObjectGroupNotCoveredExclusively;
        }

        var groupHashes = new List<DigestValue>(dataObjectGroup.Count);
        try
        {
            for(int i = 0; i < dataObjectGroup.Count; ++i)
            {
                groupHashes.Add(await CryptographicKeyEvents.ComputeDigestAsync(
                    dataObjectGroup[i], algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false));
            }

            for(int i = 0; i < groupHashes.Count; ++i)
            {
                if(!EvidenceRecordHashTree.Contains(firstList, groupHashes[i].AsReadOnlySpan()[..algorithm.OutputByteLength]))
                {
                    return EvidenceRecordVerificationStatus.DataObjectGroupNotCoveredExclusively;
                }
            }

            return EvidenceRecordVerificationStatus.Verified;
        }
        finally
        {
            for(int i = 0; i < groupHashes.Count; ++i)
            {
                groupHashes[i].Dispose();
            }
        }
    }


    /// <summary>
    /// Opens the <c>timeStamp</c> field of an <c>ArchiveTimeStamp</c> and reads its <c>TSTInfo</c>.
    /// </summary>
    /// <param name="archiveTimeStamp">The structure whose time-stamp is read.</param>
    /// <param name="pool">The memory pool the carrier and the read facts rent from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The read facts, which the caller disposes in every case.</returns>
    /// <remarks>
    /// Clause 4.1 makes the field a <c>ContentInfo</c> that "should contain the timestamp as defined in Section
    /// 1.3. (e.g., as defined with TimeStampToken in [RFC3161])" while permitting other forms. This library
    /// reads the RFC 3161 form; a field carrying another form reads as
    /// <see cref="TimestampTokenInfoStatus.TokenNotVerified"/>, which the callers report as
    /// <see cref="EvidenceRecordVerificationStatus.TimestampNotRead"/> rather than treating as a proof.
    /// </remarks>
    private static async ValueTask<TimestampTokenInfo> ReadTimeStampAsync(
        EvidenceRecordArchiveTimeStamp archiveTimeStamp,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        using PkiCertificateMemory token = CopyTimeStampToken(archiveTimeStamp.TimeStamp.Span, pool);

        return await TimestampTokenInfo.ReadFromTokenAsync(token, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Resolves the algorithm an <c>ArchiveTimeStamp</c>'s reduced hash tree is built under: its own
    /// <c>digestAlgorithm</c> field when present, otherwise the algorithm of the embedded time-stamp's message
    /// imprint, as clause 4.1 requires.
    /// </summary>
    /// <param name="archiveTimeStamp">The structure.</param>
    /// <param name="info">The already-read facts of its <c>timeStamp</c> field.</param>
    /// <returns>The algorithm, or <see langword="null"/> when it is one this library cannot compute.</returns>
    private static PkiDigestAlgorithm? ResolveDigestAlgorithm(EvidenceRecordArchiveTimeStamp archiveTimeStamp, TimestampTokenInfo info) =>
        PkiDigestAlgorithm.FromOid((archiveTimeStamp.DigestAlgorithm ?? info.MessageImprintAlgorithm).Oid);


    /// <summary>
    /// Copies a <c>timeStamp</c> field's octets into the carrier
    /// <see cref="TimestampTokenInfo.ReadFromTokenAsync"/> expects.
    /// </summary>
    /// <param name="token">The whole encoding of the field.</param>
    /// <param name="pool">The memory pool the copy is rented from.</param>
    /// <returns>The carrier. The caller owns and disposes it.</returns>
    private static PkiCertificateMemory CopyTimeStampToken(ReadOnlySpan<byte> token, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(Math.Max(token.Length, 1));
        try
        {
            token.CopyTo(owner.Memory.Span);

            return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampToken);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Copies a hash value into a digest carrier the caller owns.
    /// </summary>
    /// <param name="hashValue">The octets to copy.</param>
    /// <param name="tag">The tag naming the algorithm the value was computed under.</param>
    /// <param name="pool">The memory pool the copy is rented from.</param>
    /// <returns>The carrier. The caller owns and disposes it.</returns>
    private static DigestValue CopyDigest(ReadOnlySpan<byte> hashValue, Tag tag, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(hashValue.Length);
        try
        {
            hashValue.CopyTo(owner.Memory.Span);

            return new DigestValue(owner, tag);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Writes a <c>SEQUENCE OF</c> whose members are already-encoded values, copied verbatim.
    /// </summary>
    /// <param name="members">The members' whole encodings.</param>
    /// <param name="pool">The memory pool the encoded value is rented from.</param>
    /// <returns>The encoded sequence. The caller owns and disposes it.</returns>
    private static PooledMemory EncodeSequenceOf(IReadOnlyList<ReadOnlyMemory<byte>> members, BaseMemoryPool pool)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            for(int i = 0; i < members.Count; ++i)
            {
                writer.WriteEncodedValue(members[i].Span);
            }
        }

        return Materialise(writer, pool);
    }


    /// <summary>
    /// Rents a buffer of the writer's exact encoded length, encodes into it, and wraps it in a pooled carrier.
    /// </summary>
    /// <param name="writer">The writer holding the completed structure.</param>
    /// <param name="pool">The memory pool the buffer is rented from.</param>
    /// <returns>The encoded structure. The caller owns and disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented buffer transfers to the returned carrier, which the caller disposes; the catch disposes it on a partial failure.")]
    private static PooledMemory Materialise(AsnWriter writer, BaseMemoryPool pool)
    {
        int encodedLength = writer.GetEncodedLength();
        IMemoryOwner<byte> owner = pool.Rent(encodedLength);
        try
        {
            _ = writer.TryEncode(owner.Memory.Span, out int written);

            return new PooledMemory(owner, written, EncodedStructureTag);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// What one renewal reads from the record it renews before it builds anything.
    /// </summary>
    /// <param name="Tip">The most recent <c>ArchiveTimeStamp</c> of the most recent <c>ArchiveTimeStampChain</c> — the structure Timestamp Renewal re-timestamps and whose instant either renewal has to follow.</param>
    /// <param name="Algorithm">The algorithm that structure's hash tree was built under, resolved per clause 4.1 from its own <c>digestAlgorithm</c> field or from its time-stamp's message imprint.</param>
    /// <param name="GenerationTime">The <c>genTime</c> that structure's time-stamp asserts.</param>
    private readonly record struct EvidenceRecordRenewalSource(
        EvidenceRecordArchiveTimeStamp Tip,
        PkiDigestAlgorithm Algorithm,
        DateTimeOffset GenerationTime);
}
