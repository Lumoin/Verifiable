using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One archived data object an Evidence Record is verified against.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The XML flag is not cosmetic.</strong> Clause 4.1.2 of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-4.1.2">IETF RFC 6283</see> states that
/// "canonicalization MUST be applied over XML structured archive data", and clause 3.2 makes the canonicalization
/// method the chain names the one to apply. A verifier handed the raw serialisation of an XML document therefore
/// computes the wrong digest unless it canonicalizes first — and it must do so under the method of the chain
/// currently in force, which changes as the walk crosses a Hash-Tree Renewal. That is why the flag travels with
/// the data object rather than the caller canonicalizing in advance: only the walk knows which method applies.
/// </para>
/// <para>
/// Octets that are not XML — a signature file, an archive, a photograph — carry
/// <see cref="IsXmlArchiveData"/> as <see langword="false"/> and are hashed exactly as they stand, which is what
/// every data object inside an Associated Signature Container is.
/// </para>
/// </remarks>
[DebuggerDisplay("XmlEvidenceRecordDataObject: {Name}, {Content.Length} octets, xml {IsXmlArchiveData}")]
public sealed record XmlEvidenceRecordDataObject
{
    /// <summary>The data object's octets. The caller retains ownership.</summary>
    public required ReadOnlyMemory<byte> Content { get; init; }

    /// <summary>Whether <see cref="Content"/> is XML that clause 4.1.2 requires to be canonicalized before it is hashed.</summary>
    public bool IsXmlArchiveData { get; init; }

    /// <summary>A name for the object, used in reporting only; never part of any calculation.</summary>
    public string? Name { get; init; }
}


/// <summary>
/// Everything one verification of an Evidence Record in the XML syntax is given.
/// </summary>
/// <remarks>
/// <para>
/// The document's own octets travel beside the parsed model because the verification needs the canonical binary
/// representation of sub-trees of the document as it actually stands — namespace declarations, prefixes and
/// comments included — which no model reproduces. The canonicalization seam is handed those octets together with
/// a statement of which sub-tree is wanted.
/// </para>
/// <para>
/// <strong>The archive object is the whole set of data objects.</strong> Clause 3.1.1 states that "when an
/// archive object is a group and composed of more than one data object, the first hash list MUST contain the
/// hash values of all its data objects", so a verification is over the group, not over one member at a time.
/// Supplying a subset of a group's members and asking for a verdict would either fail the exclusivity check or,
/// with it switched off, claim a proof of a group the record does not make.
/// </para>
/// </remarks>
[DebuggerDisplay("XmlEvidenceRecordVerificationContext: {DataObjects.Count} data objects, {Document.Length} octets")]
public sealed record XmlEvidenceRecordVerificationContext
{
    /// <summary>The parsed Evidence Record. The caller retains ownership.</summary>
    public required XmlEvidenceRecord EvidenceRecord { get; init; }

    /// <summary>The octets of the <c>EvidenceRecord</c> document the model was parsed from. The caller retains ownership.</summary>
    public required ReadOnlyMemory<byte> Document { get; init; }

    /// <summary>The data objects making up the archive object being proved.</summary>
    public required IReadOnlyList<XmlEvidenceRecordDataObject> DataObjects { get; init; }

    /// <summary>The seam producing the binary representation of an element under a chain's canonicalization method.</summary>
    public required CanonicalizeXmlEvidenceRecordDelegate Canonicalize { get; init; }

    /// <summary>
    /// Whether the first <c>Sequence</c> of each Archive Time-Stamp may hold nothing beyond the values that
    /// Archive Time-Stamp protects. <see langword="true"/>, Appendix A step 5.b's own reading, is the default;
    /// <see langword="false"/> is the documented departure that takes clause 3.3 step 2's SHOULD as permission
    /// to skip the second direction.
    /// </summary>
    /// <remarks>
    /// The document contradicts itself here — Appendix A states the check unconditionally, in one sentence, as
    /// the authoritative expansion of clause 3.3, while clause 3.3 step 2 conditions it on the verifier "also
    /// seek[ing] additional proof that the Archive Time-Stamp relates to a data object group". The strict
    /// reading is the default because the loose one lets an Archive Time-Stamp that also covers objects the
    /// verifier was never shown pass as a proof about the ones it was.
    /// </remarks>
    public bool RequireDataObjectGroupExclusivity { get; init; } = true;
}


/// <summary>
/// The validation-side surface for Evidence Records in the XML syntax of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283">IETF RFC 6283</see>: the detailed verification process of
/// Appendix A, which is the authoritative expansion of clause 2.3, clause 3.3 and clause 4.3.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Validation only.</strong> This library creates Evidence Records in the ASN.1 syntax of IETF RFC 4998
/// and reads them in both. Clause 1.1 of RFC 6283 states that it "does not present a direct transformation of
/// ERS in ASN.1 syntax", and EN 319 162-1 names the two as alternatives a producer chooses between — so a
/// producer needs one and a validation application needs both, which is exactly the asymmetry shipped here.
/// </para>
/// <para>
/// <strong>Appendix A is the algorithm, not clause 3.3.</strong> Clause 3.3 and clause 4.3 each state a
/// procedure, and the appendix states one that subsumes both and settles two questions they leave open: how the
/// list of protected objects is built at each of the three kinds of position (step 4), and that the membership
/// comparison runs in both directions (step 5.b). Where the two disagree, the appendix governs, and where the
/// appendix is stricter, the strict reading ships with the loose one available as a stated departure.
/// </para>
/// <para>
/// <strong>What is not concluded here.</strong> Steps 6, 7 and 8 of the appendix — verifying each time-stamp
/// cryptographically and formally, at the succeeding member's instant rather than at the present for every
/// member but the last — are the time-stamp validation building block of ETSI EN 319 102-1 clause 5.4, which a
/// caller composes. This surface reports each member's asserted instant and its own conclusion about the hash
/// tree, which is what that caller needs and all that can be concluded without a trust anchor.
/// </para>
/// <para>
/// <strong>No recursion anywhere.</strong> Every walk here is a loop with an explicit index over a bounded
/// collection: the chains, the members of a chain, the sequences of a hash tree, the values of a sequence. The
/// input is an archived document produced by whoever archived it, and its depth is its producer's choice.
/// </para>
/// </remarks>
public static class XmlEvidenceRecords
{
    /// <summary>
    /// Verifies an Evidence Record over the archive object the context names, per Appendix A.
    /// </summary>
    /// <param name="context">The record, the document's octets, the data objects and the canonicalization seam.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The conclusion. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <remarks>
    /// Nothing an archived document states escapes as an exception: a structure the appendix does not describe,
    /// a hash tree that reaches no root, a token that cannot be read and a canonicalization the seam refused all
    /// become statuses, so a caller validating a corpus never has to distinguish a defect in this library from a
    /// defect in the document in front of it.
    /// </remarks>
    public static async ValueTask<XmlEvidenceRecordVerification> VerifyAsync(
        XmlEvidenceRecordVerificationContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        XmlEvidenceRecord record = context.EvidenceRecord;
        if(record.HasEncryptionInformation)
        {
            return new XmlEvidenceRecordVerification(XmlEvidenceRecordVerificationStatus.EncryptionInformationPresent, [], null, null, null);
        }

        if(record.Chains.Count == 0 || context.DataObjects.Count == 0)
        {
            return new XmlEvidenceRecordVerification(XmlEvidenceRecordVerificationStatus.Malformed, [], null, null, null);
        }

        var chains = new List<XmlEvidenceRecordChainVerification>(record.Chains.Count);
        bool transferred = false;
        try
        {
            XmlEvidenceRecordVerificationStatus overall = XmlEvidenceRecordVerificationStatus.Verified;
            DateTimeOffset? initialArchiveTime = null;
            DateTimeOffset? latestArchiveTime = null;
            DateTimeOffset? coveredUntil = null;
            DateTimeOffset? previousArchiveTime = null;
            bool runIntact = true;

            for(int chainIndex = 0; chainIndex < record.Chains.Count; ++chainIndex)
            {
                cancellationToken.ThrowIfCancellationRequested();
                XmlEvidenceRecordArchiveTimeStampChain chain = record.Chains[chainIndex];
                XmlEvidenceRecordVerificationStatus chainStatus = XmlEvidenceRecordVerificationStatus.Verified;
                if(chain.ArchiveTimeStamps.Count == 0)
                {
                    chainStatus = XmlEvidenceRecordVerificationStatus.Malformed;
                }
                else if(chainIndex > 0 && chain.DigestAlgorithm.OutputByteLength < record.Chains[chainIndex - 1].DigestAlgorithm.OutputByteLength)
                {
                    //Clause 4.1.1: a succeeding chain is started "using an equal or stronger digest algorithm".
                    //A shorter digest is strictly weaker, and a renewal that weakened the algorithm has defeated
                    //the only purpose the renewal had — surviving the weakening of the algorithm before it.
                    chainStatus = XmlEvidenceRecordVerificationStatus.ChainAlgorithmWeakened;
                }

                var members = new List<XmlEvidenceRecordArchiveTimeStampVerification>(chain.ArchiveTimeStamps.Count);
                bool coversDataObjects = false;
                for(int memberIndex = 0; memberIndex < chain.ArchiveTimeStamps.Count; ++memberIndex)
                {
                    XmlEvidenceRecordArchiveTimeStampVerification member =
                        await VerifyMemberAsync(context, chainIndex, memberIndex, pool, cancellationToken).ConfigureAwait(false);
                    members.Add(member);

                    if(memberIndex == 0)
                    {
                        coversDataObjects = member.Status != XmlEvidenceRecordVerificationStatus.DataObjectNotCovered
                            && member.Status != XmlEvidenceRecordVerificationStatus.RootMismatch
                            && member.Status != XmlEvidenceRecordVerificationStatus.Malformed;
                    }

                    initialArchiveTime ??= member.GenerationTime;
                    if(member.GenerationTime is DateTimeOffset generationTime)
                    {
                        latestArchiveTime = generationTime;
                        if(previousArchiveTime is DateTimeOffset earlier
                            && generationTime <= earlier
                            && chainStatus == XmlEvidenceRecordVerificationStatus.Verified)
                        {
                            //Clause 4.1: both sequences "MUST be sorted by time of the Time-Stamp in ascending
                            //order". An unread token asserts no instant and is skipped for this check rather than
                            //folded in as a default one, which would turn a broken signature into a wrong reason.
                            chainStatus = XmlEvidenceRecordVerificationStatus.TimestampsOutOfOrder;
                        }

                        previousArchiveTime = generationTime;
                    }

                    if(runIntact && member.Status == XmlEvidenceRecordVerificationStatus.Verified)
                    {
                        coveredUntil = member.GenerationTime ?? coveredUntil;
                    }
                    else
                    {
                        runIntact = false;
                    }

                    if(chainStatus == XmlEvidenceRecordVerificationStatus.Verified && member.Status != XmlEvidenceRecordVerificationStatus.Verified)
                    {
                        chainStatus = member.Status;
                    }
                }

                chains.Add(new XmlEvidenceRecordChainVerification(
                    chainStatus, chain.Order, chain.DigestAlgorithm, chain.CanonicalizationMethodUri, members, coversDataObjects));

                if(overall == XmlEvidenceRecordVerificationStatus.Verified && chainStatus != XmlEvidenceRecordVerificationStatus.Verified)
                {
                    overall = chainStatus;
                }
            }

            var verification = new XmlEvidenceRecordVerification(overall, chains, initialArchiveTime, latestArchiveTime, coveredUntil);
            transferred = true;

            return verification;
        }
        finally
        {
            if(!transferred)
            {
                for(int i = 0; i < chains.Count; ++i)
                {
                    chains[i].Dispose();
                }
            }
        }
    }


    /// <summary>
    /// Verifies one <c>ArchiveTimeStamp</c>: builds the list of digest values Appendix A step 4 says it must
    /// protect, compares that list against the first <c>Sequence</c> in both directions (step 5.b), walks the
    /// hash tree to its root and compares the root against the time-stamped value (step 5.b.ii).
    /// </summary>
    /// <param name="context">The verification's inputs.</param>
    /// <param name="chainIndex">The zero-based index of the chain, which is one less than its <c>Order</c>.</param>
    /// <param name="memberIndex">The zero-based index of the element within its chain.</param>
    /// <param name="pool">The memory pool every allocation is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The conclusion about this element. The caller owns and disposes it.</returns>
    private static async ValueTask<XmlEvidenceRecordArchiveTimeStampVerification> VerifyMemberAsync(
        XmlEvidenceRecordVerificationContext context,
        int chainIndex,
        int memberIndex,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        XmlEvidenceRecordArchiveTimeStampChain chain = context.EvidenceRecord.Chains[chainIndex];
        XmlEvidenceRecordArchiveTimeStamp member = chain.ArchiveTimeStamps[memberIndex];
        int chainOrder = chain.Order;
        int memberOrder = member.Order;

        //The branch point of clause 4.2: a later member of a chain came from a Time-Stamp Renewal, the first
        //member of a succeeding chain from a Hash-Tree Renewal, and the very first member of all is the initial
        //Archive Time-Stamp. Which one an element is decides which of Appendix A step 4's three lists applies.
        XmlEvidenceRecordRenewalKind renewalKind = memberIndex > 0
            ? XmlEvidenceRecordRenewalKind.TimeStampRenewal
            : chainIndex == 0
                ? XmlEvidenceRecordRenewalKind.Initial
                : XmlEvidenceRecordRenewalKind.HashTreeRenewal;

        if(!XmlEvidenceRecordWellKnown.IsRfc3161TimeStampTokenType(member.TimeStamp.TokenType) || member.TimeStamp.Rfc3161Token is null)
        {
            return new XmlEvidenceRecordArchiveTimeStampVerification(
                XmlEvidenceRecordVerificationStatus.UnsupportedTimeStampFormat, renewalKind, chainOrder, memberOrder,
                XmlEvidenceRecordMembershipStatus.NotEvaluated, null, null);
        }

        using TimestampTokenInfo tokenInfo = await TimestampTokenInfo.ReadFromTokenAsync(
            member.TimeStamp.Rfc3161Token, pool, cancellationToken).ConfigureAwait(false);
        if(!tokenInfo.IsRead || tokenInfo.MessageImprint is not DigestValue timestampedValue)
        {
            return new XmlEvidenceRecordArchiveTimeStampVerification(
                XmlEvidenceRecordVerificationStatus.TimestampNotRead, renewalKind, chainOrder, memberOrder,
                XmlEvidenceRecordMembershipStatus.NotEvaluated, null, null);
        }

        DateTimeOffset generationTime = tokenInfo.GenerationTime;
        PkiDigestAlgorithm? imprintAlgorithm = PkiDigestAlgorithm.FromOid(tokenInfo.MessageImprintAlgorithm.Oid);
        if(imprintAlgorithm is null)
        {
            return new XmlEvidenceRecordArchiveTimeStampVerification(
                XmlEvidenceRecordVerificationStatus.UnsupportedDigestAlgorithm, renewalKind, chainOrder, memberOrder,
                XmlEvidenceRecordMembershipStatus.NotEvaluated, generationTime, null);
        }

        if(!string.Equals(imprintAlgorithm.Value.Identifier.Oid, chain.DigestAlgorithm.Identifier.Oid, StringComparison.Ordinal))
        {
            //Clause 4.1.1: "Within a single ATSC, the digest algorithms used for the hash trees of its Archive
            //Time-Stamps and the Time-Stamp Tokens MUST be the same." A root computed under one algorithm and an
            //imprint stated under another are not comparable at all, which is step 5.b.ii's negative result
            //reached one step earlier.
            return new XmlEvidenceRecordArchiveTimeStampVerification(
                XmlEvidenceRecordVerificationStatus.RootMismatch, renewalKind, chainOrder, memberOrder,
                XmlEvidenceRecordMembershipStatus.NotEvaluated, generationTime, null);
        }

        //Appendix A step 4: the list L of digest values this Archive Time-Stamp must protect. The linkage values
        //and the data-object values are kept apart so that a value missing from the first sequence names which of
        //clause 4.3's obligations failed rather than merely that one did.
        var owned = new List<DigestValue>();
        var linkageValues = new List<ReadOnlyMemory<byte>>();
        var dataObjectValues = new List<ReadOnlyMemory<byte>>();
        try
        {
            if(memberIndex > 0)
            {
                //Step 4.b.i: the digest of the previous TimeStamp element, in its canonical binary representation.
                //Clause 4.2.1 step 1 permits cryptographic information to be added to that element before it is
                //hashed, so what is canonicalized is the element as the finished document carries it.
                XmlEvidenceRecordArchiveTimeStamp previous = chain.ArchiveTimeStamps[memberIndex - 1];
                DigestValue? linkage = await DigestCanonicalizedAsync(
                    context,
                    new XmlEvidenceRecordCanonicalizationContext
                    {
                        Document = context.Document,
                        AlgorithmUri = chain.CanonicalizationMethodUri,
                        Target = XmlEvidenceRecordCanonicalizationTarget.TimeStampElement,
                        ChainOrder = chainOrder,
                        ArchiveTimeStampOrder = previous.Order
                    },
                    chain.DigestAlgorithm,
                    pool,
                    cancellationToken).ConfigureAwait(false);
                if(linkage is null)
                {
                    return new XmlEvidenceRecordArchiveTimeStampVerification(
                        XmlEvidenceRecordVerificationStatus.CanonicalizationFailed, renewalKind, chainOrder, memberOrder,
                        XmlEvidenceRecordMembershipStatus.NotEvaluated, generationTime, null);
                }

                owned.Add(linkage);
                linkageValues.Add(linkage.AsReadOnlyMemory());
            }
            else
            {
                if(chainIndex > 0)
                {
                    //Step 4.a.ii: the digest of the ordered ArchiveTimeStampSequence "without this and successive
                    //chains", under THIS chain's canonicalization method — clause 4.1.2 states that a succeeding
                    //chain's method "must also be used for the calculation of the digest value of the preceding
                    //ATSC", which is the one place the method in force is not the one the octets were written
                    //under.
                    DigestValue? sequenceDigest = await DigestCanonicalizedAsync(
                        context,
                        new XmlEvidenceRecordCanonicalizationContext
                        {
                            Document = context.Document,
                            AlgorithmUri = chain.CanonicalizationMethodUri,
                            Target = XmlEvidenceRecordCanonicalizationTarget.ArchiveTimeStampSequencePrefix,
                            ChainCount = chainIndex
                        },
                        chain.DigestAlgorithm,
                        pool,
                        cancellationToken).ConfigureAwait(false);
                    if(sequenceDigest is null)
                    {
                        return new XmlEvidenceRecordArchiveTimeStampVerification(
                            XmlEvidenceRecordVerificationStatus.CanonicalizationFailed, renewalKind, chainOrder, memberOrder,
                            XmlEvidenceRecordMembershipStatus.NotEvaluated, generationTime, null);
                    }

                    owned.Add(sequenceDigest);
                    linkageValues.Add(sequenceDigest.AsReadOnlyMemory());
                }

                //Steps 4.a.i and 4.a.ii: the digest of every data object of the archive object, under the chain's
                //own algorithm — which is why a record whose chains name different algorithms hashes the same
                //data objects afresh at every Hash-Tree Renewal.
                for(int i = 0; i < context.DataObjects.Count; ++i)
                {
                    XmlEvidenceRecordDataObject dataObject = context.DataObjects[i];
                    DigestValue? digest = dataObject.IsXmlArchiveData
                        ? await DigestCanonicalizedAsync(
                            context,
                            new XmlEvidenceRecordCanonicalizationContext
                            {
                                Document = context.Document,
                                AlgorithmUri = chain.CanonicalizationMethodUri,
                                Target = XmlEvidenceRecordCanonicalizationTarget.ArchiveDataObject,
                                ArchiveData = dataObject.Content
                            },
                            chain.DigestAlgorithm,
                            pool,
                            cancellationToken).ConfigureAwait(false)
                        : await CryptographicKeyEvents.ComputeDigestAsync(
                            dataObject.Content, chain.DigestAlgorithm.OutputByteLength, chain.DigestAlgorithm.DigestTag, pool,
                            cancellationToken: cancellationToken).ConfigureAwait(false);
                    if(digest is null)
                    {
                        return new XmlEvidenceRecordArchiveTimeStampVerification(
                            XmlEvidenceRecordVerificationStatus.CanonicalizationFailed, renewalKind, chainOrder, memberOrder,
                            XmlEvidenceRecordMembershipStatus.NotEvaluated, generationTime, null);
                    }

                    owned.Add(digest);
                    dataObjectValues.Add(digest.AsReadOnlyMemory());
                }
            }

            if(member.HashTree is not XmlEvidenceRecordHashTree hashTree)
            {
                //Appendix A step 5.a: with no hash tree the archive object has to be one object and its digest —
                //or, for a Time-Stamp Renewal, the digest of the previous TimeStamp element — IS the time-stamped
                //value. Clause 3.3 step 4 adds that "if an archive object is having more data objects and the
                //hash tree is omitted, also exit with negative result".
                if(linkageValues.Count + dataObjectValues.Count != 1)
                {
                    return new XmlEvidenceRecordArchiveTimeStampVerification(
                        XmlEvidenceRecordVerificationStatus.HashTreeMissing, renewalKind, chainOrder, memberOrder,
                        XmlEvidenceRecordMembershipStatus.NotEvaluated, generationTime, null);
                }

                ReadOnlyMemory<byte> only = linkageValues.Count == 1 ? linkageValues[0] : dataObjectValues[0];

                return new XmlEvidenceRecordArchiveTimeStampVerification(
                    only.Span.SequenceEqual(timestampedValue.AsReadOnlySpan())
                        ? XmlEvidenceRecordVerificationStatus.Verified
                        : XmlEvidenceRecordVerificationStatus.RootMismatch,
                    renewalKind, chainOrder, memberOrder,
                    XmlEvidenceRecordMembershipStatus.NotEvaluated, generationTime, null);
            }

            if(hashTree.Sequences.Count == 0)
            {
                return new XmlEvidenceRecordArchiveTimeStampVerification(
                    XmlEvidenceRecordVerificationStatus.Malformed, renewalKind, chainOrder, memberOrder,
                    XmlEvidenceRecordMembershipStatus.NotEvaluated, generationTime, null);
            }

            XmlEvidenceRecordSequence firstSequence = hashTree.Sequences[0];
            if(linkageValues.Count > 0
                && XmlEvidenceRecordHashTrees.StateMembership(linkageValues, firstSequence, requireExclusivity: false) != XmlEvidenceRecordMembershipStatus.Satisfied)
            {
                return new XmlEvidenceRecordArchiveTimeStampVerification(
                    XmlEvidenceRecordVerificationStatus.ChainLinkageBroken, renewalKind, chainOrder, memberOrder,
                    XmlEvidenceRecordMembershipStatus.ProtectedValueMissing, generationTime, null);
            }

            if(dataObjectValues.Count > 0
                && XmlEvidenceRecordHashTrees.StateMembership(dataObjectValues, firstSequence, requireExclusivity: false) != XmlEvidenceRecordMembershipStatus.Satisfied)
            {
                return new XmlEvidenceRecordArchiveTimeStampVerification(
                    XmlEvidenceRecordVerificationStatus.DataObjectNotCovered, renewalKind, chainOrder, memberOrder,
                    XmlEvidenceRecordMembershipStatus.ProtectedValueMissing, generationTime, null);
            }

            var everything = new List<ReadOnlyMemory<byte>>(linkageValues.Count + dataObjectValues.Count);
            everything.AddRange(linkageValues);
            everything.AddRange(dataObjectValues);
            XmlEvidenceRecordMembershipStatus membership = XmlEvidenceRecordHashTrees.StateMembership(
                everything, firstSequence, context.RequireDataObjectGroupExclusivity);
            if(membership == XmlEvidenceRecordMembershipStatus.FirstSequenceHoldsExtraneousValue)
            {
                return new XmlEvidenceRecordArchiveTimeStampVerification(
                    XmlEvidenceRecordVerificationStatus.DataObjectGroupNotCoveredExclusively, renewalKind, chainOrder, memberOrder,
                    membership, generationTime, null);
            }

            using XmlEvidenceRecordRootComputation computation = await XmlEvidenceRecordHashTrees.ComputeRootAsync(
                hashTree, chain.DigestAlgorithm, pool, cancellationToken).ConfigureAwait(false);
            if(computation.Root is not DigestValue root)
            {
                return new XmlEvidenceRecordArchiveTimeStampVerification(
                    computation.Status == XmlEvidenceRecordRootStatus.HashValueLengthMismatch
                        ? XmlEvidenceRecordVerificationStatus.RootMismatch
                        : XmlEvidenceRecordVerificationStatus.Malformed,
                    renewalKind, chainOrder, memberOrder, membership, generationTime, null);
            }

            bool matches = root.AsReadOnlySpan().SequenceEqual(timestampedValue.AsReadOnlySpan());

            return new XmlEvidenceRecordArchiveTimeStampVerification(
                matches ? XmlEvidenceRecordVerificationStatus.Verified : XmlEvidenceRecordVerificationStatus.RootMismatch,
                renewalKind, chainOrder, memberOrder, membership, generationTime, computation.TakeRoot());
        }
        finally
        {
            for(int i = 0; i < owned.Count; ++i)
            {
                owned[i].Dispose();
            }
        }
    }


    /// <summary>
    /// Asks the canonicalization seam for the binary representation the context names and hashes it under the
    /// chain's digest algorithm.
    /// </summary>
    /// <param name="context">The verification's inputs, which carry the seam.</param>
    /// <param name="canonicalizationContext">Which binary representation is wanted, and under which algorithm.</param>
    /// <param name="algorithm">The digest algorithm the chain names.</param>
    /// <param name="pool">The memory pool every allocation is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The digest, owned by the caller, or <see langword="null"/> when the seam produced no binary representation.</returns>
    /// <remarks>
    /// Nothing is concluded from an element whose octets the seam could not determine: the digest of a guess is a
    /// digest of a guess, and reporting one would let a document whose canonical form is unknown pass as a
    /// document whose canonical form did not match.
    /// </remarks>
    private static async ValueTask<DigestValue?> DigestCanonicalizedAsync(
        XmlEvidenceRecordVerificationContext context,
        XmlEvidenceRecordCanonicalizationContext canonicalizationContext,
        PkiDigestAlgorithm algorithm,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        using XmlEvidenceRecordCanonicalizationResult canonicalized =
            await context.Canonicalize(canonicalizationContext, pool, cancellationToken).ConfigureAwait(false);
        if(!canonicalized.IsCanonicalized || canonicalized.BinaryRepresentation is not PooledMemory binary)
        {
            return null;
        }

        return await CryptographicKeyEvents.ComputeDigestAsync(
            binary.AsReadOnlyMemory(), algorithm.OutputByteLength, algorithm.DigestTag, pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }
}
