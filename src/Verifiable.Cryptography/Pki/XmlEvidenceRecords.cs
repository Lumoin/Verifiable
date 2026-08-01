using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
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
/// The surface for Evidence Records in the XML syntax of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283">IETF RFC 6283</see>: the detailed verification process of
/// Appendix A — the authoritative expansion of clause 2.3, clause 3.3 and clause 4.3 — and the initial creation
/// of clause 3.2, through the parse, canonicalization and write seams the XML syntax needs.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Both syntaxes are read and both are created.</strong> Clause 1.1 of RFC 6283 states that it "does
/// not present a direct transformation of ERS in ASN.1 syntax", and EN 319 162-1 names the two as alternatives
/// a producer chooses between — so each syntax has its own creation surface
/// (<see cref="EvidenceRecords.CreateInitialAsync"/> for RFC 4998, <see cref="CreateInitialAsync"/> here) and
/// nothing transforms one into the other. Renewal in this syntax remains validation-side work a custodian
/// composes: clause 4.2's procedures digest sub-trees of the document as it stands, which is a seam-design
/// question of its own, not part of initial creation.
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


    /// <summary>
    /// Creates the initial Evidence Record of clause 3.2 in the XML syntax, over the supplied archive object
    /// groups: digest every data object (XML data through the canonicalization seam, clause 4.1.2), build the
    /// clause 3.1.1 hash tree, obtain one time-stamp over its root, assemble one single-chain record per group
    /// and serialise each through the write seam.
    /// </summary>
    /// <param name="context">The groups, the algorithms, the seams and how to reach the Time-Stamping Authority.</param>
    /// <param name="pool">The memory pool every buffer this call rents comes from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The produced documents. The caller owns and disposes the result.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="context"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="EvidenceRecordCreationException">When no data object was supplied, an XML data object could not be canonicalized, the acquired token does not bind the tree's root, or the write seam produced no document.</exception>
    /// <exception cref="TimestampAcquisitionException">When the authority could not be reached, or its response failed a check.</exception>
    /// <remarks>
    /// <para>
    /// This is the RFC 6283 counterpart of <see cref="EvidenceRecords.CreateInitialAsync"/> and holds the same
    /// line: the token is acquired through <see cref="TimestampAcquisition.AcquireAsync"/>, which verifies the
    /// response before returning it, and this method additionally asserts the imprint is octet for octet the
    /// root the tree produced. A token that does not bind the root is never written into any document.
    /// </para>
    /// <para>
    /// <strong>Initial creation needs no canonicalization of the record itself.</strong> The hash tree binds
    /// the archive data — canonicalized first when it is XML, exactly as it stands otherwise — and the root
    /// goes into the RFC 3161 request; no digest of any Evidence Record element exists yet. The
    /// <c>CanonicalizationMethod</c> the chain states matters at the record's FIRST renewal, when clause 4.2's
    /// procedures digest the document's own sub-trees, so a generator states the method its custodians will
    /// canonicalize under then.
    /// </para>
    /// <para>
    /// The produced record carries one <c>ArchiveTimeStampChain</c> of one <c>ArchiveTimeStamp</c>, whose
    /// <c>HashTree</c> is the group's reduced tree in the exact shape <see cref="VerifyAsync"/> walks back:
    /// the first <c>Sequence</c> states the group's own object digests and nothing else (Appendix A step 5.b's
    /// exclusive membership), and every later <c>Sequence</c> states the sibling of one combination on the
    /// group's path to the root.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of each produced document transfers to the returned creation, which the caller disposes; the catch disposes the documents produced before a later group failed, and every intermediate model is disposed by its own using or finally.")]
    public static async ValueTask<XmlEvidenceRecordCreation> CreateInitialAsync(
        XmlEvidenceRecordCreationContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();
        if(context.DataObjectGroups.Count == 0)
        {
            throw new EvidenceRecordCreationException(
                EvidenceRecordCreationFailureKind.NoDataObject,
                "An initial Archive Time-Stamp is created over at least one data object group (RFC 6283 clause 3.2).");
        }

        //Leaf digests first: an XML data object's digest is over its canonical binary representation under the
        //chain's stated method (clause 4.1.2); any other object is hashed exactly as it stands.
        var digestGroups = new List<IReadOnlyList<DigestValue>>(context.DataObjectGroups.Count);
        try
        {
            for(int g = 0; g < context.DataObjectGroups.Count; ++g)
            {
                IReadOnlyList<XmlEvidenceRecordDataObject> group = context.DataObjectGroups[g];
                if(group.Count == 0)
                {
                    throw new EvidenceRecordCreationException(
                        EvidenceRecordCreationFailureKind.NoDataObject,
                        "A data object group holds at least one data object (RFC 6283 clause 3.1.1).");
                }

                var digests = new List<DigestValue>(group.Count);
                digestGroups.Add(digests);
                for(int i = 0; i < group.Count; ++i)
                {
                    digests.Add(await DigestDataObjectAsync(
                        group[i], context.CanonicalizationMethodUri, context.DigestAlgorithm, context.Canonicalize, pool,
                        cancellationToken).ConfigureAwait(false));
                }
            }

            using XmlEvidenceRecordHashTreeBuild build = await XmlEvidenceRecordHashTrees.BuildAsync(
                new XmlEvidenceRecordHashTreeBuildContext
                {
                    DataObjectDigestGroups = digestGroups,
                    DigestAlgorithm = context.DigestAlgorithm
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
                    "The acquired time-stamp token does not bind the root of the hash tree it was requested for (RFC 6283 clause 3.2).");
            }

            string digestMethodUri = XmlSignatureWellKnown.DigestUriFromAlgorithm(context.DigestAlgorithm)
                ?? throw new EvidenceRecordCreationException(
                    EvidenceRecordCreationFailureKind.TimestampNotUsable,
                    $"No DigestMethod identifier is defined for '{context.DigestAlgorithm.Identifier.Oid}', so no chain can state the algorithm (RFC 6283 clause 4.1.1).");

            var documents = new List<PooledMemory>(context.DataObjectGroups.Count);
            try
            {
                for(int g = 0; g < context.DataObjectGroups.Count; ++g)
                {
                    documents.Add(await WriteRecordAsync(
                        build.ClaimReducedHashTree(g), token.Token, digestMethodUri, context, pool, cancellationToken).ConfigureAwait(false));
                }

                return new XmlEvidenceRecordCreation(documents, token.Info.GenerationTime);
            }
            catch
            {
                for(int i = 0; i < documents.Count; ++i)
                {
                    documents[i].Dispose();
                }

                throw;
            }
        }
        finally
        {
            for(int g = 0; g < digestGroups.Count; ++g)
            {
                for(int i = 0; i < digestGroups[g].Count; ++i)
                {
                    digestGroups[g][i].Dispose();
                }
            }
        }


        //Digests one data object: XML archive data through the canonicalization seam first (clause 4.1.2's
        //"canonicalization MUST be applied over XML structured archive data"), any other object as it stands.
        static async ValueTask<DigestValue> DigestDataObjectAsync(
            XmlEvidenceRecordDataObject dataObject,
            string canonicalizationMethodUri,
            PkiDigestAlgorithm algorithm,
            CanonicalizeXmlEvidenceRecordDelegate canonicalize,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            if(!dataObject.IsXmlArchiveData)
            {
                return await CryptographicKeyEvents.ComputeDigestAsync(
                    dataObject.Content, algorithm.OutputByteLength, algorithm.DigestTag, pool,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
            }

            using XmlEvidenceRecordCanonicalizationResult canonicalized = await canonicalize(
                new XmlEvidenceRecordCanonicalizationContext
                {
                    Document = ReadOnlyMemory<byte>.Empty,
                    AlgorithmUri = canonicalizationMethodUri,
                    Target = XmlEvidenceRecordCanonicalizationTarget.ArchiveDataObject,
                    ArchiveData = dataObject.Content
                },
                pool,
                cancellationToken).ConfigureAwait(false);
            if(!canonicalized.IsCanonicalized || canonicalized.BinaryRepresentation is not PooledMemory binary)
            {
                throw new EvidenceRecordCreationException(
                    EvidenceRecordCreationFailureKind.ArchiveDataNotCanonicalizable,
                    $"The XML archive data object '{dataObject.Name ?? "(unnamed)"}' could not be canonicalized under '{canonicalizationMethodUri}': {canonicalized.FailureReason} (RFC 6283 clause 4.1.2).");
            }

            return await CryptographicKeyEvents.ComputeDigestAsync(
                binary.AsReadOnlyMemory(), algorithm.OutputByteLength, algorithm.DigestTag, pool,
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }


        //Assembles one group's single-chain record model — claiming the group's reduced tree and copying the
        //shared token into the model's own carrier — and serialises it through the write seam. The model is
        //disposed here whatever happens; only the document outlives the call.
        static async ValueTask<PooledMemory> WriteRecordAsync(
            XmlEvidenceRecordHashTree reducedHashTree,
            PkiCertificateMemory token,
            string digestMethodUri,
            XmlEvidenceRecordCreationContext context,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            using var record = new XmlEvidenceRecord
            {
                Version = XmlEvidenceRecordWellKnown.Version10,
                Chains =
                [
                    new XmlEvidenceRecordArchiveTimeStampChain
                    {
                        Order = 1,
                        DigestMethodUri = digestMethodUri,
                        DigestAlgorithm = context.DigestAlgorithm,
                        CanonicalizationMethodUri = context.CanonicalizationMethodUri,
                        ArchiveTimeStamps =
                        [
                            new XmlEvidenceRecordArchiveTimeStamp
                            {
                                Order = 1,
                                HashTree = reducedHashTree,
                                TimeStamp = new XmlEvidenceRecordTimeStamp
                                {
                                    TokenType = XmlEvidenceRecordWellKnown.Rfc3161TimeStampTokenType,
                                    Rfc3161Token = CopyToken(token, pool)
                                }
                            }
                        ]
                    }
                ]
            };

            using XmlEvidenceRecordWriteResult written = await context.WriteDocument(
                new XmlEvidenceRecordWriteContext { EvidenceRecord = record }, pool, cancellationToken).ConfigureAwait(false);
            if(!written.IsWritten || written.TakeDocument() is not PooledMemory document)
            {
                throw new EvidenceRecordCreationException(
                    EvidenceRecordCreationFailureKind.DocumentNotWritable,
                    $"The write seam produced no EvidenceRecord document: {written.FailureReason} (RFC 6283 clause 8).");
            }

            return document;
        }


        //Copies the shared acquired token into a carrier of the model's own, because every group's record owns
        //its whole content and the token outlives none of them.
        static PkiCertificateMemory CopyToken(PkiCertificateMemory token, MemoryPool<byte> pool)
        {
            IMemoryOwner<byte> owner = pool.Rent(token.AsReadOnlySpan().Length);
            try
            {
                token.AsReadOnlySpan().CopyTo(owner.Memory.Span);

                return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampToken);
            }
            catch
            {
                owner.Dispose();

                throw;
            }
        }
    }
}


/// <summary>
/// Everything one initial creation of an Evidence Record in the XML syntax is given — the RFC 6283 counterpart
/// of <see cref="EvidenceRecordCreationContext"/>, with the two seams the XML syntax needs and the ASN.1 one
/// does not: canonicalization for XML archive data (clause 4.1.2) and the document writer (clause 8).
/// </summary>
[DebuggerDisplay("XmlEvidenceRecordCreationContext: {DataObjectGroups.Count} groups")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "An algorithm identifier is compared as written: RFC 6283 clause 4.1.2 identifies a canonicalization algorithm by the URI string, and System.Uri normalises case, escaping and default ports, which would make two identifiers that name different algorithms compare equal.")]
public sealed record XmlEvidenceRecordCreationContext
{
    /// <summary>
    /// The archive object groups. One Evidence Record document is produced per group, each carrying that
    /// group's own reduced hash tree and all of them sharing the one time-stamp taken over the tree's root —
    /// the same centralized shape <see cref="EvidenceRecordCreationContext.DataObjectGroups"/> has for the
    /// ASN.1 syntax.
    /// </summary>
    public required IReadOnlyList<IReadOnlyList<XmlEvidenceRecordDataObject>> DataObjectGroups { get; init; }

    /// <summary>The algorithm the whole hash tree, and the time-stamp request over its root, are computed under (clause 4.1.1: one algorithm per chain).</summary>
    public required PkiDigestAlgorithm DigestAlgorithm { get; init; }

    /// <summary>
    /// The <c>CanonicalizationMethod</c> identifier the produced chain states (clause 4.1.2) — applied here to
    /// any XML archive data before it is hashed, and applied by whoever renews the record to the document's
    /// own sub-trees later.
    /// </summary>
    public required string CanonicalizationMethodUri { get; init; }

    /// <summary>The seam producing the canonical binary representation of XML archive data (clause 4.1.2); never invoked when no data object states <see cref="XmlEvidenceRecordDataObject.IsXmlArchiveData"/>.</summary>
    public required CanonicalizeXmlEvidenceRecordDelegate Canonicalize { get; init; }

    /// <summary>The seam serialising each assembled record into its <c>EvidenceRecord</c> document (clause 8).</summary>
    public required WriteEvidenceRecordXmlDelegate WriteDocument { get; init; }

    /// <summary>The Time-Stamping Authority to contact, in whatever form the transport delegate understands.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "Forwarded verbatim into TimestampFetchContext.TsaUri, which is deliberately a string for the reason that property gives: the transport delegate owns URI parsing and scheme policy.")]
    public required string TsaUri { get; init; }

    /// <summary>The transport that carries the time-stamp request to the authority and its response back.</summary>
    public required FetchTimestampResponseAsyncDelegate FetchTimestampResponse { get; init; }

    /// <summary>The <c>reqPolicy</c> object identifier to request, or <see langword="null"/> to request none; a response is verified against it either way (<see cref="TimestampAcquisition.VerifyResponseAsync"/>).</summary>
    public string? TimestampPolicyOid { get; init; }
}


/// <summary>
/// What one initial creation in the XML syntax produced: one <c>EvidenceRecord</c> document per data object
/// group, and the instant their shared time-stamp asserts — the XML counterpart of
/// <see cref="EvidenceRecordCreation"/>.
/// </summary>
[DebuggerDisplay("XmlEvidenceRecordCreation: {Documents.Count} documents at {ArchiveTime}")]
public sealed class XmlEvidenceRecordCreation: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>
    /// Initialises a new creation result.
    /// </summary>
    /// <param name="documents">One document per data object group, in the order the groups were supplied. Ownership transfers to this instance.</param>
    /// <param name="archiveTime">The <c>genTime</c> the acquired time-stamp asserts.</param>
    internal XmlEvidenceRecordCreation(IReadOnlyList<PooledMemory> documents, DateTimeOffset archiveTime)
    {
        Documents = documents;
        ArchiveTime = archiveTime;
    }


    /// <summary>Gets one <c>EvidenceRecord</c> document per data object group, in the order the groups were supplied, each tagged <see cref="XmlEvidenceRecordTags.EvidenceRecord"/>. Owned by this instance.</summary>
    public IReadOnlyList<PooledMemory> Documents { get; }

    /// <summary>Gets the <c>genTime</c> the acquired time-stamp asserts — the instant every produced record proves its data objects existed at.</summary>
    public DateTimeOffset ArchiveTime { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            for(int i = 0; i < Documents.Count; ++i)
            {
                Documents[i].Dispose();
            }

            disposed = true;
        }
    }
}
