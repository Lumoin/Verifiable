using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Why walking a hash tree did, or did not, reach a root hash value.
/// </summary>
/// <remarks>
/// <see cref="Computed"/> is deliberately not zero: a status that has not been computed must not read as a
/// successful walk.
/// </remarks>
public enum XmlEvidenceRecordRootStatus
{
    /// <summary>No walk has been attempted. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The walk reached a root hash value.</summary>
    Computed = 1,

    /// <summary>The hash tree holds no <c>Sequence</c> element, or one of them holds no <c>DigestValue</c> — neither of which clause 8's schema admits.</summary>
    Malformed = 2,

    /// <summary>
    /// A hash value is not as long as the digest algorithm the chain names produces, so it can be neither a
    /// digest under that algorithm nor equal to one.
    /// </summary>
    HashValueLengthMismatch = 3,

    /// <summary>The tree holds more <c>Sequence</c> elements, or one of them more <c>DigestValue</c> elements, than the bounds admit.</summary>
    LimitExceeded = 4
}


/// <summary>
/// The outcome of walking a hash tree to its root.
/// </summary>
[DebuggerDisplay("XmlEvidenceRecordRootComputation: {Status}")]
public sealed class XmlEvidenceRecordRootComputation: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;

    /// <summary>Whether ownership of <see cref="Root"/> has been transferred out by <see cref="TakeRoot"/>.</summary>
    private bool taken;


    /// <summary>Initialises a new outcome.</summary>
    /// <param name="status">What the walk concluded.</param>
    /// <param name="root">The root hash value, owned by this instance, or <see langword="null"/> when the walk reached none.</param>
    internal XmlEvidenceRecordRootComputation(XmlEvidenceRecordRootStatus status, DigestValue? root)
    {
        Status = status;
        Root = root;
    }


    /// <summary>Gets what the walk concluded.</summary>
    public XmlEvidenceRecordRootStatus Status { get; }

    /// <summary>Gets the root hash value, owned by this instance; <see langword="null"/> when the walk reached none.</summary>
    public DigestValue? Root { get; }

    /// <summary>Gets whether the walk reached a root.</summary>
    public bool IsComputed => Status == XmlEvidenceRecordRootStatus.Computed;


    /// <summary>
    /// Transfers ownership of <see cref="Root"/> out of this instance, so that disposing this instance no longer
    /// releases it.
    /// </summary>
    /// <returns>The root hash value, now owned by the caller, or <see langword="null"/> when the walk reached none.</returns>
    /// <remarks>
    /// The verification surface reports the root it recomputed so that a caller can compare it against an
    /// independent computation, which means the value has to outlive the walk that produced it. An explicit
    /// transfer states that in one place, rather than leaving a carrier reachable from two owners.
    /// </remarks>
    internal DigestValue? TakeRoot()
    {
        taken = true;

        return Root;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            if(!taken)
            {
                Root?.Dispose();
            }

            disposed = true;
        }
    }
}


/// <summary>
/// What comparing the list of digest values an Archive Time-Stamp must protect against the first
/// <c>Sequence</c> of its hash tree concluded — Appendix A step 5.b of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#appendix-A">IETF RFC 6283</see>.
/// </summary>
/// <remarks>
/// The two failure members are kept apart because they are two different accusations. A value of the protected
/// list missing from the first sequence says the Archive Time-Stamp does not cover an object it was supposed to;
/// a value in the first sequence that is not in the protected list says it covers something else as well, which
/// is what an attacker adding a document to somebody else's proof would produce.
/// </remarks>
public enum XmlEvidenceRecordMembershipStatus
{
    /// <summary>No comparison has been performed. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>Every check the caller asked for held.</summary>
    Satisfied = 1,

    /// <summary>"There is a digest value in the list L of digest values of protected objects, which cannot be found in the first sequence of the hash tree" — Appendix A step 5.b.</summary>
    ProtectedValueMissing = 2,

    /// <summary>"There is a hash value in the first sequence of the hash tree which is not in the list L of digest values of protected objects" — Appendix A step 5.b, the direction clause 3.3 step 2 phrases as a SHOULD.</summary>
    FirstSequenceHoldsExtraneousValue = 3
}


/// <summary>
/// The hash-tree half of the validation algorithm of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283">IETF RFC 6283</see>: the root computation of clause 3.1.1
/// and the membership comparison of Appendix A step 5.b.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This is NOT the RFC 4998 machinery under another name, and the two must never share a combination
/// rule.</strong> The specifications state the same shape and differ in the base case: clause 3.1.1 of this one
/// says outright that "when the first <c>Sequence</c> element has only one <c>DigestValue</c> element, then its
/// binary value is added to the next list obtained from the next <c>Sequence</c> element" — carried forward
/// unhashed — while RFC 4998 clause 4.3 step 3 states no such carve-out in its own text. A subroutine shared
/// between the two unconditionally would be wrong for one of them. The rules are therefore written out here
/// against this document's own clauses, and only the ORDERING primitive is reached for across the two —
/// <see cref="EvidenceRecordHashTree.CompareHashValues"/>, because "binary ascending order" is one rule that both
/// documents state identically and two copies of an ordering rule are two rules that can disagree.
/// </para>
/// <para>
/// <strong>The exception is first-<c>Sequence</c>-only.</strong> Applying "a list of one is carried forward" at
/// every level instead of only at the base silently produces a different root whenever a genuine single-sibling
/// collision occurs deeper in the tree — which happens in any tree whose node arity does not divide its leaf
/// count. <see cref="ComputeRootAsync"/> short-circuits on the first list and on no other, and a named test
/// builds exactly the tree that tells the two readings apart.
/// </para>
/// <para>
/// <strong>The membership comparison is bidirectional by default.</strong> Appendix A step 5.b states both
/// directions unconditionally, in one sentence, as the authoritative expansion of clause 3.3; clause 3.3 step 2
/// phrases the second direction as a SHOULD conditioned on the verifier "also seek[ing] additional proof that
/// the Archive Time-Stamp relates to a data object group". Where a document contradicts itself, this library
/// takes the strict reading and makes the loose one an explicit, documented departure a caller states —
/// <see cref="StateMembership"/>'s <c>requireExclusivity</c> parameter, true wherever this library calls it.
/// Refusing a first sequence that carries values nobody claimed is what stops an Archive Time-Stamp from being
/// read as a proof about objects it was never shown.
/// </para>
/// </remarks>
public static class XmlEvidenceRecordHashTrees
{
    /// <summary>
    /// The largest number of <c>Sequence</c> elements one hash tree is walked with. Clause 8's schema bounds
    /// none; a reduced tree deeper than this over a binary arity would carry more leaves than any archive this
    /// library serves.
    /// </summary>
    public static int MaximumSequences { get; } = 64;

    /// <summary>
    /// The largest number of <c>DigestValue</c> elements one <c>Sequence</c> is walked with. Every entry costs a
    /// verifier one comparison and one concatenated octet run, so the count a producer chooses is bounded.
    /// </summary>
    public static int MaximumDigestValuesPerSequence { get; } = 4096;


    /// <summary>
    /// Computes the root hash value of a hash tree, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-3.1.1">clause 3.1.1</see> and Appendix A
    /// step 5.b.i.
    /// </summary>
    /// <param name="hashTree">The hash tree, its sequences in ascending <c>Order</c>.</param>
    /// <param name="algorithm">The algorithm the chain's <c>DigestMethod</c> names, which clause 4.1.1 makes the one every calculation of the chain uses.</param>
    /// <param name="pool">The memory pool the concatenation buffer and every intermediate digest are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The outcome. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="hashTree"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// The walk is a loop over the sequences with one carried value, never a recursion: the depth is a producer's
    /// choice and this input is not authenticated until the walk it feeds has succeeded.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The carried value has exactly one owner at every point of the loop: it is disposed on every early return, disposed and replaced when a level combines, disposed by the catch, and transferred to the returned computation on success. The rule's data flow does not follow an ownership that moves across the awaited combination inside the loop; the same finding is recorded at the other asynchronous ownership-transferring loops of this namespace.")]
    public static async ValueTask<XmlEvidenceRecordRootComputation> ComputeRootAsync(
        XmlEvidenceRecordHashTree hashTree,
        PkiDigestAlgorithm algorithm,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(hashTree);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        IReadOnlyList<XmlEvidenceRecordSequence> sequences = hashTree.Sequences;
        if(sequences.Count == 0)
        {
            return new XmlEvidenceRecordRootComputation(XmlEvidenceRecordRootStatus.Malformed, null);
        }

        if(sequences.Count > MaximumSequences)
        {
            return new XmlEvidenceRecordRootComputation(XmlEvidenceRecordRootStatus.LimitExceeded, null);
        }

        DigestValue? carried = null;
        try
        {
            for(int i = 0; i < sequences.Count; ++i)
            {
                cancellationToken.ThrowIfCancellationRequested();
                IReadOnlyList<DigestValue> stated = sequences[i].DigestValues;
                if(stated.Count == 0)
                {
                    carried?.Dispose();

                    return new XmlEvidenceRecordRootComputation(XmlEvidenceRecordRootStatus.Malformed, null);
                }

                if(stated.Count > MaximumDigestValuesPerSequence)
                {
                    carried?.Dispose();

                    return new XmlEvidenceRecordRootComputation(XmlEvidenceRecordRootStatus.LimitExceeded, null);
                }

                var level = new List<ReadOnlyMemory<byte>>(stated.Count + 1);
                for(int valueIndex = 0; valueIndex < stated.Count; ++valueIndex)
                {
                    ReadOnlyMemory<byte> value = stated[valueIndex].AsReadOnlyMemory();
                    if(value.Length != algorithm.OutputByteLength)
                    {
                        carried?.Dispose();

                        return new XmlEvidenceRecordRootComputation(XmlEvidenceRecordRootStatus.HashValueLengthMismatch, null);
                    }

                    level.Add(value);
                }

                if(carried is not null)
                {
                    level.Add(carried.AsReadOnlyMemory());
                }

                //THE clause 3.1.1 exception, and it applies to the FIRST sequence alone: a first list holding a
                //single value carries that value forward as it stands rather than hashing it. Every later list
                //has the carried value added to it and is combined however many entries it then holds, which is
                //at least two, so no later level can take this branch even when the document states a single
                //sibling there.
                if(i == 0 && level.Count == 1)
                {
                    carried = Copy(level[0], algorithm, pool);

                    continue;
                }

                DigestValue combined = await CombineAsync(level, algorithm, pool, cancellationToken).ConfigureAwait(false);
                carried?.Dispose();
                carried = combined;
            }

            DigestValue root = carried!;
            carried = null;

            return new XmlEvidenceRecordRootComputation(XmlEvidenceRecordRootStatus.Computed, root);
        }
        catch
        {
            carried?.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Applies the level rule of clause 3.1.1 to one list of hash values: sort them binary ascending,
    /// concatenate the complete octets, and hash the concatenation.
    /// </summary>
    /// <param name="hashValues">The hash values of one level. The order they arrive in does not matter; they are sorted here.</param>
    /// <param name="algorithm">The algorithm the chain names.</param>
    /// <param name="pool">The memory pool the concatenation buffer and the resulting digest are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The level's hash value. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="hashValues"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When no hash value is supplied or more are supplied than one level is walked with.</exception>
    /// <remarks>
    /// Clause 3.1.1: "All collected hash values from the sequence are ordered in binary ascending order,
    /// concatenated and a new hash value is generated from that string." The ordering is
    /// <see cref="EvidenceRecordHashTree.CompareHashValues"/> — an unsigned lexicographic comparison over the
    /// complete, untruncated digest octets, which is the one rule this document and IETF RFC 4998 state
    /// identically and which therefore exists in one place for both.
    /// </remarks>
    public static async ValueTask<DigestValue> CombineAsync(
        IReadOnlyList<ReadOnlyMemory<byte>> hashValues,
        PkiDigestAlgorithm algorithm,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(hashValues);
        ArgumentNullException.ThrowIfNull(pool);
        if(hashValues.Count == 0)
        {
            throw new ArgumentException("A level of an RFC 6283 hash tree is computed over at least one hash value (clause 3.1.1).", nameof(hashValues));
        }

        if(hashValues.Count > MaximumDigestValuesPerSequence + 1)
        {
            throw new ArgumentException($"A level of an RFC 6283 hash tree is computed over at most {MaximumDigestValuesPerSequence + 1} hash values.", nameof(hashValues));
        }

        var sorted = new List<ReadOnlyMemory<byte>>(hashValues);
        sorted.Sort(EvidenceRecordHashTree.HashValueComparer);

        int total = 0;
        for(int i = 0; i < sorted.Count; ++i)
        {
            total += sorted[i].Length;
        }

        using IMemoryOwner<byte> concatenation = pool.Rent(total);
        int written = 0;
        for(int i = 0; i < sorted.Count; ++i)
        {
            sorted[i].CopyTo(concatenation.Memory[written..]);
            written += sorted[i].Length;
        }

        return await CryptographicKeyEvents.ComputeDigestAsync(
            concatenation.Memory[..total], algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Compares the list of digest values an Archive Time-Stamp must protect against the first <c>Sequence</c>
    /// of its hash tree, per Appendix A step 5.b.
    /// </summary>
    /// <param name="protectedValues">The list Appendix A step 4 builds — data object digests, a preceding sequence's digest, or a preceding time-stamp's digest.</param>
    /// <param name="firstSequence">The first <c>Sequence</c> of the Archive Time-Stamp's hash tree.</param>
    /// <param name="requireExclusivity">Whether the first sequence may hold nothing beyond the protected values. True is Appendix A's own reading and this library's default.</param>
    /// <returns>What the comparison concluded.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="protectedValues"/> or <paramref name="firstSequence"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// <para>
    /// Both directions are membership over multisets read as sets: the comparison asks whether each value occurs
    /// on the other side at all, not how many times. A producer that listed one digest twice has produced a
    /// document whose root will not match anyway, and reading the duplication as an accusation of coverage would
    /// name the wrong fault.
    /// </para>
    /// <para>
    /// The comparison is linear in the product of the two counts, both of which are bounded by the parse limits;
    /// a set would be faster and would need an equality comparer over spans that nothing else in this namespace
    /// has, for inputs this small.
    /// </para>
    /// </remarks>
    public static XmlEvidenceRecordMembershipStatus StateMembership(
        IReadOnlyList<ReadOnlyMemory<byte>> protectedValues,
        XmlEvidenceRecordSequence firstSequence,
        bool requireExclusivity)
    {
        ArgumentNullException.ThrowIfNull(protectedValues);
        ArgumentNullException.ThrowIfNull(firstSequence);

        IReadOnlyList<DigestValue> stated = firstSequence.DigestValues;
        for(int i = 0; i < protectedValues.Count; ++i)
        {
            if(!IsStated(stated, protectedValues[i].Span))
            {
                return XmlEvidenceRecordMembershipStatus.ProtectedValueMissing;
            }
        }

        if(requireExclusivity)
        {
            for(int i = 0; i < stated.Count; ++i)
            {
                if(!IsProtected(protectedValues, stated[i].AsReadOnlySpan()))
                {
                    return XmlEvidenceRecordMembershipStatus.FirstSequenceHoldsExtraneousValue;
                }
            }
        }

        return XmlEvidenceRecordMembershipStatus.Satisfied;

        //Answers whether the first sequence states a given hash value.
        static bool IsStated(IReadOnlyList<DigestValue> stated, ReadOnlySpan<byte> value)
        {
            for(int i = 0; i < stated.Count; ++i)
            {
                if(stated[i].AsReadOnlySpan().SequenceEqual(value))
                {
                    return true;
                }
            }

            return false;
        }

        //Answers whether the protected list holds a given hash value.
        static bool IsProtected(IReadOnlyList<ReadOnlyMemory<byte>> protectedValues, ReadOnlySpan<byte> value)
        {
            for(int i = 0; i < protectedValues.Count; ++i)
            {
                if(protectedValues[i].Span.SequenceEqual(value))
                {
                    return true;
                }
            }

            return false;
        }
    }


    /// <summary>
    /// Builds the hash tree of clause 3.1.1 over per-group leaf digests — the generation direction — and
    /// returns the root together with one reduced hash tree per group, each shaped exactly as
    /// <see cref="ComputeRootAsync"/> walks it back: the first <c>Sequence</c> states the group's own object
    /// digests and nothing else (Appendix A step 5.b's exclusive membership), every later <c>Sequence</c>
    /// states the sibling values of one combination on the group's path to the root, and a level where the
    /// group's node passes up alone states no <c>Sequence</c> at all.
    /// </summary>
    /// <param name="context">The per-group leaf digests and the algorithm every level is computed under.</param>
    /// <param name="pool">The memory pool every carrier this call produces is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The root and the per-group reduced trees. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="context"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When no group is supplied, a group holds no digest, a digest's length is not the algorithm's output length, or a count exceeds the bounds this class walks within.</exception>
    /// <remarks>
    /// <para>
    /// The single-value base case falls out of the shape rather than being special-cased twice: a group with
    /// one object gets a first <c>Sequence</c> of one value, whose octets clause 3.1.1 carries forward
    /// unhashed — so that group's node in the tree is the digest itself, and a single-group, single-object
    /// build has that digest as its root, time-stamped directly.
    /// </para>
    /// <para>
    /// Nodes pair two at a time in group order; an odd node passes to the next level unchanged. The pairing is
    /// a generator's own choice — clause 3.1.1 constrains how a level combines (sorted, concatenated, hashed),
    /// never which nodes a generator groups — and the reduced trees record whatever choice was made, which is
    /// all a verifier ever sees.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "At every await and every rent, a value is owned by exactly one of the nodes list, the next-level list, the sequences lists, or — for one combination's unowned window — a guard that disposes it; the catch disposes all four, and the root and the sequences transfer to the returned build, which the caller disposes.")]
    public static async ValueTask<XmlEvidenceRecordHashTreeBuild> BuildAsync(
        XmlEvidenceRecordHashTreeBuildContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        IReadOnlyList<IReadOnlyList<DigestValue>> groups = context.DataObjectDigestGroups;
        PkiDigestAlgorithm algorithm = context.DigestAlgorithm;
        if(groups.Count == 0)
        {
            throw new ArgumentException("A hash tree is built over at least one data object group (RFC 6283 clause 3.1.1).", nameof(context));
        }

        if(groups.Count > MaximumDigestValuesPerSequence)
        {
            throw new ArgumentException($"A hash tree is built over at most {MaximumDigestValuesPerSequence} data object groups.", nameof(context));
        }

        for(int g = 0; g < groups.Count; ++g)
        {
            if(groups[g].Count == 0)
            {
                throw new ArgumentException("A data object group holds at least one digest (RFC 6283 clause 3.1.1: the first hash list contains the hash values of all its data objects).", nameof(context));
            }

            if(groups[g].Count > MaximumDigestValuesPerSequence)
            {
                throw new ArgumentException($"A data object group holds at most {MaximumDigestValuesPerSequence} digests.", nameof(context));
            }

            for(int i = 0; i < groups[g].Count; ++i)
            {
                if(groups[g][i].Length != algorithm.OutputByteLength)
                {
                    throw new ArgumentException($"Every leaf digest is exactly {algorithm.OutputByteLength} bytes for '{algorithm.Identifier.Oid}' (clause 4.1.1: one algorithm per chain).", nameof(context));
                }
            }
        }

        var nodes = new List<XmlEvidenceRecordBuildNode>(groups.Count);
        var nextLevel = new List<XmlEvidenceRecordBuildNode>((groups.Count + 1) / 2);
        var sequences = new List<List<XmlEvidenceRecordSequence>>(groups.Count);
        try
        {
            for(int g = 0; g < groups.Count; ++g)
            {
                cancellationToken.ThrowIfCancellationRequested();
                IReadOnlyList<DigestValue> leafDigests = groups[g];
                var firstSequenceValues = new List<DigestValue>(leafDigests.Count);
                for(int i = 0; i < leafDigests.Count; ++i)
                {
                    firstSequenceValues.Add(Copy(leafDigests[i].AsReadOnlyMemory(), algorithm, pool));
                }

                sequences.Add([new XmlEvidenceRecordSequence { Order = 1, DigestValues = firstSequenceValues }]);

                //The group's node: a single object's digest stands as it is (the clause 3.1.1 base case a
                //verifier carries forward unhashed); several combine under the level rule.
                DigestValue node = leafDigests.Count == 1
                    ? Copy(leafDigests[0].AsReadOnlyMemory(), algorithm, pool)
                    : await CombineAsync(AsMemories(leafDigests), algorithm, pool, cancellationToken).ConfigureAwait(false);
                nodes.Add(new XmlEvidenceRecordBuildNode(node, [g]));
            }

            while(nodes.Count > 1)
            {
                cancellationToken.ThrowIfCancellationRequested();

                //The level drains from the front so a consumed node is never left behind in the source list:
                //at every await and every rent, a value is owned by exactly one of the two lists the catch
                //disposes, or by the one guarded window below.
                while(nodes.Count > 1)
                {
                    XmlEvidenceRecordBuildNode left = nodes[0];
                    XmlEvidenceRecordBuildNode right = nodes[1];
                    var beneath = new List<int>(left.Groups.Count + right.Groups.Count);
                    beneath.AddRange(left.Groups);
                    beneath.AddRange(right.Groups);

                    DigestValue combined = await CombineAsync(
                        [left.Value.AsReadOnlyMemory(), right.Value.AsReadOnlyMemory()], algorithm, pool, cancellationToken).ConfigureAwait(false);
                    try
                    {
                        AppendSiblingSequences(sequences, left.Groups, right.Value, algorithm, pool);
                        AppendSiblingSequences(sequences, right.Groups, left.Value, algorithm, pool);
                        nextLevel.Add(new XmlEvidenceRecordBuildNode(combined, beneath));
                    }
                    catch
                    {
                        //The combination's one unowned window: it is not yet in the next level's list, so the
                        //outer catch cannot release it — the same guard Copy applies to its own rental.
                        combined.Dispose();

                        throw;
                    }

                    nodes.RemoveRange(0, 2);
                    left.Value.Dispose();
                    right.Value.Dispose();
                }

                if(nodes.Count == 1)
                {
                    //An odd node passes up unchanged: no combination happened, so the groups beneath it
                    //state no Sequence for this level and the verifier's carried value crosses it as is.
                    nextLevel.Add(nodes[0]);
                    nodes.Clear();
                }

                nodes.AddRange(nextLevel);
                nextLevel.Clear();
            }

            DigestValue root = nodes[0].Value;
            var trees = new XmlEvidenceRecordHashTree[groups.Count];
            for(int g = 0; g < groups.Count; ++g)
            {
                trees[g] = new XmlEvidenceRecordHashTree { Sequences = sequences[g] };
            }

            //The root stays reachable from the nodes list — and the sequences from theirs — until both
            //transfers below cannot fail anymore.
            nodes.Clear();
            sequences.Clear();

            return new XmlEvidenceRecordHashTreeBuild(root, trees);
        }
        catch
        {
            for(int i = 0; i < nextLevel.Count; ++i)
            {
                nextLevel[i].Value.Dispose();
            }

            for(int i = 0; i < nodes.Count; ++i)
            {
                nodes[i].Value.Dispose();
            }

            for(int g = 0; g < sequences.Count; ++g)
            {
                for(int i = 0; i < sequences[g].Count; ++i)
                {
                    sequences[g][i].Dispose();
                }
            }

            throw;
        }


        //Views one group's leaf digests as the memory list the level rule combines.
        static List<ReadOnlyMemory<byte>> AsMemories(IReadOnlyList<DigestValue> digests)
        {
            var memories = new List<ReadOnlyMemory<byte>>(digests.Count);
            for(int i = 0; i < digests.Count; ++i)
            {
                memories.Add(digests[i].AsReadOnlyMemory());
            }

            return memories;
        }


        //Appends, for every group beneath one pair member, the Sequence stating the other member's value —
        //the sibling a verifier adds its carried value to at this level.
        static void AppendSiblingSequences(
            List<List<XmlEvidenceRecordSequence>> sequences, IReadOnlyList<int> groups, DigestValue sibling,
            PkiDigestAlgorithm algorithm, BaseMemoryPool pool)
        {
            for(int i = 0; i < groups.Count; ++i)
            {
                List<XmlEvidenceRecordSequence> path = sequences[groups[i]];
                path.Add(new XmlEvidenceRecordSequence
                {
                    Order = path.Count + 1,
                    DigestValues = [Copy(sibling.AsReadOnlyMemory(), algorithm, pool)]
                });
            }
        }
    }


    /// <summary>
    /// Copies one hash value into a carrier of its own, so every walk here owns every value it carries and a
    /// caller owns exactly one thing at the end, whichever branch produced it.
    /// </summary>
    /// <param name="value">The octets to copy.</param>
    /// <param name="algorithm">The algorithm whose tag the carrier states.</param>
    /// <param name="pool">The memory pool the carrier is rented from.</param>
    /// <returns>The owned copy.</returns>
    private static DigestValue Copy(ReadOnlyMemory<byte> value, PkiDigestAlgorithm algorithm, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(value.Length);
        try
        {
            value.Span.CopyTo(owner.Memory.Span);

            return new DigestValue(owner, algorithm.DigestTag);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// One node of the build walk: its value and the indices of the groups beneath it, whose reduced trees
    /// record this node's combinations.
    /// </summary>
    /// <param name="Value">The node's hash value, owned by the walk until combined or transferred.</param>
    /// <param name="Groups">The indices of the data object groups beneath this node.</param>
    private readonly record struct XmlEvidenceRecordBuildNode(DigestValue Value, IReadOnlyList<int> Groups);
}


/// <summary>
/// What <see cref="XmlEvidenceRecordHashTrees.BuildAsync"/> is given: the leaf digests of every data object,
/// grouped as the archive objects are, and the digest algorithm of the chain being started (clause 4.1.1 of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-4.1.1">IETF RFC 6283</see>: one algorithm per
/// chain).
/// </summary>
[DebuggerDisplay("XmlEvidenceRecordHashTreeBuildContext: {DataObjectDigestGroups.Count} groups")]
public sealed record XmlEvidenceRecordHashTreeBuildContext
{
    /// <summary>The leaf digests, one inner list per archive object group, each computed under <see cref="DigestAlgorithm"/> — an XML data object's digest over its canonical binary representation (clause 4.1.2). The caller retains ownership of every carrier.</summary>
    public required IReadOnlyList<IReadOnlyList<DigestValue>> DataObjectDigestGroups { get; init; }

    /// <summary>The digest algorithm every level of the tree is computed under.</summary>
    public required PkiDigestAlgorithm DigestAlgorithm { get; init; }
}


/// <summary>
/// What <see cref="XmlEvidenceRecordHashTrees.BuildAsync"/> produced: the root hash value one time-stamp is
/// obtained over, and one reduced hash tree per data object group, each ready to stand as the <c>HashTree</c>
/// element of that group's initial <c>ArchiveTimeStamp</c> (clause 3.1.1 of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-3.1.1">IETF RFC 6283</see>).
/// </summary>
[DebuggerDisplay("XmlEvidenceRecordHashTreeBuild: {GroupCount} groups")]
public sealed class XmlEvidenceRecordHashTreeBuild: IDisposable
{
    /// <summary>The per-group reduced trees; a claimed slot is <see langword="null"/> and no longer this instance's to release.</summary>
    private readonly XmlEvidenceRecordHashTree?[] reducedHashTrees;

    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>Initialises a new build outcome, taking ownership of the root and every reduced tree.</summary>
    /// <param name="root">The root hash value. Ownership transfers to this instance.</param>
    /// <param name="reducedHashTrees">One reduced tree per group. Ownership transfers to this instance.</param>
    internal XmlEvidenceRecordHashTreeBuild(DigestValue root, XmlEvidenceRecordHashTree[] reducedHashTrees)
    {
        Root = root;
        this.reducedHashTrees = reducedHashTrees;
    }


    /// <summary>Gets the root hash value the whole tree reduces to — what one time-stamp is obtained over. Owned by this instance.</summary>
    public DigestValue Root { get; }

    /// <summary>Gets the number of data object groups the tree was built over.</summary>
    public int GroupCount => reducedHashTrees.Length;


    /// <summary>
    /// Transfers ownership of one group's reduced tree out of this instance — the tree becomes the claimed
    /// record's to release, typically as the <c>HashTree</c> of the <see cref="XmlEvidenceRecordArchiveTimeStamp"/>
    /// being assembled for that group — so disposing this build no longer releases it.
    /// </summary>
    /// <param name="groupIndex">The zero-based group index.</param>
    /// <returns>The reduced tree, now owned by the caller.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="groupIndex"/> names no group.</exception>
    /// <exception cref="InvalidOperationException">When the group's tree was already claimed.</exception>
    public XmlEvidenceRecordHashTree ClaimReducedHashTree(int groupIndex)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(groupIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(groupIndex, reducedHashTrees.Length);
        XmlEvidenceRecordHashTree claimed = reducedHashTrees[groupIndex]
            ?? throw new InvalidOperationException($"The reduced hash tree of group {groupIndex} was already claimed; a tree has exactly one owner.");
        reducedHashTrees[groupIndex] = null;

        return claimed;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            Root.Dispose();
            for(int i = 0; i < reducedHashTrees.Length; ++i)
            {
                reducedHashTrees[i]?.Dispose();
            }

            disposed = true;
        }
    }
}
