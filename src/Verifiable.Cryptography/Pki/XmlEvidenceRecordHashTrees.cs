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
        MemoryPool<byte> pool,
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

        //Copies one hash value into a carrier of its own so the walk owns every value it carries and the caller
        //owns exactly one thing at the end, whichever branch produced it.
        static DigestValue Copy(ReadOnlyMemory<byte> value, PkiDigestAlgorithm algorithm, MemoryPool<byte> pool)
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
        MemoryPool<byte> pool,
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
}
