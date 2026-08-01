using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One archived data object group of
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.2">IETF RFC 4998 clause 4.2</see>: the data
/// objects that share one leaf of the hash tree and are therefore proved to have existed together.
/// </summary>
/// <remarks>
/// Clause 4.2 step 3 states the group rule: "For each data group containing more than one document, its
/// respective document hashes are binary sorted in ascending order, concatenated, and hashed." A group holding
/// exactly one document contributes that document's own hash as the leaf, unhashed a second time — which is why
/// a reduced hash tree whose first list holds a single value is verified by taking that value forward as it
/// stands.
/// </remarks>
[DebuggerDisplay("EvidenceRecordDataObjectGroup({DataObjects.Count} data objects)")]
public sealed record EvidenceRecordDataObjectGroup
{
    /// <summary>
    /// Gets the data objects of this group, as views the caller owns for the duration of the call. Each is
    /// hashed once, through the registered digest seam, to become a leaf input.
    /// </summary>
    public required IReadOnlyList<ReadOnlyMemory<byte>> DataObjects { get; init; }
}


/// <summary>
/// What one <see cref="EvidenceRecordHashTree.BuildAsync"/> call needs: the data object groups to bind
/// together, the algorithm the whole tree is built under, and how many children an inner node is given.
/// </summary>
public sealed record EvidenceRecordHashTreeBuildContext
{
    /// <summary>Gets the data object groups, in the order their reduced hash trees are returned in.</summary>
    public required IReadOnlyList<EvidenceRecordDataObjectGroup> DataObjectGroups { get; init; }

    /// <summary>
    /// Gets the algorithm every hash value of the tree is computed under. Clause 4.2 step 5 binds it to the
    /// time-stamp request: "The hash algorithm in the timestamp request MUST be the same as the hash algorithm
    /// of the hash tree, or the digestAlgorithm field of the ArchiveTimeStamp MUST be present and specify the
    /// hash algorithm of the hash tree."
    /// </summary>
    public required PkiDigestAlgorithm DigestAlgorithm { get; init; }

    /// <summary>
    /// Gets how many children an inner node is given. Clause 4.2 step 4 leaves the arity open ("place them in
    /// groups") and only recommends uniformity; the default is the binary tree of the Merkle construction the
    /// clause cites.
    /// </summary>
    public int NodeArity { get; init; } = EvidenceRecordHashTree.DefaultNodeArity;
}


/// <summary>
/// What one <see cref="EvidenceRecordHashTree.BuildFromHashValuesAsync"/> call needs: the leaf inputs of every
/// group as hash values a caller has already computed, the algorithm they were computed under, and how many
/// children an inner node is given.
/// </summary>
/// <remarks>
/// This is the entry point clause 5.2's Hash-Tree Renewal builds through. Its step 5 says to build the tree over
/// the values step 4 produced — "Concatenate each h(i) with ha(i) and generate hash values h(i)' = H (h(i)+
/// ha(i))" — which are hash values already, not data objects to be hashed again. Feeding them to
/// <see cref="EvidenceRecordHashTree.BuildAsync"/> would hash them a second time and produce a tree no verifier
/// walking clause 5.3 step 3 could reach.
/// </remarks>
public sealed record EvidenceRecordHashTreeHashValueBuildContext
{
    /// <summary>
    /// Gets the groups, each holding the hash values that are that group's leaf inputs, in the order their
    /// reduced hash trees are returned in. The values are views the caller owns and keeps alive for as long as
    /// it holds the returned build, because the reduced hash trees view them rather than copying them.
    /// </summary>
    public required IReadOnlyList<IReadOnlyList<ReadOnlyMemory<byte>>> HashValueGroups { get; init; }

    /// <summary>Gets the algorithm every supplied hash value was computed under, and every node of the tree is computed under.</summary>
    public required PkiDigestAlgorithm DigestAlgorithm { get; init; }

    /// <summary>Gets how many children an inner node is given; see <see cref="EvidenceRecordHashTreeBuildContext.NodeArity"/>.</summary>
    public int NodeArity { get; init; } = EvidenceRecordHashTree.DefaultNodeArity;
}


/// <summary>
/// What one <see cref="EvidenceRecordHashTree.ComputeRootAsync"/> call needs: the hash of the data object being
/// proved, the reduced hash tree that carries it, and the algorithm both were computed under.
/// </summary>
public sealed record EvidenceRecordRootComputationContext
{
    /// <summary>Gets the hash of the archived data object, computed under <see cref="DigestAlgorithm"/>. The caller owns it.</summary>
    public required DigestValue DataObjectHash { get; init; }

    /// <summary>Gets the reduced hash tree, leaf level first — an empty list for the degenerate form clause 4.2 admits, where the data object's own hash is the root.</summary>
    public required IReadOnlyList<EvidenceRecordPartialHashtree> ReducedHashtree { get; init; }

    /// <summary>Gets the algorithm every hash value of the tree was computed under.</summary>
    public required PkiDigestAlgorithm DigestAlgorithm { get; init; }
}


/// <summary>
/// Whether a root hash value could be recomputed from a reduced hash tree, and if not, why.
/// </summary>
/// <remarks>
/// <see cref="NotComputed"/> occupies zero so a default-initialised status never reads as a successful
/// recomputation, the same choice <see cref="TimestampTokenInfoStatus"/> makes.
/// </remarks>
public enum EvidenceRecordRootStatus
{
    /// <summary>No recomputation has been attempted. The value of an unset field, by design.</summary>
    NotComputed = 0,

    /// <summary>The root was recomputed; the walk reached the top of the reduced hash tree.</summary>
    Computed = 1,

    /// <summary>
    /// Step 2 of <see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.3">clause 4.3</see> failed: the
    /// data object's hash is not in the first list, so "terminate verification process with negative result".
    /// </summary>
    HashValueNotInFirstList = 2,

    /// <summary>A list of the reduced hash tree holds no hash value at all, so there is nothing to concatenate.</summary>
    PartialHashtreeEmpty = 3,

    /// <summary>A hash value of the reduced hash tree is not as long as the stated algorithm's output, so it was never computed under it.</summary>
    HashValueLengthMismatch = 4,

    /// <summary>The reduced hash tree holds more lists than this library walks; see <see cref="EvidenceRecordHashTree"/>'s bounds.</summary>
    ReducedHashtreeTooDeep = 5
}


/// <summary>
/// The outcome of recomputing a root hash value from a reduced hash tree.
/// </summary>
/// <remarks>
/// A failed recomputation is a result rather than an exception: a reduced hash tree arrives as attacker-supplied
/// DER, and clause 4.3 makes the membership failure a negative verification result, not an error.
/// </remarks>
[DebuggerDisplay("EvidenceRecordRootComputation({Status})")]
public sealed class EvidenceRecordRootComputation: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>
    /// Initialises a new outcome.
    /// </summary>
    /// <param name="status">Whether the root was recomputed, and if not why.</param>
    /// <param name="root">The recomputed root, owned by this instance, or <see langword="null"/> when there is none.</param>
    private EvidenceRecordRootComputation(EvidenceRecordRootStatus status, DigestValue? root)
    {
        Status = status;
        Root = root;
    }


    /// <summary>Gets whether the root was recomputed, and if not why.</summary>
    public EvidenceRecordRootStatus Status { get; }

    /// <summary>Gets the recomputed root, owned by this instance; <see langword="null"/> unless <see cref="Status"/> is <see cref="EvidenceRecordRootStatus.Computed"/>.</summary>
    public DigestValue? Root { get; }


    /// <summary>
    /// Builds the outcome of a successful recomputation.
    /// </summary>
    /// <param name="root">The recomputed root. Ownership transfers to the returned instance.</param>
    /// <returns>The outcome.</returns>
    internal static EvidenceRecordRootComputation Succeeded(DigestValue root) => new(EvidenceRecordRootStatus.Computed, root);


    /// <summary>
    /// Builds the outcome of a recomputation that could not complete.
    /// </summary>
    /// <param name="status">Why it could not complete.</param>
    /// <returns>The outcome.</returns>
    internal static EvidenceRecordRootComputation Failed(EvidenceRecordRootStatus status) => new(status, root: null);


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
/// A built hash tree: the root the time-stamp is taken over, and the reduced hash tree of every data object
/// group that went into it.
/// </summary>
/// <remarks>
/// The instance owns every digest it computed, and every <see cref="EvidenceRecordPartialHashtree"/> it hands
/// out views those digests. Disposing it invalidates them, so a caller encodes what it needs first.
/// </remarks>
[DebuggerDisplay("EvidenceRecordHashTreeBuild({ReducedHashtrees.Count} reduced hash trees)")]
public sealed class EvidenceRecordHashTreeBuild: IDisposable
{
    /// <summary>Every digest this build computed, disposed as one.</summary>
    private List<DigestValue> OwnedDigests { get; }

    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>
    /// Initialises a new build.
    /// </summary>
    /// <param name="root">The root hash carrier, one of <paramref name="ownedDigests"/>.</param>
    /// <param name="reducedHashtrees">One reduced hash tree per data object group, in the order the groups were supplied.</param>
    /// <param name="ownedDigests">Every digest computed while building. Ownership transfers to this instance.</param>
    internal EvidenceRecordHashTreeBuild(
        DigestValue root,
        IReadOnlyList<IReadOnlyList<EvidenceRecordPartialHashtree>> reducedHashtrees,
        List<DigestValue> ownedDigests)
    {
        Root = root;
        ReducedHashtrees = reducedHashtrees;
        OwnedDigests = ownedDigests;
    }


    /// <summary>Gets the root hash of the tree — the value clause 4.2 step 5 obtains a time-stamp for — as the tagged carrier this build owns and disposes.</summary>
    public DigestValue Root { get; }

    /// <summary>Gets one reduced hash tree per data object group, in the order the groups were supplied.</summary>
    public IReadOnlyList<IReadOnlyList<EvidenceRecordPartialHashtree>> ReducedHashtrees { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            for(int i = 0; i < OwnedDigests.Count; ++i)
            {
                OwnedDigests[i].Dispose();
            }

            OwnedDigests.Clear();
            disposed = true;
        }
    }
}


/// <summary>
/// The Merkle hash-tree machinery of
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.2">IETF RFC 4998 clause 4.2</see> and
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.3">clause 4.3</see>: building a tree over data
/// object groups, reducing it to one <c>reducedHashtree</c> per group, and recomputing a root from such a
/// reduced tree.
/// </summary>
/// <remarks>
/// <para>
/// <strong>One implementation, both directions.</strong> Generation and verification share the node rule
/// (<see cref="CombineAsync"/>) and the ordering rule (<see cref="CompareHashValues"/>), so a tree this library
/// builds is one it also walks back to the same root. A second implementation of either rule would be free to
/// drift, and a drifted root is a silent wire incompatibility rather than a structural error.
/// </para>
/// <para>
/// <strong>This is not <c>ats-hash-index-v3</c>.</strong> The archive time-stamp of ETSI EN 319 122-1 clause
/// 5.5.2 concatenates whole encodings in a fixed, specification-defined field order and proves coverage by set
/// membership against flat index lists. RFC 4998 sorts data-dependent hash values into binary ascending order,
/// concatenates raw digest octets at every level, and proves coverage by walking a tree path. The two are
/// different algorithms for the same problem and share no code here on purpose.
/// </para>
/// <para>
/// <strong>No recursion.</strong> The tree is built level by level and walked level by level with explicit
/// loops, and both the depth of a reduced hash tree and the width of one list are bounded, so attacker-supplied
/// structure cannot drive either the stack or the work done off the end.
/// </para>
/// </remarks>
public static class EvidenceRecordHashTree
{
    /// <summary>
    /// The largest number of <c>PartialHashtree</c> lists one <c>reducedHashtree</c> is read or walked with.
    /// The syntax bounds none; a tree deeper than this over a binary arity would carry more leaves than any
    /// archive this library serves.
    /// </summary>
    internal const int MaximumReducedHashtreeDepth = 64;

    /// <summary>
    /// The largest number of hash values one <c>PartialHashtree</c> is read or walked with. Every entry costs a
    /// verifier one comparison and one concatenated octet run, so the count an attacker chooses is bounded.
    /// </summary>
    internal const int MaximumPartialHashtreeEntries = 4096;

    /// <summary>The largest length one hash value may have, which is the longest digest this library computes.</summary>
    internal const int MaximumHashValueLength = 64;

    /// <summary>The smallest number of children an inner node may be built with.</summary>
    private const int MinimumNodeArity = 2;

    /// <summary>The largest number of children an inner node is built with here.</summary>
    private const int MaximumNodeArity = 64;


    /// <summary>
    /// How many children an inner node is given unless a caller states otherwise: two, the binary Merkle tree
    /// clause 4.2 cites.
    /// </summary>
    public static int DefaultNodeArity { get; } = 2;


    /// <summary>
    /// The ordering every node of an RFC 4998 hash tree is arranged under, as a comparer over the hash values a
    /// <see cref="EvidenceRecordPartialHashtree"/> holds.
    /// </summary>
    /// <remarks>
    /// It compares through <see cref="CompareHashValues"/>; see that member for the rule and why it is stated
    /// once rather than open-coded at each sort site.
    /// </remarks>
    public static IComparer<ReadOnlyMemory<byte>> HashValueComparer { get; } =
        Comparer<ReadOnlyMemory<byte>>.Create(static (left, right) => CompareHashValues(left.Span, right.Span));


    /// <summary>
    /// Compares two hash values in the "binary sorted in ascending order" of
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.2">clause 4.2</see>.
    /// </summary>
    /// <param name="left">The first hash value.</param>
    /// <param name="right">The second hash value.</param>
    /// <returns>A negative number when <paramref name="left"/> sorts first, a positive number when <paramref name="right"/> does, and zero when the two are identical.</returns>
    /// <remarks>
    /// <para>
    /// The rule clause 4.2 step 3 states in full is: "its respective document hashes are binary sorted in
    /// ascending order, concatenated, and hashed. The hash values are the complete output from the hash
    /// algorithm, i.e., leading zeros are not removed, with the most significant bit first." The comparison is
    /// therefore an unsigned lexicographic one over the complete, untruncated digest octets, most significant
    /// octet first, with a leading zero octet as significant as any other.
    /// </para>
    /// <para>
    /// Three plausible near-misses produce a different root with no structural error to show for it, which is
    /// why this rule is named once and property-tested rather than written out at each sort site: comparing the
    /// values as signed integers (a leading octet above <c>0x7F</c> would sort first), stripping leading zeros
    /// (two digests differing only there would compare equal), and comparing hexadecimal renderings
    /// case-insensitively or culture-sensitively.
    /// </para>
    /// <para>
    /// Values of unequal length compare by their common prefix first and by length only when one is a prefix of
    /// the other. A well-formed tree never mixes lengths — clause 5.1 requires one hash algorithm per chain —
    /// so this only decides the order of a structure that is already going to fail its length check.
    /// </para>
    /// </remarks>
    public static int CompareHashValues(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) => left.SequenceCompareTo(right);


    /// <summary>
    /// Applies the node rule of clause 4.2 to a set of hash values: binary sort them ascending, concatenate the
    /// complete octets, and hash the concatenation.
    /// </summary>
    /// <param name="hashValues">The hash values under one father node. The order they arrive in does not matter; they are sorted here.</param>
    /// <param name="algorithm">The algorithm the tree is built under.</param>
    /// <param name="pool">The memory pool the concatenation buffer and the resulting digest are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The father node's hash value. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="hashValues"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When no hash value is supplied or more are supplied than one list is read with.</exception>
    /// <exception cref="InvalidOperationException">When no digest delegate has been registered.</exception>
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
            throw new ArgumentException("A node of an RFC 4998 hash tree is computed over at least one hash value (clause 4.2).", nameof(hashValues));
        }

        if(hashValues.Count > MaximumPartialHashtreeEntries)
        {
            throw new ArgumentException($"A node of an RFC 4998 hash tree is computed over at most {MaximumPartialHashtreeEntries} hash values.", nameof(hashValues));
        }

        var sorted = new List<ReadOnlyMemory<byte>>(hashValues);
        sorted.Sort(HashValueComparer);

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
    /// Builds the hash tree of clause 4.2 over the supplied data object groups and reduces it, producing the
    /// root a time-stamp is taken over together with one <c>reducedHashtree</c> per group.
    /// </summary>
    /// <param name="context">The groups, the algorithm and the node arity.</param>
    /// <param name="pool">The memory pool every digest and concatenation buffer is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The built tree. The caller owns and disposes it, which invalidates every view it handed out.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="context"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When no group or an empty group is supplied, the arity is out of range, or a group holds more data objects than one list is read with.</exception>
    /// <exception cref="InvalidOperationException">When no digest delegate has been registered.</exception>
    /// <remarks>
    /// <para>
    /// A group holding one data object contributes that object's hash as its leaf; a group holding several
    /// contributes the hash of their binary sorted concatenation, and their own hashes become the first list of
    /// that group's reduced hash tree (clause 4.2 step 3 and the reduction's step 2).
    /// </para>
    /// <para>
    /// Inner nodes take <see cref="EvidenceRecordHashTreeBuildContext.NodeArity"/> children each. A level whose
    /// last partition would hold a single node instead carries that node up unchanged rather than hashing it
    /// alone — which is exactly what Figure 1 of clause 4.2 shows for its third data group, whose leaf is a
    /// direct child of the root. Clause 4.2 step 4's alternative, padding the level with "any data" hashed under
    /// <c>H</c>, is not taken: a padding value has to be preserved for every later verification, and carrying a
    /// node up preserves nothing while producing the same tree the clause's own figure does.
    /// </para>
    /// </remarks>
    public static async ValueTask<EvidenceRecordHashTreeBuild> BuildAsync(
        EvidenceRecordHashTreeBuildContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        if(context.DataObjectGroups.Count == 0)
        {
            throw new ArgumentException("A hash tree is built over at least one data object group (RFC 4998 clause 4.2).", nameof(context));
        }

        if(context.NodeArity < MinimumNodeArity || context.NodeArity > MaximumNodeArity)
        {
            throw new ArgumentException($"An inner node of a hash tree is given between {MinimumNodeArity} and {MaximumNodeArity} children.", nameof(context));
        }

        var owned = new List<DigestValue>();
        var groupMemberHashes = new List<List<ReadOnlyMemory<byte>>>(context.DataObjectGroups.Count);
        try
        {
            for(int groupIndex = 0; groupIndex < context.DataObjectGroups.Count; ++groupIndex)
            {
                IReadOnlyList<ReadOnlyMemory<byte>> dataObjects = context.DataObjectGroups[groupIndex].DataObjects;
                if(dataObjects.Count == 0)
                {
                    throw new ArgumentException("A data object group holds at least one data object (RFC 4998 clause 4.2).", nameof(context));
                }

                if(dataObjects.Count > MaximumPartialHashtreeEntries)
                {
                    throw new ArgumentException($"A data object group holds at most {MaximumPartialHashtreeEntries} data objects.", nameof(context));
                }

                var memberHashes = new List<ReadOnlyMemory<byte>>(dataObjects.Count);
                for(int objectIndex = 0; objectIndex < dataObjects.Count; ++objectIndex)
                {
                    DigestValue memberHash = await CryptographicKeyEvents.ComputeDigestAsync(
                        dataObjects[objectIndex],
                        context.DigestAlgorithm.OutputByteLength,
                        context.DigestAlgorithm.DigestTag,
                        pool,
                        cancellationToken: cancellationToken).ConfigureAwait(false);
                    owned.Add(memberHash);
                    memberHashes.Add(memberHash.AsReadOnlyMemory()[..context.DigestAlgorithm.OutputByteLength]);
                }

                memberHashes.Sort(HashValueComparer);
                groupMemberHashes.Add(memberHashes);
            }
        }
        catch
        {
            for(int i = 0; i < owned.Count; ++i)
            {
                owned[i].Dispose();
            }

            throw;
        }

        return await BuildFromSortedGroupsAsync(
            groupMemberHashes, context.DigestAlgorithm, context.NodeArity, firstListNamesTheGroupAlone: false, owned, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds the hash tree of clause 4.2 over leaf inputs a caller has already hashed, and reduces it — the
    /// entry point clause 5.2's Hash-Tree Renewal builds through.
    /// </summary>
    /// <param name="context">The groups of hash values, the algorithm they were computed under, and the node arity.</param>
    /// <param name="pool">The memory pool every digest and concatenation buffer is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The built tree. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="context"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When no group or an empty group is supplied, the arity is out of range, a group holds more values than one list is read with, or a supplied hash value is not as long as the stated algorithm's output.</exception>
    /// <exception cref="InvalidOperationException">When no digest delegate has been registered.</exception>
    /// <remarks>
    /// <para>
    /// This is the same tree <see cref="BuildAsync"/> builds from data objects whose hashes are the supplied
    /// values — every rule is shared, because the only difference between the two entry points is who computed
    /// the leaves. Clause 5.2 step 5 needs that difference: the values its step 4 produces,
    /// <c>h(i)' = H(h(i) + ha(i))</c>, are hash values already, and hashing them a second time would build a
    /// tree no verifier walking clause 5.3 step 3 could reach.
    /// </para>
    /// <para>
    /// <strong>The first list names the group alone.</strong> Clause 5.2 step 5 departs from the reduction of
    /// clause 4.2 for exactly this entry point: "The first hash value list in the reduced hash tree should only
    /// contain h(i)'. For a multi-document group, the first hash value list will contain the new hashes for all
    /// the documents in this group". The reduction of clause 4.2 merges a single-value group with its level-zero
    /// siblings instead — its own Figure 2 prints the merged list — so a renewal reduced that way would put the
    /// renewal values of the OTHER records of the batch into a record's first list, and clause 1.3 makes the
    /// first list what an Archive Timestamp "relates to". The extra <c>PartialHashtree</c> level this needs is
    /// the one <see href="https://www.rfc-editor.org/rfc/rfc6283#section-3.2.2">RFC 6283 clause 3.2.2</see>
    /// steps 2 and 3 mandate for the same mechanism: the object's own value alone in the first sequence, the
    /// same-father siblings in the next. Nothing about verification changes — a single-value first list is
    /// carried forward unhashed (<see cref="ComputeRootAsync"/>), so both shapes walk to the same root.
    /// </para>
    /// <para>
    /// <strong>The supplied values are not copied.</strong> The reduced hash trees returned view them, so the
    /// caller keeps them alive for as long as it holds the build. Disposing the build releases only the node
    /// values this call itself computed.
    /// </para>
    /// </remarks>
    public static async ValueTask<EvidenceRecordHashTreeBuild> BuildFromHashValuesAsync(
        EvidenceRecordHashTreeHashValueBuildContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        if(context.HashValueGroups.Count == 0)
        {
            throw new ArgumentException("A hash tree is built over at least one group of hash values (RFC 4998 clause 4.2).", nameof(context));
        }

        if(context.NodeArity < MinimumNodeArity || context.NodeArity > MaximumNodeArity)
        {
            throw new ArgumentException($"An inner node of a hash tree is given between {MinimumNodeArity} and {MaximumNodeArity} children.", nameof(context));
        }

        int digestLength = context.DigestAlgorithm.OutputByteLength;
        var groupMemberHashes = new List<List<ReadOnlyMemory<byte>>>(context.HashValueGroups.Count);
        for(int groupIndex = 0; groupIndex < context.HashValueGroups.Count; ++groupIndex)
        {
            IReadOnlyList<ReadOnlyMemory<byte>> supplied = context.HashValueGroups[groupIndex];
            if(supplied.Count == 0)
            {
                throw new ArgumentException("A group holds at least one hash value (RFC 4998 clause 4.2).", nameof(context));
            }

            if(supplied.Count > MaximumPartialHashtreeEntries)
            {
                throw new ArgumentException($"A group holds at most {MaximumPartialHashtreeEntries} hash values.", nameof(context));
            }

            var memberHashes = new List<ReadOnlyMemory<byte>>(supplied.Count);
            for(int i = 0; i < supplied.Count; ++i)
            {
                if(supplied[i].Length != digestLength)
                {
                    throw new ArgumentException(
                        $"A supplied hash value holds the {digestLength} octets the stated algorithm outputs, so that the tree it feeds is one that algorithm built.", nameof(context));
                }

                memberHashes.Add(supplied[i]);
            }

            memberHashes.Sort(HashValueComparer);
            groupMemberHashes.Add(memberHashes);
        }

        return await BuildFromSortedGroupsAsync(
            groupMemberHashes, context.DigestAlgorithm, context.NodeArity, firstListNamesTheGroupAlone: true, [], pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds the tree and reduces it from every group's own member hash values, already sorted into the binary
    /// ascending order of clause 4.2 — the one place the level construction and the reduction live, whether the
    /// leaves came from data objects or from the renewal values of clause 5.2.
    /// </summary>
    /// <param name="groupMemberHashes">Each group's member hash values, sorted. A group of one contributes its single value as the leaf; a group of several the hash of their concatenation.</param>
    /// <param name="algorithm">The algorithm every node is computed under.</param>
    /// <param name="nodeArity">How many children an inner node is given.</param>
    /// <param name="firstListNamesTheGroupAlone">Whether every group's first list holds that group's own values alone — clause 5.2 step 5's shape, stated by the renewal entry point; the reduction of clause 4.2 merges a one-value group with its level-zero siblings instead, which is what its Figure 2 prints.</param>
    /// <param name="owned">The digests already computed for the leaves, which this call adds its node values to. Ownership transfers to the returned build; the list is disposed when this call throws.</param>
    /// <param name="pool">The memory pool every digest and concatenation buffer is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The built tree.</returns>
    /// <exception cref="ArgumentException">When the tree would be deeper than this library builds.</exception>
    /// <exception cref="InvalidOperationException">When no digest delegate has been registered.</exception>
    private static async ValueTask<EvidenceRecordHashTreeBuild> BuildFromSortedGroupsAsync(
        List<List<ReadOnlyMemory<byte>>> groupMemberHashes,
        PkiDigestAlgorithm algorithm,
        int nodeArity,
        bool firstListNamesTheGroupAlone,
        List<DigestValue> owned,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        try
        {
            //Leaves: one per group. Clause 4.2 step 3 hashes only a group "containing more than one document",
            //so a group of one contributes its single member hash unchanged.
            var leaves = new List<ReadOnlyMemory<byte>>(groupMemberHashes.Count);
            for(int groupIndex = 0; groupIndex < groupMemberHashes.Count; ++groupIndex)
            {
                List<ReadOnlyMemory<byte>> memberHashes = groupMemberHashes[groupIndex];
                if(memberHashes.Count == 1)
                {
                    leaves.Add(memberHashes[0]);
                }
                else
                {
                    DigestValue groupHash = await CombineAsync(memberHashes, algorithm, pool, cancellationToken).ConfigureAwait(false);
                    owned.Add(groupHash);
                    leaves.Add(groupHash.AsReadOnlyMemory()[..algorithm.OutputByteLength]);
                }
            }

            //Levels, bottom up. Every level records, per node of the level below, which partition it belonged to
            //and which node of the level above it fed, so the reduction can walk one leaf's path without ever
            //rebuilding the tree.
            var levels = new List<List<ReadOnlyMemory<byte>>> { leaves };
            var partitionsPerLevel = new List<List<NodePartition>>();
            List<ReadOnlyMemory<byte>> current = leaves;
            while(current.Count > 1)
            {
                if(levels.Count == MaximumReducedHashtreeDepth)
                {
                    throw new ArgumentException($"A hash tree is built with at most {MaximumReducedHashtreeDepth} levels.", nameof(groupMemberHashes));
                }

                var next = new List<ReadOnlyMemory<byte>>((current.Count / nodeArity) + 1);
                var partitions = new List<NodePartition>(next.Capacity);
                for(int start = 0; start < current.Count; start += nodeArity)
                {
                    int end = Math.Min(start + nodeArity, current.Count);
                    if(end - start == 1)
                    {
                        //A lone trailing node is carried up unchanged; see the remarks on BuildAsync.
                        partitions.Add(new NodePartition(start, end, next.Count, IsPromotion: true));
                        next.Add(current[start]);

                        continue;
                    }

                    var members = new List<ReadOnlyMemory<byte>>(end - start);
                    for(int i = start; i < end; ++i)
                    {
                        members.Add(current[i]);
                    }

                    DigestValue parent = await CombineAsync(members, algorithm, pool, cancellationToken).ConfigureAwait(false);
                    owned.Add(parent);
                    partitions.Add(new NodePartition(start, end, next.Count, IsPromotion: false));
                    next.Add(parent.AsReadOnlyMemory()[..algorithm.OutputByteLength]);
                }

                partitionsPerLevel.Add(partitions);
                levels.Add(next);
                current = next;
            }

            var reducedHashtrees = new List<IReadOnlyList<EvidenceRecordPartialHashtree>>(groupMemberHashes.Count);
            for(int groupIndex = 0; groupIndex < groupMemberHashes.Count; ++groupIndex)
            {
                reducedHashtrees.Add(Reduce(groupIndex, groupMemberHashes[groupIndex], firstListNamesTheGroupAlone, levels, partitionsPerLevel));
            }

            //The root is materialised as its own owned carrier whichever way it arose — a combined node, or a
            //caller-supplied member hash promoted unchanged to the top — so the build hands out one uniform
            //tagged digest rather than a view whose ownership depends on the tree's shape.
            DigestValue root = CopyDigest(current[0].Span, algorithm.DigestTag, pool);
            owned.Add(root);

            return new EvidenceRecordHashTreeBuild(root, reducedHashtrees, owned);
        }
        catch
        {
            for(int i = 0; i < owned.Count; ++i)
            {
                owned[i].Dispose();
            }

            throw;
        }
    }


    /// <summary>
    /// Recomputes the root hash value a reduced hash tree carries an archived data object up to — steps 2 and 3
    /// of <see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.3">clause 4.3</see>.
    /// </summary>
    /// <param name="context">The data object's hash, the reduced hash tree, and the algorithm both were computed under.</param>
    /// <param name="pool">The memory pool every digest and concatenation buffer is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The outcome, which the caller disposes in every case.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="context"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">When no digest delegate has been registered.</exception>
    /// <remarks>
    /// <para>
    /// The walk is the clause's own: find the data object's hash in the first list, concatenate that list to a
    /// value, and make that value "a member of the next higher list of hash values (from the next
    /// partialHashtree)" before concatenating again, until the lists run out. Father nodes are never stored —
    /// clause 4.2's reduction says so outright — so the recomputed value is inserted into each following list
    /// rather than looked up in it.
    /// </para>
    /// <para>
    /// <strong>The single-value first list.</strong> When the first list holds exactly one hash value, that
    /// value is carried forward as it stands rather than hashed. This is clause 4.2 step 3 read in the
    /// verification direction — only a data group "containing more than one document" has its hashes
    /// concatenated and hashed, so a group of one contributes its document's hash unchanged — and it is the rule
    /// the XML form of the same syntax states outright in
    /// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-3.1.1">RFC 6283 clause 3.1.1</see>: "With one
    /// exception to this rule: when the first &lt;Sequence&gt; element has only one &lt;DigestValue&gt; element,
    /// then its binary value is added to the next list obtained from the next &lt;Sequence&gt; element." The
    /// exception applies to the first list only; every later list is concatenated and hashed however many
    /// values it ends up holding.
    /// </para>
    /// <para>
    /// An empty reduced hash tree is the degenerate form clause 4.2 admits ("only a timestamp with no hash value
    /// lists"), for which the data object's own hash is the root.
    /// </para>
    /// </remarks>
    public static async ValueTask<EvidenceRecordRootComputation> ComputeRootAsync(
        EvidenceRecordRootComputationContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);

        IReadOnlyList<EvidenceRecordPartialHashtree> lists = context.ReducedHashtree;
        if(lists.Count > MaximumReducedHashtreeDepth)
        {
            return EvidenceRecordRootComputation.Failed(EvidenceRecordRootStatus.ReducedHashtreeTooDeep);
        }

        int digestLength = context.DigestAlgorithm.OutputByteLength;
        ReadOnlyMemory<byte> dataObjectHash = context.DataObjectHash.AsReadOnlyMemory()[..digestLength];
        if(lists.Count == 0)
        {
            return EvidenceRecordRootComputation.Succeeded(CopyDigest(dataObjectHash.Span, context.DigestAlgorithm.DigestTag, pool));
        }

        for(int listIndex = 0; listIndex < lists.Count; ++listIndex)
        {
            IReadOnlyList<ReadOnlyMemory<byte>> hashValues = lists[listIndex].HashValues;
            if(hashValues.Count == 0)
            {
                return EvidenceRecordRootComputation.Failed(EvidenceRecordRootStatus.PartialHashtreeEmpty);
            }

            if(hashValues.Count > MaximumPartialHashtreeEntries)
            {
                return EvidenceRecordRootComputation.Failed(EvidenceRecordRootStatus.ReducedHashtreeTooDeep);
            }

            for(int i = 0; i < hashValues.Count; ++i)
            {
                if(hashValues[i].Length != digestLength)
                {
                    return EvidenceRecordRootComputation.Failed(EvidenceRecordRootStatus.HashValueLengthMismatch);
                }
            }
        }

        if(!Contains(lists[0].HashValues, dataObjectHash.Span))
        {
            return EvidenceRecordRootComputation.Failed(EvidenceRecordRootStatus.HashValueNotInFirstList);
        }

        DigestValue? currentOwned = null;
        try
        {
            ReadOnlyMemory<byte> current;
            if(lists[0].HashValues.Count == 1)
            {
                current = lists[0].HashValues[0];
            }
            else
            {
                currentOwned = await CombineAsync(lists[0].HashValues, context.DigestAlgorithm, pool, cancellationToken).ConfigureAwait(false);
                current = currentOwned.AsReadOnlyMemory()[..digestLength];
            }

            for(int listIndex = 1; listIndex < lists.Count; ++listIndex)
            {
                var combined = new List<ReadOnlyMemory<byte>>(lists[listIndex].HashValues.Count + 1);
                combined.AddRange(lists[listIndex].HashValues);
                combined.Add(current);

                DigestValue parent = await CombineAsync(combined, context.DigestAlgorithm, pool, cancellationToken).ConfigureAwait(false);
                currentOwned?.Dispose();
                currentOwned = parent;
                current = parent.AsReadOnlyMemory()[..digestLength];
            }

            //The walk may have ended on a value the reduced hash tree owns rather than one computed here (the
            //single-value first list of a one-leaf tree), so the root is always returned as a carrier of this
            //call's own.
            DigestValue root = CopyDigest(current.Span, context.DigestAlgorithm.DigestTag, pool);
            currentOwned?.Dispose();

            return EvidenceRecordRootComputation.Succeeded(root);
        }
        catch
        {
            currentOwned?.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Determines whether a list of hash values holds one that is octet for octet the supplied value — the
    /// membership test of step 2 of clause 4.3.
    /// </summary>
    /// <param name="hashValues">The list to search.</param>
    /// <param name="hashValue">The value searched for.</param>
    /// <returns><see langword="true"/> when the list holds the value.</returns>
    internal static bool Contains(IReadOnlyList<ReadOnlyMemory<byte>> hashValues, ReadOnlySpan<byte> hashValue)
    {
        for(int i = 0; i < hashValues.Count; ++i)
        {
            if(hashValues[i].Span.SequenceEqual(hashValue))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Copies a hash value into a digest carrier this call owns.
    /// </summary>
    /// <param name="hashValue">The octets to copy.</param>
    /// <param name="tag">The tag naming the algorithm the value was computed under.</param>
    /// <param name="pool">The memory pool the copy is rented from.</param>
    /// <returns>The carrier. The caller owns and disposes it.</returns>
    private static DigestValue CopyDigest(ReadOnlySpan<byte> hashValue, Tag tag, MemoryPool<byte> pool)
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
    /// Reduces a built tree to the <c>reducedHashtree</c> of one data object group: the lists of hash values
    /// under each father node on that group's path to the root, with the father node of the nodes below left
    /// out because it is recomputable.
    /// </summary>
    /// <param name="groupIndex">The zero-based index of the group, which is also its leaf's index at level zero.</param>
    /// <param name="groupMemberHashes">The group's own document hashes, already sorted; the first list when the group holds more than one.</param>
    /// <param name="firstListNamesTheGroupAlone">Whether a group holding ONE value also gets a first list of its own, which is what clause 5.2 step 5 asks of a renewal and what the reduction of clause 4.2 does not do.</param>
    /// <param name="levels">The tree's node values, level zero first.</param>
    /// <param name="partitionsPerLevel">The partitions that produced each level above level zero.</param>
    /// <returns>The reduced hash tree, leaf level first.</returns>
    /// <remarks>
    /// The two shapes differ only for a group of one value, and only in where that value's level-zero siblings
    /// are carried. Clause 4.2's own worked example merges them into the first list — Figure 2 prints
    /// <c>pht1 = SEQ(h2abc, h1)</c> for a one-document group — while clause 5.2 step 5 says the first list of a
    /// renewal "should only contain h(i)'", which needs the extra level
    /// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-3.2.2">RFC 6283 clause 3.2.2</see> steps 2 and
    /// 3 print for the same mechanism. Both walk to the same root, because a first list holding one value is
    /// carried forward unhashed and the node rule sorts what it concatenates.
    /// </remarks>
    private static List<EvidenceRecordPartialHashtree> Reduce(
        int groupIndex,
        List<ReadOnlyMemory<byte>> groupMemberHashes,
        bool firstListNamesTheGroupAlone,
        List<List<ReadOnlyMemory<byte>>> levels,
        List<List<NodePartition>> partitionsPerLevel)
    {
        var lists = new List<EvidenceRecordPartialHashtree>();
        if(groupMemberHashes.Count > 1 || firstListNamesTheGroupAlone)
        {
            lists.Add(new EvidenceRecordPartialHashtree { HashValues = groupMemberHashes });
        }

        int nodeIndex = groupIndex;
        for(int level = 0; level < partitionsPerLevel.Count; ++level)
        {
            List<NodePartition> partitions = partitionsPerLevel[level];
            NodePartition partition = FindPartition(partitions, nodeIndex);
            if(partition.IsPromotion)
            {
                nodeIndex = partition.ParentIndex;

                continue;
            }

            var siblings = new List<ReadOnlyMemory<byte>>(partition.End - partition.Start);
            for(int i = partition.Start; i < partition.End; ++i)
            {
                //The first list emitted holds the whole set the father node covers, the node itself included,
                //because nothing below it has been recomputed yet; every later list leaves the node out, since
                //the walk of clause 4.3 inserts the value it just computed. When the group has already emitted
                //a list of its own — always under clause 5.2 step 5's shape, and for a multi-member group under
                //clause 4.2's — this level is a later list and the node is left out here too.
                if(lists.Count > 0 && i == nodeIndex)
                {
                    continue;
                }

                siblings.Add(levels[level][i]);
            }

            siblings.Sort(HashValueComparer);
            lists.Add(new EvidenceRecordPartialHashtree { HashValues = siblings });
            nodeIndex = partition.ParentIndex;
        }

        if(lists.Count == 0)
        {
            //A single group of a single data object under clause 4.2's shape: the tree has one node and the
            //reduction produces nothing. One list naming that node is emitted anyway, so the Archive Timestamp
            //states which data object it covers instead of only asserting a root a verifier has to guess the
            //meaning of. Clause 5.2 step 5's shape has already emitted that list above, so this is unreachable
            //for a renewal — which is why a renewal of one record alone always produced the conformant singleton
            //first list while a batched one did not.
            lists.Add(new EvidenceRecordPartialHashtree { HashValues = [levels[0][groupIndex]] });
        }

        return lists;

        //Finds the partition of one level that a node of the level below fell into. The partitions are disjoint
        //and ordered, so the first one whose range covers the index is the one.
        static NodePartition FindPartition(List<NodePartition> partitions, int nodeIndex)
        {
            for(int i = 0; i < partitions.Count; ++i)
            {
                if(nodeIndex >= partitions[i].Start && nodeIndex < partitions[i].End)
                {
                    return partitions[i];
                }
            }

            throw new UnreachableException("Every node of a level belongs to exactly one partition of that level.");
        }
    }


    /// <summary>
    /// One father node's coverage of the level below it: the half-open range of child indices, the index of the
    /// node it produced at the level above, and whether it merely carried a lone child up.
    /// </summary>
    /// <param name="Start">The inclusive index of the first child.</param>
    /// <param name="End">The exclusive index just past the last child.</param>
    /// <param name="ParentIndex">The index at the level above of the node this partition produced.</param>
    /// <param name="IsPromotion">Whether the partition carried a single child up unchanged instead of hashing it.</param>
    private readonly record struct NodePartition(int Start, int End, int ParentIndex, bool IsPromotion);
}
