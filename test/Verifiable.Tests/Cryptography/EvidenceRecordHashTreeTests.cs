using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="EvidenceRecordHashTree"/>: the Merkle hash-tree build, the reduction to one
/// <c>reducedHashtree</c> per data object group, and the root recomputation of
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.2">IETF RFC 4998 clauses 4.2</see> and
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.3">4.3</see>.
/// </summary>
/// <remarks>
/// <para>
/// Every root this class asserts is checked against <see cref="EvidenceRecordOracle"/>, an independent
/// reimplementation of the same two clauses written from the specification text and hashing through a different
/// digest implementation from the one the production path resolves. A test that only compared the library
/// against itself would pass with a wrong comparator or a wrong node rule; the oracle is what makes the
/// comparison mean something.
/// </para>
/// <para>
/// The worked example of clause 4.2 — three data groups, the second holding three documents, reduced in
/// Figures 2 and 3 — is reproduced structurally, because it is the only conformance vector the RFC itself
/// carries for the reduction.
/// </para>
/// </remarks>
[TestClass]
internal sealed class EvidenceRecordHashTreeTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The algorithm every tree in this class is built under.</summary>
    private static PkiDigestAlgorithm Algorithm { get; } = PkiDigestAlgorithm.Sha256;


    /// <summary>
    /// A tree over one data object group holding one data object has that object's hash as its root: clause 4.2
    /// step 3 hashes a group's document hashes together only "for each data group containing more than one
    /// document", and step 4 builds inner nodes only "If there is more than one hash value".
    /// </summary>
    [TestMethod]
    public async Task ASingleDataObjectMakesItsOwnHashTheRoot()
    {
        byte[][] dataObjects = [[.. "the only archived data object"u8]];
        using EvidenceRecordHashTreeBuild build = await BuildAsync([dataObjects], nodeArity: 2).ConfigureAwait(false);

        byte[] expected = EvidenceRecordOracle.Hash(dataObjects[0], Algorithm);
        Assert.IsTrue(build.Root.Span.SequenceEqual(expected), "The root of a one-leaf tree is that leaf.");
        Assert.HasCount(1, build.ReducedHashtrees);
        Assert.HasCount(1, build.ReducedHashtrees[0]);
        Assert.HasCount(1, build.ReducedHashtrees[0][0].HashValues);
        Assert.IsTrue(build.ReducedHashtrees[0][0].HashValues[0].Span.SequenceEqual(expected));
    }


    /// <summary>
    /// A group holding several data objects contributes the hash of their binary sorted, concatenated hashes as
    /// one leaf, and its reduced hash tree's first list holds every member's hash — clause 4.2 step 3 and the
    /// note of the reduction that a group's own hashes "will become members of the first hash list".
    /// </summary>
    [TestMethod]
    public async Task ADataObjectGroupContributesOneLeafAndKeepsItsMembersInTheFirstList()
    {
        byte[][] group = [[.. "member a"u8], [.. "member b"u8], [.. "member c"u8]];
        using EvidenceRecordHashTreeBuild build = await BuildAsync([group], nodeArity: 2).ConfigureAwait(false);

        byte[] expected = EvidenceRecordOracle.LeafOf(group, Algorithm);
        Assert.IsTrue(build.Root.Span.SequenceEqual(expected), "The root of a one-group tree is that group's leaf.");
        Assert.HasCount(1, build.ReducedHashtrees[0]);
        Assert.HasCount(3, build.ReducedHashtrees[0][0].HashValues);

        for(int i = 0; i < group.Length; ++i)
        {
            Assert.IsTrue(
                EvidenceRecordHashTree.Contains(build.ReducedHashtrees[0][0].HashValues, EvidenceRecordOracle.Hash(group[i], Algorithm)),
                "Every member's hash is in the group's first list.");
        }
    }


    /// <summary>
    /// The worked example of clause 4.2: three data groups where groups 1 and 3 hold one document and group 2
    /// holds three. The reduced hash trees are the ones Figures 2 and 3 print — two lists for group 1 (its own
    /// hash together with group 2's leaf, then group 3's leaf), three lists for group 2 (its members, then
    /// group 1's leaf, then group 3's leaf) — and one list for group 3, whose leaf Figure 1 attaches straight
    /// to the root.
    /// </summary>
    [TestMethod]
    public async Task TheThreeGroupExampleOfClause42ReducesAsFigures2And3Print()
    {
        byte[][] group1 = [[.. "d1"u8]];
        byte[][] group2 = [[.. "d2a"u8], [.. "d2b"u8], [.. "d2c"u8]];
        byte[][] group3 = [[.. "d3"u8]];
        using EvidenceRecordHashTreeBuild build = await BuildAsync([group1, group2, group3], nodeArity: 2).ConfigureAwait(false);

        byte[] expectedRoot = EvidenceRecordOracle.BuildRoot([group1, group2, group3], Algorithm, nodeArity: 2);
        Assert.IsTrue(build.Root.Span.SequenceEqual(expectedRoot), "The root is the one the independent build reaches.");

        Assert.HasCount(2, build.ReducedHashtrees[0], "Figure 2 prints two partial hash trees for data group 1.");
        Assert.HasCount(2, build.ReducedHashtrees[0][0].HashValues, "The first holds h1 and h2abc.");
        Assert.HasCount(1, build.ReducedHashtrees[0][1].HashValues, "The second holds h3.");

        Assert.HasCount(3, build.ReducedHashtrees[1], "Figure 3 prints three partial hash trees for data group 2.");
        Assert.HasCount(3, build.ReducedHashtrees[1][0].HashValues, "The first holds h2a, h2b and h2c.");
        Assert.HasCount(1, build.ReducedHashtrees[1][1].HashValues, "The second holds h1.");
        Assert.HasCount(1, build.ReducedHashtrees[1][2].HashValues, "The third holds h3.");

        Assert.HasCount(1, build.ReducedHashtrees[2], "Data group 3's leaf is a child of the root, so one list carries it.");
        Assert.HasCount(2, build.ReducedHashtrees[2][0].HashValues, "That list holds h12 and h3.");

        await AssertReducedTreesReachTheRootAsync(build, [group1, group2, group3]).ConfigureAwait(false);
    }


    /// <summary>
    /// Every list of a reduced hash tree is stored in the binary ascending order clause 4.2 arranges it in, so a
    /// verifier that concatenates it as encoded reaches the same value the generator did.
    /// </summary>
    [TestMethod]
    public async Task EveryPartialHashtreeIsStoredInBinaryAscendingOrder()
    {
        List<byte[][]> groups = MintGroups(9);
        using EvidenceRecordHashTreeBuild build = await BuildAsync(groups, nodeArity: 2).ConfigureAwait(false);

        for(int treeIndex = 0; treeIndex < build.ReducedHashtrees.Count; ++treeIndex)
        {
            IReadOnlyList<EvidenceRecordPartialHashtree> tree = build.ReducedHashtrees[treeIndex];
            for(int listIndex = 0; listIndex < tree.Count; ++listIndex)
            {
                IReadOnlyList<ReadOnlyMemory<byte>> hashValues = tree[listIndex].HashValues;
                for(int i = 1; i < hashValues.Count; ++i)
                {
                    Assert.IsLessThanOrEqualTo(
                        0,
                        EvidenceRecordOracle.Compare(hashValues[i - 1].ToArray(), hashValues[i].ToArray()),
                        $"Partial hash tree {listIndex} of reduced tree {treeIndex} is out of binary ascending order.");
                }
            }
        }
    }


    /// <summary>
    /// A level whose node count is odd carries its trailing node up unchanged rather than hashing it alone,
    /// which is the shape Figure 1 of clause 4.2 prints; every group of such a tree still reduces back to the
    /// one root.
    /// </summary>
    [TestMethod]
    public async Task AnOddNodeCountCarriesTheTrailingNodeUpAndStillReducesToTheRoot()
    {
        List<byte[][]> groups = MintGroups(5);
        using EvidenceRecordHashTreeBuild build = await BuildAsync(groups, nodeArity: 2).ConfigureAwait(false);

        Assert.IsTrue(
            build.Root.Span.SequenceEqual(EvidenceRecordOracle.BuildRoot(groups, Algorithm, nodeArity: 2)),
            "The root is the one the independent build reaches.");

        await AssertReducedTreesReachTheRootAsync(build, groups).ConfigureAwait(false);
    }


    /// <summary>
    /// A tree deep enough to have several inner levels reduces every one of its data objects back to the same
    /// root, under both a binary and a wider node arity.
    /// </summary>
    /// <param name="groupCount">How many data object groups the tree binds.</param>
    /// <param name="nodeArity">How many children an inner node is given.</param>
    [TestMethod]
    [DataRow(2, 2)]
    [DataRow(4, 2)]
    [DataRow(7, 2)]
    [DataRow(16, 2)]
    [DataRow(10, 3)]
    [DataRow(17, 4)]
    public async Task EveryDataObjectOfAMultiLevelTreeReducesBackToTheRoot(int groupCount, int nodeArity)
    {
        List<byte[][]> groups = MintGroups(groupCount);
        using EvidenceRecordHashTreeBuild build = await BuildAsync(groups, nodeArity).ConfigureAwait(false);

        Assert.IsTrue(
            build.Root.Span.SequenceEqual(EvidenceRecordOracle.BuildRoot(groups, Algorithm, nodeArity)),
            "The root is the one the independent build reaches.");

        await AssertReducedTreesReachTheRootAsync(build, groups).ConfigureAwait(false);
    }


    /// <summary>
    /// Step 2 of clause 4.3: a data object whose hash is not in the first list terminates the verification "with
    /// negative result" rather than producing some other root.
    /// </summary>
    [TestMethod]
    public async Task AHashValueAbsentFromTheFirstListTerminatesTheWalk()
    {
        List<byte[][]> groups = MintGroups(4);
        using EvidenceRecordHashTreeBuild build = await BuildAsync(groups, nodeArity: 2).ConfigureAwait(false);
        using DigestValue foreign = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlyMemory<byte>([.. "an object the tree never bound"u8]),
            Algorithm.OutputByteLength,
            Algorithm.DigestTag,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using EvidenceRecordRootComputation computation = await EvidenceRecordHashTree.ComputeRootAsync(
            new EvidenceRecordRootComputationContext
            {
                DataObjectHash = foreign,
                ReducedHashtree = build.ReducedHashtrees[0],
                DigestAlgorithm = Algorithm
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EvidenceRecordRootStatus.HashValueNotInFirstList, computation.Status);
        Assert.IsNull(computation.Root);
    }


    /// <summary>
    /// The degenerate form clause 4.2 admits — "only a timestamp with no hash value lists" — makes the data
    /// object's own hash the root.
    /// </summary>
    [TestMethod]
    public async Task AnEmptyReducedHashtreeMakesTheDataObjectHashTheRoot()
    {
        byte[] dataObject = [.. "the archived data object"u8];
        using DigestValue dataObjectHash = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlyMemory<byte>(dataObject),
            Algorithm.OutputByteLength,
            Algorithm.DigestTag,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using EvidenceRecordRootComputation computation = await EvidenceRecordHashTree.ComputeRootAsync(
            new EvidenceRecordRootComputationContext
            {
                DataObjectHash = dataObjectHash,
                ReducedHashtree = [],
                DigestAlgorithm = Algorithm
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EvidenceRecordRootStatus.Computed, computation.Status);
        Assert.IsNotNull(computation.Root);
        Assert.IsTrue(computation.Root.AsReadOnlySpan().SequenceEqual(EvidenceRecordOracle.Hash(dataObject, Algorithm)));
    }


    /// <summary>
    /// A list of a reduced hash tree that holds no hash value at all has nothing to concatenate, which is
    /// reported rather than treated as a level that contributes nothing.
    /// </summary>
    [TestMethod]
    public async Task AnEmptyPartialHashtreeIsRefused()
    {
        byte[] dataObject = [.. "the archived data object"u8];
        using DigestValue dataObjectHash = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlyMemory<byte>(dataObject),
            Algorithm.OutputByteLength,
            Algorithm.DigestTag,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using EvidenceRecordRootComputation computation = await EvidenceRecordHashTree.ComputeRootAsync(
            new EvidenceRecordRootComputationContext
            {
                DataObjectHash = dataObjectHash,
                ReducedHashtree =
                [
                    new EvidenceRecordPartialHashtree { HashValues = [dataObjectHash.AsReadOnlyMemory()[..Algorithm.OutputByteLength]] },
                    new EvidenceRecordPartialHashtree { HashValues = [] }
                ],
                DigestAlgorithm = Algorithm
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EvidenceRecordRootStatus.PartialHashtreeEmpty, computation.Status);
    }


    /// <summary>
    /// A hash value that is not as long as the stated algorithm's output was never computed under it, so the
    /// walk refuses the structure instead of concatenating octets of mixed provenance.
    /// </summary>
    [TestMethod]
    public async Task AHashValueOfTheWrongLengthIsRefused()
    {
        byte[] dataObject = [.. "the archived data object"u8];
        using DigestValue dataObjectHash = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlyMemory<byte>(dataObject),
            Algorithm.OutputByteLength,
            Algorithm.DigestTag,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using EvidenceRecordRootComputation computation = await EvidenceRecordHashTree.ComputeRootAsync(
            new EvidenceRecordRootComputationContext
            {
                DataObjectHash = dataObjectHash,
                ReducedHashtree =
                [
                    new EvidenceRecordPartialHashtree
                    {
                        HashValues = [dataObjectHash.AsReadOnlyMemory()[..Algorithm.OutputByteLength], new ReadOnlyMemory<byte>([0x01, 0x02, 0x03])]
                    }
                ],
                DigestAlgorithm = Algorithm
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EvidenceRecordRootStatus.HashValueLengthMismatch, computation.Status);
    }


    /// <summary>
    /// The comparator is unsigned and keeps leading zeros: <c>0x00…</c> sorts before <c>0x7f…</c>, which sorts
    /// before <c>0x80…</c>, which sorts before <c>0xff…</c>. A signed comparison would put the two high values
    /// first and a leading-zero-stripping one would make the first two indistinguishable, and either mistake
    /// produces a different root with no structural error to show for it.
    /// </summary>
    [TestMethod]
    public void TheComparatorIsUnsignedAndKeepsLeadingZeros()
    {
        byte[] zeroLeading = [0x00, 0x00, 0x01];
        byte[] lowLeading = [0x7f, 0x00, 0x00];
        byte[] highLeading = [0x80, 0x00, 0x00];
        byte[] highestLeading = [0xff, 0x00, 0x00];

        Assert.IsLessThan(0, EvidenceRecordHashTree.CompareHashValues(zeroLeading, lowLeading));
        Assert.IsLessThan(0, EvidenceRecordHashTree.CompareHashValues(lowLeading, highLeading));
        Assert.IsLessThan(0, EvidenceRecordHashTree.CompareHashValues(highLeading, highestLeading));
        Assert.IsGreaterThan(0, EvidenceRecordHashTree.CompareHashValues(highestLeading, zeroLeading));
        Assert.AreEqual(0, EvidenceRecordHashTree.CompareHashValues(zeroLeading, [0x00, 0x00, 0x01]));

        //A value differing only in a leading zero octet is a different value, not an equal one.
        Assert.AreNotEqual(0, EvidenceRecordHashTree.CompareHashValues([0x00, 0x01], [0x01]));
    }


    /// <summary>
    /// The node rule concatenates in binary ascending order whatever order the values arrive in, so a caller
    /// cannot change a node's value by shuffling its children.
    /// </summary>
    [TestMethod]
    public async Task TheNodeRuleSortsWhateverOrderTheValuesArriveIn()
    {
        byte[][] values = [[.. "alpha"u8], [.. "beta"u8], [.. "gamma"u8], [.. "delta"u8]];
        var hashes = new List<ReadOnlyMemory<byte>>();
        var oracleHashes = new List<byte[]>();
        for(int i = 0; i < values.Length; ++i)
        {
            byte[] hash = EvidenceRecordOracle.Hash(values[i], Algorithm);
            oracleHashes.Add(hash);
            hashes.Add(new ReadOnlyMemory<byte>(hash));
        }

        using DigestValue combined = await EvidenceRecordHashTree.CombineAsync(
            hashes, Algorithm, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        var reversed = new List<ReadOnlyMemory<byte>>(hashes);
        reversed.Reverse();
        using DigestValue combinedReversed = await EvidenceRecordHashTree.CombineAsync(
            reversed, Algorithm, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(combined.AsReadOnlySpan().SequenceEqual(combinedReversed.AsReadOnlySpan()), "The node rule is order independent.");
        Assert.IsTrue(
            combined.AsReadOnlySpan().SequenceEqual(EvidenceRecordOracle.CombineNode(oracleHashes, Algorithm)),
            "The node rule produces the value the independent implementation produces.");
    }


    /// <summary>
    /// Builds a tree over the supplied groups through the shipped surface.
    /// </summary>
    /// <param name="groups">The groups, each a list of data object octets.</param>
    /// <param name="nodeArity">How many children an inner node is given.</param>
    /// <returns>The build. The caller disposes it.</returns>
    private async ValueTask<EvidenceRecordHashTreeBuild> BuildAsync(List<byte[][]> groups, int nodeArity)
    {
        var dataObjectGroups = new List<EvidenceRecordDataObjectGroup>(groups.Count);
        for(int i = 0; i < groups.Count; ++i)
        {
            var dataObjects = new List<ReadOnlyMemory<byte>>(groups[i].Length);
            for(int j = 0; j < groups[i].Length; ++j)
            {
                dataObjects.Add(new ReadOnlyMemory<byte>(groups[i][j]));
            }

            dataObjectGroups.Add(new EvidenceRecordDataObjectGroup { DataObjects = dataObjects });
        }

        return await EvidenceRecordHashTree.BuildAsync(
            new EvidenceRecordHashTreeBuildContext
            {
                DataObjectGroups = dataObjectGroups,
                DigestAlgorithm = Algorithm,
                NodeArity = nodeArity
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Walks every data object of every group back up its own reduced hash tree and asserts that each reaches
    /// the tree's root, both through the shipped surface and through the independent oracle.
    /// </summary>
    /// <param name="build">The built tree.</param>
    /// <param name="groups">The groups the tree was built over.</param>
    /// <returns>A task that completes when every group has been checked.</returns>
    private async ValueTask AssertReducedTreesReachTheRootAsync(EvidenceRecordHashTreeBuild build, List<byte[][]> groups)
    {
        byte[] root = build.Root.ToArray();
        for(int groupIndex = 0; groupIndex < groups.Count; ++groupIndex)
        {
            IReadOnlyList<EvidenceRecordPartialHashtree> reduced = build.ReducedHashtrees[groupIndex];
            var oracleReduced = new List<List<byte[]>>(reduced.Count);
            for(int listIndex = 0; listIndex < reduced.Count; ++listIndex)
            {
                var hashValues = new List<byte[]>(reduced[listIndex].HashValues.Count);
                for(int i = 0; i < reduced[listIndex].HashValues.Count; ++i)
                {
                    hashValues.Add(reduced[listIndex].HashValues[i].ToArray());
                }

                oracleReduced.Add(hashValues);
            }

            for(int objectIndex = 0; objectIndex < groups[groupIndex].Length; ++objectIndex)
            {
                byte[] dataObject = groups[groupIndex][objectIndex];
                using DigestValue dataObjectHash = await CryptographicKeyEvents.ComputeDigestAsync(
                    new ReadOnlyMemory<byte>(dataObject),
                    Algorithm.OutputByteLength,
                    Algorithm.DigestTag,
                    BaseMemoryPool.Shared,
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

                using EvidenceRecordRootComputation computation = await EvidenceRecordHashTree.ComputeRootAsync(
                    new EvidenceRecordRootComputationContext
                    {
                        DataObjectHash = dataObjectHash,
                        ReducedHashtree = reduced,
                        DigestAlgorithm = Algorithm
                    },
                    BaseMemoryPool.Shared,
                    TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(EvidenceRecordRootStatus.Computed, computation.Status, $"Group {groupIndex} object {objectIndex} did not walk to a root.");
                Assert.IsNotNull(computation.Root);
                Assert.IsTrue(computation.Root.AsReadOnlySpan().SequenceEqual(root), $"Group {groupIndex} object {objectIndex} walked to a different root.");

                byte[]? oracleRoot = EvidenceRecordOracle.RecomputeRoot(
                    EvidenceRecordOracle.Hash(dataObject, Algorithm), oracleReduced, Algorithm);
                Assert.IsNotNull(oracleRoot, $"The independent walk did not reach a root for group {groupIndex} object {objectIndex}.");
                Assert.IsTrue(oracleRoot.AsSpan().SequenceEqual(root), $"The independent walk reached a different root for group {groupIndex} object {objectIndex}.");
            }
        }
    }


    /// <summary>
    /// Mints a number of single-object data groups whose octets differ, so their hashes land in an order the
    /// tree has to sort rather than one the caller supplied.
    /// </summary>
    /// <param name="groupCount">How many groups to mint.</param>
    /// <returns>The groups.</returns>
    private static List<byte[][]> MintGroups(int groupCount)
    {
        var groups = new List<byte[][]>(groupCount);
        for(int i = 0; i < groupCount; ++i)
        {
            groups.Add([[.. "data object "u8, (byte)('a' + (i % 26)), (byte)('0' + (i / 26))]]);
        }

        return groups;
    }
}
