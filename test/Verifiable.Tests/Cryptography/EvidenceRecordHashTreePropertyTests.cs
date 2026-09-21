using CsCheck;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Property-based tests (CsCheck) for the two rules the whole of
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.2">IETF RFC 4998 clause 4.2</see> rests on: the
/// binary ascending ordering of hash values, and the hash tree that ordering feeds.
/// </summary>
/// <remarks>
/// <para>
/// Both rules fail silently when they are wrong — a different comparator or a different node rule produces a
/// different root with no structural error anywhere — which is exactly the shape a property test catches and an
/// example-based test does not. A failing sample is a defect, not noise: CsCheck shrinks it and prints the seed
/// that reproduces it.
/// </para>
/// </remarks>
[TestClass]
internal sealed class EvidenceRecordHashTreePropertyTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The algorithm every tree in this class is built under.</summary>
    private static PkiDigestAlgorithm Algorithm { get; } = PkiDigestAlgorithm.Sha256;


    /// <summary>
    /// The comparator agrees with an independent unsigned octet-by-octet comparison on the sign of every pair,
    /// is antisymmetric, and reports equality only for identical octets.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see> rfc4998-4.2-R10.
    /// </remarks>
    [TestMethod]
    public void TheComparatorAgreesWithAnIndependentUnsignedComparisonOnEveryPair()
    {
        (from left in Gen.Byte.Array[1, 48]
         from right in Gen.Byte.Array[1, 48]
         select (left, right))
        .Sample(sample =>
        {
            int actual = EvidenceRecordHashTree.CompareHashValues(sample.left, sample.right);
            int expected = EvidenceRecordOracle.Compare(sample.left, sample.right);
            if(Math.Sign(actual) != Math.Sign(expected))
            {
                return false;
            }

            int reversed = EvidenceRecordHashTree.CompareHashValues(sample.right, sample.left);
            if(Math.Sign(reversed) != -Math.Sign(actual))
            {
                return false;
            }

            return actual == 0 == sample.left.AsSpan().SequenceEqual(sample.right);
        }, threads: CsCheckSampling.Threads);
    }


    /// <summary>
    /// Sorting through the comparator is a total order: sorting an already sorted list changes nothing, and
    /// sorting a shuffled copy of the same values reaches the same sequence.
    /// </summary>
    [TestMethod]
    public void SortingThroughTheComparatorIsStableUnderReordering()
    {
        Gen.Byte.Array[1, 32].Array[2, 12].Sample(values =>
        {
            var first = new List<ReadOnlyMemory<byte>>();
            var second = new List<ReadOnlyMemory<byte>>();
            for(int i = 0; i < values.Length; ++i)
            {
                first.Add(new ReadOnlyMemory<byte>(values[i]));
                second.Add(new ReadOnlyMemory<byte>(values[values.Length - 1 - i]));
            }

            first.Sort(EvidenceRecordHashTree.HashValueComparer);
            second.Sort(EvidenceRecordHashTree.HashValueComparer);

            for(int i = 0; i < first.Count; ++i)
            {
                if(!first[i].Span.SequenceEqual(second[i].Span))
                {
                    return false;
                }
            }

            for(int i = 1; i < first.Count; ++i)
            {
                if(EvidenceRecordHashTree.CompareHashValues(first[i - 1].Span, first[i].Span) > 0)
                {
                    return false;
                }
            }

            return true;
        }, threads: CsCheckSampling.Threads);
    }


    /// <summary>
    /// Building a hash tree is a function of the data object groups, the algorithm and the arity, and of
    /// nothing else: the same inputs reach the same root every time, and that root is the one the independent
    /// implementation reaches.
    /// </summary>
    [TestMethod]
    public async Task BuildingTheSameTreeTwiceReachesTheSameRootAsTheIndependentBuild()
    {
        await (from groupCount in Gen.Int[1, 8]
               from objectsPerGroup in Gen.Int[1, 3]
               from nodeArity in Gen.Int[2, 4]
               from seed in Gen.Byte.Array[1, 8]
               select (groupCount, objectsPerGroup, nodeArity, seed))
        .SampleAsync(async sample => await TheBuildIsDeterministic(
            sample.groupCount, sample.objectsPerGroup, sample.nodeArity, sample.seed, TestContext.CancellationToken), iter: 25, threads: CsCheckSampling.Threads);
    }


    /// <summary>
    /// Every data object of a built tree walks its own reduced hash tree back to the tree's root, whatever the
    /// group count, the group sizes and the node arity are. This is the property that makes a reduced hash tree
    /// a proof at all.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see> rfc4998-4.3-R18.
    /// </remarks>
    [TestMethod]
    public async Task EveryDataObjectWalksItsReducedTreeBackToTheRoot()
    {
        await (from groupCount in Gen.Int[1, 9]
               from objectsPerGroup in Gen.Int[1, 4]
               from nodeArity in Gen.Int[2, 5]
               from seed in Gen.Byte.Array[1, 8]
               select (groupCount, objectsPerGroup, nodeArity, seed))
        .SampleAsync(async sample => await EveryReducedTreeReachesTheRoot(
            sample.groupCount, sample.objectsPerGroup, sample.nodeArity, sample.seed, TestContext.CancellationToken), iter: 25, threads: CsCheckSampling.Threads);
    }


    /// <summary>
    /// Runs one determinism sample: builds the same tree twice and compares both roots against the independent
    /// implementation's. Every input is an explicit parameter, so the check keeps no state.
    /// </summary>
    /// <param name="groupCount">How many data object groups the tree binds.</param>
    /// <param name="objectsPerGroup">How many data objects each group holds.</param>
    /// <param name="nodeArity">How many children an inner node is given.</param>
    /// <param name="seed">Octets mixed into every data object, so different samples bind different content.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when the sample upheld the property.</returns>
    private static async Task<bool> TheBuildIsDeterministic(int groupCount, int objectsPerGroup, int nodeArity, byte[] seed, CancellationToken cancellationToken)
    {
        List<byte[][]> groups = MintGroups(groupCount, objectsPerGroup, seed);
        using EvidenceRecordHashTreeBuild first = await BuildTree(groups, nodeArity, cancellationToken);
        using EvidenceRecordHashTreeBuild second = await BuildTree(groups, nodeArity, cancellationToken);

        byte[] expected = EvidenceRecordOracle.BuildRoot(groups, Algorithm, nodeArity);

        return first.Root.AsReadOnlySpan().SequenceEqual(second.Root.AsReadOnlySpan()) && first.Root.AsReadOnlySpan().SequenceEqual(expected);
    }


    /// <summary>
    /// Runs one reduction sample: builds the tree and walks every data object of every group back up its own
    /// reduced hash tree, through the shipped surface and through the independent implementation alike.
    /// </summary>
    /// <param name="groupCount">How many data object groups the tree binds.</param>
    /// <param name="objectsPerGroup">How many data objects each group holds.</param>
    /// <param name="nodeArity">How many children an inner node is given.</param>
    /// <param name="seed">Octets mixed into every data object.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when the sample upheld the property.</returns>
    private static async Task<bool> EveryReducedTreeReachesTheRoot(int groupCount, int objectsPerGroup, int nodeArity, byte[] seed, CancellationToken cancellationToken)
    {
        List<byte[][]> groups = MintGroups(groupCount, objectsPerGroup, seed);
        using EvidenceRecordHashTreeBuild build = await BuildTree(groups, nodeArity, cancellationToken);
        byte[] root = build.Root.AsReadOnlySpan().ToArray();

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
                    cancellationToken: cancellationToken).AsTask();

                using EvidenceRecordRootComputation computation = await EvidenceRecordHashTree.ComputeRootAsync(
                    new EvidenceRecordRootComputationContext
                    {
                        DataObjectHash = dataObjectHash,
                        ReducedHashtree = reduced,
                        DigestAlgorithm = Algorithm
                    },
                    BaseMemoryPool.Shared,
                    cancellationToken).AsTask();

                if(computation.Status != EvidenceRecordRootStatus.Computed
                    || computation.Root is null
                    || !computation.Root.AsReadOnlySpan().SequenceEqual(root))
                {
                    return false;
                }

                byte[]? oracleRoot = EvidenceRecordOracle.RecomputeRoot(
                    EvidenceRecordOracle.Hash(dataObject, Algorithm), oracleReduced, Algorithm);
                if(oracleRoot is null || !oracleRoot.AsSpan().SequenceEqual(root))
                {
                    return false;
                }
            }
        }

        return true;
    }


    /// <summary>
    /// Builds one tree through the shipped surface.
    /// </summary>
    /// <param name="groups">The groups, each a list of data object octets.</param>
    /// <param name="nodeArity">How many children an inner node is given.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The build. The caller disposes it.</returns>
    private static async Task<EvidenceRecordHashTreeBuild> BuildTree(List<byte[][]> groups, int nodeArity, CancellationToken cancellationToken)
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
            cancellationToken).AsTask();
    }


    /// <summary>
    /// Mints data object groups whose octets are distinct within a sample and differ between samples.
    /// </summary>
    /// <param name="groupCount">How many groups to mint.</param>
    /// <param name="objectsPerGroup">How many data objects each group holds.</param>
    /// <param name="seed">Octets mixed into every data object.</param>
    /// <returns>The groups.</returns>
    private static List<byte[][]> MintGroups(int groupCount, int objectsPerGroup, byte[] seed)
    {
        var groups = new List<byte[][]>(groupCount);
        for(int groupIndex = 0; groupIndex < groupCount; ++groupIndex)
        {
            var dataObjects = new byte[objectsPerGroup][];
            for(int objectIndex = 0; objectIndex < objectsPerGroup; ++objectIndex)
            {
                dataObjects[objectIndex] = [.. seed, (byte)groupIndex, (byte)objectIndex, .. "data object"u8];
            }

            groups.Add(dataObjects);
        }

        return groups;
    }
}
