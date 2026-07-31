using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
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
/// <para>
/// CsCheck's <c>Sample</c> callback is synchronous; the asynchronous calls inside it are blocked on with
/// <c>AsTask().GetAwaiter().GetResult()</c>, the idiom this suite already uses in
/// <see cref="ArchiveTimestampV3PropertyTests"/>.
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

            return (actual == 0) == sample.left.AsSpan().SequenceEqual(sample.right);
        });
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
        });
    }


    /// <summary>
    /// Building a hash tree is a function of the data object groups, the algorithm and the arity, and of
    /// nothing else: the same inputs reach the same root every time, and that root is the one the independent
    /// implementation reaches.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2025:Ensure tasks using 'IDisposable' instances complete before the instances are disposed",
        Justification = "CsCheck's Sample callback is synchronous and cannot await; GetAwaiter().GetResult() blocks until the build fully completes, so the using declarations' dispose runs strictly after every call returns.")]
    public void BuildingTheSameTreeTwiceReachesTheSameRootAsTheIndependentBuild()
    {
        (from groupCount in Gen.Int[1, 8]
         from objectsPerGroup in Gen.Int[1, 3]
         from nodeArity in Gen.Int[2, 4]
         from seed in Gen.Byte.Array[1, 8]
         select (groupCount, objectsPerGroup, nodeArity, seed))
        .Sample(sample => TheBuildIsDeterministic(
            sample.groupCount, sample.objectsPerGroup, sample.nodeArity, sample.seed, TestContext.CancellationToken), iter: 25);
    }


    /// <summary>
    /// Every data object of a built tree walks its own reduced hash tree back to the tree's root, whatever the
    /// group count, the group sizes and the node arity are. This is the property that makes a reduced hash tree
    /// a proof at all.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2025:Ensure tasks using 'IDisposable' instances complete before the instances are disposed",
        Justification = "CsCheck's Sample callback is synchronous and cannot await; GetAwaiter().GetResult() blocks until the walk fully completes, so the using declarations' dispose runs strictly after every call returns.")]
    public void EveryDataObjectWalksItsReducedTreeBackToTheRoot()
    {
        (from groupCount in Gen.Int[1, 9]
         from objectsPerGroup in Gen.Int[1, 4]
         from nodeArity in Gen.Int[2, 5]
         from seed in Gen.Byte.Array[1, 8]
         select (groupCount, objectsPerGroup, nodeArity, seed))
        .Sample(sample => EveryReducedTreeReachesTheRoot(
            sample.groupCount, sample.objectsPerGroup, sample.nodeArity, sample.seed, TestContext.CancellationToken), iter: 25);
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
    [SuppressMessage("Reliability", "CA2025:Ensure tasks using 'IDisposable' instances complete before the instances are disposed",
        Justification = "GetAwaiter().GetResult() blocks until the build fully completes, so the using declarations' dispose runs strictly after every call returns.")]
    private static bool TheBuildIsDeterministic(int groupCount, int objectsPerGroup, int nodeArity, byte[] seed, CancellationToken cancellationToken)
    {
        List<byte[][]> groups = MintGroups(groupCount, objectsPerGroup, seed);
        using EvidenceRecordHashTreeBuild first = BuildTree(groups, nodeArity, cancellationToken);
        using EvidenceRecordHashTreeBuild second = BuildTree(groups, nodeArity, cancellationToken);

        byte[] expected = EvidenceRecordOracle.BuildRoot(groups, Algorithm, nodeArity);

        return first.Root.Span.SequenceEqual(second.Root.Span) && first.Root.Span.SequenceEqual(expected);
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
    [SuppressMessage("Reliability", "CA2025:Ensure tasks using 'IDisposable' instances complete before the instances are disposed",
        Justification = "GetAwaiter().GetResult() blocks until each call fully completes, so the using declarations' dispose runs strictly after every call returns.")]
    private static bool EveryReducedTreeReachesTheRoot(int groupCount, int objectsPerGroup, int nodeArity, byte[] seed, CancellationToken cancellationToken)
    {
        List<byte[][]> groups = MintGroups(groupCount, objectsPerGroup, seed);
        using EvidenceRecordHashTreeBuild build = BuildTree(groups, nodeArity, cancellationToken);
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
                using DigestValue dataObjectHash = CryptographicKeyEvents.ComputeDigestAsync(
                    new ReadOnlyMemory<byte>(dataObject),
                    Algorithm.OutputByteLength,
                    Algorithm.DigestTag,
                    BaseMemoryPool.Shared,
                    cancellationToken: cancellationToken).AsTask().GetAwaiter().GetResult();

                using EvidenceRecordRootComputation computation = EvidenceRecordHashTree.ComputeRootAsync(
                    new EvidenceRecordRootComputationContext
                    {
                        DataObjectHash = dataObjectHash,
                        ReducedHashtree = reduced,
                        DigestAlgorithm = Algorithm
                    },
                    BaseMemoryPool.Shared,
                    cancellationToken).AsTask().GetAwaiter().GetResult();

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
    /// Builds one tree through the shipped surface, blocking until it completes.
    /// </summary>
    /// <param name="groups">The groups, each a list of data object octets.</param>
    /// <param name="nodeArity">How many children an inner node is given.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The build. The caller disposes it.</returns>
    private static EvidenceRecordHashTreeBuild BuildTree(List<byte[][]> groups, int nodeArity, CancellationToken cancellationToken)
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

        return EvidenceRecordHashTree.BuildAsync(
            new EvidenceRecordHashTreeBuildContext
            {
                DataObjectGroups = dataObjectGroups,
                DigestAlgorithm = Algorithm,
                NodeArity = nodeArity
            },
            BaseMemoryPool.Shared,
            cancellationToken).AsTask().GetAwaiter().GetResult();
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
