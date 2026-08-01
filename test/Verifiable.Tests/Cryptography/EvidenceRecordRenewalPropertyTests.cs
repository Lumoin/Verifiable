using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Threading;
using CsCheck;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Property-based tests (CsCheck) for the two rules a renewal under
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.2">IETF RFC 4998 clause 5.2</see> rests on: the
/// combination of a data object's hash with the hash of the encoded prior sequence, and the hash tree built over
/// the values that combination produces.
/// </summary>
/// <remarks>
/// Both rules fail silently when they are wrong. A renewal that combined the pair in the other order, or that
/// hashed the already-hashed renewal values a second time before treating them as leaves, produces a
/// structurally perfect record whose new chain simply proves nothing — there is no error anywhere for an
/// example-based test to catch except at the one input that happens to expose it. A failing sample here is a
/// defect, not noise: CsCheck shrinks it and prints the seed that reproduces it.
/// </remarks>
[TestClass]
internal sealed class EvidenceRecordRenewalPropertyTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The algorithms a sample may select the renewal's new hash algorithm from.</summary>
    private static IReadOnlyList<PkiDigestAlgorithm> Algorithms { get; } =
        [PkiDigestAlgorithm.Sha256, PkiDigestAlgorithm.Sha384, PkiDigestAlgorithm.Sha512];


    /// <summary>
    /// The renewal combination is a function of the data object, the encoded prior sequence and the algorithm,
    /// and of nothing else: the same inputs reach the same value every time, and that value is the one the
    /// independent implementation reaches from the clause text.
    /// </summary>
    [TestMethod]
    public void TheRenewalCombinationIsDeterministicAndMatchesTheIndependentComputation()
    {
        (from dataObject in Gen.Byte.Array[1, 64]
         from chainContent in Gen.Byte.Array[1, 64]
         from algorithmIndex in Gen.Int[0, 2]
         select (dataObject, chainContent, algorithmIndex))
        .Sample(sample => TheCombinationMatches(
            sample.dataObject, sample.chainContent, Algorithms[sample.algorithmIndex], TestContext.CancellationToken), iter: 50);
    }


    /// <summary>
    /// Every renewal value a Hash-Tree Renewal produces walks its own reduced hash tree back to the root the
    /// renewal's time-stamp is taken over, whatever the group count, the group sizes and the node arity are.
    /// This is the property that makes a renewed chain a proof of the data objects it was renewed over.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2025:Ensure tasks using 'IDisposable' instances complete before the instances are disposed",
        Justification = "CsCheck's Sample callback is synchronous and cannot await; GetAwaiter().GetResult() blocks until each call fully completes, so the using declarations' dispose runs strictly after every call returns.")]
    public void EveryRenewalValueWalksItsReducedTreeBackToTheRoot()
    {
        (from groupCount in Gen.Int[1, 7]
         from objectsPerGroup in Gen.Int[1, 3]
         from nodeArity in Gen.Int[2, 4]
         from seed in Gen.Byte.Array[1, 8]
         select (groupCount, objectsPerGroup, nodeArity, seed))
        .Sample(sample => EveryRenewalValueReachesTheRoot(
            sample.groupCount, sample.objectsPerGroup, sample.nodeArity, sample.seed, TestContext.CancellationToken), iter: 25);
    }


    /// <summary>
    /// Runs one combination sample: computes the renewal value twice through the shipped surface and once
    /// through the independent implementation, and checks all three agree while the sorted reading of the same
    /// pair does not, whenever the two readings differ at all.
    /// </summary>
    /// <param name="dataObject">The archived data object's octets.</param>
    /// <param name="chainContent">Octets wrapped into a well-formed prior chain, so that what is hashed is a real encoded sequence.</param>
    /// <param name="algorithm">The renewal's new algorithm.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when the sample upheld the property.</returns>
    [SuppressMessage("Reliability", "CA2025:Ensure tasks using 'IDisposable' instances complete before the instances are disposed",
        Justification = "GetAwaiter().GetResult() blocks until each call fully completes, so the using declarations' dispose runs strictly after every call returns.")]
    private static bool TheCombinationMatches(byte[] dataObject, byte[] chainContent, PkiDigestAlgorithm algorithm, CancellationToken cancellationToken)
    {
        byte[] priorChain = WrapAsChain(chainContent);
        byte[] encodedSequence = EvidenceRecordOracle.EncodeArchiveTimeStampSequence([priorChain]);
        byte[] expected = EvidenceRecordOracle.HashTreeRenewalValue(dataObject, [priorChain], algorithm);
        byte[] sorted = EvidenceRecordOracle.HashTreeRenewalValueSorted(dataObject, [priorChain], algorithm);

        using DigestValue first = ComputeRenewalValue(dataObject, encodedSequence, algorithm, cancellationToken);
        using DigestValue second = ComputeRenewalValue(dataObject, encodedSequence, algorithm, cancellationToken);

        ReadOnlySpan<byte> computed = first.AsReadOnlySpan()[..algorithm.OutputByteLength];
        if(!computed.SequenceEqual(second.AsReadOnlySpan()[..algorithm.OutputByteLength]) || !computed.SequenceEqual(expected))
        {
            return false;
        }

        //Where the two readings of step 4 coincide there is nothing to tell apart; where they do not, the
        //library's value is the prose's and not the figure's.
        return expected.AsSpan().SequenceEqual(sorted) || !computed.SequenceEqual(sorted);
    }


    /// <summary>
    /// Runs one tree sample: builds a hash tree over renewal values and walks every one of them back up its own
    /// reduced hash tree, through the shipped surface and through the independent implementation alike.
    /// </summary>
    /// <param name="groupCount">How many groups the renewal binds.</param>
    /// <param name="objectsPerGroup">How many data objects each group holds.</param>
    /// <param name="nodeArity">How many children an inner node is given.</param>
    /// <param name="seed">Octets mixed into every data object, so different samples bind different content.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when the sample upheld the property.</returns>
    [SuppressMessage("Reliability", "CA2025:Ensure tasks using 'IDisposable' instances complete before the instances are disposed",
        Justification = "GetAwaiter().GetResult() blocks until each call fully completes, so the using declarations' dispose runs strictly after every call returns.")]
    private static bool EveryRenewalValueReachesTheRoot(int groupCount, int objectsPerGroup, int nodeArity, byte[] seed, CancellationToken cancellationToken)
    {
        PkiDigestAlgorithm algorithm = PkiDigestAlgorithm.Sha256;
        var oracleGroups = new List<IReadOnlyList<byte[]>>(groupCount);
        var owned = new List<DigestValue>();
        var leafGroups = new List<IReadOnlyList<ReadOnlyMemory<byte>>>(groupCount);
        try
        {
            for(int groupIndex = 0; groupIndex < groupCount; ++groupIndex)
            {
                byte[] priorChain = WrapAsChain([.. seed, (byte)groupIndex, .. "prior chain"u8]);
                byte[] encodedSequence = EvidenceRecordOracle.EncodeArchiveTimeStampSequence([priorChain]);

                var oracleLeaves = new List<byte[]>(objectsPerGroup);
                var leaves = new List<ReadOnlyMemory<byte>>(objectsPerGroup);
                for(int objectIndex = 0; objectIndex < objectsPerGroup; ++objectIndex)
                {
                    byte[] dataObject = [.. seed, (byte)groupIndex, (byte)objectIndex, .. "data object"u8];
                    oracleLeaves.Add(EvidenceRecordOracle.HashTreeRenewalValue(dataObject, [priorChain], algorithm));

                    DigestValue leaf = ComputeRenewalValue(dataObject, encodedSequence, algorithm, cancellationToken);
                    owned.Add(leaf);
                    leaves.Add(leaf.AsReadOnlyMemory()[..algorithm.OutputByteLength]);
                }

                oracleGroups.Add(oracleLeaves);
                leafGroups.Add(leaves);
            }

            using EvidenceRecordHashTreeBuild build = EvidenceRecordHashTree.BuildFromHashValuesAsync(
                new EvidenceRecordHashTreeHashValueBuildContext
                {
                    HashValueGroups = leafGroups,
                    DigestAlgorithm = algorithm,
                    NodeArity = nodeArity
                },
                BaseMemoryPool.Shared,
                cancellationToken).AsTask().GetAwaiter().GetResult();

            byte[] expectedRoot = EvidenceRecordOracle.BuildRootFromHashValues(oracleGroups, algorithm, nodeArity);
            if(!build.Root.AsReadOnlySpan().SequenceEqual(expectedRoot))
            {
                return false;
            }

            for(int groupIndex = 0; groupIndex < groupCount; ++groupIndex)
            {
                IReadOnlyList<EvidenceRecordPartialHashtree> reduced = build.ReducedHashtrees[groupIndex];
                for(int objectIndex = 0; objectIndex < objectsPerGroup; ++objectIndex)
                {
                    using DigestValue leaf = CopyAsDigest(oracleGroups[groupIndex][objectIndex], algorithm);
                    using EvidenceRecordRootComputation computation = EvidenceRecordHashTree.ComputeRootAsync(
                        new EvidenceRecordRootComputationContext
                        {
                            DataObjectHash = leaf,
                            ReducedHashtree = reduced,
                            DigestAlgorithm = algorithm
                        },
                        BaseMemoryPool.Shared,
                        cancellationToken).AsTask().GetAwaiter().GetResult();

                    if(computation.Status != EvidenceRecordRootStatus.Computed
                        || computation.Root is null
                        || !computation.Root.AsReadOnlySpan().SequenceEqual(expectedRoot))
                    {
                        return false;
                    }
                }
            }

            return true;
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
    /// Computes one renewal value through the shipped surface, blocking until it completes.
    /// </summary>
    /// <param name="dataObject">The archived data object's octets.</param>
    /// <param name="encodedSequence">The encoded <c>ArchiveTimeStampSequence</c> of every prior chain.</param>
    /// <param name="algorithm">The renewal's new algorithm.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The value. The caller disposes it.</returns>
    private static DigestValue ComputeRenewalValue(byte[] dataObject, byte[] encodedSequence, PkiDigestAlgorithm algorithm, CancellationToken cancellationToken)
    {
        return EvidenceRecords.ComputeHashTreeRenewalValueAsync(
            new ReadOnlyMemory<byte>(dataObject),
            new ReadOnlyMemory<byte>(encodedSequence),
            algorithm,
            BaseMemoryPool.Shared,
            cancellationToken).AsTask().GetAwaiter().GetResult();
    }


    /// <summary>
    /// Copies hash octets into the digest carrier the root computation takes.
    /// </summary>
    /// <param name="hashValue">The octets.</param>
    /// <param name="algorithm">The algorithm the value was computed under, which names the carrier's tag.</param>
    /// <returns>The carrier. The caller disposes it.</returns>
    private static DigestValue CopyAsDigest(byte[] hashValue, PkiDigestAlgorithm algorithm)
    {
        System.Buffers.IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(hashValue.Length);
        try
        {
            hashValue.CopyTo(owner.Memory.Span);

            return new DigestValue(owner, algorithm.DigestTag);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Wraps octets into a well-formed element that stands in for a prior <c>ArchiveTimeStampChain</c>, so that
    /// what clause 5.2 step 3 hashes is a real encoded sequence rather than loose bytes.
    /// </summary>
    /// <param name="content">The octets to wrap.</param>
    /// <returns>The encoded element.</returns>
    /// <remarks>
    /// What the renewal binds is the octets of the encoding, not anything they mean, so a stand-in of the right
    /// shape exercises the rule exactly as a real chain would while keeping the property free of a Time-Stamping
    /// Authority.
    /// </remarks>
    private static byte[] WrapAsChain(byte[] content)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteOctetString(content);
        }

        return writer.Encode();
    }
}
