using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Secdsa;

namespace Verifiable.Tests.Secdsa;

/// <summary>
/// Regression tests for the migration of <see cref="SchnorrZkp"/>'s challenge
/// hash from a direct streaming <see cref="IncrementalHash"/> implementation
/// to the registered multi-segment <c>ComputeDigestAsync</c> path.
/// </summary>
/// <remarks>
/// The migrated path builds a multi-segment <see cref="ReadOnlySequence{T}"/>
/// over pool-rented per-point encodings and routes it through the registered
/// <c>ComputeDigestDelegate</c>. These tests assert that the bytes the
/// multi-segment path feeds into SHA-256 — and therefore the resulting
/// challenge value — are byte-equivalent to the pre-migration reference
/// (direct <see cref="IncrementalHash.AppendData(System.ReadOnlySpan{byte})"/>
/// over the same per-point encodings in the same order).
/// </remarks>
[TestClass]
internal sealed class SchnorrZkpChallengeHashMigrationTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task SingleGeneratorChallengeHashMatchesIncrementalHashReference()
    {
        BigInteger d = EcMath.RandomScalar();
        EcPoint dPoint = EcMath.BasePointMultiply(d);
        EcPoint[] generators = [EcMath.G];
        EcPoint[] publicKeys = [dPoint];
        byte[] binding = "challenge-binding-A"u8.ToArray();

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        SchnorrZkProof proof = await SchnorrZkp.GenerateAsync(
            generators, publicKeys, d, binding, pool, cancellationToken).ConfigureAwait(false);

        EcPoint[] reconstructedCommitments =
            ReconstructCommitments(proof, generators, publicKeys);

        BigInteger expectedChallenge = ComputeReferenceChallenge(
            generators, reconstructedCommitments, publicKeys, binding);

        Assert.AreEqual(expectedChallenge, proof.R,
            "Migrated multi-segment ComputeChallengeHash must produce byte-equivalent output to the direct IncrementalHash reference.");
    }


    [TestMethod]
    public async Task MultiGeneratorChallengeHashMatchesIncrementalHashReference()
    {
        BigInteger d = EcMath.RandomScalar();
        BigInteger h = EcMath.RandomScalar();
        EcPoint hPoint = EcMath.BasePointMultiply(h);

        EcPoint dGenerator0 = EcMath.BasePointMultiply(d);
        EcPoint dGenerator1 = EcMath.Multiply(hPoint, d);

        EcPoint[] generators = [EcMath.G, hPoint];
        EcPoint[] publicKeys = [dGenerator0, dGenerator1];
        byte[] binding = "multi-generator-binding"u8.ToArray();

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        SchnorrZkProof proof = await SchnorrZkp.GenerateAsync(
            generators, publicKeys, d, binding, pool, cancellationToken).ConfigureAwait(false);

        EcPoint[] reconstructedCommitments =
            ReconstructCommitments(proof, generators, publicKeys);

        BigInteger expectedChallenge = ComputeReferenceChallenge(
            generators, reconstructedCommitments, publicKeys, binding);

        Assert.AreEqual(expectedChallenge, proof.R,
            "Multi-generator multi-segment hashing must match the direct streaming reference byte-for-byte.");
    }


    [TestMethod]
    public async Task EmptyChallengeBindingMatchesIncrementalHashReference()
    {
        BigInteger d = EcMath.RandomScalar();
        EcPoint dPoint = EcMath.BasePointMultiply(d);
        EcPoint[] generators = [EcMath.G];
        EcPoint[] publicKeys = [dPoint];

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        SchnorrZkProof proof = await SchnorrZkp.GenerateAsync(
            generators, publicKeys, d, ReadOnlyMemory<byte>.Empty, pool, cancellationToken).ConfigureAwait(false);

        EcPoint[] reconstructedCommitments =
            ReconstructCommitments(proof, generators, publicKeys);

        BigInteger expectedChallenge = ComputeReferenceChallenge(
            generators, reconstructedCommitments, publicKeys, ReadOnlySpan<byte>.Empty);

        Assert.AreEqual(expectedChallenge, proof.R,
            "Empty challenge binding must skip the trailing segment and match the reference exactly.");
    }


    [TestMethod]
    public void EncodePointUncompressedIntoMatchesArrayOverload()
    {
        BigInteger scalar = EcMath.RandomScalar();
        EcPoint point = EcMath.BasePointMultiply(scalar);

        byte[] arrayOverload = EcMath.EncodePointUncompressed(point);

        Span<byte> destination = stackalloc byte[arrayOverload.Length];
        int written = EcMath.EncodePointUncompressedInto(point, destination);

        Assert.AreEqual(arrayOverload.Length, written,
            "Span overload must report writing the same number of bytes the array overload returns.");
        Assert.IsTrue(destination.SequenceEqual(arrayOverload),
            "Span overload must produce byte-equivalent output to the array overload.");
    }


    private static EcPoint[] ReconstructCommitments(
        SchnorrZkProof proof,
        EcPoint[] generators,
        EcPoint[] publicKeys)
    {
        EcPoint[] commitments = new EcPoint[generators.Length];
        for(int i = 0; i < generators.Length; i++)
        {
            EcPoint sG = EcMath.Multiply(generators[i], proof.S);
            EcPoint cD = EcMath.Multiply(publicKeys[i], proof.R);
            commitments[i] = EcMath.Add(sG, cD);
        }

        return commitments;
    }


    private static BigInteger ComputeReferenceChallenge(
        EcPoint[] generators,
        EcPoint[] commitments,
        EcPoint[] publicKeys,
        ReadOnlySpan<byte> challengeBinding)
    {
        using IncrementalHash hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        for(int i = 0; i < generators.Length; i++)
        {
            hasher.AppendData(EcMath.EncodePointUncompressed(generators[i]));
        }

        for(int i = 0; i < commitments.Length; i++)
        {
            hasher.AppendData(EcMath.EncodePointUncompressed(commitments[i]));
        }

        for(int i = 0; i < publicKeys.Length; i++)
        {
            hasher.AppendData(EcMath.EncodePointUncompressed(publicKeys[i]));
        }

        if(challengeBinding.Length > 0)
        {
            hasher.AppendData(challengeBinding);
        }

        byte[] hash = hasher.GetHashAndReset();
        return new BigInteger(hash, isUnsigned: true, isBigEndian: true);
    }
}
