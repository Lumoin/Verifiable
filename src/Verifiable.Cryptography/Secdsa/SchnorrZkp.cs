using System.Buffers;
using System.Numerics;
using static Verifiable.Cryptography.EllipticCurveConstants;

namespace Verifiable.Cryptography.Secdsa;

/// <summary>
/// Schnorr non-interactive zero-knowledge proof for equality of discrete logarithms
/// (Algorithms 19 and 20 of the SECDSA specification).
/// </summary>
/// <remarks>
/// <para>
/// Used in three places in the SECDSA protocol:
/// </para>
/// <list type="bullet">
///   <item><description>Proof of possession of the NCH private key u (single generator G).</description></item>
///   <item><description>Proof that G' = aU*G and Y' = aU*Y share the same discrete log aU (two generators G, Y).</description></item>
///   <item><description>Proof of signature consistency: G'' = s^(-1)*G' and Y'' = s^(-1)*Y' share the same discrete log s^(-1) (Algorithm 3, Step 6).</description></item>
/// </list>
/// <para>
/// The proof is non-interactive via the Fiat-Shamir transform using SHA-256.
/// The challenge hash binds all generators, commitments, and public keys,
/// plus an optional challenge binding for domain separation.
/// </para>
/// <para>
/// Not yet implemented: deterministic nonce derivation for the commitment scalar k.
/// See <see href="https://github.com/Lumoin/Verifiable/issues/529"/>.
/// </para>
public static class SchnorrZkp
{
    /// <summary>
    /// Generates a Schnorr ZKP proving knowledge of scalar d such that Di = d*Gi
    /// for all i (Algorithm 19).
    /// </summary>
    /// <param name="generators">The generator points G0, G1, ..., Gn.</param>
    /// <param name="publicKeys">The public key points D0 = d*G0, D1 = d*G1, ..., Dn = d*Gn.</param>
    /// <param name="witness">The witness scalar d.</param>
    /// <param name="challengeBinding">Optional context bytes bound into the challenge hash for domain separation.</param>
    /// <param name="pool">Memory pool for the per-point encoding buffers fed into the digest primitive.</param>
    /// <param name="cancellationToken">Token to observe while awaiting the digest computation.</param>
    /// <returns>The Schnorr proof (r, s).</returns>
    public static async ValueTask<SchnorrZkProof> GenerateAsync(
        EcPoint[] generators,
        EcPoint[] publicKeys,
        BigInteger witness,
        ReadOnlyMemory<byte> challengeBinding,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(generators);
        ArgumentNullException.ThrowIfNull(publicKeys);
        ArgumentNullException.ThrowIfNull(pool);

        //TODO: Replace with Rfc6979.DeriveScalar once implemented in Verifiable.Cryptography.
        //https://github.com/Lumoin/Verifiable/issues/529
        BigInteger k = EcMath.RandomScalar();
        EcPoint[] commitments = new EcPoint[generators.Length];
        for(int i = 0; i < generators.Length; i++)
        {
            commitments[i] = EcMath.Multiply(generators[i], k);
        }

        BigInteger challenge = await ComputeChallengeHashAsync(
            generators, commitments, publicKeys, challengeBinding, pool, cancellationToken).ConfigureAwait(false);
        BigInteger response = ((k - witness * challenge % EcMath.Q) % EcMath.Q + EcMath.Q) % EcMath.Q;

        return new SchnorrZkProof(challenge, response);
    }


    /// <summary>
    /// Verifies a Schnorr ZKP (Algorithm 20).
    /// </summary>
    /// <param name="proof">The proof to verify.</param>
    /// <param name="generators">The generator points.</param>
    /// <param name="publicKeys">The claimed public key points Di = d*Gi.</param>
    /// <param name="challengeBinding">The same optional context bytes used during generation.</param>
    /// <param name="pool">Memory pool for the per-point encoding buffers fed into the digest primitive.</param>
    /// <param name="cancellationToken">Token to observe while awaiting the digest computation.</param>
    /// <returns><see langword="true"/> if the proof is valid; otherwise <see langword="false"/>.</returns>
    public static async ValueTask<bool> VerifyAsync(
        SchnorrZkProof proof,
        EcPoint[] generators,
        EcPoint[] publicKeys,
        ReadOnlyMemory<byte> challengeBinding,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(generators);
        ArgumentNullException.ThrowIfNull(publicKeys);
        ArgumentNullException.ThrowIfNull(pool);

        EcPoint[] reconstructedCommitments = new EcPoint[generators.Length];
        for(int i = 0; i < generators.Length; i++)
        {
            EcPoint sG = EcMath.Multiply(generators[i], proof.S);
            EcPoint cD = EcMath.Multiply(publicKeys[i], proof.R);
            reconstructedCommitments[i] = EcMath.Add(sG, cD);
        }

        BigInteger expectedChallenge = await ComputeChallengeHashAsync(
            generators,
            reconstructedCommitments,
            publicKeys,
            challengeBinding,
            pool,
            cancellationToken).ConfigureAwait(false);

        return proof.R == expectedChallenge;
    }


    private static async ValueTask<BigInteger> ComputeChallengeHashAsync(
        EcPoint[] generators,
        EcPoint[] commitments,
        EcPoint[] publicKeys,
        ReadOnlyMemory<byte> challengeBinding,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        const int pointByteLength = P256.UncompressedPointByteCount;
        int totalPoints = generators.Length + commitments.Length + publicKeys.Length;

        IMemoryOwner<byte>[] pointOwners = new IMemoryOwner<byte>[totalPoints];
        int pointIndex = 0;
        try
        {
            BufferSegment? first = null;
            BufferSegment? last = null;

            pointIndex = AppendPointSegments(generators, pool, pointOwners, pointIndex, ref first, ref last);
            pointIndex = AppendPointSegments(commitments, pool, pointOwners, pointIndex, ref first, ref last);
            pointIndex = AppendPointSegments(publicKeys, pool, pointOwners, pointIndex, ref first, ref last);

            if(challengeBinding.Length > 0)
            {
                AppendSegment(challengeBinding, ref first, ref last);
            }

            ReadOnlySequence<byte> input = first is null
                ? ReadOnlySequence<byte>.Empty
                : new ReadOnlySequence<byte>(first, 0, last!, last!.Memory.Length);

            using DigestValue hash = await CryptographicKeyEvents.ComputeDigestAsync(
                input,
                outputByteLength: 32,
                tag: CryptoTags.Sha256Digest,
                pool: pool,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            return new BigInteger(hash.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);

            static int AppendPointSegments(
                EcPoint[] points,
                MemoryPool<byte> pool,
                IMemoryOwner<byte>[] owners,
                int startIndex,
                ref BufferSegment? first,
                ref BufferSegment? last)
            {
                for(int i = 0; i < points.Length; i++)
                {
                    IMemoryOwner<byte> owner = pool.Rent(pointByteLength);
                    owners[startIndex] = owner;
                    EcMath.EncodePointUncompressedInto(points[i], owner.Memory.Span);
                    AppendSegment(owner.Memory[..pointByteLength], ref first, ref last);
                    startIndex++;
                }

                return startIndex;
            }

            static void AppendSegment(
                ReadOnlyMemory<byte> memory,
                ref BufferSegment? first,
                ref BufferSegment? last)
            {
                if(first is null)
                {
                    BufferSegment seg = new(memory);
                    first = seg;
                    last = seg;
                }
                else
                {
                    last = last!.Append(memory);
                }
            }
        }
        finally
        {
            for(int i = 0; i < pointIndex; i++)
            {
                pointOwners[i].Dispose();
            }
        }
    }
}
