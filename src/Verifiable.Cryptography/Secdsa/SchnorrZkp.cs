using System.Numerics;
using System.Security.Cryptography;

namespace Verifiable.Cryptography.Secdsa;

/// <summary>
/// Schnorr non-interactive zero-knowledge proof for equality of discrete logarithms
/// (Algorithms 19 and 20 of the SECDSA specification at https://wellet.nl/SECDSA-EUDI-wallet-latest.pdf).
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
/// </remarks>
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
    /// <returns>The Schnorr proof (r, s).</returns>
    public static SchnorrZkProof Generate(
        EcPoint[] generators,
        EcPoint[] publicKeys,
        BigInteger witness,
        ReadOnlySpan<byte> challengeBinding)
    {
        ArgumentNullException.ThrowIfNull(generators);
        ArgumentNullException.ThrowIfNull(publicKeys);

        //TODO: Replace with a call to a deterministic nonce derivation utility
        //(RFC 6979 Section 3.2) once implemented in Verifiable.Cryptography.
        //
        //The current RandomScalar is correct and safe -- RandomNumberGenerator.Fill
        //provides cryptographically strong randomness and the 256-bit scalar makes
        //k reuse negligible (~2^-128 birthday bound). A TPM-sourced random would be
        //equivalent, not stronger.
        //
        //Deterministic derivation would additionally remove the RNG as a dependency:
        //k = HMAC-SHA256(witness || challenge_binding) is fully determined by the
        //secret inputs, guaranteeing uniqueness per (witness, binding) pair and making
        //proofs reproducible for testing and audit.
        //
        //The derivation belongs in Verifiable.Cryptography as a standalone utility
        //(e.g. Rfc6979.DeriveScalar) rather than in EcMath, because RFC 6979 nonce
        //derivation is a general cryptographic primitive reusable across ECDSA, EdDSA,
        //BBS+, and any other scheme that requires a deterministic per-message scalar.
        //RandomScalar itself must remain unchanged -- its contract is randomness, and
        //other callers (key generation, ECDSA signing, test data) depend on that.
        // TODO: https://github.com/Lumoin/Verifiable/issues/529..
        BigInteger k = EcMath.RandomScalar();
        EcPoint[] commitments = new EcPoint[generators.Length];
        for(int i = 0; i < generators.Length; i++)
        {
            commitments[i] = EcMath.Multiply(generators[i], k);
        }

        BigInteger challenge = ComputeChallengeHash(generators, commitments, publicKeys, challengeBinding);
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
    /// <returns><see langword="true"/> if the proof is valid; otherwise <see langword="false"/>.</returns>
    public static bool Verify(
        SchnorrZkProof proof,
        EcPoint[] generators,
        EcPoint[] publicKeys,
        ReadOnlySpan<byte> challengeBinding)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(generators);
        ArgumentNullException.ThrowIfNull(publicKeys);

        EcPoint[] reconstructedCommitments = new EcPoint[generators.Length];
        for(int i = 0; i < generators.Length; i++)
        {
            EcPoint sG = EcMath.Multiply(generators[i], proof.S);
            EcPoint cD = EcMath.Multiply(publicKeys[i], proof.R);
            reconstructedCommitments[i] = EcMath.Add(sG, cD);
        }

        BigInteger expectedChallenge = ComputeChallengeHash(
            generators,
            reconstructedCommitments,
            publicKeys,
            challengeBinding);

        return proof.R == expectedChallenge;
    }


    private static BigInteger ComputeChallengeHash(
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
