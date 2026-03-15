using System.Numerics;

namespace Verifiable.Cryptography.Secdsa;

/// <summary>
/// Core SECDSA algorithms from the SECDSA specification at
/// https://wellet.nl/SECDSA-EUDI-wallet-latest.pdf.
/// </summary>
/// <remarks>
/// <para>
/// Implements the software-only (Phase 1) versions of:
/// </para>
/// <list type="bullet">
///   <item><description>Algorithm 1: Key generation.</description></item>
///   <item><description>Algorithm 2: Signing.</description></item>
///   <item><description>Algorithm 14: Standard ECDSA verification on the SECDSA public key.</description></item>
///   <item><description>Algorithm 15: Full-format ECDSA verification.</description></item>
/// </list>
/// <para>
/// In Phase 2, <see cref="RawEcdsaSign"/> is replaced by a delegate backed by TPM2_Sign.
/// All other operations remain in software.
/// </para>
/// </remarks>
public static class SecdsaAlgorithms
{
    /// <summary>
    /// Generates a SECDSA key pair (Algorithm 1).
    /// </summary>
    /// <remarks>
    /// Computes Y = P * (u * G) = (u * P) * G. Neither u alone nor P alone
    /// is sufficient to produce a valid signature.
    /// </remarks>
    /// <param name="nchPrivateKey">The NCH-bound private key u.</param>
    /// <param name="pinKey">The PIN-derived key P.</param>
    /// <returns>The SECDSA key pair.</returns>
    public static SecdsaKeyPair GenerateKeyPair(BigInteger nchPrivateKey, BigInteger pinKey)
    {
        EcPoint nchPublicKey = EcMath.BasePointMultiply(nchPrivateKey);
        EcPoint publicKey = EcMath.Multiply(nchPublicKey, pinKey);

        return new SecdsaKeyPair(publicKey, nchPrivateKey, pinKey);
    }

    /// <summary>
    /// Signs a message hash using the SECDSA two-factor signing protocol (Algorithm 2).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The protocol adjusts the hash before signing with the NCH key so that the
    /// resulting signature is valid ECDSA on the combined key u*P:
    /// </para>
    /// <list type="bullet">
    ///   <item><description>Compute adjusted hash: e' = P^(-1) * e mod q.</description></item>
    ///   <item><description>Sign e' with u using raw ECDSA to produce (r, s0).</description></item>
    ///   <item><description>Compute final s: s = P * s0 mod q.</description></item>
    /// </list>
    /// <para>
    /// This ensures (r, s) is a valid ECDSA signature under public key Y = u*P*G
    /// without the NCH ever seeing P directly (Proposition 3.1).
    /// </para>
    /// </remarks>
    /// <param name="messageHash">The SHA-256 hash of the message to sign.</param>
    /// <param name="nchPrivateKey">The NCH-bound private key u.</param>
    /// <param name="pinKey">The PIN-derived key P.</param>
    /// <returns>The ECDSA signature (r, s).</returns>
    public static EcdsaSignature Sign(ReadOnlySpan<byte> messageHash, BigInteger nchPrivateKey, BigInteger pinKey)
    {
        BigInteger e = EcMath.HashToInteger(messageHash);
        BigInteger pinInverse = EcMath.ModInverse(pinKey);
        BigInteger adjustedHash = e * pinInverse % EcMath.Q;

        (BigInteger r, BigInteger s0) = RawEcdsaSign(adjustedHash, nchPrivateKey);
        BigInteger s = pinKey * s0 % EcMath.Q;

        return new EcdsaSignature(r, s);
    }


    /// <summary>
    /// Generates an attestation key pair from an HSM base public key and a wallet key-share
    /// (Algorithm 11, Option I of the SECDSA split key architecture, Section 4).
    /// </summary>
    /// <remarks>
    /// <para>
    /// In the split key architecture the wallet provider's HSM manages a single base
    /// attestation key pair per user: base private key bU (non-exportable, HSM-bound)
    /// and base public key B = bU*G. All actual attestation signing keys are derived
    /// outside the HSM, eliminating the per-attestation key management overhead.
    /// </para>
    /// <para>
    /// Option I (wallet-managed key-share): the wallet generates a random key-share
    /// scalar zU and forms the attestation public key as Y = zU * B. The combined
    /// private key is zU * bU, so neither the wallet nor the HSM alone can sign.
    /// The wallet holds zU; the HSM holds bU. Both are required for every signature.
    /// </para>
    /// <para>
    /// The PIN key P from the standard SECDSA construction is not used here. The
    /// PIN factor can be layered on top by replacing zU with P*zU in the same way
    /// that Algorithm 2 layers P over the NCH key u.
    /// </para>
    /// </remarks>
    /// <param name="basePublicKey">The HSM base public key B = bU*G.</param>
    /// <param name="keyShare">The wallet key-share scalar zU.</param>
    /// <returns>The attestation public key Y = zU*B and the key-share scalar.</returns>
    public static (EcPoint AttestationPublicKey, BigInteger KeyShare) GenerateKeyPairFromBaseKey(
        EcPoint basePublicKey,
        BigInteger keyShare)
    {
        ArgumentNullException.ThrowIfNull(basePublicKey);
        EcPoint attestationPublicKey = EcMath.Multiply(basePublicKey, keyShare);
        return (attestationPublicKey, keyShare);
    }

    /// <summary>
    /// Signs a message hash using the split key architecture (Algorithm 11, Option I).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Signing proceeds in three steps mirroring Algorithm 2:
    /// </para>
    /// <list type="bullet">
    ///   <item><description>Wallet computes e' = e * zU^(-1) mod q (adjusts hash with key-share).</description></item>
    ///   <item><description>HSM raw-signs e' with base private key bU, producing (r, s0). In production this is
    ///   a call to the PKCS#11 HSM or TPM; here the <paramref name="nchBasePrivateKey"/> scalar stands in.</description></item>
    ///   <item><description>Wallet computes final s = zU * s0 mod q (re-scales with key-share).</description></item>
    /// </list>
    /// <para>
    /// The result (r, s) is a valid ECDSA signature under attestation public key Y = zU*bU*G.
    /// This is structurally identical to Algorithm 2 with zU playing the role of P and bU
    /// playing the role of u. The same verification path (Algorithms 14 and 15) applies.
    /// </para>
    /// </remarks>
    /// <param name="messageHash">The SHA-256 hash of the message to sign.</param>
    /// <param name="nchBasePrivateKey">The HSM base private key bU. In production this is an HSM key handle.</param>
    /// <param name="keyShare">The wallet key-share scalar zU.</param>
    /// <returns>The ECDSA signature (r, s).</returns>
    public static EcdsaSignature SignWithKeyShare(
        ReadOnlySpan<byte> messageHash,
        BigInteger nchBasePrivateKey,
        BigInteger keyShare)
    {
        BigInteger e = EcMath.HashToInteger(messageHash);
        BigInteger keyShareInverse = EcMath.ModInverse(keyShare);
        BigInteger adjustedHash = e * keyShareInverse % EcMath.Q;

        (BigInteger r, BigInteger s0) = RawEcdsaSign(adjustedHash, nchBasePrivateKey);
        BigInteger s = keyShare * s0 % EcMath.Q;

        return new EcdsaSignature(r, s);
    }


    /// <param name="messageHash">The SHA-256 hash of the signed message.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <param name="publicKey">The SECDSA public key Y = P*u*G.</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    public static bool Verify(ReadOnlySpan<byte> messageHash, EcdsaSignature signature, EcPoint publicKey)
    {
        ArgumentNullException.ThrowIfNull(signature);
        BigInteger e = EcMath.HashToInteger(messageHash);
        return RawEcdsaVerify(e, signature.R, signature.S, publicKey);
    }

    /// <summary>
    /// Converts a standard ECDSA signature to full format by recovering the nonce point R.
    /// </summary>
    /// <remarks>
    /// Full format is required for Algorithm 3 (blind signing): computing
    /// G'' = s^(-1)*G' requires the full nonce point R.
    /// </remarks>
    /// <param name="signature">The (r, s) signature to convert.</param>
    /// <param name="messageHash">The message hash that was signed.</param>
    /// <param name="publicKey">The SECDSA public key, used to select the correct recovery candidate.</param>
    /// <returns>The full-format signature containing the recovered R point.</returns>
    public static FullEcdsaSignature ToFullFormat(
        EcdsaSignature signature,
        ReadOnlySpan<byte> messageHash,
        EcPoint publicKey)
    {
        ArgumentNullException.ThrowIfNull(signature);
        BigInteger e = EcMath.HashToInteger(messageHash);
        BigInteger sInv = EcMath.ModInverse(signature.S);

        EcPoint u1G = EcMath.BasePointMultiply(e * sInv % EcMath.Q);
        EcPoint u2Y = EcMath.Multiply(publicKey, signature.R * sInv % EcMath.Q);
        EcPoint rPoint = EcMath.Add(u1G, u2Y);

        return new FullEcdsaSignature(rPoint, signature.S);
    }

    /// <summary>
    /// Verifies a signature in full format (Algorithm 15).
    /// </summary>
    /// <param name="messageHash">The SHA-256 hash of the signed message.</param>
    /// <param name="signature">The full-format signature.</param>
    /// <param name="publicKey">The SECDSA public key.</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    public static bool VerifyFull(ReadOnlySpan<byte> messageHash, FullEcdsaSignature signature, EcPoint publicKey)
    {
        ArgumentNullException.ThrowIfNull(signature);
        BigInteger r = signature.RPoint.X % EcMath.Q;
        BigInteger e = EcMath.HashToInteger(messageHash);

        return RawEcdsaVerify(e, r, signature.S, publicKey);
    }


    /// <summary>
    /// Performs raw ECDSA signing of a pre-computed integer hash with a private key scalar.
    /// </summary>
    /// <remarks>
    /// In Phase 2 this is replaced by a delegate backed by TPM2_Sign, where the
    /// adjusted hash is passed directly and the NCH key handle is captured by the
    /// delegate implementation.
    /// </remarks>
    /// <param name="adjustedHash">The pre-adjusted hash integer e' = P^(-1)*e mod q.</param>
    /// <param name="nchPrivateKey">The NCH-bound private key u.</param>
    /// <returns>The raw ECDSA signature scalars (r, s0).</returns>
    private static (BigInteger r, BigInteger s0) RawEcdsaSign(BigInteger adjustedHash, BigInteger nchPrivateKey)
    {
        BigInteger r = BigInteger.Zero;
        BigInteger s0 = BigInteger.Zero;

        do
        {
            BigInteger k = EcMath.RandomScalar();
            EcPoint kG = EcMath.BasePointMultiply(k);
            r = kG.X % EcMath.Q;

            if(r.IsZero)
            {
                continue;
            }

            BigInteger kInv = EcMath.ModInverse(k);
            s0 = kInv * (adjustedHash + r * nchPrivateKey) % EcMath.Q;
        }
        while(s0.IsZero);

        return (r, s0);
    }


    private static bool RawEcdsaVerify(BigInteger e, BigInteger r, BigInteger s, EcPoint publicKey)
    {
        if(r <= BigInteger.Zero || r >= EcMath.Q)
        {
            return false;
        }

        if(s <= BigInteger.Zero || s >= EcMath.Q)
        {
            return false;
        }

        BigInteger sInv = EcMath.ModInverse(s);
        BigInteger u1 = e * sInv % EcMath.Q;
        BigInteger u2 = r * sInv % EcMath.Q;

        EcPoint point = EcMath.Add(EcMath.BasePointMultiply(u1), EcMath.Multiply(publicKey, u2));
        if(point.IsInfinity)
        {
            return false;
        }

        return point.X % EcMath.Q == r;
    }
}
