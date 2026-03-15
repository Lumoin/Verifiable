using System;
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
    /// Verifies a SECDSA signature using standard ECDSA verification (Algorithm 14).
    /// </summary>
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