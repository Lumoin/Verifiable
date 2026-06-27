using System;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// The RSA card side of ICAO Doc 9303 Part 11 §6.1 Active Authentication — the ISO/IEC 9796-2 counterpart of
/// <see cref="ActiveAuthenticationCardResponder"/>. Given the chip's RSA Active Authentication private key
/// (matching the EF.DG15 public key) and the terminal's INTERNAL AUTHENTICATE challenge, it signs the
/// challenge with message recovery so the terminal can prove the chip holds the matching private key.
/// </summary>
/// <remarks>
/// <para>
/// This responder owns no cryptography of its own: it resolves the registered ISO/IEC 9796-2 signing
/// function and signs the challenge with it. That function treats the challenge as the non-recovered message
/// part M2 and produces the random recoverable part M1 itself, returning the signature the terminal's
/// resolved verification function recovers M1 from — so the two interoperate only when the chip holds the
/// private key matching its announced DG15 public key. Elliptic-curve Active Authentication is the sibling
/// <see cref="ActiveAuthenticationCardResponder"/>.
/// </para>
/// </remarks>
public static class RsaActiveAuthenticationCardResponder
{
    /// <summary>
    /// Signs an INTERNAL AUTHENTICATE challenge with the chip's RSA Active Authentication private key using
    /// ISO/IEC 9796-2 Digital Signature scheme 1.
    /// </summary>
    /// <param name="activeAuthenticationPrivateKey">The chip's RSA Active Authentication private key (PKCS#1 DER <c>RSAPrivateKey</c>). Borrowed.</param>
    /// <param name="challenge">The terminal's challenge RND.IFD to sign (the non-recovered message part M2).</param>
    /// <param name="pool">The memory pool for the signature buffer.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The chip's signature over the challenge. The caller owns and disposes it.</returns>
    /// <exception cref="InvalidOperationException">Thrown when no ISO/IEC 9796-2 signing function is registered.</exception>
    public static async ValueTask<Signature> SignChallengeAsync(
        ReadOnlyMemory<byte> activeAuthenticationPrivateKey,
        ReadOnlyMemory<byte> challenge,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        RecoverableSigningDelegate sign = RecoverableSignatureFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(CryptoAlgorithm.RsaIso9796d2, Purpose.Signing);

        return await sign(activeAuthenticationPrivateKey, challenge, pool, null, cancellationToken).ConfigureAwait(false);
    }
}
