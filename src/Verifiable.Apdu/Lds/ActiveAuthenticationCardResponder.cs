using System;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// The card side of ICAO Doc 9303 Part 11 §6.1 Active Authentication — the inverse of
/// <see cref="ActiveAuthentication"/>. Given the chip's Active Authentication private key (matching the
/// EF.DG15 public key) and the terminal's INTERNAL AUTHENTICATE challenge, it signs the challenge so the
/// terminal can prove the chip holds the matching private key (anti-cloning).
/// </summary>
/// <remarks>
/// <para>
/// This responder owns no cryptography of its own: it resolves the registered ECDSA signing function for
/// the curve the chip's DG15 key lies on and signs the challenge with it. The signing function hashes the
/// challenge with the curve-appropriate hash internally (SHA-256 for P-256, SHA-224 for brainpoolP224r1)
/// and returns the signature in IEEE P1363 (<c>r ‖ s</c>) encoding — the same encoding the terminal's
/// resolved verification function expects, so the two interoperate only when the chip holds the private
/// key matching its announced DG15 public key. RSA/ISO-9796-2 Active Authentication is a separate slice.
/// </para>
/// </remarks>
public static class ActiveAuthenticationCardResponder
{
    /// <summary>
    /// Signs an INTERNAL AUTHENTICATE challenge with the chip's Active Authentication private key.
    /// </summary>
    /// <param name="activeAuthenticationPrivateKey">The chip's Active Authentication private key (unsigned big-endian scalar on <paramref name="curve"/>). Borrowed.</param>
    /// <param name="curve">A tag carrying the curve <see cref="CryptoAlgorithm"/>, from the chip's EF.DG15 public key.</param>
    /// <param name="challenge">The terminal's challenge RND.IFD to sign.</param>
    /// <param name="pool">The memory pool for the signature buffer.</param>
    /// <param name="eventSink">
    /// Receives the <see cref="SignatureProducedEvent"/> the resolved <see cref="SigningDelegate"/>
    /// constructs, or <see langword="null"/> to route it to <see cref="CryptographicKeyEvents.DefaultSink"/>.
    /// This responder resolves and invokes the registry delegate directly rather than through a bound
    /// <see cref="PrivateKey"/> (there is no key object here, only raw key bytes), so a
    /// <see cref="CryptoEventSink"/> is this call site's route — see <see cref="CryptoEventSink"/>.
    /// </param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The chip's signature over the challenge. The caller owns and disposes it.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the curve tag carries no algorithm, or no signing function is registered for it.</exception>
    public static async ValueTask<Signature> SignChallengeAsync(
        ReadOnlyMemory<byte> activeAuthenticationPrivateKey,
        Tag curve,
        ReadOnlyMemory<byte> challenge,
        BaseMemoryPool pool,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(curve);
        ArgumentNullException.ThrowIfNull(pool);

        if(!curve.TryGet(out CryptoAlgorithm algorithm))
        {
            throw new InvalidOperationException("The Active Authentication key tag must carry a curve algorithm.");
        }

        SigningDelegate sign = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, Purpose.Signing);

        (Signature signature, CryptoEvent? evt) = await sign(activeAuthenticationPrivateKey, challenge, pool, null, cancellationToken).ConfigureAwait(false);

        if(evt is not null)
        {
            (eventSink ?? CryptographicKeyEvents.DefaultSink)(evt);
        }

        return signature;
    }
}
