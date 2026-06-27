using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

namespace Verifiable.Apdu.Pace;

/// <summary>
/// Type-latched convenience over the byte-level PACE composition primitives on
/// <see cref="PaceGenericMapping"/>. The primitives take <see cref="ReadOnlyMemory{T}"/> so they can serve
/// any byte source (a freshly computed point, a value parsed off the wire, a worked-example vector); these
/// extensions add the ergonomic surface for callers that already hold the pooled, tagged semantic carriers,
/// performing the single borrow into the byte layer in one place rather than at every call site.
/// </summary>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer does not recognize C# 13 extension type syntax.")]
[SuppressMessage("Naming", "CA1708:Identifiers should differ by more than case", Justification = "Analyzer does not recognize C# 13 extension type syntax.")]
public static class PaceCompositionExtensions
{
    extension(EncodedEcPoint peerPublicKey)
    {
        /// <summary>
        /// Agrees the PACE shared secret with this peer public key — the X-coordinate of
        /// <c>privateKey · peerPublicKey</c>.
        /// </summary>
        /// <param name="privateKey">This party's key-agreement ephemeral private key.</param>
        /// <param name="curve">A tag carrying the curve <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/>.</param>
        /// <param name="pool">The memory pool.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The shared secret K (the X-coordinate) as a <see cref="SharedSecret"/>. The caller disposes it.</returns>
        public ValueTask<SharedSecret> AgreeSharedSecretAsync(
            ReadOnlyMemory<byte> privateKey,
            Tag curve,
            BaseMemoryPool pool,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(curve);
            ArgumentNullException.ThrowIfNull(pool);

            return PaceGenericMapping.AgreeSharedSecretAsync(privateKey, peerPublicKey.AsReadOnlyMemory(), curve, pool, cancellationToken);
        }
    }


    extension(SymmetricKeyMemory macKey)
    {
        /// <summary>
        /// Computes the PACE mutual-authentication token over this MAC key, the peer's ephemeral public key,
        /// and the protocol OID (a truncated AES-CMAC).
        /// </summary>
        /// <param name="peerEphemeralPublicKey">The other party's ephemeral public key.</param>
        /// <param name="objectIdentifier">The PACE protocol OID value bytes (without the outer 0x06 tag).</param>
        /// <param name="pool">The memory pool.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The 8-byte authentication token as a <see cref="MacValue"/>. The caller disposes it.</returns>
        public ValueTask<MacValue> ComputeAuthenticationTokenAsync(
            EncodedEcPoint peerEphemeralPublicKey,
            ReadOnlyMemory<byte> objectIdentifier,
            BaseMemoryPool pool,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(peerEphemeralPublicKey);
            ArgumentNullException.ThrowIfNull(pool);

            return PaceGenericMapping.ComputeAuthenticationTokenAsync(macKey, peerEphemeralPublicKey.AsReadOnlyMemory(), objectIdentifier, pool, cancellationToken);
        }
    }
}
