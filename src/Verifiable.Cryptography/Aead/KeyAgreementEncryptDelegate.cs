using System.Buffers;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// Delegate for the encrypt-side ECDH key agreement step.
/// </summary>
/// <remarks>
/// <para>
/// Performs elliptic curve Diffie-Hellman key agreement on the encrypt side:
/// generates an ephemeral key pair, computes the shared secret Z by multiplying
/// the ephemeral private key against the recipient's public key, and returns Z
/// together with the ephemeral public key coordinates.
/// </para>
/// <para>
/// This delegate covers only the key agreement step. Key derivation and symmetric
/// encryption are separate operations performed by <see cref="KeyDerivationDelegate"/>
/// and <see cref="AeadEncryptDelegate"/> respectively. This separation allows each
/// step to be backed by a different hardware boundary — for example ECDH in a TPM
/// via TPM2_ECDH_KeyGen, KDF in software, and AES-GCM in an HSM.
/// </para>
/// <para>
/// This delegate is async because the key agreement step may be performed by a remote
/// HSM, TPM, or other hardware boundary.
/// </para>
/// </remarks>
/// <param name="recipientPublicKey">
/// The recipient's public key. The <see cref="Tag"/> identifies the curve and encoding.
/// </param>
/// <param name="pool">Memory pool for allocating the shared secret and EPK coordinates.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// An <see cref="EphemeralKeyAgreementResult"/> holding the shared secret Z and the
/// ephemeral public key coordinates. The caller must zero the shared secret and dispose
/// as soon as the CEK has been derived.
/// </returns>
public delegate ValueTask<EphemeralKeyAgreementResult> KeyAgreementEncryptDelegate(
    PublicKeyMemory recipientPublicKey,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);
