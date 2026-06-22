using System.Buffers;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// Delegate for the encrypt-side ECDH-ES key agreement step against a single recipient
/// using a <em>caller-held</em> ephemeral private key, for multi-recipient JWE
/// (anoncrypt) where one ephemeral key pair is shared across every recipient.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why this exists separately from <see cref="KeyAgreementEncryptDelegate"/>.</strong>
/// <see cref="KeyAgreementEncryptDelegate"/> generates a fresh ephemeral key pair
/// <em>inside</em> the call and returns the resulting <c>epk</c> alongside the shared
/// secret. That is correct for the single-recipient JWE Compact Serialization, but
/// produces a different <c>epk</c> per call. RFC 7516 §7.2 General JSON Serialization
/// shares one JWE Protected Header — and therefore one <c>epk</c> — across all
/// recipients (draft-madden-jose-ecdh-1pu-04 §2.1 likewise reuses the ephemeral key for
/// multiple recipients on the same curve). The orchestrator must therefore generate the
/// ephemeral key pair <em>once</em>, place its public part in the protected header, and
/// perform the per-recipient agreement with that one shared ephemeral key. This delegate
/// is that per-recipient step: it takes the caller-held ephemeral private key bytes and
/// returns only the shared secret — the <c>epk</c> is held by the orchestrator, not
/// returned here.
/// </para>
/// <para>
/// Keeping the per-recipient agreement as its own unit (rather than one call that agrees
/// to N recipients) mirrors the existing one-recipient idiom exactly and keeps each
/// agreement at a natural hardware-boundary granularity — different recipient keys may
/// live behind different HSM/TPM boundaries.
/// </para>
/// <para>
/// This delegate is async because the key agreement step may be performed by a remote
/// HSM, TPM, or other hardware boundary.
/// </para>
/// </remarks>
/// <param name="recipientPublicKey">
/// The recipient's static public key. The <see cref="Tag"/> identifies the curve and encoding.
/// </param>
/// <param name="ephemeralPrivateKeyBytes">
/// The shared ephemeral private key bytes, unwrapped from <see cref="PrivateKeyMemory"/>.
/// The same ephemeral key is passed for every recipient on the curve. The bytes must not
/// be stored or referenced after the delegate returns.
/// </param>
/// <param name="pool">Memory pool for allocating the shared secret.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The shared secret Z = Ze (the single ECDH-ES agreement between the ephemeral private
/// key and the recipient's static public key). The caller must zero and dispose it as
/// soon as the key encryption key has been derived.
/// </returns>
public delegate ValueTask<SharedSecret> MultiRecipientKeyAgreementEncryptDelegate(
    PublicKeyMemory recipientPublicKey,
    ReadOnlyMemory<byte> ephemeralPrivateKeyBytes,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);
