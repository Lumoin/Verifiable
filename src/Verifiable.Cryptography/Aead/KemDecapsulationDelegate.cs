using System.Buffers;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// Delegate for KEM (Key Encapsulation Mechanism) decapsulation.
/// </summary>
/// <remarks>
/// <para>
/// Used for post-quantum algorithms such as ML-KEM (NIST FIPS 203) where the sender
/// encapsulates a shared secret to the recipient's public key and transmits the
/// ciphertext. The recipient decapsulates using their private key to recover the
/// shared secret, which is then fed into a key derivation function to produce the
/// content encryption key.
/// </para>
/// <para>
/// The returned <see cref="SharedSecret"/> is transient key material. The caller must
/// derive the content encryption key and dispose the secret immediately — it must never
/// be persisted or transmitted.
/// </para>
/// </remarks>
/// <param name="privateKeyBytes">
/// The recipient's KEM private key bytes, unwrapped from <see cref="PrivateKeyMemory"/>.
/// The bytes must not be stored or referenced after the delegate returns.
/// </param>
/// <param name="encapsulatedKey">
/// The ciphertext produced by the sender during encapsulation. In compact JWE
/// serialization this arrives in the <c>encrypted_key</c> slot (second segment).
/// </param>
/// <param name="pool">Memory pool for allocating the shared secret.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The recovered shared secret. The caller owns the returned instance and must dispose
/// it immediately after deriving the content encryption key.
/// </returns>
public delegate ValueTask<SharedSecret> KemDecapsulationDelegate(
    ReadOnlyMemory<byte> privateKeyBytes,
    ReadOnlyMemory<byte> encapsulatedKey,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);
