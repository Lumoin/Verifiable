using System.Buffers;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// Delegate for AEAD symmetric decryption.
/// </summary>
/// <remarks>
/// <para>
/// Performs authenticated decryption using a pre-derived content encryption key (CEK).
/// Authentication tag verification is intrinsic — if the tag does not match, the
/// delegate throws <see cref="System.Security.Cryptography.CryptographicException"/>
/// and <see cref="DecryptedContent"/> is never returned.
/// </para>
/// <para>
/// This delegate is async because the decryption step may be performed by a remote
/// HSM or other hardware boundary.
/// </para>
/// </remarks>
/// <param name="ciphertext">The encrypted bytes to decrypt.</param>
/// <param name="cek">
/// The content encryption key derived from ECDH key agreement and KDF.
/// Must be disposed by the caller immediately after this delegate returns.
/// </param>
/// <param name="iv">The initialization vector nonce.</param>
/// <param name="tag">The authentication tag to verify before decryption.</param>
/// <param name="aad">The additional authenticated data to verify.</param>
/// <param name="pool">Memory pool for allocating the decrypted plaintext.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The decrypted plaintext as <see cref="DecryptedContent"/>. The caller owns and
/// must dispose it.
/// </returns>
/// <exception cref="System.Security.Cryptography.CryptographicException">
/// Thrown when authentication tag verification fails.
/// </exception>
public delegate ValueTask<DecryptedContent> AeadDecryptDelegate(
    Ciphertext ciphertext,
    ContentEncryptionKey cek,
    Nonce iv,
    AuthenticationTag tag,
    AdditionalData aad,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);
