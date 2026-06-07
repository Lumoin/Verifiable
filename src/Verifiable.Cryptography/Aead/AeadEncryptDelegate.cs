using System.Buffers;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// Delegate for AEAD symmetric encryption.
/// </summary>
/// <remarks>
/// <para>
/// Performs authenticated encryption of plaintext using a pre-derived content
/// encryption key (CEK). The AAD binds the ciphertext to the JWE protected header,
/// preventing header substitution attacks.
/// </para>
/// <para>
/// This delegate is async because the encryption step may be performed by a remote
/// HSM or other hardware boundary — for example when the CEK is sent to an HSM
/// rather than used in software.
/// </para>
/// </remarks>
/// <param name="plaintext">The plaintext bytes to encrypt.</param>
/// <param name="key">
/// The symmetric key to encrypt under. May be the inner key from
/// <see cref="ContentEncryptionKey.UseKey"/> for ephemeral derived CEKs, or a
/// long-lived <see cref="SymmetricKeyMemory"/> for persistent-AEAD scenarios
/// (e.g. an authority's DPP/eIDAS payload encryption key). Must be disposed by
/// the caller immediately after this delegate returns.
/// </param>
/// <param name="aad">
/// The additional authenticated data. For JWE this is the ASCII-encoded Base64url
/// protected header, per RFC 7516 §5.1 step 14.
/// </param>
/// <param name="pool">Memory pool for allocating IV, ciphertext, and authentication tag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// An <see cref="AeadEncryptResult"/> holding the IV, ciphertext, and authentication
/// tag. The caller owns and must dispose it.
/// </returns>
public delegate ValueTask<AeadEncryptResult> AeadEncryptDelegate(
    ReadOnlyMemory<byte> plaintext,
    SymmetricKeyMemory key,
    AdditionalData aad,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);
