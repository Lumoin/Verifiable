using System.Buffers;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// Delegate for ECDH-style key agreement and AEAD decryption.
/// </summary>
/// <remarks>
/// <para>
/// Used for algorithms such as ECDH-ES where both parties contribute key material
/// through elliptic curve Diffie-Hellman. The shared secret is derived from the
/// recipient's private key and the sender's ephemeral public key coordinates, then
/// used to derive a content encryption key for AEAD decryption.
/// </para>
/// <para>
/// Parameters are protocol-neutral types from <c>Verifiable.Cryptography.Aead</c>.
/// The caller — typically an extension method in a higher-level layer — unpacks the
/// relevant components from whatever protocol structure carried them (JWE, HPKE, etc.)
/// and passes them individually. This delegate has no knowledge of JWE, JOSE, or any
/// serialization format.
/// </para>
/// <para>
/// AES-GCM authentication tag verification is intrinsic to decryption. If the tag does
/// not match, the delegate throws — <see cref="DecryptedContent"/> is never returned for
/// a tampered token.
/// </para>
/// </remarks>
/// <param name="privateKeyBytes">
/// The recipient's private key bytes, unwrapped from <see cref="PrivateKeyMemory"/>.
/// The bytes must not be stored or referenced after the delegate returns.
/// </param>
/// <param name="iv">The initialization vector nonce for the AEAD operation.</param>
/// <param name="ciphertext">The encrypted bytes to decrypt.</param>
/// <param name="authTag">The authentication tag to verify before decryption.</param>
/// <param name="aad">The additional authenticated data.</param>
/// <param name="epkX">
/// The sender's ephemeral public key X coordinate. The <see cref="Tag"/> on this
/// <see cref="PublicKeyMemory"/> identifies the curve via <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/>
/// and the encoding via <see cref="Verifiable.Cryptography.Context.EncodingScheme"/>.
/// </param>
/// <param name="epkY">The sender's ephemeral public key Y coordinate.</param>
/// <param name="encryptionAlgorithm">
/// The content encryption algorithm identifier, e.g. <c>A128GCM</c>. Used as the
/// AlgorithmID input to the Concat KDF.
/// </param>
/// <param name="pool">Memory pool for allocating the decrypted content.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The decrypted plaintext as <see cref="DecryptedContent"/>. The caller owns the
/// returned instance and must dispose it.
/// </returns>
public delegate ValueTask<DecryptedContent> KeyAgreementDelegate(
    ReadOnlyMemory<byte> privateKeyBytes,
    Nonce iv,
    Ciphertext ciphertext,
    AuthenticationTag authTag,
    AdditionalData aad,
    PublicKeyMemory epkX,
    PublicKeyMemory epkY,
    string encryptionAlgorithm,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);
