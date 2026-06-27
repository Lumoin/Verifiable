using System.Buffers;
using System.Collections.Frozen;

namespace Verifiable.Cryptography;

/// <summary>
/// Encrypts <paramref name="plaintext"/> with a symmetric block cipher in CBC mode under
/// <paramref name="keyBytes"/> and <paramref name="iv"/>, and optionally produces a
/// <see cref="CryptoEvent"/> describing the operation.
/// </summary>
/// <remarks>
/// <para>
/// This delegate performs an <em>unauthenticated</em> CBC transform — no padding is added
/// or removed and no MAC is computed. <paramref name="plaintext"/> MUST already be a whole
/// number of cipher blocks; the caller owns block padding (for ICAO Doc 9303 Secure Messaging
/// this is ISO/IEC 7816-4 / ISO 9797-1 method 2 padding, applied by the Secure Messaging
/// layer) and owns the separate MAC (see <see cref="ComputeBlockCipherMacDelegate"/>). This
/// separation is what eMRTD Secure Messaging requires and what the bundled AEAD / CBC-HMAC
/// paths deliberately do not expose.
/// </para>
/// <para>
/// The block cipher is selected by the <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/>
/// carried in <paramref name="tag"/> (for example two-key Triple-DES for eMRTD BAC, AES for PACE),
/// mirroring how <see cref="ComputeHmacDelegate"/> selects its hash from the tag. The async shape
/// matches the other registry delegates because a backend may delegate to a hardware boundary.
/// </para>
/// </remarks>
/// <param name="plaintext">The block-aligned plaintext to encrypt.</param>
/// <param name="keyBytes">The symmetric key material.</param>
/// <param name="iv">The initialization vector (one cipher block; all zero for eMRTD Secure Messaging).</param>
/// <param name="tag">Metadata carrying the <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/> that selects the cipher.</param>
/// <param name="pool">Memory pool for the ciphertext buffer.</param>
/// <param name="context">Optional context parameters for the operation.</param>
/// <param name="cancellationToken">Cancellation token for async operations.</param>
/// <returns>The <see cref="Aead.Ciphertext"/> (owned by the caller) and an optional event.</returns>
public delegate ValueTask<(Aead.Ciphertext Result, CryptoEvent? Event)> SymmetricEncryptDelegate(
    ReadOnlyMemory<byte> plaintext,
    ReadOnlyMemory<byte> keyBytes,
    ReadOnlyMemory<byte> iv,
    Tag tag,
    MemoryPool<byte> pool,
    FrozenDictionary<string, object>? context = null,
    CancellationToken cancellationToken = default);


/// <summary>
/// Decrypts <paramref name="ciphertext"/> with a symmetric block cipher in CBC mode under
/// <paramref name="keyBytes"/> and <paramref name="iv"/>, and optionally produces a
/// <see cref="CryptoEvent"/> describing the operation.
/// </summary>
/// <remarks>
/// <para>
/// The inverse of <see cref="SymmetricEncryptDelegate"/>: an unauthenticated CBC transform that
/// removes no padding. <paramref name="ciphertext"/> MUST be a whole number of cipher blocks and
/// the returned <see cref="DecryptedContent"/> is the still-padded plaintext; the caller strips
/// padding. The cipher is selected by the
/// <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/> in <paramref name="tag"/>.
/// </para>
/// </remarks>
/// <param name="ciphertext">The block-aligned ciphertext to decrypt.</param>
/// <param name="keyBytes">The symmetric key material.</param>
/// <param name="iv">The initialization vector (one cipher block; all zero for eMRTD Secure Messaging).</param>
/// <param name="tag">Metadata carrying the <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/> that selects the cipher.</param>
/// <param name="pool">Memory pool for the plaintext buffer.</param>
/// <param name="context">Optional context parameters for the operation.</param>
/// <param name="cancellationToken">Cancellation token for async operations.</param>
/// <returns>The <see cref="DecryptedContent"/> (owned by the caller) and an optional event.</returns>
public delegate ValueTask<(DecryptedContent Result, CryptoEvent? Event)> SymmetricDecryptDelegate(
    ReadOnlyMemory<byte> ciphertext,
    ReadOnlyMemory<byte> keyBytes,
    ReadOnlyMemory<byte> iv,
    Tag tag,
    MemoryPool<byte> pool,
    FrozenDictionary<string, object>? context = null,
    CancellationToken cancellationToken = default);
