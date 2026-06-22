using System.Buffers;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// Delegate for unwrapping a content encryption key from its wrapped form per
/// <see href="https://www.rfc-editor.org/rfc/rfc3394">RFC 3394</see> AES Key Wrap.
/// </summary>
/// <remarks>
/// <para>
/// The inverse of <see cref="KeyWrapDelegate"/>. Integrity verification is intrinsic:
/// the algorithm recovers the RFC 3394 §2.2.3 initial value alongside the key data, and
/// a mismatch means the wrapped key or the key encryption key is wrong. In that case
/// the delegate throws <see cref="System.Security.Cryptography.CryptographicException"/>
/// and no key material is returned.
/// </para>
/// <para>
/// This delegate is async because the unwrap operation may be performed by a remote
/// HSM or other hardware boundary.
/// </para>
/// </remarks>
/// <param name="keyEncryptionKey">
/// The key encryption key. Not disposed by this delegate — the caller retains
/// ownership and must dispose it after the call.
/// </param>
/// <param name="wrappedKey">
/// The wrapped key bytes from the JWE encrypted key slot. Public ciphertext;
/// its length must be a multiple of 8 bytes and at least 24 bytes.
/// </param>
/// <param name="pool">Memory pool for allocating the unwrapped key.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The unwrapped content encryption key, 8 bytes shorter than the wrapped input.
/// The caller owns and must dispose it — disposal zeroes the underlying memory.
/// </returns>
/// <exception cref="System.Security.Cryptography.CryptographicException">
/// Thrown when the RFC 3394 integrity check fails.
/// </exception>
public delegate ValueTask<SymmetricKeyMemory> KeyUnwrapDelegate(
    SymmetricKeyMemory keyEncryptionKey,
    ReadOnlyMemory<byte> wrappedKey,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);
