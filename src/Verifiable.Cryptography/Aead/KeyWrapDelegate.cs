using System.Buffers;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// Delegate for wrapping a content encryption key under a key encryption key per
/// <see href="https://www.rfc-editor.org/rfc/rfc3394">RFC 3394</see> AES Key Wrap.
/// </summary>
/// <remarks>
/// <para>
/// Used by the JWE Key Agreement with Key Wrapping mode — the <c>ECDH-ES+A256KW</c>
/// and <c>ECDH-1PU+A256KW</c> key management algorithms. The key encryption key is
/// derived via Concat KDF from an ECDH shared secret; the content encryption key is
/// randomly generated and protected by this operation for transport in the JWE
/// encrypted key slot.
/// </para>
/// <para>
/// AES Key Wrap is deterministic: the same key encryption key and content encryption
/// key always produce the same wrapped bytes. The integrity check embedded in the
/// algorithm is verified on unwrap by <see cref="KeyUnwrapDelegate"/>.
/// </para>
/// <para>
/// This delegate is async because the wrap operation may be performed by a remote
/// HSM or other hardware boundary.
/// </para>
/// </remarks>
/// <param name="keyEncryptionKey">
/// The key encryption key. Not disposed by this delegate — the caller retains
/// ownership and must dispose it after the call.
/// </param>
/// <param name="contentEncryptionKey">
/// The content encryption key to wrap. Its length must be a multiple of 8 bytes and
/// at least 16 bytes. Not disposed by this delegate — the caller retains ownership.
/// </param>
/// <param name="pool">Memory pool for allocating the wrapped key.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The wrapped key as <see cref="Ciphertext"/>, 8 bytes longer than the input key.
/// The caller owns and must dispose it.
/// </returns>
public delegate ValueTask<Ciphertext> KeyWrapDelegate(
    SymmetricKeyMemory keyEncryptionKey,
    SymmetricKeyMemory contentEncryptionKey,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);
