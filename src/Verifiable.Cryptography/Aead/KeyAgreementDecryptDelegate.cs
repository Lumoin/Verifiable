using System.Buffers;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// Delegate for the decrypt-side ECDH key agreement step.
/// </summary>
/// <remarks>
/// <para>
/// Performs elliptic curve Diffie-Hellman key agreement on the decrypt side:
/// computes the shared secret Z by multiplying the recipient's private key against
/// the sender's ephemeral public key.
/// </para>
/// <para>
/// This delegate covers only the key agreement step. Key derivation and symmetric
/// decryption are separate operations performed by <see cref="KeyDerivationDelegate"/>
/// and <see cref="AeadDecryptDelegate"/> respectively. This separation allows the TPM
/// to perform ECDH via TPM2_ECDH_ZGen while KDF and AES-GCM run in software or in
/// a separate hardware component.
/// </para>
/// <para>
/// The private key bytes are unwrapped from <see cref="PrivateKeyMemory"/> by the
/// caller via <see cref="PrivateKeyMemory.WithKeyBytesAsync{TArg,TResult}"/> and must
/// not be stored or referenced after the delegate returns.
/// </para>
/// <para>
/// This delegate is async because the key agreement step may be performed by a remote
/// HSM, TPM, or other hardware boundary.
/// </para>
/// </remarks>
/// <param name="privateKeyBytes">
/// The recipient's private key bytes, unwrapped from <see cref="PrivateKeyMemory"/>.
/// Must not be stored or referenced after the delegate returns.
/// </param>
/// <param name="epk">
/// The sender's ephemeral public key in uncompressed encoding: <c>0x04 || X || Y</c>.
/// The TPM backend extracts X and Y internally for <c>TPM2_ECDH_ZGen</c>.
/// </param>
/// <param name="pool">Memory pool for allocating the shared secret.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The shared secret Z. The caller must zero it and dispose as soon as the CEK has
/// been derived.
/// </returns>
public delegate ValueTask<SharedSecret> KeyAgreementDecryptDelegate(
    ReadOnlyMemory<byte> privateKeyBytes,
    PublicKeyMemory epk,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);
