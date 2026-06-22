using System.Buffers;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// Delegate for the decrypt-side ECDH One-Pass Unified Model (ECDH-1PU) key agreement
/// step as defined in
/// <see href="https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04">draft-madden-jose-ecdh-1pu-04</see>.
/// </summary>
/// <remarks>
/// <para>
/// Performs two Diffie-Hellman computations and concatenates the results: Ze from the
/// recipient's static private key against the sender's ephemeral public key, and Zs
/// from the recipient's static private key against the sender's static public key.
/// The returned shared secret is Z = Ze || Zs per NIST SP 800-56A §6.2.1.2 — byte
/// identical to the value the sender computed on the encrypt side.
/// </para>
/// <para>
/// The sender's static public key is resolved by the caller from the <c>skid</c> or
/// <c>apu</c> JWE header through whatever key resolution the protocol defines — for
/// DIDComm v2 the sender's DID document <c>keyAgreement</c> section. All three keys
/// MUST be on the same curve.
/// </para>
/// <para>
/// This delegate is async because the key agreement step may be performed by a remote
/// HSM, TPM, or other hardware boundary.
/// </para>
/// </remarks>
/// <param name="recipientPrivateKeyBytes">
/// The recipient's static private key bytes, unwrapped from <see cref="PrivateKeyMemory"/>.
/// The bytes must not be stored or referenced after the delegate returns.
/// </param>
/// <param name="ephemeralPublicKey">
/// The sender's ephemeral public key from the JWE <c>epk</c> header. The
/// <see cref="Tag"/> identifies the curve and encoding.
/// </param>
/// <param name="senderPublicKey">The sender's static public key.</param>
/// <param name="pool">Memory pool for allocating the shared secret.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The shared secret Z = Ze || Zs. The caller must zero and dispose it as soon as the
/// key has been derived.
/// </returns>
public delegate ValueTask<SharedSecret> AuthenticatedKeyAgreementDecryptDelegate(
    ReadOnlyMemory<byte> recipientPrivateKeyBytes,
    PublicKeyMemory ephemeralPublicKey,
    PublicKeyMemory senderPublicKey,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);
