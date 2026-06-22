using System.Buffers;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// Delegate for the encrypt-side ECDH One-Pass Unified Model (ECDH-1PU) key agreement
/// step as defined in
/// <see href="https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04">draft-madden-jose-ecdh-1pu-04</see>.
/// </summary>
/// <remarks>
/// <para>
/// Performs two Diffie-Hellman computations and concatenates the results: Ze from a
/// freshly generated ephemeral private key against the recipient's static public key,
/// and Zs from the sender's static private key against the recipient's static public
/// key. The returned shared secret is Z = Ze || Zs per NIST SP 800-56A §6.2.1.2.
/// </para>
/// <para>
/// The sender's static key contribution is what authenticates the sender to the
/// recipient — this is the authcrypt primitive of DIDComm v2. Both keys MUST be on
/// the same curve; the curve is identified by the <see cref="Tag"/> on
/// <paramref name="recipientPublicKey"/>.
/// </para>
/// <para>
/// This delegate covers only the key agreement step. Key derivation is performed by
/// <see cref="AuthenticatedKeyDerivationDelegate"/>, which feeds the JWE
/// Authentication Tag into the KDF in Key Agreement with Key Wrapping mode.
/// </para>
/// <para>
/// This delegate is async because the key agreement step may be performed by a remote
/// HSM, TPM, or other hardware boundary.
/// </para>
/// </remarks>
/// <param name="recipientPublicKey">
/// The recipient's static public key. The <see cref="Tag"/> identifies the curve and encoding.
/// </param>
/// <param name="senderPrivateKeyBytes">
/// The sender's static private key bytes, unwrapped from <see cref="PrivateKeyMemory"/>.
/// The bytes must not be stored or referenced after the delegate returns.
/// </param>
/// <param name="pool">Memory pool for allocating the shared secret and EPK coordinates.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// An <see cref="EphemeralKeyAgreementResult"/> holding Z = Ze || Zs and the ephemeral
/// public key. The caller must zero the shared secret and dispose as soon as the key
/// has been derived.
/// </returns>
public delegate ValueTask<EphemeralKeyAgreementResult> AuthenticatedKeyAgreementEncryptDelegate(
    PublicKeyMemory recipientPublicKey,
    ReadOnlyMemory<byte> senderPrivateKeyBytes,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);
