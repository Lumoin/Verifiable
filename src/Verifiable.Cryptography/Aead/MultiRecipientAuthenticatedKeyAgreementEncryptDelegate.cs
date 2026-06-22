using System.Buffers;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// Delegate for the encrypt-side ECDH-1PU key agreement step against a single recipient
/// using a <em>caller-held</em> ephemeral private key, for multi-recipient JWE
/// (authcrypt) where one ephemeral key pair is shared across every recipient per
/// <see href="https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04#section-2.1">draft-madden-jose-ecdh-1pu-04 §2.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why this exists separately from <see cref="AuthenticatedKeyAgreementEncryptDelegate"/>.</strong>
/// <see cref="AuthenticatedKeyAgreementEncryptDelegate"/> generates a fresh ephemeral
/// key pair <em>inside</em> the call and returns the resulting <c>epk</c> with the shared
/// secret — a different <c>epk</c> per call. The §2.1 multi-recipient construction
/// reuses one ephemeral key pair across all recipients on the same curve and carries it
/// once in the JWE Protected Header. The orchestrator therefore generates the ephemeral
/// key pair once and performs each recipient's two-DH agreement with this delegate,
/// which takes the caller-held ephemeral private key bytes and returns only the shared
/// secret Z = Ze || Zs — the <c>epk</c> is held by the orchestrator, not returned here.
/// </para>
/// <para>
/// Z is per-recipient even though the ephemeral key is shared: Ze is the agreement
/// between the shared ephemeral private key and <em>this</em> recipient's public key, and
/// Zs is the agreement between the sender's static private key and the same recipient
/// public key. Both halves depend on the recipient, so a fresh Z is computed per call.
/// </para>
/// <para>
/// The sender's static key contribution (Zs) is what authenticates the sender to the
/// recipient — this is the authcrypt primitive of DIDComm v2. All three keys MUST be on
/// the same curve.
/// </para>
/// <para>
/// This delegate is async because the key agreement step may be performed by a remote
/// HSM, TPM, or other hardware boundary.
/// </para>
/// </remarks>
/// <param name="recipientPublicKey">
/// The recipient's static public key. The <see cref="Tag"/> identifies the curve and encoding.
/// </param>
/// <param name="ephemeralPrivateKeyBytes">
/// The shared ephemeral private key bytes. The same ephemeral key is passed for every
/// recipient on the curve. The bytes must not be stored or referenced after the call.
/// </param>
/// <param name="senderPrivateKeyBytes">
/// The sender's static private key bytes. The bytes must not be stored or referenced
/// after the delegate returns.
/// </param>
/// <param name="pool">Memory pool for allocating the shared secret.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The shared secret Z = Ze || Zs per NIST SP 800-56A §6.2.1.2. The caller must zero and
/// dispose it as soon as the key encryption key has been derived.
/// </returns>
public delegate ValueTask<SharedSecret> MultiRecipientAuthenticatedKeyAgreementEncryptDelegate(
    PublicKeyMemory recipientPublicKey,
    ReadOnlyMemory<byte> ephemeralPrivateKeyBytes,
    ReadOnlyMemory<byte> senderPrivateKeyBytes,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);
