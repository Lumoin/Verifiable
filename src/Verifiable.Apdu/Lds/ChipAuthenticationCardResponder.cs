using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Apdu.Pace;
using Verifiable.Apdu.SecureMessaging;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// The card side of ICAO Doc 9303 Part 11 / BSI TR-03110 EACv1 Chip Authentication — the inverse of
/// <see cref="ChipAuthentication"/>. Given the chip's static Chip Authentication private key (matching the
/// EF.DG14 public key) and the terminal's ephemeral public key from MSE:Set KAT, it agrees the
/// static–ephemeral ECDH secret, derives the new Secure Messaging session keys, and builds the re-keyed
/// card session with the send-sequence counter reset to zero.
/// </summary>
/// <remarks>
/// <para>
/// The shared secret is <c>K = SK_DH_IC · PK_DH_IFD</c> (the chip's static private key with the terminal's
/// ephemeral public key) — the same <c>K</c> the terminal agrees from the other side, so the re-keyed
/// sessions interoperate only if the chip holds the matching private key. The cryptography reuses
/// <see cref="PaceGenericMapping.AgreeSharedSecretAsync"/> and
/// <see cref="PaceKeyDerivation.DeriveSessionKeysAsync"/> and the cipher-to-tag mapping of
/// <see cref="ChipAuthentication"/>; this responder owns no cryptography of its own. The chip's private key
/// and the curve come from the card's DG14 personalisation.
/// </para>
/// </remarks>
public static class ChipAuthenticationCardResponder
{
    /// <summary>
    /// Agrees the Chip Authentication secret and establishes the re-keyed card Secure Messaging session.
    /// </summary>
    /// <param name="chipPrivateKey">The chip's static Chip Authentication private key (unsigned big-endian scalar on <paramref name="curve"/>). Borrowed.</param>
    /// <param name="terminalEphemeralPublicKey">The terminal's ephemeral public key from MSE:Set KAT (SEC1 uncompressed).</param>
    /// <param name="curve">A tag carrying the curve <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/>, from the matching DG14 public key.</param>
    /// <param name="cipher">The Secure Messaging cipher the protocol establishes, from the matching DG14 info.</param>
    /// <param name="pool">The sensitive-memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The re-keyed card Secure Messaging session (send-sequence counter zero). The caller owns and disposes it.</returns>
    /// <exception cref="NotSupportedException">Thrown for the AES-192/256 ciphers, whose SHA-256 KDF is a separate slice.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned session transfers to the caller; the session keys are disposed on a failure path.")]
    public static async ValueTask<SecureMessagingCardSession> EstablishSessionAsync(
        ReadOnlyMemory<byte> chipPrivateKey,
        ReadOnlyMemory<byte> terminalEphemeralPublicKey,
        Tag curve,
        ChipAuthenticationCipher cipher,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(curve);
        ArgumentNullException.ThrowIfNull(pool);

        SecureMessagingProfile profile = ProfileFor(cipher);
        (Tag encryptionKeyTag, Tag macKeyTag) = ChipAuthentication.SessionKeyTags(cipher);

        //K = SK_DH_IC · PK_DH_IFD (the chip's static key with the terminal's ephemeral key).
        using SharedSecret sharedSecret = await PaceGenericMapping.AgreeSharedSecretAsync(
            chipPrivateKey, terminalEphemeralPublicKey, curve, pool, cancellationToken).ConfigureAwait(false);

        (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) = await PaceKeyDerivation.DeriveSessionKeysAsync(
            sharedSecret.AsReadOnlyMemory(), encryptionKeyTag, macKeyTag, pool, cancellationToken).ConfigureAwait(false);
        try
        {
            //Chip Authentication resets the send-sequence counter to zero on both sides.
            using IMemoryOwner<byte> initialSendSequenceCounter = pool.Rent(profile.BlockSize);
            initialSendSequenceCounter.Memory.Span[..profile.BlockSize].Clear();

            return new SecureMessagingCardSession(
                encryptionKey, macKey, initialSendSequenceCounter.Memory.Span[..profile.BlockSize], profile, pool);
        }
        catch
        {
            encryptionKey.Dispose();
            macKey.Dispose();

            throw;
        }
    }


    /// <summary>
    /// The Secure Messaging profile a Chip Authentication cipher establishes. The card builds the session,
    /// so unlike the terminal it selects the profile here; the AES-192/256 profiles are a separate slice.
    /// </summary>
    private static SecureMessagingProfile ProfileFor(ChipAuthenticationCipher cipher) => cipher switch
    {
        ChipAuthenticationCipher.TripleDes => SecureMessagingProfile.TripleDes,
        ChipAuthenticationCipher.Aes128 => SecureMessagingProfile.Aes128,
        ChipAuthenticationCipher.Aes192 or ChipAuthenticationCipher.Aes256 => throw new NotSupportedException(
            $"Chip Authentication cipher '{cipher}' has no Secure Messaging profile yet (the AES-192/256 SHA-256 KDF is a separate slice)."),
        _ => throw new ArgumentOutOfRangeException(nameof(cipher), cipher, "Unknown Chip Authentication cipher.")
    };
}
