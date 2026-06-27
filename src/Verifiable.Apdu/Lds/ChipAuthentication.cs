using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Apdu.Pace;
using Verifiable.Apdu.SecureMessaging;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// ICAO Doc 9303 Part 11 / BSI TR-03110 §6.2 Chip Authentication (EACv1): the anti-cloning step that
/// agrees a fresh Secure Messaging key with the chip's static key from EF.DG14 and proves the chip holds
/// the matching private key.
/// </summary>
/// <remarks>
/// <para>
/// The terminal generates an ephemeral key pair on the chip's curve, sends its ephemeral public key to
/// the chip in an MSE:Set KAT command (INS <c>0x22</c>, P1 <c>0x41</c>, P2 <c>0xA6</c>) over the
/// access-protocol (BAC or PACE) Secure Messaging session, and agrees the static–ephemeral ECDH secret
/// <c>K = SK_DH_IFD · PK_DH_IC</c> against the DG14 public key. The new session keys
/// <c>KSenc = KDF(K, 1)</c> and <c>KSmac = KDF(K, 2)</c> re-key Secure Messaging with the send-sequence
/// counter reset to zero; from then on the chip can keep the session in step only if it derived the same
/// <c>K</c>, which requires its private key — so a clone lacking that key is locked out.
/// </para>
/// <para>
/// This is the EACv1 "simple" variant: the chip acknowledges MSE:Set KAT with <c>9000</c> and is
/// authenticated implicitly by the subsequent Secure Messaging rather than by returning an explicit
/// authentication token. The ECDH agreement reuses <see cref="PaceGenericMapping.AgreeSharedSecretAsync"/>
/// (a generic TR-03110 scalar·point primitive) and the key derivation reuses
/// <see cref="PaceKeyDerivation.DeriveSessionKeysAsync"/>; the terminal's ephemeral private key is supplied
/// by the caller — from the entropy provider in production, injected from a worked example in tests — so
/// the flow is deterministic.
/// </para>
/// </remarks>
public static class ChipAuthentication
{
    /// <summary>The MANAGE SECURITY ENVIRONMENT instruction byte.</summary>
    private const byte ManageSecurityEnvironmentInstruction = 0x22;

    /// <summary>P1 of MSE:Set KAT — set a Key Agreement Template for computation (Doc 9303 Part 11 §6.2 / ISO 7816-4).</summary>
    private const byte SetForComputationParameter = 0x41;

    /// <summary>P2 of MSE:Set KAT — the Key Agreement Template (KAT) tag.</summary>
    private const byte KeyAgreementTemplateParameter = 0xA6;

    /// <summary>BER-TLV tag for the terminal's ephemeral public key in MSE:Set KAT (DO'91').</summary>
    private const int EphemeralPublicKeyTag = 0x91;

    /// <summary>BER-TLV tag for the chip's private-key reference in MSE:Set KAT (DO'84'), sent when DG14 offers more than one key.</summary>
    private const int PrivateKeyReferenceTag = 0x84;


    /// <summary>
    /// Establishes a Chip Authentication session, returning the new Secure Messaging session keys KSenc and KSmac.
    /// </summary>
    /// <param name="device">The card device. Borrowed, not disposed.</param>
    /// <param name="session">The access-protocol (BAC or PACE) Secure Messaging session the MSE:Set KAT runs over. Borrowed, not disposed.</param>
    /// <param name="chipPublicKey">The chip's static Chip Authentication public key from EF.DG14 (SEC1 uncompressed, tagged with its curve). Borrowed.</param>
    /// <param name="cipher">The Secure Messaging cipher the protocol establishes, from the paired <see cref="ChipAuthenticationInfo"/>.</param>
    /// <param name="terminalEphemeralPrivateKey">The terminal's ephemeral private key on the chip's curve, from the entropy provider.</param>
    /// <param name="keyId">The chip's key identifier, or <see langword="null"/> when DG14 offers a single key (then no DO'84' is sent).</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The new session keys KSenc and KSmac, tagged for <paramref name="cipher"/>. The caller disposes both and builds a fresh <see cref="SecureMessagingSession"/> with the send-sequence counter reset to zero.</returns>
    /// <exception cref="InvalidOperationException">Thrown on a card or transport error, or when the chip rejects MSE:Set KAT.</exception>
    /// <exception cref="NotSupportedException">Thrown for the AES-192/256 ciphers, whose SHA-256 KDF is a separate slice.</exception>
    public static async ValueTask<(SymmetricKeyMemory EncryptionKey, SymmetricKeyMemory MacKey)> EstablishAsync(
        ApduDevice device,
        SecureMessagingSession session,
        EncodedEcPoint chipPublicKey,
        ChipAuthenticationCipher cipher,
        ReadOnlyMemory<byte> terminalEphemeralPrivateKey,
        int? keyId,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(chipPublicKey);
        ArgumentNullException.ThrowIfNull(pool);

        (Tag encryptionKeyTag, Tag macKeyTag) = SessionKeyTags(cipher);
        Tag curve = chipPublicKey.Tag;

        EcMultiplyGeneratorDelegate multiplyGenerator = Resolve<EcMultiplyGeneratorDelegate>();

        //The terminal's ephemeral public key on the chip's curve: PK_DH_IFD = SK_DH_IFD · G.
        using EncodedEcPoint terminalEphemeralPublicKey = await multiplyGenerator(
            terminalEphemeralPrivateKey, curve, pool, cancellationToken).ConfigureAwait(false);

        //Send it to the chip in MSE:Set KAT over the current Secure Messaging session (fail-closed on rejection).
        await SetKeyAgreementTemplateAsync(
            device, session, terminalEphemeralPublicKey.AsReadOnlyMemory(), keyId, pool, cancellationToken).ConfigureAwait(false);

        //Agree the static–ephemeral ECDH secret K against the chip's DG14 key (its X-coordinate).
        using SharedSecret sharedSecret = await PaceGenericMapping.AgreeSharedSecretAsync(
            terminalEphemeralPrivateKey, chipPublicKey.AsReadOnlyMemory(), curve, pool, cancellationToken).ConfigureAwait(false);

        //Derive the new Secure Messaging session keys KSenc = KDF(K, 1) and KSmac = KDF(K, 2).
        return await PaceKeyDerivation.DeriveSessionKeysAsync(
            sharedSecret.AsReadOnlyMemory(), encryptionKeyTag, macKeyTag, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Sends MSE:Set KAT over the Secure Messaging session — DO'91' with the terminal's ephemeral public
    /// key, and DO'84' with the key identifier when one is given — and checks the chip accepted it.
    /// </summary>
    private static async ValueTask SetKeyAgreementTemplateAsync(
        ApduDevice device,
        SecureMessagingSession session,
        ReadOnlyMemory<byte> ephemeralPublicKey,
        int? keyId,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> data = pool.Rent(KeyAgreementTemplateDataLength(ephemeralPublicKey.Length, keyId));
        int dataLength = WriteKeyAgreementTemplateData(ephemeralPublicKey.Span, keyId, data.Memory.Span);

        using ProtectedCommandApdu protectedCommand = await session.ProtectCommandAsync(
            0x00, ManageSecurityEnvironmentInstruction, SetForComputationParameter, KeyAgreementTemplateParameter,
            data.Memory[..dataLength], expectedResponseLength: null, pool, cancellationToken).ConfigureAwait(false);

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, protectedCommand.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
        if(result.IsTransportError)
        {
            throw new InvalidOperationException($"Chip Authentication MSE:Set KAT failed with a transport error 0x{result.TransportErrorCode:X8}.");
        }

        using ApduResponse response = result.Value;
        if(!response.StatusWord.IsSuccess)
        {
            throw new InvalidOperationException($"Chip Authentication MSE:Set KAT carried a transport error: {response.StatusWord}.");
        }

        using SecureMessagingResponse unprotected = await session.UnprotectResponseAsync(
            response.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
        if(!unprotected.StatusWord.IsSuccess)
        {
            throw new InvalidOperationException($"Chip Authentication MSE:Set KAT was rejected by the chip: {unprotected.StatusWord}.");
        }
    }


    /// <summary>
    /// Writes the MSE:Set KAT data field — <c>91 ‖ ephemeral public key</c> then, when a key identifier is
    /// given, <c>84 ‖ key identifier</c> — into <paramref name="destination"/>, returning the byte count.
    /// </summary>
    private static int WriteKeyAgreementTemplateData(ReadOnlySpan<byte> ephemeralPublicKey, int? keyId, Span<byte> destination)
    {
        var writer = new BerTlvWriter(destination);
        writer.WriteElement(EphemeralPublicKeyTag, ephemeralPublicKey);
        if(keyId is int reference)
        {
            writer.WriteElement(PrivateKeyReferenceTag, [(byte)reference]);
        }

        return writer.Written;
    }


    /// <summary>
    /// The encoded length of the MSE:Set KAT data field — DO'91' and the optional DO'84'.
    /// </summary>
    private static int KeyAgreementTemplateDataLength(int ephemeralPublicKeyLength, int? keyId) =>
        BerTlvWriter.ElementSize(EphemeralPublicKeyTag, ephemeralPublicKeyLength)
        + (keyId.HasValue ? BerTlvWriter.ElementSize(PrivateKeyReferenceTag, 1) : 0);


    /// <summary>
    /// The Secure Messaging carrier tags for KSenc and KSmac of a Chip Authentication cipher. The 3DES and
    /// AES-128 profiles share the SHA-1 KDF and differ only in these tags; the AES-192/256 profiles need
    /// the SHA-256 KDF and are a separate slice. Shared with the card-side
    /// <see cref="ChipAuthenticationCardResponder"/>, which derives the same keys.
    /// </summary>
    internal static (Tag EncryptionKeyTag, Tag MacKeyTag) SessionKeyTags(ChipAuthenticationCipher cipher) => cipher switch
    {
        ChipAuthenticationCipher.TripleDes => (CryptoTags.TripleDesCbc, CryptoTags.RetailMac),
        ChipAuthenticationCipher.Aes128 => (CryptoTags.Aes128Cbc, CryptoTags.Aes128Cmac),
        ChipAuthenticationCipher.Aes192 or ChipAuthenticationCipher.Aes256 => throw new NotSupportedException(
            $"Chip Authentication cipher '{cipher}' derives keys with the SHA-256 KDF, which is not yet implemented."),
        _ => throw new ArgumentOutOfRangeException(nameof(cipher), cipher, "Unknown Chip Authentication cipher.")
    };


    /// <summary>
    /// Resolves a registered delegate or throws.
    /// </summary>
    private static TDelegate Resolve<TDelegate>() where TDelegate: Delegate =>
        CryptographicKeyFactory.GetFunction<TDelegate>(typeof(TDelegate))
            ?? throw new InvalidOperationException($"No {typeof(TDelegate).Name} has been registered.");
}
