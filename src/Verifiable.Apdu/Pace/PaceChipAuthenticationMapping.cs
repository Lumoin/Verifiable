using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Apdu.SecureMessaging;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

namespace Verifiable.Apdu.Pace;

/// <summary>
/// The PACE Chip Authentication Mapping (CAM) steps that extend Generic Mapping (ICAO Doc 9303 Part 11
/// §4.4.3.5): the chip folds Chip Authentication into PACE by deriving <c>CA_IC = s_IC⁻¹ · s_Map,IC mod n</c>
/// from its static Chip Authentication private key and the ephemeral mapping private key, encrypting it under
/// KSenc, and sending it alongside the round-4 tokens; the terminal recovers <c>CA_IC</c> and verifies
/// <c>PK_Map,IC = CA_IC · PK_IC</c> against the chip's static public key, authenticating the chip.
/// </summary>
/// <remarks>
/// The mapping, key agreement, session-key derivation, and authentication tokens are identical to Generic
/// Mapping (<see cref="PaceGenericMapping"/>); CAM only adds the Encrypted Chip Authentication Data exchanged
/// in the final round. The CA data is encoded to the group-order width (<c>FE2OS</c>), padded with ISO/IEC
/// 9797-1 method 2, and encrypted in AES-CBC with <c>IV = E(KSenc, -1)</c>, where <c>-1</c> is the all-ones
/// 128-bit block (Doc 9303 §4.4.3.5.4).
/// </remarks>
public static class PaceChipAuthenticationMapping
{
    /// <summary>The AES block size in bytes; CAM uses the AES-128 profile.</summary>
    private const int BlockLength = 16;

    /// <summary>The fill byte of the all-ones block <c>-1</c> used to derive the CA-data encryption IV.</summary>
    private const byte AllOnes = 0xFF;


    /// <summary>
    /// Generates the chip's Chip Authentication Data <c>CA_IC = s_IC⁻¹ · s_Map,IC mod n</c> (Doc 9303 §4.4.3.5.1).
    /// </summary>
    /// <param name="staticPrivateKey">The chip's static Chip Authentication private key <c>s_IC</c>.</param>
    /// <param name="mappingPrivateKey">The chip's ephemeral mapping private key <c>s_Map,IC</c> from the Generic Mapping round.</param>
    /// <param name="curve">A tag carrying the curve <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/>.</param>
    /// <param name="pool">The sensitive-memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The Chip Authentication Data <c>CA_IC</c>. The caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the scalar transfers to the returned ChipAuthenticationData, which the caller disposes; the catch disposes it on a failure path.")]
    public static async ValueTask<ChipAuthenticationData> GenerateAsync(
        ReadOnlyMemory<byte> staticPrivateKey,
        ReadOnlyMemory<byte> mappingPrivateKey,
        Tag curve,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(curve);
        ArgumentNullException.ThrowIfNull(pool);

        EcChipAuthenticationDataDelegate compute = Resolve<EcChipAuthenticationDataDelegate>();
        IMemoryOwner<byte> caData = await compute(staticPrivateKey, mappingPrivateKey, curve, pool, cancellationToken).ConfigureAwait(false);
        try
        {
            return new ChipAuthenticationData(caData, curve);
        }
        catch
        {
            caData.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Encrypts the Chip Authentication Data into the Encrypted Chip Authentication Data <c>A_IC</c> (DO'8A')
    /// under KSenc: ISO/IEC 9797-1 method 2 padding, AES-CBC with <c>IV = E(KSenc, -1)</c> (Doc 9303 §4.4.3.5.4).
    /// </summary>
    /// <param name="chipAuthenticationData">The Chip Authentication Data <c>CA_IC</c> to encrypt.</param>
    /// <param name="encryptionKey">The PACE session encryption key KSenc.</param>
    /// <param name="pool">The sensitive-memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The Encrypted Chip Authentication Data <c>A_IC</c>. The caller disposes it.</returns>
    public static async ValueTask<Ciphertext> EncryptAsync(
        ChipAuthenticationData chipAuthenticationData,
        SymmetricKeyMemory encryptionKey,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(chipAuthenticationData);
        ArgumentNullException.ThrowIfNull(encryptionKey);
        ArgumentNullException.ThrowIfNull(pool);

        SymmetricEncryptDelegate encrypt = Resolve<SymmetricEncryptDelegate>();
        using IMemoryOwner<byte> initialisationVector = await ComputeInitialisationVectorAsync(encrypt, encryptionKey, pool, cancellationToken).ConfigureAwait(false);

        //The padded CA data is secret (derived from the static private key), so it lives in pinned memory.
        ReadOnlySpan<byte> caData = chipAuthenticationData.AsReadOnlySpan();
        int paddedLength = Iso9797Padding.PaddedLength(caData.Length, BlockLength);
        using IMemoryOwner<byte> padded = pool.Rent(paddedLength, AllocationKind.Pinned);
        Iso9797Padding.Pad(caData, BlockLength, padded.Memory.Span);

        (Ciphertext encrypted, _) = await encrypt(
            padded.Memory[..paddedLength], encryptionKey.AsReadOnlyMemory(), initialisationVector.Memory[..BlockLength], CryptoTags.Aes128Cbc, pool, null, cancellationToken).ConfigureAwait(false);

        return encrypted;
    }


    /// <summary>
    /// Recovers the Chip Authentication Data from the Encrypted Chip Authentication Data <c>A_IC</c> — the
    /// inverse of <see cref="EncryptAsync"/>.
    /// </summary>
    /// <param name="encryptedChipAuthenticationData">The Encrypted Chip Authentication Data <c>A_IC</c> from DO'8A'.</param>
    /// <param name="encryptionKey">The PACE session encryption key KSenc.</param>
    /// <param name="curve">A tag carrying the curve <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/> the recovered scalar is reduced over.</param>
    /// <param name="pool">The sensitive-memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The recovered Chip Authentication Data <c>CA_IC</c>. The caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the scalar transfers to the returned ChipAuthenticationData, which the caller disposes; the catch disposes it on a failure path.")]
    public static async ValueTask<ChipAuthenticationData> DecryptAsync(
        ReadOnlyMemory<byte> encryptedChipAuthenticationData,
        SymmetricKeyMemory encryptionKey,
        Tag curve,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(encryptionKey);
        ArgumentNullException.ThrowIfNull(curve);
        ArgumentNullException.ThrowIfNull(pool);

        SymmetricEncryptDelegate encrypt = Resolve<SymmetricEncryptDelegate>();
        SymmetricDecryptDelegate decrypt = Resolve<SymmetricDecryptDelegate>();
        using IMemoryOwner<byte> initialisationVector = await ComputeInitialisationVectorAsync(encrypt, encryptionKey, pool, cancellationToken).ConfigureAwait(false);

        (DecryptedContent padded, _) = await decrypt(
            encryptedChipAuthenticationData, encryptionKey.AsReadOnlyMemory(), initialisationVector.Memory[..BlockLength], CryptoTags.Aes128Cbc, pool, null, cancellationToken).ConfigureAwait(false);
        using(padded)
        {
            //Strip the ISO/IEC 9797-1 method 2 padding; the unpadded scalar is the group-order width.
            int length = Iso9797Padding.UnpaddedLength(padded.AsReadOnlySpan());
            IMemoryOwner<byte> caData = pool.Rent(length, AllocationKind.Pinned);
            try
            {
                padded.AsReadOnlySpan()[..length].CopyTo(caData.Memory.Span);

                return new ChipAuthenticationData(caData, curve);
            }
            catch
            {
                caData.Dispose();

                throw;
            }
        }
    }


    /// <summary>
    /// Verifies the chip by checking <c>PK_Map,IC = CA_IC · PK_IC</c> (Doc 9303 §4.4.3.5.2): the recovered CA
    /// data scaled by the chip's static public key must reproduce the mapping public key from round 2.
    /// </summary>
    /// <param name="chipAuthenticationData">The recovered Chip Authentication Data <c>CA_IC</c>.</param>
    /// <param name="staticPublicKey">The chip's static Chip Authentication public key <c>PK_IC</c> from EF.CardSecurity.</param>
    /// <param name="mappingPublicKey">The chip's mapping public key <c>PK_Map,IC</c> from the Generic Mapping round.</param>
    /// <param name="curve">A tag carrying the curve <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/>.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when the chip authenticates, otherwise <see langword="false"/>.</returns>
    public static async ValueTask<bool> VerifyAsync(
        ChipAuthenticationData chipAuthenticationData,
        EncodedEcPoint staticPublicKey,
        EncodedEcPoint mappingPublicKey,
        Tag curve,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(chipAuthenticationData);
        ArgumentNullException.ThrowIfNull(staticPublicKey);
        ArgumentNullException.ThrowIfNull(mappingPublicKey);
        ArgumentNullException.ThrowIfNull(curve);
        ArgumentNullException.ThrowIfNull(pool);

        EcMultiplyPointDelegate multiplyPoint = Resolve<EcMultiplyPointDelegate>();
        using EncodedEcPoint recovered = await multiplyPoint(
            chipAuthenticationData.AsReadOnlyMemory(), staticPublicKey.AsReadOnlyMemory(), curve, pool, cancellationToken).ConfigureAwait(false);

        return CryptographicOperations.FixedTimeEquals(recovered.AsReadOnlySpan(), mappingPublicKey.AsReadOnlySpan());
    }


    /// <summary>
    /// Computes the CA-data encryption IV <c>= E(KSenc, -1)</c>, where <c>-1</c> is the all-ones 128-bit block
    /// (Doc 9303 §4.4.3.5.4): a single-block AES-CBC encryption of the all-ones block under KSenc with a zero IV.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned IV buffer transfers to the caller, which disposes it.")]
    private static async ValueTask<IMemoryOwner<byte>> ComputeInitialisationVectorAsync(
        SymmetricEncryptDelegate encrypt, SymmetricKeyMemory encryptionKey, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> minusOne = pool.Rent(BlockLength);
        minusOne.Memory.Span[..BlockLength].Fill(AllOnes);
        using IMemoryOwner<byte> zeroIv = pool.Rent(BlockLength);

        (Ciphertext ivBlock, _) = await encrypt(
            minusOne.Memory[..BlockLength], encryptionKey.AsReadOnlyMemory(), zeroIv.Memory[..BlockLength], CryptoTags.Aes128Cbc, pool, null, cancellationToken).ConfigureAwait(false);
        try
        {
            IMemoryOwner<byte> initialisationVector = pool.Rent(BlockLength);
            ivBlock.AsReadOnlySpan().CopyTo(initialisationVector.Memory.Span);

            return initialisationVector;
        }
        finally
        {
            ivBlock.Dispose();
        }
    }


    /// <summary>
    /// Resolves a registered delegate or throws.
    /// </summary>
    private static TDelegate Resolve<TDelegate>() where TDelegate: Delegate =>
        CryptographicKeyFactory.GetFunction<TDelegate>(typeof(TDelegate))
            ?? throw new InvalidOperationException($"No {typeof(TDelegate).Name} has been registered.");
}
