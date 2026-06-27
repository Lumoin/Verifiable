using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;

namespace Verifiable.Apdu.Pace;

/// <summary>
/// The card side of ICAO Doc 9303 Part 11 PACE with Generic Mapping — the inverse of
/// <see cref="PaceProtocol"/>. It covers the four chained GENERAL AUTHENTICATE rounds from the chip's
/// perspective: the encrypted nonce (the card derives the PACE password key from its own MRZ, draws the
/// nonce, and encrypts it), the nonce mapping, the ephemeral key agreement, and the mutual-authentication
/// tokens.
/// </summary>
/// <remarks>
/// <para>
/// The PACE password for MRZ access is <c>K = SHA-1(MRZ information)</c> (the same MRZ information BAC uses);
/// the nonce-encryption key is <c>Kπ = KDF(K, 3)</c> and the chip encrypts a fresh 16-octet nonce <c>s</c>
/// under it in AES-128 CBC with a zero IV (Doc 9303 §4.4.1). The mapping derives a fresh generator
/// <c>Ĝ = s·G + H</c> from an ephemeral ECDH exchange, key agreement runs over <c>Ĝ</c> to a shared secret,
/// the AES session keys come from the PACE KDF, and each side authenticates the other's ephemeral public key
/// with an AES-CMAC token.
/// </para>
/// <para>
/// The cryptography routes through the registered provider delegates and reuses
/// <see cref="PaceKeyDerivation"/> and <see cref="PaceGenericMapping"/>; the chip's nonce and ephemeral
/// private keys are drawn from the card's RNG (injected in tests). The ephemeral private keys are sized to
/// the curve from the length of the peer point the round carries, so no curve-specific scalar length is
/// hard-coded.
/// </para>
/// </remarks>
public static class PaceCardResponder
{
    /// <summary>The PACE nonce length in bytes (one AES-128 block) for the AES-128 profile.</summary>
    private const int NonceLength = 16;

    /// <summary>The SHA-1 digest length in bytes.</summary>
    private const int Sha1Length = 20;

    //eMRTD PACE derives the password key with SHA-1; the convenience digest tags omit SHA-1 by design, so
    //it is composed inline here.
    private static Tag Sha1DigestTag { get; } = Tag.Create(
        (typeof(HashAlgorithmName), HashAlgorithmName.SHA1),
        (typeof(Purpose), Purpose.Digest),
        (typeof(EncodingScheme), EncodingScheme.Raw));


    /// <summary>
    /// Draws the PACE nonce and encrypts it under the card's MRZ-derived password key (round 1).
    /// </summary>
    /// <param name="mrzInformation">The MRZ information the card derives its password from (from <see cref="Verifiable.Apdu.Bac.BasicAccessControl.BuildMrzInformation"/>).</param>
    /// <param name="rng">The card's RNG backend, used to draw the nonce.</param>
    /// <param name="pool">The sensitive-memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The encrypted nonce <c>z</c> (public wire bytes) and the plaintext nonce <c>s</c> (16 bytes, retained for the mapping round). The caller owns and disposes both.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the encrypted nonce and the nonce transfers to the caller, which disposes both; the catch disposes the nonce on a failure path.")]
    public static async ValueTask<(IMemoryOwner<byte> EncryptedNonce, IMemoryOwner<byte> Nonce)> EncryptNonceAsync(
        string mrzInformation,
        FillEntropyDelegate rng,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(mrzInformation);
        ArgumentNullException.ThrowIfNull(rng);
        ArgumentNullException.ThrowIfNull(pool);

        using SymmetricKeyMemory nonceKey = await DeriveNonceKeyAsync(mrzInformation, pool, cancellationToken).ConfigureAwait(false);

        //The nonce s is secret until the mapping step consumes it; it lives in pinned memory.
        IMemoryOwner<byte> nonce = pool.Rent(NonceLength, AllocationKind.Pinned);
        try
        {
            rng(nonce.Memory.Span[..NonceLength]);

            IMemoryOwner<byte> encryptedNonce = await EncryptAsync(nonce.Memory[..NonceLength], nonceKey, pool, cancellationToken).ConfigureAwait(false);

            return (encryptedNonce, nonce);
        }
        catch
        {
            nonce.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Runs the nonce-mapping round (round 2): generates the chip's mapping key pair, maps the nonce to the
    /// ephemeral generator <c>Ĝ</c>, and returns the chip's mapping public key for the terminal.
    /// </summary>
    /// <param name="nonce">The decrypted nonce <c>s</c> the card drew in round 1.</param>
    /// <param name="terminalMappingPublicKey">The terminal's mapping public key from DO'81' (SEC1 uncompressed).</param>
    /// <param name="curve">A tag carrying the curve <see cref="CryptoAlgorithm"/>.</param>
    /// <param name="rng">The card's RNG backend, used to draw the chip mapping private key.</param>
    /// <param name="pool">The sensitive-memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// The chip's mapping public key (DO'82' value), the mapped generator <c>Ĝ</c> retained for the
    /// key-agreement round, and the chip's mapping private key <c>s_Map,IC</c> retained for Chip Authentication
    /// Mapping (it blinds the static key in round 4). The caller disposes all three.
    /// </returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the mapping public key, the mapped generator, and the mapping private key transfers to the caller; they are disposed on a failure path.")]
    public static async ValueTask<(EncodedEcPoint MappingPublicKey, EncodedEcPoint MappedGenerator, IMemoryOwner<byte> MappingPrivateKey)> MapAsync(
        ReadOnlyMemory<byte> nonce,
        ReadOnlyMemory<byte> terminalMappingPublicKey,
        Tag curve,
        FillEntropyDelegate rng,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(curve);
        ArgumentNullException.ThrowIfNull(rng);
        ArgumentNullException.ThrowIfNull(pool);

        //The mapping private key is a scalar the size of a field element; the terminal point is 0x04 || X || Y.
        //It is retained (returned to the caller) because Chip Authentication Mapping needs it in round 4.
        IMemoryOwner<byte> mappingPrivateKey = DrawScalar(terminalMappingPublicKey.Length, rng, pool, out int scalarLength);
        try
        {
            EcMultiplyGeneratorDelegate multiplyGenerator = Resolve<EcMultiplyGeneratorDelegate>();
            EncodedEcPoint mappingPublicKey = await multiplyGenerator(
                mappingPrivateKey.Memory[..scalarLength], curve, pool, cancellationToken).ConfigureAwait(false);
            try
            {
                EncodedEcPoint mappedGenerator = await PaceGenericMapping.MapNonceAsync(
                    nonce, mappingPrivateKey.Memory[..scalarLength], terminalMappingPublicKey, curve, pool, cancellationToken).ConfigureAwait(false);

                return (mappingPublicKey, mappedGenerator, mappingPrivateKey);
            }
            catch
            {
                mappingPublicKey.Dispose();

                throw;
            }
        }
        catch
        {
            mappingPrivateKey.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Runs the key-agreement round (round 3): generates the chip's ephemeral key pair over the mapped
    /// generator, agrees the shared secret, derives the AES session keys, and returns the chip's ephemeral
    /// public key for the terminal.
    /// </summary>
    /// <param name="mappedGenerator">The mapped generator <c>Ĝ</c> from the mapping round (SEC1 uncompressed).</param>
    /// <param name="terminalEphemeralPublicKey">The terminal's ephemeral public key from DO'83' (SEC1 uncompressed).</param>
    /// <param name="curve">A tag carrying the curve <see cref="CryptoAlgorithm"/>.</param>
    /// <param name="rng">The card's RNG backend, used to draw the chip ephemeral private key.</param>
    /// <param name="pool">The sensitive-memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The chip's ephemeral public key (DO'84' value) and the AES session keys KSenc and KSmac. The caller disposes all three.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the ephemeral public key and both session keys transfers to the caller; the public key is disposed on a failure path.")]
    public static async ValueTask<(EncodedEcPoint EphemeralPublicKey, SymmetricKeyMemory EncryptionKey, SymmetricKeyMemory MacKey)> AgreeAsync(
        ReadOnlyMemory<byte> mappedGenerator,
        ReadOnlyMemory<byte> terminalEphemeralPublicKey,
        Tag curve,
        FillEntropyDelegate rng,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(curve);
        ArgumentNullException.ThrowIfNull(rng);
        ArgumentNullException.ThrowIfNull(pool);

        //The ephemeral key lives on the mapped generator's curve, so the scalar is the same field-element size.
        using IMemoryOwner<byte> ephemeralPrivateKey = DrawScalar(mappedGenerator.Length, rng, pool, out int scalarLength);

        EcMultiplyPointDelegate multiplyPoint = Resolve<EcMultiplyPointDelegate>();
        EncodedEcPoint ephemeralPublicKey = await multiplyPoint(
            ephemeralPrivateKey.Memory[..scalarLength], mappedGenerator, curve, pool, cancellationToken).ConfigureAwait(false);
        try
        {
            using SharedSecret sharedSecret = await PaceGenericMapping.AgreeSharedSecretAsync(
                ephemeralPrivateKey.Memory[..scalarLength], terminalEphemeralPublicKey, curve, pool, cancellationToken).ConfigureAwait(false);
            (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) = await PaceKeyDerivation.DeriveSessionKeysAsync(
                sharedSecret.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);

            return (ephemeralPublicKey, encryptionKey, macKey);
        }
        catch
        {
            ephemeralPublicKey.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Runs the mutual-authentication round (round 4): verifies the terminal's token T_IFD against the chip's
    /// own ephemeral public key and, on success, computes the chip's token T_IC over the terminal's ephemeral
    /// public key.
    /// </summary>
    /// <param name="macKey">The session MAC key KSmac.</param>
    /// <param name="terminalToken">The terminal's authentication token T_IFD from DO'85'.</param>
    /// <param name="chipEphemeralPublicKey">The chip's own ephemeral public key (the value T_IFD authenticates).</param>
    /// <param name="terminalEphemeralPublicKey">The terminal's ephemeral public key (the value T_IC authenticates).</param>
    /// <param name="objectIdentifier">The PACE protocol OID value bytes (without the outer 0x06 tag), from MSE:Set AT.</param>
    /// <param name="pool">The sensitive-memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The chip's authentication token T_IC (DO'86' value). The caller disposes it.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the terminal's token T_IFD does not verify.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned chip token transfers to the caller, which disposes it.")]
    public static async ValueTask<MacValue> AuthenticateAsync(
        SymmetricKeyMemory macKey,
        ReadOnlyMemory<byte> terminalToken,
        EncodedEcPoint chipEphemeralPublicKey,
        EncodedEcPoint terminalEphemeralPublicKey,
        ReadOnlyMemory<byte> objectIdentifier,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(macKey);
        ArgumentNullException.ThrowIfNull(chipEphemeralPublicKey);
        ArgumentNullException.ThrowIfNull(terminalEphemeralPublicKey);
        ArgumentNullException.ThrowIfNull(pool);

        //T_IFD authenticates the chip's ephemeral public key; verify it before answering (fail-closed).
        using(MacValue expectedTerminalToken = await macKey.ComputeAuthenticationTokenAsync(
            chipEphemeralPublicKey, objectIdentifier, pool, cancellationToken).ConfigureAwait(false))
        {
            if(!CryptographicOperations.FixedTimeEquals(terminalToken.Span, expectedTerminalToken.AsReadOnlySpan()))
            {
                throw new InvalidOperationException("PACE mutual authentication failed: the terminal's token T_IFD did not verify.");
            }
        }

        //T_IC authenticates the terminal's ephemeral public key.
        return await macKey.ComputeAuthenticationTokenAsync(
            terminalEphemeralPublicKey, objectIdentifier, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Draws a curve scalar of a field element's size — half the SEC1 uncompressed point length
    /// <c>0x04 || X || Y</c> — from the card's RNG into a pinned buffer.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented scalar buffer transfers to the caller, which disposes it.")]
    private static IMemoryOwner<byte> DrawScalar(int encodedPointLength, FillEntropyDelegate rng, BaseMemoryPool pool, out int scalarLength)
    {
        scalarLength = (encodedPointLength - 1) / 2;
        IMemoryOwner<byte> scalar = pool.Rent(scalarLength, AllocationKind.Pinned);
        try
        {
            rng(scalar.Memory.Span[..scalarLength]);

            return scalar;
        }
        catch
        {
            scalar.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Derives the nonce-encryption key Kπ from the MRZ: <c>K = SHA-1(MRZ information)</c>, then <c>Kπ = KDF(K, 3)</c>.
    /// </summary>
    private static async ValueTask<SymmetricKeyMemory> DeriveNonceKeyAsync(string mrzInformation, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        //The MRZ information is the PACE access secret.
        using IMemoryOwner<byte> mrzBytes = pool.Rent(Encoding.ASCII.GetByteCount(mrzInformation), AllocationKind.Pinned);
        Encoding.ASCII.GetBytes(mrzInformation, mrzBytes.Memory.Span);

        using DigestValue passwordSeed = await ComputeSha1Async(mrzBytes.Memory, pool, cancellationToken).ConfigureAwait(false);

        return await PaceKeyDerivation.DerivePasswordKeyAsync(passwordSeed.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Encrypts the nonce under Kπ in AES-128 CBC with a zero IV, copying the cryptogram into a right-sized buffer.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned encrypted-nonce buffer transfers to the caller, which disposes it.")]
    private static async ValueTask<IMemoryOwner<byte>> EncryptAsync(ReadOnlyMemory<byte> nonce, SymmetricKeyMemory nonceKey, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        SymmetricEncryptDelegate encrypt = Resolve<SymmetricEncryptDelegate>();
        using IMemoryOwner<byte> zeroIv = pool.Rent(NonceLength);
        (Ciphertext cryptogram, _) = await encrypt(
            nonce, nonceKey.AsReadOnlyMemory(), zeroIv.Memory, CryptoTags.Aes128Cbc, pool, null, cancellationToken).ConfigureAwait(false);
        try
        {
            IMemoryOwner<byte> owner = pool.Rent(cryptogram.AsReadOnlySpan().Length);
            cryptogram.AsReadOnlySpan().CopyTo(owner.Memory.Span);

            return owner;
        }
        finally
        {
            cryptogram.Dispose();
        }
    }


    /// <summary>
    /// Computes a SHA-1 digest through the registered digest delegate into a pinned <see cref="DigestValue"/>.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned DigestValue transfers to the caller, which disposes it.")]
    private static async ValueTask<DigestValue> ComputeSha1Async(ReadOnlyMemory<byte> input, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        ComputeDigestDelegate digest = CryptographicKeyFactory.GetFunction<ComputeDigestDelegate>(typeof(ComputeDigestDelegate))
            ?? throw new InvalidOperationException("No ComputeDigestDelegate has been registered.");

        (DigestValue value, _) = await digest(
            new ReadOnlySequence<byte>(input), Sha1Length, Sha1DigestTag, pool, null, cancellationToken).ConfigureAwait(false);
        try
        {
            //The PACE password seed is secret, so it is re-homed to pinned memory.
            IMemoryOwner<byte> owner = pool.Rent(Sha1Length, AllocationKind.Pinned);
            value.AsReadOnlySpan().CopyTo(owner.Memory.Span);

            return new DigestValue(owner, Sha1DigestTag);
        }
        finally
        {
            value.Dispose();
        }
    }


    /// <summary>
    /// Resolves a registered symmetric delegate or throws.
    /// </summary>
    private static TDelegate Resolve<TDelegate>() where TDelegate: Delegate =>
        CryptographicKeyFactory.GetFunction<TDelegate>(typeof(TDelegate))
            ?? throw new InvalidOperationException($"No {typeof(TDelegate).Name} has been registered.");
}
