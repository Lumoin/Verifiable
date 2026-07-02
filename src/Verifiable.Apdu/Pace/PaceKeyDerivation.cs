using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Apdu.Pace;

/// <summary>
/// The ICAO Doc 9303 Part 11 PACE key-derivation function and password handling for the AES-128
/// profile: deriving the nonce-encryption key Kπ and the session keys KSenc / KSmac from a secret,
/// and decrypting the chip's encrypted nonce.
/// </summary>
/// <remarks>
/// <para>
/// The key derivation is Section 9.7.1: <c>KDF(K, c) = SHA-1(K || c)</c> truncated to 16 octets for
/// the AES-128 and 3DES profiles, where <c>c</c> is a 32-bit big-endian counter — 1 for KSenc,
/// 2 for KSmac, and 3 for Kπ. The nonce the chip sends is one AES block encrypted under Kπ in CBC
/// mode with a zero IV; decrypting it yields the nonce <c>s</c> that seeds the mapping step.
/// </para>
/// <para>
/// This covers the symmetric foundation of PACE. The mapping (the mapped generator Ĝ = s·G + H for
/// Generic Mapping) and the ephemeral key agreement need elliptic-curve point arithmetic and are a
/// separate slice. SHA-1 routes through the registered digest delegate; the cipher through the
/// registered symmetric delegate. Only the AES-128 profile (SHA-1 KDF) is implemented here; the
/// AES-192/256 profiles use SHA-256 and are added when needed.
/// </para>
/// </remarks>
public static class PaceKeyDerivation
{
    /// <summary>The SHA-1 digest length in bytes.</summary>
    private const int Sha1Length = 20;

    /// <summary>The AES-128 key length in bytes (the truncation length of the KDF for this profile).</summary>
    private const int Aes128KeyLength = 16;

    /// <summary>The Secure Messaging session-key length in bytes — 16 for both the AES-128 and two-key 3DES profiles (both SHA-1 KDF).</summary>
    private const int SessionKeyByteLength = 16;

    /// <summary>The KDF counter selecting the encryption session key KSenc.</summary>
    private const uint EncryptionCounter = 1;

    /// <summary>The KDF counter selecting the MAC session key KSmac.</summary>
    private const uint MacCounter = 2;

    /// <summary>The KDF counter selecting the password-derived nonce key Kπ.</summary>
    private const uint PasswordCounter = 3;

    //eMRTD PACE (AES-128 / 3DES profile) derives keys with SHA-1; the convenience digest tags omit
    //SHA-1 by design, so it is composed inline here.
    private static readonly Tag Sha1DigestTag = Tag.Create(HashAlgorithmName.SHA1).With(Purpose.Digest).With(EncodingScheme.Raw);


    /// <summary>
    /// Derives the password-dependent nonce key Kπ = KDF(password, 3) for AES-128.
    /// </summary>
    /// <param name="password">The PACE password K (for MRZ access this is SHA-1 of the MRZ information).</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The nonce key Kπ. The caller disposes it.</returns>
    public static ValueTask<SymmetricKeyMemory> DerivePasswordKeyAsync(
        ReadOnlyMemory<byte> password,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default) =>
        DeriveKeyAsync(password, PasswordCounter, Aes128KeyLength, CryptoTags.Aes128Cbc, pool, cancellationToken);


    /// <summary>
    /// Derives the AES-128 session keys KSenc = KDF(K, 1) and KSmac = KDF(K, 2) from the agreed secret
    /// (the PACE AES profile).
    /// </summary>
    /// <param name="sharedSecret">The shared secret K produced by the PACE key agreement.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The KSenc and KSmac session keys. The caller disposes both.</returns>
    public static ValueTask<(SymmetricKeyMemory EncryptionKey, SymmetricKeyMemory MacKey)> DeriveSessionKeysAsync(
        ReadOnlyMemory<byte> sharedSecret,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default) =>
        DeriveSessionKeysAsync(sharedSecret, CryptoTags.Aes128Cbc, CryptoTags.Aes128Cmac, pool, cancellationToken);


    /// <summary>
    /// Derives the session keys KSenc = KDF(K, 1) and KSmac = KDF(K, 2) from the agreed secret, tagging
    /// them for a caller-chosen Secure Messaging cipher — the AES-128 (<see cref="CryptoTags.Aes128Cbc"/> /
    /// <see cref="CryptoTags.Aes128Cmac"/>) or two-key 3DES (<see cref="CryptoTags.TripleDesCbc"/> /
    /// <see cref="CryptoTags.RetailMac"/>) profile.
    /// </summary>
    /// <remarks>
    /// Both profiles derive 16-octet keys with the SHA-1 KDF, so only the carrier tags differ; PACE always
    /// establishes AES-128, while Chip Authentication selects the cipher its EF.DG14 announces. The
    /// AES-192/256 profiles use the SHA-256 KDF and are a separate slice, so a caller passes their tags
    /// only once that derivation is wired.
    /// </remarks>
    /// <param name="sharedSecret">The shared secret K produced by the key agreement (PACE or Chip Authentication).</param>
    /// <param name="encryptionKeyTag">The carrier tag for KSenc.</param>
    /// <param name="macKeyTag">The carrier tag for KSmac.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The KSenc and KSmac session keys. The caller disposes both.</returns>
    public static async ValueTask<(SymmetricKeyMemory EncryptionKey, SymmetricKeyMemory MacKey)> DeriveSessionKeysAsync(
        ReadOnlyMemory<byte> sharedSecret,
        Tag encryptionKeyTag,
        Tag macKeyTag,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(encryptionKeyTag);
        ArgumentNullException.ThrowIfNull(macKeyTag);

        SymmetricKeyMemory encryptionKey = await DeriveKeyAsync(
            sharedSecret, EncryptionCounter, SessionKeyByteLength, encryptionKeyTag, pool, cancellationToken).ConfigureAwait(false);
        try
        {
            SymmetricKeyMemory macKey = await DeriveKeyAsync(
                sharedSecret, MacCounter, SessionKeyByteLength, macKeyTag, pool, cancellationToken).ConfigureAwait(false);

            return (encryptionKey, macKey);
        }
        catch
        {
            encryptionKey.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Decrypts the chip's encrypted nonce z under Kπ (AES-128 CBC, zero IV) to recover the nonce s.
    /// </summary>
    /// <param name="passwordKey">The nonce key Kπ from <see cref="DerivePasswordKeyAsync"/>.</param>
    /// <param name="encryptedNonce">The encrypted nonce z (one AES block).</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The decrypted nonce s (16 bytes). The caller disposes it.</returns>
    public static async ValueTask<DecryptedContent> DecryptNonceAsync(
        SymmetricKeyMemory passwordKey,
        ReadOnlyMemory<byte> encryptedNonce,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(passwordKey);
        ArgumentNullException.ThrowIfNull(pool);

        SymmetricDecryptDelegate decrypt = Resolve<SymmetricDecryptDelegate>();
        using IMemoryOwner<byte> zeroIv = pool.Rent(Aes128KeyLength);
        (DecryptedContent nonce, _) = await decrypt(
            encryptedNonce, passwordKey.AsReadOnlyMemory(), zeroIv.Memory,
            CryptoTags.Aes128CbcDecryptedContent, pool, null, cancellationToken).ConfigureAwait(false);

        return nonce;
    }


    /// <summary>
    /// Computes KDF(secret, counter) = SHA-1(secret || counter) truncated to <paramref name="keyByteLength"/>.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented key buffer transfers to the returned SymmetricKeyMemory, which the caller disposes.")]
    private static async ValueTask<SymmetricKeyMemory> DeriveKeyAsync(
        ReadOnlyMemory<byte> secret,
        uint counter,
        int keyByteLength,
        Tag tag,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pool);

        using IMemoryOwner<byte> derivationInput = pool.Rent(secret.Length + sizeof(uint), AllocationKind.Pinned);
        secret.Span.CopyTo(derivationInput.Memory.Span);
        BinaryPrimitives.WriteUInt32BigEndian(derivationInput.Memory.Span[secret.Length..], counter);

        using DigestValue hash = await ComputeSha1Async(derivationInput.Memory, pool, cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> owner = pool.Rent(keyByteLength, AllocationKind.Pinned);
        try
        {
            hash.AsReadOnlySpan()[..keyByteLength].CopyTo(owner.Memory.Span);

            return new SymmetricKeyMemory(owner, tag);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Computes a SHA-1 digest through the registered digest delegate into a pinned <see cref="DigestValue"/>
    /// (the PACE key-derivation hashes are secret).
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
