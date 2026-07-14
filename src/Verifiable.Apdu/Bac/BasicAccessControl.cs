using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Apdu.Mrz;
using Verifiable.Apdu.SecureMessaging;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;

namespace Verifiable.Apdu.Bac;

/// <summary>
/// ICAO Doc 9303 Part 11 Basic Access Control (BAC): derives the access keys from the MRZ,
/// performs the challenge-response mutual authentication with the chip, and establishes a
/// 3DES <see cref="SecureMessagingSession"/>.
/// </summary>
/// <remarks>
/// <para>
/// BAC proves the terminal has optical access to the data page (it knows the MRZ) before the
/// chip releases any data. The MRZ yields a key seed (Section 9.7.1 / Appendix D.2); the seed
/// derives KEnc and KMAC; a GET CHALLENGE + EXTERNAL AUTHENTICATE exchange with random nonces
/// authenticates both sides and produces the session keys KSenc / KSmac and the initial
/// send-sequence counter (Appendix D.3), which are handed to a <see cref="SecureMessagingSession"/>.
/// </para>
/// <para>
/// All cryptography routes through the registered provider delegates, and every value crosses a
/// boundary as a named carrier — <see cref="GetChallengeResponse"/>, <see cref="Ciphertext"/>,
/// <see cref="MacValue"/>, <see cref="DecryptedContent"/>, <see cref="DigestValue"/>,
/// <see cref="SymmetricKeyMemory"/> — not a naked buffer. Working buffers are pooled; the access
/// secrets (the MRZ information, the key seed and derivation inputs, the authentication input S
/// which carries KIFD, and the decrypted chip response R which carries KIC) use
/// <see cref="AllocationKind.Pinned"/>. The random terminal nonce (RND.IFD) and keying material
/// (KIFD) are supplied by the caller from the configured entropy provider.
/// </para>
/// </remarks>
public static class BasicAccessControl
{
    /// <summary>The 3DES cipher block size — the alignment unit for padding, the SSC, and the IV.</summary>
    private const int BlockSize = 8;

    /// <summary>The byte length of RND.IC and RND.IFD.</summary>
    private const int NonceLength = 8;

    /// <summary>The byte length of KIFD and KIC.</summary>
    private const int KeyingMaterialLength = 16;

    /// <summary>The byte length of a derived 3DES key (KEnc/KMAC/KSenc/KSmac).</summary>
    private const int KeyLength = 16;

    /// <summary>The byte length of the SHA-1 digest used throughout BAC key derivation.</summary>
    private const int Sha1Length = 20;

    //eMRTD BAC mandates SHA-1; the convenience digest tags omit SHA-1 by design, so it is composed inline here.
    private static Tag Sha1DigestTag { get; } = Tag.Create(HashAlgorithmName.SHA1).With(Purpose.Digest).With(EncodingScheme.Raw);


    /// <summary>
    /// Computes the ICAO Doc 9303 Part 3 check digit (weights 7, 3, 1) over an MRZ field.
    /// </summary>
    /// <param name="field">The MRZ field characters (digits, A-Z, and the filler '&lt;').</param>
    /// <returns>The check digit as the character '0'-'9'.</returns>
    /// <remarks>
    /// The canonical implementation lives on <see cref="MachineReadableZone"/> (the Part 3 layer);
    /// this remains for callers deriving the access-key seed without first parsing a full MRZ.
    /// </remarks>
    public static char ComputeCheckDigit(ReadOnlySpan<char> field) => MachineReadableZone.ComputeCheckDigit(field);


    /// <summary>
    /// Builds the 'MRZ information' string (Appendix D.2): the document number, date of birth, and
    /// date of expiry, each followed by its check digit.
    /// </summary>
    /// <param name="documentNumber">The document number field as it appears in the MRZ (9 characters with '&lt;' filler for the common case).</param>
    /// <param name="dateOfBirth">The date of birth in YYMMDD.</param>
    /// <param name="dateOfExpiry">The date of expiry in YYMMDD.</param>
    /// <returns>The concatenated MRZ information used as the BAC key-seed input.</returns>
    public static string BuildMrzInformation(string documentNumber, string dateOfBirth, string dateOfExpiry)
    {
        ArgumentNullException.ThrowIfNull(documentNumber);
        ArgumentNullException.ThrowIfNull(dateOfBirth);
        ArgumentNullException.ThrowIfNull(dateOfExpiry);

        return string.Concat(
            documentNumber, ComputeCheckDigit(documentNumber).ToString(),
            dateOfBirth, ComputeCheckDigit(dateOfBirth).ToString(),
            dateOfExpiry, ComputeCheckDigit(dateOfExpiry).ToString());
    }


    /// <summary>
    /// Derives the BAC access keys KEnc and KMAC from the MRZ information (Section 9.7.1 / Appendix D.2):
    /// the key seed is the first 16 bytes of SHA-1(MRZ information).
    /// </summary>
    /// <param name="mrzInformation">The MRZ information from <see cref="BuildMrzInformation"/>.</param>
    /// <param name="pool">The sensitive-memory pool for the key buffers.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The KEnc and KMAC keys. The caller owns and disposes both.</returns>
    public static async ValueTask<(SymmetricKeyMemory EncryptionKey, SymmetricKeyMemory MacKey)> DeriveAccessKeysAsync(
        string mrzInformation,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(mrzInformation);
        ArgumentNullException.ThrowIfNull(pool);

        //The MRZ information is the BAC access secret.
        using IMemoryOwner<byte> mrzBytes = pool.Rent(Encoding.ASCII.GetByteCount(mrzInformation), AllocationKind.Pinned);
        Encoding.ASCII.GetBytes(mrzInformation, mrzBytes.Memory.Span);

        using DigestValue seedHash = await ComputeSha1Async(mrzBytes.Memory, pool, cancellationToken).ConfigureAwait(false);

        return await DeriveKeyPairAsync(seedHash.AsReadOnlyMemory()[..KeyLength], pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Performs the BAC mutual authentication with the chip and establishes the Secure Messaging session
    /// (Appendix D.3).
    /// </summary>
    /// <param name="device">The card device to exchange APDUs with.</param>
    /// <param name="encryptionKey">The KEnc access key from <see cref="DeriveAccessKeysAsync"/>. Borrowed, not disposed.</param>
    /// <param name="macKey">The KMAC access key from <see cref="DeriveAccessKeysAsync"/>. Borrowed, not disposed.</param>
    /// <param name="terminalNonce">The 8-byte terminal random RND.IFD, sourced from the entropy provider.</param>
    /// <param name="terminalKeyingMaterial">The 16-byte terminal keying material KIFD, sourced from the entropy provider.</param>
    /// <param name="pool">The sensitive-memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The established <see cref="SecureMessagingSession"/>. The caller disposes it.</returns>
    /// <exception cref="InvalidOperationException">Thrown on a card or transport error, a failed MAC, or a nonce mismatch.</exception>
    public static async ValueTask<SecureMessagingSession> EstablishSessionAsync(
        ApduDevice device,
        SymmetricKeyMemory encryptionKey,
        SymmetricKeyMemory macKey,
        ReadOnlyMemory<byte> terminalNonce,
        ReadOnlyMemory<byte> terminalKeyingMaterial,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(encryptionKey);
        ArgumentNullException.ThrowIfNull(macKey);
        ArgumentNullException.ThrowIfNull(pool);

        if(terminalNonce.Length != NonceLength)
        {
            throw new ArgumentException($"RND.IFD must be {NonceLength} bytes.", nameof(terminalNonce));
        }

        if(terminalKeyingMaterial.Length != KeyingMaterialLength)
        {
            throw new ArgumentException($"KIFD must be {KeyingMaterialLength} bytes.", nameof(terminalKeyingMaterial));
        }

        using GetChallengeResponse chipNonce = await RequestChallengeAsync(device, pool, cancellationToken).ConfigureAwait(false);

        //The terminal token is EIFD || MIFD where EIFD = E(KEnc, RND.IFD || RND.IC || KIFD).
        using Ciphertext terminalCryptogram = await ComputeTerminalCryptogramAsync(
            encryptionKey, terminalNonce, chipNonce.AsReadOnlyMemory(), terminalKeyingMaterial, pool, cancellationToken).ConfigureAwait(false);
        using MacValue terminalMac = await ComputeRetailMacAsync(macKey, terminalCryptogram.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);

        using ExternalAuthenticateResponse response = await ExchangeAuthenticationAsync(
            device, terminalCryptogram, terminalMac, pool, cancellationToken).ConfigureAwait(false);

        //The chip's response is EIC || MIC. Verify the MAC, then decrypt and check the echoed nonce.
        ReadOnlyMemory<byte> responseBytes = response.AsReadOnlyMemory();
        ReadOnlyMemory<byte> chipCryptogram = responseBytes[..(responseBytes.Length - BlockSize)];
        ReadOnlyMemory<byte> chipMac = responseBytes[(responseBytes.Length - BlockSize)..];

        await VerifyChipMacAsync(macKey, chipCryptogram, chipMac, pool, cancellationToken).ConfigureAwait(false);

        using DecryptedContent decoded = await DecryptChipResponseAsync(encryptionKey, chipCryptogram, pool, cancellationToken).ConfigureAwait(false);

        //R = RND.IC || RND.IFD || KIC. The echoed RND.IFD must match what the terminal sent.
        if(!CryptographicOperations.FixedTimeEquals(decoded.AsReadOnlySpan().Slice(NonceLength, NonceLength), terminalNonce.Span))
        {
            throw new InvalidOperationException(
                "BAC mutual authentication failed: the chip did not echo the terminal nonce RND.IFD.");
        }

        return await BuildSessionAsync(
            terminalKeyingMaterial, decoded.AsReadOnlyMemory().Slice(2 * NonceLength, KeyingMaterialLength),
            chipNonce.AsReadOnlyMemory(), terminalNonce, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Issues GET CHALLENGE and returns the 8-byte chip nonce RND.IC.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the GetChallengeResponse transfers to the caller, which disposes it.")]
    private static async ValueTask<GetChallengeResponse> RequestChallengeAsync(ApduDevice device, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        ApduResult<GetChallengeResponse> result = await device.GetChallengeAsync(NonceLength, pool, cancellationToken).ConfigureAwait(false);
        if(!result.IsSuccess)
        {
            throw new InvalidOperationException($"BAC GET CHALLENGE failed: {result}.");
        }

        GetChallengeResponse challenge = result.Value;
        if(challenge.Length != NonceLength)
        {
            challenge.Dispose();
            throw new InvalidOperationException($"BAC GET CHALLENGE returned {challenge.Length} bytes, expected {NonceLength}.");
        }

        return challenge;
    }


    /// <summary>
    /// Computes the terminal cryptogram EIFD = E(KEnc, RND.IFD || RND.IC || KIFD), with S held in pinned memory.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned Ciphertext transfers to the caller, which disposes it.")]
    private static async ValueTask<Ciphertext> ComputeTerminalCryptogramAsync(
        SymmetricKeyMemory encryptionKey,
        ReadOnlyMemory<byte> terminalNonce,
        ReadOnlyMemory<byte> chipNonce,
        ReadOnlyMemory<byte> terminalKeyingMaterial,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        //S = RND.IFD || RND.IC || KIFD — a secret because it carries KIFD.
        using IMemoryOwner<byte> s = pool.Rent(2 * NonceLength + KeyingMaterialLength, AllocationKind.Pinned);
        terminalNonce.Span.CopyTo(s.Memory.Span);
        chipNonce.Span.CopyTo(s.Memory.Span[NonceLength..]);
        terminalKeyingMaterial.Span.CopyTo(s.Memory.Span[(2 * NonceLength)..]);

        SymmetricEncryptDelegate encrypt = Resolve<SymmetricEncryptDelegate>();
        using IMemoryOwner<byte> zeroIv = pool.Rent(BlockSize);
        (Ciphertext cryptogram, _) = await encrypt(
            s.Memory, encryptionKey.AsReadOnlyMemory(), zeroIv.Memory, CryptoTags.TripleDesCbc, pool, null, cancellationToken).ConfigureAwait(false);

        return cryptogram;
    }


    /// <summary>
    /// Sends EXTERNAL AUTHENTICATE with the terminal token EIFD || MIFD and returns the chip's response EIC || MIC.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the ExternalAuthenticateResponse transfers to the caller, which disposes it.")]
    private static async ValueTask<ExternalAuthenticateResponse> ExchangeAuthenticationAsync(
        ApduDevice device, Ciphertext terminalCryptogram, MacValue terminalMac, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        int macLength = terminalMac.AsReadOnlySpan().Length;
        int tokenLength = terminalCryptogram.Length + macLength;
        using IMemoryOwner<byte> token = pool.Rent(tokenLength);
        terminalCryptogram.AsReadOnlySpan().CopyTo(token.Memory.Span);
        terminalMac.AsReadOnlySpan().CopyTo(token.Memory.Span[terminalCryptogram.Length..]);

        ApduResult<ExternalAuthenticateResponse> result = await device.ExternalAuthenticateAsync(
            token.Memory.Span, tokenLength, pool, cancellationToken).ConfigureAwait(false);
        if(!result.IsSuccess)
        {
            throw new InvalidOperationException($"BAC EXTERNAL AUTHENTICATE failed: {result}.");
        }

        ExternalAuthenticateResponse response = result.Value;
        if(response.Length != tokenLength)
        {
            response.Dispose();
            throw new InvalidOperationException(
                $"BAC EXTERNAL AUTHENTICATE returned {response.Length} bytes, expected {tokenLength}.");
        }

        return response;
    }


    /// <summary>
    /// Verifies the chip's Retail MAC (MIC) over its cryptogram (EIC).
    /// </summary>
    private static async ValueTask VerifyChipMacAsync(
        SymmetricKeyMemory macKey, ReadOnlyMemory<byte> chipCryptogram, ReadOnlyMemory<byte> chipMac,
        BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> padded = pool.Rent(Iso9797Padding.PaddedLength(chipCryptogram.Length, BlockSize));
        Iso9797Padding.Pad(chipCryptogram.Span, BlockSize, padded.Memory.Span);

        VerifyBlockCipherMacDelegate verify = Resolve<VerifyBlockCipherMacDelegate>();
        (bool isValid, _) = await verify(
            padded.Memory, macKey.AsReadOnlyMemory(), chipMac, CryptoTags.RetailMac, pool, null, cancellationToken).ConfigureAwait(false);
        if(!isValid)
        {
            throw new InvalidOperationException("BAC mutual authentication failed: the chip's MAC (MIC) did not verify.");
        }
    }


    /// <summary>
    /// Decrypts the chip cryptogram EIC into R = RND.IC || RND.IFD || KIC, a secret held in pinned memory.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned DecryptedContent transfers to the caller, which disposes it.")]
    private static async ValueTask<DecryptedContent> DecryptChipResponseAsync(
        SymmetricKeyMemory encryptionKey, ReadOnlyMemory<byte> chipCryptogram, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        SymmetricDecryptDelegate decrypt = Resolve<SymmetricDecryptDelegate>();
        using IMemoryOwner<byte> zeroIv = pool.Rent(BlockSize);
        (DecryptedContent decoded, _) = await decrypt(
            chipCryptogram, encryptionKey.AsReadOnlyMemory(), zeroIv.Memory, CryptoTags.TripleDesCbcDecryptedContent, pool, null, cancellationToken).ConfigureAwait(false);
        try
        {
            IMemoryOwner<byte> owner = pool.Rent(decoded.AsReadOnlySpan().Length, AllocationKind.Pinned);
            decoded.AsReadOnlySpan().CopyTo(owner.Memory.Span);

            return new DecryptedContent(owner, CryptoTags.TripleDesCbcDecryptedContent);
        }
        finally
        {
            decoded.Dispose();
        }
    }


    /// <summary>
    /// Derives the session keys from KSeed = KIFD XOR KIC and assembles the session with its initial SSC.
    /// </summary>
    private static async ValueTask<SecureMessagingSession> BuildSessionAsync(
        ReadOnlyMemory<byte> terminalKeyingMaterial,
        ReadOnlyMemory<byte> chipKeyingMaterial,
        ReadOnlyMemory<byte> chipNonce,
        ReadOnlyMemory<byte> terminalNonce,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> sessionSeed = pool.Rent(KeyingMaterialLength, AllocationKind.Pinned);
        XorInto(terminalKeyingMaterial.Span, chipKeyingMaterial.Span, sessionSeed.Memory.Span);

        //SSC = the four low-order bytes of RND.IC followed by the four low-order bytes of RND.IFD.
        using IMemoryOwner<byte> sendSequenceCounter = pool.Rent(BlockSize);
        chipNonce.Span[(NonceLength - 4)..].CopyTo(sendSequenceCounter.Memory.Span);
        terminalNonce.Span[(NonceLength - 4)..].CopyTo(sendSequenceCounter.Memory.Span[4..]);

        (SymmetricKeyMemory sessionEncryptionKey, SymmetricKeyMemory sessionMacKey) =
            await DeriveKeyPairAsync(sessionSeed.Memory, pool, cancellationToken).ConfigureAwait(false);
        try
        {
            return new SecureMessagingSession(sessionEncryptionKey, sessionMacKey, sendSequenceCounter.Memory.Span, SecureMessagingProfile.TripleDes, pool);
        }
        catch
        {
            sessionEncryptionKey.Dispose();
            sessionMacKey.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Writes the byte-wise XOR of <paramref name="left"/> and <paramref name="right"/> into <paramref name="destination"/>.
    /// </summary>
    private static void XorInto(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> destination)
    {
        for(int i = 0; i < destination.Length; i++)
        {
            destination[i] = (byte)(left[i] ^ right[i]);
        }
    }


    /// <summary>
    /// Derives a 3DES key pair (counters 1 and 2) from a 16-byte key seed — the access keys KEnc/KMAC from
    /// the MRZ seed, or the session keys KSenc/KSmac from KSeed = KIFD XOR KIC. Shared by the terminal and
    /// the card side of BAC so both derive identical keys with the same SHA-1 KDF and DES parity adjustment.
    /// </summary>
    /// <param name="keySeed">The 16-byte key seed.</param>
    /// <param name="pool">The sensitive-memory pool for the key buffers.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The encryption key (counter 1) and MAC key (counter 2). The caller owns and disposes both.</returns>
    public static async ValueTask<(SymmetricKeyMemory EncryptionKey, SymmetricKeyMemory MacKey)> DeriveKeyPairAsync(
        ReadOnlyMemory<byte> keySeed, BaseMemoryPool pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        SymmetricKeyMemory encryptionKey = await DeriveKeyAsync(keySeed, counter: 1, CryptoTags.TripleDesCbc, pool, cancellationToken).ConfigureAwait(false);
        try
        {
            SymmetricKeyMemory macKey = await DeriveKeyAsync(keySeed, counter: 2, CryptoTags.RetailMac, pool, cancellationToken).ConfigureAwait(false);

            return (encryptionKey, macKey);
        }
        catch
        {
            encryptionKey.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Derives one 3DES key: SHA-1(keySeed || counter), the first 16 bytes, with DES odd parity adjusted.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented key buffer transfers to the returned SymmetricKeyMemory, which the caller disposes.")]
    private static async ValueTask<SymmetricKeyMemory> DeriveKeyAsync(
        ReadOnlyMemory<byte> keySeed, uint counter, Tag tag, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> derivationInput = pool.Rent(keySeed.Length + sizeof(uint), AllocationKind.Pinned);
        keySeed.Span.CopyTo(derivationInput.Memory.Span);
        BinaryPrimitives.WriteUInt32BigEndian(derivationInput.Memory.Span[keySeed.Length..], counter);

        using DigestValue hash = await ComputeSha1Async(derivationInput.Memory, pool, cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> keyOwner = pool.Rent(KeyLength, AllocationKind.Pinned);
        try
        {
            hash.AsReadOnlySpan()[..KeyLength].CopyTo(keyOwner.Memory.Span);
            AdjustDesParity(keyOwner.Memory.Span);

            return new SymmetricKeyMemory(keyOwner, tag);
        }
        catch
        {
            keyOwner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Computes a SHA-1 digest through the registered digest delegate into a pinned <see cref="DigestValue"/>.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned DigestValue transfers to the caller, which disposes it.")]
    private static async ValueTask<DigestValue> ComputeSha1Async(
        ReadOnlyMemory<byte> input, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        ComputeDigestDelegate digest = CryptographicKeyFactory.GetFunction<ComputeDigestDelegate>(typeof(ComputeDigestDelegate))
            ?? throw new InvalidOperationException("No ComputeDigestDelegate has been registered.");

        (DigestValue value, _) = await digest(
            new ReadOnlySequence<byte>(input), Sha1Length, Sha1DigestTag, pool, null, cancellationToken).ConfigureAwait(false);
        try
        {
            //The SHA-1 seed/key-derivation hashes are secret in BAC, so they are re-homed to pinned memory.
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
    /// Computes an 8-byte Retail MAC over <paramref name="data"/> with ISO 9797-1 method 2 padding applied.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned MacValue transfers to the caller, which disposes it.")]
    private static async ValueTask<MacValue> ComputeRetailMacAsync(
        SymmetricKeyMemory macKey, ReadOnlyMemory<byte> data, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> padded = pool.Rent(Iso9797Padding.PaddedLength(data.Length, BlockSize));
        Iso9797Padding.Pad(data.Span, BlockSize, padded.Memory.Span);

        ComputeBlockCipherMacDelegate computeMac = Resolve<ComputeBlockCipherMacDelegate>();
        (MacValue mac, _) = await computeMac(
            padded.Memory, macKey.AsReadOnlyMemory(), BlockSize, CryptoTags.RetailMac, pool, null, cancellationToken).ConfigureAwait(false);

        return mac;
    }


    /// <summary>
    /// Adjusts each byte of <paramref name="key"/> to odd parity by flipping the low bit when needed,
    /// as DES keys require.
    /// </summary>
    private static void AdjustDesParity(Span<byte> key)
    {
        for(int i = 0; i < key.Length; i++)
        {
            if((BitOperations.PopCount(key[i]) & 1) == 0)
            {
                key[i] ^= 0x01;
            }
        }
    }


    /// <summary>
    /// Resolves a registered symmetric delegate or throws.
    /// </summary>
    private static TDelegate Resolve<TDelegate>() where TDelegate: Delegate =>
        CryptographicKeyFactory.GetFunction<TDelegate>(typeof(TDelegate))
            ?? throw new InvalidOperationException($"No {typeof(TDelegate).Name} has been registered.");
}