using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Apdu.SecureMessaging;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

namespace Verifiable.Apdu.Bac;

/// <summary>
/// The card side of ICAO Doc 9303 Part 11 Basic Access Control — the inverse of
/// <see cref="BasicAccessControl"/>. Given the access keys derived from the chip's own MRZ, the chip nonce
/// RND.IC it already issued (via GET CHALLENGE), and the terminal's EXTERNAL AUTHENTICATE token, it
/// authenticates the terminal and returns the card's response token, establishing the 3DES
/// <see cref="SecureMessagingCardSession"/>.
/// </summary>
/// <remarks>
/// <para>
/// The terminal proves it knows the MRZ by sending <c>EIFD || MIFD</c>; the card verifies the MAC, decrypts
/// to recover <c>RND.IFD || RND.IC || KIFD</c>, checks the chip nonce it issued was echoed, then answers
/// with <c>EIC || MIC</c> where <c>EIC = E(KEnc, RND.IC || RND.IFD || KIC)</c>. Both sides then derive the
/// session keys from <c>KSeed = KIFD XOR KIC</c> and the initial send-sequence counter from the two nonces
/// (Appendix D.3), so the card and the terminal hold matching Secure Messaging sessions. A standalone
/// counterpart to <see cref="SecureMessagingCardSession"/>: it composes the registered provider delegates
/// and reuses the direction-neutral key derivations of <see cref="BasicAccessControl"/>, and owns no
/// cryptography of its own. The chip keying material KIC and the issued RND.IC are supplied by the caller —
/// from the card's RNG in production, injected in tests.
/// </para>
/// </remarks>
public static class BasicAccessControlCardResponder
{
    /// <summary>The 3DES cipher block size — the alignment unit for padding, the SSC, and the IV.</summary>
    private const int BlockSize = 8;

    /// <summary>The byte length of RND.IC and RND.IFD.</summary>
    private const int NonceLength = 8;

    /// <summary>The byte length of KIFD and KIC.</summary>
    private const int KeyingMaterialLength = 16;


    /// <summary>
    /// Authenticates the terminal's EXTERNAL AUTHENTICATE token and establishes the card Secure Messaging session.
    /// </summary>
    /// <param name="encryptionKey">The access key KEnc derived from the chip's MRZ. Borrowed, not disposed.</param>
    /// <param name="macKey">The access key KMAC derived from the chip's MRZ. Borrowed, not disposed.</param>
    /// <param name="chipNonce">The chip nonce RND.IC the card issued in the preceding GET CHALLENGE (8 bytes).</param>
    /// <param name="chipKeyingMaterial">The chip keying material KIC, from the card's RNG (16 bytes).</param>
    /// <param name="terminalToken">The terminal's authentication token <c>EIFD || MIFD</c> (40 bytes).</param>
    /// <param name="pool">The sensitive-memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The card's response token <c>EIC || MIC</c> (public wire bytes) and the established <see cref="SecureMessagingCardSession"/>. The caller owns and disposes both.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the terminal's MAC does not verify or the chip nonce was not echoed.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the response token and the session transfers to the caller; the session keys are disposed on a failure path.")]
    public static async ValueTask<(IMemoryOwner<byte> ResponseToken, SecureMessagingCardSession Session)> EstablishSessionAsync(
        SymmetricKeyMemory encryptionKey,
        SymmetricKeyMemory macKey,
        ReadOnlyMemory<byte> chipNonce,
        ReadOnlyMemory<byte> chipKeyingMaterial,
        ReadOnlyMemory<byte> terminalToken,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(encryptionKey);
        ArgumentNullException.ThrowIfNull(macKey);
        ArgumentNullException.ThrowIfNull(pool);

        if(chipNonce.Length != NonceLength)
        {
            throw new ArgumentException($"RND.IC must be {NonceLength} bytes.", nameof(chipNonce));
        }

        if(chipKeyingMaterial.Length != KeyingMaterialLength)
        {
            throw new ArgumentException($"KIC must be {KeyingMaterialLength} bytes.", nameof(chipKeyingMaterial));
        }

        int expectedTokenLength = 2 * NonceLength + KeyingMaterialLength + BlockSize;
        if(terminalToken.Length != expectedTokenLength)
        {
            throw new ArgumentException($"The terminal token EIFD || MIFD must be {expectedTokenLength} bytes.", nameof(terminalToken));
        }

        //The terminal token is EIFD || MIFD. Verify the MAC, then decrypt and check the echoed nonce.
        ReadOnlyMemory<byte> terminalCryptogram = terminalToken[..(terminalToken.Length - BlockSize)];
        ReadOnlyMemory<byte> terminalMac = terminalToken[(terminalToken.Length - BlockSize)..];

        await VerifyTerminalMacAsync(macKey, terminalCryptogram, terminalMac, pool, cancellationToken).ConfigureAwait(false);

        //S = RND.IFD || RND.IC || KIFD — a secret because it carries KIFD.
        using DecryptedContent decoded = await DecryptAsync(encryptionKey, terminalCryptogram, pool, cancellationToken).ConfigureAwait(false);
        ReadOnlyMemory<byte> terminalNonce = decoded.AsReadOnlyMemory()[..NonceLength];
        ReadOnlyMemory<byte> echoedChipNonce = decoded.AsReadOnlyMemory().Slice(NonceLength, NonceLength);
        ReadOnlyMemory<byte> terminalKeyingMaterial = decoded.AsReadOnlyMemory().Slice(2 * NonceLength, KeyingMaterialLength);

        //The terminal must have echoed the chip nonce RND.IC the card issued.
        if(!CryptographicOperations.FixedTimeEquals(echoedChipNonce.Span, chipNonce.Span))
        {
            throw new InvalidOperationException("BAC mutual authentication failed: the terminal did not echo the chip nonce RND.IC.");
        }

        //The card token is EIC || MIC where EIC = E(KEnc, RND.IC || RND.IFD || KIC).
        IMemoryOwner<byte> responseToken = await BuildResponseTokenAsync(
            encryptionKey, macKey, chipNonce, terminalNonce, chipKeyingMaterial, pool, cancellationToken).ConfigureAwait(false);
        try
        {
            SecureMessagingCardSession session = await BuildSessionAsync(
                terminalKeyingMaterial, chipKeyingMaterial, chipNonce, terminalNonce, pool, cancellationToken).ConfigureAwait(false);

            return (responseToken, session);
        }
        catch
        {
            responseToken.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Verifies the terminal's Retail MAC (MIFD) over its cryptogram (EIFD).
    /// </summary>
    private static async ValueTask VerifyTerminalMacAsync(
        SymmetricKeyMemory macKey, ReadOnlyMemory<byte> terminalCryptogram, ReadOnlyMemory<byte> terminalMac,
        BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> padded = pool.Rent(Iso9797Padding.PaddedLength(terminalCryptogram.Length, BlockSize));
        Iso9797Padding.Pad(terminalCryptogram.Span, BlockSize, padded.Memory.Span);

        VerifyBlockCipherMacDelegate verify = Resolve<VerifyBlockCipherMacDelegate>();
        (bool isValid, _) = await verify(
            padded.Memory, macKey.AsReadOnlyMemory(), terminalMac, CryptoTags.RetailMac, pool, null, cancellationToken).ConfigureAwait(false);
        if(!isValid)
        {
            throw new InvalidOperationException("BAC mutual authentication failed: the terminal's MAC (MIFD) did not verify.");
        }
    }


    /// <summary>
    /// Decrypts the terminal cryptogram EIFD into S = RND.IFD || RND.IC || KIFD, a secret held in pinned memory.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned DecryptedContent transfers to the caller, which disposes it.")]
    private static async ValueTask<DecryptedContent> DecryptAsync(
        SymmetricKeyMemory encryptionKey, ReadOnlyMemory<byte> terminalCryptogram, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        SymmetricDecryptDelegate decrypt = Resolve<SymmetricDecryptDelegate>();
        using IMemoryOwner<byte> zeroIv = pool.Rent(BlockSize);
        (DecryptedContent decoded, _) = await decrypt(
            terminalCryptogram, encryptionKey.AsReadOnlyMemory(), zeroIv.Memory, CryptoTags.TripleDesCbcDecryptedContent, pool, null, cancellationToken).ConfigureAwait(false);
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
    /// Builds the card response token EIC || MIC, where EIC = E(KEnc, RND.IC || RND.IFD || KIC) and MIC is its Retail MAC.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned response-token buffer transfers to the caller, which disposes it.")]
    private static async ValueTask<IMemoryOwner<byte>> BuildResponseTokenAsync(
        SymmetricKeyMemory encryptionKey,
        SymmetricKeyMemory macKey,
        ReadOnlyMemory<byte> chipNonce,
        ReadOnlyMemory<byte> terminalNonce,
        ReadOnlyMemory<byte> chipKeyingMaterial,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        //R = RND.IC || RND.IFD || KIC — a secret because it carries KIC.
        using IMemoryOwner<byte> r = pool.Rent(2 * NonceLength + KeyingMaterialLength, AllocationKind.Pinned);
        chipNonce.Span.CopyTo(r.Memory.Span);
        terminalNonce.Span.CopyTo(r.Memory.Span[NonceLength..]);
        chipKeyingMaterial.Span.CopyTo(r.Memory.Span[(2 * NonceLength)..]);

        SymmetricEncryptDelegate encrypt = Resolve<SymmetricEncryptDelegate>();
        using IMemoryOwner<byte> zeroIv = pool.Rent(BlockSize);
        (Ciphertext chipCryptogram, _) = await encrypt(
            r.Memory, encryptionKey.AsReadOnlyMemory(), zeroIv.Memory, CryptoTags.TripleDesCbc, pool, null, cancellationToken).ConfigureAwait(false);
        try
        {
            using MacValue chipMac = await ComputeRetailMacAsync(macKey, chipCryptogram.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);

            //EIC || MIC is public wire bytes.
            int tokenLength = chipCryptogram.AsReadOnlySpan().Length + chipMac.AsReadOnlySpan().Length;
            IMemoryOwner<byte> token = pool.Rent(tokenLength);
            try
            {
                chipCryptogram.AsReadOnlySpan().CopyTo(token.Memory.Span);
                chipMac.AsReadOnlySpan().CopyTo(token.Memory.Span[chipCryptogram.AsReadOnlySpan().Length..]);

                return token;
            }
            catch
            {
                token.Dispose();

                throw;
            }
        }
        finally
        {
            chipCryptogram.Dispose();
        }
    }


    /// <summary>
    /// Derives the session keys from KSeed = KIFD XOR KIC and assembles the card session with its initial SSC.
    /// </summary>
    private static async ValueTask<SecureMessagingCardSession> BuildSessionAsync(
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
            await BasicAccessControl.DeriveKeyPairAsync(sessionSeed.Memory, pool, cancellationToken).ConfigureAwait(false);
        try
        {
            return new SecureMessagingCardSession(sessionEncryptionKey, sessionMacKey, sendSequenceCounter.Memory.Span, SecureMessagingProfile.TripleDes, pool);
        }
        catch
        {
            sessionEncryptionKey.Dispose();
            sessionMacKey.Dispose();

            throw;
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
    /// Resolves a registered symmetric delegate or throws.
    /// </summary>
    private static TDelegate Resolve<TDelegate>() where TDelegate: Delegate =>
        CryptographicKeyFactory.GetFunction<TDelegate>(typeof(TDelegate))
            ?? throw new InvalidOperationException($"No {typeof(TDelegate).Name} has been registered.");
}
