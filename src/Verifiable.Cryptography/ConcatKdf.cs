using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Cryptography.Aead;

namespace Verifiable.Cryptography;

/// <summary>
/// Concat KDF (single-step key derivation function) as specified in
/// <see href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf">NIST SP 800-56A §5.8.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// Derives keying material from a shared secret and a set of fixed-length info fields.
/// Used wherever a shared secret from ECDH key agreement or KEM decapsulation must be
/// turned into a symmetric key of a specific length.
/// </para>
/// <para>
/// This implementation performs the multi-round single-step KDF of NIST SP 800-56A §5.8.1.1:
/// for <c>reps = ceil(keydatalen / hashlen)</c> rounds the digest of
/// <c>counter || Z || OtherInfo</c> is computed with the counter running 1..reps as a 32-bit
/// big-endian integer, the round outputs are concatenated, and the result is truncated to
/// <c>keydatalen</c>. When the requested length fits in one hash output the loop runs once with
/// counter 1, so the derivation is byte identical to the single-round JOSE profile of
/// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.6.2">RFC 7518 §4.6.2</see> for
/// the common ≤256-bit ECDH-ES key lengths.
/// </para>
/// <para>
/// The JOSE profile
/// (<see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.6.2">RFC 7518 §4.6.2</see>)
/// uses SHA-256, sets <c>algorithmId</c> to the JWE <c>enc</c> value, and passes empty
/// byte strings for <c>partyUInfo</c> and <c>partyVInfo</c>. Callers supply those values
/// directly — this function has no knowledge of JOSE or JWE.
/// </para>
/// <para>
/// All intermediate allocations come from the supplied <see cref="MemoryPool{T}"/> and
/// are zeroed before disposal. The returned owner must also be zeroed and disposed by
/// the caller immediately after use.
/// </para>
/// </remarks>
public static class ConcatKdf
{
    /// <summary>
    /// Derives keying material from a shared secret using a single-round SHA-256 Concat KDF.
    /// </summary>
    /// <param name="sharedSecret">
    /// The shared secret Z, encoded as a fixed-length unsigned big-endian integer.
    /// For ECDH this is the x-coordinate of the shared EC point. For ML-KEM this is
    /// the 32-byte decapsulation output.
    /// </param>
    /// <param name="algorithmId">
    /// The algorithm identifier string, length-prefixed as required by NIST SP 800-56A.
    /// In the JOSE profile this is the JWE <c>enc</c> value, e.g. <c>A128GCM</c>.
    /// </param>
    /// <param name="partyUInfo">
    /// Producer info bytes. Pass an empty span when no party info is used, as in the
    /// JOSE profile per RFC 7518 §4.6.2.
    /// </param>
    /// <param name="partyVInfo">
    /// Recipient info bytes. Pass an empty span when no party info is used, as in the
    /// JOSE profile per RFC 7518 §4.6.2.
    /// </param>
    /// <param name="keydataLenBits">
    /// The required output key length in bits. Must be a positive multiple of 8. Lengths
    /// larger than the SHA-256 output size use the multi-round derivation of NIST SP 800-56A
    /// §5.8.1.1.
    /// </param>
    /// <param name="pool">Memory pool for all intermediate and output allocations.</param>
    /// <returns>
    /// The derived <see cref="ContentEncryptionKey"/> of exactly
    /// <paramref name="keydataLenBits"/> / 8 bytes. The caller must dispose
    /// it immediately after use — disposal zeroes the underlying memory.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="keydataLenBits"/> is not a positive multiple of 8.
    /// </exception>
    public static ContentEncryptionKey Derive(
        ReadOnlySpan<byte> sharedSecret,
        string algorithmId,
        ReadOnlySpan<byte> partyUInfo,
        ReadOnlySpan<byte> partyVInfo,
        int keydataLenBits,
        MemoryPool<byte> pool) =>
        Derive(sharedSecret, algorithmId, partyUInfo, partyVInfo, keydataLenBits,
            committedTag: [], CryptoTags.AesGcmCek, pool);


    /// <summary>
    /// Derives keying material using a single-round SHA-256 Concat KDF with an
    /// optional authentication tag commitment per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04#section-2.3">draft-madden-jose-ecdh-1pu-04 §2.3</see>.
    /// </summary>
    /// <param name="sharedSecret">
    /// The shared secret Z. For ECDH-1PU this is the concatenation Ze || Zs per
    /// NIST SP 800-56A §6.2.1.2.
    /// </param>
    /// <param name="algorithmId">
    /// The algorithm identifier string. In Key Agreement with Key Wrapping mode the
    /// JWE <c>alg</c> value, e.g. <c>ECDH-1PU+A256KW</c>; otherwise the <c>enc</c> value.
    /// </param>
    /// <param name="partyUInfo">Producer info bytes, empty when no party info is used.</param>
    /// <param name="partyVInfo">Recipient info bytes, empty when no party info is used.</param>
    /// <param name="keydataLenBits">
    /// The required output key length in bits. Must be a positive multiple of 8. Lengths
    /// larger than the SHA-256 output size of 256 bits are produced by the multi-round
    /// derivation of NIST SP 800-56A §5.8.1.1 — for example a 512-bit composite key for the
    /// A256CBC-HS512 content encryption algorithm.
    /// </param>
    /// <param name="committedTag">
    /// The JWE Authentication Tag octets appended to SuppPubInfo as a length-prefixed
    /// cctag in ECDH-1PU Key Agreement with Key Wrapping mode. Pass an empty span for
    /// Direct Key Agreement mode and for ECDH-ES, where cctag is absent — the hash
    /// input is then byte identical to the RFC 7518 §4.6.2 layout.
    /// </param>
    /// <param name="outputTag">
    /// The <see cref="Tag"/> applied to the derived key — a key encryption key tag
    /// such as <see cref="CryptoTags.AesKwKeyEncryptionKey"/> in Key Agreement with
    /// Key Wrapping mode, a content encryption key tag otherwise.
    /// </param>
    /// <param name="pool">Memory pool for all intermediate and output allocations.</param>
    /// <returns>
    /// The derived <see cref="ContentEncryptionKey"/> of exactly
    /// <paramref name="keydataLenBits"/> / 8 bytes. The caller must dispose
    /// it immediately after use — disposal zeroes the underlying memory.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="keydataLenBits"/> is not a positive multiple of 8.
    /// </exception>
    public static ContentEncryptionKey Derive(
        ReadOnlySpan<byte> sharedSecret,
        string algorithmId,
        ReadOnlySpan<byte> partyUInfo,
        ReadOnlySpan<byte> partyVInfo,
        int keydataLenBits,
        ReadOnlySpan<byte> committedTag,
        Tag outputTag,
        MemoryPool<byte> pool)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithmId);
        ArgumentNullException.ThrowIfNull(outputTag);
        ArgumentNullException.ThrowIfNull(pool);

        if(keydataLenBits <= 0 || keydataLenBits % 8 != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(keydataLenBits),
                $"keydataLenBits must be a positive multiple of 8. Received {keydataLenBits}.");
        }

        int algIdByteCount = Encoding.ASCII.GetByteCount(algorithmId);

        //Hash input layout per NIST SP 800-56A §5.8.1.1:
        //4 (counter) | Z | 4 len(AlgID) AlgID | 4 len(apu) apu | 4 len(apv) apv | 4 (keydataLen)
        //followed in ECDH-1PU Key Agreement with Key Wrapping mode by the cctag,
        //itself of the form 4 len(tag) | tag, completing SuppPubInfo = keydatalen || cctag.
        //Only the leading counter changes between rounds; the rest of the buffer is fixed.
        int hashInputLength =
            4
            + sharedSecret.Length
            + 4 + algIdByteCount
            + 4 + partyUInfo.Length
            + 4 + partyVInfo.Length
            + 4
            + (committedTag.IsEmpty ? 0 : 4 + committedTag.Length);

        using IMemoryOwner<byte> hashInputOwner = pool.Rent(hashInputLength);
        Span<byte> hashInput = hashInputOwner.Memory.Span[..hashInputLength];
        hashInput.Clear();

        //Write everything after the counter once: Z, then OtherInfo.
        int offset = 4;

        sharedSecret.CopyTo(hashInput[offset..]);
        offset += sharedSecret.Length;

        BinaryPrimitives.WriteInt32BigEndian(hashInput[offset..], algIdByteCount);
        offset += 4;
        Encoding.ASCII.GetBytes(algorithmId, hashInput[offset..]);
        offset += algIdByteCount;

        BinaryPrimitives.WriteInt32BigEndian(hashInput[offset..], partyUInfo.Length);
        offset += 4;
        partyUInfo.CopyTo(hashInput[offset..]);
        offset += partyUInfo.Length;

        BinaryPrimitives.WriteInt32BigEndian(hashInput[offset..], partyVInfo.Length);
        offset += 4;
        partyVInfo.CopyTo(hashInput[offset..]);
        offset += partyVInfo.Length;

        BinaryPrimitives.WriteInt32BigEndian(hashInput[offset..], keydataLenBits);
        offset += 4;

        if(!committedTag.IsEmpty)
        {
            BinaryPrimitives.WriteInt32BigEndian(hashInput[offset..], committedTag.Length);
            offset += 4;
            committedTag.CopyTo(hashInput[offset..]);
        }

        int outputByteLength = keydataLenBits / 8;

        //NIST SP 800-56A §5.8.1.1: reps = ceil(keydatalen / hashlen). When the requested
        //length fits in one SHA-256 output the loop runs exactly once with counter 1, byte
        //identical to the single-round RFC 7518 §4.6.2 derivation.
        int reps = (outputByteLength + SHA256.HashSizeInBytes - 1) / SHA256.HashSizeInBytes;

        IMemoryOwner<byte> outputOwner = pool.Rent(outputByteLength);

        try
        {
            int copied = 0;

            for(int counter = 1; counter <= reps; ++counter)
            {
                BinaryPrimitives.WriteInt32BigEndian(hashInput[..4], counter);

                //Hash through the registered ComputeDigestDelegate so Concat KDF picks up
                //the same observability and CBOM provenance stamping as every other digest.
                //ConcatKdf.Derive is sync (pure mathematics, no I/O); the sync bridge
                //asserts the underlying delegate completed synchronously (true for the
                //Microsoft software backend) and throws if a hardware-async backend is
                //registered.
                using DigestValue digest = CryptographicKeyEvents.ComputeDigestSyncBridge(
                    hashInputOwner.Memory[..hashInputLength],
                    SHA256.HashSizeInBytes,
                    CryptoTags.Sha256Digest,
                    pool);

                int take = Math.Min(SHA256.HashSizeInBytes, outputByteLength - copied);
                digest.AsReadOnlySpan()[..take].CopyTo(outputOwner.Memory.Span[copied..]);
                copied += take;
            }
        }
        catch
        {
            //A failing hash round (e.g. a hardware-async backend rejected by the sync bridge)
            //must not leak partially derived key material in the rented buffer.
            outputOwner.Memory.Span[..outputByteLength].Clear();
            outputOwner.Dispose();
            throw;
        }
        finally
        {
            hashInput.Clear();
        }

        //Build the inner SymmetricKeyMemory first, then wrap it in the
        //single-use ContentEncryptionKey wrapper that AEAD consumers unwrap via UseKey().
        SymmetricKeyMemory inner = new(outputOwner, outputTag);
        return new ContentEncryptionKey(inner);
    }


    /// <summary>
    /// A <see cref="Verifiable.Cryptography.Aead.KeyDerivationDelegate"/> that wraps
    /// <see cref="Derive(ReadOnlySpan{byte}, string, ReadOnlySpan{byte}, ReadOnlySpan{byte}, int, MemoryPool{byte})"/>
    /// using SHA-256 Concat KDF.
    /// </summary>
    /// <remarks>
    /// Pass this to <see cref="Verifiable.Cryptography.Aead.KeyAgreementFunctionRegistry{T1,T2}.Initialize"/>
    /// as the KDF matcher for ECDH-ES flows.
    /// </remarks>
    public static Verifiable.Cryptography.Aead.KeyDerivationDelegate DefaultKeyDerivationDelegate =>
        static (sharedSecret, algorithmId, partyUInfo, partyVInfo, keydataLenBits, pool) =>
            Derive(sharedSecret.AsReadOnlySpan(), algorithmId, partyUInfo, partyVInfo, keydataLenBits, pool);


    /// <summary>
    /// A <see cref="Verifiable.Cryptography.Aead.AuthenticatedKeyDerivationDelegate"/>
    /// that wraps <see cref="Derive(ReadOnlySpan{byte}, string, ReadOnlySpan{byte}, ReadOnlySpan{byte}, int, ReadOnlySpan{byte}, Tag, MemoryPool{byte})"/>
    /// using SHA-256 Concat KDF with the ECDH-1PU authentication tag commitment.
    /// </summary>
    /// <remarks>
    /// The derived key is tagged <see cref="CryptoTags.AesKwKeyEncryptionKey"/> — the
    /// Key Agreement with Key Wrapping shape used by <c>ECDH-1PU+A256KW</c>. Direct
    /// Key Agreement callers derive their content encryption key through
    /// <see cref="Derive(ReadOnlySpan{byte}, string, ReadOnlySpan{byte}, ReadOnlySpan{byte}, int, ReadOnlySpan{byte}, Tag, MemoryPool{byte})"/>
    /// with an empty tag and their own output tag.
    /// </remarks>
    public static Verifiable.Cryptography.Aead.AuthenticatedKeyDerivationDelegate DefaultAuthenticatedKeyDerivationDelegate =>
        static (sharedSecret, algorithmId, partyUInfo, partyVInfo, keydataLenBits, committedTag, pool) =>
            Derive(sharedSecret.AsReadOnlySpan(), algorithmId, partyUInfo, partyVInfo, keydataLenBits,
                committedTag, CryptoTags.AesKwKeyEncryptionKey, pool);
}
