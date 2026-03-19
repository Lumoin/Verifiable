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
/// This implementation supports a single hash round, which covers all practical key
/// lengths up to the hash output size (256 bits for SHA-256). The counter is always 1.
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
    /// The required output key length in bits. Must be a positive multiple of 8 and
    /// must not exceed the SHA-256 output size of 256 bits.
    /// </param>
    /// <param name="pool">Memory pool for all intermediate and output allocations.</param>
    /// <returns>
    /// The derived <see cref="ContentEncryptionKey"/> of exactly
    /// <paramref name="keydataLenBits"/> / 8 bytes. The caller must dispose
    /// it immediately after use — disposal zeroes the underlying memory.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="keydataLenBits"/> is not a positive multiple of 8
    /// or exceeds 256.
    /// </exception>
    public static ContentEncryptionKey Derive(
        ReadOnlySpan<byte> sharedSecret,
        string algorithmId,
        ReadOnlySpan<byte> partyUInfo,
        ReadOnlySpan<byte> partyVInfo,
        int keydataLenBits,
        MemoryPool<byte> pool)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithmId);
        ArgumentNullException.ThrowIfNull(pool);

        if(keydataLenBits <= 0 || keydataLenBits > 256 || keydataLenBits % 8 != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(keydataLenBits),
                $"keydataLenBits must be a positive multiple of 8 and must not exceed 256. " +
                $"Received {keydataLenBits}.");
        }

        int algIdByteCount = Encoding.ASCII.GetByteCount(algorithmId);

        //Hash input layout per NIST SP 800-56A §5.8.1.1:
        //4 (counter) | Z | 4 len(AlgID) AlgID | 4 len(apu) apu | 4 len(apv) apv | 4 (keydataLen)
        int hashInputLength =
            4
            + sharedSecret.Length
            + 4 + algIdByteCount
            + 4 + partyUInfo.Length
            + 4 + partyVInfo.Length
            + 4;

        using IMemoryOwner<byte> hashInputOwner = pool.Rent(hashInputLength);
        Span<byte> hashInput = hashInputOwner.Memory.Span[..hashInputLength];
        hashInput.Clear();

        int offset = 0;

        //Counter = 1 in big-endian 32-bit.
        BinaryPrimitives.WriteInt32BigEndian(hashInput[offset..], 1);
        offset += 4;

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

        using IMemoryOwner<byte> digestOwner = pool.Rent(SHA256.HashSizeInBytes);
        SHA256.HashData(hashInput, digestOwner.Memory.Span);
        hashInput.Clear();

        int outputByteLength = keydataLenBits / 8;
        IMemoryOwner<byte> outputOwner = pool.Rent(outputByteLength);
        digestOwner.Memory.Span[..outputByteLength].CopyTo(outputOwner.Memory.Span);
        digestOwner.Memory.Span.Clear();

        return new ContentEncryptionKey(outputOwner, CryptoTags.AesGcmCek);
    }


    /// <summary>
    /// A <see cref="Verifiable.Cryptography.Aead.KeyDerivationDelegate"/> that wraps
    /// <see cref="Derive"/> using SHA-256 Concat KDF.
    /// </summary>
    /// <remarks>
    /// Pass this to <see cref="Verifiable.Cryptography.Aead.KeyAgreementFunctionRegistry{T1,T2}.Initialize"/>
    /// as the KDF matcher for ECDH-ES flows.
    /// </remarks>
    public static Verifiable.Cryptography.Aead.KeyDerivationDelegate DefaultKeyDerivationDelegate =>
        static (sharedSecret, algorithmId, partyUInfo, partyVInfo, keydataLenBits, pool) =>
            Derive(sharedSecret.AsReadOnlySpan(), algorithmId, partyUInfo, partyVInfo, keydataLenBits, pool);
}
