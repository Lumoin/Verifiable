using System;
using System.Buffers;
using Verifiable.Cryptography;

namespace Verifiable.Core.Did.Methods.WebVh;

/// <summary>
/// The did:webvh hash primitive shared by the SCID, the entryHash and the pre-rotation key hashes:
/// <c>base58btc(multihash(input, SHA-256))</c>.
/// </summary>
/// <remarks>
/// <para>
/// did:webvh v1.0 fixes the hash to SHA-256 and encodes the multihash bytes with <strong>raw</strong>
/// base58btc — there is no multibase <c>z</c> prefix (unlike a did:key / did:peer multikey, which is a
/// multibase string). A SHA-256 multihash always renders to a base58btc string beginning with <c>Qm</c>.
/// </para>
/// <para>
/// The input is the bytes whose hash is taken: the JCS-canonical log entry for the SCID and the entryHash,
/// or the UTF-8 multikey string for a pre-rotation key hash.
/// </para>
/// </remarks>
internal static class WebVhHash
{
    //did:webvh v1.0 permits only SHA-256; the multihash is varint(0x12) || varint(0x20) || 32-byte digest.
    private const int Sha256DigestLength = 32;


    /// <summary>
    /// Computes <c>base58btc(multihash(input, SHA-256))</c> for the given input bytes, taking the SHA-256 digest
    /// through the supplied <see cref="ComputeDigestDelegate"/> — and so its telemetry, CBOM stamping and event
    /// emission — by awaiting <see cref="CryptographicKeyEvents.ComputeDigestAsync(ComputeDigestDelegate, System.Buffers.ReadOnlySequence{byte}, int, Tag, MemoryPool{byte}, System.Collections.Frozen.FrozenDictionary{string, object}, System.Threading.CancellationToken)"/>,
    /// so a hardware-async digest backend (TPM2_Hash, KMS) works as well as a synchronously-completing software one.
    /// </summary>
    /// <param name="input">The bytes to hash.</param>
    /// <param name="computeDigest">The digest implementation the verification was built with (caller-supplied or the registered default).</param>
    /// <param name="base58Encoder">The raw base58btc encoder, which produces no multibase prefix.</param>
    /// <param name="pool">The pool the digest input and output buffers are rented from.</param>
    /// <param name="cancellationToken">Cancels an in-flight digest on a hardware-async backend (TPM2_Hash, KMS).</param>
    /// <returns>The base58btc-encoded SHA-256 multihash string.</returns>
    public static async ValueTask<string> ComputeBase58Async(ReadOnlyMemory<byte> input, ComputeDigestDelegate computeDigest, EncodeDelegate base58Encoder, MemoryPool<byte> pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(base58Encoder);
        ArgumentNullException.ThrowIfNull(pool);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            computeDigest, new ReadOnlySequence<byte>(input), Sha256DigestLength, CryptoTags.Sha256Digest, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return EncodeMultihash(digest.AsReadOnlySpan(), base58Encoder);

        //The multihash assembly is a pure-compute span operation with no seam; kept in a synchronous local so no
        //ref struct (the stackalloc buffer) is live across the await above.
        static string EncodeMultihash(ReadOnlySpan<byte> digest, EncodeDelegate base58Encoder)
        {
            ReadOnlySpan<byte> sha256Code = MultihashHeaders.Sha2Bits256;
            Span<byte> multihash = stackalloc byte[sha256Code.Length + 1 + Sha256DigestLength];
            sha256Code.CopyTo(multihash);
            multihash[sha256Code.Length] = Sha256DigestLength;
            digest.CopyTo(multihash[(sha256Code.Length + 1)..]);

            return base58Encoder(multihash);
        }
    }


    /// <summary>
    /// Whether a base58btc-encoded multihash string carries the SHA-256 multihash header fixed by
    /// did:webvh v1.0: <c>varint(0x12)</c> (sha2-256) followed by <c>varint(0x20)</c> (the 32-byte length),
    /// then a 32-byte digest.
    /// </summary>
    /// <remarks>
    /// did:webvh v1.0 permits only SHA-256, and the multihash format is self-describing, so a claimed hash
    /// whose algorithm prefix is not sha2-256 is rejected by algorithm — not only by a recomputed-value
    /// mismatch (did:webvh v1.0, Cryptographic Agility: "Hashes use the Multihash format … verifiers
    /// determine the algorithm from the data itself"). An undecodable string is treated as a non-conforming
    /// (non-SHA-256) multihash.
    /// </remarks>
    /// <param name="base58Multihash">The base58btc-encoded multihash string (no multibase prefix).</param>
    /// <param name="base58Decoder">The raw base58btc decoder.</param>
    /// <param name="pool">The pool the decoded multihash bytes are rented from.</param>
    /// <returns><see langword="true"/> when the string decodes to a SHA-256 multihash of the correct length.</returns>
    public static bool IsSha256Multihash(string base58Multihash, DecodeDelegate base58Decoder, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(base58Decoder);
        ArgumentNullException.ThrowIfNull(pool);

        if(string.IsNullOrEmpty(base58Multihash))
        {
            return false;
        }

        ReadOnlySpan<byte> sha256Code = MultihashHeaders.Sha2Bits256;
        int expectedLength = sha256Code.Length + 1 + Sha256DigestLength;

        try
        {
            using IMemoryOwner<byte> decoded = base58Decoder(base58Multihash, pool);
            ReadOnlySpan<byte> bytes = decoded.Memory.Span;

            return bytes.Length == expectedLength
                && bytes[..sha256Code.Length].SequenceEqual(sha256Code)
                && bytes[sha256Code.Length] == Sha256DigestLength;
        }
        catch(Exception exception) when(exception is FormatException or ArgumentException)
        {
            return false;
        }
    }
}
