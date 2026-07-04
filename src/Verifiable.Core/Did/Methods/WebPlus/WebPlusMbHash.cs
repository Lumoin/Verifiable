using System;
using System.Buffers;
using Verifiable.Cryptography;

namespace Verifiable.Core.Did.Methods.WebPlus;

/// <summary>
/// The did:webplus MBHash primitive: a multibase-encoded multihash,
/// <c>multibase(base64url, multihash(code ‖ length ‖ digest))</c>, that backs the <c>selfHash</c> field, the
/// root-self-hash in the DID, and the <c>hashedKey</c> pre-rotation commitment (did:webplus Draft v0.4,
/// MBHash Values).
/// </summary>
/// <remarks>
/// <para>
/// Unlike the did:webvh hash (raw base58btc, SHA-256 only, no multibase prefix), a did:webplus MBHash is a
/// multibase string: a leading <c>u</c> (base64url, RECOMMENDED; base58btc <c>z</c> is also permitted) followed
/// by the base64url encoding of the self-describing multihash. The multihash header names the hash function, so
/// a verifier reads the algorithm from the value itself; BLAKE3 is the default (<see cref="MultihashHeaders.Blake3"/>).
/// </para>
/// <para>
/// The digest is supplied by the caller as a <see cref="ComputeDigestDelegate"/> (or the registered default) — the library does not pin
/// one — so the same primitive serves every MUST-support algorithm. This is the cousin of
/// <c>WebVhHash</c> and a candidate to be generalized into the shared SAID primitive once KERI/ACDC land.
/// </para>
/// </remarks>
internal static class WebPlusMbHash
{
    /// <summary>
    /// Computes the MBHash <c>u·base64url(multihash(hashFunction(input)))</c> for the given input bytes and
    /// multihash code.
    /// </summary>
    /// <param name="input">The bytes whose hash is taken (for a self-hash, the JCS form with self-hash slots set to the placeholder).</param>
    /// <param name="multihashCode">The multihash code naming the hash function, e.g. <see cref="MultihashHeaders.Blake3"/> or <see cref="MultihashHeaders.Sha2Bits256"/>.</param>
    /// <param name="digestLength">The digest length in bytes (e.g. 32 for a 256-bit hash).</param>
    /// <param name="computeDigest">The digest implementation (caller-supplied or the registered default) matching the algorithm named by <paramref name="multihashCode"/>.</param>
    /// <param name="digestTag">The digest tag naming that algorithm for the seam, e.g. <see cref="CryptoTags.Blake3Digest"/>.</param>
    /// <param name="base64UrlEncoder">The base64url (no padding) encoder; the <c>u</c> multibase prefix is prepended by this method.</param>
    /// <param name="pool">The pool used for any non-stack temporary buffer.</param>
    /// <param name="cancellationToken">Cancels an in-flight digest on a hardware-async backend (TPM2_Hash, KMS).</param>
    /// <returns>The MBHash string.</returns>
    public static async ValueTask<string> ComputeAsync(
        ReadOnlyMemory<byte> input,
        ReadOnlyMemory<byte> multihashCode,
        int digestLength,
        ComputeDigestDelegate computeDigest,
        Tag digestTag,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(digestTag);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(pool);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            computeDigest, new ReadOnlySequence<byte>(input), digestLength, digestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return EncodeMultihash(digest.AsReadOnlySpan(), multihashCode.Span, base64UrlEncoder, pool);
    }


    /// <summary>
    /// Produces the MBHash placeholder for a hash function: the multihash of an all-zeros digest of
    /// <paramref name="digestLength"/> bytes. Self-hash slots are set to this placeholder before the document
    /// is hashed (did:webplus Draft v0.4, Self-Hashed Data — Placeholders).
    /// </summary>
    /// <param name="multihashCode">The multihash code naming the hash function.</param>
    /// <param name="digestLength">The digest length in bytes for that hash function.</param>
    /// <param name="base64UrlEncoder">The base64url (no padding) encoder.</param>
    /// <param name="pool">The pool used for any non-stack temporary buffer.</param>
    /// <returns>The placeholder MBHash string.</returns>
    public static string Placeholder(
        ReadOnlySpan<byte> multihashCode,
        int digestLength,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(pool);

        Span<byte> zeroDigest = stackalloc byte[digestLength];
        zeroDigest.Clear();

        return EncodeMultihash(zeroDigest, multihashCode, base64UrlEncoder, pool);
    }


    //Builds the self-describing multihash (code ‖ single-byte length ‖ digest) and multibase-encodes it with the
    //base64url 'u' prefix. The length is a single byte: every did:webplus MUST-support digest is <= 64 bytes, so
    //its varint length fits in one byte.
    private static string EncodeMultihash(
        ReadOnlySpan<byte> digest,
        ReadOnlySpan<byte> multihashCode,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> pool)
    {
        Span<byte> multihashHeader = stackalloc byte[multihashCode.Length + 1];
        multihashCode.CopyTo(multihashHeader);
        multihashHeader[multihashCode.Length] = (byte)digest.Length;

        return MultibaseSerializer.Encode(digest, multihashHeader, MultibaseAlgorithms.Base64Url, base64UrlEncoder, pool);
    }
}
