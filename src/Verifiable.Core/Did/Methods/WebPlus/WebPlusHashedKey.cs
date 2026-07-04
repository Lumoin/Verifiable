using System;
using System.Buffers;
using System.Text;
using Verifiable.Cryptography;

namespace Verifiable.Core.Did.Methods.WebPlus;

/// <summary>
/// Computes the <c>hashedKey</c> pre-rotation commitment of a did:webplus update rule: the
/// <see cref="WebPlusMbHash">MBHash</see> of an MBPubKey, the value a <see cref="HashedKeyUpdateRule"/> names
/// (did:webplus Draft v0.4, Update Rules — <c>{"hashedKey":"&lt;MBHash&gt;"}</c>; WP-UR-4). The commitment is the
/// MBHash of the MBPubKey's characters: the specification's worked example states "the hash of the <c>kid</c>
/// field of the JWS header … should match the <c>hashedKey</c> field", and the <c>kid</c> field value is the
/// MBPubKey string.
/// </summary>
/// <remarks>
/// The hash function and multihash code are supplied by the caller — the library pins none — so the same
/// primitive serves every MUST-support algorithm. <see cref="CreateMatcher"/> binds the algorithm into a
/// <see cref="HashedKeyMatcher"/> the update-rule evaluation consumes; the per-call MBPubKey and MBHash arrive as
/// the matcher's parameters, never captured.
/// </remarks>
public static class WebPlusHashedKey
{
    /// <summary>
    /// Computes the MBHash commitment of <paramref name="mbPubKey"/> — the MBHash of its UTF-8 characters.
    /// </summary>
    /// <param name="mbPubKey">The MBPubKey whose commitment is computed.</param>
    /// <param name="multihashCode">The multihash code naming the hash function, e.g. <see cref="MultihashHeaders.Blake3"/>.</param>
    /// <param name="digestLength">The digest length in bytes for that hash function.</param>
    /// <param name="computeDigest">The digest implementation matching <paramref name="multihashCode"/>.</param>
    /// <param name="digestTag">The digest tag naming that algorithm for the seam.</param>
    /// <param name="base64UrlEncoder">The base64url (no padding) encoder.</param>
    /// <param name="pool">The pool used for the working buffer.</param>
    /// <param name="cancellationToken">Cancels an in-flight digest on a hardware-async backend (TPM2_Hash, KMS).</param>
    /// <returns>The MBHash string committing to <paramref name="mbPubKey"/>.</returns>
    public static async ValueTask<string> ComputeAsync(
        string mbPubKey,
        ReadOnlyMemory<byte> multihashCode,
        int digestLength,
        ComputeDigestDelegate computeDigest,
        Tag digestTag,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(mbPubKey);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(digestTag);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(pool);

        int byteCount = Encoding.UTF8.GetByteCount(mbPubKey);
        using IMemoryOwner<byte> owner = pool.Rent(byteCount);
        Encoding.UTF8.GetBytes(mbPubKey, owner.Memory.Span[..byteCount]);

        return await WebPlusMbHash.ComputeAsync(owner.Memory[..byteCount], multihashCode, digestLength, computeDigest, digestTag, base64UrlEncoder, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds a <see cref="HashedKeyMatcher"/> that decides whether an MBPubKey satisfies a <c>hashedKey</c>
    /// update rule under the given hash algorithm: it computes the MBPubKey's MBHash and compares it to the
    /// rule's MBHash. The algorithm is bound here; the candidate key and commitment arrive per call.
    /// </summary>
    /// <param name="multihashCode">The multihash code naming the hash function.</param>
    /// <param name="digestLength">The digest length in bytes for that hash function.</param>
    /// <param name="computeDigest">The digest implementation matching <paramref name="multihashCode"/>.</param>
    /// <param name="digestTag">The digest tag naming that algorithm for the seam.</param>
    /// <param name="base64UrlEncoder">The base64url (no padding) encoder.</param>
    /// <param name="pool">The pool used for the working buffers.</param>
    /// <returns>A <see cref="HashedKeyMatcher"/> for the update-rule evaluation.</returns>
    public static HashedKeyMatcher CreateMatcher(
        ReadOnlyMemory<byte> multihashCode,
        int digestLength,
        ComputeDigestDelegate computeDigest,
        Tag digestTag,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(digestTag);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(pool);

        return async (mbPubKey, mbHash, cancellationToken) =>
            string.Equals(await ComputeAsync(mbPubKey, multihashCode, digestLength, computeDigest, digestTag, base64UrlEncoder, pool, cancellationToken).ConfigureAwait(false), mbHash, StringComparison.Ordinal);
    }
}
