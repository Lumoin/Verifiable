using System;
using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Foundation;

namespace Verifiable.Core.Did.Methods.WebPlus;

/// <summary>
/// Verifies the <c>selfHash</c> of a did:webplus DID document: the self-describing
/// <see cref="WebPlusMbHash">MBHash</see> the document commits to itself with (did:webplus Draft v0.4,
/// Self-Hashed Data).
/// </summary>
/// <remarks>
/// <para>
/// A self-hashed document carries its own hash in a set of "self-hash slots". Generation sets every slot to the
/// algorithm's placeholder, JCS-canonicalizes, hashes, and writes the digest back into every slot; verification
/// reverses it. Because a validly-constructed document holds the <em>same</em> self-hash value in every slot —
/// the <c>selfHash</c> field, the root-self-hash in the DID, each verification method's <c>id</c>/<c>controller</c>
/// and the <c>selfHash</c> query parameter, and (necessarily, since it embeds the self-hash) the
/// <c>publicKeyJwk.kid</c> — the slots are exactly the occurrences of the self-hash value. Verification therefore
/// replaces every occurrence of that value with the placeholder, re-hashes, and checks the result reproduces the
/// claimed value.
/// </para>
/// <para>
/// The substitution is length-preserving: a self-hash and its placeholder are the same multihash algorithm and
/// length, so replacing one with the other does not disturb the JCS canonical form. The caller supplies the
/// hash function and multihash code matching the claimed self-hash (a verifier reads the algorithm from the
/// self-describing value); the library pins none.
/// </para>
/// </remarks>
internal static class WebPlusSelfHash
{
    /// <summary>
    /// Verifies that <paramref name="selfHashValue"/> is the correct self-hash of the JCS document bytes.
    /// </summary>
    /// <param name="jcsDocument">The DID document in its JCS canonical form (the bytes that were hashed).</param>
    /// <param name="selfHashValue">The claimed self-hash (the document's <c>selfHash</c> field value).</param>
    /// <param name="multihashCode">The multihash code naming the hash function the self-hash uses, e.g. <see cref="MultihashHeaders.Blake3"/>.</param>
    /// <param name="digestLength">The digest length in bytes for that hash function.</param>
    /// <param name="computeDigest">The digest implementation matching <paramref name="multihashCode"/>.</param>
    /// <param name="digestTag">The digest tag naming that algorithm for the seam.</param>
    /// <param name="base64UrlEncoder">The base64url (no padding) encoder.</param>
    /// <param name="pool">The pool used for the working buffer.</param>
    /// <param name="cancellationToken">Cancels an in-flight digest on a hardware-async backend (TPM2_Hash, KMS).</param>
    /// <returns><see langword="true"/> when the document's self-hash reproduces <paramref name="selfHashValue"/>.</returns>
    public static async ValueTask<bool> VerifyAsync(
        ReadOnlyMemory<byte> jcsDocument,
        ReadOnlyMemory<char> selfHashValue,
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

        //A self-hash and its placeholder are the same algorithm and length; a length mismatch means the claimed
        //value is not a self-hash of this algorithm, so it cannot verify. This placeholder substitution is a
        //pure-compute span step run before the digest await.
        if(!TryRentWithSelfHashSlotsPlaceholdered(jcsDocument.Span, selfHashValue.Span, multihashCode.Span, digestLength, base64UrlEncoder, pool, out IMemoryOwner<byte> owner, out int length))
        {
            return false;
        }

        using(owner)
        {
            string recomputed = await WebPlusMbHash.ComputeAsync(owner.Memory[..length], multihashCode, digestLength, computeDigest, digestTag, base64UrlEncoder, pool, cancellationToken).ConfigureAwait(false);

            return recomputed.AsSpan().SequenceEqual(selfHashValue.Span);
        }
    }


    /// <summary>
    /// Rents a pooled copy of <paramref name="jcsDocument"/> with every occurrence of
    /// <paramref name="selfHashValue"/> replaced by the algorithm's MBHash placeholder (length-preserving). This
    /// is the "set all self-hash slots to the placeholder" step shared by self-hash verification (over the whole
    /// document) and proof-payload reconstruction (over the document with its <c>proofs</c> removed) — a
    /// did:webplus proof's detached payload is the JCS of the document, <c>proofs</c> deleted, self-hash slots
    /// set to the placeholder (did:webplus Draft v0.4, Self-Hashed Signed Data).
    /// </summary>
    /// <param name="jcsDocument">The JCS bytes to copy and substitute over.</param>
    /// <param name="selfHashValue">The self-hash value occupying every slot (the document's <c>selfHash</c>).</param>
    /// <param name="multihashCode">The multihash code naming the self-hash's hash function.</param>
    /// <param name="digestLength">The digest length in bytes for that hash function.</param>
    /// <param name="base64UrlEncoder">The base64url (no padding) encoder.</param>
    /// <param name="pool">The pool used for the returned buffer.</param>
    /// <param name="owner">The rented buffer holding the substituted bytes; the caller disposes it. Only valid when the method returns <see langword="true"/>.</param>
    /// <param name="length">The valid length within <paramref name="owner"/>.</param>
    /// <returns>
    /// <see langword="true"/> with the substituted buffer; <see langword="false"/> (and a disposed, ignorable
    /// <paramref name="owner"/>) when <paramref name="selfHashValue"/> is not the placeholder's length and so is
    /// not a self-hash of this algorithm.
    /// </returns>
    internal static bool TryRentWithSelfHashSlotsPlaceholdered(
        ReadOnlySpan<byte> jcsDocument,
        ReadOnlySpan<char> selfHashValue,
        ReadOnlySpan<byte> multihashCode,
        int digestLength,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> pool,
        out IMemoryOwner<byte> owner,
        out int length)
    {
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(pool);

        string placeholder = WebPlusMbHash.Placeholder(multihashCode, digestLength, base64UrlEncoder, pool);
        if(selfHashValue.Length != placeholder.Length)
        {
            owner = EmptyMemoryOwner.Instance;
            length = 0;

            return false;
        }

        //The self-hash value and placeholder are ASCII (the multibase 'u' prefix plus base64url characters), so
        //they map to bytes one-to-one for the byte-level substitution over the JCS document.
        Span<byte> findBytes = stackalloc byte[selfHashValue.Length];
        Span<byte> replaceBytes = stackalloc byte[placeholder.Length];
        for(int i = 0; i < selfHashValue.Length; i++)
        {
            findBytes[i] = (byte)selfHashValue[i];
            replaceBytes[i] = (byte)placeholder[i];
        }

        length = jcsDocument.Length;
        owner = pool.Rent(length);
        Span<byte> buffer = owner.Memory.Span[..length];
        jcsDocument.CopyTo(buffer);
        ReplaceAll(buffer, findBytes, replaceBytes);

        return true;
    }


    /// <summary>
    /// Replaces, in place, every occurrence of find with replace. find and replace are the same length, so the
    /// buffer length is unchanged and the JCS canonical form is preserved.
    /// </summary>
    private static void ReplaceAll(Span<byte> buffer, ReadOnlySpan<byte> find, ReadOnlySpan<byte> replace)
    {
        int index = 0;
        while(index <= buffer.Length - find.Length)
        {
            int found = buffer[index..].IndexOf(find);
            if(found < 0)
            {
                break;
            }

            int at = index + found;
            replace.CopyTo(buffer[at..]);
            index = at + replace.Length;
        }
    }
}
