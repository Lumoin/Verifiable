using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Cryptography;

namespace Verifiable.JCose;

/// <summary>
/// Pure functions for computing the <c>apu</c> (Agreement PartyUInfo) and <c>apv</c>
/// (Agreement PartyVInfo) JWE header parameter values from their byte recipes.
/// </summary>
/// <remarks>
/// <para>
/// The byte recipes implemented here are JOSE-generic: an <c>apu</c> is the base64url
/// encoding of a producer-identifying octet string, and an <c>apv</c> is the base64url
/// encoding of a SHA-256 hash over a recipient-identifying octet string. The DIDComm v2
/// profile (DIDComm Messaging v2.1, the <c>encrypted</c> message section) fixes what those
/// octet strings are: the <c>apu</c> input is the sender key id (<c>skid</c>) value, and
/// the <c>apv</c> input is the alphanumerically-sorted recipient <c>kid</c> list joined
/// with <c>.</c>. Those DIDComm semantics — which keys, how they are resolved — belong to
/// the DIDComm protocol layer; only the byte recipes live here, where they are reusable by
/// any JOSE caller that supplies the same inputs.
/// </para>
/// <para>
/// All hashing flows through an injected <see cref="ComputeDigestDelegate"/> so this layer
/// references no concrete crypto backend, matching the surrounding JCose convention.
/// </para>
/// </remarks>
public static class JweAgreementInfo
{
    /// <summary>
    /// Computes the <c>apu</c> value as the base64url encoding of <paramref name="partyUInfo"/>.
    /// </summary>
    /// <remarks>
    /// In the DIDComm v2 profile <paramref name="partyUInfo"/> is the UTF-8 bytes of the
    /// sender key id (<c>skid</c>) value, so <c>apu = base64url(UTF8(skid))</c>. The
    /// recipient recovers the <c>skid</c> by base64url-decoding <c>apu</c> when no explicit
    /// <c>skid</c> header is present.
    /// </remarks>
    /// <param name="partyUInfo">The producer-identifying octet string.</param>
    /// <param name="base64UrlEncoder">Delegate for Base64url encoding.</param>
    /// <returns>The base64url-encoded <c>apu</c> value.</returns>
    public static string ComputeApu(ReadOnlySpan<byte> partyUInfo, EncodeDelegate base64UrlEncoder)
    {
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);

        return base64UrlEncoder(partyUInfo);
    }


    /// <summary>
    /// Computes the DIDComm v2 <c>apu</c> value from a sender key id string:
    /// <c>base64url(UTF8(senderKeyId))</c>.
    /// </summary>
    /// <param name="senderKeyId">The sender key id (<c>skid</c>) value, e.g. a DID URL.</param>
    /// <param name="base64UrlEncoder">Delegate for Base64url encoding.</param>
    /// <param name="pool">Memory pool for the intermediate UTF-8 allocation.</param>
    /// <returns>The base64url-encoded <c>apu</c> value.</returns>
    public static string ComputeApuFromSenderKeyId(
        string senderKeyId,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> pool)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(senderKeyId);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(pool);

        int byteCount = Encoding.UTF8.GetByteCount(senderKeyId);
        using IMemoryOwner<byte> owner = pool.Rent(byteCount);
        Encoding.UTF8.GetBytes(senderKeyId, owner.Memory.Span);

        return base64UrlEncoder(owner.Memory.Span[..byteCount]);
    }


    /// <summary>
    /// Computes the DIDComm v2 <c>apv</c> value from a recipient key id list:
    /// <c>base64url(SHA-256(UTF8(sorted(kids) joined with ".")))</c>.
    /// </summary>
    /// <remarks>
    /// The recipient key ids are sorted with ordinal (alphanumeric, byte-order) comparison
    /// and joined with a single <c>.</c> separator, the SHA-256 hash of the UTF-8 bytes of
    /// the joined string is computed through <paramref name="computeDigest"/>, and the hash
    /// is base64url-encoded. This binds the set of recipients into the key derivation for
    /// every recipient, matching DIDComm Messaging v2.1.
    /// </remarks>
    /// <param name="recipientKeyIds">The recipient key ids (<c>kid</c> values).</param>
    /// <param name="base64UrlEncoder">Delegate for Base64url encoding.</param>
    /// <param name="pool">Memory pool for intermediate and output allocations.</param>
    /// <returns>The base64url-encoded <c>apv</c> value.</returns>
    /// <remarks>
    /// The SHA-256 hash flows through the registered <see cref="ComputeDigestDelegate"/>, the
    /// same software-digest seam <see cref="ConcatKdf"/> hashes through, so the digest picks
    /// up the project's observability and CBOM provenance stamping. The computation is pure
    /// mathematics, so it bridges to a synchronous call.
    /// </remarks>
    /// <exception cref="ArgumentException">Thrown when <paramref name="recipientKeyIds"/> is empty.</exception>
    public static string ComputeApvFromRecipientKeyIds(
        IReadOnlyCollection<string> recipientKeyIds,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(recipientKeyIds);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(pool);

        if(recipientKeyIds.Count == 0)
        {
            throw new ArgumentException(
                "At least one recipient key id is required to compute apv.", nameof(recipientKeyIds));
        }

        using DigestValue digest = ComputeApvDigest(recipientKeyIds, pool);

        return base64UrlEncoder(digest.AsReadOnlySpan());
    }


    /// <summary>
    /// Whether a received envelope's <c>apv</c> matches the recipient set it claims to commit to — re-derives
    /// <c>SHA-256(UTF8(sorted(kids) joined with "."))</c> from the wire <c>recipients[]</c> kids and compares
    /// it (constant-time) to the decoded header <c>apv</c>.
    /// </summary>
    /// <remarks>
    /// The <c>recipients</c> array is a top-level JWE member, NOT part of the AEAD-protected header, so a
    /// tampered recipient set is not detected by the AEAD tag. The key derivation binds the
    /// protected-header <c>apv</c> as PartyVInfo — not the actual <c>recipients[]</c> — so the CEK still
    /// unwraps for the legitimate recipient even if the recipient set was altered. Re-deriving <c>apv</c> on
    /// consume is the integrity check that binds the recipient set (DIDComm v2.1 §ECDH-ES / §ECDH-1PU key
    /// wrapping — the recipient binding). A mismatched, malformed, or absent recipient set returns
    /// <see langword="false"/> so the caller can fail closed.
    /// </remarks>
    /// <param name="recipientKeyIds">The wire <c>recipients[]</c> key ids.</param>
    /// <param name="expectedApvDigest">The decoded header <c>apv</c> bytes (a raw SHA-256 digest).</param>
    /// <param name="pool">Memory pool for intermediate allocations.</param>
    /// <returns><see langword="true"/> when the re-derived digest equals <paramref name="expectedApvDigest"/>.</returns>
    public static bool ApvMatchesRecipients(
        IReadOnlyCollection<string> recipientKeyIds,
        ReadOnlySpan<byte> expectedApvDigest,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(recipientKeyIds);
        ArgumentNullException.ThrowIfNull(pool);

        if(recipientKeyIds.Count == 0 || expectedApvDigest.Length != SHA256.HashSizeInBytes)
        {
            return false;
        }

        using DigestValue digest = ComputeApvDigest(recipientKeyIds, pool);

        return CryptographicOperations.FixedTimeEquals(digest.AsReadOnlySpan(), expectedApvDigest);
    }


    //Computes the raw apv digest: SHA-256(UTF8(sorted(recipient kids) joined with ".")), through the same
    //registered software-digest seam ConcatKdf and the produce side hash through, so CBOM/observability
    //provenance stays consistent. Kids are sorted ordinal and joined with a single '.' (DIDComm v2.1).
    private static DigestValue ComputeApvDigest(IReadOnlyCollection<string> recipientKeyIds, MemoryPool<byte> pool)
    {
        string[] sorted = [.. recipientKeyIds];
        Array.Sort(sorted, StringComparer.Ordinal);
        string joined = string.Join('.', sorted);

        int byteCount = Encoding.UTF8.GetByteCount(joined);
        using IMemoryOwner<byte> inputOwner = pool.Rent(byteCount);
        Encoding.UTF8.GetBytes(joined, inputOwner.Memory.Span);

        return CryptographicKeyEvents.ComputeDigestSyncBridge(
            inputOwner.Memory[..byteCount],
            SHA256.HashSizeInBytes,
            CryptoTags.Sha256Digest,
            pool);
    }
}
