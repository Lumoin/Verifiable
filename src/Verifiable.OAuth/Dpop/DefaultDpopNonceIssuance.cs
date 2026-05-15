using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Keys;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The library's default <see cref="IssueDpopNonceDelegate"/> implementation.
/// </summary>
/// <remarks>
/// <para>
/// Produces a binary-packed nonce: kid (1-byte length-prefixed UTF-8) +
/// issuedAt (8-byte int64 BE Unix seconds) + audienceHash (16 bytes, first
/// half of SHA-256 of the audience URI's <see cref="Uri.OriginalString"/>) +
/// random (16 bytes CSPRNG) + hmacTag (32 bytes HMAC-SHA-256 over the
/// preceding bytes). The whole thing is base64url-encoded for the wire.
/// </para>
/// <para>
/// Paired with <see cref="DefaultDpopNonceValidation.ValidateAsync"/>;
/// both must agree on the format. Applications wanting a different wire
/// shape (HTTP-signing binding, attestation-bound nonces, JWT-shaped
/// nonces for human inspection) provide their own end-to-end pair.
/// </para>
/// </remarks>
public static class DefaultDpopNonceIssuance
{
    /// <summary>
    /// Issues a fresh DPoP nonce. Loads the current HMAC keyset, asks the
    /// selector to pick a kid, looks up the material via the byte-loader,
    /// then signs the binary-packed payload with the resolved key.
    /// </summary>
    public static async ValueTask<string> IssueAsync(
        Uri audience,
        TenantId tenantId,
        RequestContext context,
        GetHmacKeySetDelegate getHmacKeySet,
        SelectHmacKeyDelegate? selectHmacKey,
        ResolveServerHmacKeyDelegate resolveServerHmacKey,
        TimeProvider timeProvider,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audience);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(getHmacKeySet);
        ArgumentNullException.ThrowIfNull(resolveServerHmacKey);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        KeySet<HmacKey> keySet = await getHmacKeySet(
            tenantId, context, cancellationToken).ConfigureAwait(false);

        string? chosenKid = selectHmacKey is not null
            ? await selectHmacKey(keySet, WellKnownHmacPurposes.DpopNonce, tenantId, context, cancellationToken)
                .ConfigureAwait(false)
            : DefaultSelectCurrent(keySet);
        if(chosenKid is null)
        {
            throw new InvalidOperationException(
                "No current HMAC key available for nonce issuance.");
        }

        HmacKey? key = await resolveServerHmacKey(
            chosenKid, tenantId, context, cancellationToken).ConfigureAwait(false);
        if(key is null)
        {
            throw new InvalidOperationException(
                $"HMAC key for kid '{chosenKid}' could not be resolved.");
        }

        byte[] kidBytes = Encoding.UTF8.GetBytes(key.Kid);
        if(kidBytes.Length > byte.MaxValue)
        {
            throw new InvalidOperationException(
                $"Kid '{key.Kid}' is too long; the binary nonce format requires <=255 UTF-8 bytes.");
        }

        long issuedAtUnixSeconds = timeProvider.GetUtcNow().ToUnixTimeSeconds();

        //First half of SHA-256(audience.OriginalString) — pinning the nonce to a single endpoint.
        byte[] audienceUtf8 = Encoding.UTF8.GetBytes(audience.OriginalString);
        using DigestValue audienceDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            audienceUtf8.AsMemory(),
            outputByteLength: 32,
            tag: CryptoTags.Sha256Digest,
            pool: memoryPool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        //Pack the payload: 1 + kidLen + 8 + 16 + 16 bytes before the HMAC.
        int payloadLength = 1 + kidBytes.Length
            + WellKnownDpopValues.NonceIssuedAtByteLength
            + WellKnownDpopValues.NonceAudienceHashByteLength
            + WellKnownDpopValues.NonceRandomByteLength;
        int totalLength = payloadLength + WellKnownDpopValues.NonceHmacTagByteLength;

        using IMemoryOwner<byte> packedOwner = memoryPool.Rent(totalLength);
        Memory<byte> packedMemory = packedOwner.Memory[..totalLength];

        //Scope the span work so it does not cross the await on ComputeHmacAsync.
        {
            Span<byte> packed = packedMemory.Span;
            int offset = 0;
            packed[offset++] = (byte)kidBytes.Length;
            kidBytes.CopyTo(packed[offset..]);
            offset += kidBytes.Length;
            BinaryPrimitives.WriteInt64BigEndian(packed[offset..], issuedAtUnixSeconds);
            offset += WellKnownDpopValues.NonceIssuedAtByteLength;
            audienceDigest.AsReadOnlySpan()[..WellKnownDpopValues.NonceAudienceHashByteLength]
                .CopyTo(packed[offset..]);
            offset += WellKnownDpopValues.NonceAudienceHashByteLength;
            RandomNumberGenerator.Fill(packed.Slice(offset, WellKnownDpopValues.NonceRandomByteLength));
            offset += WellKnownDpopValues.NonceRandomByteLength;
            Debug.Assert(offset == payloadLength);
        }

        //HMAC over the first payloadLength bytes; result fills the trailing 32-byte tag region.
        ReadOnlyMemory<byte> hmacMessage = packedMemory[..payloadLength];

        using HmacValue hmacTag = await key.Material.ComputeHmacAsync(
            hmacMessage,
            outputByteLength: WellKnownDpopValues.NonceHmacTagByteLength,
            pool: memoryPool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        Span<byte> finalSpan = packedMemory.Span;
        hmacTag.AsReadOnlySpan().CopyTo(finalSpan[payloadLength..]);

        return base64UrlEncoder(finalSpan);
    }


    private static string? DefaultSelectCurrent(KeySet<HmacKey> keySet)
    {
        foreach(HmacKey k in keySet.Current)
        {
            return k.Kid;
        }
        return null;
    }
}
