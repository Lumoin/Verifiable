using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.OAuth.Server;

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
    /// Issues a fresh DPoP nonce. Composes
    /// <see cref="ResolveServerHmacKeyDelegate"/> for the kid'd HMAC key,
    /// <see cref="CryptographicKeyEvents"/>'s digest dispatcher for the
    /// audience hash, and the resolved <see cref="SymmetricKey"/>'s bound
    /// HMAC delegate for the integrity tag.
    /// </summary>
    public static async ValueTask<string> IssueAsync(
        Uri audience,
        TenantId tenantId,
        RequestContext context,
        ResolveServerHmacKeyDelegate resolveServerHmacKey,
        TimeProvider timeProvider,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audience);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(resolveServerHmacKey);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        HmacKeyResolution? resolution = await resolveServerHmacKey(
            kid: null, tenantId, context, cancellationToken).ConfigureAwait(false);
        if(resolution is null)
        {
            throw new InvalidOperationException(
                "ResolveServerHmacKeyAsync returned no current key for nonce issuance.");
        }

        byte[] kidBytes = Encoding.UTF8.GetBytes(resolution.Kid);
        if(kidBytes.Length > byte.MaxValue)
        {
            throw new InvalidOperationException(
                $"Kid '{resolution.Kid}' is too long; the binary nonce format requires <=255 UTF-8 bytes.");
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

        using HmacValue hmacTag = await resolution.Key.ComputeHmacAsync(
            hmacMessage,
            outputByteLength: WellKnownDpopValues.NonceHmacTagByteLength,
            pool: memoryPool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        Span<byte> finalSpan = packedMemory.Span;
        hmacTag.AsReadOnlySpan().CopyTo(finalSpan[payloadLength..]);

        return base64UrlEncoder(finalSpan);
    }
}
