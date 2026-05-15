using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Keys;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The library's default <see cref="ValidateDpopNonceDelegate"/>.
/// </summary>
/// <remarks>
/// Mirrors <see cref="DefaultDpopNonceIssuance.IssueAsync"/>: decodes the
/// binary-packed format, checks slot membership for the extracted kid,
/// looks up the kid'd key, recomputes the HMAC, verifies the audience hash
/// and the issuedAt window. Cheap structural checks run first; the resolver
/// and HMAC computation only run after the nonce has cleared the cheap
/// checks.
/// </remarks>
public static class DefaultDpopNonceValidation
{
    /// <summary>
    /// Validates a presented nonce against the expected audience and the
    /// application's HMAC keyset.
    /// </summary>
    public static async ValueTask<DpopNonceValidationResult> ValidateAsync(
        string presentedNonce,
        Uri expectedAudience,
        TenantId tenantId,
        RequestContext context,
        GetHmacKeySetDelegate getHmacKeySet,
        ResolveServerHmacKeyDelegate resolveServerHmacKey,
        TimeProvider timeProvider,
        TimeSpan validityWindow,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(presentedNonce);
        ArgumentNullException.ThrowIfNull(expectedAudience);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(getHmacKeySet);
        ArgumentNullException.ThrowIfNull(resolveServerHmacKey);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        //Structural decode.
        IMemoryOwner<byte> decodedOwner;
        try
        {
            decodedOwner = base64UrlDecoder(presentedNonce, memoryPool);
        }
        catch
        {
            return DpopNonceValidationResult.Failure(DpopNonceValidationFailureReason.Malformed);
        }

        try
        {
            ReadOnlyMemory<byte> decoded = decodedOwner.Memory;
            int minimumLength = 1 + 0
                + WellKnownDpopValues.NonceIssuedAtByteLength
                + WellKnownDpopValues.NonceAudienceHashByteLength
                + WellKnownDpopValues.NonceRandomByteLength
                + WellKnownDpopValues.NonceHmacTagByteLength;
            if(decoded.Length < minimumLength)
            {
                return DpopNonceValidationResult.Failure(DpopNonceValidationFailureReason.Malformed);
            }

            ReadOnlySpan<byte> decodedSpan = decoded.Span;

            int offset = 0;
            byte kidLength = decodedSpan[offset++];
            int requiredLength = 1 + kidLength
                + WellKnownDpopValues.NonceIssuedAtByteLength
                + WellKnownDpopValues.NonceAudienceHashByteLength
                + WellKnownDpopValues.NonceRandomByteLength
                + WellKnownDpopValues.NonceHmacTagByteLength;
            if(decoded.Length < requiredLength)
            {
                return DpopNonceValidationResult.Failure(DpopNonceValidationFailureReason.Malformed);
            }

            string kid = Encoding.UTF8.GetString(decodedSpan.Slice(offset, kidLength));
            offset += kidLength;

            long issuedAtUnixSeconds = BinaryPrimitives.ReadInt64BigEndian(decodedSpan[offset..]);
            offset += WellKnownDpopValues.NonceIssuedAtByteLength;
            DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(issuedAtUnixSeconds);

            ReadOnlyMemory<byte> presentedAudienceHash =
                decoded.Slice(offset, WellKnownDpopValues.NonceAudienceHashByteLength);
            offset += WellKnownDpopValues.NonceAudienceHashByteLength;

            offset += WellKnownDpopValues.NonceRandomByteLength;

            int payloadLength = offset;
            ReadOnlyMemory<byte> presentedHmacTag =
                decoded.Slice(offset, WellKnownDpopValues.NonceHmacTagByteLength);

            //Expiry check before hitting the resolver — cheap, structural.
            DateTimeOffset now = timeProvider.GetUtcNow();
            if(issuedAt < now - validityWindow || issuedAt > now + validityWindow)
            {
                return DpopNonceValidationResult.Failure(DpopNonceValidationFailureReason.Expired);
            }

            //Audience check before signature — cheaper than HMAC, no resolver call.
            byte[] expectedAudienceUtf8 = Encoding.UTF8.GetBytes(expectedAudience.OriginalString);
            using DigestValue expectedAudienceDigest = await CryptographicKeyEvents.ComputeDigestAsync(
                expectedAudienceUtf8.AsMemory(),
                outputByteLength: 32,
                tag: CryptoTags.Sha256Digest,
                pool: memoryPool,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            if(!CryptographicOperations.FixedTimeEquals(
                presentedAudienceHash.Span,
                expectedAudienceDigest.AsReadOnlySpan()[..WellKnownDpopValues.NonceAudienceHashByteLength]))
            {
                return DpopNonceValidationResult.Failure(DpopNonceValidationFailureReason.AudienceMismatch);
            }

            //Slot-membership check — only Current and Retiring kids are valid for
            //verification. Incoming kids are pre-published but not yet usable;
            //Historical kids are archived. A presented nonce whose kid is outside
            //the verification slots is rejected before incurring HMAC work.
            KeySet<HmacKey> keySet = await getHmacKeySet(
                tenantId, context, cancellationToken).ConfigureAwait(false);
            if(!keySet.IsKidValidForVerification(kid))
            {
                return DpopNonceValidationResult.Failure(DpopNonceValidationFailureReason.UnknownKid);
            }

            //Resolver lookup — could hit a backend (Vault, KMS) on cold cache.
            HmacKey? key = await resolveServerHmacKey(
                kid, tenantId, context, cancellationToken).ConfigureAwait(false);
            if(key is null)
            {
                return DpopNonceValidationResult.Failure(DpopNonceValidationFailureReason.UnknownKid);
            }

            //Recompute HMAC over the payload bytes and verify in constant time.
            ReadOnlyMemory<byte> hmacMessage = decoded[..payloadLength];
            bool hmacValid = await key.Material.VerifyHmacAsync(
                hmacMessage,
                presentedHmacTag,
                pool: memoryPool,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            if(!hmacValid)
            {
                return DpopNonceValidationResult.Failure(DpopNonceValidationFailureReason.HmacMismatch);
            }

            return DpopNonceValidationResult.Success(new DpopNoncePayload
            {
                Kid = kid,
                IssuedAt = issuedAt
            });
        }
        finally
        {
            decodedOwner.Dispose();
        }
    }
}
