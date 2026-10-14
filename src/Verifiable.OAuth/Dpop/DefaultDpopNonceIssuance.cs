using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;
using Verifiable.Core;
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
/// preceding bytes). The whole thing is written for the wire in base64url
/// without padding (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC 7515 Section 2</see>).
/// </para>
/// <para>
/// Paired with <see cref="DefaultDpopNonceValidation.ValidateAsync"/>;
/// both must agree on the format.
/// </para>
/// </remarks>
public static class DefaultDpopNonceIssuance
{
    /// <summary>
    /// Issues a fresh DPoP nonce. Loads the current HMAC keyset, asks the
    /// selector to pick a kid, looks up the material via the byte-loader,
    /// then signs the binary-packed payload with the resolved key. The
    /// nonce's random segment is filled through the caller-supplied
    /// <paramref name="fillEntropy"/> — the application owns the entropy
    /// source and its provenance tracking; there is deliberately no overload
    /// that fills from the OS CSPRNG directly.
    /// </summary>
    /// <param name="audience">The URI of the endpoint the nonce is issued for; the nonce carries the hash of its <see cref="Uri.OriginalString"/>.</param>
    /// <param name="tenantId">The tenant whose HMAC keyset signs the nonce.</param>
    /// <param name="context">The exchange the nonce is issued in, passed to the keyset, HMAC key selector and HMAC key delegates.</param>
    /// <param name="getHmacKeySet">Loads the tenant's HMAC keyset.</param>
    /// <param name="selectHmacKey">Picks the key identifier the nonce is signed under, or <see langword="null"/> for the keyset's first current HMAC key.</param>
    /// <param name="resolveServerHmacKey">Resolves the HMAC key of the chosen key identifier.</param>
    /// <param name="timeProvider">The clock whose current instant the nonce carries as its issue time.</param>
    /// <param name="base64UrlEncoder">
    /// Writes the nonce octets as base64url without padding,
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC 7515 Section 2</see> ("with all trailing '='
    /// characters omitted"); <see cref="DefaultDpopNonceValidation.ValidateAsync"/> accepts that spelling alone, so a
    /// nonce written with padding or in another alphabet is refused when it is presented.
    /// </param>
    /// <param name="fillEntropy">Fills the nonce's 16-octet random field; the application's entropy source.</param>
    /// <param name="memoryPool">The pool the packed nonce and the digest are rented from.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The nonce text the <c>DPoP-Nonce</c> field carries.</returns>
    public static async ValueTask<string> IssueAsync(
        Uri audience,
        TenantId tenantId,
        ExchangeContext context,
        GetHmacKeySetDelegate getHmacKeySet,
        SelectHmacKeyDelegate? selectHmacKey,
        ResolveServerHmacKeyDelegate resolveServerHmacKey,
        TimeProvider timeProvider,
        EncodeDelegate base64UrlEncoder,
        FillEntropyDelegate fillEntropy,
        BaseMemoryPool memoryPool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audience);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(getHmacKeySet);
        ArgumentNullException.ThrowIfNull(resolveServerHmacKey);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(fillEntropy);
        ArgumentNullException.ThrowIfNull(memoryPool);

        KeySet keySet = await getHmacKeySet(
            tenantId, context, cancellationToken).ConfigureAwait(false);

        KeyId? chosenKid = selectHmacKey is not null
            ? await selectHmacKey(keySet, WellKnownHmacPurposes.DpopNonce, tenantId, context, cancellationToken)
                .ConfigureAwait(false)
            : DefaultSelectCurrent(keySet);
        if(chosenKid is null)
        {
            throw new InvalidOperationException(
                "No current HMAC key available for nonce issuance.");
        }

        KeyId kid = chosenKid.Value;
        SymmetricKey? material = await resolveServerHmacKey(
            kid, tenantId, context, cancellationToken).ConfigureAwait(false);
        if(material is null)
        {
            throw new InvalidOperationException(
                $"HMAC key for kid '{kid.Value}' could not be resolved.");
        }

        byte[] kidBytes = Encoding.UTF8.GetBytes(kid.Value);
        if(kidBytes.Length > byte.MaxValue)
        {
            throw new InvalidOperationException(
                $"Kid '{kid.Value}' is too long; the binary nonce format requires <=255 UTF-8 bytes.");
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
            fillEntropy(packed.Slice(offset, WellKnownDpopValues.NonceRandomByteLength));
            offset += WellKnownDpopValues.NonceRandomByteLength;
            Debug.Assert(offset == payloadLength);
        }

        //HMAC over the first payloadLength bytes; result fills the trailing 32-byte tag region.
        ReadOnlyMemory<byte> hmacMessage = packedMemory[..payloadLength];

        using HmacValue hmacTag = await material.ComputeHmacAsync(
            hmacMessage,
            outputByteLength: WellKnownDpopValues.NonceHmacTagByteLength,
            pool: memoryPool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        Span<byte> finalSpan = packedMemory.Span;
        hmacTag.AsReadOnlySpan().CopyTo(finalSpan[payloadLength..]);

        return base64UrlEncoder(finalSpan);
    }


    /// <summary>The key identifier a nonce is signed under when no selector is given: the keyset's first current HMAC key.</summary>
    /// <param name="keySet">The tenant's HMAC keyset.</param>
    /// <returns>The first current key identifier, or <see langword="null"/> when the keyset holds none.</returns>
    private static KeyId? DefaultSelectCurrent(KeySet keySet)
    {
        foreach(KeyId kid in keySet.Current)
        {
            return kid;
        }

        return null;
    }
}
