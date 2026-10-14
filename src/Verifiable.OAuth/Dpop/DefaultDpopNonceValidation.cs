using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Keys;
using Verifiable.OAuth.Validation;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The library's default <see cref="ValidateDpopNonceDelegate"/>.
/// </summary>
/// <remarks>
/// Mirrors <see cref="DefaultDpopNonceIssuance.IssueAsync"/>: holds the presented
/// text to the one the issuance wrote (base64url characters alone, exactly the
/// structure's octets, their canonical spelling; a nonce that does not exactly
/// match one supplied is rejected: RFC 9449 Section 8 for the authorization
/// server; Sections 7.1 and 4.3 (check 10) for a resource), decodes the
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
    /// <param name="presentedNonce">The <c>nonce</c> claim of the presented DPoP proof, as the proof carries it.</param>
    /// <param name="expectedAudience">The URI of the endpoint the nonce was issued for; the nonce's audience hash must be that of its <see cref="Uri.OriginalString"/>.</param>
    /// <param name="tenantId">The tenant whose HMAC keyset the nonce is checked against.</param>
    /// <param name="context">The exchange the proof arrived in, passed to the keyset and HMAC key delegates.</param>
    /// <param name="getHmacKeySet">Loads the tenant's HMAC keyset; the nonce's key identifier must be valid for verification in it.</param>
    /// <param name="resolveServerHmacKey">Resolves the HMAC key of the nonce's key identifier.</param>
    /// <param name="timeProvider">The clock the nonce's issue time is checked against.</param>
    /// <param name="validityWindow">How far the nonce's issue time may lie before or after the current instant.</param>
    /// <param name="base64UrlDecoder">
    /// Reads the base64url spelling without padding (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC
    /// 7515 Section 2</see>, "with all trailing '=' characters omitted"), the one
    /// <see cref="DefaultDpopNonceIssuance.IssueAsync"/>'s encoder writes, into an owner whose memory holds exactly the
    /// decoded octets; a padded, white-space or base64 spelling never reaches it, since this validator refuses any
    /// character outside the base64url alphabet before decoding.
    /// </param>
    /// <param name="memoryPool">The pool the decoded nonce and the digests are rented from.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The nonce's key identifier and issue time, or the reason it is refused.</returns>
    public static async ValueTask<DpopNonceValidationResult> ValidateAsync(
        string presentedNonce,
        Uri expectedAudience,
        TenantId tenantId,
        ExchangeContext context,
        GetHmacKeySetDelegate getHmacKeySet,
        ResolveServerHmacKeyDelegate resolveServerHmacKey,
        TimeProvider timeProvider,
        TimeSpan validityWindow,
        DecodeDelegate base64UrlDecoder,
        BaseMemoryPool memoryPool,
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

        //RFC 9449 Section 8 at the authorization server; Sections 7.1 and 4.3 (check 10) at a resource: the nonce must be
        //exactly the text supplied, which the issuance wrote in base64url without padding; a character outside that
        //alphabet (white space, padding, the base64 alphabet's own) is no such text, whatever the decoder makes of it.
        if(!IsBase64UrlText(presentedNonce))
        {
            return DpopNonceValidationResult.Failure(DpopNonceValidationFailureReason.Malformed);
        }

        //Structural decode.
        IMemoryOwner<byte> decodedOwner;
        try
        {
            decodedOwner = base64UrlDecoder(presentedNonce, memoryPool);
        }
        catch
        {
            //presentedNonce is client-supplied wire input; any decode failure is a malformed nonce rather
            //than an internal fault.
            return DpopNonceValidationResult.Failure(DpopNonceValidationFailureReason.Malformed);
        }

        using(decodedOwner)
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
            //The issued structure is exactly these octets: a suffix past the tag is no nonce the issuance wrote, and the
            //text must be the one canonical spelling of them.
            if(decoded.Length != requiredLength)
            {
                return DpopNonceValidationResult.Failure(DpopNonceValidationFailureReason.Malformed);
            }

            if(!IsCanonicalBase64UrlOf(presentedNonce, decoded.Length))
            {
                return DpopNonceValidationResult.Failure(DpopNonceValidationFailureReason.Malformed);
            }

            //Reject zero-length kid before constructing a KeyId — its
            //constructor rejects empty values.
            if(kidLength == 0)
            {
                return DpopNonceValidationResult.Failure(DpopNonceValidationFailureReason.Malformed);
            }

            string kidString = Encoding.UTF8.GetString(decodedSpan.Slice(offset, kidLength));
            KeyId kid;
            try
            {
                kid = new KeyId(kidString);
            }
            catch(ArgumentException)
            {
                return DpopNonceValidationResult.Failure(DpopNonceValidationFailureReason.Malformed);
            }

            offset += kidLength;

            long issuedAtUnixSeconds = BinaryPrimitives.ReadInt64BigEndian(decodedSpan[offset..]);
            offset += WellKnownDpopValues.NonceIssuedAtByteLength;

            //The timestamp is read before the HMAC is checked, so it is still presented, unverified
            //input: a value no DateTimeOffset holds is a malformed nonce, never a server fault.
            if(!JwtTemporalChecks.IsRepresentableUnixSeconds(issuedAtUnixSeconds))
            {
                return DpopNonceValidationResult.Failure(DpopNonceValidationFailureReason.Malformed);
            }

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

            //Slot-membership check — only Current and Retiring kids are valid
            //for verification. Incoming kids are pre-published but not yet
            //usable; Historical kids are archived.
            KeySet keySet = await getHmacKeySet(
                tenantId, context, cancellationToken).ConfigureAwait(false);
            if(!keySet.IsKidValidForVerification(kid))
            {
                return DpopNonceValidationResult.Failure(DpopNonceValidationFailureReason.UnknownKid);
            }

            //Resolver lookup — could hit a backend (Vault, KMS) on cold cache.
            SymmetricKey? material = await resolveServerHmacKey(
                kid, tenantId, context, cancellationToken).ConfigureAwait(false);
            if(material is null)
            {
                return DpopNonceValidationResult.Failure(DpopNonceValidationFailureReason.UnknownKid);
            }

            //Recompute HMAC over the payload bytes and verify in constant time.
            ReadOnlyMemory<byte> hmacMessage = decoded[..payloadLength];
            bool hmacValid = await material.VerifyHmacAsync(
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
                Kid = kid.Value,
                IssuedAt = issuedAt
            });
        }
    }


    /// <summary>
    /// Whether every character of <paramref name="text"/> is one of the base64url alphabet of
    /// <see href="https://www.rfc-editor.org/rfc/rfc4648#section-5">RFC 4648 Section 5</see> (Table 2), the encoding
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC 7515 Section 2</see> defines "with all trailing
    /// '=' characters omitted" and the issuance writes the nonce in. White space, the <c>=</c> padding and the base64
    /// characters <c>+</c> and <c>/</c> are outside it, and
    /// <see href="https://www.rfc-editor.org/rfc/rfc4648#section-3.3">RFC 4648 Section 3.3</see> reads: "Implementations
    /// MUST reject the encoded data if it contains characters outside the base alphabet when interpreting base-encoded
    /// data, unless the specification referring to this document explicitly states otherwise"; RFC 7515 Section 2 states
    /// no such exception. This check holds that rule before any decoder runs. A decoder that reads <c>+</c> and
    /// <c>/</c> as the values of <c>-</c> and <c>_</c> is outside Section 3.3, and for such a decoder this check is what
    /// holds RFC 9449's exact match against that spelling of the supplied octets. It is the one base64url alphabet rule
    /// of the DPoP code, read also for the spelling of a JWK SHA-256 Thumbprint by
    /// <see cref="DpopJwkUtilities.IsJwkSha256ThumbprintSpelling(string)"/>.
    /// </summary>
    /// <param name="text">The presented nonce, or the presented thumbprint.</param>
    /// <returns><see langword="true"/> when the text is base64url characters alone.</returns>
    internal static bool IsBase64UrlText(string text)
    {
        foreach(char c in text)
        {
            if(Base64UrlValue(c) < 0)
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Whether <paramref name="text"/>, base64url characters alone, is the one spelling of <paramref name="octetCount"/>
    /// octets a conforming encoder writes: its length is the unpadded length of that many octets, and the bits of its last
    /// character that no octet carries are zero, <see href="https://www.rfc-editor.org/rfc/rfc4648#section-3.5">RFC 4648
    /// Section 3.5</see>: "These pad bits MUST be set to zero by conforming encoders". A decoder may read other spellings
    /// as the same octets; <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see> rejects
    /// a nonce that "does not exactly match a nonce recently supplied" at the authorization server, and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">Sections 7.1</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">4.3</see> (check 10, "the nonce claim matches the
    /// server-provided nonce value") hold a resource to the same; the issuance supplied this spelling alone.
    /// The length comparison is reached by a text of a non-canonical length only through a decoder that reads such a
    /// text as exactly the structure's octets: under the alphabet check before decoding and the exact decoded length, a
    /// conforming decoder does not reach it, since an alphabet-only text of the decoded length's octets has the canonical
    /// length. The pad-bit comparison is the one enforcement of the canonical spelling for a decoder that reads a set
    /// pad bit (Section 3.5: "decoders MAY chose to reject an encoding if the pad bits have not been set to zero").
    /// It is the one canonical-spelling rule of the DPoP code, read also for the 32 octets of a JWK SHA-256 Thumbprint
    /// by <see cref="DpopJwkUtilities.IsJwkSha256ThumbprintSpelling(string)"/>.
    /// </summary>
    /// <param name="text">The presented nonce, or the presented thumbprint.</param>
    /// <param name="octetCount">The number of octets the text decodes to.</param>
    /// <returns><see langword="true"/> when the text is the canonical base64url of its octets.</returns>
    internal static bool IsCanonicalBase64UrlOf(string text, int octetCount)
    {
        int canonicalLength = ((octetCount * 4) + 2) / 3;
        if(text.Length != canonicalLength)
        {
            return false;
        }

        int padBitMask = (octetCount % 3) switch
        {
            1 => 0b1111,
            2 => 0b11,
            _ => 0
        };

        return (Base64UrlValue(text[^1]) & padBitMask) == 0;
    }


    /// <summary>
    /// The value of <paramref name="c"/> in the base64url alphabet of RFC 4648 Section 5, Table 2, the one table the
    /// base64url spelling checks of the DPoP code read.
    /// </summary>
    /// <param name="c">The character.</param>
    /// <returns>The value, 0 to 63, or -1 for a character outside the alphabet.</returns>
    internal static int Base64UrlValue(char c) => c switch
    {
        >= 'A' and <= 'Z' => c - 'A',
        >= 'a' and <= 'z' => c - 'a' + 26,
        >= '0' and <= '9' => c - '0' + 52,
        '-' => 62,
        '_' => 63,
        _ => -1
    };
}
