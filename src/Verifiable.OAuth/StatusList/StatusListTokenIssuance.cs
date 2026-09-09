using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.StatusList;

/// <summary>
/// Composes and signs a Section 5.1 Status List Token in JWT format
/// (<c>statuslist+jwt</c>) from a <see cref="StatusListToken"/>.
/// </summary>
/// <remarks>
/// <para>
/// The claims set is built by <see cref="StatusListTokenClaims.ToPayload"/> — the one Core
/// mapping shared with the verification side — and the header is built by
/// <see cref="UnsignedJwt.ForSigning"/> with <c>typ</c> pinned to
/// <see cref="WellKnownMediaTypes.Jwt.StatusListJwt"/> ("typ: REQUIRED. The JWT type MUST be
/// statuslist+jwt.") and <c>alg</c> derived from <paramref name="signingKey"/>'s
/// <see cref="Tag"/> via <see cref="CryptoFormatConversions.DefaultTagToJwaConverter"/>. Signing
/// flows through <see cref="JwtSigningExtensions.SignAsync"/>, the standard JCose composition
/// pattern this project's other JWT issuers (<c>KbJwtIssuance</c>, <c>ClientAssertionSigning</c>)
/// share — algorithm dispatch lives in the registry, not in a per-call-site delegate.
/// </para>
/// <para>
/// "2. The JWT MUST be secured using a cryptographic signature or MAC algorithm." This
/// composition always signs; Section 11.6 records "implementers SHOULD default to digital
/// signatures if they are unsure" as the reason a MAC-secured Status List Token is not a
/// composition this method offers — an application that needs one composes it directly over the
/// JCose MAC primitives. "Both ttl and exp are RECOMMENDED to be used by the Status Issuer"
/// (Section 13.7): both are written whenever <paramref name="token"/> carries them, since that
/// choice belongs to <see cref="StatusListTokenClaims.ToPayload"/>, not to this composition.
/// </para>
/// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>
/// and <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.6">Section 11.6</see>.
/// </remarks>
public static class StatusListTokenIssuance
{
    /// <summary>
    /// Composes the compact-serialized, signed Status List Token JWT for <paramref name="token"/>.
    /// </summary>
    /// <param name="token">The Status List Token to encode and sign.</param>
    /// <param name="signingKey">
    /// The Status Issuer's signing key. The JWS <c>alg</c> is derived from the key's <see cref="Tag"/>.
    /// </param>
    /// <param name="keyId">The key identifier for the <c>kid</c> header parameter.</param>
    /// <param name="base64UrlEncoder">
    /// Base64url encoder, used both for the <c>lst</c> claim's compressed bytes and for compact
    /// JWS serialization.
    /// </param>
    /// <param name="headerSerializer">Serializes the protected header to UTF-8 JSON bytes.</param>
    /// <param name="payloadSerializer">Serializes the payload claims to UTF-8 JSON bytes.</param>
    /// <param name="memoryPool">Memory pool for transient signing buffers.</param>
    /// <param name="cancellationToken">Cancellation token, propagated through the registry-resolved signing delegate.</param>
    /// <returns>The compact-serialized Status List Token JWT (<c>header.payload.signature</c>).</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when any required argument is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="keyId"/> is empty or whitespace, or when <paramref name="token"/>'s
    /// Status List is packed <c>MostSignificantFirst</c> (the W3C Bitstring Status List's order)
    /// rather than the <c>LeastSignificantFirst</c> order Section 4.1 of the Token Status List
    /// specification requires — see <see cref="Core.StatusList.StatusList.EnsureIetfBitOrder"/>, called
    /// through <see cref="StatusListTokenClaims.ToPayload"/>.
    /// </exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "JwsMessage is disposed via the using statement before the method returns; the returned string is independent of the message.")]
    public static async ValueTask<string> ComposeAsync(
        StatusListToken token,
        PrivateKeyMemory signingKey,
        string keyId,
        EncodeDelegate base64UrlEncoder,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        BaseMemoryPool memoryPool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(memoryPool);

        cancellationToken.ThrowIfCancellationRequested();

        JwtPayload payload = StatusListTokenClaims.ToPayload(token, base64UrlEncoder);
        UnsignedJwt unsigned = UnsignedJwt.ForSigning(signingKey, keyId, payload, WellKnownMediaTypes.Jwt.StatusListJwt);

        using JwsMessage jws = await unsigned.SignAsync(
            signingKey,
            headerSerializer,
            payloadSerializer,
            base64UrlEncoder,
            memoryPool,
            cancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, base64UrlEncoder);
    }
}
