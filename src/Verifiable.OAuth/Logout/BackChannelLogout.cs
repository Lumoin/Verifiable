using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.SecurityEvents;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Text;
using Verifiable.JCose;

namespace Verifiable.OAuth.Logout;

/// <summary>
/// The OIDC Back-Channel Logout 1.0 Logout Token primitives — the OP-side builder and the
/// RP-side verifier (<see href="https://openid.net/specs/openid-connect-backchannel-1_0.html">OIDC Back-Channel Logout 1.0</see>).
/// </summary>
/// <remarks>
/// <para>
/// A Logout Token is a signed JWS that looks like an ID Token carrying an <c>events</c> claim
/// — it is NOT a generic RFC 8417 Security Event Token: its <c>sub</c>/<c>sid</c> are top-level
/// JWT claims (not an RFC 9493 <c>sub_id</c>) and its explicit <c>typ</c> is
/// <see cref="WellKnownMediaTypes.Jwt.LogoutJwt"/> (<c>logout+jwt</c>), so these primitives
/// compose the JWS directly rather than going through
/// <see cref="SecurityEventTokenIssuance"/> / <see cref="SecurityEventTokenVerification"/>
/// (whose <c>typ</c> is <c>secevent+jwt</c>). Signing/verification flow through the same
/// JCose composition every other token in the codebase uses — no new crypto.
/// </para>
/// <para>
/// Delivery (the OP POSTing the token to each registered RP's <c>backchannel_logout_uri</c>)
/// and key resolution (an RP fetching the OP's <c>jwks_uri</c> by <c>kid</c>) are transport
/// concerns layered on top of these primitives by the application, not part of them — the
/// builder returns the compact token and the verifier takes the already-resolved public key.
/// </para>
/// </remarks>
[DebuggerDisplay("BackChannelLogout")]
public static class BackChannelLogout
{
    /// <summary>The UTF-8 source literal of <see cref="BackChannelLogoutEventType"/>.</summary>
    public static ReadOnlySpan<byte> BackChannelLogoutEventTypeUtf8 => "http://schemas.openid.net/event/backchannel-logout"u8;

    /// <summary>
    /// The back-channel logout event-type identifier — the member name a Logout Token's
    /// <c>events</c> claim MUST carry, mapping to an empty JSON object
    /// (<see href="https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken">OIDC Back-Channel Logout 1.0 §2.4</see>).
    /// </summary>
    public static readonly string BackChannelLogoutEventType = Utf8Constants.ToInternedString(BackChannelLogoutEventTypeUtf8);

    /// <summary>Reused empty payload for tolerant reads of an absent or malformed claim.</summary>
    private static readonly IReadOnlyDictionary<string, object> EmptyPayload =
        new Dictionary<string, object>(0, StringComparer.Ordinal);


    /// <summary>
    /// Builds and signs a Logout Token (§2.4) about the session identified by
    /// <paramref name="subject"/> and/or <paramref name="sessionId"/>. At least one of the two
    /// is required. The token carries <c>iss</c>/<c>aud</c>/<c>iat</c>/<c>jti</c>, the
    /// <c>events</c> claim with the back-channel logout member (an empty object), an explicit
    /// <c>typ</c> of <c>logout+jwt</c>, and deliberately no <c>nonce</c>.
    /// </summary>
    /// <param name="issuer">The <c>iss</c> claim — the OP's issuer identifier.</param>
    /// <param name="audience">The <c>aud</c> claim — the RP the token is delivered to (its client identifier).</param>
    /// <param name="jwtId">The <c>jti</c> claim — a unique per-token identifier for replay defense.</param>
    /// <param name="issuedAt">The <c>iat</c> claim, encoded as Unix seconds.</param>
    /// <param name="subject">The <c>sub</c> claim — the logged-out subject; optional when <paramref name="sessionId"/> is given.</param>
    /// <param name="sessionId">The <c>sid</c> claim — the terminated session; optional when <paramref name="subject"/> is given.</param>
    /// <param name="signingKey">The OP's signing key; the <c>alg</c> derives from its <see cref="Tag"/>.</param>
    /// <param name="base64UrlEncoder">Base64url encoder for compact serialization.</param>
    /// <param name="headerSerializer">Serializes the protected header to UTF-8 JSON bytes.</param>
    /// <param name="payloadSerializer">Serializes the payload claims to UTF-8 JSON bytes.</param>
    /// <param name="memoryPool">Memory pool for transient signing buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="signingKeyId">Optional <c>kid</c> header naming the signing key in the OP's JWK set.</param>
    /// <returns>The compact-serialized Logout Token (<c>header.payload.signature</c>).</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "JwsMessage is disposed via the using statement before the method returns; the returned string is independent of the message.")]
    public static async ValueTask<string> BuildLogoutTokenAsync(
        string issuer,
        string audience,
        string jwtId,
        DateTimeOffset issuedAt,
        string? subject,
        string? sessionId,
        PrivateKeyMemory signingKey,
        EncodeDelegate base64UrlEncoder,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken,
        string? signingKeyId = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);
        ArgumentException.ThrowIfNullOrWhiteSpace(jwtId);
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(memoryPool);

        //§2.4: a Logout Token MUST contain a sub Claim, a sid Claim, or both.
        if(string.IsNullOrEmpty(subject) && string.IsNullOrEmpty(sessionId))
        {
            throw new ArgumentException(
                "A Logout Token MUST carry a subject (sub), a session id (sid), or both (OIDC Back-Channel Logout 1.0 §2.4).",
                nameof(subject));
        }

        cancellationToken.ThrowIfCancellationRequested();

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);

        var header = new JwtHeader(signingKeyId is null ? 2 : 3)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = WellKnownMediaTypes.Jwt.LogoutJwt
        };

        if(signingKeyId is not null)
        {
            header[WellKnownJwkMemberNames.Kid] = signingKeyId;
        }

        int capacity = 5
            + (subject is not null ? 1 : 0)
            + (sessionId is not null ? 1 : 0);

        //§2.4: the events Claim is a JSON object containing the back-channel logout member
        //whose value is an empty JSON object. No nonce is included.
        var events = new Dictionary<string, object>(1, StringComparer.Ordinal)
        {
            [BackChannelLogoutEventType] = new Dictionary<string, object>(0, StringComparer.Ordinal)
        };

        var payload = new JwtPayload(capacity)
        {
            [WellKnownJwtClaimNames.Iss] = issuer,
            [WellKnownJwtClaimNames.Aud] = audience,
            [WellKnownJwtClaimNames.Iat] = issuedAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Jti] = jwtId,
            [SecurityEventTokenClaimNames.Events] = events
        };

        if(!string.IsNullOrEmpty(subject))
        {
            payload[WellKnownJwtClaimNames.Sub] = subject;
        }

        if(!string.IsNullOrEmpty(sessionId))
        {
            payload[WellKnownJwtClaimNames.Sid] = sessionId;
        }

        var unsigned = new UnsignedJwt(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            signingKey,
            headerSerializer,
            payloadSerializer,
            base64UrlEncoder,
            memoryPool,
            cancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, base64UrlEncoder);
    }


    /// <summary>
    /// Verifies a Logout Token and validates the §2.6 rules, returning a result rather than
    /// throwing so a Receiver can branch on the cause. The order is fail-fast and firewalled:
    /// signature first (under <paramref name="signingPublicKey"/>), then — only once the
    /// signature holds — the §2.6 claim checks over the verified payload: <c>iss</c> match,
    /// <c>aud</c> includes this Receiver, <c>iat</c> present, a <c>sub</c> and/or <c>sid</c>,
    /// the back-channel logout member in <c>events</c>, and no <c>nonce</c>.
    /// </summary>
    /// <remarks>
    /// The optional §2.6 <c>jti</c> replay check is a Receiver concern (it needs the Receiver's
    /// recently-seen store) and is layered on top of this primitive, not part of it.
    /// </remarks>
    /// <param name="logoutToken">The compact Logout Token (<c>header.payload.signature</c>).</param>
    /// <param name="signingPublicKey">The OP's public key, resolved by the Receiver from the OP's <c>jwks_uri</c> by <c>kid</c>.</param>
    /// <param name="expectedIssuer">The OP issuer the <c>iss</c> claim MUST equal.</param>
    /// <param name="expectedAudience">This Receiver's client identifier the <c>aud</c> claim MUST include.</param>
    /// <param name="base64UrlDecoder">Base64url decoder for the compact segments.</param>
    /// <param name="payloadDeserializer">Deserializes the payload segment's JSON bytes into a claim map.</param>
    /// <param name="memoryPool">Memory pool for transient verification buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<BackChannelLogoutVerificationResult> VerifyLogoutTokenAsync(
        string logoutToken,
        PublicKeyMemory signingPublicKey,
        string expectedIssuer,
        string expectedAudience,
        DecodeDelegate base64UrlDecoder,
        Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>?> payloadDeserializer,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logoutToken);
        ArgumentNullException.ThrowIfNull(signingPublicKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedIssuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedAudience);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(payloadDeserializer);
        ArgumentNullException.ThrowIfNull(memoryPool);

        JwsVerificationResult verification;
        try
        {
            verification = await Jws.VerifyAndDecodeAsync(
                logoutToken,
                base64UrlDecoder,
                bytes => payloadDeserializer(bytes) ?? EmptyPayload,
                memoryPool,
                signingPublicKey,
                cancellationToken).ConfigureAwait(false);
        }
        catch(Exception ex) when(ex is FormatException or InvalidOperationException)
        {
            return BackChannelLogoutVerificationResult.Failed(BackChannelLogoutValidationError.Malformed);
        }

        if(!verification.IsValid)
        {
            return BackChannelLogoutVerificationResult.Failed(BackChannelLogoutValidationError.SignatureInvalid);
        }

        JwtPayload payload = verification.Payload;

        //§2.6: validate iss/aud/iat as for an ID Token.
        if(!TryGetString(payload, WellKnownJwtClaimNames.Iss, out string? iss)
            || !string.Equals(iss, expectedIssuer, StringComparison.Ordinal))
        {
            return BackChannelLogoutVerificationResult.Failed(BackChannelLogoutValidationError.IssuerMismatch);
        }

        if(!AudienceContains(payload, expectedAudience))
        {
            return BackChannelLogoutVerificationResult.Failed(BackChannelLogoutValidationError.AudienceMismatch);
        }

        if(!payload.ContainsKey(WellKnownJwtClaimNames.Iat))
        {
            return BackChannelLogoutVerificationResult.Failed(BackChannelLogoutValidationError.MissingIssuedAt);
        }

        //§2.6: a Logout Token MUST contain a sub Claim, a sid Claim, or both.
        TryGetString(payload, WellKnownJwtClaimNames.Sub, out string? subject);
        TryGetString(payload, WellKnownJwtClaimNames.Sid, out string? sessionId);
        if(string.IsNullOrEmpty(subject) && string.IsNullOrEmpty(sessionId))
        {
            return BackChannelLogoutVerificationResult.Failed(BackChannelLogoutValidationError.MissingSubjectAndSession);
        }

        //§2.6: the events Claim MUST contain the back-channel logout member.
        if(!ContainsLogoutEvent(payload))
        {
            return BackChannelLogoutVerificationResult.Failed(BackChannelLogoutValidationError.MissingLogoutEvent);
        }

        //§2.6: a Logout Token MUST NOT contain a nonce Claim.
        if(payload.ContainsKey(WellKnownJwtClaimNames.Nonce))
        {
            return BackChannelLogoutVerificationResult.Failed(BackChannelLogoutValidationError.ForbiddenNonce);
        }

        return BackChannelLogoutVerificationResult.Success(subject, sessionId);
    }


    /// <summary>Reads a string-valued claim, or <see langword="null"/> when absent or not a string.</summary>
    private static bool TryGetString(JwtPayload payload, string name, out string? value)
    {
        if(payload.TryGetValue(name, out object? raw) && raw is string s)
        {
            value = s;
            return true;
        }

        value = null;
        return false;
    }


    /// <summary>Whether the <c>aud</c> claim (a string or an array of strings) includes <paramref name="expected"/>.</summary>
    private static bool AudienceContains(JwtPayload payload, string expected)
    {
        if(!payload.TryGetValue(WellKnownJwtClaimNames.Aud, out object? value))
        {
            return false;
        }

        if(value is string single)
        {
            return string.Equals(single, expected, StringComparison.Ordinal);
        }

        if(value is IEnumerable<object> items)
        {
            foreach(object item in items)
            {
                if(item is string audience && string.Equals(audience, expected, StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }


    /// <summary>Whether the <c>events</c> claim is an object carrying the back-channel logout member.</summary>
    private static bool ContainsLogoutEvent(JwtPayload payload) =>
        payload.TryGetValue(SecurityEventTokenClaimNames.Events, out object? events)
        && events is IReadOnlyDictionary<string, object> map
        && map.ContainsKey(BackChannelLogoutEventType);
}
