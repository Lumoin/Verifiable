using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// Issues (builds and signs) a Security Event Token in compact JWS serialization
/// per <see href="https://www.rfc-editor.org/rfc/rfc8417">RFC 8417</see>.
/// </summary>
/// <remarks>
/// <para>
/// The SET is signed by the Transmitter's key; the protected header carries the
/// explicit <c>typ</c> of <see cref="WellKnownMediaTypes.Jwt.SecEventJwt"/>
/// (<c>secevent+jwt</c>) that RFC 8417 §2.3 and SSF §4.1.1 require, plus the
/// <c>alg</c> derived from the signing key's <see cref="Tag"/> and an optional
/// <c>kid</c> a Receiver uses to select the key from the Transmitter's
/// <c>jwks_uri</c>.
/// </para>
/// <para>
/// Signing flows through the standard JCose composition
/// (<see cref="UnsignedJwt"/> → <see cref="JwtSigningExtensions.SignAsync"/>),
/// which resolves the per-algorithm signing function from the key's
/// <see cref="Tag"/> via the crypto function registry — the same path used by
/// token issuance, KB-JWT issuance, and JAR signing.
/// </para>
/// </remarks>
public static class SecurityEventTokenIssuance
{
    /// <summary>
    /// Builds and signs a SET carrying <paramref name="events"/> about the
    /// principal identified by <paramref name="subjectId"/>.
    /// </summary>
    /// <param name="issuer">The <c>iss</c> claim — the Transmitter's issuer identifier.</param>
    /// <param name="audiences">The <c>aud</c> claim — the Receiver(s); at least one is required.</param>
    /// <param name="jwtId">The <c>jti</c> claim — a unique per-token identifier for replay defense.</param>
    /// <param name="issuedAt">The <c>iat</c> claim, encoded as Unix seconds.</param>
    /// <param name="events">The events to carry; at least one is required (RFC 8417 §2.2).</param>
    /// <param name="signingKey">The Transmitter's signing key; the <c>alg</c> derives from its <see cref="Tag"/>.</param>
    /// <param name="base64UrlEncoder">Base64url encoder for compact serialization.</param>
    /// <param name="headerSerializer">Serializes the protected header to UTF-8 JSON bytes.</param>
    /// <param name="payloadSerializer">Serializes the payload claims to UTF-8 JSON bytes.</param>
    /// <param name="memoryPool">Memory pool for transient signing buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="signingKeyId">Optional <c>kid</c> header naming the signing key in the Transmitter's JWK set.</param>
    /// <param name="subjectId">Optional <c>sub_id</c> subject identifier for the principal the SET is about.</param>
    /// <param name="timeOfEvent">Optional <c>toe</c> claim — when the event occurred, encoded as Unix seconds.</param>
    /// <param name="transaction">Optional <c>txn</c> claim correlating the SET with a transaction.</param>
    /// <returns>The compact-serialized SET (<c>header.payload.signature</c>).</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "JwsMessage is disposed via the using statement before the method returns; the returned string is independent of the message.")]
    public static async ValueTask<string> IssueAsync(
        string issuer,
        IReadOnlyList<string> audiences,
        string jwtId,
        DateTimeOffset issuedAt,
        IReadOnlyList<SecurityEvent> events,
        PrivateKeyMemory signingKey,
        EncodeDelegate base64UrlEncoder,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken,
        string? signingKeyId = null,
        SubjectIdentifier? subjectId = null,
        DateTimeOffset? timeOfEvent = null,
        string? transaction = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentNullException.ThrowIfNull(audiences);
        ArgumentException.ThrowIfNullOrWhiteSpace(jwtId);
        ArgumentNullException.ThrowIfNull(events);
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(memoryPool);

        if(audiences.Count == 0)
        {
            throw new ArgumentException("A SET requires at least one audience.", nameof(audiences));
        }

        if(events.Count == 0)
        {
            throw new ArgumentException("A SET requires at least one event.", nameof(events));
        }

        cancellationToken.ThrowIfCancellationRequested();

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);

        var header = new JwtHeader(signingKeyId is null ? 2 : 3)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = WellKnownMediaTypes.Jwt.SecEventJwt
        };

        if(signingKeyId is not null)
        {
            header[WellKnownJwkMemberNames.Kid] = signingKeyId;
        }

        int capacity = 4
            + (subjectId is not null ? 1 : 0)
            + (timeOfEvent is not null ? 1 : 0)
            + (transaction is not null ? 1 : 0);

        var payload = new JwtPayload(capacity)
        {
            [WellKnownJwtClaimNames.Iss] = issuer,
            [WellKnownJwtClaimNames.Iat] = issuedAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Jti] = jwtId,
            [WellKnownJwtClaimNames.Aud] = BuildAudience(audiences),
            [SecurityEventTokenClaimNames.Events] = BuildEvents(events)
        };

        if(subjectId is not null)
        {
            payload[SecurityEventTokenClaimNames.SubId] = subjectId.ToWireObject();
        }

        if(timeOfEvent is not null)
        {
            payload[SecurityEventTokenClaimNames.Toe] = timeOfEvent.Value.ToUnixTimeSeconds();
        }

        if(transaction is not null)
        {
            payload[SecurityEventTokenClaimNames.Txn] = transaction;
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


    //A single audience is written as a JSON string; multiple as a JSON array,
    //per the "aud" syntax of RFC 7519 §4.1.3.
    private static object BuildAudience(IReadOnlyList<string> audiences)
    {
        if(audiences.Count == 1)
        {
            return audiences[0];
        }

        var array = new List<object>(audiences.Count);
        foreach(string audience in audiences)
        {
            array.Add(audience);
        }

        return array;
    }


    //The "events" claim is a JSON object keyed by event-type URI; each value is
    //the event payload object (RFC 8417 §2.2).
    private static Dictionary<string, object> BuildEvents(IReadOnlyList<SecurityEvent> events)
    {
        var map = new Dictionary<string, object>(events.Count, StringComparer.Ordinal);
        foreach(SecurityEvent securityEvent in events)
        {
            ArgumentNullException.ThrowIfNull(securityEvent);
            map[securityEvent.EventType] = new Dictionary<string, object>(securityEvent.Payload, StringComparer.Ordinal);
        }

        return map;
    }
}
