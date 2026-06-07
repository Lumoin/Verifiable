using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// Issues the two framework SETs the Shared Signals Framework itself defines —
/// the Verification Event (SSF 1.0 §8.1.4.1) and the Stream Updated Event
/// (§8.1.5) — composed over <see cref="SecurityEventTokenIssuance"/>.
/// </summary>
/// <remarks>
/// Both events identify the stream itself: the top-level <c>sub_id</c> MUST be
/// an <c>opaque</c> Subject Identifier whose <c>id</c> is the <c>stream_id</c>,
/// which these helpers enforce so a transmitter cannot emit a framework event
/// about the wrong kind of subject.
/// </remarks>
public static class SsfFrameworkSetIssuance
{
    /// <summary>
    /// Issues a Verification Event SET (§8.1.4.1). When the verification was
    /// triggered by the Receiver with a <c>state</c>, the Transmitter MUST echo it
    /// in the event payload; a Transmitter-initiated verification carries none.
    /// </summary>
    /// <param name="streamId">The stream being verified — becomes the <c>opaque</c> <c>sub_id</c>.</param>
    /// <param name="state">The Receiver-supplied state to echo, or <see langword="null"/> when Transmitter-initiated.</param>
    /// <param name="issuer">The <c>iss</c> claim — the Transmitter's issuer identifier.</param>
    /// <param name="audiences">The <c>aud</c> claim — the Receiver(s).</param>
    /// <param name="jwtId">The <c>jti</c> claim.</param>
    /// <param name="issuedAt">The <c>iat</c> claim.</param>
    /// <param name="signingKey">The Transmitter's signing key.</param>
    /// <param name="base64UrlEncoder">Base64url encoder for compact serialization.</param>
    /// <param name="headerSerializer">Serializes the protected header to UTF-8 JSON bytes.</param>
    /// <param name="payloadSerializer">Serializes the payload claims to UTF-8 JSON bytes.</param>
    /// <param name="memoryPool">Memory pool for transient signing buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="signingKeyId">Optional <c>kid</c> header naming the signing key.</param>
    /// <returns>The compact-serialized verification SET.</returns>
    public static ValueTask<string> IssueVerificationSetAsync(
        string streamId,
        string? state,
        string issuer,
        IReadOnlyList<string> audiences,
        string jwtId,
        DateTimeOffset issuedAt,
        PrivateKeyMemory signingKey,
        EncodeDelegate base64UrlEncoder,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken,
        string? signingKeyId = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(streamId);

        var payload = new Dictionary<string, object>(state is null ? 0 : 1, StringComparer.Ordinal);
        if(state is not null)
        {
            payload[SsfStreamManagementParameterNames.State] = state;
        }

        return SecurityEventTokenIssuance.IssueAsync(
            issuer,
            audiences,
            jwtId,
            issuedAt,
            [new SecurityEvent { EventType = SsfEventTypes.Verification, Payload = payload }],
            signingKey,
            base64UrlEncoder,
            headerSerializer,
            payloadSerializer,
            memoryPool,
            cancellationToken,
            signingKeyId,
            subjectId: SubjectIdentifier.Opaque(streamId));
    }


    /// <summary>
    /// Issues a Stream Updated Event SET (§8.1.5) — the Transmitter MUST send it
    /// before pausing/disabling a stream on its own initiative and upon
    /// re-enabling it.
    /// </summary>
    /// <param name="streamId">The stream whose status changed — becomes the <c>opaque</c> <c>sub_id</c>.</param>
    /// <param name="status">
    /// The new status (REQUIRED) — one of the <see cref="SsfStreamStatusValues"/>.
    /// </param>
    /// <param name="reason">Optional short description of why the Transmitter changed the status.</param>
    /// <param name="issuer">The <c>iss</c> claim — the Transmitter's issuer identifier.</param>
    /// <param name="audiences">The <c>aud</c> claim — the Receiver(s).</param>
    /// <param name="jwtId">The <c>jti</c> claim.</param>
    /// <param name="issuedAt">The <c>iat</c> claim.</param>
    /// <param name="signingKey">The Transmitter's signing key.</param>
    /// <param name="base64UrlEncoder">Base64url encoder for compact serialization.</param>
    /// <param name="headerSerializer">Serializes the protected header to UTF-8 JSON bytes.</param>
    /// <param name="payloadSerializer">Serializes the payload claims to UTF-8 JSON bytes.</param>
    /// <param name="memoryPool">Memory pool for transient signing buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="signingKeyId">Optional <c>kid</c> header naming the signing key.</param>
    /// <returns>The compact-serialized stream-updated SET.</returns>
    public static ValueTask<string> IssueStreamUpdatedSetAsync(
        string streamId,
        string status,
        string? reason,
        string issuer,
        IReadOnlyList<string> audiences,
        string jwtId,
        DateTimeOffset issuedAt,
        PrivateKeyMemory signingKey,
        EncodeDelegate base64UrlEncoder,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken,
        string? signingKeyId = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(streamId);
        ArgumentException.ThrowIfNullOrWhiteSpace(status);

        var payload = new Dictionary<string, object>(reason is null ? 1 : 2, StringComparer.Ordinal)
        {
            [SsfStreamStatusParameterNames.Status] = status
        };
        if(reason is not null)
        {
            payload[SsfStreamStatusParameterNames.Reason] = reason;
        }

        return SecurityEventTokenIssuance.IssueAsync(
            issuer,
            audiences,
            jwtId,
            issuedAt,
            [new SecurityEvent { EventType = SsfEventTypes.StreamUpdated, Payload = payload }],
            signingKey,
            base64UrlEncoder,
            headerSerializer,
            payloadSerializer,
            memoryPool,
            cancellationToken,
            signingKeyId,
            subjectId: SubjectIdentifier.Opaque(streamId));
    }
}
