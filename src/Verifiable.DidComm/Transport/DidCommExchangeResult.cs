using System;
using Verifiable.Foundation;

namespace Verifiable.DidComm.Transport;

/// <summary>
/// The transport-neutral outcome of a DIDComm request/response exchange conducted over a connection the
/// Return-Route extension directs a reply onto, per
/// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">DIDComm Messaging Return-Route and Queue Transport Extension</see>.
/// </summary>
/// <remarks>
/// <para>
/// Reuses <see cref="DidCommTransmitError"/> — the same failure taxonomy as the one-way
/// <see cref="DidCommTransmitResult"/> — since an exchange can fail the same ways a one-way send can (policy
/// denial, endpoint non-acceptance, transport failure); it additionally MAY carry a reply.
/// </para>
/// <para>
/// <see cref="ReplyBody"/> is pass-through wire data: this type performs no classification of it —
/// distinguishing a plaintext/signed/encrypted DIDComm reply is <c>DidCommInbound.Classify</c>'s job, not
/// this result's. <see cref="HasReply"/> is <see langword="true"/> exactly when <see cref="ReplyBody"/> is
/// non-empty; an accepted outcome with an empty body (e.g. a bare HTTP 202) is a legal "accepted, nothing to
/// return".
/// </para>
/// <para>
/// <strong>Ownership.</strong> This type owns <see cref="ReplyBody"/> and implements <see cref="IDisposable"/>
/// by delegating to it: <c>using var result = await ...ExchangeAsync(...)</c> returns the rented reply lease
/// to its pool exactly once, however the result was minted — a reply-less outcome disposes
/// <see cref="PooledMemory.Empty"/>, which is always a no-op. Disposing twice in SERIALIZED succession is
/// safe (delegation inherits <see cref="PooledMemory"/>'s own double-dispose guard, a plain bool underneath —
/// concurrent double-dispose is not a guarantee this makes). Reading <see cref="ReplyBody"/>'s bytes after
/// disposal throws through the same carrier for every reply this library mints — a <see cref="BaseMemoryPool"/>
/// rental copied via <c>PooledMemory.FromBytes</c> — see <see cref="PooledMemory.AsReadOnlySpan"/>'s own
/// remarks for the dependency that guarantee rests on.
/// </para>
/// <para>
/// The factories are <see langword="public"/> so an exchange delegate defined outside this assembly (a
/// WebSocket/Bluetooth/libp2p binding) can mint a result.
/// </para>
/// </remarks>
public sealed class DidCommExchangeResult: IDisposable
{
    private DidCommExchangeResult(
        bool isAccepted,
        int? transportStatusCode,
        DidCommTransmitError error,
        PooledMemory replyBody,
        string? replyMediaType)
    {
        IsAccepted = isAccepted;
        TransportStatusCode = transportStatusCode;
        Error = error;
        ReplyBody = replyBody;
        ReplyMediaType = replyMediaType;
    }


    /// <summary>Whether the endpoint accepted the request.</summary>
    public bool IsAccepted { get; }

    /// <summary>An OPTIONAL transport-specific numeric code (e.g. an HTTPS status), or <see langword="null"/> for a transport without one or when no response was received.</summary>
    public int? TransportStatusCode { get; }

    /// <summary>The reason the exchange did not succeed, or <see cref="DidCommTransmitError.None"/> when it was accepted.</summary>
    public DidCommTransmitError Error { get; }

    /// <summary>The reply bytes carried back on the same connection, owned by this result, or <see cref="PooledMemory.Empty"/> when none arrived.</summary>
    public PooledMemory ReplyBody { get; }

    /// <summary>The reply's IANA media type as the endpoint reported it, or <see langword="null"/> when there is no reply or none was reported.</summary>
    public string? ReplyMediaType { get; }

    /// <summary>Whether a non-empty reply arrived.</summary>
    public bool HasReply => !ReplyBody.IsEmpty;


    /// <summary>
    /// Mints an accepted outcome carrying a reply delivered back on the same connection. This is an OWNERSHIP
    /// TRANSFER: the result owns <paramref name="replyBody"/> from this call on, and the caller MUST NOT
    /// dispose it separately — disposing the returned result (<see cref="Dispose"/>) returns the lease.
    /// </summary>
    /// <param name="transportStatusCode">The transport's numeric code, or <see langword="null"/> for a channel without one.</param>
    /// <param name="replyBody">The reply bytes; ownership transfers to the returned result.</param>
    /// <param name="replyMediaType">The reply's IANA media type, or <see langword="null"/> when not reported.</param>
    /// <returns>An accepted result carrying the reply.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="replyBody"/> is <see langword="null"/>.</exception>
    public static DidCommExchangeResult Accepted(int? transportStatusCode, PooledMemory replyBody, string? replyMediaType)
    {
        ArgumentNullException.ThrowIfNull(replyBody);

        return new DidCommExchangeResult(true, transportStatusCode, DidCommTransmitError.None, replyBody, replyMediaType);
    }


    /// <summary>Mints an accepted outcome with no reply — a legal "accepted, nothing to return" (e.g. a bare 202).</summary>
    /// <param name="transportStatusCode">The transport's numeric code, or <see langword="null"/> for a channel without one.</param>
    /// <returns>An accepted result carrying no reply.</returns>
    public static DidCommExchangeResult Accepted(int? transportStatusCode = null)
    {
        return new DidCommExchangeResult(true, transportStatusCode, DidCommTransmitError.None, PooledMemory.Empty, null);
    }


    /// <summary>Mints a rejected outcome — the endpoint was reached but did not accept — optionally carrying the transport's numeric code. Never carries a reply.</summary>
    /// <param name="transportStatusCode">The transport's numeric code, or <see langword="null"/> for a channel without one.</param>
    /// <returns>A rejected result.</returns>
    public static DidCommExchangeResult Rejected(int? transportStatusCode = null)
    {
        return new DidCommExchangeResult(false, transportStatusCode, DidCommTransmitError.Rejected, PooledMemory.Empty, null);
    }


    /// <summary>Mints an outcome for an endpoint the outbound policy denied before contact.</summary>
    /// <returns>A policy-denied result.</returns>
    public static DidCommExchangeResult DeniedByPolicy()
    {
        return new DidCommExchangeResult(false, null, DidCommTransmitError.DeniedByPolicy, PooledMemory.Empty, null);
    }


    /// <summary>Mints an outcome for a transport-level delivery failure (socket/DNS/connection error, no response, or a reply that exceeded the caller's accepted size bound).</summary>
    /// <returns>A transport-failure result.</returns>
    public static DidCommExchangeResult TransportFailed()
    {
        return new DidCommExchangeResult(false, null, DidCommTransmitError.TransportFailed, PooledMemory.Empty, null);
    }


    /// <summary>Returns <see cref="ReplyBody"/>'s lease to its pool. Safe to call more than once, and a no-op for a reply-less result (<see cref="PooledMemory.Empty"/>).</summary>
    public void Dispose()
    {
        ReplyBody.Dispose();
    }
}
