using System;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;

namespace Verifiable.DidComm.Transport;

/// <summary>
/// A transport-neutral DIDComm request/response exchange: delivers a packed envelope — its bytes and IANA
/// media type — to a concrete endpoint and returns whatever reply the endpoint sends back over the SAME
/// connection, per the
/// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">DIDComm Messaging Return-Route and Queue Transport Extension</see>.
/// </summary>
/// <remarks>
/// <para>
/// This is the documented EXCEPTION to the one-way rule <see cref="DidCommSendDelegate"/> carries. DIDComm
/// transports are one-way by default (DIDComm Messaging v2.1
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">§Transports</see>,
/// §HTTPS, §WebSockets: no application reply flows back on the delivery channel) — but the Return-Route
/// extension directs a reply onto the same connection when the request carries <c>return_route: all</c> — see
/// <c>DidCommReturnRouteExtensions.IsReturnRouteAll</c>. This delegate exists only for that directed-reply
/// case; a request that does not set the directive uses <see cref="DidCommSendDelegate"/> instead. The
/// Return-Route extension also permits a satisfiable <c>thread</c> to direct a reply, but the shipped
/// <see cref="DidCommTransportExtensions"/>'s <c>ExchangeAsync</c> guard admits ONLY <c>return_route: all</c> —
/// thread-directed replies are out of scope for this surface.
/// </para>
/// <para>
/// Not to be confused with <see cref="ExchangeContext"/>: that type carries the outbound fetch policy and
/// per-operation state passed to every call; this delegate IS the request/response channel that produces the
/// reply, carrying no policy of its own.
/// </para>
/// <para>
/// <paramref name="message"/> is a BORROWED view valid only for the duration of the returned task — the same
/// discipline as <see cref="DidCommSendDelegate"/>: the caller keeps the packed request alive across the
/// await, and an implementation MUST finish reading the bytes before its task completes and MUST NOT retain
/// the memory afterwards. The reply carried on <see cref="DidCommExchangeResult.ReplyBody"/> is owned by the
/// result, not borrowed — the caller of this delegate disposes the returned <see cref="DidCommExchangeResult"/>
/// to return that reply's lease.
/// </para>
/// </remarks>
/// <param name="message">The packed request bytes to deliver.</param>
/// <param name="mediaType">The request's IANA media type (e.g. <c>application/didcomm-encrypted+json</c>).</param>
/// <param name="endpoint">The concrete transport endpoint to deliver to.</param>
/// <param name="context">The exchange context carrying the outbound policy and any per-operation state.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The transport-neutral request/response outcome, including any reply.</returns>
public delegate ValueTask<DidCommExchangeResult> DidCommExchangeDelegate(
    ReadOnlyMemory<byte> message,
    string mediaType,
    Uri endpoint,
    ExchangeContext context,
    CancellationToken cancellationToken);
