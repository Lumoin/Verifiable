using System;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.DidComm.ReturnRoute;

namespace Verifiable.DidComm.Transport;

/// <summary>
/// Transport-neutral transmission of a packed DIDComm message: hands the envelope's bytes and IANA media type
/// to a <see cref="DidCommSendDelegate"/>, which delivers them over whatever channel the application provides,
/// per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>.
/// </summary>
/// <remarks>
/// DIDComm is transport-agnostic: these overloads carry no <c>System.Net</c> and make no channel assumption —
/// they read the message's channel-independent bytes and static media type and pass them to the supplied
/// delegate. The HTTPS binding is one such delegate (<see cref="DidCommHttpTransport.CreateSendDelegate"/>); a
/// WebSocket/Bluetooth/libp2p delegate is supplied by the application. The packed message is kept alive across
/// the await, so the borrowed bytes are valid for the duration of the delegate's task. Alongside these one-way
/// <c>TransmitAsync</c> overloads, this type also carries the <c>ExchangeAsync</c> overloads that pair a packed
/// request with a <see cref="DidCommExchangeDelegate"/> seam — that path serves ONLY a request carrying
/// <c>return_route: all</c>, a precondition it throws on rather than silently ignores.
/// </remarks>
public static class DidCommTransportExtensions
{
    /// <summary>Transmits a packed encrypted message to <paramref name="endpoint"/> via <paramref name="send"/>.</summary>
    /// <param name="message">The packed encrypted message to deliver.</param>
    /// <param name="endpoint">The concrete transport endpoint.</param>
    /// <param name="context">The exchange context carrying the outbound policy.</param>
    /// <param name="send">The transport that delivers the bytes over a specific channel.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The transport-neutral delivery outcome.</returns>
    public static ValueTask<DidCommTransmitResult> TransmitAsync(
        this DidCommEncryptedMessage message,
        Uri endpoint,
        ExchangeContext context,
        DidCommSendDelegate send,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);

        return SendCoreAsync(message.AsReadOnlyMemory(), DidCommEncryptedMessage.MediaType, endpoint, context, send, cancellationToken);
    }


    /// <summary>Transmits a packed signed message to <paramref name="endpoint"/> via <paramref name="send"/>.</summary>
    /// <param name="message">The packed signed message to deliver.</param>
    /// <param name="endpoint">The concrete transport endpoint.</param>
    /// <param name="context">The exchange context carrying the outbound policy.</param>
    /// <param name="send">The transport that delivers the bytes over a specific channel.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The transport-neutral delivery outcome.</returns>
    public static ValueTask<DidCommTransmitResult> TransmitAsync(
        this DidCommSignedMessage message,
        Uri endpoint,
        ExchangeContext context,
        DidCommSendDelegate send,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);

        return SendCoreAsync(message.AsReadOnlyMemory(), DidCommSignedMessage.MediaType, endpoint, context, send, cancellationToken);
    }


    /// <summary>
    /// Transmits a packed plaintext message to <paramref name="endpoint"/> via <paramref name="send"/>. Plaintext
    /// has no confidentiality or authenticity and is not normally sent across a security boundary; the overload
    /// exists for completeness.
    /// </summary>
    /// <param name="message">The packed plaintext message to deliver.</param>
    /// <param name="endpoint">The concrete transport endpoint.</param>
    /// <param name="context">The exchange context carrying the outbound policy.</param>
    /// <param name="send">The transport that delivers the bytes over a specific channel.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The transport-neutral delivery outcome.</returns>
    public static ValueTask<DidCommTransmitResult> TransmitAsync(
        this DidCommPlaintextMessage message,
        Uri endpoint,
        ExchangeContext context,
        DidCommSendDelegate send,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);

        return SendCoreAsync(message.AsReadOnlyMemory(), DidCommPlaintextMessage.MediaType, endpoint, context, send, cancellationToken);
    }


    //Reads the message's borrowed bytes and static media type and hands them to the supplied transport. The
    //null guards mirror the producer-side guards the HTTPS binding applies; the send delegate owns the
    //channel-specific delivery and the outcome mapping.
    private static ValueTask<DidCommTransmitResult> SendCoreAsync(
        ReadOnlyMemory<byte> body,
        string mediaType,
        Uri endpoint,
        ExchangeContext context,
        DidCommSendDelegate send,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(send);

        return send(body, mediaType, endpoint, context, cancellationToken);
    }


    /// <summary>
    /// Exchanges a packed encrypted request with <paramref name="endpoint"/> via <paramref name="exchange"/>,
    /// returning any reply carried back over the same connection, per the
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">DIDComm Messaging Return-Route and Queue Transport Extension</see>.
    /// </summary>
    /// <param name="message">The packed encrypted message to deliver — the packed rendering of <paramref name="request"/>. This is a documented caller obligation: the two are not cross-checked at this layer.</param>
    /// <param name="request">The plaintext request that was packed into <paramref name="message"/>. MUST direct replies onto the connection.</param>
    /// <param name="endpoint">The concrete transport endpoint.</param>
    /// <param name="context">The exchange context carrying the outbound policy.</param>
    /// <param name="exchange">The transport that delivers the bytes over a specific channel and reads back any reply.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The transport-neutral request/response outcome, including any reply. The caller owns the returned
    /// <see cref="DidCommExchangeResult"/> and disposes it (<c>using var result = await ...ExchangeAsync(...)</c>)
    /// to return the reply's pooled lease; a reply-less outcome disposes as a no-op.
    /// </returns>
    /// <exception cref="ArgumentException"><paramref name="request"/> does not carry <c>return_route: all</c> — see <c>DidCommReturnRouteExtensions.IsReturnRouteAll</c>.</exception>
    public static ValueTask<DidCommExchangeResult> ExchangeAsync(
        this DidCommEncryptedMessage message,
        DidCommMessage request,
        Uri endpoint,
        ExchangeContext context,
        DidCommExchangeDelegate exchange,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);

        return ExchangeCoreAsync(message.AsReadOnlyMemory(), DidCommEncryptedMessage.MediaType, request, endpoint, context, exchange, cancellationToken);
    }


    /// <summary>
    /// Exchanges a packed signed request with <paramref name="endpoint"/> via <paramref name="exchange"/>,
    /// returning any reply carried back over the same connection, per the
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">DIDComm Messaging Return-Route and Queue Transport Extension</see>.
    /// </summary>
    /// <param name="message">The packed signed message to deliver — the packed rendering of <paramref name="request"/>. This is a documented caller obligation: the two are not cross-checked at this layer.</param>
    /// <param name="request">The plaintext request that was packed into <paramref name="message"/>. MUST direct replies onto the connection.</param>
    /// <param name="endpoint">The concrete transport endpoint.</param>
    /// <param name="context">The exchange context carrying the outbound policy.</param>
    /// <param name="exchange">The transport that delivers the bytes over a specific channel and reads back any reply.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The transport-neutral request/response outcome, including any reply. The caller owns the returned
    /// <see cref="DidCommExchangeResult"/> and disposes it (<c>using var result = await ...ExchangeAsync(...)</c>)
    /// to return the reply's pooled lease; a reply-less outcome disposes as a no-op.
    /// </returns>
    /// <exception cref="ArgumentException"><paramref name="request"/> does not carry <c>return_route: all</c> — see <c>DidCommReturnRouteExtensions.IsReturnRouteAll</c>.</exception>
    public static ValueTask<DidCommExchangeResult> ExchangeAsync(
        this DidCommSignedMessage message,
        DidCommMessage request,
        Uri endpoint,
        ExchangeContext context,
        DidCommExchangeDelegate exchange,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);

        return ExchangeCoreAsync(message.AsReadOnlyMemory(), DidCommSignedMessage.MediaType, request, endpoint, context, exchange, cancellationToken);
    }


    /// <summary>
    /// Exchanges a packed plaintext request with <paramref name="endpoint"/> via <paramref name="exchange"/>,
    /// returning any reply carried back over the same connection, per the
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">DIDComm Messaging Return-Route and Queue Transport Extension</see>.
    /// Plaintext has no confidentiality or authenticity and is not normally sent across a security boundary;
    /// the overload exists for completeness.
    /// </summary>
    /// <param name="message">The packed plaintext message to deliver — the packed rendering of <paramref name="request"/>. This is a documented caller obligation: the two are not cross-checked at this layer.</param>
    /// <param name="request">The request that was packed into <paramref name="message"/> (the same instance for a plaintext exchange). MUST direct replies onto the connection.</param>
    /// <param name="endpoint">The concrete transport endpoint.</param>
    /// <param name="context">The exchange context carrying the outbound policy.</param>
    /// <param name="exchange">The transport that delivers the bytes over a specific channel and reads back any reply.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The transport-neutral request/response outcome, including any reply. The caller owns the returned
    /// <see cref="DidCommExchangeResult"/> and disposes it (<c>using var result = await ...ExchangeAsync(...)</c>)
    /// to return the reply's pooled lease; a reply-less outcome disposes as a no-op.
    /// </returns>
    /// <exception cref="ArgumentException"><paramref name="request"/> does not carry <c>return_route: all</c> — see <c>DidCommReturnRouteExtensions.IsReturnRouteAll</c>.</exception>
    public static ValueTask<DidCommExchangeResult> ExchangeAsync(
        this DidCommPlaintextMessage message,
        DidCommMessage request,
        Uri endpoint,
        ExchangeContext context,
        DidCommExchangeDelegate exchange,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);

        return ExchangeCoreAsync(message.AsReadOnlyMemory(), DidCommPlaintextMessage.MediaType, request, endpoint, context, exchange, cancellationToken);
    }


    //Guards that the request directs replies onto the connection — the exchange channel only exists for that
    //case (Return-Route and Queue Transport Extension §Return Route Header) — then hands the borrowed bytes
    //and static media type to the supplied exchange delegate.
    private static ValueTask<DidCommExchangeResult> ExchangeCoreAsync(
        ReadOnlyMemory<byte> body,
        string mediaType,
        DidCommMessage request,
        Uri endpoint,
        ExchangeContext context,
        DidCommExchangeDelegate exchange,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(exchange);

        if(!request.IsReturnRouteAll())
        {
            throw new ArgumentException(
                "An exchange delegate is used only for a request that directs replies onto the connection " +
                "(return_route: all) — DIDComm Messaging Return-Route and Queue Transport Extension " +
                "§Return Route Header.",
                nameof(request));
        }

        return exchange(body, mediaType, endpoint, context, cancellationToken);
    }
}
