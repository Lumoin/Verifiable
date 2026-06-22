using System;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;

namespace Verifiable.DidComm;

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
/// the await, so the borrowed bytes are valid for the duration of the delegate's task.
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
}
