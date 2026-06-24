using System;
using System.Collections.Generic;

namespace Verifiable.DidComm.TrustPing;

/// <summary>
/// Build and interpret for the DIDComm Trust Ping Protocol 2.0 — the two-message connectivity check that
/// proves a channel works end to end, per
/// <see href="https://didcomm.org/trust-ping/2.0/">DIDComm Trust Ping Protocol 2.0</see>.
/// </summary>
/// <remarks>
/// <para>
/// Trust Ping is a didcomm.org companion protocol, NOT part of the DIDComm Messaging v2.1 core
/// specification. A sender sends a <c>ping</c> (normally inside an encrypted envelope); if a
/// <c>ping-response</c> comes back, the sender has proven the recipient's DID resolves, the keys agree,
/// any mediators forward, and the envelope round-trips — the trust the protocol's name refers to is
/// confidence that the channel works, not identity trust.
/// </para>
/// <para>
/// <see cref="CreatePing"/> and <see cref="CreatePingResponse"/> are producer-side and MAY throw on bad
/// caller arguments; the <c>Is…</c> discriminators read a (already envelope-authenticated) message and never
/// throw. The discriminators use the spec-mandated MTURI dispatch match
/// (<see cref="MessageTypeUri.IsSameMessageType(MessageTypeUri?)"/>): protocol and message names ignoring
/// case and punctuation, same major version, under the same documentation URI — so a future
/// <c>trust-ping/2.x</c> ping still dispatches. There is no typed body record: a ping carries only the
/// optional <c>response_requested</c> flag and a ping-response carries nothing, so — like the ACK surface
/// (<see cref="DidCommAckExtensions"/>) — the protocol operates directly on <see cref="DidCommMessage"/>.
/// </para>
/// </remarks>
public static class TrustPingExtensions
{
    //The ping / ping-response Message Type URIs, parsed once for semver-compatible handler dispatch.
    private static readonly MessageTypeUri PingMessageType = MessageTypeUri.Parse(WellKnownTrustPingNames.PingType);
    private static readonly MessageTypeUri PingResponseMessageType = MessageTypeUri.Parse(WellKnownTrustPingNames.PingResponseType);


    /// <summary>
    /// Builds a Trust Ping <c>ping</c> message: <c>type</c> is the ping Message Type URI and
    /// <c>body.response_requested</c> states whether a <c>ping-response</c> is wanted
    /// (didcomm.org/trust-ping/2.0 §ping).
    /// </summary>
    /// <param name="id">REQUIRED. The ping message id, unique to the sender; it seeds the thread the ping-response continues (DIDComm v2.1 §Message Headers).</param>
    /// <param name="from">OPTIONAL but recommended. The sender identifier, so the receiver can address the ping-response.</param>
    /// <param name="responseRequested">Whether a <c>ping-response</c> is wanted; defaults to <see langword="true"/>. Pass <see langword="false"/> for a fire-and-forget liveness signal the receiver MUST NOT answer.</param>
    /// <returns>The ping message.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="id"/> is null or empty.</exception>
    public static DidCommMessage CreatePing(string id, string? from = null, bool responseRequested = true)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);

        return new DidCommMessage
        {
            Id = id,
            Type = WellKnownTrustPingNames.PingType,
            From = from,
            Body = new Dictionary<string, object> { [WellKnownTrustPingNames.ResponseRequested] = responseRequested }
        };
    }


    /// <summary>
    /// Builds the <c>ping-response</c> answering <paramref name="ping"/>: <c>type</c> is the ping-response
    /// Message Type URI, it carries no body (the spec's ping-response is <c>{type, id, thid}</c>), and <c>thid</c> continues the ping's thread
    /// so the sender can correlate the response with its ping (didcomm.org/trust-ping/2.0 §ping-response).
    /// The caller decides whether to send it by consulting <see cref="IsPingResponseRequested"/> first.
    /// </summary>
    /// <param name="ping">The received ping the response answers.</param>
    /// <param name="id">REQUIRED. The ping-response's own message id, unique to the responder.</param>
    /// <param name="from">OPTIONAL. The responder identifier.</param>
    /// <returns>The ping-response message continuing the ping's thread.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="id"/> is null or empty, <paramref name="ping"/> is not a Trust Ping ping, or the ping carries no thread id.</exception>
    public static DidCommMessage CreatePingResponse(this DidCommMessage ping, string id, string? from = null)
    {
        ArgumentNullException.ThrowIfNull(ping);
        ArgumentException.ThrowIfNullOrEmpty(id);

        if(!ping.IsTrustPing())
        {
            throw new ArgumentException(
                "A ping-response can only be built for a Trust Ping 2.0 ping message (didcomm.org/trust-ping/2.0).",
                nameof(ping));
        }

        //The ping-response MUST be part of the ping's thread; the ping normally starts a new thread, so its
        //effective thread id is its own id (DIDComm v2.1 §Threading).
        if(ping.EffectiveThreadId is not string threadId)
        {
            throw new ArgumentException(
                "The ping MUST carry an 'id' (or 'thid') so the ping-response can continue its thread (didcomm.org/trust-ping/2.0 §ping-response).",
                nameof(ping));
        }

        return new DidCommMessage
        {
            Id = id,
            Type = WellKnownTrustPingNames.PingResponseType,
            From = from,
            ThreadId = threadId
        };
    }


    /// <summary>
    /// Whether <paramref name="message"/> is a Trust Ping <c>ping</c> — its <c>type</c> names the ping
    /// Message Type URI (didcomm.org/trust-ping/2.0 §ping).
    /// </summary>
    /// <param name="message">The message to inspect.</param>
    /// <returns><see langword="true"/> when the message is a ping.</returns>
    public static bool IsTrustPing(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return MessageTypeUri.TryParse(message.Type, out MessageTypeUri? messageType)
            && messageType.IsSameMessageType(PingMessageType);
    }


    /// <summary>
    /// Whether <paramref name="message"/> is a Trust Ping <c>ping-response</c> — its <c>type</c> names the
    /// ping-response Message Type URI (didcomm.org/trust-ping/2.0 §ping-response).
    /// </summary>
    /// <param name="message">The message to inspect.</param>
    /// <returns><see langword="true"/> when the message is a ping-response.</returns>
    public static bool IsTrustPingResponse(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return MessageTypeUri.TryParse(message.Type, out MessageTypeUri? messageType)
            && messageType.IsSameMessageType(PingResponseMessageType);
    }


    /// <summary>
    /// Whether <paramref name="ping"/> requests a <c>ping-response</c> — <c>true</c> unless its
    /// <c>body.response_requested</c> is the explicit boolean <see langword="false"/>
    /// (didcomm.org/trust-ping/2.0 §ping: <c>response_requested</c> is OPTIONAL and defaults to
    /// <see langword="true"/>).
    /// </summary>
    /// <remarks>
    /// A malformed (non-boolean) <c>response_requested</c> does not silently suppress the response: the
    /// protocol's stated default is <see langword="true"/>, so only an explicit <see langword="false"/>
    /// turns it off — erring toward the cooperative direction a connectivity check expects.
    /// </remarks>
    /// <param name="ping">The received ping.</param>
    /// <returns><see langword="true"/> unless the ping explicitly declines a response.</returns>
    public static bool IsPingResponseRequested(this DidCommMessage ping)
    {
        ArgumentNullException.ThrowIfNull(ping);

        if(ping.Body is { } body
            && body.TryGetValue(WellKnownTrustPingNames.ResponseRequested, out object? value)
            && value is bool requested)
        {
            return requested;
        }

        return true;
    }
}
