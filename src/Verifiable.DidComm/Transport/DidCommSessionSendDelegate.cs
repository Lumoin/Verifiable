using System;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.DidComm.Transport;

/// <summary>
/// Sends ONE complete DIDComm frame over an application's already-open, persistent duplex connection (a
/// WebSocket, or any channel that stays open across multiple messages), per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports §WebSockets</see>.
/// </summary>
/// <remarks>
/// <para>
/// This is the persistent-connection sibling of <see cref="DidCommSendDelegate"/>: that delegate dials a
/// fresh endpoint per call, this one reuses a connection the application already holds open — the seam
/// <see cref="DidCommSocketSession"/> is built on. The application owns the socket and its pump (connect or
/// accept, handshake, frame reassembly, close); this delegate only ever sees a COMPLETE frame as memory
/// (DIDComm v2.1 §WebSockets: "each message MUST be transmitted individually; ... the unit of encryption or
/// signing is one message only").
/// </para>
/// <para>
/// Websockets are one-way by default (DIDComm v2.1 §WebSockets: "Websockets are used only for one-way
/// transmission from sender to receiver; responses don't flow back the other way on the socket") — this
/// delegate is that one-way send, called from <see cref="DidCommSocketSession.SendAsync"/>. The documented
/// exception is <see cref="DidCommSocketSession.ExchangeAsync"/>, which sends over this SAME delegate but
/// only after its own guard has confirmed the request directs a reply onto the connection via the
/// Return-Route extension's <c>return_route: all</c>.
/// </para>
/// <para>
/// An implementation SENDS <paramref name="message"/> as a text frame (UTF-8 JSON) — the measured interop
/// posture: the one shipping DIDComm v2 WebSocket mediator (affinidi-messaging) sends text, and its SDK
/// client DROPS binary/fragmented frames, so a text send is what a real peer actually accepts.
/// <paramref name="mediaType"/> is informational for the channel: a raw WebSocket conveys no per-frame media
/// type at all (measured — zero shipping mediators negotiate or convey one), so a raw-WS implementation
/// ignores it; a STOMP-over-WebSocket channel, which DOES pin per-message <c>content-type</c> conveyance
/// (DIDComm v2.1 §WebSockets), MAY map it onto that header. The receiver's actual dispatch mechanism is
/// envelope classification (<see cref="DidCommInbound.Classify"/> with no content type), never this value.
/// <see cref="DidCommSocketSession.ExchangeAsync"/> — which has no independent media-type input of its own —
/// passes <see langword="null"/> here, the decidable "no media type" a raw WebSocket actually conveys; only
/// <see cref="DidCommSocketSession.SendAsync"/> forwards a caller-supplied, non-empty value.
/// </para>
/// <para>
/// <paramref name="message"/> is a BORROWED view valid only for the duration of the returned task — the same
/// discipline as <see cref="DidCommSendDelegate"/>: the caller keeps the packed message alive across the
/// await, and an implementation MUST finish reading the bytes before its task completes and MUST NOT retain
/// the memory afterwards.
/// </para>
/// </remarks>
/// <param name="message">The packed envelope bytes to send as one complete frame.</param>
/// <param name="mediaType">
/// The envelope's IANA media type — informational only for a raw WebSocket; see remarks.
/// <see langword="null"/> when the channel conveys no per-message media type at all (the correlated-exchange
/// path on a raw WebSocket).
/// </param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The transport-neutral send outcome (no numeric transport status on a WebSocket).</returns>
public delegate ValueTask<DidCommTransmitResult> DidCommSessionSendDelegate(
    ReadOnlyMemory<byte> message,
    string? mediaType,
    CancellationToken cancellationToken);
