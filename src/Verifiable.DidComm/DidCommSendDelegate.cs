using System;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;

namespace Verifiable.DidComm;

/// <summary>
/// A transport-neutral DIDComm message sender: delivers a packed envelope — its bytes and IANA media type — to
/// a concrete endpoint over whatever channel the application provides (HTTPS, WebSockets, Bluetooth, libp2p, or
/// any other), per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>.
/// </summary>
/// <remarks>
/// <para>
/// This is the seam a transport implements. DIDComm is transport-agnostic — trust comes from the envelope, not
/// the connection — so packing yields channel-independent bytes plus a media type
/// (<see cref="DidCommEncryptedMessage.MediaType"/> and the sibling constants), and a
/// <see cref="DidCommSendDelegate"/> carries those over one specific channel and reports a transport-neutral
/// <see cref="DidCommTransmitResult"/>. The HTTPS binding is one such delegate, obtained from
/// <see cref="DidCommHttpTransport.CreateSendDelegate"/>; the library itself carries no <c>System.Net</c>, so a
/// WebSocket/Bluetooth/libp2p delegate is supplied by the application with no library change.
/// </para>
/// <para>
/// <paramref name="message"/> is a BORROWED view valid only for the duration of the returned task: the caller
/// keeps the packed message alive across the await, so an implementation MUST finish reading the bytes before
/// its task completes and MUST NOT retain the memory afterwards.
/// </para>
/// <para>
/// Delivery is one-way (DIDComm v2.1 §HTTPS, §WebSockets: no application reply flows back on the delivery
/// channel), so the delegate reports only whether the endpoint accepted the message and, if not, the failure
/// mode — never a reply.
/// </para>
/// </remarks>
/// <param name="message">The packed envelope bytes to deliver.</param>
/// <param name="mediaType">The envelope's IANA media type (e.g. <c>application/didcomm-encrypted+json</c>), conveyed to the receiver as the channel prescribes (DIDComm v2.1 §Transport Requirements: each transport defines how the media type is carried).</param>
/// <param name="endpoint">The concrete transport endpoint to deliver to.</param>
/// <param name="context">The exchange context carrying the outbound policy and any per-operation state.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The transport-neutral delivery outcome.</returns>
public delegate ValueTask<DidCommTransmitResult> DidCommSendDelegate(
    ReadOnlyMemory<byte> message,
    string mediaType,
    Uri endpoint,
    ExchangeContext context,
    CancellationToken cancellationToken);
