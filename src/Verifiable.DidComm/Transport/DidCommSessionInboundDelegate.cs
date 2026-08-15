using System;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.DidComm.Transport;

/// <summary>
/// Receives one complete, uncorrelated inbound DIDComm frame from a <see cref="DidCommSocketSession"/>: a
/// Live-Mode-delivered message, or any frame whose caller-supplied correlation id matched no outstanding
/// <see cref="DidCommSocketSession.ExchangeAsync"/> call, per
/// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0 §Live Mode</see>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="DidCommSocketSession.AcceptInboundFrameAsync"/> dispatches here AFTER enforcing
/// <see cref="DidCommSocketSessionOptions.MaxReceiveBytes"/> and finding no correlation — this delegate never
/// sees a refused, over-cap frame. Classification is <see cref="DidCommInbound.Classify"/> called with NO
/// content type: a raw WebSocket conveys no per-frame media type (the measured, evidence-backed mechanism —
/// see <see cref="DidCommSessionSendDelegate"/>'s remarks), so an implementation classifies by envelope shape
/// and dispatches to the matching unpack itself.
/// </para>
/// <para>
/// The framing convention this seam measures is asymmetric: <see cref="DidCommSessionSendDelegate"/> always
/// SENDS a text frame, but an implementation feeding frames to THIS delegate is BINARY-TOLERANT-ACCEPT — a
/// peer that sends binary measurably exists, so an implementation reading frames off the wire accepts either
/// <c>WebSocketMessageType.Text</c> or <c>.Binary</c> and UTF-8-decodes either into the same
/// <see cref="ReadOnlyMemory{T}"/> <paramref name="frame"/> carries here. This is a receive-side tolerance,
/// not a two-way binary contract — the seam itself never sends binary.
/// </para>
/// <para>
/// <paramref name="frame"/> is a BORROWED view for the duration of the returned task, the same discipline as
/// the other transport delegates: an implementation MUST finish reading it (or copy what it needs to retain)
/// before the task completes.
/// </para>
/// </remarks>
/// <param name="frame">The complete, uncorrelated inbound frame.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask DidCommSessionInboundDelegate(ReadOnlyMemory<byte> frame, CancellationToken cancellationToken);
