using System;
using System.Threading;
using Verifiable.DidComm.ProblemReports;

namespace Verifiable.DidComm.Transport;

/// <summary>
/// Per-connection configuration for a <see cref="DidCommSocketSession"/>: the inbound size cap, the
/// application-negotiated subprotocol provenance, and the correlated-exchange timeout.
/// </summary>
/// <remarks>
/// Every member is OPTIONAL and independently defaultable — a caller supplies only the ones its channel or
/// policy cares about. All three are scalar, so record-synthesized equality is exact value equality with no
/// hand-written override; the validated <c>init</c> accessors below back their properties with private
/// fields for that validation alone, which does not change what the synthesized equality members compare —
/// record equality is over ALL instance fields, generated or not.
/// </remarks>
public sealed record DidCommSocketSessionOptions
{
    /// <summary>
    /// The backing store <see cref="MaxReceiveBytes"/>'s validating <c>init</c> accessor assigns. A field
    /// because an <c>init</c> accessor may assign a sibling field of its own declaring type outside a
    /// constructor, but never a get-only auto-property's compiler-generated backing field, which only a
    /// constructor of the declaring type may assign.
    /// </summary>
    private readonly long? maxReceiveBytes;

    /// <summary>
    /// The backing store <see cref="ExchangeTimeout"/>'s validating <c>init</c> accessor assigns, for the
    /// same reason <see cref="maxReceiveBytes"/> stays a field.
    /// </summary>
    private readonly TimeSpan? exchangeTimeout;


    /// <summary>
    /// OPTIONAL inbound size cap in bytes — the <c>max_receive_bytes</c> Agent Constraint Disclosure
    /// (<see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#agent-constraint-disclosure">DIDComm Messaging v2.1 §Agent Constraint Disclosure</see>:
    /// "the total length of the DIDComm header plus the size of the message payload that an agent is willing
    /// to receive"): on the wire, the whole encrypted envelope IS that total — there is no separate header
    /// section to measure apart from the payload — so the frame's own length is the measured quantity this
    /// cap compares against. <see langword="null"/> means the session imposes no bound of its own.
    /// <see cref="DidCommSocketSession.AcceptInboundFrameAsync"/> enforces this FIRST, before any correlation
    /// or unsolicited dispatch, refusing an over-cap frame with the
    /// <see cref="WellKnownProblemCodes.MessageTooBig"/> association.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The assigned value is zero or negative — a length an agent is willing to receive cannot be non-positive (same guard shape as <see cref="DidCommHttpTransport.CreateExchangeDelegate"/>'s <c>maxReplyBytes</c>).</exception>
    public long? MaxReceiveBytes
    {
        get => maxReceiveBytes;
        init
        {
            if(value is { } bytes)
            {
                ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(bytes, 0L, nameof(value));
            }

            maxReceiveBytes = value;
        }
    }

    /// <summary>
    /// OPTIONAL — whatever <c>Sec-WebSocket-Protocol</c> value the application's handshake negotiated,
    /// carried through as an OBSERVABLE provenance slot: <see cref="DidCommSocketSession.NegotiatedSubprotocol"/>
    /// surfaces it verbatim, but nothing in this library dispatches on it. Measured against the one shipping
    /// DIDComm v2 WebSocket mediator (affinidi-messaging), which negotiates a plain upgrade with no
    /// subprotocol at all — this slot exists for an application that adopts one with its own real deployment
    /// precedent; this library invents none. <see langword="null"/> when the handshake negotiated none.
    /// </summary>
    public string? NegotiatedSubprotocol { get; init; }

    /// <summary>
    /// OPTIONAL bound on how long <see cref="DidCommSocketSession.ExchangeAsync"/> waits for a correlated
    /// reply before completing as <see cref="DidCommExchangeResult.TransportFailed"/> — no reply channel
    /// materialized, not a thrown exception. <see langword="null"/> waits indefinitely, bounded only by the
    /// caller's own <see cref="CancellationToken"/>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">
    /// The assigned value is negative and is not <see cref="Timeout.InfiniteTimeSpan"/>, or exceeds the
    /// largest delay <see cref="CancellationTokenSource"/> supports (<c>uint.MaxValue - 1</c> milliseconds,
    /// about 49.7 days) — either end of the invalid range would otherwise surface as an undocumented
    /// exception only AFTER the frame already went on the wire, deep inside the timeout machinery rather
    /// than at the point the caller misconfigured it.
    /// </exception>
    public TimeSpan? ExchangeTimeout
    {
        get => exchangeTimeout;
        init
        {
            if(value is { } timeout)
            {
                if(timeout < TimeSpan.Zero && timeout != Timeout.InfiniteTimeSpan)
                {
                    throw new ArgumentOutOfRangeException(nameof(value), timeout, "ExchangeTimeout must be non-negative, or Timeout.InfiniteTimeSpan to wait indefinitely.");
                }

                if(timeout.TotalMilliseconds > uint.MaxValue - 1)
                {
                    throw new ArgumentOutOfRangeException(nameof(value), timeout, "ExchangeTimeout exceeds the largest delay CancellationTokenSource supports (uint.MaxValue - 1 milliseconds).");
                }
            }

            exchangeTimeout = value;
        }
    }
}
