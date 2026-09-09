using System;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.DidComm.ProblemReports;
using Verifiable.DidComm.ReturnRoute;
using Verifiable.DidComm.Routing;
using Verifiable.Foundation;

namespace Verifiable.DidComm.Transport;

/// <summary>
/// How a session disposed of one accepted inbound frame — the outcome <see cref="DidCommSocketSession.AcceptInboundFrameAsync"/> reports.
/// </summary>
public enum DidCommInboundFrameDisposition
{
    /// <summary>The frame exceeded <see cref="DidCommSocketSessionOptions.MaxReceiveBytes"/> and was refused before correlation or dispatch.</summary>
    Refused,

    /// <summary>The frame completed an outstanding <see cref="DidCommSocketSession.ExchangeAsync"/> call by its caller-supplied correlation id.</summary>
    Correlated,

    /// <summary>The frame carried no matching correlation and was handed to the session's <see cref="DidCommSessionInboundDelegate"/>.</summary>
    DispatchedUnsolicited
}


/// <summary>
/// The outcome of <see cref="DidCommSocketSession.AcceptInboundFrameAsync"/> for one inbound frame.
/// </summary>
/// <remarks>
/// Mirrors the <see cref="DidCommTransmitResult"/>/<see cref="DidCommExchangeResult"/> shape: a private
/// constructor behind public factories, so an instance is minted only by the session that decided the
/// disposition. <see cref="DidCommInboundFrameResult.ProblemCode"/> is populated only for
/// <see cref="DidCommInboundFrameDisposition.Refused"/> — the association
/// <see cref="WellKnownProblemCodes.MessageTooBig"/> names
/// (<see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#agent-constraint-disclosure">DIDComm Messaging v2.1 §Agent Constraint Disclosure</see>:
/// "It is recommended that the agent imposing the constraint send a problem report citing the constraint as
/// the cause of a reception error"). Composing and sending that problem report — over the return-route, or
/// emitting a transport-level error instead when "sending a response in the opposite direction ... may not
/// always be possible" — is the APPLICATION's decision with the existing <c>DidCommProblemReportExtensions</c>
/// surface; this result only carries the association, since a session cannot decide on the caller's behalf
/// whether a reply channel is available or appropriate. Stated honestly: <see cref="WellKnownProblemCodes.MessageTooBig"/>'s
/// wire literal does not itself parse through <see cref="ProblemCode.Parse"/> (see that constant's own
/// remarks for why), so the route this refusal most often reaches an application through is the
/// transport-level error the same clause names directly, not a wire problem report built from this string.
/// </remarks>
public sealed class DidCommInboundFrameResult
{
    private DidCommInboundFrameResult(DidCommInboundFrameDisposition disposition, string? problemCode)
    {
        Disposition = disposition;
        ProblemCode = problemCode;
    }


    /// <summary>How the frame was disposed of.</summary>
    public DidCommInboundFrameDisposition Disposition { get; }

    /// <summary>
    /// The problem code associated with a <see cref="DidCommInboundFrameDisposition.Refused"/> outcome, or
    /// <see langword="null"/> for any other disposition.
    /// </summary>
    public string? ProblemCode { get; }

    /// <summary>Whether the frame was refused for exceeding the inbound size cap.</summary>
    public bool IsRefused => Disposition == DidCommInboundFrameDisposition.Refused;


    /// <summary>Mints a refusal carrying the problem code the violated constraint names.</summary>
    /// <param name="problemCode">The associated problem code.</param>
    /// <returns>A refused result.</returns>
    public static DidCommInboundFrameResult Refused(string problemCode)
    {
        ArgumentException.ThrowIfNullOrEmpty(problemCode);

        return new DidCommInboundFrameResult(DidCommInboundFrameDisposition.Refused, problemCode);
    }


    /// <summary>Mints a result for a frame that completed an outstanding correlated exchange.</summary>
    /// <returns>A correlated result.</returns>
    public static DidCommInboundFrameResult Correlated()
    {
        return new DidCommInboundFrameResult(DidCommInboundFrameDisposition.Correlated, null);
    }


    /// <summary>Mints a result for a frame dispatched to the session's unsolicited delegate.</summary>
    /// <returns>An unsolicited-dispatch result.</returns>
    public static DidCommInboundFrameResult DispatchedUnsolicited()
    {
        return new DidCommInboundFrameResult(DidCommInboundFrameDisposition.DispatchedUnsolicited, null);
    }
}


/// <summary>
/// The library's per-connection state and conventions for a persistent, role-symmetric DIDComm duplex session
/// (a WebSocket, or any channel that stays open across multiple messages): the once-per-socket return-route
/// directive, the Live Mode flag with its reset-on-disconnect rule, the inbound size cap, and correlated
/// request/reply matching — completing, for a persistent channel, the receive-side story
/// <see cref="DidCommSendDelegate"/>/<see cref="DidCommExchangeDelegate"/> cover for a single-shot one.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Ownership boundary.</strong> The application owns the socket and its pump: connect or accept,
/// handshake, frame reassembly, and close. This session owns only the per-connection CONVENTIONS the specs
/// attach to a persistent channel — it never touches a socket, and every buffer it sees or returns is a plain
/// <see cref="ReadOnlyMemory{T}"/> the pump hands it (DIDComm v2.1 §WebSockets: "each message MUST be
/// transmitted individually" — this seam only ever sees COMPLETE frames as memory).
/// </para>
/// <para>
/// <strong>One-way by default.</strong> Websockets are one-way by default
/// (<see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>
/// §WebSockets: "Websockets are used only for one-way transmission from sender to receiver; responses don't
/// flow back the other way on the socket") — <see cref="SendAsync"/> is that default.
/// <see cref="ExchangeAsync"/> is the documented exception: it sends over the identical
/// <see cref="DidCommSessionSendDelegate"/>, but only after its own guard has confirmed the request directs a
/// reply onto the connection via the Return-Route extension's <c>return_route: all</c> — the exception is
/// guard-enforced, never assumed.
/// </para>
/// <para>
/// <strong>Transport definition.</strong> Per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>
/// §Transport Requirements ("Each transport MUST define: format of <c>serviceEndpoint</c> <c>uri</c> ...;
/// where additional context definition is hosted"): a peer reaches a session built on this seam through the
/// <c>ws</c>/<c>wss</c> URI schemes carried on the SAME <see cref="DidCommServiceEndpoint.Uri"/> surface every
/// other DIDComm transport shares — this seam defines no scheme of its own and no <c>serviceEndpoint</c>
/// object properties beyond that surface, so there is no additional context to host anywhere else; a future
/// WS-specific property would extend <see cref="DidCommServiceEndpoint"/> itself, not this type.
/// </para>
/// <para>
/// <strong>Role symmetry.</strong> The identical shape serves both roles named in Message Pickup 3.0 and
/// Coordinate Mediation 2.0: a recipient (e.g. a wallet) uses <see cref="SendAsync"/>/<see cref="ExchangeAsync"/>
/// to poll a mediator; a mediator uses <see cref="AcceptInboundFrameAsync"/> on its accept side together with
/// <see cref="SetLiveDelivery"/>/<see cref="MarkReturnRouteEstablished"/> to track the connection's state. The
/// deliver-vs-queue decision and the queue itself stay application seam — this session tracks only whether
/// live delivery is currently enabled, not where a message goes when it is not.
/// </para>
/// <para>
/// <strong>The decrypt boundary.</strong> A session never decrypts. <see cref="ExchangeAsync"/> correlates by
/// the OUTGOING request's own <see cref="DidCommMessage.EffectiveThreadId"/> — that is plaintext to the
/// sender before packing. On the INBOUND side, <see cref="AcceptInboundFrameAsync"/> is handed a
/// correlation id the APPLICATION already recovered by unpacking the frame; the session itself cannot read
/// <c>thid</c> out of an encrypted envelope. Likewise <see cref="MarkReturnRouteEstablished"/> is called by
/// the application after it has unpacked an inbound message and observed
/// <see cref="DidCommReturnRouteExtensions.IsReturnRouteAll"/> on it — the session cannot observe that for
/// received bytes on its own.
/// </para>
/// <para>
/// <strong>Thread safety.</strong> One concurrent reader (the application's pump, calling
/// <see cref="AcceptInboundFrameAsync"/>) together with any number of concurrent senders
/// (<see cref="SendAsync"/>/<see cref="ExchangeAsync"/>) is safe: the correlation table is a
/// <see cref="ConcurrentDictionary{TKey,TValue}"/>, and the return-route/live-mode flags are read and set
/// through <see cref="Interlocked"/>/<see cref="Volatile"/> operations, never a lock the pump could contend
/// on. <see cref="DisposeAsync"/> completes every outstanding <see cref="ExchangeAsync"/> call as
/// <see cref="DidCommExchangeResult.TransportFailed"/> instead of leaving it pending forever.
/// </para>
/// </remarks>
public sealed class DidCommSocketSession: IAsyncDisposable
{
    private DidCommSessionSendDelegate Send { get; }
    private DidCommSocketSessionOptions Options { get; }
    private DidCommSessionInboundDelegate Unsolicited { get; }
    private BaseMemoryPool Pool { get; }
    private TimeProvider TimeProvider { get; }
    private ConcurrentDictionary<string, TaskCompletionSource<DidCommExchangeResult>> PendingExchanges { get; } = new(StringComparer.Ordinal);

    private int isReturnRouteEstablishedFlag;
    private int isLiveDeliveryEnabledFlag;
    private int isDisposedFlag;


    /// <summary>Constructs a session over an application-owned, already-open persistent connection.</summary>
    /// <param name="send">Sends one complete frame over the connection.</param>
    /// <param name="options">Per-connection configuration.</param>
    /// <param name="unsolicited">Receives every inbound frame that does not correlate to an outstanding exchange.</param>
    /// <param name="pool">The pool a correlated reply frame is copied into (see <see cref="AcceptInboundFrameAsync"/>).</param>
    /// <param name="timeProvider">The clock <see cref="ExchangeAsync"/>'s <see cref="DidCommSocketSessionOptions.ExchangeTimeout"/> is realized against.</param>
    public DidCommSocketSession(DidCommSessionSendDelegate send, DidCommSocketSessionOptions options, DidCommSessionInboundDelegate unsolicited, BaseMemoryPool pool, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(send);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(unsolicited);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(timeProvider);

        this.Send = send;
        this.Options = options;
        this.Unsolicited = unsolicited;
        this.Pool = pool;
        this.TimeProvider = timeProvider;
    }


    /// <summary>
    /// The application-negotiated <c>Sec-WebSocket-Protocol</c> value recorded at construction, verbatim and
    /// unchanged for the session's lifetime — an OBSERVABLE provenance slot, never dispatched on by this
    /// library. <see langword="null"/> when the application's handshake negotiated none (see
    /// <see cref="DidCommSocketSessionOptions.NegotiatedSubprotocol"/>).
    /// </summary>
    public string? NegotiatedSubprotocol => Options.NegotiatedSubprotocol;

    /// <summary>
    /// Whether the return-route directive has been established once for this socket
    /// (<see href="https://didcomm.org/messagepickup/3.0/">Message Pickup 3.0 §Requirements</see> /
    /// <see href="https://didcomm.org/coordinate-mediation/2.0/">Coordinate Mediation 2.0 §Requirements</see>:
    /// "This header must be set each time the communication channel is established: once per established
    /// websocket"). Latches to <see langword="true"/> on the recipient side when <see cref="SendAsync"/> or
    /// <see cref="ExchangeAsync"/> accepts a send whose request directs <c>return_route: all</c>, or on the
    /// mediator side when the application calls <see cref="MarkReturnRouteEstablished"/> after unpacking an
    /// inbound one carrying it. Never resets for the lifetime of this session — a broken connection is a new
    /// <see cref="DidCommSocketSession"/>, not a reset on this one.
    /// </summary>
    public bool IsReturnRouteEstablished => Volatile.Read(ref isReturnRouteEstablishedFlag) != 0;

    /// <summary>
    /// Whether Live Mode is currently enabled on this session — the mediator-side state of record (the
    /// recipient uses this same member as its own local mirror). Starts <see langword="false"/>: a new
    /// <see cref="DidCommSocketSession"/> IS a new connection, so Message Pickup 3.0 §Live Mode's "a new
    /// inbound connection starts with Live Mode disabled" is structural here — the per-connection lifetime of
    /// this object is the reset, not a value this type has to remember to clear. Set with
    /// <see cref="SetLiveDelivery"/>.
    /// </summary>
    public bool IsLiveDeliveryEnabled => Volatile.Read(ref isLiveDeliveryEnabledFlag) != 0;


    /// <summary>
    /// Sets the Live Mode state (Message Pickup 3.0 §Live Mode Change). Structural enforcement of "Live Mode
    /// MUST only be enabled when a persistent transport is used" (§Live Mode): this flag exists only on a
    /// <see cref="DidCommSocketSession"/> — nothing on the one-shot <see cref="DidCommExchangeDelegate"/> HTTP
    /// path can enable it, because that surface carries no such member at all.
    /// </summary>
    /// <param name="isEnabled">The new Live Mode state.</param>
    public void SetLiveDelivery(bool isEnabled)
    {
        Interlocked.Exchange(ref isLiveDeliveryEnabledFlag, isEnabled ? 1 : 0);
    }


    /// <summary>
    /// Marks the return-route directive established for this socket — the MEDIATOR-side counterpart to the
    /// recipient-side latch <see cref="SendAsync"/>/<see cref="ExchangeAsync"/> apply. Called by the
    /// application after it has unpacked an inbound message and found
    /// <see cref="DidCommReturnRouteExtensions.IsReturnRouteAll"/> true: a session cannot decrypt to observe
    /// that on its own (see the type remarks' decrypt boundary). Idempotent — a second and later call is a
    /// no-op, matching "once per established websocket" (Message Pickup 3.0 §Requirements / Coordinate
    /// Mediation 2.0 §Requirements).
    /// </summary>
    public void MarkReturnRouteEstablished()
    {
        Interlocked.CompareExchange(ref isReturnRouteEstablishedFlag, 1, 0);
    }


    /// <summary>
    /// Sends <paramref name="message"/> as one complete frame over the session — the one-way counterpart to
    /// <see cref="ExchangeAsync"/>. When the send is accepted and <paramref name="request"/> directs
    /// <c>return_route: all</c>, latches <see cref="IsReturnRouteEstablished"/>.
    /// </summary>
    /// <param name="message">The packed envelope bytes to send.</param>
    /// <param name="mediaType">The envelope's IANA media type, forwarded to the underlying <see cref="DidCommSessionSendDelegate"/>.</param>
    /// <param name="request">The plaintext request that was packed into <paramref name="message"/> — inspected only for its return-route directive.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The transport-neutral send outcome.</returns>
    /// <exception cref="ObjectDisposedException">The session has been disposed.</exception>
    public async ValueTask<DidCommTransmitResult> SendAsync(ReadOnlyMemory<byte> message, string mediaType, DidCommMessage request, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref isDisposedFlag) != 0, this);
        ArgumentException.ThrowIfNullOrEmpty(mediaType);
        ArgumentNullException.ThrowIfNull(request);

        DidCommTransmitResult result = await Send(message, mediaType, cancellationToken).ConfigureAwait(false);

        if(result.IsAccepted && request.IsReturnRouteAll())
        {
            MarkReturnRouteEstablished();
        }

        return result;
    }


    /// <summary>
    /// Sends <paramref name="packed"/> and correlates the eventual reply by <paramref name="request"/>'s
    /// <see cref="DidCommMessage.EffectiveThreadId"/>, per the
    /// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">DIDComm Messaging Return-Route and Queue Transport Extension</see>
    /// generalized to a stream: unlike the one-shot HTTP exchange, replies and Live-Mode deliveries interleave
    /// on one socket, so this registers the request's thread id in an outstanding-exchange table before
    /// sending, and <see cref="AcceptInboundFrameAsync"/> completes it when a frame's caller-supplied
    /// correlation id matches.
    /// </summary>
    /// <param name="packed">The packed request bytes to send.</param>
    /// <param name="request">The plaintext request that was packed. MUST direct <c>return_route: all</c> and carry a non-empty <see cref="DidCommMessage.EffectiveThreadId"/>.</param>
    /// <param name="cancellationToken">Cancellation token — a cancellation request rethrows.</param>
    /// <returns>
    /// The correlated reply, with <see cref="DidCommExchangeResult.ReplyMediaType"/> always
    /// <see langword="null"/> (raw WebSocket conveys none; the caller classifies the reply body with
    /// <see cref="DidCommInbound.Classify"/>). Completes as <see cref="DidCommExchangeResult.TransportFailed"/>
    /// — not a thrown exception — when <see cref="DidCommSocketSessionOptions.ExchangeTimeout"/> elapses
    /// before a reply correlates, or when disposal races the wait. The returned <see cref="DidCommExchangeResult.ReplyBody"/>
    /// is UNVERIFIED wire data: correlating a frame to this call by thread id is routing, not sender
    /// authentication — the socket confers none
    /// (<see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>
    /// §WebSockets: "The trust of each message MUST be associated with DIDComm encryption or signing, not
    /// from the socket connection itself"). Under anoncrypt the reply is repudiable by design; associating it
    /// with a specific counterparty rests on the application's OWN channel authentication (TLS pinning, an
    /// authenticated upgrade) or an authcrypt/signature check performed after unpack — a caller MUST NOT
    /// treat a correlated result as proof of who sent it. The caller owns the returned result and disposes
    /// it (<c>using var result = await session.ExchangeAsync(...)</c>) to return the reply's pooled lease;
    /// a reply-less outcome disposes as a no-op. When the call ends by THROWING, a reply that had already
    /// correlated before the exception is abandoned — its lease is returned and its bytes discarded, never
    /// redelivered to <see cref="DidCommSessionInboundDelegate"/> — so a caller that must not lose a reply
    /// relies on the peer's retransmission (Message Pickup 3.0 dequeues only on <c>messages-received</c>).
    /// </returns>
    /// <exception cref="ObjectDisposedException">The session has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="request"/> has no non-empty <see cref="DidCommMessage.EffectiveThreadId"/>, does not
    /// direct <c>return_route: all</c>, or an exchange for the same thread id is already outstanding on this
    /// session.
    /// </exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Three owners dispose the DidCommExchangeResult instances minted here: the caller this method returns a result to (including the send-failure mint returned directly, not routed through the TaskCompletionSource); AcceptInboundFrameAsync's own dispose of an orphaned correlation; and this method's catch block, the one custody point for an exceptional exit that leaves a settled-but-unobserved reply behind.")]
    public async ValueTask<DidCommExchangeResult> ExchangeAsync(ReadOnlyMemory<byte> packed, DidCommMessage request, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref isDisposedFlag) != 0, this);
        ArgumentNullException.ThrowIfNull(request);

        if(request.EffectiveThreadId is not { Length: > 0 } threadId)
        {
            throw new ArgumentException(
                "An exchange over the session requires a non-empty EffectiveThreadId to correlate the reply " +
                "(DIDComm Messaging v2.1 §Threading).",
                nameof(request));
        }

        if(!request.IsReturnRouteAll())
        {
            throw new ArgumentException(
                "An exchange over the session is used only for a request that directs replies onto the " +
                "connection (return_route: all) — DIDComm Messaging Return-Route and Queue Transport " +
                "Extension §Return Route Header.",
                nameof(request));
        }

        var completion = new TaskCompletionSource<DidCommExchangeResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        if(!PendingExchanges.TryAdd(threadId, completion))
        {
            throw new ArgumentException(
                $"An exchange for thread id '{threadId}' is already outstanding on this session.",
                nameof(request));
        }

        var ownRegistration = new KeyValuePair<string, TaskCompletionSource<DidCommExchangeResult>>(threadId, completion);

        //Published, so re-check for a DisposeAsync that already ran its drain before this registration
        //existed to see: TryAdd (above) and DisposeAsync's flag-then-drain can interleave as
        //check-disposed / dispose-drains-nothing / register, which would otherwise leave this registration
        //waiting forever. Re-reading the flag AFTER a successful publish closes that window either way —
        //whichever of the two orderings actually occurred, at least one of DisposeAsync's drain loop or this
        //recheck observes the registration and settles it.
        if(Volatile.Read(ref isDisposedFlag) != 0)
        {
            //Settle before de-registering: a frame that correlated on the pump thread between the publish
            //above and this recheck already claimed the registration and settled it with a real reply — the
            //TrySetResult below then fails and the reply is delivered rather than discarded. When the settle
            //succeeds, any later frame for this thread id finds the registration gone (or settled) and is
            //dispatched unsolicited, never claimed for a caller that has already given up.
            bool isSelfSettled = completion.TrySetResult(DidCommExchangeResult.TransportFailed());
            PendingExchanges.TryRemove(ownRegistration);

            return isSelfSettled
                ? DidCommExchangeResult.TransportFailed()
                : await completion.Task.ConfigureAwait(false);
        }

        try
        {
            //ExchangeAsync has no independent media-type input of its own: the receiver classifies inbound
            //frames by envelope shape regardless of what accompanies this send, so null — a decidable "no
            //media type" — is what actually crosses a raw WebSocket. SendAsync carries a caller-supplied
            //media type for a channel that does convey one (e.g. STOMP).
            DidCommTransmitResult sent = await Send(packed, null, cancellationToken).ConfigureAwait(false);
            if(!sent.IsAccepted)
            {
                //The registration was live during the send, so a reply can have correlated already. Settle
                //with the send failure; when that loses (a real reply won the race), deliver the reply — the
                //frame was claimed from the pump as Correlated and MUST NOT be discarded.
                DidCommExchangeResult sendFailure = sent.Error switch
                {
                    DidCommTransmitError.DeniedByPolicy => DidCommExchangeResult.DeniedByPolicy(),
                    DidCommTransmitError.Rejected => DidCommExchangeResult.Rejected(sent.TransportStatusCode),
                    _ => DidCommExchangeResult.TransportFailed()
                };

                return completion.TrySetResult(sendFailure)
                    ? sendFailure
                    : await completion.Task.ConfigureAwait(false);
            }

            MarkReturnRouteEstablished();

            return await WaitForCorrelatedReplyAsync(completion, Options.ExchangeTimeout, TimeProvider, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            //The one exceptional-exit custody point: an exception escaping the send delegate or
            //WaitForCorrelatedReplyAsync (a non-cancellation throw, or the caller's own token firing) can
            //leave `completion` already settled with a genuine correlated reply that raced the failure —
            //nothing else will ever observe or dispose it. Settling first (a no-op when already settled)
            //guarantees completion.Task is complete, so awaiting and disposing it here returns that lease
            //exactly once before the exception propagates.
            completion.TrySetResult(DidCommExchangeResult.TransportFailed());
            (await completion.Task.ConfigureAwait(false)).Dispose();

            throw;
        }
        finally
        {
            //Settle before de-registering so EVERY exit — including an exception thrown out of the send —
            //leaves the registration observably settled: a frame arriving in the removal window then fails
            //its TrySetResult and falls through to unsolicited dispatch instead of being claimed for a
            //caller that is no longer listening. A no-op whenever the exchange already holds a result.
            completion.TrySetResult(DidCommExchangeResult.TransportFailed());

            //Value-comparing: removes ONLY this call's own registration. A plain TryRemove(threadId, out _)
            //could instead delete a NEWER registration that reused the same thread id after this one already
            //completed and was replaced.
            PendingExchanges.TryRemove(ownRegistration);
        }
    }


    //Awaits the exchange's correlated completion, bounded by an optional timeout that resolves to a settled
    //DidCommExchangeResult (never a throw) rather than the linked-token OperationCanceledException a naive
    //WaitAsync(linked) would otherwise surface. A genuine caller cancellation is distinguished by the ORIGINAL
    //token's own state and rethrows instead of being folded into a result. Either way, BEFORE returning or
    //rethrowing, this settles `completion` itself first (TrySetResult(TransportFailed)): a WaitAsync
    //timeout/cancellation only cancels the WAIT, not the awaited TaskCompletionSource, so without this a
    //frame that arrives for this thread id after the wait gives up but before ExchangeAsync's finally removes
    //the registration would otherwise still find it unsettled — AcceptInboundFrameAsync's TrySetResult would
    //succeed and report Correlated even though nothing is listening anymore, silently losing the frame.
    //Settling first makes that later TrySetResult observably fail, so AcceptInboundFrameAsync falls through
    //to unsolicited dispatch instead — the frame is delivered, never dropped.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The DidCommExchangeResult minted for each TrySetResult call transfers ownership into completion's TaskCompletionSource; on the return paths the caller owns and disposes the returned result, and on the rethrow paths ExchangeAsync's own catch block is the custody point that disposes the settled result before the exception propagates further.")]
    private static async ValueTask<DidCommExchangeResult> WaitForCorrelatedReplyAsync(
        TaskCompletionSource<DidCommExchangeResult> completion,
        TimeSpan? timeout,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        if(timeout is not { } value)
        {
            try
            {
                return await completion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch(OperationCanceledException)
            {
                //The caller's own token fired, so this exchange is abandoned rather than delivered: settle
                //`completion` (a no-op when a genuine correlated reply already won the race) and rethrow.
                //ExchangeAsync's own catch block is the one place that observes and disposes the settled
                //result on this path.
                completion.TrySetResult(DidCommExchangeResult.TransportFailed());

                throw;
            }
        }

        using var timeoutSource = new CancellationTokenSource(value, timeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutSource.Token);

        try
        {
            return await completion.Task.WaitAsync(linked.Token).ConfigureAwait(false);
        }
        catch(OperationCanceledException)
        {
            completion.TrySetResult(DidCommExchangeResult.TransportFailed());

            if(cancellationToken.IsCancellationRequested)
            {
                //Same reasoning as the no-timeout branch above: the caller's own token fired, so this wait is
                //abandoned rather than merely timed out. ExchangeAsync's own catch block observes and
                //disposes the settled result on this path.
                throw;
            }

            //WaitAsync races the linked timeout token against `completion` itself, and that race is not
            //decidable from outside: the token can enter the canceled state at essentially the same instant
            //AcceptInboundFrameAsync's TrySetResult settles `completion` with a genuine correlated reply, and
            //WaitAsync may still surface OperationCanceledException even though the antecedent Task already
            //holds that real result. The TrySetResult call above is a no-op whenever that happened (the Task
            //was already settled), so `completion.Task` is guaranteed complete by this point either way —
            //awaiting it returns whichever result actually won the race, instead of a freshly synthesized
            //TransportFailed that would silently discard a reply that landed a few ticks ahead of the timeout.
            return await completion.Task.ConfigureAwait(false);
        }
    }


    /// <summary>
    /// The application pump's inbound entry point for one complete frame: enforces
    /// <see cref="DidCommSocketSessionOptions.MaxReceiveBytes"/> FIRST
    /// (<see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#agent-constraint-disclosure">DIDComm Messaging v2.1 §Agent Constraint Disclosure</see>),
    /// then routes by <paramref name="correlationThreadId"/> — matched against an outstanding
    /// <see cref="ExchangeAsync"/> call, or dispatched to the session's <see cref="DidCommSessionInboundDelegate"/>
    /// when it is <see langword="null"/> or matches nothing.
    /// </summary>
    /// <remarks>
    /// A frame whose id matches a REGISTERED exchange that has already settled on its own (its own timeout
    /// or a genuine cancellation) is never silently dropped: the correlating <c>TrySetResult</c> observably
    /// FAILS in that case, and this method falls through to unsolicited dispatch instead of reporting the
    /// frame <see cref="DidCommInboundFrameDisposition.Correlated"/> — for that case, a reply that loses
    /// the race with its own exchange's completion is DELIVERED unsolicited, never lost. The discriminator
    /// is the <c>TrySetResult</c> outcome, not the registration's presence: when the correlating
    /// <c>TrySetResult</c> SUCCEEDS and the exchange then exits by throwing, this method has already
    /// reported <see cref="DidCommInboundFrameDisposition.Correlated"/>, and the reply is abandoned in
    /// <see cref="ExchangeAsync"/>'s exceptional exit rather than redelivered here — see that method's
    /// <c>returns</c>. Session disposal reaches neither branch through this method: after
    /// <see cref="DisposeAsync"/> the entry check throws <see cref="ObjectDisposedException"/> before
    /// correlation is attempted.
    /// A correlated result is routing, never sender authentication — see <see cref="ExchangeAsync"/>'s
    /// <c>returns</c> for the trust boundary (DIDComm Messaging v2.1 §Transports §WebSockets: trust comes
    /// from the envelope, never the connection); the correlation id itself is equally untrusted, since a
    /// hostile peer that guesses an outstanding <c>thid</c> correlates exactly like a genuine reply — that
    /// routing reality is why this method makes no authentication claim at all.
    /// </remarks>
    /// <param name="frame">
    /// The complete inbound frame — a BORROWED view valid only for the duration of this call. When
    /// <paramref name="correlationThreadId"/> matches an outstanding <see cref="ExchangeAsync"/> registration,
    /// its bytes are copied into a pooled <see cref="DidCommExchangeResult.ReplyBody"/> — the same ownership
    /// <see cref="DidCommExchangeDelegate"/> documents for its own reply, owned and disposed by the exchange's
    /// caller. When that registration turns out to have already settled on its own (see the remarks), this
    /// method disposes the copy itself before falling through to unsolicited dispatch, so the rented lease is
    /// returned either way. A frame that does not correlate at all is never copied — it is read only for the
    /// duration of the unsolicited dispatch.
    /// </param>
    /// <param name="correlationThreadId">
    /// The <c>thid</c> the APPLICATION already recovered by unpacking <paramref name="frame"/> — a session
    /// cannot decrypt to read it (see the type remarks' decrypt boundary). <see langword="null"/> always
    /// dispatches unsolicited, whether the frame is genuinely unsolicited or simply not yet unpacked. This
    /// value is UNVERIFIED: it drives routing only, never sender authentication (see the remarks).
    /// </param>
    /// <param name="cancellationToken">Cancellation token, forwarded to the unsolicited delegate.</param>
    /// <returns>How the frame was disposed of. Never throws on frame content.</returns>
    /// <exception cref="ObjectDisposedException">The session has been disposed.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The minted DidCommExchangeResult transfers ownership into the pending exchange's TaskCompletionSource on the correlated path (its caller disposes it), and is disposed explicitly right below on the orphaned-registration path.")]
    public ValueTask<DidCommInboundFrameResult> AcceptInboundFrameAsync(ReadOnlyMemory<byte> frame, string? correlationThreadId, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref isDisposedFlag) != 0, this);

        if(Options.MaxReceiveBytes is { } maxReceiveBytes && frame.Length > maxReceiveBytes)
        {
            return ValueTask.FromResult(DidCommInboundFrameResult.Refused(WellKnownProblemCodes.MessageTooBig));
        }

        if(correlationThreadId is { Length: > 0 } id && PendingExchanges.TryRemove(id, out TaskCompletionSource<DidCommExchangeResult>? pending))
        {
            //Copied, never aliased: the caller's pump reads this result AFTER AcceptInboundFrameAsync
            //returns (ExchangeAsync's TaskCompletionSource runs continuations asynchronously), so a pooling
            //pump that reuses `frame`'s backing buffer immediately after the call returns must not be able
            //to corrupt a reply already handed to the exchange. The copy happens before TrySetResult so the
            //rented buffer is only ever handed off once its ownership destination (this result) already exists.
            PooledMemory replyBody = PooledMemory.FromBytes(frame.Span, Pool, BufferTags.Json);
            DidCommExchangeResult result = DidCommExchangeResult.Accepted(null, replyBody, null);

            bool wasSet;
            try
            {
                wasSet = pending.TrySetResult(result);
            }
            catch
            {
                //TrySetResult never takes ownership of result — it only stores the reference for the
                //awaiting ExchangeAsync call to read — so an unexpected throw here still leaves result
                //otherwise unowned.
                result.Dispose();

                throw;
            }

            if(wasSet)
            {
                return ValueTask.FromResult(DidCommInboundFrameResult.Correlated());
            }

            //The registration was already settled by its own ExchangeAsync call (timeout/cancellation/
            //disposal won the race) before this frame arrived — see the remarks. The result minted above is
            //orphaned: nobody will ever observe or dispose it, so its lease is returned here before falling
            //through — the frame is still delivered, just unsolicited rather than attributed to an exchange
            //nobody is awaiting.
            result.Dispose();
        }

        return DispatchUnsolicitedAsync(frame, cancellationToken);
    }


    //Hands an uncorrelated (or genuinely unsolicited) frame to the application's live-delivery handler.
    private async ValueTask<DidCommInboundFrameResult> DispatchUnsolicitedAsync(ReadOnlyMemory<byte> frame, CancellationToken cancellationToken)
    {
        await Unsolicited(frame, cancellationToken).ConfigureAwait(false);

        return DidCommInboundFrameResult.DispatchedUnsolicited();
    }


    /// <summary>
    /// Marks the session disposed and completes every outstanding <see cref="ExchangeAsync"/> call as
    /// <see cref="DidCommExchangeResult.TransportFailed"/> rather than leaving it pending forever. The socket
    /// itself is torn down by the application independently — this only settles the library's own
    /// correlation state.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TransportFailed() always carries PooledMemory.Empty (never a rented lease), so transferring it into each pending exchange's TaskCompletionSource without a local dispose is safe; that TaskCompletionSource's own awaiter owns and disposes the settled result.")]
    public ValueTask DisposeAsync()
    {
        if(Interlocked.Exchange(ref isDisposedFlag, 1) != 0)
        {
            return ValueTask.CompletedTask;
        }

        foreach(string threadId in PendingExchanges.Keys)
        {
            if(PendingExchanges.TryRemove(threadId, out TaskCompletionSource<DidCommExchangeResult>? completion))
            {
                completion.TrySetResult(DidCommExchangeResult.TransportFailed());
            }
        }

        return ValueTask.CompletedTask;
    }
}
