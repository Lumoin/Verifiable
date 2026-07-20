using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Apdu.Ctap;

/// <summary>
/// The authenticator (card) side of the CTAP2-over-NFC binding: a <see cref="TransceiveDelegate"/>-shaped
/// responder that speaks FIDO applet selection, NFCCTAP_MSG deframing and ISO/IEC 7816-4 response
/// chaining, delegating only the opaque CTAP2 envelope to a supplied <see cref="CtapPayloadTransceiveDelegate"/>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Shape, not a shared type.</strong> <see cref="TransceiveAsync"/> has exactly the shape of
/// <see cref="TransceiveDelegate"/>, so <c>ApduDevice.Create(responder.TransceiveAsync)</c> plugs this
/// responder straight into <see cref="ApduDevice"/> and, through it, <see cref="ApduExecutor"/> — the
/// same precedent <c>CardSimulator.TransceiveAsync</c> establishes for the eMRTD profile. This type is
/// a genuinely separate responder, not a branch on <c>CardSimulator</c>: its own SELECT parser, its own
/// lifecycle, its own instruction table.
/// </para>
/// <para>
/// <strong>Deferred processing is opt-in.</strong> <see cref="Create(CtapPayloadTransceiveDelegate)"/>
/// wires only the synchronous seam: every <see cref="WellKnownCtapInstructionCodes.NfcCtapMsg"/> request
/// is awaited to completion inside the same call, so this responder never emits
/// (<see cref="WellKnownCtapStatusWords.ResponseStatus"/>, <c>0x9100</c>) and an
/// <see cref="WellKnownCtapInstructionCodes.NfcCtapGetResponse"/> poll always answers "conditions not
/// satisfied" (<c>0x6985</c>) rather than "instruction not supported" (<c>0x6D00</c>).
/// <see cref="Create(CtapPayloadTransceiveDelegate, CtapPayloadDeferredTransceiveDelegate, CtapPayloadDeferredPollDelegate, CtapPayloadDeferredCancelDelegate)"/>
/// additionally wires the deferral seam per
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-ctap-response">
/// CTAP 2.3, section 11.3.7.2</see>: an <c>NFCCTAP_MSG</c> whose P1 carries
/// <see cref="WellKnownCtapCommandParameters.SupportsGetResponseP1Bit"/> (lines 10799-10800's MAY,
/// conditioned on that bit — never emitted otherwise) may park, answering <c>0x9100</c> with one
/// <see cref="WellKnownCtapKeepaliveStatusCodes.UpNeeded"/> data byte; the client then polls or cancels
/// with <see cref="WellKnownCtapInstructionCodes.NfcCtapGetResponse"/> (lines 10817-10821's SHALLs) until
/// the parked request resolves. Whichever <c>Create</c> overload built this instance, a request without
/// the P1 bit — or any request at all when deferral was never wired — always completes synchronously.
/// </para>
/// <para>
/// <strong>Response chaining is genuinely exercised, both encodings.</strong> Per
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-fragmentation">
/// section 11.3.6</see>: if the incoming <c>NFCCTAP_MSG</c> used extended-length encoding, the full
/// response is returned in one frame; if it used short encoding, the response is chunked with
/// <c>61xx</c>, and subsequent <see cref="InstructionCode.GetResponse"/> (<c>0xC0</c>) commands drain
/// the remainder — mirroring what <see cref="ApduExecutor"/> already does on the terminal side of any
/// ISO/IEC 7816-4 exchange.
/// </para>
/// <para>
/// <strong>Ownership.</strong> A chained response spans multiple <see cref="TransceiveAsync"/> calls,
/// so the responder holds the pooled response buffer across calls while a chain is being drained. The
/// creator owns the responder and must dispose it; disposal releases any chain still in flight — the
/// same convention <see cref="Automata.CardSimulator"/> follows for its retained pooled state.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class CtapNfcResponder: IDisposable
{
    /// <summary>The CTAP2-only Select-response version string (spec §11.3.3): never the CTAP2.3 version string itself, which appears only in <c>authenticatorGetInfo</c>.</summary>
    private static ReadOnlySpan<byte> SelectVersionString => "FIDO_2_0"u8;

    private CtapPayloadTransceiveDelegate PayloadTransceive { get; }

    private CtapPayloadDeferredTransceiveDelegate? DeferredTransceive { get; }

    private CtapPayloadDeferredPollDelegate? DeferredPoll { get; }

    private CtapPayloadDeferredCancelDelegate? DeferredCancel { get; }

    /// <summary>
    /// Gets a value indicating whether this instance was created with the deferral seam wired
    /// (<see cref="Create(CtapPayloadTransceiveDelegate, CtapPayloadDeferredTransceiveDelegate, CtapPayloadDeferredPollDelegate, CtapPayloadDeferredCancelDelegate)"/>).
    /// </summary>
    private bool DeferralConfigured => DeferredTransceive is not null;

    /// <summary>Gets or sets a value indicating whether the FIDO applet is currently selected.</summary>
    private bool AppletSelected { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether an <c>NFCCTAP_MSG</c> request has parked awaiting user
    /// presence and is awaiting an <see cref="WellKnownCtapInstructionCodes.NfcCtapGetResponse"/> poll
    /// or cancel — the responder's own mirror of the authenticator-side parked state
    /// <see cref="DeferredPoll"/>/<see cref="DeferredCancel"/> resolve. Cleared by a completed poll, a
    /// cancel, or the supersede discipline any new <c>SELECT</c>, deselection, or <c>NFCCTAP_MSG</c>
    /// applies.
    /// </summary>
    private bool DeferredResponsePending { get; set; }

    /// <summary>
    /// Gets or sets whether the parked <c>NFCCTAP_MSG</c> request used extended-length encoding — once
    /// <see cref="DeferredResponsePending"/> resolves, the completed response's own framing follows this
    /// exactly as an ordinary synchronous response would (spec §11.3.6).
    /// </summary>
    private bool PendingDeferralWasExtended { get; set; }

    /// <summary>
    /// Gets or sets the pooled response envelope a chain is currently being drained from; owns the
    /// buffer <see cref="PendingChain"/> views into. <see langword="null"/> when no chain is
    /// outstanding — disposed and cleared together with <see cref="PendingChain"/> by
    /// <see cref="ClearPendingChain"/>.
    /// </summary>
    private PooledMemory? PendingResponse { get; set; }

    /// <summary>
    /// Gets or sets the response bytes not yet delivered to the terminal, awaiting the next
    /// <see cref="InstructionCode.GetResponse"/> (<c>0xC0</c>); empty when no chain is outstanding. A
    /// view into <see cref="PendingResponse"/>'s buffer, valid only while that buffer is undisposed.
    /// </summary>
    private ReadOnlyMemory<byte> PendingChain { get; set; }

    /// <summary>Whether <see cref="Dispose"/> has run.</summary>
    private bool disposed;

    /// <summary>
    /// Disposes any outstanding chained response buffer and clears the pending-chain state. Called
    /// whenever a new SELECT, deselection, or <c>NFCCTAP_MSG</c> supersedes whatever chain, if any, was
    /// still in flight — and by <see cref="Dispose"/> — so a chain abandoned mid-drain never leaks its
    /// pooled buffer.
    /// </summary>
    private void ClearPendingChain()
    {
        PendingResponse?.Dispose();
        PendingResponse = null;
        PendingChain = ReadOnlyMemory<byte>.Empty;
    }


    /// <summary>
    /// Tears down a request parked awaiting deferred completion, if any: invokes
    /// <see cref="DeferredCancel"/>, discards the returned envelope, and clears
    /// <see cref="DeferredResponsePending"/>. Called wherever <see cref="ClearPendingChain"/> is — a new
    /// <c>SELECT</c>, applet deselection, or <c>NFCCTAP_MSG</c> supersedes whatever request, if any, was
    /// still parked — so a superseded deferral never leaves the authenticator-side parked state it
    /// references without a deterministic teardown. A no-op when nothing is parked.
    /// </summary>
    /// <param name="pool">The memory pool for <see cref="DeferredCancel"/>'s discarded envelope.</param>
    /// <param name="cancellationToken">Cancellation token forwarded to <see cref="DeferredCancel"/>.</param>
    private async ValueTask ClearPendingDeferralAsync(MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        if(!DeferredResponsePending)
        {
            return;
        }

        using PooledMemory discardedEnvelope = await DeferredCancel!(pool, cancellationToken).ConfigureAwait(false);
        DeferredResponsePending = false;
    }


    /// <summary>
    /// Initializes a new instance over the supplied opaque-payload seam and, optionally, the deferral seam.
    /// </summary>
    /// <param name="payloadTransceive">The seam that handles one opaque CTAP2 request/response envelope synchronously.</param>
    /// <param name="deferredTransceive">The seam beginning a request that may defer, or <see langword="null"/> if deferral is not wired.</param>
    /// <param name="deferredPoll">The seam polling a parked request, or <see langword="null"/> if deferral is not wired.</param>
    /// <param name="deferredCancel">The seam cancelling a parked request, or <see langword="null"/> if deferral is not wired.</param>
    private CtapNfcResponder(
        CtapPayloadTransceiveDelegate payloadTransceive,
        CtapPayloadDeferredTransceiveDelegate? deferredTransceive,
        CtapPayloadDeferredPollDelegate? deferredPoll,
        CtapPayloadDeferredCancelDelegate? deferredCancel)
    {
        this.PayloadTransceive = payloadTransceive;
        this.DeferredTransceive = deferredTransceive;
        this.DeferredPoll = deferredPoll;
        this.DeferredCancel = deferredCancel;
    }


    /// <summary>
    /// Creates a responder that deframes NFC/ISO7816-4 traffic and forwards opaque CTAP2 envelopes to
    /// <paramref name="payloadTransceive"/>.
    /// </summary>
    /// <param name="payloadTransceive">
    /// The seam handling one opaque CTAP2 request/response envelope — typically a CTAP2 authenticator
    /// implementation's own method, bound here by ordinary C# method-group conversion.
    /// </param>
    /// <returns>
    /// A responder ready to be wrapped by <c>ApduDevice.Create(responder.TransceiveAsync)</c>. The
    /// caller owns it and must dispose it; disposal releases any chained response buffer still in flight.
    /// </returns>
    /// <remarks>
    /// No deferral seam: every <c>NFCCTAP_MSG</c> completes synchronously regardless of P1. Use
    /// <see cref="Create(CtapPayloadTransceiveDelegate, CtapPayloadDeferredTransceiveDelegate, CtapPayloadDeferredPollDelegate, CtapPayloadDeferredCancelDelegate)"/>
    /// to enable <c>NFCCTAP_GETRESPONSE</c> deferral.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="payloadTransceive"/> is <see langword="null"/>.</exception>
    public static CtapNfcResponder Create(CtapPayloadTransceiveDelegate payloadTransceive)
    {
        ArgumentNullException.ThrowIfNull(payloadTransceive);

        return new CtapNfcResponder(payloadTransceive, null, null, null);
    }


    /// <summary>
    /// Creates a responder that deframes NFC/ISO7816-4 traffic, forwards opaque CTAP2 envelopes to
    /// <paramref name="payloadTransceive"/>, and additionally supports deferring a request across
    /// separate <c>NFCCTAP_MSG</c>/<c>NFCCTAP_GETRESPONSE</c> exchanges
    /// (<see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-ctap-response">
    /// CTAP 2.3, section 11.3.7.2</see>, lines 10817-10821) via <paramref name="deferredTransceive"/>/
    /// <paramref name="deferredPoll"/>/<paramref name="deferredCancel"/>.
    /// </summary>
    /// <param name="payloadTransceive">
    /// The seam handling one opaque CTAP2 request/response envelope synchronously — used whenever the
    /// client's <c>NFCCTAP_MSG</c> P1 does not carry <see cref="WellKnownCtapCommandParameters.SupportsGetResponseP1Bit"/>.
    /// </param>
    /// <param name="deferredTransceive">
    /// The seam beginning one CTAP2 request that may park awaiting user presence — invoked only when
    /// the client's P1 carries <see cref="WellKnownCtapCommandParameters.SupportsGetResponseP1Bit"/>.
    /// </param>
    /// <param name="deferredPoll">The seam polling a previously parked request.</param>
    /// <param name="deferredCancel">The seam cancelling a previously parked request, also used to supersede a parked request on a new SELECT, deselection, or NFCCTAP_MSG.</param>
    /// <returns>
    /// A responder ready to be wrapped by <c>ApduDevice.Create(responder.TransceiveAsync)</c>. The
    /// caller owns it and must dispose it; disposal releases any chained response buffer still in flight.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is <see langword="null"/>.</exception>
    public static CtapNfcResponder Create(
        CtapPayloadTransceiveDelegate payloadTransceive,
        CtapPayloadDeferredTransceiveDelegate deferredTransceive,
        CtapPayloadDeferredPollDelegate deferredPoll,
        CtapPayloadDeferredCancelDelegate deferredCancel)
    {
        ArgumentNullException.ThrowIfNull(payloadTransceive);
        ArgumentNullException.ThrowIfNull(deferredTransceive);
        ArgumentNullException.ThrowIfNull(deferredPoll);
        ArgumentNullException.ThrowIfNull(deferredCancel);

        return new CtapNfcResponder(payloadTransceive, deferredTransceive, deferredPoll, deferredCancel);
    }


    /// <summary>
    /// Handles one command APDU: applet selection, NFCCTAP_MSG, GET RESPONSE chaining,
    /// NFCCTAP_GETRESPONSE, or NFCCTAP_CONTROL deselection.
    /// </summary>
    /// <param name="commandApdu">The complete command APDU bytes.</param>
    /// <param name="pool">The memory pool for the response buffer.</param>
    /// <param name="cancellationToken">Cancellation token forwarded to <see cref="CtapPayloadTransceiveDelegate"/> and, when deferral is configured, the deferral delegates.</param>
    /// <returns>A result carrying the response APDU. Always a success at the transport level; card-level errors ride the status word, matching the established <c>VirtualCard</c> convention.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="pool"/> is <see langword="null"/>.</exception>
    public async ValueTask<ApduResult<ApduResponse>> TransceiveAsync(
        ReadOnlyMemory<byte> commandApdu,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ObjectDisposedException.ThrowIf(disposed, this);

        if(commandApdu.Length < ApduConstants.CommandHeaderSize)
        {
            return Reply(StatusWord.WrongLength, pool);
        }

        ReadOnlySpan<byte> header = commandApdu.Span;
        byte ins = header[1];
        byte p1 = header[2];

        ValueTask<ApduResult<ApduResponse>> dispatched = ins switch
        {
            var i when i == InstructionCode.Select.Code => HandleSelectAsync(commandApdu, p1, pool, cancellationToken),
            var i when i == WellKnownCtapInstructionCodes.NfcCtapMsg.Code => HandleNfcCtapMsgAsync(commandApdu, p1, pool, cancellationToken),
            var i when i == InstructionCode.GetResponse.Code => HandleGetResponseAsync(commandApdu, pool),
            var i when i == WellKnownCtapInstructionCodes.NfcCtapGetResponse.Code => HandleNfcCtapGetResponseAsync(commandApdu, p1, pool, cancellationToken),
            var i when i == WellKnownCtapInstructionCodes.NfcCtapControl.Code => HandleControlAsync(p1, pool, cancellationToken),
            _ => ValueTask.FromResult(Reply(StatusWord.InstructionNotSupported, pool))
        };

        return await dispatched.ConfigureAwait(false);
    }


    /// <summary>
    /// Handles applet selection (spec §11.3.3): only select-by-AID for <see cref="WellKnownAid.Fido"/>
    /// succeeds. Supersedes any request still parked awaiting deferred completion.
    /// </summary>
    /// <param name="commandApdu">The SELECT command APDU.</param>
    /// <param name="p1">The command's P1 byte.</param>
    /// <param name="pool">The memory pool for the response buffer.</param>
    /// <param name="cancellationToken">Cancellation token forwarded to <see cref="DeferredCancel"/> when superseding a parked request.</param>
    /// <returns>The SELECT response.</returns>
    private async ValueTask<ApduResult<ApduResponse>> HandleSelectAsync(
        ReadOnlyMemory<byte> commandApdu, byte p1, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        AppletSelected = false;
        await ClearPendingDeferralAsync(pool, cancellationToken).ConfigureAwait(false);
        ClearPendingChain();

        if(p1 != WellKnownCommandParameters.SelectByDfNameP1)
        {
            return Reply(StatusWord.IncorrectP1P2, pool);
        }

        if(!TryParseDataAndLe(commandApdu, out ReadOnlyMemory<byte> aid, out _, out _))
        {
            return Reply(StatusWord.WrongLength, pool);
        }

        if(!WellKnownAid.Matches(aid.Span, WellKnownAid.Fido))
        {
            return Reply(StatusWord.FileNotFound, pool);
        }

        AppletSelected = true;

        return Reply(SelectVersionString, StatusWord.Success, pool);
    }


    /// <summary>
    /// Handles applet deselection (spec §11.3.4): the applet ignores all CTAP commands until the next
    /// SELECT. Supersedes any request still parked awaiting deferred completion.
    /// </summary>
    /// <param name="p1">The command's P1 byte.</param>
    /// <param name="pool">The memory pool for the response buffer.</param>
    /// <param name="cancellationToken">Cancellation token forwarded to <see cref="DeferredCancel"/> when superseding a parked request.</param>
    /// <returns>The deselection response.</returns>
    private async ValueTask<ApduResult<ApduResponse>> HandleControlAsync(byte p1, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        if(p1 != WellKnownCtapCommandParameters.DeselectControlP1)
        {
            return Reply(StatusWord.IncorrectP1P2, pool);
        }

        AppletSelected = false;
        await ClearPendingDeferralAsync(pool, cancellationToken).ConfigureAwait(false);
        ClearPendingChain();

        return Reply(StatusWord.Success, pool);
    }


    /// <summary>
    /// Deframes an NFCCTAP_MSG command (spec §11.3.5.1), forwards the opaque envelope to
    /// <see cref="PayloadTransceive"/> or, when eligible and wired, <see cref="DeferredTransceive"/>, and
    /// frames the response per spec §11.3.6. Supersedes any request still parked from an earlier exchange.
    /// </summary>
    /// <param name="commandApdu">The NFCCTAP_MSG command APDU.</param>
    /// <param name="p1">The command's P1 byte.</param>
    /// <param name="pool">The memory pool for command and response buffers.</param>
    /// <param name="cancellationToken">Cancellation token forwarded to <see cref="PayloadTransceive"/>/<see cref="DeferredTransceive"/>.</param>
    /// <returns>The framed response.</returns>
    private async ValueTask<ApduResult<ApduResponse>> HandleNfcCtapMsgAsync(
        ReadOnlyMemory<byte> commandApdu, byte p1, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        if(!AppletSelected)
        {
            return Reply(StatusWord.ConditionsNotSatisfied, pool);
        }

        await ClearPendingDeferralAsync(pool, cancellationToken).ConfigureAwait(false);
        ClearPendingChain();

        if(!TryParseDataAndLe(commandApdu, out ReadOnlyMemory<byte> payload, out int requestedLe, out bool isExtended))
        {
            return Reply(StatusWord.WrongLength, pool);
        }

        //THE TRAP (:10799-10800): a 0x9100 deferral is legal only when the client's own P1 declares
        //NFCCTAP_GETRESPONSE support. Without the bit — or without the deferral seam wired at all —
        //this always falls through to the synchronous PayloadTransceive path below, byte-identical to a
        //responder created via the single-delegate Create overload.
        if(WellKnownCtapCommandParameters.IsSupportsGetResponseP1Bit(p1) && DeferralConfigured)
        {
            PooledMemory deferredResult = await DeferredTransceive!(payload, pool, cancellationToken).ConfigureAwait(false);

            if(deferredResult.Length == 0)
            {
                deferredResult.Dispose();
                DeferredResponsePending = true;
                PendingDeferralWasExtended = isExtended;

                return Reply([WellKnownCtapKeepaliveStatusCodes.UpNeeded], WellKnownCtapStatusWords.ResponseStatus, pool);
            }

            return EmitMsgResponse(deferredResult, requestedLe, isExtended, pool);
        }

        PooledMemory response = await PayloadTransceive(payload, pool, cancellationToken).ConfigureAwait(false);

        return EmitMsgResponse(response, requestedLe, isExtended, pool);
    }


    /// <summary>
    /// Frames a complete opaque CTAP2 response envelope per spec §11.3.6: an extended-length request is
    /// answered in one frame regardless of size, a short-form request chains via <see cref="EmitChunk"/>.
    /// Shared by the synchronous <see cref="PayloadTransceive"/> path and every deferred-completion path
    /// (an <c>NFCCTAP_MSG</c> whose deferred begin resolves immediately, and a later
    /// <c>NFCCTAP_GETRESPONSE</c> poll resolving a parked request), so the framing rule and the
    /// dispose-after-copy ordering it depends on are implemented exactly once.
    /// </summary>
    /// <param name="response">The complete response envelope; ownership transfers to this method.</param>
    /// <param name="requestedLe">The Le the terminal requested on the exchange carrying this response.</param>
    /// <param name="isExtended">Whether the originating NFCCTAP_MSG request used extended-length encoding.</param>
    /// <param name="pool">The memory pool for the response buffer.</param>
    /// <returns>The framed response.</returns>
    private ApduResult<ApduResponse> EmitMsgResponse(PooledMemory response, int requestedLe, bool isExtended, MemoryPool<byte> pool)
    {
        if(isExtended)
        {
            //Spec §11.3.6: an extended-length request MUST be answered with an extended-length
            //response, in one frame — never chained, regardless of the response's size. The frame's
            //bytes are copied into the ApduResponse's own buffer before this scope ends, so response's
            //own buffer is disposed immediately.
            using(response)
            {
                return Reply(response.AsReadOnlySpan(), StatusWord.Success, pool);
            }
        }

        //Ownership transfers to PendingResponse: the first chunk may not drain the whole response, in
        //which case EmitChunk retains it (via PendingResponse/PendingChain) across the GET RESPONSE
        //calls that follow, disposing it only once the chain is fully drained.
        PendingResponse = response;

        return EmitChunk(response.AsReadOnlyMemory(), requestedLe, pool);
    }


    /// <summary>
    /// Handles a GET RESPONSE (<c>0xC0</c>), draining the next fragment of a chained response.
    /// </summary>
    /// <param name="commandApdu">The GET RESPONSE command APDU.</param>
    /// <param name="pool">The memory pool for the response buffer.</param>
    /// <returns>The next fragment, or an error if no chain is outstanding.</returns>
    private ValueTask<ApduResult<ApduResponse>> HandleGetResponseAsync(ReadOnlyMemory<byte> commandApdu, MemoryPool<byte> pool)
    {
        if(PendingChain.Length == 0)
        {
            return ValueTask.FromResult(Reply(StatusWord.ConditionsNotSatisfied, pool));
        }

        int requestedLe = ParseCase2Le(commandApdu.Span);

        return ValueTask.FromResult(EmitChunk(PendingChain, requestedLe, pool));
    }


    /// <summary>
    /// Handles an NFCCTAP_GETRESPONSE (<c>0x11</c>) poll or cancel
    /// (<see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-ctap-response">
    /// CTAP 2.3, section 11.3.7.2</see>, lines 10817-10821).
    /// </summary>
    /// <param name="commandApdu">The NFCCTAP_GETRESPONSE command APDU.</param>
    /// <param name="p1">The command's P1 byte: <see cref="WellKnownCtapCommandParameters.CancelP1"/> requests cancellation; any other value polls.</param>
    /// <param name="pool">The memory pool for the response buffer.</param>
    /// <param name="cancellationToken">Cancellation token forwarded to <see cref="DeferredPoll"/>/<see cref="DeferredCancel"/>.</param>
    /// <returns>
    /// <c>0x6985</c> (conditions not satisfied) when nothing is parked, regardless of
    /// <paramref name="p1"/> — the out-of-sequence fence. Otherwise: the cancel outcome
    /// (<c>0x9000</c> with the opaque envelope <see cref="DeferredCancel"/> returns — the
    /// <c>CTAP2_ERR_KEEPALIVE_CANCEL</c> status byte per :10819-10821's SHALL, opaque to this
    /// responder) when <paramref name="p1"/> is <see cref="WellKnownCtapCommandParameters.CancelP1"/>;
    /// otherwise the poll outcome (<c>0x9100</c> with one
    /// <see cref="WellKnownCtapKeepaliveStatusCodes.UpNeeded"/> data byte while still parked, or the
    /// completed response once resolved).
    /// </returns>
    private async ValueTask<ApduResult<ApduResponse>> HandleNfcCtapGetResponseAsync(
        ReadOnlyMemory<byte> commandApdu, byte p1, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        if(!DeferredResponsePending)
        {
            return Reply(StatusWord.ConditionsNotSatisfied, pool);
        }

        if(WellKnownCtapCommandParameters.IsCancelP1(p1))
        {
            using PooledMemory cancelEnvelope = await DeferredCancel!(pool, cancellationToken).ConfigureAwait(false);
            DeferredResponsePending = false;

            return Reply(cancelEnvelope.AsReadOnlySpan(), StatusWord.Success, pool);
        }

        //Any other P1 with a request parked is the normal poll: lines 10823's P1-RFU MUST binds the
        //platform, not this responder, which permissively treats every non-cancel P1 as a poll.
        PooledMemory pollResult = await DeferredPoll!(pool, cancellationToken).ConfigureAwait(false);

        if(pollResult.Length == 0)
        {
            pollResult.Dispose();

            return Reply([WellKnownCtapKeepaliveStatusCodes.UpNeeded], WellKnownCtapStatusWords.ResponseStatus, pool);
        }

        DeferredResponsePending = false;
        int requestedLe = ParseCase2Le(commandApdu.Span);

        return EmitMsgResponse(pollResult, requestedLe, PendingDeferralWasExtended, pool);
    }


    /// <summary>
    /// Emits the next chunk of <paramref name="data"/>, sized to <paramref name="requestedLe"/> (or the
    /// short-form maximum when non-positive), saving any remainder in <see cref="PendingChain"/> and
    /// reporting <c>61xx</c> when a remainder exists or <c>9000</c> when the data is fully drained — at
    /// which point <see cref="PendingResponse"/>, the pooled buffer <paramref name="data"/> views into,
    /// is disposed, since nothing more will be read from it.
    /// </summary>
    /// <param name="data">The bytes still owed to the terminal.</param>
    /// <param name="requestedLe">The Le the terminal requested on this exchange.</param>
    /// <param name="pool">The memory pool for the response buffer.</param>
    /// <returns>The framed chunk.</returns>
    private ApduResult<ApduResponse> EmitChunk(ReadOnlyMemory<byte> data, int requestedLe, MemoryPool<byte> pool)
    {
        int wanted = requestedLe <= 0 ? ApduConstants.MaxShortResponseData : requestedLe;
        int chunkSize = Math.Min(wanted, data.Length);
        ReadOnlySpan<byte> chunk = data.Span[..chunkSize];
        ReadOnlyMemory<byte> remainder = data.Slice(chunkSize);

        if(remainder.Length == 0)
        {
            //The chunk is copied into Reply's own freshly rented buffer before PendingResponse is
            //disposed: disposing first would clear PendingResponse's buffer (SensitiveMemory's own
            //contract) while chunk is still a view into it, corrupting the copy Reply is about to make.
            ApduResult<ApduResponse> reply = Reply(chunk, StatusWord.Success, pool);

            PendingResponse?.Dispose();
            PendingResponse = null;
            PendingChain = ReadOnlyMemory<byte>.Empty;

            return reply;
        }

        PendingChain = remainder;
        int available = Math.Min(remainder.Length, ApduConstants.MaxShortResponseData);
        byte sw2 = (byte)(available == ApduConstants.MaxShortResponseData ? 0 : available);

        return Reply(chunk, StatusWord.FromBytes(0x61, sw2), pool);
    }


    /// <summary>
    /// Builds a response carrying no data, only a status word.
    /// </summary>
    /// <param name="statusWord">The status word.</param>
    /// <param name="pool">The memory pool for the response buffer.</param>
    /// <returns>The response, wrapped as a successful transceive.</returns>
    private static ApduResult<ApduResponse> Reply(StatusWord statusWord, MemoryPool<byte> pool) =>
        Reply(ReadOnlySpan<byte>.Empty, statusWord, pool);


    /// <summary>
    /// Builds a response carrying <paramref name="data"/> followed by <paramref name="statusWord"/>.
    /// </summary>
    /// <param name="data">The response data field.</param>
    /// <param name="statusWord">The status word.</param>
    /// <param name="pool">The memory pool for the response buffer.</param>
    /// <returns>The response, wrapped as a successful transceive per the established <c>VirtualCard</c> convention: any status word, including an error, is a successful transceive at the transport level.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned ApduResponse, which the caller disposes.")]
    private static ApduResult<ApduResponse> Reply(ReadOnlySpan<byte> data, StatusWord statusWord, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(data.Length + ApduConstants.StatusWordSize);
        Span<byte> span = owner.Memory.Span;
        data.CopyTo(span);
        span[data.Length] = statusWord.Sw1;
        span[data.Length + 1] = statusWord.Sw2;

        var response = new ApduResponse(owner, data.Length + ApduConstants.StatusWordSize);

        return ApduResult<ApduResponse>.Success(response, statusWord);
    }


    /// <summary>
    /// Parses the data field and, if present, the Le field of a Case 3/4-shaped command (header, an
    /// optional <c>0x00</c> extended-length marker, Lc, data, and an optional Le) — the inverse of
    /// <see cref="CommandApdu.BuildCase4(byte, byte, byte, byte, ReadOnlySpan{byte}, int, bool, MemoryPool{byte})"/>.
    /// </summary>
    /// <param name="commandApdu">The complete command APDU.</param>
    /// <param name="data">The data field, if parsing succeeded.</param>
    /// <param name="requestedLe">The requested Le, or <c>0</c> if the command carries no Le field.</param>
    /// <param name="isExtended">Whether the command used extended-length encoding.</param>
    /// <returns><see langword="true"/> if the command could be parsed as Case 3 or Case 4.</returns>
    private static bool TryParseDataAndLe(
        ReadOnlyMemory<byte> commandApdu, out ReadOnlyMemory<byte> data, out int requestedLe, out bool isExtended)
    {
        ReadOnlySpan<byte> span = commandApdu.Span;
        data = ReadOnlyMemory<byte>.Empty;
        requestedLe = 0;
        isExtended = false;

        if(span.Length <= ApduConstants.CommandHeaderSize)
        {
            return false;
        }

        byte marker = span[ApduConstants.CommandHeaderSize];
        int cursor = ApduConstants.CommandHeaderSize + 1;

        if(marker == 0x00 && span.Length >= cursor + 2)
        {
            int lc = (span[cursor] << 8) | span[cursor + 1];
            cursor += 2;
            if(span.Length < cursor + lc)
            {
                return false;
            }

            data = commandApdu.Slice(cursor, lc);
            cursor += lc;
            isExtended = true;

            if(span.Length == cursor + 2)
            {
                requestedLe = (span[cursor] << 8) | span[cursor + 1];
            }

            return true;
        }

        int shortLc = marker;
        if(span.Length < cursor + shortLc)
        {
            return false;
        }

        data = commandApdu.Slice(cursor, shortLc);
        cursor += shortLc;

        if(span.Length == cursor + 1)
        {
            requestedLe = span[cursor];
        }

        return true;
    }


    /// <summary>
    /// Parses the Le field of a Case 2-shaped command (header plus Le only, no data) — the inverse of
    /// <see cref="CommandApdu.BuildCase2"/>. A zero Le byte means the short-form maximum (256); a zero
    /// extended Le means the extended-form maximum (65536).
    /// </summary>
    /// <param name="commandApdu">The complete command APDU.</param>
    /// <returns>The requested Le, or <c>0</c> if the command is not Case-2 shaped.</returns>
    private static int ParseCase2Le(ReadOnlySpan<byte> commandApdu)
    {
        if(commandApdu.Length == ApduConstants.CommandHeaderSize + 1)
        {
            byte le = commandApdu[ApduConstants.CommandHeaderSize];

            return le == 0 ? ApduConstants.MaxShortResponseData : le;
        }

        if(commandApdu.Length == ApduConstants.CommandHeaderSize + 3
            && commandApdu[ApduConstants.CommandHeaderSize] == 0x00)
        {
            int le = (commandApdu[ApduConstants.CommandHeaderSize + 1] << 8) | commandApdu[ApduConstants.CommandHeaderSize + 2];

            return le == 0 ? ApduConstants.MaxExtendedResponseData : le;
        }

        return 0;
    }


    /// <inheritdoc />
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        disposed = true;
        ClearPendingChain();
    }


    private string DebuggerDisplay => AppletSelected
        ? $"CtapNfcResponder(selected, {PendingChain.Length}B chain pending{(DeferredResponsePending ? ", deferral pending" : string.Empty)})"
        : "CtapNfcResponder(not selected)";
}
