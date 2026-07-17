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
/// <strong>Wave-1 scope: no deferred processing.</strong> <see cref="WellKnownCtapInstructionCodes.NfcCtapGetResponse"/>
/// (<c>0x11</c>) polls for the "still processing" wrapper
/// (<see cref="WellKnownCtapStatusWords.ResponseStatus"/>, <c>0x9100</c>) per
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-ctap-response">
/// CTAP 2.3, section 11.3.7.2</see>. This responder always awaits <see cref="CtapPayloadTransceiveDelegate"/>
/// to completion synchronously inside <see cref="WellKnownCtapInstructionCodes.NfcCtapMsg"/> handling
/// (wave 1's <c>authenticatorGetInfo</c> has no user-presence wait to model), so it never emits
/// <c>0x9100</c> and never has a deferred result to report. The instruction is still recognized: an
/// out-of-sequence poll answers "conditions not satisfied" (<c>0x6985</c>) rather than "instruction not
/// supported" (<c>0x6D00</c>), leaving room for a future authenticator that does defer.
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

    /// <summary>Gets or sets a value indicating whether the FIDO applet is currently selected.</summary>
    private bool AppletSelected { get; set; }

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
    /// Initializes a new instance over the supplied opaque-payload seam.
    /// </summary>
    /// <param name="payloadTransceive">The seam that handles one opaque CTAP2 request/response envelope.</param>
    private CtapNfcResponder(CtapPayloadTransceiveDelegate payloadTransceive)
    {
        this.PayloadTransceive = payloadTransceive;
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
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="payloadTransceive"/> is <see langword="null"/>.</exception>
    public static CtapNfcResponder Create(CtapPayloadTransceiveDelegate payloadTransceive)
    {
        ArgumentNullException.ThrowIfNull(payloadTransceive);

        return new CtapNfcResponder(payloadTransceive);
    }


    /// <summary>
    /// Handles one command APDU: applet selection, NFCCTAP_MSG, GET RESPONSE chaining,
    /// NFCCTAP_GETRESPONSE, or NFCCTAP_CONTROL deselection.
    /// </summary>
    /// <param name="commandApdu">The complete command APDU bytes.</param>
    /// <param name="pool">The memory pool for the response buffer.</param>
    /// <param name="cancellationToken">Cancellation token forwarded to <see cref="CtapPayloadTransceiveDelegate"/>.</param>
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
            var i when i == InstructionCode.Select.Code => HandleSelectAsync(commandApdu, p1, pool),
            var i when i == WellKnownCtapInstructionCodes.NfcCtapMsg.Code => HandleNfcCtapMsgAsync(commandApdu, pool, cancellationToken),
            var i when i == InstructionCode.GetResponse.Code => HandleGetResponseAsync(commandApdu, pool),
            var i when i == WellKnownCtapInstructionCodes.NfcCtapGetResponse.Code => HandleNfcCtapGetResponseAsync(pool),
            var i when i == WellKnownCtapInstructionCodes.NfcCtapControl.Code => HandleControlAsync(p1, pool),
            _ => ValueTask.FromResult(Reply(StatusWord.InstructionNotSupported, pool))
        };

        return await dispatched.ConfigureAwait(false);
    }


    /// <summary>
    /// Handles applet selection (spec §11.3.3): only select-by-AID for <see cref="WellKnownAid.Fido"/> succeeds.
    /// </summary>
    /// <param name="commandApdu">The SELECT command APDU.</param>
    /// <param name="p1">The command's P1 byte.</param>
    /// <param name="pool">The memory pool for the response buffer.</param>
    /// <returns>The SELECT response.</returns>
    private ValueTask<ApduResult<ApduResponse>> HandleSelectAsync(ReadOnlyMemory<byte> commandApdu, byte p1, MemoryPool<byte> pool)
    {
        AppletSelected = false;
        ClearPendingChain();

        if(p1 != WellKnownCommandParameters.SelectByDfNameP1)
        {
            return ValueTask.FromResult(Reply(StatusWord.IncorrectP1P2, pool));
        }

        if(!TryParseDataAndLe(commandApdu, out ReadOnlyMemory<byte> aid, out _, out _))
        {
            return ValueTask.FromResult(Reply(StatusWord.WrongLength, pool));
        }

        if(!WellKnownAid.Matches(aid.Span, WellKnownAid.Fido))
        {
            return ValueTask.FromResult(Reply(StatusWord.FileNotFound, pool));
        }

        AppletSelected = true;

        return ValueTask.FromResult(Reply(SelectVersionString, StatusWord.Success, pool));
    }


    /// <summary>
    /// Handles applet deselection (spec §11.3.4): the applet ignores all CTAP commands until the next SELECT.
    /// </summary>
    /// <param name="p1">The command's P1 byte.</param>
    /// <param name="pool">The memory pool for the response buffer.</param>
    /// <returns>The deselection response.</returns>
    private ValueTask<ApduResult<ApduResponse>> HandleControlAsync(byte p1, MemoryPool<byte> pool)
    {
        if(p1 != WellKnownCtapCommandParameters.DeselectControlP1)
        {
            return ValueTask.FromResult(Reply(StatusWord.IncorrectP1P2, pool));
        }

        AppletSelected = false;
        ClearPendingChain();

        return ValueTask.FromResult(Reply(StatusWord.Success, pool));
    }


    /// <summary>
    /// Deframes an NFCCTAP_MSG command (spec §11.3.5.1), forwards the opaque envelope to
    /// <see cref="PayloadTransceive"/>, and frames the response per spec §11.3.6.
    /// </summary>
    /// <param name="commandApdu">The NFCCTAP_MSG command APDU.</param>
    /// <param name="pool">The memory pool for command and response buffers.</param>
    /// <param name="cancellationToken">Cancellation token forwarded to <see cref="PayloadTransceive"/>.</param>
    /// <returns>The framed response.</returns>
    private async ValueTask<ApduResult<ApduResponse>> HandleNfcCtapMsgAsync(
        ReadOnlyMemory<byte> commandApdu, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        if(!AppletSelected)
        {
            return Reply(StatusWord.ConditionsNotSatisfied, pool);
        }

        ClearPendingChain();

        if(!TryParseDataAndLe(commandApdu, out ReadOnlyMemory<byte> payload, out int requestedLe, out bool isExtended))
        {
            return Reply(StatusWord.WrongLength, pool);
        }

        PooledMemory response = await PayloadTransceive(payload, pool, cancellationToken).ConfigureAwait(false);

        if(isExtended)
        {
            //Spec §11.3.6: an extended-length request MUST be answered with an extended-length
            //response, in one frame — never chained, regardless of the response's size this wave. The
            //frame's bytes are copied into the ApduResponse's own buffer before this scope ends, so the
            //payload delegate's buffer is disposed immediately.
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
    /// Handles an NFCCTAP_GETRESPONSE (<c>0x11</c>) poll or cancel. See the type remarks for why this
    /// wave never has a deferred result to report.
    /// </summary>
    /// <param name="pool">The memory pool for the response buffer.</param>
    /// <returns>A "conditions not satisfied" response.</returns>
    private static ValueTask<ApduResult<ApduResponse>> HandleNfcCtapGetResponseAsync(MemoryPool<byte> pool)
    {
        return ValueTask.FromResult(Reply(StatusWord.ConditionsNotSatisfied, pool));
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
        ? $"CtapNfcResponder(selected, {PendingChain.Length}B chain pending)"
        : "CtapNfcResponder(not selected)";
}
