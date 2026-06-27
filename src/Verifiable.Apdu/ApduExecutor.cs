using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Apdu;

/// <summary>
/// Shared APDU command execution engine.
/// </summary>
/// <remarks>
/// <para>
/// The executor handles protocol mechanics that are common to all APDU commands:
/// </para>
/// <list type="bullet">
///   <item><description>Response chaining — <c>61xx</c> triggers automatic <c>GET RESPONSE</c> commands to retrieve remaining data.</description></item>
///   <item><description>Le correction — <c>6Cxx</c> triggers a single automatic retry with the corrected Le value.</description></item>
///   <item><description>Status word extraction — the SW is stripped from the data and returned separately.</description></item>
/// </list>
/// <para>
/// <strong>Design:</strong> The executor submits raw bytes via <see cref="ApduDevice.TransceiveAsync"/>
/// and assembles the complete response from one or more exchanges. The caller sees a single
/// <see cref="ApduResult{T}"/> with the fully assembled data.
/// </para>
/// <para>
/// <strong>Key invariant:</strong> After the executor completes, the caller never sees
/// <c>61xx</c> or <c>6Cxx</c> status words when the chain runs to completion. Success is
/// <c>9000</c>.
/// </para>
/// <para>
/// <strong>Le correction contract (<c>6Cxx</c>):</strong> A <c>6Cxx</c> status word means the
/// requested Le was wrong and the card reports the available length in SW2. The executor retries
/// the same command once with <c>Le = SW2</c>. The retried command's response is routed back
/// through the same post-processing, so a <c>6Cxx</c> that is answered by <c>61xx</c> still
/// chains, and a chain that ends in <c>9000</c> still collapses to <c>9000</c>. Only one Le
/// correction is attempted per command: if the retry again answers <c>6Cxx</c>, that second
/// <c>6Cxx</c> is surfaced to the caller as the card's response (no infinite retry). The retry
/// applies only to commands whose final byte is a short-form Le field (Case 2 / Case 4 short);
/// for a command with no Le field or an extended-length Le, the <c>6Cxx</c> is surfaced to the
/// caller unchanged rather than fabricating a corrupted retry.
/// </para>
/// <para>
/// <strong>Chain overflow contract (<c>61xx</c>):</strong> Response chaining issues at most
/// <see cref="MaxChainedResponses"/> <c>GET RESPONSE</c> commands. If the card still reports
/// <c>61xx</c> after that limit is reached, the executor stops and returns the data assembled so
/// far together with the last <c>61xx</c> status word — it does <strong>not</strong> fabricate a
/// <c>9000</c>. The caller therefore sees a successful result whose <see cref="ApduResponse.StatusWord"/>
/// is still <c>61xx</c>, signalling that the card had more data than the executor was willing to drain.
/// </para>
/// </remarks>
public static class ApduExecutor
{
    /// <summary>
    /// Maximum number of <c>GET RESPONSE</c> commands to issue for a single response chain.
    /// Prevents infinite loops from misbehaving cards.
    /// </summary>
    private const int MaxChainedResponses = 64;

    /// <summary>
    /// ISO/IEC 7816-4 command-chaining bit in the CLA byte. Set on a command that is one segment
    /// of an outbound chain; never set on a stand-alone <c>GET RESPONSE</c>.
    /// </summary>
    private const byte CommandChainingBit = 0x10;

    /// <summary>
    /// Submits a command and handles response chaining and Le correction.
    /// </summary>
    /// <param name="device">The APDU device.</param>
    /// <param name="commandApdu">The complete command APDU bytes.</param>
    /// <param name="pool">The memory pool for allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A result with the fully assembled response (data + final SW) or an error.</returns>
    public static async ValueTask<ApduResult<ApduResponse>> ExecuteAsync(
        ApduDevice device,
        ReadOnlyMemory<byte> commandApdu,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(pool);

        //The command currently on the wire. It starts as the caller's command and is replaced
        //by an Le-corrected copy if the card answers 6Cxx. The CLA and originally-requested Le
        //of this command drive any subsequent GET RESPONSE (see HandleResponseChainingAsync).
        ReadOnlyMemory<byte> currentCommand = commandApdu;
        IMemoryOwner<byte>? correctedCommandOwner = null;
        bool hasAttemptedLeCorrection = false;

        try
        {
            while(true)
            {
                ApduResult<ApduResponse> result = await device.TransceiveAsync(
                    currentCommand, pool, cancellationToken).ConfigureAwait(false);

                if(!result.IsSuccess)
                {
                    return result;
                }

                ApduResponse response = result.Value;

                //A conformant response always carries SW1-SW2. A successful transceive that returns
                //fewer than two bytes is a protocol integrity failure (e.g. a truncated frame); it is
                //surfaced through the result channel rather than allowed to throw while reading the SW.
                if(response.Length < ApduConstants.StatusWordSize)
                {
                    response.Dispose();

                    return ApduResult<ApduResponse>.TransportError(ApduConstants.MalformedResponseTransportError);
                }

                StatusWord sw = response.StatusWord;

                //Le correction (6Cxx): the card reports the correct length in SW2. Retry the same
                //command once with Le = SW2, then route the retry's response back through this loop
                //so a following 61xx still chains. A second 6Cxx is treated as the card's answer.
                //The retry only applies to commands whose last byte is a short-form Le field
                //(Case 2 / Case 4 short); for any other shape, overwriting the last byte would
                //corrupt the command, so the 6Cxx is surfaced to the caller instead.
                if(sw.IsWrongLeWithCorrection && !hasAttemptedLeCorrection
                    && TryGetShortRequestedLe(commandApdu.Span, out _))
                {
                    byte correctLe = sw.CorrectLe;
                    response.Dispose();

                    correctedCommandOwner = BuildLeCorrectedCommand(commandApdu.Span, correctLe, pool);
                    currentCommand = correctedCommandOwner.Memory;
                    hasAttemptedLeCorrection = true;

                    continue;
                }

                //Response chaining (61xx): issue GET RESPONSE to retrieve remaining data. The GET
                //RESPONSE commands carry the originating command's CLA (channel/SM bits preserved)
                //and clamp Le against the originating command's requested length. Both are extracted
                //here, while the command span is in scope, because the async chaining method cannot
                //hold a ReadOnlySpan parameter.
                if(sw.IsMoreDataAvailable)
                {
                    //GET RESPONSE per ISO/IEC 7816-4 §5.3.3 reuses the originating command's CLA so
                    //logical-channel bits (low nibble) and any secure-messaging bits are carried
                    //over; the outbound command-chaining bit is cleared because GET RESPONSE is a
                    //stand-alone command.
                    byte getResponseCla = (byte)(currentCommand.Span[0] & ~CommandChainingBit);

                    //The originating command's requested Le bounds the first GET RESPONSE. A value
                    //of zero means no usable short-form constraint was found, so the clamp is skipped.
                    int originalRequestedLe = TryGetShortRequestedLe(currentCommand.Span, out int parsedLe)
                        ? parsedLe
                        : 0;

                    return await HandleResponseChainingAsync(
                        device, response, getResponseCla, originalRequestedLe, pool, cancellationToken).ConfigureAwait(false);
                }

                return result;
            }
        }
        finally
        {
            correctedCommandOwner?.Dispose();
        }
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ApduResponse takes ownership of assembledOwner. The caller is responsible for disposing the returned ApduResult.")]
    private static async ValueTask<ApduResult<ApduResponse>> HandleResponseChainingAsync(
        ApduDevice device,
        ApduResponse initialResponse,
        byte getResponseCla,
        int originalRequestedLe,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        //When the originating command asked for fewer bytes than the card reports available,
        //requesting more would over-read; clamping the first GET RESPONSE to min(originalLe, SW2)
        //matches ISO/IEC 7816-4 Annex A.4. A non-positive originalRequestedLe means no constraint.
        //Collect all data fragments. The initial response has data + SW=61xx.
        int totalDataLength = initialResponse.DataLength;
        byte[][] fragments = new byte[MaxChainedResponses + 1][];
        int fragmentCount = 0;

        if(initialResponse.DataLength > 0)
        {
            fragments[fragmentCount] = initialResponse.Data.ToArray();
            fragmentCount++;
        }

        StatusWord currentSw = initialResponse.StatusWord;
        initialResponse.Dispose();

        bool isFirstGetResponse = true;
        int chainCount = 0;
        while(currentSw.IsMoreDataAvailable && chainCount < MaxChainedResponses)
        {
            //SW2 reports the bytes the card can return next (0 means 256). The first GET RESPONSE
            //is additionally clamped to the originating command's requested Le; later iterations
            //use SW2 directly because no original-Le constraint remains.
            int available = currentSw.BytesAvailable == 0
                ? ApduConstants.MaxShortResponseData
                : currentSw.BytesAvailable;

            int requestedLe = isFirstGetResponse && originalRequestedLe > 0 && originalRequestedLe < available
                ? originalRequestedLe
                : available;

            //Le is encoded in a single short-form byte; 256 is encoded as 0x00.
            byte le = (byte)(requestedLe == ApduConstants.MaxShortResponseData ? 0 : requestedLe);

            using CommandApdu getResponseCommand = CommandApdu.BuildCase2(
                getResponseCla, InstructionCode.GetResponse.Code, 0x00, 0x00,
                le, useExtended: false, pool);

            ApduResult<ApduResponse> chainResult = await device.TransceiveAsync(
                getResponseCommand.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);

            if(!chainResult.IsSuccess)
            {
                return chainResult;
            }

            using ApduResponse chainResponse = chainResult.Value;

            //A GET RESPONSE answer must also carry SW1-SW2; a sub-status-word frame mid-chain is a
            //protocol integrity failure surfaced through the result channel.
            if(chainResponse.Length < ApduConstants.StatusWordSize)
            {
                return ApduResult<ApduResponse>.TransportError(ApduConstants.MalformedResponseTransportError);
            }

            currentSw = chainResponse.StatusWord;

            if(chainResponse.DataLength > 0)
            {
                fragments[fragmentCount] = chainResponse.Data.ToArray();
                totalDataLength += chainResponse.DataLength;
                fragmentCount++;
            }

            isFirstGetResponse = false;
            chainCount++;
        }

        //Assemble all fragments into a single response.
        IMemoryOwner<byte> assembledOwner = pool.Rent(totalDataLength + ApduConstants.StatusWordSize);
        Span<byte> assembled = assembledOwner.Memory.Span;

        int offset = 0;
        for(int i = 0; i < fragmentCount; i++)
        {
            fragments[i].CopyTo(assembled[offset..]);
            offset += fragments[i].Length;
        }

        //Final SW. A chain that drained to 9000 collapses to 9000. If the chain stopped while the
        //card still reported 61xx (overflow past MaxChainedResponses), the last 61xx is preserved
        //so the caller can see the chain was truncated rather than completed.
        StatusWord finalSw = currentSw.IsSuccess ? StatusWord.Success : currentSw;
        assembled[offset] = finalSw.Sw1;
        assembled[offset + 1] = finalSw.Sw2;

        var assembledResponse = new ApduResponse(assembledOwner, totalDataLength + ApduConstants.StatusWordSize);

        return ApduResult<ApduResponse>.Success(assembledResponse, finalSw);
    }

    private static IMemoryOwner<byte> BuildLeCorrectedCommand(
        ReadOnlySpan<byte> originalCommand,
        byte correctLe,
        MemoryPool<byte> pool)
    {
        //The original command ends with Le (1 byte for short encoding).
        //Replace the last byte with the corrected value.
        IMemoryOwner<byte> owner = pool.Rent(originalCommand.Length);
        originalCommand.CopyTo(owner.Memory.Span);
        owner.Memory.Span[originalCommand.Length - 1] = correctLe;

        return owner;
    }

    /// <summary>
    /// Determines the response length (Le) a short-encoding command requested, if it can be parsed
    /// unambiguously. Extended-encoding commands and commands without an Le field yield
    /// <see langword="false"/>, in which case the caller imposes no original-Le clamp on GET RESPONSE.
    /// </summary>
    private static bool TryGetShortRequestedLe(ReadOnlySpan<byte> command, out int le)
    {
        le = 0;

        //Case 1 (header only) carries no Le.
        if(command.Length <= ApduConstants.CommandHeaderSize)
        {
            return false;
        }

        byte lengthByte = command[ApduConstants.CommandHeaderSize];

        //Case 2 short: header + Le. Le of 0x00 means 256.
        if(command.Length == ApduConstants.CommandHeaderSize + 1)
        {
            le = lengthByte == 0 ? ApduConstants.MaxShortResponseData : lengthByte;

            return true;
        }

        //A leading 0x00 length byte with further bytes indicates extended encoding, which this
        //short-form parser does not decode; impose no clamp.
        if(lengthByte == 0)
        {
            return false;
        }

        //Short Lc present: header + Lc + data (+ optional Le). Case 3 has no Le; Case 4 short
        //ends with a single Le byte.
        int caseFourLength = ApduConstants.CommandHeaderSize + 1 + lengthByte + 1;
        if(command.Length == caseFourLength)
        {
            byte leByte = command[caseFourLength - 1];
            le = leByte == 0 ? ApduConstants.MaxShortResponseData : leByte;

            return true;
        }

        return false;
    }
}
