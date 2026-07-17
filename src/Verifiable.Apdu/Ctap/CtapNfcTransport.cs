using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Apdu.Ctap;

/// <summary>
/// The client (platform/terminal) side of the CTAP2-over-NFC binding: composes a CTAP2 request/response
/// exchange over an already-selected FIDO applet, in pure ISO/IEC 7816-4 vocabulary.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-command-framing">
/// CTAP 2.3, section 11.3.5.1: Command framing</see> frames every CTAP2 request as an
/// <see cref="WellKnownCtapInstructionCodes.NfcCtapMsg"/> command APDU whose data field is the opaque
/// CTAP2 request envelope. This type builds that command, always using extended-length encoding
/// (<c>useExtended: true</c>) to sidestep <em>outbound</em> short-APDU command chaining (CLA
/// <c>0x90</c>/<c>0x80</c> per
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-fragmentation">
/// section 11.3.6: Fragmentation</see>) entirely this wave — a spec-conforming client choice since
/// extended-length encoding is always an option, and the CTAP2 <c>authenticatorGetInfo</c> request this
/// wave exercises has no data field to fragment in the first place. Building that outbound chaining is
/// deferred to a later wave if a request ever needs it.
/// </para>
/// <para>
/// <strong>Free response chaining.</strong> <c>61xx</c>/<c>GET RESPONSE</c> reassembly and <c>6Cxx</c>
/// Le correction are handled by the existing, unmodified <see cref="ApduExecutor"/> — the generic
/// ISO/IEC 7816-4 engine already does exactly what
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-fragmentation">
/// section 11.3.6</see>'s worked example needs.
/// </para>
/// <para>
/// <strong>The 0x9100 keep-alive loop.</strong> A response status word of
/// <see cref="WellKnownCtapStatusWords.ResponseStatus"/> (<c>0x9100</c>) means the authenticator has
/// deferred completion; this type polls with
/// <see cref="WellKnownCtapInstructionCodes.NfcCtapGetResponse"/> per
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-ctap-response">
/// section 11.3.7.2</see> until a final <c>9000</c> or an error. If the caller's
/// <see cref="CancellationToken"/> fires while a poll is outstanding, the cancel variant
/// (P1 <c>0x11</c>) is sent once before the cancellation is surfaced, per the same section.
/// </para>
/// <para>
/// <strong>Shape, not a shared type.</strong> <see cref="TransceiveAsync"/> has exactly the shape of
/// <see cref="CtapPayloadTransceiveDelegate"/> and, by construction, of the identically-shaped
/// transceive delegate the CTAP2 authenticator-API layer defines elsewhere in this solution — a CTAP2
/// client built against that layer binds directly to <c>transport.TransceiveAsync</c> by ordinary C#
/// method-group conversion, exactly as <c>CardSimulator.TransceiveAsync</c> converts directly to
/// <see cref="TransceiveDelegate"/> today. This project gains no reference to that layer because of it.
/// </para>
/// </remarks>
public sealed class CtapNfcTransport
{
    private ApduDevice Device { get; }

    /// <summary>
    /// Initializes a new instance closing over an already-selected authenticator device.
    /// </summary>
    /// <param name="device">The device with the FIDO applet already selected.</param>
    private CtapNfcTransport(ApduDevice device)
    {
        Device = device;
    }


    /// <summary>
    /// Composes a CTAP2-over-NFC transceive method over an already-selected FIDO applet.
    /// </summary>
    /// <param name="device">
    /// The device with the FIDO applet already selected via
    /// <c>device.SelectAsync(WellKnownAid.Fido, pool, cancellationToken)</c>. Applet selection is a
    /// one-shot session bracketing step, not per-command traffic, so it is not part of this transport.
    /// </param>
    /// <returns>A transport whose <see cref="TransceiveAsync"/> method carries CTAP2 request/response
    /// envelopes over <paramref name="device"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="device"/> is <see langword="null"/>.</exception>
    public static CtapNfcTransport OverApdu(ApduDevice device)
    {
        ArgumentNullException.ThrowIfNull(device);

        return new CtapNfcTransport(device);
    }


    /// <summary>
    /// Sends one CTAP2 request envelope and returns the corresponding response envelope.
    /// </summary>
    /// <param name="request">The opaque CTAP2 request envelope (CTAP command byte plus CBOR parameters).</param>
    /// <param name="pool">The memory pool for command and response buffers.</param>
    /// <param name="cancellationToken">A cancellation token, honored via the NFCCTAP_GETRESPONSE cancel variant.</param>
    /// <returns>
    /// The opaque CTAP2 response envelope (CTAP status byte plus CBOR response data), in a
    /// <see cref="PooledMemory"/> rented from <paramref name="pool"/>; the caller owns it and must
    /// dispose it.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="CtapNfcTransportException">
    /// Thrown when the authenticator returns a card-level error status word, or the transport fails.
    /// </exception>
    public async ValueTask<PooledMemory> TransceiveAsync(
        ReadOnlyMemory<byte> request,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pool);

        using CommandApdu command = CommandApdu.BuildCase4(
            WellKnownCtapCommandParameters.ClassByte, WellKnownCtapInstructionCodes.NfcCtapMsg.Code,
            WellKnownCtapCommandParameters.SupportsGetResponseP1Bit, WellKnownCommandParameters.ReservedForFutureUse,
            request.Span, 0, useExtended: true, pool);

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            Device, command.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);

        while(true)
        {
            if(result.IsTransportError)
            {
                throw new CtapNfcTransportException(result.TransportErrorCode);
            }

            using ApduResponse response = result.Value;
            StatusWord statusWord = response.StatusWord;

            if(statusWord.IsSuccess)
            {
                //One copy at the protocol boundary, out of the ApduResponse's pooled buffer (still
                //alive here) and into a fresh pooled buffer the caller owns — the same move
                //ApduResponse.FromResponseBytes itself makes when a platform transport hands it raw
                //bytes.
                return PooledMemory.FromBytes(response.Data, pool, CtapTags.ResponseEnvelope);
            }

            if(!WellKnownCtapStatusWords.IsResponseStatus(statusWord))
            {
                throw new CtapNfcTransportException(statusWord);
            }

            if(cancellationToken.IsCancellationRequested)
            {
                _ = await IssueGetResponseAsync(Device, WellKnownCtapCommandParameters.CancelP1, pool, CancellationToken.None).ConfigureAwait(false);

                cancellationToken.ThrowIfCancellationRequested();
            }

            result = await IssueGetResponseAsync(Device, WellKnownCommandParameters.ReservedForFutureUse, pool, cancellationToken).ConfigureAwait(false);
        }

        //Issues one NFCCTAP_GETRESPONSE, isolated in its own method (rather than inline in the polling
        //loop above) so the single command-build-then-execute shape stays simple regardless of which
        //loop iteration calls it. p1 selects the normal poll (0x00) or cancel (0x11) variant.
        static async ValueTask<ApduResult<ApduResponse>> IssueGetResponseAsync(
            ApduDevice device, byte p1, MemoryPool<byte> pool, CancellationToken cancellationToken)
        {
            using CommandApdu getResponseCommand = CommandApdu.BuildCase2(
                WellKnownCtapCommandParameters.ClassByte, WellKnownCtapInstructionCodes.NfcCtapGetResponse.Code,
                p1, WellKnownCommandParameters.ReservedForFutureUse, 0, useExtended: false, pool);

            return await ApduExecutor.ExecuteAsync(
                device, getResponseCommand.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
        }
    }
}
