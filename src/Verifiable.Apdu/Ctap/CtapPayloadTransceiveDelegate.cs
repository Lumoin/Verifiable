using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Apdu.Ctap;

/// <summary>
/// Delegate for handling one complete CTAP2 request/response envelope on the authenticator (card)
/// side of the NFC transport, with zero awareness of CTAP2 command semantics or NFC framing.
/// </summary>
/// <param name="request">
/// The opaque CTAP2 request envelope exactly as carried in an <c>NFCCTAP_MSG</c> data field: the
/// CTAP command byte followed by CBOR-encoded parameters
/// (<see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-command-framing">
/// CTAP 2.3, section 11.3.5.1: Command framing</see>). <see cref="CtapNfcResponder"/> deframes the
/// incoming NFCCTAP_MSG command APDU down to exactly these bytes before invoking this delegate, and
/// reframes exactly what this delegate returns back into a response APDU; it never inspects the
/// content.
/// </param>
/// <param name="pool">The memory pool available for allocating the response buffer.</param>
/// <param name="cancellationToken">Cancellation token for the operation.</param>
/// <returns>
/// The opaque CTAP2 response envelope: a CTAP status byte followed by CBOR-encoded response data
/// (<see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-response-framing">
/// CTAP 2.3, section 11.3.5.2: Response framing</see>), wrapped in a <see cref="PooledMemory"/> carrier
/// allocated from <paramref name="pool"/>. Ownership transfers to the caller (<see cref="CtapNfcResponder"/>),
/// which must dispose it once it has copied the bytes into the response APDU it frames.
/// </returns>
/// <remarks>
/// <para>
/// <strong>Method-group conversion, not a shared type.</strong> This delegate is deliberately identical
/// in shape to the transceive delegate the CTAP2 authenticator-API layer defines elsewhere in this
/// solution — the same BCL types (<see cref="ReadOnlyMemory{T}"/>, <see cref="MemoryPool{T}"/>,
/// <see cref="CancellationToken"/>) plus the transport-neutral <see cref="PooledMemory"/> carrier from
/// <c>Verifiable.Foundation</c>, which <c>Verifiable.Apdu</c> already references — so this shape adds
/// no new reference in either direction. A CTAP2 authenticator implementation built against that layer
/// exposes one method with this exact request/response shape; that single method converts, by ordinary
/// C# method-group conversion, both to that layer's own delegate (for a client role) and to this
/// delegate (for wiring into <see cref="CtapNfcResponder"/> on the authenticator/card role) — with
/// neither project gaining a reference to the other, and no shared delegate type between the two.
/// </para>
/// <para>
/// <strong>Buffer lifetime.</strong> The <c>request</c> parameter is a view over the terminal-side
/// command APDU's pooled storage and is valid only for the duration of this call — it is cleared once
/// the caller's command buffer is disposed, which happens as soon as this delegate returns. An
/// implementation that needs the bytes beyond its own synchronous continuation must copy them (for
/// example into the CBOR reader it hands off to, or an explicit <c>ToArray()</c>) rather than retain
/// the <see cref="ReadOnlyMemory{T}"/> itself.
/// </para>
/// </remarks>
public delegate ValueTask<PooledMemory> CtapPayloadTransceiveDelegate(
    ReadOnlyMemory<byte> request,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);
