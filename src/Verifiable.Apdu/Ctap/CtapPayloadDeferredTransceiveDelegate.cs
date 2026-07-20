using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Apdu.Ctap;

/// <summary>
/// Delegate for beginning one CTAP2 request/response envelope on an authenticator (card) side that can
/// defer completion across separate NFC exchanges, with zero awareness of CTAP2 command semantics or
/// NFC framing.
/// </summary>
/// <param name="request">
/// The opaque CTAP2 request envelope, exactly as <see cref="CtapPayloadTransceiveDelegate"/>'s own
/// <c>request</c> parameter — <see cref="CtapNfcResponder"/> deframes the incoming <c>NFCCTAP_MSG</c>
/// command APDU down to exactly these bytes before invoking this delegate.
/// </param>
/// <param name="pool">The memory pool available for allocating the response buffer.</param>
/// <param name="cancellationToken">Cancellation token for the operation.</param>
/// <returns>
/// The complete opaque CTAP2 response envelope, exactly as <see cref="CtapPayloadTransceiveDelegate"/>'s
/// own return — OR a ZERO-LENGTH <see cref="PooledMemory"/> marking "the command parked awaiting user
/// presence"
/// (<see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-ctap-response">
/// CTAP 2.3, section 11.3.7.2</see>, lines 10817-10818's SHALL): every real CTAP2 response envelope
/// carries at least one status byte, so an empty result is unambiguous. This marker convention is
/// specific to this delegate and to <see cref="CtapPayloadDeferredPollDelegate"/>/
/// <see cref="CtapPayloadDeferredCancelDelegate"/> — it never applies to
/// <see cref="CtapPayloadTransceiveDelegate"/>, whose own empty result stays an ordinary decode failure
/// on the client side.
/// </returns>
/// <remarks>
/// <para>
/// <strong>Shape, not a shared type.</strong> Method-group-compatible with a CTAP2 authenticator
/// implementation's own "begin a deferrable transceive" method — the same BCL types
/// (<see cref="ReadOnlyMemory{T}"/>, <see cref="MemoryPool{T}"/>, <see cref="CancellationToken"/>) plus
/// the transport-neutral <see cref="PooledMemory"/> carrier, mirroring
/// <see cref="CtapPayloadTransceiveDelegate"/>'s own no-shared-type, no-new-reference precedent: neither
/// project gains a reference to the other because of this shape.
/// </para>
/// <para>
/// <see cref="CtapNfcResponder"/> invokes this delegate only from <c>NFCCTAP_MSG</c> handling, and only
/// when the client's P1 carries <see cref="WellKnownCtapCommandParameters.SupportsGetResponseP1Bit"/> —
/// never otherwise (CTAP 2.3, lines 10799-10800's MAY is conditioned on that bit; a responder created
/// without this delegate wired never invokes it either).
/// </para>
/// </remarks>
public delegate ValueTask<PooledMemory> CtapPayloadDeferredTransceiveDelegate(
    ReadOnlyMemory<byte> request,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);
