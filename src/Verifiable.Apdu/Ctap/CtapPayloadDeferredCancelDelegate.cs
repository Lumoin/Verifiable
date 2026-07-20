using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Apdu.Ctap;

/// <summary>
/// Delegate for cancelling a previously deferred CTAP2 request on the authenticator (card) side, with
/// zero awareness of CTAP2 command semantics or NFC framing.
/// </summary>
/// <param name="pool">The memory pool available for allocating the response buffer.</param>
/// <param name="cancellationToken">Cancellation token for the operation.</param>
/// <returns>
/// The complete opaque CTAP2 response envelope for the cancellation — never empty: CTAP 2.3, lines
/// 10819-10821's SHALL fixes it to a bare <c>CTAP2_ERR_KEEPALIVE_CANCEL</c> status byte
/// (<see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
/// section 8.2</see>, <c>0x2D</c>). <see cref="CtapPayloadDeferredTransceiveDelegate"/>/
/// <see cref="CtapPayloadDeferredPollDelegate"/>'s empty-marker convention does not apply here — a
/// cancel always resolves.
/// </returns>
/// <remarks>
/// <para>
/// <strong>Shape, not a shared type.</strong> Method-group-compatible with a CTAP2 authenticator
/// implementation's own "cancel a deferred transceive" method, mirroring
/// <see cref="CtapPayloadTransceiveDelegate"/>'s own no-shared-type, no-new-reference precedent.
/// </para>
/// <para>
/// <see cref="CtapNfcResponder"/> invokes this delegate both from <c>NFCCTAP_GETRESPONSE</c> handling
/// when P1 is <see cref="WellKnownCtapCommandParameters.CancelP1"/>
/// (<see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-ctap-response">
/// CTAP 2.3, section 11.3.7.2</see>) and whenever a new <c>SELECT</c>, applet deselection, or
/// <c>NFCCTAP_MSG</c> supersedes a request still parked from an earlier exchange — in the supersede
/// case the returned envelope is discarded, its only role there being to deterministically tear down
/// the authenticator-side parked state.
/// </para>
/// </remarks>
public delegate ValueTask<PooledMemory> CtapPayloadDeferredCancelDelegate(
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);
