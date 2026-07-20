using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Apdu.Ctap;

/// <summary>
/// Delegate for polling a previously deferred CTAP2 request on the authenticator (card) side, with zero
/// awareness of CTAP2 command semantics or NFC framing.
/// </summary>
/// <param name="pool">The memory pool available for allocating the response buffer.</param>
/// <param name="cancellationToken">Cancellation token for the operation.</param>
/// <returns>
/// A ZERO-LENGTH <see cref="PooledMemory"/> if the deferred request is still pending, otherwise the
/// complete opaque CTAP2 response envelope — see <see cref="CtapPayloadDeferredTransceiveDelegate"/>'s
/// identical empty-marker convention.
/// </returns>
/// <remarks>
/// <para>
/// <strong>Shape, not a shared type.</strong> Method-group-compatible with a CTAP2 authenticator
/// implementation's own "poll a deferred transceive" method, mirroring
/// <see cref="CtapPayloadTransceiveDelegate"/>'s own no-shared-type, no-new-reference precedent.
/// </para>
/// <para>
/// <see cref="CtapNfcResponder"/> invokes this delegate from <c>NFCCTAP_GETRESPONSE</c> handling
/// (<see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-ctap-response">
/// CTAP 2.3, section 11.3.7.2</see>) only while a request is parked, and only for a P1 other than
/// <see cref="WellKnownCtapCommandParameters.CancelP1"/> — <see cref="CtapPayloadDeferredCancelDelegate"/>
/// handles the cancel variant instead. Called at most once per <c>NFCCTAP_GETRESPONSE</c> command.
/// </para>
/// </remarks>
public delegate ValueTask<PooledMemory> CtapPayloadDeferredPollDelegate(
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);
