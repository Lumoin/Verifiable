using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Delegate for submitting a complete CTAP2 request envelope and receiving the complete CTAP2
/// response envelope, independent of the underlying wire transport.
/// </summary>
/// <param name="request">
/// The complete CTAP2 request bytes for one authenticator operation. Over NFC this is the CTAP
/// command byte followed by CBOR-encoded parameters that a transport binds into one or more command
/// APDUs; over other transports it is framed differently, but the bytes handed to this delegate are
/// always the transport-agnostic CTAP2 request. Uses <see cref="ReadOnlyMemory{T}"/> rather than
/// <see cref="ReadOnlySpan{T}"/> because the call crosses an <c>await</c> boundary — exchanging a
/// request with a roaming authenticator, whether over NFC, USB, or BLE, is inherently asynchronous.
/// </param>
/// <param name="pool">The memory pool available for allocating the response buffer.</param>
/// <param name="cancellationToken">Cancellation token for the operation.</param>
/// <returns>
/// The complete CTAP2 response bytes for the operation: a status byte followed by CBOR-encoded
/// response data, wrapped in a <see cref="PooledMemory"/> carrier allocated from <paramref name="pool"/>.
/// Ownership transfers to the caller, which must dispose it (typically with a <see langword="using"/>
/// at the point it decodes the response) — disposing clears the buffer and returns it to the pool.
/// </returns>
/// <remarks>
/// <para>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#protocol-structure">
/// CTAP 2.3, section 3: Protocol Structure</see> specifies the protocol in three layers: the
/// Authenticator API (an abstract operation taking parameters and returning a result), Message
/// Encoding (encoding that operation as a request/response pair), and a Transport-specific Binding
/// (carrying that request/response pair over USB, NFC, or Bluetooth). This delegate is the seam
/// between the second and third layers: CTAP2 command construction and response interpretation
/// operate purely on the bytes this delegate exchanges, with zero awareness of which transport
/// carried them.
/// </para>
/// <para>
/// <strong>Method-group conversion, not a shared type.</strong> This delegate deliberately uses only
/// BCL types (<see cref="ReadOnlyMemory{T}"/>, <see cref="MemoryPool{T}"/>,
/// <see cref="CancellationToken"/>) and the transport-neutral <see cref="PooledMemory"/> carrier from
/// <c>Verifiable.Foundation</c> — a project both <c>Verifiable.Fido2</c> and <c>Verifiable.Apdu</c>
/// already reference, so neither project gains a new reference to the other because of this shape. A
/// transport binding built on <c>Verifiable.Apdu</c> (for example an NFC transceive method composed
/// over <c>ApduDevice</c>/<c>ApduExecutor</c>) never needs to reference this delegate's declaring type
/// or <c>Verifiable.Fido2</c> at all: it only needs a method with this exact parameter and return
/// shape. At the composition site — wherever both projects are already in scope, such as a flow test
/// or a CLI wiring path — that method converts directly to a <see cref="Ctap2TransceiveDelegate"/>
/// instance by ordinary C# method-group conversion, exactly as <c>CardSimulator.TransceiveAsync</c>
/// converts directly to <c>Verifiable.Apdu.TransceiveDelegate</c> today. Neither
/// <c>Verifiable.Fido2.csproj</c> nor <c>Verifiable.Apdu.csproj</c> gains a reference to the other
/// because of this binding.
/// </para>
/// </remarks>
public delegate ValueTask<PooledMemory> Ctap2TransceiveDelegate(
    ReadOnlyMemory<byte> request,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);
