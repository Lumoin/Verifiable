using System.Buffers;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Apdu;

/// <summary>
/// Delegate for submitting a command APDU and receiving a response APDU.
/// </summary>
/// <param name="commandApdu">
/// The complete command APDU bytes (CLA, INS, P1, P2, optional Lc, data, Le).
/// Uses <see cref="System.ReadOnlyMemory{T}"/> rather than <see cref="System.ReadOnlySpan{T}"/>
/// because the call crosses an <c>await</c> boundary — NFC transceive on Android and iOS
/// is inherently asynchronous.
/// </param>
/// <param name="pool">The memory pool for allocating the response buffer.</param>
/// <param name="cancellationToken">Cancellation token for the operation.</param>
/// <returns>
/// A result containing the <see cref="ApduResponse"/> or a transport error.
/// The caller owns the response and must dispose it.
/// </returns>
/// <remarks>
/// <para>
/// This is the single abstraction boundary between the APDU protocol engine and
/// the platform transport. Implementations wire platform-specific NFC or PC/SC
/// APIs into this delegate:
/// </para>
/// <list type="bullet">
///   <item><description>Android: <c>IsoDep.Transceive</c>.</description></item>
///   <item><description>iOS: <c>NFCISO7816Tag.SendCommand</c>.</description></item>
///   <item><description>PC/SC: <c>SCardTransmit</c>.</description></item>
///   <item><description>Virtual: <see cref="VirtualCard"/> for testing and replay.</description></item>
/// </list>
/// <para>
/// The protocol engine (executor) calls this delegate for each individual APDU
/// exchange. Response chaining (<c>GET RESPONSE</c> for <c>61xx</c>) and Le
/// correction (<c>6Cxx</c>) are handled by the executor, not the delegate
/// implementation.
/// </para>
/// </remarks>
public delegate ValueTask<ApduResult<ApduResponse>> TransceiveDelegate(
    ReadOnlyMemory<byte> commandApdu,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);
