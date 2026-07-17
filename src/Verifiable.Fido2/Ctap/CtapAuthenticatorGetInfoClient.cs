using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The RP/platform-side <c>authenticatorGetInfo</c> operation: builds the request envelope, sends it
/// through a transport-neutral <see cref="Ctap2TransceiveDelegate"/>, and decodes the response into
/// its typed model.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetInfo">
/// CTAP 2.3, section 6.4: authenticatorGetInfo (0x04)</see>: "This method takes no inputs," so the
/// request envelope is exactly the one-byte command code with no CBOR parameters — no request codec
/// seam is needed for this operation. This type never touches CBOR itself; the response payload
/// decode is supplied by the caller as a <see cref="DecodeCtapGetInfoResponseDelegate"/>, keeping
/// <c>Verifiable.Fido2</c> serialization-agnostic.
/// </remarks>
public static class CtapAuthenticatorGetInfoClient
{
    /// <summary>
    /// Sends an <c>authenticatorGetInfo</c> request and decodes the response.
    /// </summary>
    /// <param name="transceive">
    /// The transport-neutral CTAP2 request/response exchange, typically an NFC, USB, or BLE binding's
    /// transceive method bound here by ordinary C# method-group conversion.
    /// </param>
    /// <param name="decodeResponse">The codec that decodes the response's CBOR payload.</param>
    /// <param name="pool">The memory pool for the request and response buffers.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>The decoded <c>authenticatorGetInfo</c> response.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="transceive"/>, <paramref name="decodeResponse"/>, or <paramref name="pool"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="Fido2FormatException">The response envelope is empty.</exception>
    /// <exception cref="CtapCommandException">The authenticator returned a non-success status code.</exception>
    public static async ValueTask<CtapGetInfoResponse> GetInfoAsync(
        Ctap2TransceiveDelegate transceive,
        DecodeCtapGetInfoResponseDelegate decodeResponse,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transceive);
        ArgumentNullException.ThrowIfNull(decodeResponse);
        ArgumentNullException.ThrowIfNull(pool);

        byte[] request = [WellKnownCtapCommands.GetInfo];

        using PooledMemory envelope = await transceive(request, pool, cancellationToken).ConfigureAwait(false);

        if(envelope.Length == 0)
        {
            throw new Fido2FormatException("The authenticatorGetInfo response envelope is empty; a CTAP2 status byte was expected.");
        }

        byte statusCode = envelope.AsReadOnlySpan()[0];
        if(!WellKnownCtapStatusCodes.IsOk(statusCode))
        {
            throw new CtapCommandException(statusCode);
        }

        return decodeResponse(envelope.AsReadOnlyMemory()[1..]);
    }
}
