using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The RP/platform-side <c>authenticatorGetNextAssertion</c> operation: builds the request envelope,
/// sends it through a transport-neutral <see cref="Ctap2TransceiveDelegate"/>, and decodes the response
/// into the same typed model <c>authenticatorGetAssertion</c> uses.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetNextAssertion">
/// CTAP 2.3, section 6.3: authenticatorGetNextAssertion (0x08)</see>: "It takes no arguments," so the
/// request envelope is exactly the one-byte command code with no CBOR parameters — mirroring
/// <see cref="CtapAuthenticatorGetInfoClient"/>'s shape, the same bare-command-byte pattern. "On success,
/// the authenticator returns the same structure as returned by the authenticatorGetAssertion method" (with
/// <c>numberOfCredentials</c> omitted), so this operation reuses <see cref="CtapGetAssertionResponse"/>
/// and <see cref="DecodeCtapGetAssertionResponseDelegate"/> rather than defining a new response model.
/// </remarks>
public static class CtapAuthenticatorGetNextAssertionClient
{
    /// <summary>
    /// Sends an <c>authenticatorGetNextAssertion</c> request and decodes the response.
    /// </summary>
    /// <param name="transceive">
    /// The transport-neutral CTAP2 request/response exchange, typically an NFC, USB, or BLE binding's
    /// transceive method bound here by ordinary C# method-group conversion.
    /// </param>
    /// <param name="decodeResponse">The codec that decodes the response's CBOR payload.</param>
    /// <param name="pool">The memory pool for the request and response buffers.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>The decoded <c>authenticatorGetNextAssertion</c> response.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="transceive"/>, <paramref name="decodeResponse"/>, or <paramref name="pool"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="Fido2FormatException">The response envelope is empty.</exception>
    /// <exception cref="CtapCommandException">The authenticator returned a non-success status code.</exception>
    public static async ValueTask<CtapGetAssertionResponse> GetNextAssertionAsync(
        Ctap2TransceiveDelegate transceive,
        DecodeCtapGetAssertionResponseDelegate decodeResponse,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transceive);
        ArgumentNullException.ThrowIfNull(decodeResponse);
        ArgumentNullException.ThrowIfNull(pool);

        byte[] request = [WellKnownCtapCommands.GetNextAssertion];

        using PooledMemory envelope = await transceive(request, pool, cancellationToken).ConfigureAwait(false);

        if(envelope.Length == 0)
        {
            throw new Fido2FormatException("The authenticatorGetNextAssertion response envelope is empty; a CTAP2 status byte was expected.");
        }

        byte statusCode = envelope.AsReadOnlySpan()[0];
        if(!WellKnownCtapStatusCodes.IsOk(statusCode))
        {
            throw new CtapCommandException(statusCode);
        }

        return decodeResponse(envelope.AsReadOnlyMemory()[1..], pool);
    }
}
