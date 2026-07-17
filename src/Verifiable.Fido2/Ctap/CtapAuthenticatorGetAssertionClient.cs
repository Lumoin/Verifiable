using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The RP/platform-side <c>authenticatorGetAssertion</c> operation: builds the request envelope, sends
/// it through a transport-neutral <see cref="Ctap2TransceiveDelegate"/>, and decodes the response into
/// its typed model.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion">
/// CTAP 2.3, section 6.2: authenticatorGetAssertion (0x02)</see>. Mirrors
/// <see cref="CtapAuthenticatorGetInfoClient"/>'s shape: the request envelope is
/// <see cref="WellKnownCtapCommands.GetAssertion"/> followed by the CBOR-encoded parameter map an
/// injected <see cref="EncodeCtapGetAssertionRequestDelegate"/> produces; the response status byte is
/// checked via <see cref="WellKnownCtapStatusCodes.IsOk"/>, a non-success status raises
/// <see cref="CtapCommandException"/>, and the response payload is decoded by an injected
/// <see cref="DecodeCtapGetAssertionResponseDelegate"/>. Unlike <c>authenticatorMakeCredential</c>'s
/// response, an <c>authenticatorGetAssertion</c> response's <c>authData</c>/<c>signature</c> already have
/// exactly the shape <see cref="Fido2AssertionVerifier"/> expects — no CTAP&#8594;WebAuthn envelope
/// translation is needed on the assertion side.
/// </remarks>
public static class CtapAuthenticatorGetAssertionClient
{
    /// <summary>
    /// Sends an <c>authenticatorGetAssertion</c> request and decodes the response.
    /// </summary>
    /// <param name="transceive">
    /// The transport-neutral CTAP2 request/response exchange, typically an NFC, USB, or BLE binding's
    /// transceive method bound here by ordinary C# method-group conversion.
    /// </param>
    /// <param name="encodeRequest">The codec that CBOR-encodes <paramref name="request"/>.</param>
    /// <param name="request">The request model to send.</param>
    /// <param name="decodeResponse">The codec that decodes the response's CBOR payload.</param>
    /// <param name="pool">The memory pool for the request and response buffers.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>The decoded <c>authenticatorGetAssertion</c> response.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="transceive"/>, <paramref name="encodeRequest"/>, <paramref name="request"/>,
    /// <paramref name="decodeResponse"/>, or <paramref name="pool"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="Fido2FormatException">The response envelope is empty.</exception>
    /// <exception cref="CtapCommandException">The authenticator returned a non-success status code.</exception>
    public static async ValueTask<CtapGetAssertionResponse> GetAssertionAsync(
        Ctap2TransceiveDelegate transceive,
        EncodeCtapGetAssertionRequestDelegate encodeRequest,
        CtapGetAssertionRequest request,
        DecodeCtapGetAssertionResponseDelegate decodeResponse,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transceive);
        ArgumentNullException.ThrowIfNull(encodeRequest);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(decodeResponse);
        ArgumentNullException.ThrowIfNull(pool);

        byte[] envelope = BuildRequestEnvelope(encodeRequest(request));

        using PooledMemory response = await transceive(envelope, pool, cancellationToken).ConfigureAwait(false);

        if(response.Length == 0)
        {
            throw new Fido2FormatException("The authenticatorGetAssertion response envelope is empty; a CTAP2 status byte was expected.");
        }

        byte statusCode = response.AsReadOnlySpan()[0];
        if(!WellKnownCtapStatusCodes.IsOk(statusCode))
        {
            throw new CtapCommandException(statusCode);
        }

        return decodeResponse(response.AsReadOnlyMemory()[1..], pool);
    }


    /// <summary>
    /// Builds the complete request envelope: <see cref="WellKnownCtapCommands.GetAssertion"/> followed by
    /// <paramref name="parameters"/>.
    /// </summary>
    private static byte[] BuildRequestEnvelope(TaggedMemory<byte> parameters)
    {
        byte[] envelope = new byte[parameters.Length + 1];
        envelope[0] = WellKnownCtapCommands.GetAssertion;
        parameters.Span.CopyTo(envelope.AsSpan(1));

        return envelope;
    }
}
