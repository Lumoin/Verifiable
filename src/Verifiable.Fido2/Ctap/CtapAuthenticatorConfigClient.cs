using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The RP/platform-side <c>authenticatorConfig</c> operation: builds the request envelope and sends it
/// through a transport-neutral <see cref="Ctap2TransceiveDelegate"/>.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorConfig">
/// CTAP 2.3, section 6.11: authenticatorConfig (0x0D) Command Definition</see>. Mirrors
/// <see cref="CtapAuthenticatorClientPinClient"/>'s shape: the request envelope is
/// <see cref="WellKnownCtapCommands.AuthenticatorConfig"/> followed by the CBOR-encoded parameter map an
/// injected <see cref="EncodeCtapAuthenticatorConfigRequestDelegate"/> produces, and the response status
/// byte is checked via <see cref="WellKnownCtapStatusCodes.IsOk"/>, a non-success status raising
/// <see cref="CtapCommandException"/>. Unlike <see cref="CtapAuthenticatorClientPinClient"/>,
/// <c>authenticatorConfig</c> defines no response CBOR body — success is the bare status byte — so
/// there is no response type or decode delegate here. One generic operation serves every subcommand —
/// the subcommand-specific request shape lives entirely in the caller-built <see cref="CtapAuthenticatorConfigRequest"/>,
/// and <c>pinUvAuthParam</c> assembly/signing stays caller-side, exactly as
/// <see cref="CtapAuthenticatorClientPinClient"/> leaves its crypto to callers.
/// </remarks>
public static class CtapAuthenticatorConfigClient
{
    /// <summary>
    /// Sends an <c>authenticatorConfig</c> request and confirms success.
    /// </summary>
    /// <param name="transceive">
    /// The transport-neutral CTAP2 request/response exchange, typically an NFC, USB, or BLE binding's
    /// transceive method bound here by ordinary C# method-group conversion.
    /// </param>
    /// <param name="encodeRequest">The codec that CBOR-encodes <paramref name="request"/>.</param>
    /// <param name="request">The request model to send.</param>
    /// <param name="pool">The memory pool for the request and response buffers.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="transceive"/>, <paramref name="encodeRequest"/>, <paramref name="request"/>, or
    /// <paramref name="pool"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="Fido2FormatException">The response envelope is empty.</exception>
    /// <exception cref="CtapCommandException">The authenticator returned a non-success status code.</exception>
    public static async ValueTask AuthenticatorConfigAsync(
        Ctap2TransceiveDelegate transceive,
        EncodeCtapAuthenticatorConfigRequestDelegate encodeRequest,
        CtapAuthenticatorConfigRequest request,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transceive);
        ArgumentNullException.ThrowIfNull(encodeRequest);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(pool);

        byte[] envelope = BuildRequestEnvelope(encodeRequest(request));

        using PooledMemory response = await transceive(envelope, pool, cancellationToken).ConfigureAwait(false);

        if(response.Length == 0)
        {
            throw new Fido2FormatException("The authenticatorConfig response envelope is empty; a CTAP2 status byte was expected.");
        }

        byte statusCode = response.AsReadOnlySpan()[0];
        if(!WellKnownCtapStatusCodes.IsOk(statusCode))
        {
            throw new CtapCommandException(statusCode);
        }
    }


    /// <summary>
    /// Builds the complete request envelope: <see cref="WellKnownCtapCommands.AuthenticatorConfig"/>
    /// followed by <paramref name="parameters"/>.
    /// </summary>
    private static byte[] BuildRequestEnvelope(TaggedMemory<byte> parameters)
    {
        byte[] envelope = new byte[parameters.Length + 1];
        envelope[0] = WellKnownCtapCommands.AuthenticatorConfig;
        parameters.Span.CopyTo(envelope.AsSpan(1));

        return envelope;
    }
}
