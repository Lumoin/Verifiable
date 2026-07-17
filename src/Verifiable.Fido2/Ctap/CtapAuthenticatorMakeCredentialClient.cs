using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The RP/platform-side <c>authenticatorMakeCredential</c> operation: builds the request envelope,
/// sends it through a transport-neutral <see cref="Ctap2TransceiveDelegate"/>, decodes the response into
/// its typed model, and translates that CTAP response into a WebAuthn <c>attestationObject</c>.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential">
/// CTAP 2.3, section 6.1: authenticatorMakeCredential (0x01)</see>. Mirrors
/// <see cref="CtapAuthenticatorGetInfoClient"/>'s shape: the request envelope is
/// <see cref="WellKnownCtapCommands.MakeCredential"/> followed by the CBOR-encoded parameter map an
/// injected <see cref="EncodeCtapMakeCredentialRequestDelegate"/> produces; the response status byte is
/// checked via <see cref="WellKnownCtapStatusCodes.IsOk"/>, a non-success status raises
/// <see cref="CtapCommandException"/>, and the response payload is decoded by an injected
/// <see cref="DecodeCtapMakeCredentialResponseDelegate"/>. This type never touches CBOR itself, keeping
/// <c>Verifiable.Fido2</c> serialization-agnostic.
/// </para>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-createCredential">W3C Web Authentication Level 3,
/// section 5.4: Options for Credential Creation</see>'s client-processing steps assemble the
/// <c>AuthenticatorAttestationResponse.attestationObject</c> the relying party ultimately verifies from
/// exactly the authenticator's <c>fmt</c>/<c>authData</c>/<c>attStmt</c> — the client never forwards the
/// CTAP-only response members (<c>epAtt</c>, <c>largeBlobKey</c>, <c>unsignedExtensionOutputs</c>). The
/// CTAP authenticator simulator this client talks to emits pure CTAP; <see cref="BuildAttestationObject"/>
/// is where that translation happens, on the client side, not the authenticator side.
/// </para>
/// </remarks>
public static class CtapAuthenticatorMakeCredentialClient
{
    /// <summary>
    /// Sends an <c>authenticatorMakeCredential</c> request and decodes the response.
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
    /// <returns>The decoded <c>authenticatorMakeCredential</c> response.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="transceive"/>, <paramref name="encodeRequest"/>, <paramref name="request"/>,
    /// <paramref name="decodeResponse"/>, or <paramref name="pool"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="Fido2FormatException">The response envelope is empty.</exception>
    /// <exception cref="CtapCommandException">The authenticator returned a non-success status code.</exception>
    public static async ValueTask<CtapMakeCredentialResponse> MakeCredentialAsync(
        Ctap2TransceiveDelegate transceive,
        EncodeCtapMakeCredentialRequestDelegate encodeRequest,
        CtapMakeCredentialRequest request,
        DecodeCtapMakeCredentialResponseDelegate decodeResponse,
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
            throw new Fido2FormatException("The authenticatorMakeCredential response envelope is empty; a CTAP2 status byte was expected.");
        }

        byte statusCode = response.AsReadOnlySpan()[0];
        if(!WellKnownCtapStatusCodes.IsOk(statusCode))
        {
            throw new CtapCommandException(statusCode);
        }

        return decodeResponse(response.AsReadOnlyMemory()[1..]);
    }


    /// <summary>
    /// Translates a decoded <c>authenticatorMakeCredential</c> response into a WebAuthn
    /// <c>attestationObject</c>: the client's own processing step, distinct from the authenticator's
    /// pure-CTAP response.
    /// </summary>
    /// <param name="response">The decoded <c>authenticatorMakeCredential</c> response.</param>
    /// <param name="encodeAttestationObject">The codec that CBOR-encodes the <c>attestationObject</c>.</param>
    /// <returns>The encoded, text-keyed <c>attestationObject</c> bytes.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="response"/> or <paramref name="encodeAttestationObject"/> is <see langword="null"/>.
    /// </exception>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential">
    /// CTAP 2.3, section 6.1.2</see>, step 17's "omit attestation from the output" instruction is a
    /// CTAP-response-layer omission: <see cref="CtapMakeCredentialResponse.AttStmt"/> is
    /// <see langword="null"/> on the wire. WebAuthn's <c>attestationObject</c>, by contrast, has no such
    /// nullable slot — <see href="https://www.w3.org/TR/webauthn-3/#sctn-none-attestation">section 8.7's</see>
    /// <c>none</c> format CDDL fixes <c>attStmt</c> to the empty map unconditionally. This translation
    /// bridges the two: a <see langword="null"/> <see cref="CtapMakeCredentialResponse.AttStmt"/> supplies
    /// <see cref="NoneAttestation.CanonicalEmptyMap"/> in the encoded <c>attestationObject</c>, so a
    /// CTAP-omitted attestation still reaches the relying party as spec-conformant WebAuthn wire bytes.
    /// </remarks>
    public static TaggedMemory<byte> BuildAttestationObject(
        CtapMakeCredentialResponse response, EncodeAttestationObjectDelegate encodeAttestationObject)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(encodeAttestationObject);

        ReadOnlyMemory<byte> attestationStatement = response.AttStmt ?? new byte[] { NoneAttestation.CanonicalEmptyMap };

        return encodeAttestationObject(response.Fmt, attestationStatement, response.AuthData);
    }


    /// <summary>
    /// Builds the complete request envelope: <see cref="WellKnownCtapCommands.MakeCredential"/> followed
    /// by <paramref name="parameters"/>.
    /// </summary>
    private static byte[] BuildRequestEnvelope(TaggedMemory<byte> parameters)
    {
        byte[] envelope = new byte[parameters.Length + 1];
        envelope[0] = WellKnownCtapCommands.MakeCredential;
        parameters.Span.CopyTo(envelope.AsSpan(1));

        return envelope;
    }
}
