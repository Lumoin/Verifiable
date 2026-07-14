namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Encodes an <c>authenticatorGetInfo</c> response model into its CTAP2-canonical CBOR payload bytes.
/// </summary>
/// <param name="response">The response model to encode.</param>
/// <returns>
/// The CBOR-encoded response payload (the bytes that follow the CTAP2 status byte in the response
/// envelope), wrapped in a <see cref="TaggedMemory{T}"/> so the buffer's provenance travels with it
/// without a defensive copy.
/// </returns>
/// <remarks>
/// <para>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding">
/// CTAP 2.3, section 8: Message Encoding</see>: "all encoding is done using the concise binary
/// encoding CBOR" and "all encoders MUST serialize CBOR in the CTAP2 canonical CBOR encoding form."
/// This is the FIRST CTAP2-canonical CBOR <em>writer</em> this library ships (the decode side has
/// production precedent in <c>Verifiable.Cbor.Fido2</c>'s COSE_Key readers).
/// </para>
/// <para>
/// The concrete CBOR codec is supplied at the composition edge, keeping <c>Verifiable.Fido2</c>
/// serialization-agnostic — mirrors <see cref="ReadCredentialPublicKeyDelegate"/>'s established
/// seam shape exactly. The shipped default, <c>Verifiable.Cbor.Ctap.CtapGetInfoResponseCborWriter.Write</c>,
/// is method-group-compatible with this delegate.
/// </para>
/// </remarks>
public delegate TaggedMemory<byte> EncodeCtapGetInfoResponseDelegate(CtapGetInfoResponse response);
