namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Encodes an <c>authenticatorMakeCredential</c> response model into its CTAP2-canonical CBOR payload
/// bytes — the authenticator-side operation.
/// </summary>
/// <param name="response">The response model to encode.</param>
/// <returns>
/// The CBOR-encoded response payload (the bytes that follow the CTAP2 status byte in the response
/// envelope), wrapped in a <see cref="TaggedMemory{T}"/> so the buffer's provenance travels with it
/// without a defensive copy.
/// </returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping <c>Verifiable.Fido2</c>
/// serialization-agnostic — mirrors <see cref="EncodeCtapGetInfoResponseDelegate"/>'s established seam
/// shape. The shipped default, <c>Verifiable.Cbor.Ctap.CtapMakeCredentialResponseCborWriter.Write</c>, is
/// method-group-compatible with this delegate.
/// </remarks>
public delegate TaggedMemory<byte> EncodeCtapMakeCredentialResponseDelegate(CtapMakeCredentialResponse response);
