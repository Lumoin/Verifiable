namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Encodes an <c>authenticatorGetAssertion</c> request model into its CTAP2-canonical CBOR parameter
/// map bytes — the client/RP-side operation.
/// </summary>
/// <param name="request">The request model to encode.</param>
/// <returns>
/// The CBOR-encoded parameter map (the bytes that follow the command byte in the request envelope),
/// wrapped in a <see cref="TaggedMemory{T}"/> so the buffer's provenance travels with it without a
/// defensive copy.
/// </returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping <c>Verifiable.Fido2</c>
/// serialization-agnostic — mirrors <see cref="EncodeCtapMakeCredentialRequestDelegate"/>'s seam shape.
/// The shipped default, <c>Verifiable.Cbor.Ctap.CtapGetAssertionRequestCborWriter.Write</c>, is
/// method-group-compatible with this delegate.
/// </remarks>
public delegate TaggedMemory<byte> EncodeCtapGetAssertionRequestDelegate(CtapGetAssertionRequest request);
