namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Encodes an <c>authenticatorClientPIN</c> request model into its CTAP2-canonical CBOR parameter map
/// bytes — the RP/platform-side operation.
/// </summary>
/// <param name="request">The request model to encode.</param>
/// <returns>The CBOR-encoded parameter map.</returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping <c>Verifiable.Fido2</c>
/// serialization-agnostic — mirrors <see cref="EncodeCtapMakeCredentialRequestDelegate"/>'s shape. The
/// shipped default, <c>Verifiable.Cbor.Ctap.CtapClientPinRequestCborWriter.Write</c>, is
/// method-group-compatible with this delegate.
/// </remarks>
public delegate TaggedMemory<byte> EncodeCtapClientPinRequestDelegate(CtapClientPinRequest request);
