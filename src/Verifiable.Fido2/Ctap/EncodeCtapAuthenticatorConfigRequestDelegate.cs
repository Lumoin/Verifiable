namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Encodes an <c>authenticatorConfig</c> request model into its CTAP2-canonical CBOR parameter map —
/// the RP/platform-side operation.
/// </summary>
/// <param name="request">The request model to encode.</param>
/// <returns>The encoded parameter map, tagged <see cref="Fido2BufferTags.CtapAuthenticatorConfigRequestPayload"/>.</returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping <c>Verifiable.Fido2</c>
/// serialization-agnostic — mirrors <see cref="EncodeCtapClientPinRequestDelegate"/>'s shape. The
/// shipped default, <c>Verifiable.Cbor.Ctap.CtapAuthenticatorConfigRequestCborWriter.Write</c>, is
/// method-group-compatible with this delegate.
/// </remarks>
public delegate TaggedMemory<byte> EncodeCtapAuthenticatorConfigRequestDelegate(CtapAuthenticatorConfigRequest request);
