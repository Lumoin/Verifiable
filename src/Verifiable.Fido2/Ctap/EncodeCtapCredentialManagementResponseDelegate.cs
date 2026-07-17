namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Encodes an <c>authenticatorCredentialManagement</c> response model into its CTAP2-canonical CBOR
/// payload bytes — the authenticator-side operation.
/// </summary>
/// <param name="response">The response model to encode.</param>
/// <returns>
/// The CBOR-encoded response payload (the bytes that follow the CTAP2 status byte in the response
/// envelope).
/// </returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping <c>Verifiable.Fido2</c>
/// serialization-agnostic — mirrors <see cref="EncodeCtapClientPinResponseDelegate"/>'s shape. The
/// shipped default, <c>Verifiable.Cbor.Ctap.CtapCredentialManagementResponseCborWriter.Write</c>, is
/// method-group-compatible with this delegate. A REQUIRED
/// <see cref="Ctap.Authenticator.Automata.CtapAuthenticatorSimulator"/> constructor parameter, the same
/// precedent <see cref="EncodeCtapClientPinResponseDelegate"/> establishes for a command whose responses
/// carry a CBOR body.
/// </remarks>
public delegate TaggedMemory<byte> EncodeCtapCredentialManagementResponseDelegate(CtapCredentialManagementResponse response);
