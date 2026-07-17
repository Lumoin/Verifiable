namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Encodes an <c>authenticatorBioEnrollment</c> response model into its CTAP2-canonical CBOR payload
/// bytes — the authenticator-side operation.
/// </summary>
/// <param name="response">The response model to encode.</param>
/// <returns>
/// The CBOR-encoded response payload (the bytes that follow the CTAP2 status byte in the response
/// envelope).
/// </returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping <c>Verifiable.Fido2</c>
/// serialization-agnostic — mirrors <see cref="EncodeCtapCredentialManagementResponseDelegate"/>'s
/// shape. The shipped default, <c>Verifiable.Cbor.Ctap.CtapBioEnrollmentResponseCborWriter.Write</c>,
/// is method-group-compatible with this delegate. A REQUIRED
/// <see cref="Ctap.Authenticator.Automata.CtapAuthenticatorSimulator"/> constructor parameter — see
/// <see cref="DecodeCtapBioEnrollmentRequestDelegate"/>'s remarks for the "always advertised, so always
/// decodable/encodable" posture this shares.
/// </remarks>
public delegate TaggedMemory<byte> EncodeCtapBioEnrollmentResponseDelegate(CtapBioEnrollmentResponse response);
