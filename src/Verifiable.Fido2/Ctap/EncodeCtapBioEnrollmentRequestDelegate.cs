namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Encodes an <c>authenticatorBioEnrollment</c> request model into its CTAP2-canonical CBOR parameter
/// map — the RP/platform-side operation.
/// </summary>
/// <param name="request">The request model to encode.</param>
/// <returns>The encoded parameter map.</returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping <c>Verifiable.Fido2</c>
/// serialization-agnostic — mirrors <see cref="EncodeCtapCredentialManagementRequestDelegate"/>'s
/// shape. The shipped default, <c>Verifiable.Cbor.Ctap.CtapBioEnrollmentRequestCborWriter.Write</c>, is
/// method-group-compatible with this delegate. No authenticator-side production code consumes this
/// delegate — it exists for the platform-side test/real-wire harness that assembles
/// <c>authenticatorBioEnrollment</c> requests.
/// </remarks>
public delegate TaggedMemory<byte> EncodeCtapBioEnrollmentRequestDelegate(CtapBioEnrollmentRequest request);
