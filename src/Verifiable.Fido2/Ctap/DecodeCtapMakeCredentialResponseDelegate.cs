using System;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Decodes the CTAP2-canonical CBOR payload of an <c>authenticatorMakeCredential</c> response into its
/// typed model — the client/RP-side operation.
/// </summary>
/// <param name="payload">
/// The CBOR-encoded response payload (the bytes following the CTAP2 status byte in the response
/// envelope).
/// </param>
/// <returns>
/// The decoded response model. Carries no <c>SensitiveMemory</c> members, so no memory pool is needed to
/// decode it.
/// </returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping <c>Verifiable.Fido2</c>
/// serialization-agnostic. The shipped default,
/// <c>Verifiable.Cbor.Ctap.CtapMakeCredentialResponseCborReader.Read</c>, is method-group-compatible
/// with this delegate.
/// </remarks>
/// <exception cref="Fido2FormatException">
/// <paramref name="payload"/> is not valid CTAP2 canonical CBOR, or omits a Required member
/// (<c>fmt</c> or <c>authData</c>).
/// </exception>
public delegate CtapMakeCredentialResponse DecodeCtapMakeCredentialResponseDelegate(ReadOnlyMemory<byte> payload);
