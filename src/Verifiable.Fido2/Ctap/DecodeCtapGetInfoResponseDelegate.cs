using System;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Decodes the CTAP2-canonical CBOR payload of an <c>authenticatorGetInfo</c> response into its
/// typed model.
/// </summary>
/// <param name="payload">
/// The CBOR-encoded response payload (the bytes following the CTAP2 status byte in the response
/// envelope).
/// </param>
/// <returns>The decoded response model.</returns>
/// <remarks>
/// <para>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetInfo">
/// CTAP 2.3, section 6.4: authenticatorGetInfo (0x04)</see>. The concrete CBOR codec is supplied at
/// the composition edge, keeping <c>Verifiable.Fido2</c> serialization-agnostic — mirrors
/// <see cref="ReadCredentialPublicKeyDelegate"/>'s established seam shape exactly. The shipped
/// default, <c>Verifiable.Cbor.Ctap.CtapGetInfoResponseCborReader.Read</c>, is
/// method-group-compatible with this delegate.
/// </para>
/// </remarks>
/// <exception cref="Fido2FormatException">
/// <paramref name="payload"/> is not valid CTAP2 canonical CBOR, or omits a Required member
/// (<c>versions</c> or <c>aaguid</c>).
/// </exception>
public delegate CtapGetInfoResponse DecodeCtapGetInfoResponseDelegate(ReadOnlyMemory<byte> payload);
