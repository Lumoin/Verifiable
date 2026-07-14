using System;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Decodes the CTAP2-canonical CBOR payload of an <c>authenticatorClientPIN</c> response into its
/// typed model — the RP/platform-side operation.
/// </summary>
/// <param name="payload">
/// The CBOR-encoded response payload (the bytes following the CTAP2 status byte in the response
/// envelope).
/// </param>
/// <returns>The decoded response model.</returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping <c>Verifiable.Fido2</c>
/// serialization-agnostic — mirrors <see cref="DecodeCtapGetInfoResponseDelegate"/>'s shape. The
/// shipped default, <c>Verifiable.Cbor.Ctap.CtapClientPinResponseCborReader.Read</c>, is
/// method-group-compatible with this delegate.
/// </remarks>
/// <exception cref="Fido2FormatException">
/// <paramref name="payload"/> is not valid CTAP2 canonical CBOR.
/// </exception>
public delegate CtapClientPinResponse DecodeCtapClientPinResponseDelegate(ReadOnlyMemory<byte> payload);
