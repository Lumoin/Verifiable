using System;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Decodes the CTAP2-canonical CBOR payload of an <c>authenticatorClientPIN</c> request into its typed
/// model — the authenticator-side operation.
/// </summary>
/// <param name="parametersCbor">The CBOR-encoded request parameter map.</param>
/// <returns>The decoded request model.</returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping <c>Verifiable.Fido2</c>
/// serialization-agnostic — mirrors <see cref="DecodeCtapMakeCredentialRequestDelegate"/>'s shape,
/// minus a memory pool: every member this delegate decodes is either a plain scalar or an opaque byte
/// string/COSE_Key copied onto the heap, with no pooled <c>SensitiveMemory</c> carrier this wave. The
/// shipped default, <c>Verifiable.Cbor.Ctap.CtapClientPinRequestCborReader.Read</c>, is
/// method-group-compatible with this delegate.
/// </remarks>
/// <exception cref="Fido2FormatException">
/// <paramref name="parametersCbor"/> is not valid CTAP2 canonical CBOR, or omits the Required
/// <c>subCommand</c> member.
/// </exception>
public delegate CtapClientPinRequest DecodeCtapClientPinRequestDelegate(ReadOnlyMemory<byte> parametersCbor);
