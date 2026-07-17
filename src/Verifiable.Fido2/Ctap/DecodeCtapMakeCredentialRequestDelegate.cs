using System;
using System.Buffers;
using Verifiable.Cryptography;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Decodes the CTAP2-canonical CBOR parameter map of an <c>authenticatorMakeCredential</c> request into
/// its typed model — the authenticator-side operation.
/// </summary>
/// <param name="parametersCbor">
/// The CBOR-encoded parameter map (the bytes following the command byte in the request envelope).
/// </param>
/// <param name="pool">
/// The memory pool the returned model's <see cref="CtapMakeCredentialRequest.ClientDataHash"/>,
/// <see cref="CtapMakeCredentialRequest.User"/>'s user handle, and any
/// <see cref="CtapMakeCredentialRequest.ExcludeList"/> credential identifiers rent from.
/// </param>
/// <returns>The decoded request model. The caller owns and disposes its <see cref="SensitiveMemory"/> carriers.</returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping <c>Verifiable.Fido2</c>
/// serialization-agnostic. The shipped default,
/// <c>Verifiable.Cbor.Ctap.CtapMakeCredentialRequestCborReader.Read</c>, is method-group-compatible with
/// this delegate and composes the shipped <c>Verifiable.Cbor.Ctap.CtapParameterMapReader</c> for its
/// first pass over the top-level parameter map.
/// </remarks>
/// <exception cref="Fido2FormatException">
/// <paramref name="parametersCbor"/> is not valid CTAP2 canonical CBOR, omits a Required member, or
/// carries a member of the wrong CBOR type.
/// </exception>
public delegate CtapMakeCredentialRequest DecodeCtapMakeCredentialRequestDelegate(ReadOnlyMemory<byte> parametersCbor, MemoryPool<byte> pool);
